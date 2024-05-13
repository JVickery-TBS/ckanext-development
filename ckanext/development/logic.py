import os
import sys
import json
import datetime
import logging
import traceback
import sqlalchemy
from ckan.plugins.toolkit import asbool, config, url_for, get_action, ObjectNotFound, chained_action, check_access
from ckanext.xloader.loader import load_csv, load_table, calculate_record_count, create_column_indexes
from ckanext.xloader.utils import datastore_resource_exists, get_xloader_user_apitoken
from ckanext.xloader.jobs import MAX_TYPE_GUESSING_LENGTH, _download_resource_data, set_datastore_active, StoringHandler
from ckanext.xloader.job_exceptions import JobError, FileCouldNotBeLoadedError
from ckanext.xloader.db import mark_job_as_completed, mark_job_as_errored, init, add_pending_job


@chained_action
def force_sync_xloader_submit(up_func, context, data_dict):
    check_access('xloader_submit', context, data_dict)
    if not data_dict.get('resource_id'):
        return
    try:
        resource = get_action('resource_show')(context, {'id': data_dict['resource_id']})
    except ObjectNotFound:
        return
    custom_xloader_submit(context, resource)


def _get_logger(database_logging=True, job_id=None):
    logger = logging.getLogger('%s.%s' % (__name__, job_id)
                               if job_id else __name__)

    if database_logging:
        # Set-up logging to the db
        db_handler = StoringHandler(job_id, input)
        db_handler.setLevel(logging.DEBUG)
        db_handler.setFormatter(logging.Formatter('%(message)s'))
        logger.addHandler(db_handler)

    return logger


def _get_xloader_user_context():
    """ Returns the Xloader user.

    xloader actions require an authenticated user to perform the actions. This
    method returns the context for actions.
    """
    user = config.get('ckanext.xloader.user', None)
    if user:
        return {"user": user}

    user = get_action('get_site_user')({'ignore_auth': True}, {})
    return {"user": user['name']}


def _update_resource(resource, patch_only=False):
    """
    Update the given CKAN resource to say that it has been stored in datastore
    ok.
    or patch the given CKAN resource for file hash
    """
    action = 'resource_update' if not patch_only else 'resource_patch'
    user = get_action('get_site_user')({'ignore_auth': True}, {})
    context = {
        'ignore_auth': True,
        'user': user['name'],
        'auth_user_obj': None,
        'is_xloadering': True,
    }
    get_action(action)(context, resource)


def custom_xloader_submit(context, resource):

    logger = _get_logger(database_logging=False)

    init(config)

    xloader_user_context = _get_xloader_user_context()

    task = {
        'entity_id': resource.get('id'),
        'entity_type': 'resource',
        'task_type': 'xloader',
        'last_updated': str(datetime.datetime.utcnow()),
        'state': 'submitting',
        'key': 'xloader',
        'value': '{}',
        'error': '{}',
    }

    try:
        existing_task = get_action('task_status_show')(context, {
            'entity_id': resource.get('id'),
            'task_type': 'xloader',
            'key': 'xloader'
        })
        # TODO: in case another user edits the resource,
        # we want to be able to somehow handle that in sync mode
        task['id'] = existing_task['id']
    except ObjectNotFound:
        pass

    task = get_action('task_status_update')(dict(**xloader_user_context, ignore_auth=True), task)
    job_id = task.get('id')
    value = json.dumps({'job_id': job_id})
    task['value'] = value
    task = get_action('task_status_update')(dict(**xloader_user_context, ignore_auth=True), task)

    callback_url = url_for(
        "api.action",
        ver=3,
        logic_function="xloader_hook",
        qualified=True
    )
    data = {
        'api_key': get_xloader_user_apitoken(),
        'job_type': 'xloader_to_datastore',
        'result_url': callback_url,
        'metadata': {
            'ignore_hash': True,  # always ignore has in sync mode
            'ckan_url': config['ckan.site_url'],
            'resource_id': resource.get('id'),
            'set_url_type': False,  # never set url_type to datapusher in sync mode
            'task_created': task['last_updated'],
            'original_url': resource.get('url'),
        }
    }

    job_dict = dict(metadata=data['metadata'],
                    status='running')
    get_action('xloader_hook')(xloader_user_context, job_dict)

    errored = False
    try:
        _sync_mode_xloader(resource=resource,
                           data=data,
                           job_dict=job_dict,
                           xloader_user_context=xloader_user_context,
                           job_id=job_id)
        job_dict['status'] = 'complete'
        mark_job_as_completed(job_id, job_dict)
    except JobError as e:
        mark_job_as_errored(job_id, str(e))
        job_dict['status'] = 'error'
        job_dict['error'] = str(e)
        logger.error('xloader error: {0}, {1}'.format(e, traceback.format_exc()))
        errored = True
    except Exception as e:
        mark_job_as_errored(job_id, traceback.format_tb(sys.exc_info()[2])[-1] + repr(e))
        job_dict['status'] = 'error'
        job_dict['error'] = str(e)
        logger.error('xloader error: {0}, {1}'.format(e, traceback.format_exc()))
        errored = True
    finally:
        # job_dict is defined in xloader_hook's docstring
        is_saved_ok = get_action('xloader_hook')(xloader_user_context, job_dict)
        errored = errored or not is_saved_ok
    return 'error' if errored else None


def _sync_mode_xloader(resource, data, job_dict, xloader_user_context, job_id):

    # Store details of the job in the db
    try:
        add_pending_job(job_id, **data)
    except sqlalchemy.exc.IntegrityError:
        raise JobError('job_id {} already exists'.format(job_id))

    logger = _get_logger(database_logging=True, job_id=job_id)

    resource_ckan_url = '/dataset/{}/resource/{}'.format(resource['package_id'], resource['id'])
    logger.info('Express Load starting: %s', resource_ckan_url)

    # download resource
    tmp_file, file_hash = _download_resource_data(resource, data, data.get('api_key'), logger)

    def direct_load():
        fields = load_csv(tmp_file.name,
                          resource_id=resource['id'],
                          mimetype=resource.get('format'),
                          logger=logger)
        calculate_record_count(resource_id=resource['id'], logger=logger)
        set_datastore_active(data.get('metadata'), resource, logger)
        if 'result_url' in data:
            job_dict['status'] = 'running_but_viewable'
            get_action('xloader_hook')(xloader_user_context, job_dict)
        logger.info('Data now available to users: %s', resource_ckan_url)
        create_column_indexes(fields=fields,
                              resource_id=resource['id'],
                              logger=logger)
        _update_resource(resource={'id': resource['id'], 'hash': resource['hash']}, patch_only=True)
        logger.info('File Hash updated for resource: %s', resource['hash'])

    def tabulator_load():
        try:
            load_table(tmp_file.name,
                       resource_id=resource['id'],
                       mimetype=resource.get('format'),
                       logger=logger)
        except JobError as e:
            logger.error('Error during tabulator load: %s', e)
            raise
        calculate_record_count(resource_id=resource['id'], logger=logger)
        set_datastore_active(data.get('metadata'), resource, logger)
        logger.info('Finished loading with tabulator')
        _update_resource(resource={'id': resource['id'], 'hash': resource['hash']}, patch_only=True)
        logger.info('File Hash updated for resource: %s', resource['hash'])

    logger.info('Loading CSV')

    use_type_guessing = asbool(
        config.get('ckanext.xloader.use_type_guessing', config.get(
            'ckanext.xloader.just_load_with_messytables', False))) \
        and not datastore_resource_exists(resource['id']) \
        and os.path.getsize(tmp_file.name) <= MAX_TYPE_GUESSING_LENGTH

    logger.info("'use_type_guessing' mode is: %s", use_type_guessing)

    try:
        if use_type_guessing:
            tabulator_load()
        else:
            try:
                direct_load()
            except JobError as e:
                logger.warning('Load using COPY failed: %s', e)
                logger.info('Trying again with tabulator')
                tabulator_load()
    except FileCouldNotBeLoadedError as e:
        logger.warning('Loading excerpt for this format not supported.')
        logger.error('Loading file raised an error: %s', e)
        raise JobError('Loading file raised an error: {}'.format(e))

    tmp_file.close()

    logger.info('Express Load completed')
