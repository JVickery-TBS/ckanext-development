import datetime
import json
import traceback
import sys
import time
import logging
import os
import sqlalchemy as sa

from ckan.plugins.toolkit import (
    check_access,
    get_action,
    ValidationError,
    ObjectNotFound,
    navl_validate,
    config,
    url_for,
    asbool,
    chained_action,
)
from ckan.plugins import PluginImplementations

from ckanext.xloader.schema import xloader_submit_schema
from ckanext.xloader import (
    interfaces as xloader_interfaces,
    utils,
    db,
    loader,
)
from ckanext.xloader.job_exceptions import(
    JobError,
    FileCouldNotBeLoadedError,
)
from ckanext.xloader.jobs import (
    MAX_RETRIES,
    RETRYABLE_ERRORS,
    MAX_TYPE_GUESSING_LENGTH,
    _download_resource_data,
    get_resource_and_dataset,
    StoringHandler,
    validate_input,
    set_datastore_active,
)


log = logging.getLogger(__name__)
_validate = navl_validate


@chained_action
def xloader_submit(up_func, context, data_dict):

    schema = context.get('schema', xloader_submit_schema())
    data_dict, errors = _validate(data_dict, schema, context)
    if errors:
        raise ValidationError(errors)

    check_access('xloader_submit', context, data_dict)

    res_id = data_dict['resource_id']
    try:
        resource_dict = get_action('resource_show')(context, {
            'id': res_id,
        })
    except ObjectNotFound:
        return False

    for plugin in PluginImplementations(xloader_interfaces.IXloader):
        upload = plugin.can_upload(res_id)
        if not upload:
            msg = "Plugin {0} rejected resource {1}"\
                .format(plugin.__class__.__name__, res_id)
            log.info(msg)
            return False

    # Check if this resource is already in the process of being xloadered
    task = {
        'entity_id': res_id,
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
            'entity_id': res_id,
            'task_type': 'xloader',
            'key': 'xloader'
        })
        # TODO: implement a pending or running timeout here...
        if existing_task:
            # for now...just delete the existing task
            get_action('task_status_delete')(context, {
                'id': existing_task['id']})
    except ObjectNotFound:
        pass

    model = context['model']

    get_action('task_status_update')(
        {'session': model.meta.create_local_session(), 'ignore_auth': True},
        task
    )

    callback_url = url_for(
        "api.action",
        ver=3,
        logic_function="xloader_hook",
        qualified=True
    )
    data = {
        'api_key': utils.get_xloader_user_apitoken(),
        'job_type': 'xloader_to_datastore',
        'result_url': callback_url,
        'metadata': {
            'ignore_hash': data_dict.get('ignore_hash', False),
            'ckan_url': config.get('ckanext.xloader.site_url', config['ckan.site_url']),
            'resource_id': res_id,
            'set_url_type': data_dict.get('set_url_type', False),
            'task_created': task['last_updated'],
            'original_url': resource_dict.get('url'),
        }
    }
    # Expand timeout for resources that have to be type-guessed
    timeout = config.get(
        'ckanext.xloader.job_timeout',
        '3600' if utils.datastore_resource_exists(res_id) else '10800')
    log.debug("Timeout for XLoading resource %s is %s", res_id, timeout)

    try:
        _xloader_data_into_datastore(data)
    except Exception:
        log.exception('Unable to xloader: res_id=%s', res_id)
        return False
    log.debug('Loading to DataStore via xloader: res_id=%s', res_id)

    value = json.dumps({'job_id': res_id})

    task['value'] = value
    task['state'] = 'pending'
    task['last_updated'] = str(datetime.datetime.utcnow())

    get_action('task_status_update')(
        {'session': model.meta.create_local_session(), 'ignore_auth': True},
        task
    )

    return True


def _get_xloader_user_context():
    # type: () -> Context|dict
    """ Returns the Xloader user.

    xloader actions require an authenticated user to perform the actions. This
    method returns the context for actions.
    """
    user = config.get('ckanext.xloader.user', None)
    if user:
        return {"user": user}

    user = get_action('get_site_user')({'ignore_auth': True}, {})
    return {"user": user['name']}


def _callback_xloader_hook(job_dict, logger):
    try:
        get_action('xloader_hook')(_get_xloader_user_context(), job_dict)
    except Exception as e:
        logger.warning("Failed to call xloader_hook action: %s", e)
        return False

    return True


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


def _xloader_data_into_datastore(input):
    job_dict = dict(metadata=input['metadata'],
                    status='running')

    logger = _get_logger(database_logging=False)

    _callback_xloader_hook(job_dict=job_dict,
                           logger=logger)

    job_id = job_dict.get('metadata').get('resource_id')
    errored = False
    try:
        _xloader_data_into_datastore_(input, job_dict)
        job_dict['status'] = 'complete'
        db.mark_job_as_completed(job_id, job_dict)
    except JobError as e:
        db.mark_job_as_errored(job_id, str(e))
        job_dict['status'] = 'error'
        job_dict['error'] = str(e)
        log.error('xloader error: %s, %s', e, traceback.format_exc())
        errored = True
    except Exception as e:
        if isinstance(e, RETRYABLE_ERRORS):
            tries = job_dict['metadata'].get('tries', 0)
            if tries < MAX_RETRIES:
                tries = tries + 1
                log.info("Job %s failed due to temporary error [%s], retrying", job_id, e)
                job_dict['status'] = 'pending'
                job_dict['metadata']['tries'] = tries
                _xloader_data_into_datastore(input)
                return None

        db.mark_job_as_errored(
            job_id, traceback.format_tb(sys.exc_info()[2])[-1] + repr(e))
        job_dict['status'] = 'error'
        job_dict['error'] = str(e)
        log.error('xloader error: %s, %s', e, traceback.format_exc())
        errored = True
    finally:
        # job_dict is defined in xloader_hook's docstring
        is_saved_ok = _callback_xloader_hook(job_dict=job_dict,
                                             logger=logger)
        errored = errored or not is_saved_ok
    return 'error' if errored else None


def _xloader_data_into_datastore_(input, job_dict):
    job_id = job_dict.get('metadata').get('resource_id')
    db.init(config)

    # Store details of the job in the db
    try:
        db.add_pending_job(job_id, **input)
    except sa.exc.IntegrityError:
        pass
        #raise JobError('job_id {} already exists'.format(job_id))

    logger = _get_logger(job_id=job_id)

    validate_input(input)

    data = input['metadata']

    resource_id = data['resource_id']
    api_key = input.get('api_key')
    try:
        resource, dataset = get_resource_and_dataset(resource_id, api_key)
    except (JobError, ObjectNotFound):
        # try again in 5 seconds just in case CKAN is slow at adding resource
        time.sleep(5)
        resource, dataset = get_resource_and_dataset(resource_id, api_key)
    resource_ckan_url = '/dataset/{}/resource/{}' \
        .format(dataset['name'], resource['id'])
    logger.info('Express Load starting: %s', resource_ckan_url)

    # check if the resource url_type is a datastore
    if resource.get('url_type') == 'datastore':
        logger.info('Ignoring resource - url_type=datastore - dump files are '
                    'managed with the Datastore API')
        return

    # download resource
    tmp_file, file_hash = _download_resource_data(resource, data, api_key,
                                                  logger)

    if (resource.get('hash') == file_hash
            and not data.get('ignore_hash')):
        logger.info('Ignoring resource - the file hash hasn\'t changed: '
                    '{hash}.'.format(hash=file_hash))
        return
    logger.info('File hash: %s', file_hash)
    resource['hash'] = file_hash

    def direct_load():
        fields = loader.load_csv(
            tmp_file.name,
            resource_id=resource['id'],
            mimetype=resource.get('format'),
            logger=logger)
        loader.calculate_record_count(
            resource_id=resource['id'], logger=logger)
        set_datastore_active(data, resource, logger)
        job_dict['status'] = 'running_but_viewable'
        _callback_xloader_hook(job_dict=job_dict,
                               logger=logger)
        logger.info('Data now available to users: %s', resource_ckan_url)
        loader.create_column_indexes(
            fields=fields,
            resource_id=resource['id'],
            logger=logger)
        _update_resource(resource={'id': resource['id'], 'hash': resource['hash']},
                        patch_only=True)
        logger.info('File Hash updated for resource: %s', resource['hash'])

    def tabulator_load():
        try:
            loader.load_table(tmp_file.name,
                              resource_id=resource['id'],
                              mimetype=resource.get('format'),
                              logger=logger)
        except JobError as e:
            logger.error('Error during tabulator load: %s', e)
            raise
        loader.calculate_record_count(
            resource_id=resource['id'], logger=logger)
        set_datastore_active(data, resource, logger)
        logger.info('Finished loading with tabulator')
        _update_resource(resource={'id': resource['id'], 'hash': resource['hash']},
                        patch_only=True)
        logger.info('File Hash updated for resource: %s', resource['hash'])

    # Load it
    logger.info('Loading CSV')
    # If ckanext.xloader.use_type_guessing is not configured, fall back to
    # deprecated ckanext.xloader.just_load_with_messytables
    use_type_guessing = asbool(
        config.get('ckanext.xloader.use_type_guessing', config.get(
            'ckanext.xloader.just_load_with_messytables', False))) \
        and not utils.datastore_resource_exists(resource['id']) \
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


def _update_resource(resource, patch_only=False):
    action = 'resource_update' if not patch_only else 'resource_patch'
    user = get_action('get_site_user')({'ignore_auth': True}, {})
    context = {
        'ignore_auth': True,
        'user': user['name'],
        'auth_user_obj': None,
        'xloadering': True,
    }
    get_action(action)(context, resource)
