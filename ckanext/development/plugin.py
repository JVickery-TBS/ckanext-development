import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.logic.schema as schema
from ckan.lib.plugins import DefaultDatasetForm

from ckanext.development import logic
from ckanext.xloader.interfaces import IXloader
try:
    from ckanext.xloader.interfaces import IPipeXloader
    HAS_PIPE_XLOADER = True
except ImportError:
    HAS_PIPE_XLOADER = False

from logging import getLogger


log = getLogger(__name__)


class DevelopmentPlugin(plugins.SingletonPlugin, DefaultDatasetForm):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IDatasetForm, inherit=True)
    plugins.implements(plugins.IActions)
    plugins.implements(plugins.IResourceController, inherit=True)
    plugins.implements(IXloader, inherit=True)
    if HAS_PIPE_XLOADER:
        plugins.implements(IPipeXloader, inherit=True)

    # DefaultDatasetForm

    def create_package_schema(self):
        return schema.default_create_package_schema()


    def update_package_schema(self):
        return schema.default_update_package_schema()


    def show_package_schema(self):
        return schema.default_show_package_schema()


    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, "templates")
        toolkit.add_public_directory(config_, "public")
        toolkit.add_resource("assets", "development")

        config_['scheming.dataset_schemas'] = """
            ckanext.development:schemas/dataset.yaml
            """

        config_['scheming.organization_schemas'] = """
            ckanext.development:schemas/organization.yaml
            """

        config_['scheming.group_schemas'] = """
            ckanext.development:schemas/group.yaml
            """

        config_['scheming.presets'] = """
            ckanext.scheming:presets.json
            ckanext.fluent:presets.json
            ckanext.development:schemas/presets.yaml
            ckanext.development:schemas/validation_placeholder_presets.yaml
            """


    # IXloader

    def can_upload(self, resource_id):
        if not toolkit.config.get('ckanext.dev.xloader_sync', False):
            # check if file is uploded
            try:
                res = toolkit.get_action(u'resource_show')({'ignore_auth': True},
                                                            {'id': resource_id})

                if res.get('url_type', None) != 'upload':
                    log.error(
                        'Only uploaded resources can be added to the Data Store.')
                    return False

            except toolkit.ObjectNotFound:
                log.error('Resource %s does not exist.' % resource_id)
                return False

            # check if validation report exists
            try:
                validation = toolkit.get_action(u'resource_validation_show')(
                    {'ignore_auth': True},
                    {'resource_id': res['id']})
                if validation.get('status', None) != 'success':
                    log.error(
                        'Only validated resources can be added to the Data Store.')
                    return False

            except toolkit.ObjectNotFound:
                log.error('No validation report exists for resource %s' %
                        resource_id)
                return False

            return True
        # Never allow Xloader plugin to automatically submit to be Xloadered.
        return False

    # IPipeXloader

    def receive_xloader_status(self, xloader_status):
        if xloader_status.get('entity_type') != 'resource':
            return
        state = xloader_status.get('state')
        resource_id = xloader_status.get('entity_id')
        res_dict = toolkit.get_action('resource_show')({'ignore_auth': True}, {'id': resource_id})
        res_name = toolkit.h.get_translated(res_dict, 'name')
        if state == 'complete':
            toolkit.h.flash_success("Complete: resource \"%s\" has been successfully loaded into the DataStore." % res_name)
        elif state == 'error':
            toolkit.h.flash_error("Error: resource \"%s\" could not be loaded into the DataStore." % res_name)
        elif state == 'pending':
            toolkit.h.flash_success("Pending: resource \"%s\" waiting to be loaded into the DataStore." % res_name)
        elif state == 'submitting':
            toolkit.h.flash_success("Submitting: resource \"%s\" being queued to go into the DataStore." % res_name)
        else:
            toolkit.h.flash_success("Info: resource \"%s\" has not been loaded into the DataStore yet." % res_name)


    #IActions

    def get_actions(self):
        if not toolkit.config.get('ckanext.dev.xloader_sync', False):
            return {}
        return {'xloader_submit': logic.force_sync_xloader_submit}


    # IResourceController

    def after_resource_update(self, context, resource):
        if not toolkit.config.get('ckanext.dev.xloader_sync', False):
            return resource
        # If the Resource has a successful validation report, Xloader it synchronously.
        # check if the resource is being updated/patched from Xloader and prevent any looping
        if context.get('is_xloadering'):
            del context['is_xloadering']
            return

        # check if validation report exists and is successful
        try:
            validation = toolkit.get_action(u'resource_validation_show')(
                {'ignore_auth': True},
                {'resource_id': resource.get('id')})
            if validation.get('status', None) != 'success':
                log.error(
                    'Only validated resources can be added to the Data Store.')
                return
        except toolkit.ObjectNotFound:
            log.error('No validation report exists for resource %s' %
                      resource.get('id'))
            return

        # submit to custom Xloader
        logic.custom_xloader_submit(context, resource)

