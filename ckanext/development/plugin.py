import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.logic.schema as schema
from ckan.lib.plugins import DefaultDatasetForm

from ckanext.development import logic
from ckanext.xloader.interfaces import IXloader

from logging import getLogger


log = getLogger(__name__)


class DevelopmentPlugin(plugins.SingletonPlugin, DefaultDatasetForm):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IDatasetForm, inherit=True)
    plugins.implements(plugins.IActions)
    plugins.implements(plugins.IResourceController, inherit=True)
    plugins.implements(IXloader, inherit=True)

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
        """
        Never allow Xloader plugin to automatically submit to be Xloadered.
        """
        return False


    #IActions

    def get_actions(self):
        return {'xloader_submit': logic.force_sync_xloader_submit}


    # IResourceController

    def after_resource_update(self, context, resource):
        """
        If the Resource has a successful validation report, Xloader it synchronously.
        """
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

