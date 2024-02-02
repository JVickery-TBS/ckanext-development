import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import ckan.logic.schema as schema
from ckan.lib.plugins import DefaultDatasetForm


class DevelopmentPlugin(plugins.SingletonPlugin, DefaultDatasetForm):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IDatasetForm, inherit=True)

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

