import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit


class DevelopmentPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)


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

        config_['scheming.presets'] = """
            ckanext.scheming:presets.json
            ckanext.fluent:presets.json
            ckanext.development:schemas/presets.yaml
            ckanext.development:schemas/validation_placeholder_presets.yaml
            """

