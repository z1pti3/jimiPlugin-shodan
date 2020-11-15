from core import plugin, model

class _shodan(plugin._plugin):
    version = 0.3

    def install(self):
        # Register models
        model.registerModel("shodanGetHostByIP","_shodanGetHostByIP","_action","plugins.shodan.models.action")
        model.registerModel("shodanDomainLookup","_shodanDomainLookup","_action","plugins.shodan.models.action")
        model.registerModel("shodanReverseLookup","_shodanReverseLookup","_action","plugins.shodan.models.action")
        model.registerModel("shodanSearch","_shodanSearch","_action","plugins.shodan.models.action")
        return True

    def uninstall(self):
        # deregister models
        model.deregisterModel("shodanGetHostByIP","_shodanGetHostByIP","_action","plugins.shodan.models.action")
        model.deregisterModel("shodanDomainLookup","_shodanDomainLookup","_action","plugins.shodan.models.action")
        model.deregisterModel("shodanReverseLookup","_shodanReverseLookup","_action","plugins.shodan.models.action")
        model.deregisterModel("shodanSearch","_shodanSearch","_action","plugins.shodan.models.action")
        return True

    def upgrade(self,LatestPluginVersion):
        if self.version < 0.3:
            model.registerModel("shodanSearch","_shodanSearch","_action","plugins.shodan.models.action")
        if self.version < 0.2:
            model.registerModel("shodanDomainLookup","_shodanDomainLookup","_action","plugins.shodan.models.action")
            model.registerModel("shodanReverseLookup","_shodanReverseLookup","_action","plugins.shodan.models.action")

