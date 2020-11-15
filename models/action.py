import json

from plugins.shodan.includes import shodan

from core.models import action
from core import auth, db, helpers

class _shodanSearch(action._action):
    apiToken = str()
    queryString = str()
    facetsString = str()

    def run(self,data,persistentData,actionResult):
        if not hasattr(self,"plain_apiToken"):
            self.plain_apiToken = auth.getPasswordFromENC(self.apiToken)

        queryString = helpers.evalString(self.queryString,{"data" : data})
        facetsString = helpers.evalString(self.facetsString,{"data" : data})
        sapi = shodan._shodanapi(self.plain_apiToken)
        response = sapi.hostSearch(queryString,facetsString)
        responseData = response.text
        if response.status_code == 200:
            responseData = json.loads(responseData)
            for x, responseDataItem in enumerate(responseData["matches"]):
                responseData["matches"][x] = helpers.unicodeEscapeDict(responseDataItem)
                try:
                    responseData["matches"][x]["ssl"]["cert"]["serial"] = str(responseDataItem["ssl"]["cert"]["serial"])
                except:
                    pass
        actionResult["result"] = True
        actionResult["rc"] = response.status_code
        actionResult["data"] =  responseData
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_shodanSearch, self).setAttribute(attr,value,sessionData=sessionData)


class _shodanGetHostByIP(action._action):
    apiToken = str()
    ip = str()

    def run(self,data,persistentData,actionResult):
        if not hasattr(self,"plain_apiToken"):
            self.plain_apiToken = auth.getPasswordFromENC(self.apiToken)

        ip = helpers.evalString(self.ip,{"data" : data})
        sapi = shodan._shodanapi(self.plain_apiToken)
        response = sapi.getHostByIP(ip)
        responseData = response.text
        if response.status_code == 200:
            responseData = json.loads(responseData)
        actionResult["result"] = True
        actionResult["rc"] = response.status_code
        actionResult["data"] =  responseData
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_shodanGetHostByIP, self).setAttribute(attr,value,sessionData=sessionData)

class _shodanDomainLookup(action._action):
    apiToken = str()
    domain = str()

    def run(self,data,persistentData,actionResult):
        if not hasattr(self,"plain_apiToken"):
            self.plain_apiToken = auth.getPasswordFromENC(self.apiToken)

        domain = helpers.evalString(self.domain,{"data" : data})
        sapi = shodan._shodanapi(self.plain_apiToken)
        response = sapi.domainLookup(domain)
        responseData = response.text
        if response.status_code == 200:
            responseData = json.loads(responseData)
        actionResult["result"] = True
        actionResult["rc"] = response.status_code
        actionResult["data"] =  response.text
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_shodanDomainLookup, self).setAttribute(attr,value,sessionData=sessionData)

class _shodanReverseLookup(action._action):
    apiToken = str()
    ip = str()

    def run(self,data,persistentData,actionResult):
        if not hasattr(self,"plain_apiToken"):
            self.plain_apiToken = auth.getPasswordFromENC(self.apiToken)

        ip = helpers.evalString(self.ip,{"data" : data})
        sapi = shodan._shodanapi(self.plain_apiToken)
        response = sapi.reverseLookup(ip)
        responseData = response.text
        if response.status_code == 200:
            responseData = json.loads(responseData)
        actionResult["result"] = True
        actionResult["rc"] = response.status_code
        actionResult["data"] =  response.text
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_shodanReverseLookup, self).setAttribute(attr,value,sessionData=sessionData)

