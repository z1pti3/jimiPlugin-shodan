import requests
import json
import uuid
import time
from pathlib import Path

class _shodanapi():
    url = "https://api.shodan.io/"

    def __init__(self,apiToken,ca=None,requestTimeout=30):
        self.apiToken = apiToken
        self.requestTimeout = requestTimeout
        if ca:
            self.ca = Path(ca)
        else:
            self.ca = None

    def api(self,method,endpoint,data=None):
        method = method.upper()
        kwargs = {}
        if self.ca:
            kwargs["ca"] = self.ca
        if method == "GET":
            response = requests.get("{0}{1}".format(self.url,endpoint),**kwargs)
        # Force rate limit sleeping ( all API methods have a limit of 1 per second)
        time.sleep(1)
        return response 

    def getHostByIP(self,ip):
        response = self.api("GET","shodan/host/{0}?key={1}".format(ip,self.apiToken))
        return response

    def domainLookup(self,domain):
        response = self.api("GET","dns/domain/{0}?key={1}".format(domain,self.apiToken))
        return response

    def reverseLookup(self,ip):
        response = self.api("GET","dns/reverse?ips={0}&key={1}".format(ip,self.apiToken))
        return response

    def hostSearch(self,query,facets):
        response = self.api("GET","shodan/host/search?&key={0}&query={1}&facets={2}".format(self.apiToken,query,facets))
        return response

