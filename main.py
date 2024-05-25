import json
import requests
import urllib.parse
import ipaddress
from flask_cors import CORS
from flask import Flask, request, jsonify

# Check if Ipv4
def is_ipv4(text):
  try:
    ipaddress.ip_address(text)
    return True  # Valid IPv4 address, return False
  except ValueError:
    return False

# Hold Policy Data
class PolicyData():
    def __init__(self,HttpsService:str, name:str, realIpAddress:str, serverPool:str, httpService:str, vServer:str, webProtectionProfile:str):
        self.name:str =name
        self.realIpAddress:str =realIpAddress
        self.serverPool:str =serverPool
        self.httpService:str =httpService
        self.HttpsService:str =HttpsService
        self.vServer:str =vServer
        self.webProtectionProfile = webProtectionProfile

# Hold Waf Data   
class WafData():
    def __init__(self, realIpAddress:str, webProtectionProfile:str):
        self.realIpAddress:str =realIpAddress
        self.webProtectionProfile = webProtectionProfile
   

# Authentication class
class Authentication:
    def __init__(self):
        # Start a session for multiple requests
        self.session = requests.Session()
        
    #Login headers
    loginHeaders = {
    "Accept": "*/*",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "host": "20.28.60.56",
    }
    # Login information
    loginData = {
    "ajax": 1,
    "username": "fg",
    "secretkey": "Fg-123123123"
    }
    
    # Login to get cookie
    def login(self):
        url = "https://20.28.60.56:8443/logincheck"
        try:
            response = self.session.post(url, verify=False, headers=self.loginHeaders,data=self.loginData)
            response.raise_for_status()
            #return response.headers['Set-Cookie']
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            
    # Extract CSRF Token
    def getCsrfToken(self):
        headersCSRF ={
            "host": "20.28.60.56",
        } 
        url = "https://20.28.60.56:8443/api/v2.0/system/state"
        try:
            response = self.session.get(url, verify=False, headers=headersCSRF)
            response.raise_for_status()
            data = response.json()
            return data['resutls']['admin']['csrf_token']
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
  
# Whitelist API functions class 
class WhiteList():
    # Get All Whitelisted IP address
    def getWhitelist(self, authentication:Authentication):
        url = "https://20.28.60.56:8443/api/v2.0/cmdb/waf/ip-list/members?mkey=whitelist"
        try:
            authentication.login()
            response = authentication.session.get(url, verify=False)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")

        data = response.json()

        # Extract relevant data and create dictionaries
        waf_members = []
        for member in data["results"]:
            waf_members.append({
                "ip": member.get("ip"),
                "id": member.get("id")
            })
            
        return waf_members

    # Add an IP address to whitelist
    def addWhitelist(self,ipToBeAdded:str, authentication:Authentication):
        authentication.login()
        # Required headers for add finction
        headersAdd = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type":"application/json;charset=UTF-8",
        "Connection": "keep-alive",
        "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "host": "20.28.60.56",
        "X-CSRFTOKEN":authentication.getCsrfToken()
    }
        url = "https://20.28.60.56:8443/api/v2.0/cmdb/waf/ip-list/members?mkey=whitelist"
        
        data ={"data":{"q_type":0,"id":"0","type":"trust-ip","type_val":"0","group-type":"ip-string","group-type_val":"0","ip":str(ipToBeAdded),"ip-group":"","ip-group_val":"0"}}
        json_string = json.dumps(data)

        try:
            response = authentication.session.post(url, verify=False, headers=headersAdd, data=json_string)
            
            response.raise_for_status()
            return 'response'
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
    
    #Delete and ip address from whitelist
    def deleteWhitelist(self,idToDelete:str, authentication:Authentication):
        authentication.login()
        headersDelete = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "host": "20.28.60.56",
        "X-CSRFTOKEN":authentication.getCsrfToken()
    }
        url = "https://20.28.60.56:8443/api/v2.0/cmdb/waf/ip-list/members?mkey=whitelist&sub_mkey=" + idToDelete
        try:
            response = authentication.session.delete(url,verify=False, headers=headersDelete)
            response.raise_for_status()
            return 'response'
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            return 'error'

# Blacklist API functions class 

class BlackList():
    # Get all blacklisted IP addresses
    def getBlacklist(self,authentication:Authentication):
        url = "https://20.28.60.56:8443/api/v2.0/cmdb/waf/ip-list/members?mkey=blacklist"
        try:
            authentication.login()
            response = authentication.session.get(url, verify=False)
            response.raise_for_status()
            
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")

        data = response.json()

        # Extract relevant data and create dictionaries
        waf_members = []
        for member in data["results"]:
            waf_members.append({
                "ip": member.get("ip"),
                "id": member.get("id")
            })
        return waf_members

    # Add ip address to blacklist
    def addBlacklist(self, ipToBeAdded:str, authentication:Authentication):
        authentication.login()
        # Required headers for add finction
        headersAdd = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Content-Type":"application/json;charset=UTF-8",
        "Connection": "keep-alive",
        "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "application/json, text/plain, */*",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "host": "20.28.60.56",
        "X-CSRFTOKEN":authentication.getCsrfToken()
    }
        url = "https://20.28.60.56:8443/api/v2.0/cmdb/waf/ip-list/members?mkey=blacklist"
        
        data ={"data":{"q_type":0,"id":"0","type":"black-ip","type_val":"0","group-type":"ip-string","group-type_val":"0","ip":str(ipToBeAdded),"ip-group":"","ip-group_val":"0"}}
        json_string = json.dumps(data)

        try:
            response = authentication.session.post(url, verify=False, headers=headersAdd, data=json_string)
            
            response.raise_for_status()
            return 'response'
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
    
    # Delete blacklisted ip address
    def deleteBlacklist(self,idToDelete:str, authentication:Authentication):
        authentication.login()
        headersDelete = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "host": "20.28.60.56",
        "X-CSRFTOKEN":authentication.getCsrfToken()
        }
        url = "https://20.28.60.56:8443/api/v2.0/cmdb/waf/ip-list/members?mkey=blacklist&sub_mkey=" + idToDelete
        try:
            response = authentication.session.delete(url,verify=False, headers=headersDelete)
            response.raise_for_status()
            return 'response'
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            return 'error'

# Policy API functions class 
class Policy():
    # Add policy function
    def addPolicy(self, authentication:Authentication, data:PolicyData):
        authentication.login()
        headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Content-Type":"application/json;charset=UTF-8",
        "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "host": "20.28.60.56",
        "X-CSRFTOKEN":authentication.getCsrfToken()
        }
        postData=  {"data":
        {"protocol":"HTTP",
        "name":data.name,
        "deployment-mode":"server-pool",
        "client-real-ip":"enable",
        "real-ip-addr":data.realIpAddress,
        "ssl":"enable",
        "http2":"disable",
        "certificate-type":"disable",
        "multi-certificate":"disable",
        "http-to-https":"disable",
        "traffic-mirror":"disable",
        "traffic-mirror-type":"client-side",
        "monitor-mode":"disable",
        "syncookie":"disable",
        "half-open-threshold":8192,
        "case-sensitive":"disable",
        "proxy-protocol":"disable",
        "retry-on":"disable",
        "retry-on-cache-size":512,
        "retry-on-connect-failure":"disable",
        "retry-times-on-connect-failure":3,
        "retry-on-http-layer":"disable",
        "retry-times-on-http-layer":3,
        "retry-on-http-response-codes":"404 408 500 501 502 503 504",
        "web-cache":"disable",
        "prefer-current-session":"disable",
        "tlog":"disable",
        "scripting-list":"",
        "tags":"",
        "redirect-naked-domain":"disable",
        "tls-v10":"enable",
        "tls-v11":"enable",
        "tls-v12":"enable",
        "tls-v13":"disable",
        "ssl-cipher":"medium",
        "ssl-custom-cipher":"ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305 ECDHE-RSA-CHACHA20-POLY1305 ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-SHA384 ECDHE-RSA-AES256-SHA384 ECDHE-ECDSA-AES128-SHA256 ECDHE-RSA-AES128-SHA256 ECDHE-ECDSA-AES256-SHA ECDHE-RSA-AES256-SHA ECDHE-ECDSA-AES128-SHA ECDHE-RSA-AES128-SHA AES256-GCM-SHA384 AES128-GCM-SHA256 AES256-SHA256 AES128-SHA256",
        "tls13-custom-cipher":"TLS_AES_256_GCM_SHA384",
        "ssl-noreg":"enable",
        "sni":"disable",
        "sni-strict":"disable",
        "urlcert":"disable",
        "urlcert-hlen":32,
        "client-certificate-forwarding":"disable",
        "client-certificate-forwarding-sub-header":"X-Client-DN",
        "client-certificate-forwarding-cert-header":"X-Client-Cert",
        "hsts-header":"disable",
        "hsts-max-age":15552000,
        "hsts-include-subdomains":"disable",
        "hsts-preload":"disable",
        "use-ciphers-group":"disable",
        "vserver":data.vServer,
        "server-pool":data.serverPool,
        "service":data.httpService,
        "https-service":data.HttpsService,
        "web-protection-profile":data.webProtectionProfile,
        "replacemsg":"Predefined"}}

    
        json_string = json.dumps(postData)
        url = "https://20.28.60.56:8443/api/v2.0/cmdb/server-policy/policy"
        try:
            response = authentication.session.post(url,verify=False, headers=headers, data=json_string)
            
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            return 'error'
    
    # Get policies function 
    def getPolicies(self, authentication:Authentication):
        authentication.login()
        headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Content-Type":"application/json;charset=UTF-8",
        "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "host": "20.28.60.56",
        }
        url = "https://20.28.60.56:8443/api/v2.0/cmdb/server-policy/policy"
        try:
            response = authentication.session.get(url,verify=False, headers=headers)
            
            data = response.json()

            # Extract relevant data and create dictionaries
            policy_members = []
            for member in data["results"]:
                if(not is_ipv4(text=member.get("name"))):
                    policy_members.append({
                    "https-service": member.get("https-service"),
                    "name": member.get("name"),
                    "real-ip-addr": member.get("real-ip-addr"),
                    "server-pool": member.get("server-pool"),
                    "service": member.get("service"),
                    "vserver": member.get("vserver"),
                    "web-protection-profile": member.get("web-protection-profile"),
            })
            return policy_members
            
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            return 'error'
    
    # Update policies function    
    def updatePolicy(self, authentication:Authentication, data:PolicyData):
        authentication.login()
        headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Content-Type":"application/json;charset=UTF-8",
        "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "host": "20.28.60.56",
        "X-CSRFTOKEN":authentication.getCsrfToken()
        }
        postData=  {"data":
        {"protocol":"HTTP",
        "name":data.name,
        "deployment-mode":"server-pool",
        "client-real-ip":"enable",
        "real-ip-addr":data.realIpAddress,
        "ssl":"enable",
        "http2":"disable",
        "certificate-type":"disable",
        "multi-certificate":"disable",
        "http-to-https":"disable",
        "traffic-mirror":"disable",
        "traffic-mirror-type":"client-side",
        "monitor-mode":"disable",
        "syncookie":"disable",
        "half-open-threshold":8192,
        "case-sensitive":"disable",
        "proxy-protocol":"disable",
        "retry-on":"disable",
        "retry-on-cache-size":512,
        "retry-on-connect-failure":"disable",
        "retry-times-on-connect-failure":3,
        "retry-on-http-layer":"disable",
        "retry-times-on-http-layer":3,
        "retry-on-http-response-codes":"404 408 500 501 502 503 504",
        "web-cache":"disable",
        "prefer-current-session":"disable",
        "tlog":"disable",
        "scripting-list":"",
        "tags":"",
        "redirect-naked-domain":"disable",
        "tls-v10":"enable",
        "tls-v11":"enable",
        "tls-v12":"enable",
        "tls-v13":"disable",
        "ssl-cipher":"medium",
        "ssl-custom-cipher":"ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305 ECDHE-RSA-CHACHA20-POLY1305 ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-SHA384 ECDHE-RSA-AES256-SHA384 ECDHE-ECDSA-AES128-SHA256 ECDHE-RSA-AES128-SHA256 ECDHE-ECDSA-AES256-SHA ECDHE-RSA-AES256-SHA ECDHE-ECDSA-AES128-SHA ECDHE-RSA-AES128-SHA AES256-GCM-SHA384 AES128-GCM-SHA256 AES256-SHA256 AES128-SHA256",
        "tls13-custom-cipher":"TLS_AES_256_GCM_SHA384",
        "ssl-noreg":"enable",
        "sni":"disable",
        "sni-strict":"disable",
        "urlcert":"disable",
        "urlcert-hlen":32,
        "client-certificate-forwarding":"disable",
        "client-certificate-forwarding-sub-header":"X-Client-DN",
        "client-certificate-forwarding-cert-header":"X-Client-Cert",
        "hsts-header":"disable",
        "hsts-max-age":15552000,
        "hsts-include-subdomains":"disable",
        "hsts-preload":"disable",
        "use-ciphers-group":"disable",
        "vserver":data.vServer,
        "server-pool":data.serverPool,
        "service":data.httpService,
        "https-service":data.HttpsService,
        "web-protection-profile":data.webProtectionProfile,
        "replacemsg":"Predefined"}}

    
        json_string = json.dumps(postData)
        url = "https://20.28.60.56:8443/api/v2.0/cmdb/server-policy/policy?mkey=" + urllib.parse.quote(data.name, safe='~()*!@#$&\'+,;=-:.^')
        
        try:
            response = authentication.session.put(url,verify=False, headers=headers, data=json_string)
            
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            return 'error'
    
    # Delete policies function    
    def deletePolicy(self, authentication:Authentication, data:PolicyData):
        authentication.login()
        headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Content-Type":"application/json;charset=UTF-8",
        "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "host": "20.28.60.56",
        "X-CSRFTOKEN":authentication.getCsrfToken()
        }

        url = "https://20.28.60.56:8443/api/v2.0/cmdb/server-policy/policy?mkey=" + urllib.parse.quote(data.name, safe='~()*!@#$&\'+,;=-:.^')
        
        try:
            response = authentication.session.delete(url,verify=False, headers=headers)
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            return 'error'

# WAF API functions class       
class Waf():
    # Add Waf function
    def addWaf(self, authentication:Authentication, data:WafData):
        authentication.login()
        headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Content-Type":"application/json;charset=UTF-8",
        "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "host": "20.28.60.56",
        "X-CSRFTOKEN":authentication.getCsrfToken()
        }
        postData=  {"data":
        {"protocol":"HTTP",
        "name":data.realIpAddress,
        "deployment-mode":"server-pool",
        "client-real-ip":"enable",
        "real-ip-addr":data.realIpAddress,
        "ssl":"enable",
        "http2":"disable",
        "certificate-type":"disable",
        "multi-certificate":"disable",
        "http-to-https":"disable",
        "traffic-mirror":"disable",
        "traffic-mirror-type":"client-side",
        "monitor-mode":"enable",
        "syncookie":"disable",
        "half-open-threshold":8192,
        "case-sensitive":"disable",
        "proxy-protocol":"disable",
        "retry-on":"disable",
        "retry-on-cache-size":512,
        "retry-on-connect-failure":"disable",
        "retry-times-on-connect-failure":3,
        "retry-on-http-layer":"disable",
        "retry-times-on-http-layer":3,
        "retry-on-http-response-codes":"404 408 500 501 502 503 504",
        "web-cache":"disable",
        "prefer-current-session":"disable",
        "tlog":"disable",
        "scripting-list":"",
        "tags":"",
        "redirect-naked-domain":"disable",
        "tls-v10":"enable",
        "tls-v11":"enable",
        "tls-v12":"enable",
        "tls-v13":"disable",
        "ssl-cipher":"medium",
        "ssl-custom-cipher":"ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305 ECDHE-RSA-CHACHA20-POLY1305 ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-SHA384 ECDHE-RSA-AES256-SHA384 ECDHE-ECDSA-AES128-SHA256 ECDHE-RSA-AES128-SHA256 ECDHE-ECDSA-AES256-SHA ECDHE-RSA-AES256-SHA ECDHE-ECDSA-AES128-SHA ECDHE-RSA-AES128-SHA AES256-GCM-SHA384 AES128-GCM-SHA256 AES256-SHA256 AES128-SHA256",
        "tls13-custom-cipher":"TLS_AES_256_GCM_SHA384",
        "ssl-noreg":"enable",
        "sni":"disable",
        "sni-strict":"disable",
        "urlcert":"disable",
        "urlcert-hlen":32,
        "client-certificate-forwarding":"disable",
        "client-certificate-forwarding-sub-header":"X-Client-DN",
        "client-certificate-forwarding-cert-header":"X-Client-Cert",
        "hsts-header":"disable",
        "hsts-max-age":15552000,
        "hsts-include-subdomains":"disable",
        "hsts-preload":"disable",
        "use-ciphers-group":"disable",
        "vserver":"Port 5",
        "server-pool":"Enable Single Server",
        "service":"HTTP",
        "https-service":"HTTPS",
        "web-protection-profile": data.webProtectionProfile,
        "replacemsg":"Predefined"}}

    
        json_string = json.dumps(postData)
        url = "https://20.28.60.56:8443/api/v2.0/cmdb/server-policy/policy"
        try:
            response = authentication.session.post(url,verify=False, headers=headers, data=json_string)
            
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            return 'error'
    
    # Get all WAFs function
    def getWaf(self, authentication:Authentication):
        authentication.login()
        headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Content-Type":"application/json;charset=UTF-8",
        "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "host": "20.28.60.56",
        }
        url = "https://20.28.60.56:8443/api/v2.0/cmdb/server-policy/policy"
        try:
            response = authentication.session.get(url,verify=False, headers=headers)
            
            data = response.json()

            # Extract relevant data and create dictionaries
            policy_members = []
            for member in data["results"]:
                if(is_ipv4(text=member.get("name"))):
                    policy_members.append({
                    "https-service": member.get("https-service"),
                    "name": member.get("name"),
                    "real-ip-addr": member.get("real-ip-addr"),
                    "server-pool": member.get("server-pool"),
                    "service": member.get("service"),
                    "vserver": member.get("vserver"),
                    "web-protection-profile": member.get("web-protection-profile"),
            })
            return policy_members
            
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            return 'error'
    
    # Update a waf function
    def updateWaf(self, authentication:Authentication, data:WafData):
        authentication.login()
        headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Content-Type":"application/json;charset=UTF-8",
        "sec-ch-ua": "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": "\"Windows\"",
        "Upgrade-Insecure-Requests": "1",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "host": "20.28.60.56",
        "X-CSRFTOKEN":authentication.getCsrfToken()
        }
       
        postData=  {"data":
            {"protocol":"HTTP",
            "name":data.realIpAddress,
            "deployment-mode":"server-pool",
            "client-real-ip":"enable",
            "real-ip-addr":data.realIpAddress,
            "ssl":"enable",
            "http2":"disable",
            "certificate-type":"disable",
            "multi-certificate":"disable",
            "http-to-https":"disable",
            "traffic-mirror":"disable",
            "traffic-mirror-type":"client-side",
            "monitor-mode":"disable",
            "syncookie":"disable",
            "half-open-threshold":8192,
            "case-sensitive":"disable",
            "proxy-protocol":"disable",
            "retry-on":"disable",
            "retry-on-cache-size":512,
            "retry-on-connect-failure":"disable",
            "retry-times-on-connect-failure":3,
            "retry-on-http-layer":"disable",
            "retry-times-on-http-layer":3,
            "retry-on-http-response-codes":"404 408 500 501 502 503 504",
            "web-cache":"disable",
            "prefer-current-session":"disable",
            "tlog":"disable",
            "scripting-list":"",
            "tags":"",
            "redirect-naked-domain":"disable",
            "tls-v10":"enable",
            "tls-v11":"enable",
            "tls-v12":"enable",
            "tls-v13":"disable",
            "ssl-cipher":"medium",
            "ssl-custom-cipher":"ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305 ECDHE-RSA-CHACHA20-POLY1305 ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-SHA384 ECDHE-RSA-AES256-SHA384 ECDHE-ECDSA-AES128-SHA256 ECDHE-RSA-AES128-SHA256 ECDHE-ECDSA-AES256-SHA ECDHE-RSA-AES256-SHA ECDHE-ECDSA-AES128-SHA ECDHE-RSA-AES128-SHA AES256-GCM-SHA384 AES128-GCM-SHA256 AES256-SHA256 AES128-SHA256",
            "tls13-custom-cipher":"TLS_AES_256_GCM_SHA384",
            "ssl-noreg":"enable",
            "sni":"disable",
            "sni-strict":"disable",
            "urlcert":"disable",
            "urlcert-hlen":32,
            "client-certificate-forwarding":"disable",
            "client-certificate-forwarding-sub-header":"X-Client-DN",
            "client-certificate-forwarding-cert-header":"X-Client-Cert",
            "hsts-header":"disable",
            "hsts-max-age":15552000,
            "hsts-include-subdomains":"disable",
            "hsts-preload":"disable",
            "use-ciphers-group":"disable",
            "vserver":"Port 5",
            "server-pool":"Enable Single Server",
            "service":"HTTP",
            "https-service":"HTTPS",
            "web-protection-profile": data.webProtectionProfile,
            "replacemsg":"Predefined"}}

    
        json_string = json.dumps(postData)
        url = "https://20.28.60.56:8443/api/v2.0/cmdb/server-policy/policy?mkey=" + data.realIpAddress
        
        try:
            response = authentication.session.put(url,verify=False, headers=headers, data=json_string)
            
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            return 'error'
       

# APIs
app = Flask(__name__)

cors = CORS(app, resources={r"/*": {"origins": "https://services-orchestrator.web.app"}})


###     Whitelist     ###
# Get Whitelist
@app.route("/wl")
def apiGetWhielist():
    return WhiteList().getWhitelist(authentication= Authentication())

# Add Whitelist
@app.route("/wl/a/<ip>")
def apiAddWhielist(ip):
    return WhiteList().addWhitelist(ipToBeAdded=ip, authentication=Authentication())

# Delete Whitelist
@app.route("/wl/d/<id>")
def apiDeleteWhielist(id):
    return WhiteList().deleteWhitelist(idToDelete= id, authentication=Authentication())



###     Blacklist     ###

# Get Blacklist
@app.route("/bl")
def apiGetBlack():
    return BlackList().getBlacklist(authentication= Authentication())

# Add Blacklist
@app.route("/bl/a/<ip>")
def apiAddBlacklist(ip):
    authentication = Authentication()
    return BlackList().addBlacklist(ipToBeAdded=ip, authentication=Authentication())

# Delete Blacklist
@app.route("/bl/d/<id>")
def apiDeleteBlacklist(id):
    authentication = Authentication()
    return BlackList().deleteBlacklist(idToDelete= id, authentication=Authentication())



###     Policy    ###
# Add policy
@app.route("/pol/a",methods=['POST'])
def apiAddPolicy():
    data = request.json
    if not data or not data.get('https-service') or not data.get('name') or not data.get('real-ip-addr')  or not data.get('server-pool') or not data.get('service') or not data.get('vserver') or not data.get('web-protection-profile'):
        return jsonify({'error': 'Missing parameter'}), 400
    
    reqData:PolicyData = PolicyData(httpService=data.get('service'), name=data.get('name'),realIpAddress= data.get('real-ip-addr'), serverPool=  data.get('server-pool') , HttpsService= data.get('https-service') , vServer= data.get('vserver'), webProtectionProfile=data.get('web-protection-profile') )
    
    
    
    return Policy().addPolicy(authentication = Authentication(), data = reqData)

# Update policy
@app.route("/pol/u",methods=['POST'])
def apiupdatePolicy():
    data = request.json
    if not data or not data.get('https-service') or not data.get('name') or not data.get('real-ip-addr')  or not data.get('server-pool') or not data.get('service') or not data.get('vserver') or not data.get('web-protection-profile'):
        return jsonify({'error': 'Missing parameter'}), 400
    
    reqData:PolicyData = PolicyData(httpService=data.get('service'), name=data.get('name'),realIpAddress= data.get('real-ip-addr'), serverPool=  data.get('server-pool') , HttpsService= data.get('https-service') , vServer= data.get('vserver'), webProtectionProfile=data.get('web-protection-profile') )
    return Policy().updatePolicy(authentication = Authentication(), data = reqData)

#Delete policy
@app.route("/pol/d",methods=['POST'])
def apiDeletePolicy():
    data = request.json
    if not data or not data.get('https-service') or not data.get('name') or not data.get('real-ip-addr')  or not data.get('server-pool') or not data.get('service') or not data.get('vserver') or not data.get('web-protection-profile'):
        return jsonify({'error': 'Missing parameter'}), 400
    
    reqData:PolicyData = PolicyData(httpService=data.get('service'), name=data.get('name'),realIpAddress= data.get('real-ip-addr'), serverPool=  data.get('server-pool') , HttpsService= data.get('https-service') , vServer= data.get('vserver'), webProtectionProfile=data.get('web-protection-profile') )
    return Policy().deletePolicy(authentication = Authentication(), data = reqData)

#  Get Existing policies
@app.route("/pol")
def apiGetPolicy():
    return Policy().getPolicies(authentication = Authentication())


####   WAF   ###
#Add WAF
@app.route("/waf/a",methods=['POST'])
def apiAddWaf():
    data = request.json
    if not data or  not data.get('real-ip-addr') or not data.get('web-protection-profile'):
        return jsonify({'error': 'Missing parameter'}), 400
    
    reqData:WafData = WafData(realIpAddress= data.get('real-ip-addr'), webProtectionProfile= 'Inline Standard Protection'if data.get('web-protection-profile') != 'none' else "" )
    return Waf().addWaf(authentication = Authentication(), data = reqData)
#Update Waf
@app.route("/waf/u",methods=['POST'])
def apiupdateWaf():
    data = request.json
    if not data or  not data.get('real-ip-addr') or not data.get('web-protection-profile'):
        return jsonify({'error': 'Missing parameter'}), 400
    
    reqData:WafData = WafData(realIpAddress= data.get('real-ip-addr'), webProtectionProfile='Inline Standard Protection'if data.get('web-protection-profile') != 'none' else "" )
    return Waf().updateWaf(authentication = Authentication(), data = reqData)

# Get Existing Waf
@app.route("/waf")
def apiGetWaf():
    return Waf().getWaf(authentication = Authentication())
