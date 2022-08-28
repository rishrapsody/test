import os
from netmiko import ConnectHandler
import jc
import user_data
import argparse
import csv
import requests
import json
import git
from pprint import pprint
from texttable import Texttable
from datetime import datetime
from colorama import init, Fore, Back, Style
from typing import List,Dict,Union
import ipaddress
import urllib3
urllib3.disable_warnings()

## script help content
parser = argparse.ArgumentParser(description='''
You can provide input in below format:
Valid:
1. Enter PrivateAccess nxID(separated by commas)[eg.4042106,3150376] :->> 3150376
2. Enter PrivateAccess nxID(separated by commas)[eg.4042106,3150376] :->> 3150376,4042106

Invalid:
1. Enter PrivateAccess nxID(separated by commas)[eg.4042106,3150376] :->> 3150376, ABC
2. Enter PrivateAccess nxID(separated by commas)[eg.4042106,3150376] :->> 3150376XYZ

Default path for Proxy file: $HOME/.ssh/config (update ssh_config_file variable if its different for you)
''',formatter_class=argparse.RawTextHelpFormatter)

args = parser.parse_args()


## function to get user input and save as a list
def get_user_input() -> List:
    try:
        user_input = input("Enter PrivateAccess nxID(separated by commas)[eg.4042106,3150376] :->> ")
        input_parsed = [int(x.strip()) for x in user_input.split(',')]
        return(input_parsed)

    except ValueError as e:
        print(e)
        print("Invalid user inputs. Please try again")
        get_user_input()
    except Exception as e:
        print(e)
        print("Re-check input")
        get_user_input()

## function to get arvpnID, custcode, custid, localsubnet for each nexus in input list
def find_arvpnID_mapping(input: List) -> Union[Dict,Dict,Dict,Dict,Dict]:
    try:
        headers = {'Content-Type': 'application/json'}
        arvpn = {}
        cust_code = {}
        cust_id = {}
        local_subnet = {}
        site_name = {}
        for nx_id in input:
            url = "https://eagleeye-test.aryaka.info/eagleeye/api/nexus/{}/info?nexus_id".format(nx_id)
            response = requests.request("GET", url, headers=headers,verify=False).json()
            if response.get('arvpn_machine_id') !=  None and response['arvpn_machine_id'] != 0:
                arvpn[nx_id] = response["arvpn_machine_id"]
                temp = []
                if len(response["routeInfo"]["route"]["localSubnets"]) == 0:
                    local_subnet[nx_id] = Fore.RED+"None"+Fore.RESET
                elif len(response["routeInfo"]["route"]["localSubnets"]) == 1:
                    subnet = response["routeInfo"]["route"]["localSubnets"][0]["ip"] + "/" + response["routeInfo"]["route"]["localSubnets"][0]["mask"]
                    temp.append(subnet)
                    local_subnet[nx_id] = temp
                else:
                    
                    for i in range(len(response["routeInfo"]["route"]["localSubnets"])):
                        subnet = response["routeInfo"]["route"]["localSubnets"][i]["ip"] + "/" + response["routeInfo"]["route"]["localSubnets"][i]["mask"]
                        temp.append(subnet)
                    local_subnet[nx_id] = temp

            else:
                errors_list.append("Unable to find arvpn server-id. Check if nexus {} is of type PrivateAccess. Nexus may be using older edge provider".format(nx_id))
                exit("Unable to find arvpn server-id. \n->Check if nexus {} is of type PrivateAccess. \n->Nexus may be using older edge provider \n->Nexus is either not active or has no connexus".format(nx_id))
            cust_code[nx_id] = response["customer_code"].lower()
            cust_id[nx_id] = response["customer_id"]
            site_name[nx_id] =  response["loc_name"]
        return(arvpn,cust_code,cust_id,local_subnet,site_name)
    except requests.exceptions.ConnectionError:
        exit("Unable to establish connection with API server. Check if your VPN is UP\n")
    except requests.exceptions.Timeout as e:
        print ("Timeout Error:",e) 
    except Exception as e:
        print(e)
        errors_list.append("Either EE is unresponsive or nexus is not PrivateAccess. Please check")
        func = "find_arvpnID_mapping"
        report_admin(func,e,errors_list)
        exit("Landed into exception while executing EE Nexus API.\n->Unable to find arvpn server for input nx: {}\n->EE API might be unresponsive. Check with Admin".format(nx_id))


## function to get arvpn server hostname for each arvpnID. Returns nexus to server hostname mapping
def find_arvpn_server(arvpn_dict: Dict) -> Dict:
    try:
        # df = pd.read_csv("data/arvpn.csv")
        # temp_dict = {}
        # for k,v in arvpn_dict.items():
        #     temp_dict[k] = df.loc[df["Id"] == v,'Name'].item()
        # return(temp_dict)
        temp_dict = {}
        for k,v in arvpn_dict.items():
            headers = {'Content-Type': 'application/json'}
            url = "https://eagleeye-test.aryaka.info/eagleeye/command/run"
            payload = json.dumps({"commandName":"uname -a","entityType":"mach","entityId":[v],"roles":["arvpn"],"blocking":"true"})
            response = requests.request("GET", url, headers=headers, data=payload,verify=False).json()
            temp_dict[k] = response["batch"]["exec"][0]["hostName"]
        return(temp_dict)
    except Exception as e:
        print(e)
        errors_list.append("Unable to parse arvpn server name using API call. Check with Admin")
        func = "find_arvpn_server"
        report_admin(func,e,errors_list)
        exit("Landed into exception while executing EE Command API.\n->Unable to find arvpn hostname for nx: {}\n->EE API might be unresponsive. Check with Admin".format(k))


## function to get vpn tunnel status and return dictionary per nexus
def get_vpn_tunnel_status(input: List,cust_id: Dict) -> Dict:
    try:
        tunnel_info = {}
        headers = {'Content-Type': 'application/json'}
        for nx_id in input:
            url = "https://eagleeye-test.aryaka.info/eagleeye/api/customer/{}/nexus/down".format(cust_id[nx_id])
            response = requests.request("GET", url, headers=headers,verify=False).json()
            if nx_id in response["nexusIds"]:
                tunnel_info[nx_id] = Fore.RED+"DOWN"+Fore.RESET
            else:
                tunnel_info[nx_id] = "UP"
        return(tunnel_info)
    except Exception as e:
        #print(e)
        func ="get_vpn_tunnel_status"
        err_list = "Landed into exception while executing EE Tunnel Status API.\n->Unable to find TunnelStatus for nx: {}".format(nx_id)
        report_admin(func,e,err_list)
        exit("Landed into exception while executing EE Tunnel Status API.\n->Unable to find TunnelStatus for nx: {}\n->EE API might be unresponsive. Check with Admin".format(nx_id))


## function to parse link profiles and validate config
def validate_link_profile(profiles: Dict,nexus: str,pop: str,cust_code: Dict,tunnel_info: Dict) -> List:
    #pprint(profiles)
    lp_data = []
    #print(nexus)
    for lp in profiles:
        if not str(nexus) in lp["Name"]:
            pass
        else:
            #pprint(lp)
            try:
                exp_name = "{}-{}-{}".format(cust_code[nexus],pop,nexus)
                if not exp_name == lp["Name"]:
                    lp_data.append(["LinkProfile","Name",lp["Name"],"Should follow standard i.e.cust_code-pop-nexus",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    lp_data.append(["LinkProfile", "Name", lp["Name"], "Should follow standard i.e.cust_code-pop-nexus", "PASSED"])
            except Exception as e:
                lp_data.append(["LinkProfile","Name","NA","Should follow standard i.e.cust_code-pop-nexus",Fore.RED+"FAILED"+Fore.RESET])
            try:
                if lp["Direction"] != 'bidirectional':
                    lp_data.append(["LinkProfile","Direction",lp['Direction'],"bidirectional",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    lp_data.append(["LinkProfile", "Direction", lp['Direction'], "bidirectional", "PASSED"])
            except Exception as e:
                lp_data.append(["LinkProfile", "Direction", "Not Configured", "bidirectional", Fore.RED+"FAILED"+Fore.RESET])

            try:
                if "State" in lp.keys():
                    if lp["State"] != 'enabled':
                        lp_data.append(["LinkProfile","State",lp["State"],"Enabled at Secure-Server level",Fore.RED+"FAILED"+Fore.RESET])
                    else:
                        lp_data.append(["LinkProfile","State",lp["State"],"Enabled at Secure-Server level","PASSED"])
                else:
                    if tunnel_info[nexus] == "UP":
                        lp_data.append(["LinkProfile","State","enabled","enabled","PASSED"])
                    else:
                        lp_data.append(["LinkProfile","State","Unable to find key","enabled",Fore.MAGENTA+"N/A"+Fore.RESET])
            except Exception as e:
                #print(e)
                lp_data.append(["LinkProfile","State","Unable to find key","enabled",Fore.RED+"FAILED"+Fore.RESET])

            try:
                if int(lp["Timeout"]) != int(0):
                    lp_data.append(["LinkProfile","Timeout",lp["Timeout"],"0",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    lp_data.append(["LinkProfile", "Timeout", lp["Timeout"], "0", "PASSED"])
            except Exception as e:
                lp_data.append(["LinkProfile", "Timeout", "Not Configured", "0", Fore.RED+"FAILED"+Fore.RESET])

            try:
                if lp["RemoteUserId"] != lp["VpnTunnelEndpoint"]:
                    lp_data.append(["LinkProfile","RemoteUserId/VpnEndpoint",lp["RemoteUserId"],"RemoteUserId=VpnTunnelEndpoint",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    lp_data.append(["LinkProfile", "RemoteUserId/VpnEndpoint", lp["RemoteUserId"],
                                    "RemoteUserId=VpnTunnelEndpoint", "PASSED"])
            except Exception as e:
                lp_data.append(["LinkProfile","RemoteUserId/VpnEndpoint","Not Configured","RemoteUserId=VpnTunnelEndpoint",Fore.RED+"FAILED"+Fore.RESET])

            try:
                if "asn" not in lp["IkePolicy"]:
                    lp_data.append(["LinkProfile","IkePolicy",lp["IkePolicy"],"ike-policy-asn-default",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    lp_data.append(["LinkProfile", "IkePolicy", lp["IkePolicy"], "ike-policy-asn-default", "PASSED"])
            except Exception as e:
                lp_data.append(["LinkProfile","IkePolicy","Not Configured","ike-policy-asn-default",Fore.RED+"FAILED"+Fore.RESET])

            try:
                if "asn" not in lp["IPSecPolicy"]:
                    lp_data.append(["LinkProfile","IPSecPolicy",lp["IPSecPolicy"],"ipsec-policy-asn-default",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    lp_data.append(["LinkProfile", "IPSecPolicy", lp["IPSecPolicy"], "ipsec-policy-asn-default", "PASSED"])
            except Exception as e:
                lp_data.append(["LinkProfile","IPSecPolicy","Not Configured","ipsec-policy-asn-default",Fore.RED+"FAILED"+Fore.RESET])

            try:
                if lp["PrivateIpAddress"] != "255.255.255.255":
                    lp_data.append(["LinkProfile","PrivateIpAddress",lp["PrivateIpAddress"],"255.255.255.255",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    lp_data.append(["LinkProfile", "PrivateIpAddress", lp["PrivateIpAddress"], "255.255.255.255", "PASSED"])

            except Exception as e:
                lp_data.append(["LinkProfile","PrivateIpAddress","Not Configured","255.255.255.255",Fore.RED+"FAILED"+Fore.RESET])

            try:
                if lp["ExchangeMode"] != "main":
                    lp_data.append(["LinkProfile","ExchangeMode",lp["ExchangeMode"],"main",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    lp_data.append(["LinkProfile", "ExchangeMode", lp["ExchangeMode"], "main", "PASSED"])
            except Exception as e:
                lp_data.append(["LinkProfile","ExchangeMode","Not Configured","main",Fore.RED+"FAILED"+Fore.RESET])

    return(lp_data)

## function to parse domain groups and validate config
def validate_domain_group(groups: Dict,nexus: str,pop: str,cust_code: Dict,tunnel_info: Dict,local_subnet: Dict) -> List:
    dg_data = []
    for dg in groups:
        if not cust_code[nexus] in dg["Name"]:
            pass
        else:
            #pprint(dg)
            try:
                if not dg["Name"].startswith(cust_code[nexus]) and not dg["Name"].endswith("row") or not dg["Name"].startswith(cust_code[nexus]) and not dg["Name"].endswith("mlc"):
                    dg_data.append(["DomainGroup","Name",dg["Name"],"Start with custcode and end with region",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    dg_data.append(["DomainGroup", "Name", dg["Name"], "Start with custcode and end with region", "PASSED"])
            except Exception as e:
                dg_data.append(["DomainGroup", "Name", "Not Configured", "Start with custcode and end with region", Fore.RED+"FAILED"+Fore.RESET])

            try:
                if "State" in dg.keys():
                    if dg["State"] != "enabled":
                        dg_data.append(["DomainGroup", "State", dg["State"], "Enabled at Secure-Server level", Fore.RED+"FAILED"+Fore.RESET])
                    else:
                        dg_data.append(["DomainGroup", "State", dg["State"], "Enabled at Secure-Server level", "PASSED"])
                else:
                    dg_data.append(["DomainGroup", "State", "enabled", "enabled", "PASSED"])
            except Exception as e:
                #print(e)
                dg_data.append(["DomainGroup", "State", "Unable to find key", "enabled", Fore.RED+"FAILED"+Fore.RESET])

            try:
                if dg['Suffix'] == "" or '.' not in dg['Suffix']:
                    dg_data.append(["DomainGroup","Suffix",dg['Suffix'],"Should not be empty",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    dg_data.append(["DomainGroup", "Suffix", dg['Suffix'], "Should not be empty", "PASSED"])
            except Exception as e:
                dg_data.append(["DomainGroup","Suffix","Not Configured","Should not be empty",Fore.RED+"FAILED"+Fore.RESET])

            try:
                if dg["DNS1"] == "" and dg["DNS2"] == "":
                    dg_data.append(["DomainGroup","DNS","","Atleast one should be configured",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    dg_data.append(["DomainGroup", "DNS", dg["DNS1"] + "/" + dg["DNS2"] , "Atleast one should be configured", "PASSED"])
            except Exception as e:
                dg_data.append(["DomainGroup","DNS","Not Configured","Atleast one should be configured",Fore.RED+"FAILED"+Fore.RESET])

            try:
                if dg["SEM1"] != "212.59.89.1":
                    dg_data.append(["DomainGroup","SEM1",dg["SEM1"],"212.59.89.1",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    dg_data.append(["DomainGroup", "SEM1", dg["SEM1"], "212.59.89.1", "PASSED"])
            except Exception as e:
                dg_data.append(["DomainGroup","SEM1","Not Configured","212.59.89.1",Fore.RED+"FAILED"+Fore.RESET])

            try:
                if dg["SEM2"] != "212.59.89.17":
                    dg_data.append(["DomainGroup", "SEM2", dg["SEM2"], "212.59.89.17", Fore.RED+"FAILED"+Fore.RESET])
                else:
                    dg_data.append(["DomainGroup", "SEM2", dg["SEM2"], "212.59.89.17", "PASSED"])
            except Exception as e:
                dg_data.append(["DomainGroup", "SEM2", "Not Configured", "212.59.89.17", Fore.RED+"FAILED"+Fore.RESET])

            try:
                if dg["IKev2Auth"] != "EAP":
                    dg_data.append(["DomainGroup","IKEv2Auth",dg["IKev2Auth"],"EAP",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    dg_data.append(["DomainGroup", "IKEv2Auth", dg["IKev2Auth"], "EAP", "PASSED"])
            except Exception as e:
                dg_data.append(["DomainGroup","IKEv2Auth","Not Configured","EAP",Fore.RED+"FAILED"+Fore.RESET])

            try:
                if dg["IKEEapType"] != "PAP":
                    dg_data.append(["DomainGroup","IKEEapType",dg["IKEEapType"],"PAP",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    dg_data.append(["DomainGroup", "IKEEapType", dg["IKEEapType"], "PAP", "PASSED"])
            except Exception as e:
                dg_data.append(["DomainGroup","IKEEapType","Not Configured","EAP",Fore.RED+"FAILED"+Fore.RESET])

            try:
                if "IKEv2AllowAuthEAP" in dg.keys():
                    if dg["IKEv2AllowAuthEAP"] == "disabled":
                        dg_data.append(["DomainGroup","IKEv2AllowAuthEAP","disabled","enabled",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    dg_data.append(["DomainGroup","IKEv2AllowAuthEAP","enabled","enabled","PASSED"])
            except Exception as e:
                dg_data.append(["DomainGroup","IKEv2AllowAuthEAP","Unable to find key","enabled",Fore.RED+"FAILED"+Fore.RESET])

            try:
                if dg["ServerCertificate"] != "IPsec":
                    dg_data.append(["DomainGroup","ServerCertificate",dg["ServerCertificate"],"IPsec",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    dg_data.append(["DomainGroup", "ServerCertificate", dg["ServerCertificate"], "IPsec", "PASSED"])
            except Exception as e:
                dg_data.append(["DomainGroup","ServerCertificate","Not Configured","IPsec",Fore.RED+"FAILED"+Fore.RESET])

            try:
                if dg["RadiusState1"] != "enabled":
                    dg_data.append(["DomainGroup","RadiusState1",dg["RadiusState1"],"enabled",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    try:
                        if dg["RadiusAuthHost1"] != "10.0.1.140" or dg["RadiusAuthPassword1"] != "crypt:2cb46e2cdf973ce030319173664f6add90330ae34f71dc74":
                            dg_data.append(["DomainGroup","RadiusAuthHost1/Password1",dg["RadiusAuthHost1"]+"/"+"crypt paswd","10.0.1.140/<Look in passpack>",Fore.RED+"FAILED"+Fore.RESET])
                        else:
                            dg_data.append(["DomainGroup", "RadiusAuthHost1/Password1",dg["RadiusAuthHost1"]+"/"+"crypt paswd","10.0.1.140/<Look in passpack>", "PASSED"])
                    except Exception as e:
                        dg_data.append(["DomainGroup","RadiusAuthHost1/Password1","NA or set at Server Template","10.0.1.140/<Look in passpack>",Fore.RED+"FAILED"+Fore.RESET])
            except Exception as e:
                dg_data.append(["DomainGroup","RadiusState1","Not Configured","enabled",Fore.RED+"FAILED"+Fore.RESET])

            try:
                if dg["RadiusState2"] != "enabled":
                    dg_data.append(["DomainGroup","RadiusState2",dg["RadiusState2"],"enabled",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    try:
                        if dg["RadiusAuthHost2"] != "10.0.201.85" or dg["RadiusAuthPassword2"] != "crypt:2cb46e2cdf973ce030319173664f6add90330ae34f71dc74":
                            dg_data.append(["DomainGroup","RadiusAuthHost2/Password2",dg["RadiusAuthHost2"]+"/"+"crypt paswd","10.0.201.85/<Look in passpack>",Fore.RED+"FAILED"+Fore.RESET])
                        else:
                            dg_data.append(["DomainGroup", "RadiusAuthHost2/Password2",dg["RadiusAuthHost2"]+"/"+"crypt paswd","10.0.201.85/<Look in passpack>", "PASSED"])
                    except Exception as e:
                        print(e)
                        dg_data.append(["DomainGroup","RadiusAuthHost2/Password2","NA or set at Server Template","10.0.201.85/<Look in passpack>",Fore.RED+"FAILED"+Fore.RESET])
            except Exception as e:
                dg_data.append(["DomainGroup","RadiusState2","Not Configured","enabled",Fore.RED+"FAILED"+Fore.RESET])



            try:
                if not dg["IPPools"]:
                    dg_data.append(["DomainGroup","IPPools",dg["IPPools"]["IPPool"],"Pool details should be complete",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    if not isinstance(dg["IPPools"]["IPPool"],list):
                        dg_data.append(["DomainGroup", "IPPools", dg["IPPools"]["IPPool"]["PoolNr"] + "/" + (dg["IPPools"]["IPPool"]["PoolBegin"] + "-" + dg["IPPools"]["IPPool"]["PoolEnd"]), "Pool details should be complete","PASSED"])
                    elif len(dg["IPPools"]["IPPool"]) > 1:
                        errors_list.append("IP Pool should not be more than 1")
                        for i in range(len(dg["IPPools"]["IPPool"])):
                            #print(i)
                            dg_data.append(["DomainGroup", "IPPools", dg["IPPools"]["IPPool"][i]["PoolNr"] + "/" + (dg["IPPools"]["IPPool"][i]["PoolBegin"] + "-" + dg["IPPools"]["IPPool"][i]["PoolEnd"]), "Pool details should be complete","PASSED"])
                    else:
                        dg_data.append(["DomainGroup","IPPools","Not Configured","Pool details should be complete",Fore.RED+"FAILED"+Fore.RESET])                        
            except Exception as e:
                dg_data.append(["DomainGroup","IPPools","Not Configured","Pool details should be complete",Fore.RED+"FAILED"+Fore.RESET])



            try:
                if dg["IPPools"]:
                    flag = 0
                    if not "None" in local_subnet[nexus]:
                        if not isinstance(dg["IPPools"]["IPPool"],list):
                            for subnet in local_subnet[nexus]:
                                if ipaddress.ip_address(dg["IPPools"]["IPPool"]["PoolBegin"]) in ipaddress.ip_network(subnet) and ipaddress.ip_address(dg["IPPools"]["IPPool"]["PoolEnd"]) in ipaddress.ip_network(subnet):
                                    dg_data.append(["Network Test","IPPool","IPs are part of ANMC subnet "+ subnet,"IPs should be part of ANMC subnet","PASSED"])
                                    flag = 1
                            if flag == 0:
                                dg_data.append(["Network Test","IPPool","IPs are not part of ANMC subnet "+ subnet,"IPs shoudl be part of ANMC subnet",Fore.RED+"FAILED"+Fore.RESET])
                        else:
                            for i in range(len(dg["IPPools"]["IPPool"])):
                                flag = 0
                                for subnet in local_subnet[nexus]:
                                    if ipaddress.ip_address(dg["IPPools"]["IPPool"][i]["PoolBegin"]) in ipaddress.ip_network(subnet) and ipaddress.ip_address(dg["IPPools"]["IPPool"][i]["PoolEnd"]) in ipaddress.ip_network(subnet):
                                        dg_data.append(["Network Test","IPPool","Pool "+dg["IPPools"]["IPPool"][i]["PoolNr"]+" IPs are part of ANMC subnet "+ subnet,"Pool "+dg["IPPools"]["IPPool"][i]["PoolNr"]+" IPs should be part of ANMC subnet","PASSED"])
                                        flag = 1
                                if flag == 0:
                                    dg_data.append(["Network Test","IPPool","Pool "+dg["IPPools"]["IPPool"][i]["PoolNr"]+" IPs are not part of ANMC subnet "+ subnet,"Pool "+dg["IPPools"]["IPPool"][i]["PoolNr"]+" IPs shoudl be part of ANMC subnet",Fore.RED+"FAILED"+Fore.RESET])

            except Exception as e:
                #print(e)
                errors_list.append(e)


            try:
                if dg["IPPools"]:
                    if not isinstance(dg["IPPools"]["IPPool"],list):
                        if int(dg["IPPools"]["IPPool"]["PoolNr"]) > 0 and ipaddress.ip_address(dg["IPPools"]["IPPool"]["PoolBegin"]) < ipaddress.ip_address(dg["IPPools"]["IPPool"]["PoolEnd"]):
                            dg_data.append(["Network Test","IPPool","Begin IP comes before End IP","Begin IP comes before End IP","PASSED"])
                        else:
                            dg_data.append(["Network Test","IPPool","Begin IP comes after End IP","Begin IP comes before End IP",Fore.RED+"FAILED"+Fore.RESET])
                    else:
                        for i in range(len(dg["IPPools"]["IPPool"])):
                            if int(dg["IPPools"]["IPPool"][i]["PoolNr"]) > 0 and ipaddress.ip_address(dg["IPPools"]["IPPool"][i]["PoolBegin"]) < ipaddress.ip_address(dg["IPPools"]["IPPool"][i]["PoolEnd"]):
                                dg_data.append(["Network Test","IPPool","Pool "+dg["IPPools"]["IPPool"][i]["PoolNr"]+" Begin IP comes before End IP","Pool "+dg["IPPools"]["IPPool"][i]["PoolNr"]+" Begin IP comes before End IP","PASSED"])
                            else:
                                dg_data.append(["Network Test","IPPool","Pool "+dg["IPPools"]["IPPool"][i]["PoolNr"]+" Begin IP comes after End IP","Pool "+dg["IPPools"]["IPPool"][i]["PoolNr"]+" Begin IP comes before End IP",Fore.RED+"FAILED"+Fore.RESET])
            except Exception as e:
                #print(e)
                errors_list.append(e)

            try:
                if dg["RadiusForwardEAP"] != "enabled":
                    dg_data.append(["DomainGroup","RadiusForwardEAP",dg["RadiusForwardEAP"],"enabled",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    dg_data.append(["DomainGroup", "RadiusForwardEAP", dg["RadiusForwardEAP"], "enabled", "PASSED"])
            except Exception as e:
                dg_data.append(["DomainGroup", "RadiusForwardEAP", "Not Configured", "enabled", Fore.RED+"FAILED"+Fore.RESET])

            try:
                if not dg["VpnEndpoint"] or pop not in dg["VpnEndpoint"] or str(nexus) not in dg["VpnEndpoint"]:
                    dg_data.append(["DomainGroup","VpnEndpoint",dg["VpnEndpoint"],"VpnEndpoint should have same pop LinkProfile",Fore.RED+"FAILED"+Fore.RESET])
                else:
                    dg_data.append(["DomainGroup", "VpnEndpoint", dg["VpnEndpoint"], "VpnEndpoint should have same pop LinkProfile","PASSED"])
            except Exception as e:
                dg_data.append(["DomainGroup","VpnEndpoint","Not Configured","VpnEndpoint should have same pop LinkProfile",Fore.RED+"FAILED"+Fore.RESET])

    return(dg_data)

## function to report errors to Admin
def report_admin(func,err,err_list):
    try:
        url = 'https://hook.eu1.make.com/b6d397uv8573gmpvac99g9raa7kadapd'
        headers = {'Content-Type': 'application/json'}
        user = os.getlogin()

        payload = json.dumps({
            "func" : func,
            "err" : str(err),
            "err_list" : err_list,
            "user" : user
        })
        response = requests.request("POST", url, headers=headers,verify=False,data=payload)
    except Exception as e:
        print(e)
        exit(1)


## Main function starts here
def main_starts_here() -> None:

    try:
        global errors_list
        errors_list = []
    #clear screen
        if (os.name == 'posix'):
            os.system('clear')
        else:
            os.system('cls')
    #getting user input and validating
        input = get_user_input()

    #get arvpn_id to nexus mapping
        arvpn_dict,cust_code,cust_id,local_subnet,site_name = find_arvpnID_mapping(input)

    #get vpn tunnel status
        tunnel_info = get_vpn_tunnel_status(input,cust_id)


    #get arvpn_id to arvpn server mapping
        final_data = find_arvpn_server(arvpn_dict)
        #print(final_data)

        t = Texttable(max_width=0)
        t.set_deco(Texttable.HEADER | Texttable.BORDER | Texttable.VLINES)

        now = datetime.now()
        now_converted = now.strftime("%d_%m_%Y@%H_%M")
        file = "result-{}.csv".format(now_converted)
        #print(file)
        f = open(file,'w+')
        #print(f)
        writer = csv.writer(f)


    ## iterating over each nexus and its server to fetch data
        for nexus,arvpn_server in final_data.items():
            global_list = []
            link_profiles = []
            domain_groups = []
            device = {
                "device_type": "linux",
                "host": arvpn_server,
                "use_keys": True,
            #    "key_file" : "<provide path to your private key>",
            #    "ssh_config_file" : "$HOME/.ssh/config",
                "key_file" : user_data.key_file,
                "ssh_config_file": user_data.ssh_config_file,
            }

            #if device['key_file'] == "<provide path to your private key>" or device['key_file'] == "":
            #    exit("Your private key is not present. Please update and retry. Thanks!!")


            try:
                with ConnectHandler(**device) as net_connect:
                    try:
                        output = net_connect.send_command("sudo cat /opt/ncp/ses/etc/cfg/srvlx.conf", read_timeout=10)
                        data = jc.parse('xml', output)
                        out_dict = dict(data)
                        pop = arvpn_server.split(".")[1]
                        try:
                            #print("\nFetching and validating Link Profile for nexus {}".format(nexus))
                            link_profiles = validate_link_profile(out_dict["ServerConfiguration"]["LinkProfiles"]["LinkProfile"], nexus,pop,cust_code,tunnel_info)
                        except Exception as e:
                            print(e)
                            errors_list.append("unable to find matching Link Profiles on server {} for nexus {}".format(arvpn_server, nexus))
                        global_list = global_list + link_profiles


                        # get domain-groups and scrub data
                        try:
                            #print("Fetching and validating Domain Group for nexus {}".format(nexus))
                            domain_groups = validate_domain_group(out_dict["ServerConfiguration"]["DomainGroups"]["DomainGroup"], nexus,pop,cust_code,tunnel_info,local_subnet)
                        except Exception as e:
                            print(e)
                            errors_list.append("unable to find matching Domain Groups on server {} for nexus {}".format(arvpn_server, nexus))
                        global_list = global_list + domain_groups

                    except Exception as e:
                        print(e)
                        errors_list.append(e)

                writer.writerow(["****NEXUS:{}****".format(nexus)])
                print("\n")
                print(Back.GREEN+"****NEXUS:{}****".format(nexus)+Back.RESET)
                print("Site Info:")
                print("Customer_ID: {}".format(cust_id[nexus]))
                print("Name: {}".format(site_name[nexus]))
                print("Tunnel_Status: {}".format(tunnel_info[nexus]))
                if "None" in local_subnet[nexus]:
                    print("Local_Subnet: {}".format(local_subnet[nexus]))
                else:
                    print("Local_Subnet: {}".format(*local_subnet[nexus],sep=", "))
                #print("==============================================================================================================================================")
                global_list.insert(0, ["TYPE", "SECTION", "CONFIGURED", "EXPECTED", "VALIDATION"])
                t.reset()
                t.add_rows(global_list)
                writer.writerows(global_list)
                writer.writerow([""])
                writer.writerow(["#########","#########","#########","#########","#########","#########"])
                print(t.draw())
            except Exception as e:
                print(e)
                #pprint(device)
                print("**Unable to ssh {}**.\n->Please check your if Private key and ASA Proxy path is updated.\nCurrent Config:\n->Key = {}\n->ProxyPath = {}".format(device["host"],device["key_file"],device["ssh_config_file"]))
                errors_list.append("Unable to ssh {}".format(device["host"]))



        writer.writerow(["Errors:"])
        print("Errors:")
        if len(errors_list) == 0:
            writer.writerow(["No additional errors"])
            print("No additional errors")
            print("NOTE: This tool cannot validate PSK since its saved in cryptic format")
            print("NOTE: This tool cannot validate client config since its stored in db and not cannot be parsed")
        else:
            for error in errors_list:
                print(error)
                writer.writerow(error)
            print("NOTE: This tool cannot validate PSK since its saved in cryptic format")
            print("NOTE: This tool cannot validate client config since its stored in db and not cannot be parsed")
        f.close()

    except KeyboardInterrupt:
        print("\nKeyBoard Interrupt by user.....")
        exit(1)


## code starting point to check key_file and ssh_config_file.
if __name__ == "__main__":
    try:
        init()
        #R = "\033[0;31;40m"
        #N = '\033[0m'
        
        try:
            user_data.key_file
        except AttributeError:
            exit("key_file variable for private key is required in user_data. Please Check!!!")

        try:
            user_data.ssh_config_file
        except AttributeError:
            exit("ssh_config_file variable for proxy path is required in user_data.\nDefault Path is:$HOME/.ssh/config. Please Check!!!")

    ## checking remote repo for updates
        try:
            repo = git.Repo('.')
            current = repo.head.commit
            repo.remotes.origin.pull()
            if current != repo.head.commit:
                exit("Your script has been auto-updated. Check Confluence for newly added updates.\nYou can re-run the script to perform validation!!\n")
        except Exception as e:
            print(e)
            exit("Error in pulling repo from remote origin.\n Have you modified the file locally? or moved script to different path?\nIf yes, please delete folder and re-do steps mentioned in confluence")


    #call main function
        main_starts_here()

        try:
            run_again = str(input("\nWant to run again for different nexus?(y/n):")).lower()
            if run_again.startswith('y') or run_again == 'ok':
                main_starts_here()
            elif run_again.startswith('n'):
                exit("Got it!! BYE!!")
            else:
                exit("Can't understand. BYE!!")

        except KeyboardInterrupt:
            print("\nKeyBoard Interrupt by user.....")
            exit(1)

        except Exception as e:
            print(e)
            exit("Invalid input format.BYE!!")

    except KeyboardInterrupt:
        print("\nKeyBoard Interrupt by user.....")
        exit(1)







