# -*- coding: utf-8 -*-
import sys

cve_name = ""
for tmp in sys.argv:
    if "CVE" in tmp:
        cve_name = "CVE" + tmp.split("CVE")[1].split(".")[0]
        print cve_name

if cve_name != "":
    import requests
    import urllib3
    from urllib3.exceptions import InsecureRequestWarning
    urllib3.disable_warnings(InsecureRequestWarning)
    import json

    host = "https://app.deepsecurity.trendmicro.com/api/"

    get_computer = host + "intrusionpreventionrules/search"

    header = {
        "api-secret-key": "406BE245-CB19-0B3D-C5AA-05B1985D7D0B:C57B8819-8FA5-3138-2903-3FA576451B37:BfJCN7hiXfgxZzvvjQlxVkSCZRPTSFSPS6WWSLswegU=",
        "api-version": "v1",
        "Content-Type": "application/json"
    }

    body = {
    "searchCriteria": [
        {
            "fieldName": "CVE",
            "stringTest": "equal",
            "stringValue": cve_name,
            }
    ],
    "sortByObjectID": True
    }

    response = requests.post(get_computer, headers=header, data=json.dumps(body), verify=False)

    rule_id_list = []
    for rule in response.json()["intrusionPreventionRules"]:
        rule_id_list.append(rule["ID"])

    get_computer = host + "computers"

    response = requests.get(get_computer, headers=header, verify=False)

    computer_id_list = []
    for computer in response.json()["computers"]:
        if computer["intrusionPrevention"]["state"] != "off":
            computer_id_list.append(computer["ID"])

    for computer_id in computer_id_list:
        get_computer = host + "computers/" + str(computer_id) + "/intrusionprevention/assignments"

        response = requests.get(get_computer, headers=header, verify=False)

        for rule_id in rule_id_list:
            for rec_rule in response.json()["recommendedToAssignRuleIDs"]:
                if rule_id == rec_rule:
                    body = {
                        "ruleIDs": [rule_id]
                    }
                    response = requests.post(get_computer, headers=header, data=json.dumps(body), verify=False)
                    print("add(host_id): ", str(computer_id))
    print("end")
