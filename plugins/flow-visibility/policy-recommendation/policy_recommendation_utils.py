import json
import yaml

from ipaddress import ip_address, IPv4Address
from re import sub

def get_IP_version(IP):
    return "v4" if type(ip_address(IP)) is IPv4Address else "v6"

def camel(s):
    s = sub(r"(_|-)+", " ", s).title().replace(" ", "")
    return s[0].lower() + s[1:] if s else ""

def camel_dict(d):
    result = {}
    for key, value in d.items():
        if isinstance(value, list):
            result[camel(key)] = list(map(
                lambda x: camel_dict(x) if isinstance(x, dict) else x, value
            ))
        elif isinstance(value, dict) and key != "match_labels":
            result[camel(key)] = camel_dict(value)
        elif value != None:
            result[camel(key)] = value
    return result

def dict_to_yaml(d):
    return yaml.dump(yaml.load(json.dumps(camel_dict(d)), Loader=yaml.FullLoader))