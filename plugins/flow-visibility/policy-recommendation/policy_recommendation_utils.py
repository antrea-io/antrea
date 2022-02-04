# Copyright 2022 Antrea Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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