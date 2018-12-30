#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import grp
import getpass
import pwd

SUPPORTED_PROVIDERS = ["Airvpn", "Mullvad", "ProtonVPN", "PIA", "Windscribe"]

def get_user_group():
    username = getpass.getuser()
    group = grp.getgrgid(pwd.getpwnam(username).pw_gid).gr_name
    return {"user" : username, "group" : group}

def create_server_dict(current_dict, protocol_dict):
    provider = current_dict["provider"]
    if provider in SUPPORTED_PROVIDERS:

        try:
            mode = protocol_dict[provider]["selected"]
        except KeyError:
            mode = "protocol_1"

        port = protocol_dict[provider][mode]["port"]
        protocol = protocol_dict[provider][mode]["protocol"]

        if provider == "Airvpn":
            if protocol_dict["Airvpn"][mode]["ipv6"] == "ipv6":
                ipv6 = "on"
            else: 
                ipv6 = "off"

            try:
                ip_chosen = protocol_dict["Airvpn"][mode]["ip"]

                if ip_chosen == "ip3" or ip_chosen == "ip4":
                    tlscrypt = "on"
                else:
                    tlscrypt = "off"

                if ipv6 == "on":
                    ip = current_dict["{}_6".format(ip_chosen)]
                else:
                    ip = current_dict[ip_chosen]

            except KeyError:
                ip = current_dict["ip1"]

            current_dict.update({"ip" : ip, "port": port, "protocol": protocol, 
                                    "prot_index": mode, "ipv6" : ipv6, "tlscrypt" : tlscrypt})

        elif provider == "Mullvad":
            try:
                if current_dict["tunnel"] == "WireGuard":
                    current_dict.update({"port": "51820", "protocol": "UDP"})
                else:
                    current_dict.update({"port": port, "protocol": protocol, "prot_index": mode})

            except KeyError:
                current_dict.update({"port": port, "protocol": protocol, "prot_index": mode})

        elif provider == "Windscribe":
            if protocol == "SSL":
                ip = current_dict["ip2"]
                current_dict.update({"port": port, "protocol": protocol, "prot_index": mode, "ip" : ip})

            else:
                current_dict.update({"port": port, "protocol": protocol, "prot_index": mode})
        else:
            current_dict.update({"port": port, "protocol": protocol, "prot_index": mode})

    else:
        try: 
            port = protocol_dict[provider]["port"]
            protocol = protocol_dict[provider]["protocol"]
            current_dict.update({"port": port, "protocol": protocol})
        except KeyError:
            pass

    return current_dict
