#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json

ROOTDIR = "/usr/share/qomui"
HOMEDIR = "{}/.qomui".format(os.path.expanduser("~"))
SUPPORTED_PROVIDERS = ["Airvpn", "AzireVPN", "Mullvad", "PIA", "ProtonVPN", "Windscribe"]
LOGDIR = "/usr/share/qomui/logs"
OPATH = "/org/qomui/service"
IFACE = "org.qomui.service"
BUS_NAME = "org.qomui.service"

default_settings = {
    "alt_dns1": "208.67.222.222",
    "alt_dns2": "208.67.220.220",
    "firewall": 0,
    "autoconnect": 0,
    "minimize": 0,
    "ipv6_disable": 0,
    "alt_dns": 0,
    "no_dnsmasq": 0,
    "dns_off": 0,
    "bypass": 0,
    "ping": 0,
    "auto_update": 0,
    "block_lan": 0,
    "preserve_rules": 0,
    "fw_gui_only": 0,
    "log_level": "Info"
}


def load_config():
    global settings

    try:
        with open('{}/config.json'.format(ROOTDIR), 'r') as c:
            settings = json.load(c)
            for k, v in default_settings.items():
                if k not in settings.keys():
                    settings[k] = v

    except (FileNotFoundError, json.decoder.JSONDecodeError) as e:
        settings = default_settings
