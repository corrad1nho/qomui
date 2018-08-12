import json
import shlex
import os
import logging
from subprocess import check_call, check_output, CalledProcessError
from collections import Counter

ROOTDIR = "/usr/share/qomui"
saved_rules = []
saved_rules_6 = []
ip_cmd = ["iptables", "--wait",]
ip6_cmd = ["ip6tables", "--wait",]
devnull = open(os.devnull, 'w')

def add_rule(rule):
    a = 1
    try:
        check = rule[:]
        if "-D" not in check:
            if check[0] == "-A":
                check[0] = "-C"
            elif check[0] == "-I":
                check[0] = "-C"
                check.pop(2)
            elif check[2] == "-A":
                check[2] = "-C"
            check_call(ip_cmd + check, stdout=devnull, stderr=devnull)
            logging.debug("iptables: %s already exists" %rule)
            a = 0
    except (IndexError, CalledProcessError):
        pass

    try:
        if a == 1:
            check_call(ip_cmd + rule, stdout=devnull, stderr=devnull)
            logging.debug("iptables: applied %s" %rule)

    except CalledProcessError:
        if "-D" not in rule:
            logging.warning("iptables: failed to apply %s" %rule)

def add_rule_6(rule):
    a = 1
    try:
        check = rule[:]
        if "-D" not in check:
            if check[0] == "-A":
                check[0] = "-C"
            elif check[0] == "-I":
                check[0] = "-C"
                check.pop(2)
            elif check[2] == "-A":
                check[2] = "-C"
            check_call(ip6_cmd + check, stdout=devnull, stderr=devnull)
            logging.debug("ipt6ables: %s already exists" %rule)
            a = 0
    except (IndexError, CalledProcessError):
        pass

    try:
        if a == 1:
            check_call(ip6_cmd + rule, stdout=devnull, stderr=devnull)
            logging.debug("ip6tables: applied %s" %rule)

    except CalledProcessError:
        if "-D" not in rule:
            logging.warning("ip6tables: failed to apply %s" %rule)

def apply_rules(opt, block_lan=0, preserve=0):
    fw_rules = get_config()
    save_existing_rules(fw_rules)
    save_existing_rules_6(fw_rules)

    for rule in fw_rules["flush"]:
        add_rule(rule)

    for rule in fw_rules["flushv6"]:
        add_rule_6(rule)

    logging.info("iptables: flushed existing rules")

    for rule in saved_rules:
        if preserve == 1:
            add_rule(rule)

    for rule in saved_rules_6:
        if preserve == 1:
            add_rule_6(rule)

    if opt == 1:
        for rule in fw_rules["defaults"]:
            add_rule(rule)

        if block_lan == 0:
            for rule in fw_rules["ipv4local"]:
                add_rule(rule)

            for rule in fw_rules["ipv6local"]:
                add_rule_6(rule)

        for rule in fw_rules["defaultsv6"]:
            add_rule_6(rule)

        for rule in fw_rules["ipv4rules"]:
            add_rule(rule)

        for rule in fw_rules["ipv6rules"]:
            add_rule_6(rule)

        logging.info("iptables: activated firewall")

    elif opt == 0:
        for rule in fw_rules["unsecure"]:
            add_rule(rule)

        for rule in fw_rules["unsecurev6"]:
            add_rule_6(rule)

        logging.info("iptables: deactivated firewall")

def save_existing_rules(fw_rules):
    existing_rules = check_output(["iptables", "-S"]).decode("utf-8")
    for line in existing_rules.split('\n'):
        rpl = line.replace("/32", "")
        rule = shlex.split(rpl)
        if len(rule) != 0:
            match = 0
            omit = fw_rules["ipv4rules"] + fw_rules["flush"] + fw_rules["ipv4local"]
            for x in omit:
                if Counter(x) == Counter(rule):
                    match = 1
            if match == 0 and rule not in saved_rules:
                saved_rules.append(rule)
            match = 0

def save_existing_rules_6(fw_rules):
    existing_rules = check_output(["ip6tables", "-S"]).decode("utf-8")
    for line in existing_rules.split('\n'):
        rpl = line.replace("/32", "")
        rule = shlex.split(rpl)
        if len(rule) != 0:
            match = 0
            omit = fw_rules["ipv6rules"] + fw_rules["flushv6"] + fw_rules["ipv6local"]
            for x in omit:
                if Counter(x) == Counter(rule):
                    match = 1
            if match == 0 and rule not in saved_rules_6:
                saved_rules_6.append(rule)
            match = 0

def get_config():
    try:
        with open("%s/firewall.json" %ROOTDIR, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.decoder.JSONDecodeError) as e:
        logging.debug("Loading default firewall configuration")
        try:
            with open("%s/firewall_default.json" %ROOTDIR, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.decoder.JSONDecodeError) as e:
            logging.debug("Failed to load firewall configuration")
            return None
