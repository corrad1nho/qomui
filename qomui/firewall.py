import json
import shlex
import os
import logging
from subprocess import check_call, check_output, CalledProcessError, Popen, PIPE
from collections import Counter

from qomui import config

saved_rules = []
saved_rules_6 = []
devnull = open(os.devnull, 'w')
ip6_available = True


def check_ipv6():
    try:
        ipv6_info = open("/proc/net/if_inet6", "r").read()
        if ipv6_info:
            return True

        else:
            logging.info("ipv6 stack not available")
            return False

    except (OSError, FileNotFoundError) as e:
        logging.debug("Unable to determine whether ipv6 is available")
        return True


def add_rule(rule, check=0, ipt="ip4"):
    if ipt == "ip4":
        ip_cmd = ["iptables", "--wait", ]
    else:
        ip_cmd = ["ip6tables", "--wait", ]

    if ipt == "ip4" or check == 1 or check_ipv6() is True:
        # check if rule already exists and only set it otherwise
        try:
            if len(rule) > 3 or "-D" not in rule:
                check = ["-C" if x == "-A" or x == "-I" else x for x in rule]
                check_call(ip_cmd + check, stdout=devnull, stderr=devnull)
                logging.debug("iptables: {} already exists".format(rule))

            else:
                raise IndexError

        except (IndexError, CalledProcessError):
            try:
                check_call(ip_cmd + rule, stdout=devnull, stderr=devnull)
                logging.debug("iptables: applied {}".format(ip_cmd + rule))

            except CalledProcessError:
                logging.warning("iptables: failed to apply {}".format(ip_cmd + rule))


def apply_rules(opt, block_lan=0, preserve=0):
    fw_rules = get_config()
    if opt != 2:
        batch_rule(fw_rules["flush"])
        batch_rule_6(fw_rules["flushv6"])

    logging.info("iptables: flushed existing rules")

    if preserve == 1:
        save_existing_rules(fw_rules)
        save_existing_rules_6(fw_rules)
        batch_rule(saved_rules)
        batch_rule_6(saved_rules_6)

    if opt == 1:
        batch_rule(fw_rules["defaults"])
        batch_rule_6(fw_rules["defaultsv6"])

        if block_lan == 0:
            batch_rule(fw_rules["ipv4local"])
            batch_rule_6(fw_rules["ipv6local"])

        batch_rule(fw_rules["ipv4rules"])
        batch_rule_6(fw_rules["ipv6rules"])
        logging.info("iptables: activated firewall")

    elif opt == 0:
        batch_rule(fw_rules["unsecure"])
        batch_rule_6(fw_rules["unsecurev6"])
        logging.info("iptables: deactivated firewall")


def batch_rule(rules):
    for rule in rules:
        add_rule(rule)


def batch_rule_6(rules):
    if check_ipv6() is True:
        for rule in rules:
            add_rule(rule, check=1, ipt="ip6")


def save_existing_rules(fw_rules):
    try:
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

    except (CalledProcessError, FileNotFoundError) as e:
        logging.error("ip4tables: Could not read active rules - {}".format(e))


def save_existing_rules_6(fw_rules):
    if check_ipv6() is True:
        try:
            existing_rules = check_output(["ip6tables", "-S"]).decode("utf-8")
            for line in existing_rules.split('\n'):
                rpl = line.replace("/32", "")
                rule = shlex.split(rpl)
                if len(rule) != 0:
                    match = 0
                    omit = fw_rules["ipv6rules"] + \
                        fw_rules["flushv6"] + fw_rules["ipv6local"]
                    for x in omit:
                        if Counter(x) == Counter(rule):
                            match = 1
                    if match == 0 and rule not in saved_rules_6:
                        saved_rules_6.append(rule)
                    match = 0

        except (CalledProcessError, FileNotFoundError) as e:
            logging.error(
                "ip6tables: Could not read active rules - {}".format(e))


def allow_dest_ip(ip, action):
    rule = [action, 'OUTPUT', '-d', ip, '-j', 'ACCEPT']

    try:
        if len(ip.split(".")) == 4:
            add_rule(rule)

        elif len(ip.split(":")) >= 4:
            if check_ipv6() is True:
                add_rule(rule, ipt="ip6")
    except BaseException:
        logging.error("{} is not a valid ip address".format(ip))


def get_config():
    try:
        with open("{}/firewall.json".format(config.ROOTDIR), "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.decoder.JSONDecodeError) as e:
        logging.info("Loading default firewall configuration")
        try:
            with open("{}/firewall_default.json".format(config.ROOTDIR), "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.decoder.JSONDecodeError) as e:
            logging.debug("Failed to load firewall configuration")
            return None


def check_firewall_services():
    firewall_services = ["ufw", "firewalld"]
    detected_firewall = []

    for fw in firewall_services:

        try:
            result = check_output(
                ["systemctl", "is-enabled", fw],
                stderr=devnull).decode("utf-8")

            if result == "enabled\n":
                detected_firewall.append(fw)
                logging.warning(
                    "Detected enable firewall service: {}".format(fw))

            else:
                logging.debug("{}.service is not enabled".format(fw))

        except (FileNotFoundError, CalledProcessError) as e:
            logging.debug(
                "{}.service does either not exist or is not enabled".format(fw))

    return detected_firewall


def save_iptables():
    try:
        outfile = open("{}/iptables_before.rules".format(config.ROOTDIR), "w")
        save = Popen(["iptables-save"], stdout=outfile, stderr=PIPE)
        save.wait()
        outfile.flush()
        logging.debug("Saved iptables rules")

    except (CalledProcessError, FileNotFoundError):
        logging.debug("Failed to save current iptables rules")

    if check_ipv6() is True:

        try:
            outfile6 = open("{}/ip6tables_before.rules".format(config.ROOTDIR), "w")
            save6 = Popen(["ip6tables-save"], stdout=outfile, stderr=PIPE)
            save6.wait()
            outfile6.flush()
            logging.debug("Saved ip6tables rules")

        except (CalledProcessError, FileNotFoundError):
            logging.debug("Failed to save current ip6tables rules")


def restore_iptables():
    try:
        restore = Popen(
            ["iptables-restore", "{}/iptables_before.rules".format(config.ROOTDIR)],
            stderr=PIPE)
        logging.debug("Restored previous iptables rules")

    except (CalledProcessError, FileNotFoundError):
        logging.debug("FileNotFoundError: Failed to restore iptables rules")

    if check_ipv6() is True:

        try:
            restore = Popen(["ip6tables-restore",
                             "{}/ip6tables_before.rules".format(config.ROOTDIR)],
                            stderr=PIPE)
            logging.debug("Restored previous ip6tables rules")

        except (CalledProcessError, FileNotFoundError):
            logging.debug(
                "FileNotFoundError: Failed to restore ip6tables rules")
