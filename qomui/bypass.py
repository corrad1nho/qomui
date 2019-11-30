#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
from subprocess import check_call, CalledProcessError

from qomui import firewall

cgroup_path = "/sys/fs/cgroup/net_cls/bypass_qomui"
cls_id = "0x00110011"
interface = None

def create_cgroup(user, group, interface, gw=None,  gw_6=None, default_int=None, no_dnsmasq=0):

    logging.info("Creating bypass for {}".format(interface))
    delete_cgroup(default_int)
    cgroup_iptables = [
        ["-t", "mangle", "-A", "OUTPUT", "-m", "cgroup",
         "--cgroup", "0x00110011", "-j", "MARK", "--set-mark", "11"],
        ["-t", "nat", "-A", "POSTROUTING", "-m", "cgroup",
         "--cgroup", "0x00110011", "-o", "{}".format(interface), "-j", "MASQUERADE"],
        ["-I", "OUTPUT", "1", "-m", "cgroup",
         "--cgroup", "0x00110011", "-j", "ACCEPT"],
        ["-I", "INPUT", "1", "-m", "cgroup",
         "--cgroup", "0x00110011", "-j", "ACCEPT"]
        ]

    if no_dnsmasq == 0:
        cgroup_iptables.append(
            ["-t", "nat", "-A", "OUTPUT", "-m", "cgroup", "--cgroup",
            "0x00110011", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5354"]
            )
        cgroup_iptables.append(
            ["-t", "nat", "-A", "OUTPUT", "-m", "cgroup", "--cgroup",
            "0x00110011", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5354"]
            )

    if not os.path.exists(cgroup_path):
        os.makedirs(cgroup_path)
        with open("{}/net_cls.classid".format(cgroup_path), 'w') as setcid:
            setcid.write(cls_id)
            setcid.close()
            logging.debug("Bypass: Created cgroup 'net_cls:bypass_qomui'")

    
    with open("/etc/iproute2/rt_tables") as rt_check:
        if "11 bypass_qomui" not in rt_check.read():
            rt_check.close()
            with open("/etc/iproute2/rt_tables", "a") as rt_tables:
                rt_tables.write("11 bypass_qomui\n")
            logging.debug("Bypass: Created new routing table")

        else:
            rt_check.close()
            logging.debug("Bypass: No routing table added - table bypass_qomui already exists")

    firewall.batch_rule(cgroup_iptables)
    if gw_6 != "None" and default_int == interface:
        firewall.batch_rule_6(cgroup_iptables)

    else:
        logging.debug("Blocking ipv6 via bypass_qomui")
        cgroup_iptables.pop(1)
        cgroup_iptables.insert(1, ["-t", "nat", "-A", "POSTROUTING", "-m", "cgroup",
                                   "--cgroup", "0x00110011", "-o", "{}".format(interface), "-j", "MASQUERADE"])
        cgroup_iptables.pop(2)
        cgroup_iptables.insert(2, ["-I", "OUTPUT", "1", "-m", "cgroup", "--cgroup", "0x00110011", "-j", "DROP"])
        cgroup_iptables.pop(3)
        cgroup_iptables.insert(3, ["-I", "INPUT", "1", "-m", "cgroup", "--cgroup", "0x00110011", "-j", "DROP"])
        firewall.batch_rule_6(cgroup_iptables)

    try:
        check_call(["ip", "rule", "add", "fwmark", "11", "table", "bypass_qomui"])
        if interface == default_int:
            check_call(["ip", "route", "flush", "table", "bypass_qomui"])
            check_call(["ip", "rule", "add", "fwmark", "11", "table", "bypass_qomui"])
            check_call(["ip", "route", "add", "default", "via",
                        "{}".format(gw), "dev", "{}".format(interface), "table", "bypass_qomui"])
            logging.debug("Bypass: Set ipv4 route 'default via {} dev {}'".format(gw, interface))
    except CalledProcessError:
        logging.error("Bypass: Failed to set ipv4 route 'default via {} dev {}'".format(gw, interface))

    try:
        check_call(["ip", "-6", "rule", "add", "fwmark", "11", "table", "bypass_qomui"])
        if interface == default_int:
            check_call(["ip", "-6", "route", "flush", "table", "bypass_qomui"])
            check_call(["ip", "-6", "route", "add", "default", "via",
                        "{}".format(gw_6), "dev", "{}".format(interface), "table", "bypass_qomui"])
            logging.debug("Bypass: Set ipv6 route 'default via {} dev {}'".format(gw_6, interface))
    except CalledProcessError:
        logging.error("Bypass: Failed to set ipv6 route 'default via {} dev {}' failed".format(gw, interface))

    with open("/proc/sys/net/ipv4/conf/all/rp_filter", 'w') as rp_edit_all:
        rp_edit_all.write("2")

    try:
        with open("/proc/sys/net/ipv4/conf/{}/rp_filter".format(interface), 'w') as rp_edit_int:
            rp_edit_int.write("2")
            logging.debug("Disabled reverse path filtering for {}".format(interface))
    except FileNotFoundError:
        logging.error("Failed to disable reverse path filtering for {}".format(interface))

    try:
        check_call(["cgcreate", "-t", "{}:{}".format(user, group), "-a" "{}:{}".format(user, group), "-g", "net_cls:bypass_qomui"])
        logging.debug("Bypass: Configured cgroup access for {}".format(user))
        logging.info("Successfully created cgroup for {}".format(interface))

    except (CalledProcessError, FileNotFoundError) as e:
        logging.error("Creating cgroup failed - is libcgroup installed?")

def delete_cgroup(interface):

    cgroup_iptables_del = [
        ["-t", "mangle", "-D", "OUTPUT", "-m", "cgroup",
         "--cgroup", "0x00110011", "-j", "MARK", "--set-mark", "11"],
        ["-t", "nat", "-D", "POSTROUTING", "-m", "cgroup",
         "--cgroup", "0x00110011", "-o", "{}".format(interface), "-j", "MASQUERADE"],
        ["-D", "OUTPUT", "-m", "cgroup",
         "--cgroup", "0x00110011", "-j", "ACCEPT"],
        ["-D", "INPUT", "-m", "cgroup",
         "--cgroup", "0x00110011", "-j", "ACCEPT"],
        ["-t", "nat", "-D", "OUTPUT", "-m", "cgroup", "--cgroup",
         "0x00110011", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5354"],
        ["-t", "nat", "-D", "OUTPUT", "-m", "cgroup", "--cgroup",
         "0x00110011", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5354"]
        ]

    try:
        check_call(["ip", "rule", "del", "fwmark", "11", "table", "bypass_qomui"])
    except CalledProcessError:
        pass

    firewall.batch_rule(cgroup_iptables_del)
    firewall.batch_rule_6(cgroup_iptables_del)

    try:
        os.rmdir(cgroup_path)

    except (OSError, FileNotFoundError):
        logging.debug("Bypass: Could not delete {} - resource does not exist or is busy".format(cgroup_path))

    logging.info("Deleted cgroup")

def set_bypass_vpn(interface, interface_cmd, tun, tun_cmd):
    postroutes =   [[
                    "-t", "nat", tun_cmd, "POSTROUTING",
                    "-m", "cgroup", "--cgroup", "0x00110011",
                    "-o", tun, "-j", "MASQUERADE"
                    ],
                    [
                    "-t", "nat", interface_cmd, "POSTROUTING",
                    "-m", "cgroup", "--cgroup", "0x00110011",
                    "-o", interface, "-j", "MASQUERADE"
                    ]]

    firewall.batch_rule(postroutes)
    firewall.batch_rule_6(postroutes)


