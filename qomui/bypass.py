#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
from subprocess import check_call, Popen, CalledProcessError
from qomui import firewall

cgroup_path = "/sys/fs/cgroup/net_cls/bypass_qomui"
cls_id = "0x00110011"
default_interface = None
ROOTDIR = "/usr/share/qomui/"

def create_cgroup(user, group, default_interface, default_gateway, default_interface_6, default_gateway_6):
    
    cleanup = delete_cgroup(default_interface, default_interface_6)
    
    cgroup_iptables = [["-t", "mangle", "-A", "OUTPUT", "-m", "cgroup", 
                       "--cgroup", "0x00110011", "-j", "MARK", "--set-mark", "11"],
                        ["-t", "nat", "-A", "POSTROUTING", "-m", "cgroup", 
                       "--cgroup", "0x00110011", "-o", "%s" %default_interface , "-j", "MASQUERADE"],
                        ["-I", "OUTPUT", "1", "-m", "cgroup", 
                       "--cgroup", "0x00110011", "-j", "ACCEPT"],
                        ["-I", "INPUT", "1", "-m", "cgroup", 
                       "--cgroup", "0x00110011", "-j", "ACCEPT"],
                        ["-t", "nat", "-A", "OUTPUT", "-m", "cgroup", "--cgroup", 
                         "0x00110011", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5354"],
                        ["-t", "nat", "-A", "OUTPUT", "-m", "cgroup", "--cgroup", 
                         "0x00110011", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5354"]
                        ]
    
    if not os.path.exists(cgroup_path):
        os.makedirs(cgroup_path)
        with open("%s/net_cls.classid" % cgroup_path, 'w') as setcid:
            setcid.write(cls_id)
            setcid.close()
    
    try: 
        check_call(["ip", "route", "show", "table", "bypass_qomui"])
        logging.debug("No routing table added - table bypass_qomui already exists")
    except CalledProcessError:
        with open("/etc/iproute2/rt_tables", "a") as rt_tables:
            rt_tables.write("11 bypass_qomui\n")
        logging.debug("Created new routing table - bypass_qomui")
    
    for rule in cgroup_iptables:
        firewall.add_rule(rule)
    
    if default_gateway_6 != "None":
        cgroup_iptables.pop(1)
        cgroup_iptables.insert(1, ["-t", "nat", "-A", "POSTROUTING", "-m", "cgroup", 
                        "--cgroup", "0x00110011", "-o", "%s" %default_interface_6 , "-j", "MASQUERADE"])
        
        for rule in cgroup_iptables:
            firewall.add_rule_6(rule)
            
    else:
        logging.debug("Blocking ipv6 via bypass_qomui")
        cgroup_iptables.pop(1)
        cgroup_iptables.insert(1, ["-t", "nat", "-A", "POSTROUTING", "-m", "cgroup", 
                        "--cgroup", "0x00110011", "-o", "%s" %default_interface , "-j", "MASQUERADE"])
        cgroup_iptables.pop(2)
        cgroup_iptables.insert(2, ["-I", "OUTPUT", "1", "-m", "cgroup", "--cgroup", "0x00110011", "-j", "DROP"])
        cgroup_iptables.pop(3)
        cgroup_iptables.insert(3, ["-I", "INPUT", "1", "-m", "cgroup", "--cgroup", "0x00110011", "-j", "DROP"])
        
        for rule in cgroup_iptables:
            firewall.add_rule_6(rule)
        
    route_cmds = [
        ["ip", "route", "flush", "table", "bypass_qomui"],
        ["ip", "rule", "add", "fwmark", "11", "table", "bypass_qomui"]
        ]
    
    try:
        check_call(["ip", "route", "flush", "table", "bypass_qomui"])
    except CalledProcessError:
        pass
    
    try:
        check_call(["ip", "route", "flush", "table", "bypass_qomui"])
        check_call(["ip", "rule", "add", "fwmark", "11", "table", "bypass_qomui"])
        check_call(["ip", "route", "add", "default", "via", 
                    "%s" %default_gateway, "dev", "%s" %default_interface, "table", "bypass_qomui"])
    except CalledProcessError:
        logging.error("Could not set ipv4 routes for cgroup")
        
    try:
        check_call(["ip", "-6", "route", "flush", "table", "bypass_qomui"])
        check_call(["ip", "-6", "rule", "add", "fwmark", "11", "table", "bypass_qomui"])
        check_call(["ip", "-6", "route", "add", "default", "via", 
                    "%s" %default_gateway_6, "dev", "%s" %default_interface_6, "table", "bypass_qomui"])
    except CalledProcessError:
        logging.error("Could not set ipv6 routes for cgroup")
        
    try:
        check_call(["cgcreate", "-t", "%s:%s" %(user, group), "-a" "%s:%s" %(user, group), "-g", "net_cls:bypass_qomui"])
    except CalledProcessError:
        logging.error("Creating cgroup failed")
        
    with open ("/proc/sys/net/ipv4/conf/all/rp_filter", 'w') as rp_edit_all:
        rp_edit_all.write("2")
    with open ("/proc/sys/net/ipv4/conf/%s/rp_filter" %default_interface, 'w') as rp_edit_int:
        rp_edit_int.write("2")
        
    logging.info("Succesfully created cgroup to bypass OpenVPN tunnel")
    
def delete_cgroup(default_interface, default_interface_6):
    
    cgroup_iptables_del = [["-t", "mangle", "-D", "OUTPUT", "-m", "cgroup", 
                       "--cgroup", "0x00110011", "-j", "MARK", "--set-mark", "11"],
                        ["-t", "nat", "-D", "POSTROUTING", "-m", "cgroup", 
                       "--cgroup", "0x00110011", "-o", "%s" %default_interface , "-j", "MASQUERADE"],
                        ["-D", "OUTPUT", "-m", "cgroup", 
                       "--cgroup", "0x00110011", "-j", "ACCEPT"],
                        ["-D", "INPUT", "-m", "cgroup", 
                       "--cgroup", "0x00110011", "-j", "ACCEPT"],
                        ["-t", "nat", "-D", "OUTPUT", "-m", "cgroup", "--cgroup", 
                         "0x00110011", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5354"],
                        ["-t", "nat", "-D", "OUTPUT", "-m", "cgroup", "--cgroup", 
                         "0x00110011", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "5354"]
                        ]
                        
    with open ("/proc/sys/net/ipv4/conf/all/rp_filter", 'w') as rp_edit_all:
        rp_edit_all.write("1")
    with open ("/proc/sys/net/ipv4/conf/%s/rp_filter" %default_interface, 'w') as rp_edit_int:
        rp_edit_int.write("1")
        
    try:
        check_call(["ip", "rule", "del", "fwmark", "11", "table", "bypass_qomui"])
        check_call(["ip", "route", "flush", "table", "bypass_qomui"])
    except CalledProcessError:
        pass
        
    for rule in cgroup_iptables_del:
        firewall.add_rule(rule)
        
    cgroup_iptables_del.pop(1)
    cgroup_iptables_del.insert(1, ["-t", "nat", "-D", "POSTROUTING", "-m", "cgroup", 
                    "--cgroup", "0x00110011", "-o", "%s" %default_interface_6 , "-j", "MASQUERADE"])
    
    for rule in cgroup_iptables_del:
        firewall.add_rule_6(rule)
        
    try:
        os.rmdir(cgroup_path)
    except (OSError, FileNotFoundError):
        logging.debug("Could not delete %s - resource does not exist or is busy" %cgroup_path)
    
    logging.info("Deleted cgroup")
