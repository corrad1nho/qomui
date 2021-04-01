#!/usr/bin/env python3

import logging
from subprocess import Popen

from qomui import firewall
from subprocess import CalledProcessError


def set_dns(server_1, server_2=None, tun=None, main_int=None):
    try:
        Popen(["systemctl", "is-active", "--quiet", "systemd-resolved"])
        Popen(["systemd-resolve", "--flush-caches"])
        dns_systemd_cmd = [
            "systemd-resolve",
            "--interface={}".format(tun),
            "--set-dns={}".format(server_1)
        ]

        if server_2 is not None:
            dns_systemd_cmd.append("--set-dns={}".format(server_2))

        dns_systemd_cmd = [
            "systemd-resolve",
            "--interface={}".format(main_int),
            "--set-dns={}".format(server_1)
        ]
        if server_2 is not None:
            dns_systemd_cmd.append("--set-dns={}".format(server_2))

        Popen(dns_systemd_cmd)
        logging.info("DNS: Set {} and {} as dns servers via systemd-resolve".format(server_1, server_2))


    except (CalledProcessError, FileNotFoundError):
        resolv = open("/etc/resolv.conf", "w")
        lines = [
            "#modified by Qomui\n",
            "nameserver {}\n".format(server_1)
        ]

        if server_2 is not None:
            lines.append("nameserver {}\n".format(server_2))

        resolv.writelines(lines)
        logging.info(
            "DNS: Overwriting /etc/resolv.conf with {} and {}".format(server_1, server_2))


def dnsmasq(interface, port, server_1, server_2, pid):
    dnsmasq_cmd = [
        "dnsmasq",
        "--port={}".format(port),
        "--interface={}".format(interface),
        "--listen-address=127.0.0.1",
        "--bogus-priv",
        "--bind-interfaces",
        "--except-interface=lo",
        "--no-hosts",
        "--no-resolv",
        "--pid=/var/run/dnsmasq_qomui{}.pid".format(pid)
    ]

    for server in [server_1, server_2]:
        if server is not None:
            dnsmasq_cmd.append("--server={}".format(server))

    try:
        Popen(dnsmasq_cmd)
        logging.debug("dnsmasq: {}".format(dnsmasq_cmd))

    except CalledProcessError:
        logging.error("dnsmasq: {} failed".format(dnsmasq_cmd))


def dns_request_exception(action, dns_1, dns_2, port):
    rules = []
    protocols = ["udp", "tcp"]

    if action == "-I":
        logging.info("iptables: adding exception for DNS requests")

    elif action == "-D":
        logging.info("iptables: removing exception for DNS requests")

    for p in protocols:
        rules.append([action, 'OUTPUT', '-p', p,
                      '--dport', port, '-j', 'ACCEPT'])
        rules.append([action, 'INPUT', '-p', p,
                      '--sport', port, '-j', 'ACCEPT'])

    for rule in rules:
        firewall.add_rule(rule)
        firewall.add_rule(rule, ipt="ip6")
