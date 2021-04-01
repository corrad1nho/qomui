#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import time
import json
import psutil
import requests
from subprocess import CalledProcessError, check_output
from PyQt5 import QtCore


class NetMon(QtCore.QThread):
    net_state_change = QtCore.pyqtSignal(int, dict)
    log = QtCore.pyqtSignal(tuple)

    def __init__(self):
        QtCore.QThread.__init__(self)

    def run(self):
        net_iface_dir = "/sys/class/net/"
        net_check = 0
        i = "None"

        while True:
            prior = net_check
            i = "None"
            net_check = 0
            routes = {
                "gateway": "None",
                "gateway_6": "None",
                "interface": "None",
                "interface_6": "None"
            }

            try:
                for iface in os.listdir(net_iface_dir):
                    with open("{}{}/operstate".format(net_iface_dir, iface), "r") as n:

                        if n.read() == "up\n":
                            net_check = 1
                            i = iface

                if prior != net_check and net_check == 1:
                    routes = self.default_gateway_check()
                    gw = routes["gateway"]
                    gw_6 = routes["gateway_6"]

                    if gw != "None" or gw_6 != "None":
                        self.net_state_change.emit(net_check, routes)

                    else:
                        net_check = 0

                elif prior != net_check and net_check == 0:
                    self.net_state_change.emit(net_check, routes)

                time.sleep(2)

            except (FileNotFoundError, PermissionError) as e:
                self.log.emit(("error", e))

    def default_gateway_check(self):
        try:
            route_cmd = ["ip", "route", "show", "default", "0.0.0.0/0"]
            default_route = check_output(route_cmd).decode("utf-8")
            parse_route = default_route.split(" ")
            default_gateway_4 = parse_route[2]
            default_interface_4 = parse_route[4]

        except (CalledProcessError, IndexError):
            self.log.emit(
                ('info', 'Could not identify default gateway - no network connectivity'))
            default_gateway_4 = "None"
            default_interface_4 = "None"

        try:
            route_cmd = ["ip", "-6", "route", "show", "default", "::/0"]
            default_route = check_output(route_cmd).decode("utf-8")
            parse_route = default_route.split(" ")
            default_gateway_6 = parse_route[2]
            default_interface_6 = parse_route[4]

        except (CalledProcessError, IndexError):
            self.log.emit(
                ('error',
                 'Could not identify default gateway for ipv6 - no network connectivity'))
            default_gateway_6 = "None"
            default_interface_6 = "None"

        self.log.emit(
            ("debug", "Network interface - ipv4: {}".format(default_interface_4)))
        self.log.emit(
            ("debug", "Default gateway - ipv4: {}".format(default_gateway_4)))
        self.log.emit(
            ("debug", "Network interface - ipv6: {}".format(default_interface_6)))
        self.log.emit(
            ("debug", "Default gateway - ipv6: {}".format(default_gateway_6)))

        return {
            "gateway": default_gateway_4,
            "gateway_6": default_gateway_6,
            "interface": default_interface_4,
            "interface_6": default_interface_6
        }

class TunnelMon(QtCore.QThread):
    stat = QtCore.pyqtSignal(list)
    ip = QtCore.pyqtSignal(dict)
    time = QtCore.pyqtSignal(str)
    check = QtCore.pyqtSignal()
    lost = QtCore.pyqtSignal()
    log = QtCore.pyqtSignal(tuple)

    def __init__(self, tun, bypass, tun_hop=None):
        QtCore.QThread.__init__(self)
        self.tun = tun
        self.bypass = bypass
        self.tun_hop = tun_hop

    def run(self):
        connected = True
        check_url = "https://ipv4.ipleak.net/json"
        check_url_6 = "https://ipv6.ipleak.net/json"
        check_url_alt = "https://ipv4.icanhazip.com/"
        check_url_alt_6 = "https://ipv6.icanhazip.com/"
        check_url_loc = "http://ip-api.com/json"

        if self.bypass is None:

            try:
                query = requests.get(check_url, timeout=1).content.decode("utf-8")
                ip = json.loads(query)["ip"]

            except (KeyError, requests.exceptions.RequestException, json.decoder.JSONDecodeError):

                try:
                    ip = requests.get(check_url_alt, timeout=1).content.decode("utf-8").replace("\n", "")

                except requests.exceptions.RequestException:
                    self.log.emit(("info", "Could not determine external ipv4 address"))
                    ip = None

            try:
                query = requests.get(check_url_6, timeout=1).content.decode("utf-8")
                ip_6 = json.loads(query)["ip"]

            except (KeyError, requests.exceptions.RequestException, json.decoder.JSONDecodeError):

                try:
                    ip_6 = requests.get(check_url_alt_6, timeout=1).content.decode("utf-8").replace("\n", "")

                except requests.exceptions.RequestException:
                    self.log.emit(("info", "Could not determine external ipv6 address"))
                    ip_6 = None

            try:
                query = requests.get(check_url_loc, timeout=1).content.decode("utf-8")
                lat = json.loads(query)["lat"]
                lon = json.loads(query)["lon"]

            except (KeyError, requests.exceptions.RequestException, json.decoder.JSONDecodeError):
                self.log.emit(("info", "Could not determine location"))
                lat = 0
                lon = 0

            self.log.emit(("info", "External ip = {} - {}".format(ip, ip_6)))
            self.ip.emit({"ip4":ip,"ip6":ip_6,"lat":lat,"lon":lon})

        t0 = time.time()
        accum = (0, 0)
        start_time = time.time()

        try:
            counter = psutil.net_io_counters(pernic=True)[self.tun]
            stat = (counter.bytes_recv, counter.bytes_sent)

        except KeyError:
            stat = (0,0)

        while connected is True:
            last_stat = stat
            time.sleep(1)
            time_measure = time.time()
            elapsed = time_measure - start_time

            if int(elapsed) % 900 == 0:
                self.check.emit()

            return_time = self.time_format(int(elapsed))
            self.time.emit(return_time)

            try:
                counter = psutil.net_io_counters(pernic=True)[self.tun]
                if self.tun_hop is not None:
                    tun_hop_test = psutil.net_io_counters(pernic=True)[self.tun_hop]
                t1 = time.time()
                stat = (counter.bytes_recv, counter.bytes_sent)
                DLrate, ULrate = [(now - last) / (t1 - t0) / 1024.0 for now, last in zip(stat, last_stat)]
                DLacc, ULacc = [(now + last) / (1024*1024) for now, last in zip(stat, last_stat)]
                t0 = time.time()
                self.stat.emit([DLrate, DLacc, ULrate, ULacc])

            except (KeyError, OSError):
                break

        connected = False
        self.log.emit(("info", "Interface {} does not exist anymore".format(self.tun)))
        self.lost.emit()

    def time_format(self, e):
        calc = '{:02d}d {:02d}h {:02d}m {:02d}s'.format(e // 86400,
                                                        (e % 86400 // 3600),
                                                        (e % 3600 // 60),
                                                        e % 60
                                                        )
        split = calc.split(" ")

        if split[0] == "00d" and split[1] == "00h":
            return ("{} {}".format(split[2], split[3]))

        elif split[0] == "00d" and split[1] != "00h":
            return ("{} {}".format(split[1], split[2]))

        else:
            return ("{} {}".format(split[0], split[1]))