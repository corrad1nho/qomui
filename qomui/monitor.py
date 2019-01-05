#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
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
                        "gateway" : "None",
                        "gateway_6" : "None",
                        "interface" : "None",
                        "interface_6" : "None"
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
            self.log.emit(('info', 'Could not identify default gateway - no network connectivity'))
            default_gateway_4 = "None"
            default_interface_4 = "None"

        try:
            route_cmd = ["ip", "-6", "route", "show", "default", "::/0"]
            default_route = check_output(route_cmd).decode("utf-8")
            parse_route = default_route.split(" ")
            default_gateway_6 = parse_route[2]
            default_interface_6 = parse_route[4]

        except (CalledProcessError, IndexError):
            self.log.emit(('error', 'Could not identify default gateway for ipv6 - no network connectivity'))
            default_gateway_6 = "None"
            default_interface_6 = "None"

        self.log.emit(("debug", "Network interface - ipv4: {}".format(default_interface_4)))
        self.log.emit(("debug","Default gateway - ipv4: {}".format(default_gateway_4)))
        self.log.emit(("debug","Network interface - ipv6: {}".format(default_interface_6)))
        self.log.emit(("debug","Default gateway - ipv6: {}".format(default_gateway_6)))

        return {
            "gateway" : default_gateway_4,
            "gateway_6" : default_gateway_6,
            "interface" : default_interface_4,
            "interface_6" : default_interface_6
            }
