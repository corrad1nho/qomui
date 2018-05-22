#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from PyQt5 import QtCore
from subprocess import CalledProcessError, check_output
import re


class LatencyCheck(QtCore.QThread):
    lat_signal = QtCore.pyqtSignal(tuple)

    def __init__(self, server_dict, interface):
        QtCore.QThread.__init__(self)
        self.server_dict = server_dict
        self.interface = interface
            
    def run(self):
        for k,v in self.server_dict.items():
            try:
                ip = v["ip"]
            except KeyError:
                ip = v["prim_ip"]
            
            try:
                pinger = check_output(["ping", "-c", "1", "-W", "1", "-I", "%s" %self.interface, "%s" %ip]).decode("utf-8")
                latencysearch = re.search(r'rtt min/avg/max/mdev = \d+(?:\.\d+)?/\d+(?:\.\d+)?/\d+(?:\.\d+)?/\d+(?:\.\d+)?', pinger)
                if latencysearch != None:
                    latencyraw = str(latencysearch.group())
                    latency = latencyraw.split("/")[4]
                else:
                    latency = "999"
            except CalledProcessError:
                latency = "999"
            
            latency_float = float(latency)
            if latency != "999":
                latency_string = "{0:.1f} ms".format(latency_float)
            else:
                latency_string = "N.A."
            
            self.lat_signal.emit((k, latency_string, latency_float))
                
