#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from PyQt5 import QtCore
from subprocess import CalledProcessError, check_output
import re
import logging

class LatencyCheck(QtCore.QThread):
    lat_signal = QtCore.pyqtSignal(tuple)
    finished = QtCore.pyqtSignal()

    def __init__(self, server_dict, interface):
        QtCore.QThread.__init__(self)
        self.server_dict = server_dict
        self.interface = interface

    def sort_by_latency(self, server):
        try:
            return float(server[1]["latency"])
        except KeyError:
            return 999

    def run(self):
        try:
            for k,v in sorted(self.server_dict.items(), key=self.sort_by_latency):
                try:
                    ip = v["ip"]
                except KeyError:
                    try:
                        ip = v["ip1"]
                    except KeyError:
                        ip = v["prim_ip"]

                try:
                    pinger = check_output(["ping", "-c", "1", "-W", "1", "-I", "{}".format(self.interface), "{}".format(ip)]).decode("utf-8")
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

        except RuntimeError:
            logging.debug("RuntimeError: Latency check is already running")

        self.finished.emit()
