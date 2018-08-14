#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import shutil
import getopt
from subprocess import Popen

ROOTDIR = "/usr/share/qomui"

def copy(argv):
    try:
        opts, args = getopt.getopt(argv,"d:f")
    except getopt.GetoptError:
        sys.exit(2)
    for opt, arg in opts:
        if opt == "-d":
            homedir = arg
            try:
                shutil.copyfile("{}/config_temp.json".format(homedir), "{}/config.json".format(ROOTDIR))
                Popen(['chown', 'root', '{}/config.json'.format(ROOTDIR)])
                Popen(['chmod', '644', '{}/config.json'.format(ROOTDIR)])
                os.remove("{}/config_temp.json".format(homedir))
            except FileNotFoundError:
                sys.exit(1)
        if opt == "-f":
            try:
                shutil.copyfile("{}/firewall_temp.json".format(homedir), "{}/firewall.json".format(ROOTDIR))
                Popen(['chown', 'root', '{}/firewall.json'.format(ROOTDIR)])
                Popen(['chmod', '644', '{}/firewall.json'.format(ROOTDIR)])
                os.remove("{}/firewall_temp.json".format(homedir))
            except FileNotFoundError:
                pass

    sys.exit(0)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Updateconf can only be run as root")
        sys.exit(1)
    copy(sys.argv[1:])
