#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import shutil
import getopt
from subprocess import Popen

rootdir = "/usr/share/qomui"

def copy(argv):
    try:
        opts, args = getopt.getopt(argv,"d:f")
    except getopt.GetoptError:
        sys.exit(2)
    for opt, arg in opts:
        if opt == "-d":
            homedir = arg
            try:
                shutil.copyfile("%s/config_temp.json" %(homedir), "%s/config.json" %(rootdir))
                Popen(['chown', 'root', '%s/config.json' %(rootdir)])
                Popen(['chmod', '644', '%s/config.json' %(rootdir)])
                os.remove("%s/config_temp.json" %(homedir))
            except FileNotFoundError:
                sys.exit(1)
        if opt == "-f":
            try:
                shutil.copyfile("%s/firewall_temp.json" %(homedir), "%s/firewall.json" %(rootdir))
                Popen(['chown', 'root', '%s/firewall.json' % (rootdir)])
                Popen(['chmod', '644', '%s/firewall.json' % (rootdir)])
                os.remove("%s/firewall_temp.json" %(homedir))
            except FileNotFoundError:
                pass

    sys.exit(0)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Updateconf can only be run as root")
        sys.exit(1)
    copy(sys.argv[1:])


    



    
