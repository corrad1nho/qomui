#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import dbus
import argparse
import readline
import json
import time
import shutil
from dbus.mainloop.pyqt5 import DBusQtMainLoop
from PyQt5 import QtCore, Qt
from subprocess import Popen, PIPE
import getpass
import signal
from qomui import utils, update

ROOTDIR = "/usr/share/qomui"
HOMEDIR = "{}/.qomui".format(os.path.expanduser("~"))
SUPPORTED_PROVIDERS = ["Airvpn", "Mullvad", "PIA", "ProtonVPN", "Windscribe"]
app = QtCore.QCoreApplication(sys.argv)

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s


class QomuiCli(QtCore.QObject):
    hop_server_dict = None
    hop_active = 0

    def __init__(self, args=None):
        QtCore.QObject.__init__(self)

        try:
            self.dbus = dbus.SystemBus()
            self.qomui_dbus = self.dbus.get_object('org.qomui.service', '/org/qomui/service')
            self.qomui_service = dbus.Interface(self.qomui_dbus, 'org.qomui.service')
            self.qomui_service.connect_to_signal("reply", self.openvpn_log_monitor)
            self.qomui_service.connect_to_signal("conn_info", self.openvpn_log_print)
            self.qomui_service.connect_to_signal("imported", self.downloaded)

        except dbus.exceptions.DBusException:
            print("Error: qomui-service is not available")
            print('Use "systemctl start qomui" to run the background service')
            print("Exiting...")
            sys.exit(1)

        self.args = args
        self.arguments(self.args)

    def arguments(self, args):
        if args["terminate"] is True:
            print("Succesfully disconnected")
            self.kill()
            sys.exit(0)

        if args["set_protocol"] is not None:
            protocol_dict = self.load_json("{}/protocol.json".format(HOMEDIR))
            provider = args["set_protocol"]

            try:
                for k, v in protocol_dict[provider].items():
                    if k != "selected":
                        number = k.split("_")[1]
                        attrs = ", ".join(v.values())
                        print("{}: {}".format(number, attrs))

                choice = input("Enter number of protocol: ")
                prot_chosen = "protocol_{}".format(choice)
                print(prot_chosen)

                if prot_chosen in protocol_dict[provider].keys():
                    protocol_dict[provider]["selected"] = prot_chosen

                    with open("{}/protocol.json".format(HOMEDIR), "w") as p:
                        json.dump(protocol_dict, p)

                    print("Port/Protocol for {} successfully changed".format(provider))

                else:
                    print("Invalid number: Protocol/Port has not been changed")

            except KeyError:
                print("Sorry, can't change port/protocol for this provider")

            sys.exit(0)

        if args["connect"] is not None:
            self.server_dict = self.load_json("{}/server.json".format(HOMEDIR))
            self.protocol_dict = self.load_json("{}/protocol.json".format(HOMEDIR))
            keys = self.server_dict.keys()

            if args["via"] is not None:
                self.hop_active = 1
                hop_server = args["via"]

                if hop_server in keys:
                    self.set_hop(hop_server)

                else:
                    print("Sorry, {} does not exist".format(hop_server))
                    self.autocomplete(keys, action="set_hop")

            server = args["connect"]

            if server in keys:
                self.establish_connection(server)

            else:
                print("Sorry, {} does not exist".format(server))
                self.autocomplete(keys, action="establish_connection")

        if args["list"] is not None:
            server_dict = self.load_json("{}/server.json".format(HOMEDIR))
            for k, v in server_dict.items():
                v_lower = [v.lower() for v in v.values()]
                a_lower = [a.lower() for a in args["list"]]
                check = all(i in v_lower for i in a_lower)
                if check:
                    formatted = "{} - {} - {}".format(k, v["country"], v["provider"])
                    print(formatted)

            sys.exit(0)

        if args["enable"] is not None:
            config = self.get_config()
            for o in args["enable"]:
                if o in config.keys():
                    config[o] = 1

                else:
                    print('"{}" is not a valid option')

            update_conf = self.applyoptions(config)

        if args["disable"] is not None:
            config = self.get_config()
            for o in args["disable"]:
                if o in config.keys():
                    config[o] = 0
                else:
                    print('"{}" is not a valid option')

            update_conf = self.applyoptions(config)

        if args["set_alt_dns"] is not None:
            config = self.get_config()
            config["alt_dns1"] = args["set_alt_dns"][0]
            config["alt_dns2"] = args["set_alt_dns"][1]
            update_conf = self.applyoptions(config)

        if args["show_options"] is True:
            config = self.get_config()
            self.show_config(config)

        if args["delete_provider"] is not None:
            del_list = []
            provider = args["delete_provider"]
            self.server_dict = self.load_json("{}/server.json".format(HOMEDIR))
            self.protocol_dict = self.load_json("{}/protocol.json".format(HOMEDIR))
            for k, v in self.server_dict.items():
                if v["provider"] == provider:
                    del_list.append(k)
            for k in del_list:
                self.server_dict.pop(k)
            try:
                self.protocol_dict.pop(provider)
            except KeyError:
                pass

            self.qomui_service.delete_provider(provider)
            with open("{}/server.json".format(HOMEDIR), "w") as s:
                json.dump(self.server_dict, s)

            print("{} deleted".format(provider))
            sys.exit(0)

        if args["add"] is not None:
            provider = args["add"]
            self.add_server(provider)

    def autocomplete(self, keys, action=None):
        readline.set_completer(AutoCompleter(keys).complete)
        readline.parse_and_bind('tab: complete')
        line = ""
        while line not in keys:
            line = input("Try again ('TAB' for autocompletion): ")

        do = getattr(self, action)
        do(line)

    def establish_connection(self, server):
        self.ovpn_dict = utils.create_server_dict(self.server_dict[server],
                                                  self.protocol_dict
                                                  )

        if self.hop_server_dict is not None:
            self.ovpn_dict.update({"hop": "2"})
        else:
            self.ovpn_dict.update({"hop": "0"})

        self.kill()
        self.qomui_service.connect_to_server(self.ovpn_dict)

        config = self.get_config()
        try:
            if config["bypass"] == 1:
                self.qomui_service.bypass(utils.get_user_group())
        except KeyError:
            pass

    def set_hop(self, server):
        self.hop_server_dict = utils.create_server_dict(self.server_dict[server],
                                                        self.protocol_dict
                                                        )
        self.qomui_service.set_hop(self.hop_server_dict)

    def add_server(self, provider):
        path = "None"
        print(
            "Automatic download is available for the following providers: Airvpn, Mullvad, PIA, Windscribe and "
            "ProtonVPN")
        if provider not in SUPPORTED_PROVIDERS:
            path = input("Enter path of folder containing config files of {}:\n".format(provider))
            if not os.path.exists(path):
                print("{} is not a valid (path)".format(path))
                sys.exit(1)

        print("Please enter your credentials")
        if provider == "Mullvad":
            username = input("Enter account number:\n")
            password = "m"

        else:
            username = input("Enter username:\n")
            password = getpass.getpass("Enter password:\n")

        if not os.path.exists("{}/temp".format(HOMEDIR)):
            os.makedirs("{}/temp".format(HOMEDIR))

        print("Please wait....")

        credentials = {
            "provider": provider,
            "username": username,
            "password": password,
            "folderpath": path,
            "homedir": HOMEDIR
        }

        self.qomui_service.import_thread(credentials)

    def log_from_thread(self, msg):
        print(msg[1])

    def downloaded(self, msg):
        split = msg.split("&")
        if len(split) >= 2:
            print(split[0])
            print(split[1])
            print("Configuration of {} could not be imported".format(split[2]))
            app.quit()

        else:
            self.server_dict = self.load_json("{}/server.json".format(HOMEDIR))
            self.protocol_dict = self.load_json("{}/protocol.json".format(HOMEDIR))
            with open("{}/{}.json".format(HOMEDIR, msg), "r") as p:
                content = json.load(p)

            provider = content["provider"]
            for k, v in content["server"].items():

                try:
                    if self.server_dict[k]["favourite"] == "on":
                        content["server"][k]["favourite"] = "on"

                except KeyError:
                    pass

            if provider in SUPPORTED_PROVIDERS:
                del_list = []

                for k, v in self.server_dict.items():
                    if v["provider"] == provider:
                        del_list.append(k)

                for k in del_list:
                    self.server_dict.pop(k)

            self.server_dict.update(content["server"])

            try:
                if 'selected' in self.protocol_dict[provider].keys():
                    content["protocol"]["selected"] = self.protocol_dict[provider]["selected"]
                else:
                    content["protocol"]["selected"] = "protocol_1"

            except KeyError:
                pass

            try:
                self.protocol_dict[provider] = (content["protocol"])

            except KeyError:
                pass

            with open("{}/server.json".format(HOMEDIR), "w") as s:
                json.dump(self.server_dict, s)

            with open("{}/protocol.json".format(HOMEDIR), "w") as p:
                json.dump(self.protocol_dict, p)

            os.remove("{}/{}.json".format(HOMEDIR, msg))
            print("Succesfully added config files for {}".format(provider))
            app.quit()

    def kill(self):
        self.qomui_service.disconnect("main")

    def show_config(self, config):
        print("Current configuration:")
        for k, v in config.items():
            print("{} : {}".format(k, v))

        sys.exit(0)

    def openvpn_log_monitor(self, reply):
        if reply == "connection_established":
            if self.hop_active == 1:
                self.hop_active = 0
            else:
                print("Connection to {} successful".format(self.ovpn_dict["name"]))
                app.quit()

        elif reply == "conn_attempt_failed":
            self.kill()
            print("Connection attempt failed")
            print("Application was unable to connect to server\nSee log for further information")
            app.quit()

    def openvpn_log_print(self, reply):
        print(reply)

    def load_json(self, json_file):
        try:
            with open(json_file, 'r') as j:
                return json.load(j)

        except FileNotFoundError:
            if json_file == "/usr/share/qomui/config.json":
                try:
                    with open("{}/default_config.json".format(ROOTDIR), 'r') as j:
                        print("Loading default configuration")
                        return json.load(j)
                except FileNotFoundError:
                    print("{} does not exist".format(json_file))
                    return {}
            else:
                print("{} does not exist".format(json_file))
                return {}

    def applyoptions(self, temp_config):

        with open('{}/config_temp.json'.format(HOMEDIR), 'w') as config:
            json.dump(temp_config, config)

        update_cmd = ['sudo', sys.executable, '-m', 'qomui.mv_config',
                      '-d', '{}'.format(HOMEDIR)]

        update = Popen(update_cmd, stdin=PIPE, stdout=PIPE, universal_newlines=True)
        prompt = update.communicate("" + '\n')[1]

        if update.returncode == 0:
            print("Configuration successfully changed")
            self.qomui_service.load_firewall()

            try:
                if temp_config["bypass"] == 1:
                    self.qomui_service.bypass(utils.get_user_group())
            except KeyError:
                pass

        else:
            print("Configuration change failed")

        self.show_config(self.get_config())

    def get_config(self):
        config_dict = self.load_json("{}/config.json".format(ROOTDIR))
        return config_dict


class AutoCompleter(object):

    def __init__(self, keys):
        self.keys = sorted(keys)
        return

    def complete(self, text, state):
        response = None
        if state == 0:
            if text:
                self.matches = [s for s in self.keys if s.lower() and s.lower().startswith(text.lower())]
            else:
                self.matches = self.options[:]
        try:
            response = self.matches[state]
        except IndexError:
            response = None

        return response


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--connect", help="Connect to server [Name of server]")
    parser.add_argument("-t", "--terminate", action='store_true', help="Disconnect")
    parser.add_argument("-p", "--set-protocol", help="Set port/protocol for [provider]")
    parser.add_argument("-v", "--via", help="Choose server for doublehop [Name of server]")
    parser.add_argument("-e", "--enable", nargs='*',
                        help="Enable [autoconnect] [firewall] [bypass] [ipv6_disable] [alt_dns]"
                        )
    parser.add_argument("-d", "--disable", nargs='*',
                        help="Disable [autoconnect] [firewall] [bypass] [ipv6_disable] [alt_dns]"
                        )
    parser.add_argument("-o", "--show-options", action='store_true', help="Show current configuration")
    parser.add_argument("--set-alt-dns", nargs=2, help="Set alternative DNS servers [DNS1] [DNS2]")
    parser.add_argument("-a", "--add", help="Add/update servers of [provider]")
    parser.add_argument("--delete-provider", help="Delete provider")
    parser.add_argument("-l", "--list", nargs='*', help="List servers [Provider, Country ...]")
    args = vars(parser.parse_args())

    signal.signal(signal.SIGINT, signal.SIG_DFL)
    mainloop = DBusQtMainLoop(set_as_default=True)
    ex = QomuiCli(args=args)
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
