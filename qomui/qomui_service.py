#!/usr/bin/env python3

import sys
import os
import time
import shutil
import logging
import logging.handlers
import json
import threading
import signal
from datetime import date, datetime

from subprocess import Popen, PIPE, check_output, check_call, CalledProcessError, STDOUT

import pexpect
import psutil
import requests
from PyQt5 import QtCore
import dbus
import dbus.service
from dbus.mainloop.pyqt5 import DBusQtMainLoop

from qomui import firewall, bypass, update, dns_manager, tunnel

ROOTDIR = "/usr/share/qomui"
LOGDIR = "/usr/share/qomui/logs"
OPATH = "/org/qomui/service"
IFACE = "org.qomui.service"
BUS_NAME = "org.qomui.service"
SUPPORTED_PROVIDERS = ["Airvpn", "AzireVPN", "Mullvad", "PIA", "ProtonVPN", "Windscribe"]

class GuiLogHandler(logging.Handler):
    def __init__(self, send_log, parent=None):
        super().__init__()
        self.send_log = send_log

    def handle(self, record):
        msg = self.format(record)
        self.send_log(msg)

class QomuiDbus(dbus.service.Object):
    pid_list = []
    firewall_opt = 1
    hop = 0
    hop_dict = {"none" : "none"}
    tun = None
    tun_hop = None
    tun_bypass = None
    connect_status = 0
    config = {}
    wg_connect = 0
    version = "None"
    thread_list = []
    interface = "eth0"

    def __init__(self):
        
        if not os.path.exists(LOGDIR):
            os.makedirs(LOGDIR)

        self.sys_bus = dbus.SystemBus()
        self.bus_name = dbus.service.BusName(BUS_NAME, bus=self.sys_bus)
        dbus.service.Object.__init__(self, self.bus_name, OPATH)
        self.logger = logging.getLogger()
        self.gui_handler = GuiLogHandler(self.send_log)
        self.gui_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(self.gui_handler)
        self.filehandler = logging.handlers.RotatingFileHandler("{}/qomui.log".format(LOGDIR),
                                                       maxBytes=2*1024*1024, backupCount=3)
        self.logger.addHandler(self.filehandler)
        self.filehandler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.setLevel(logging.DEBUG)
        self.logger.info("Dbus-service successfully initialized")

        #Clean slate after (re-)starting
        try:
            check_call(["killall", "openvpn"])
            self.logger.debug("Killed all running instances of OpenVPN")
        except CalledProcessError:
            pass

        self.check_version()
        firewall.save_iptables()
        self.load_firewall(0)

    #after upgrade: gui and service might be running different versions
    def check_version(self):
        try:
            with open("{}/VERSION".format(ROOTDIR), "r") as v:
                version = v.read().split("\n")
                self.version = version[0]

        except FileNotFoundError:
            self.logger.warning("{}/VERSION does not exist".format(ROOTDIR))

    @dbus.service.method(BUS_NAME, in_signature='', out_signature='s')
    def get_version(self):
        return self.version

    @dbus.service.method(BUS_NAME, out_signature='i')
    def restart(self):
        try:
            Popen(["systemctl", "daemon-reload"])
            Popen(["systemctl", "restart", "qomui"])

        except CalledProcessError as e:
            self.logger.error(e)

    #receive log from gui and handle it
    @dbus.service.method(BUS_NAME, in_signature='s')
    def share_log(self, msg):
        record = json.loads(msg)
        log = logging.makeLogRecord(record)
        self.filehandler.handle(log)
        self.gui_handler.handle(log)

    #send log to qomui-gui so it can be displayed
    @dbus.service.signal(BUS_NAME, signature='s')
    def send_log(self, msg):
        return msg

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='')
    def log_level_change(self, level):
        self.logger.setLevel(getattr(logging, level.upper()))
        self.config["log_level"] = level

        with open('{}/config.json'.format(ROOTDIR), 'w') as save_config:
            json.dump(self.config, save_config)

    @dbus.service.method(BUS_NAME, in_signature='a{ss}', out_signature='')
    def connect_to_server(self, ovpn_dict):
        name = ovpn_dict["name"]
        if ovpn_dict["tunnel"] == "WireGuard":
            self.wg_connect = 1
            self.wg_provider = ovpn_dict["provider"]

        setattr(self, "{}_dict".format(name), tunnel.TunnelThread(ovpn_dict, self.hop_dict, self.config))
        getattr(self, "{}_dict".format(name)).log.connect(self.log_thread)
        getattr(self, "{}_dict".format(name)).status.connect(self.reply)
        getattr(self, "{}_dict".format(name)).dev.connect(self.set_tun)
        getattr(self, "{}_dict".format(name)).dnsserver.connect(self.set_dns)
        getattr(self, "{}_dict".format(name)).pid.connect(self.add_pid)
        getattr(self, "{}_dict".format(name)).bypass.connect(self.cgroup_vpn)
        getattr(self, "{}_dict".format(name)).start()
        self.logger.debug("New thread for OpenVPN process started")

    @dbus.service.method(BUS_NAME, in_signature='a{ss}', out_signature='')
    def set_hop(self, ovpn_dict):
        self.hop_dict = ovpn_dict

    def add_pid(self, pid):
        self.pid_list.append(pid)

    #get fw configuration - might be called from gui after config change
    @dbus.service.method(BUS_NAME, in_signature='i', out_signature='')
    def load_firewall(self, stage):
        try:
            with open('{}/config.json'.format(ROOTDIR), 'r') as c:
                self.config = json.load(c)

        except (FileNotFoundError, json.decoder.JSONDecodeError) as e:
            self.logger.error('{}: Could not open config.json - loading default configuration'.format(e))
            with open('{}/default_config.json'.format(ROOTDIR), 'r') as c:
                self.config = json.load(c)

        try:
            self.logger.setLevel(self.config["log_level"].upper())
            self.disable_ipv6(self.config["ipv6_disable"])
            fw = self.config["firewall"]
            gui_only = self.config["fw_gui_only"]
            block_lan=self.config["block_lan"]
            preserve=self.config["preserve_rules"] 

            if fw == 1 and gui_only == 0:
                opt = 1
            elif gui_only == 1 and stage == 1:
                firewall.save_iptables()
                opt = fw
            elif gui_only == 1 and stage == 2:
                firewall.restore_iptables()
                opt = 2
            elif fw == 0 and stage == 1:
                opt = 0
                firewall.restore_iptables()
            else:
                opt = 2

            if opt < 2:
                firewall.apply_rules(
                                    opt,
                                    block_lan=block_lan, 
                                    preserve=preserve
                                    )
        except KeyError:
            self.logger.warning('Malformed config file')

        #default dns is always set to the alternative servers
        self.dns = self.config["alt_dns1"]
        self.dns_2 = self.config["alt_dns2"]
        self.dns_bypass = self.config["alt_dns1"]
        self.dns_2_bypass = self.config["alt_dns2"]

    @dbus.service.method(BUS_NAME, in_signature='i', out_signature='')
    def disable_ipv6(self, i):
        if i == 1:
            Popen(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=1'])
            self.logger.info('Disabled ipv6')
        else:
            Popen(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0'])
            self.logger.info('(Re-)enabled ipv6')

    #set dns servers detected in tunnel thread
    def set_dns(self, dns):
        setattr(self, "dns{}".format(dns[0]), dns[1])
        setattr(self, "dns_2{}".format(dns[0]), dns[2])

    def set_tun(self, tun):
        setattr(self, tun[0], tun[1])

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='s')
    def return_tun_device(self, tun):
        return getattr(self, tun)

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='')
    def disconnect(self, env):

        if env == "main":
            self.restore_default_dns()
            self.tun is None
            for i in self.pid_list:
                if i[1] != "OpenVPN_bypass":
                    self.kill_pid(i)

            if self.wg_connect == 1:
                try:
                    wg_down = Popen(["wg-quick", "down", "{}/wg_qomui.conf".format(ROOTDIR)], stdout=PIPE, stderr=STDOUT)
                    for line in wg_down.stdout:
                        self.logger.info("WireGuard: " + line.decode("utf-8").replace("\n", ""))

                except CalledProcessError:
                    pass

                #as WireGuard is down we can remove those rules
                wg_rules = [
                    ["-D", "INPUT", "-i", "wg_qomui", "-j", "ACCEPT"],
                    ["-D", "OUTPUT", "-o", "wg_qomui", "-j", "ACCEPT"]
                    ]
                firewall.batch_rule_6(wg_rules)
                firewall.batch_rule(wg_rules)
                tunnel.exe_custom_scripts("down", self.wg_provider, self.config)
                self.wg_connect = 0

        elif env == "bypass":
            for i in self.pid_list:
                if i[1] == "OpenVPN_bypass":
                    self.kill_pid(i)

    def kill_pid(self, i):
        if psutil.pid_exists(i[0]):

            try:
                self.logger.debug("OS: process {} killed - {}".format(i[0], i[1]))
                Popen(['kill', '{}'.format(i[0])])

            except CalledProcessError:
                self.logger.debug("OS: process {} does not exist anymore".format(i))

    #allow downloading from provider api/site even if firewall is activated and no connection is active
    def allow_provider_ip(self, provider):
        server = []

        if provider == "Airvpn":
            server.append("www.airvpn.org")

        elif provider == "Mullvad":
            server.append("www.mullvad.net")
            server.append("api.mullvad.net")

        elif provider == "PIA":
            server.append("www.privateinternetaccess.com")

        elif provider == "Windscribe":
            server.append("www.windscribe.com")
            server.append("assets.windscribe.com")

        elif provider == "ProtonVPN":
            server.append("api.protonmail.ch")

        dns_manager.dns_request_exception("-I", self.config["alt_dns1"], self.config["alt_dns2"], "53")

        if len(server) > 0:
            for s in server:

                try:
                    dig_cmd = ["dig", "+time=2", "+tries=1", "{}".format(s), "+short"]
                    answer = check_output(dig_cmd).decode("utf-8")
                    parse = answer.split("\n")
                    ip = parse[len(parse)-2]
                    firewall.add_rule(['-I', 'OUTPUT', '1', '-d', '{}'.format(ip), '-j', 'ACCEPT'])
                    self.logger.info("iptables: Allowing access to {}".format(s))

                except CalledProcessError as e:
                    self.logger.error("{}: Could not resolve {}".format(e, s))

    #save and restore content of /etc/resolv.conf
    @dbus.service.method(BUS_NAME, in_signature='', out_signature='')
    def save_default_dns(self):
        shutil.copyfile("/etc/resolv.conf", "/etc/resolv.conf.qomui.bak")
        self.logger.debug("Created backup of /etc/resolv.conf")

    @dbus.service.method(BUS_NAME, in_signature='', out_signature='')
    def restore_default_dns(self):
        try:
            shutil.copyfile("/etc/resolv.conf.qomui.bak", "/etc/resolv.conf")
            self.logger.debug("Restored backup of /etc/resolv.conf")

        except FileNotFoundError:
            self.logger.warning("Default DNS settings not restored. Could not find backup of /etc/resolv.conf")

    @dbus.service.method(BUS_NAME, in_signature='ss', out_signature='')
    def change_ovpn_config(self, provider, certpath):

        for f in os.listdir(certpath):
            f_source = "{}/{}".format(certpath, f)

            if provider in SUPPORTED_PROVIDERS:
                f_dest = "{}/{}/openvpn.conf".format(ROOTDIR, provider)
            else:
                f_dest = "{}/{}/{}".format(ROOTDIR, provider, f)

            shutil.copyfile(f_source, f_dest)
            self.logger.debug("copied {} to {}".format(f, f_dest))

    @dbus.service.method(BUS_NAME, in_signature='a{ss}', out_signature='')
    def import_thread(self, credentials):
        provider = credentials["provider"]
        self.homedir = credentials["homedir"]
        self.allow_provider_ip(provider)

        try:
            if credentials["credentials"] == "unknown":

                try:
                    auth_file = "{}/{}/{}-auth.txt".format(ROOTDIR, provider, provider)

                    with open(auth_file, "r") as auth:
                        up = auth.read().split("\n")
                        credentials["username"] = up[0]
                        credentials["password"] = up[1]

                except FileNotFoundError:
                    self.logger.error("Could not find {} - Aborting update".format(auth_file))

                if provider == "Airvpn":
                    credentials["key"] = self.config["airvpn_key"]

        except KeyError:
            pass

        if "username" in credentials:
            self.start_import_thread(provider, credentials)

    def start_import_thread(self, provider, credentials):
        setattr(self, "import_{}".format(provider), update.AddServers(credentials))
        getattr(self, "import_{}".format(provider)).log.connect(self.log_thread)
        getattr(self, "import_{}".format(provider)).finished.connect(self.downloaded)
        getattr(self, "import_{}".format(provider)).failed.connect(self.imported)
        getattr(self, "import_{}".format(provider)).started.connect(self.progress_bar)
        getattr(self, "import_{}".format(provider)).start()

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='')
    def cancel_import(self, provider):
        getattr(self, "import_{}".format(provider)).terminate()
        getattr(self, "import_{}".format(provider)).wait()

    def log_thread(self, log):
        getattr(logging, log[0])(log[1])

    def downloaded(self, content):
        provider = content["provider"]

        #dns requests must be allowed to resolve hostnames in config files
        dns_manager.dns_request_exception("-D", self.config["alt_dns1"], self.config["alt_dns2"], "53")

        if provider in SUPPORTED_PROVIDERS:
            with open('{}/config.json'.format(ROOTDIR), 'w') as save_config:
                self.config["{}_last".format(provider)] = str(datetime.utcnow())
                if provider == "Airvpn":
                    self.config["airvpn_key"] = content["airvpn_key"]
                json.dump(self.config, save_config)

        with open('{}/{}.json'.format(self.homedir, provider), 'w') as p:
            Popen(['chmod', '0666', '{}/{}.json'.format(self.homedir, provider)])
            json.dump(content, p)

        self.imported(provider)

    @dbus.service.signal(BUS_NAME, signature='s')
    def progress_bar(self, provider):
        return provider

    @dbus.service.signal(BUS_NAME, signature='s')
    def imported(self, result):
        return result

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='')
    def delete_provider(self, provider):
        path = "{}/{}".format(ROOTDIR, provider)
        if os.path.exists(path):
            shutil.rmtree(path)
            try:
                os.remove("{}/certs/{}-auth.txt".format(ROOTDIR, provider))
            except FileNotFoundError:
                pass

    @dbus.service.method(BUS_NAME, in_signature='a{ss}', out_signature='')
    def bypass(self, net):
        self.net = net
        #default_routes = self.default_gateway_check()
        self.gw = self.net["gateway"]
        self.gw_6 = self.net["gateway_6"]
        default_interface_4 = self.net["interface"]
        default_interface_6 = self.net["interface_6"]

        if self.gw != "None" or self.gw_6 != "None":
            try:

                if default_interface_6 != "None":
                    self.interface = default_interface_6

                elif default_interface_4 != "None":
                    self.interface = default_interface_4

                else:
                    self.interface = "None"

                if self.config["bypass"] == 1:
                    bypass.create_cgroup(
                        self.net["user"],
                        self.net["group"],
                        self.interface,
                        gw=self.gw,
                        gw_6=self.gw_6,
                        default_int=self.interface
                        )

                    self.kill_dnsmasq()

                    #dnsmasq is needed to handle requests from bypass
                    dns_manager.dnsmasq(
                                        self.interface,
                                        "5354",
                                        self.config["alt_dns1"],
                                        self.config["alt_dns2"],
                                        "_bypass"
                                        )

                elif self.config["bypass"] == 0:

                    try:
                        bypass.delete_cgroup(self.interface)
                    except AttributeError:
                        pass

            except KeyError:
                self.logger.warning('Config file corrupted - bypass option does not exist')

    #determine default ipv4/ipv6 routes and default network interface - moved to NetMon thread
    """@dbus.service.method(BUS_NAME, in_signature='', out_signature='a{ss}')
    def default_gateway_check(self):
        try:
            route_cmd = ["ip", "route", "show", "default", "0.0.0.0/0"]
            default_route = check_output(route_cmd).decode("utf-8")
            parse_route = default_route.split(" ")
            default_gateway_4 = parse_route[2]
            default_interface_4 = parse_route[4]

        except (CalledProcessError, IndexError):
            self.logger.info('Could not identify default gateway - no network connectivity')
            default_gateway_4 = "None"
            default_interface_4 = "None"

        try:
            route_cmd = ["ip", "-6", "route", "show", "default", "::/0"]
            default_route = check_output(route_cmd).decode("utf-8")
            parse_route = default_route.split(" ")
            default_gateway_6 = parse_route[2]
            default_interface_6 = parse_route[4]

        except (CalledProcessError, IndexError):
            self.logger.info('Could not identify default gateway for ipv6 - no network connectivity')
            default_gateway_6 = "None"
            default_interface_6 = "None"

        self.logger.debug("Network interface - ipv4: {}".format(default_interface_4))
        self.logger.debug("Default gateway - ipv4: {}".format(default_gateway_4))
        self.logger.debug("Network interface - ipv6: {}".format(default_interface_6))
        self.logger.debug("Default gateway - ipv6: {}".format(default_gateway_6))

        return {
            "gateway" : default_gateway_4,
            "gateway_6" : default_gateway_6,
            "interface" : default_interface_4,
            "interface_6" : default_interface_6
            }"""

    def cgroup_vpn(self):
        self.kill_dnsmasq()

        if self.tun_bypass is not None:
            dev_bypass = self.tun_bypass
            bypass.create_cgroup(
                            self.net["user"],
                            self.net["group"],
                            dev_bypass,
                            default_int=self.interface
                            )

            if self.tun is not None:
                interface = self.tun

            else:
                interface = self.interface

            interface_bypass = self.tun_bypass
            dns_manager.set_dns("127.0.0.1")
            dns_manager.dnsmasq(
                                interface,
                                "53",
                                self.dns,
                                self.dns_2,
                                ""
                                )

        else:
            dev_bypass = self.interface
            dns_manager.set_dns(self.dns, self.dns_2)

        if self.config["bypass"] == 1:
            dns_manager.dnsmasq(
                                dev_bypass,
                                "5354",
                                self.dns_bypass,
                                self.dns_2_bypass,
                                "_bypass"
                                )

            bypass.create_cgroup(
                                self.net["user"],
                                self.net["group"],
                                dev_bypass,
                                gw=self.gw,
                                gw_6=self.gw_6,
                                default_int=self.interface
                                )

    def kill_dnsmasq(self):
        pid_files = [
                    "/var/run/dnsmasq_qomui.pid",
                    "/var/run/dnsmasq_qomui_bypass.pid"
                    ]

        for f in pid_files:
            try:
                pid = open(f, "r").read().replace("\n", "")
                self.kill_pid((int(pid), "dnsmasq"))

            except FileNotFoundError:
                self.logger.debug("{} does not exist".format(f))

    @dbus.service.signal(BUS_NAME, signature='s')
    def reply(self, msg):
        return msg

    @dbus.service.method(BUS_NAME, in_signature='ss')
    def update_qomui(self, version, packetmanager):
        self.version = version
        self.packetmanager = packetmanager
        self.install_thread = threading.Thread(target=self.update_thread)
        self.install_thread.start()

    def update_thread(self):
        python = sys.executable
        base_url = "https://github.com/corrad1nho/qomui/"

        try:
            if self.packetmanager == "DEB":
                deb_pack = "qomui-{}-amd64.deb".format(self.version[1:])
                deb_url = "{}releases/download/v{}/{}".format(base_url, self.version[1:], deb_pack)
                deb_down = requests.get(deb_url, stream=True, timeout=2)
                with open('{}/{}'.format(ROOTDIR, deb_pack), 'wb') as deb:
                    shutil.copyfileobj(deb_down.raw, deb)

                upgrade_cmd = ["dpkg", "-i", "{}/{}".format(ROOTDIR, deb_pack)]

            elif self.packetmanager == "RPM":
                rpm_pack = "qomui-{}-1.x86_64.rpm".format(self.version[1:])
                rpm_url = "{}releases/download/v{}/{}".format(base_url, self.version[1:], rpm_pack)
                rpm_down = requests.get(rpm_url, stream=True, timeout=2)
                with open('{}/{}'.format(ROOTDIR, rpm_pack), 'wb') as rpm:
                    shutil.copyfileobj(rpm_down.raw, rpm)

                upgrade_cmd = ["rpm", "-i", "{}/{}".format(ROOTDIR, rpm_pack)]

            else:
                url = "{}archive/{}.zip".format(base_url, self.version)
                self.logger.debug(url)
                upgrade_cmd = [
                    python,
                    "-m", "pip",
                    "install", url,
                    "--upgrade",
                    "--force-reinstall",
                    "--no-deps"
                    ]

            check_output(upgrade_cmd, cwd=ROOTDIR)
            with open("{}/VERSION".format(ROOTDIR), "w") as vfile:
                if self.packetmanager != "None":
                    vfile.write("{}\n{}".format(self.version[1:], self.packetmanager))
                else:
                    vfile.write(self.version[1:])
            self.updated(self.version)

        except (CalledProcessError, requests.exceptions.RequestException, FileNotFoundError) as e:
            self.logger.error("{}: Upgrade failed".format(e))
            self.updated("failed")

    @dbus.service.signal(BUS_NAME, signature='s')
    def updated(self, version):
        return version

def main():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    DBusQtMainLoop(set_as_default=True)
    app = QtCore.QCoreApplication([])
    service = QomuiDbus()
    app.exec_()

if __name__ == '__main__':
    main()
