#!/usr/bin/env python3

import sys
import os
import time
import threading
import shutil
import logging
import logging.handlers
import json
import signal

from datetime import datetime, date
from subprocess import Popen, PIPE, check_output, check_call, CalledProcessError, STDOUT

import pexpect
import psutil
import requests
from PyQt5 import QtCore
import dbus
import dbus.service
from dbus.mainloop.pyqt5 import DBusQtMainLoop

from qomui import firewall, bypass, update, dns_manager

ROOTDIR = "/usr/share/qomui"
OPATH = "/org/qomui/service"
IFACE = "org.qomui.service"
BUS_NAME = "org.qomui.service"
SUPPORTED_PROVIDERS = ["Airvpn", "Mullvad", "ProtonVPN", "PIA", "Windscribe"]

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
    hop_dict = {"none" : "none"}
    tun = None
    tun_hop = None
    tun_bypass = None
    connect_status = 0
    config = {}
    wg_connect = 0
    version = "None"
    thread_list = []

    def __init__(self):
        self.sys_bus = dbus.SystemBus()
        self.bus_name = dbus.service.BusName(BUS_NAME, bus=self.sys_bus)
        dbus.service.Object.__init__(self, self.bus_name, OPATH)
        self.logger = logging.getLogger()
        self.gui_handler = GuiLogHandler(self.send_log)
        self.gui_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(self.gui_handler)
        self.filehandler = logging.handlers.RotatingFileHandler("{}/qomui.log".format(ROOTDIR),
                                                       maxBytes=2*1024*1024, backupCount=1)
        self.logger.addHandler(self.filehandler)
        self.filehandler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.setLevel(logging.DEBUG)
        self.logger.info("Dbus-service successfully initialized")
        self.check_version()
        self.load_firewall(0)

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

    @dbus.service.method(BUS_NAME, in_signature='s')
    def share_log(self, msg):
        record = json.loads(msg)
        log = logging.makeLogRecord(record)
        self.filehandler.handle(log)
        self.gui_handler.handle(log)

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='')
    def log_level_change(self, level):
        self.logger.setLevel(getattr(logging, level.upper()))
        self.config["log_level"] = level

        with open('{}/config.json'.format(ROOTDIR), 'w') as save_config:
            json.dump(self.config, save_config)

    @dbus.service.method(BUS_NAME, in_signature='a{ss}', out_signature='')
    def connect_to_server(self, ovpn_dict):
        self.ovpn_dict = ovpn_dict
        self.hop = self.ovpn_dict["hop"]
        self.connect_thread = threading.Thread(target=self.vpn_thread)
        self.connect_thread.start()
        self.logger.debug("New thread for OpenVPN process started")

    @dbus.service.method(BUS_NAME, in_signature='a{ss}', out_signature='')
    def set_hop(self, ovpn_dict):
        self.hop_dict = ovpn_dict

    def add_pid(self, pid):
        self.pid_list.append(pid)

    @dbus.service.signal(BUS_NAME, signature='s')
    def send_log(self, msg):
        return msg

    @dbus.service.signal(BUS_NAME, signature='s')
    def conn_info(self, msg):
        return msg

    @dbus.service.method(BUS_NAME, in_signature='i', out_signature='')
    def load_firewall(self, activate):
        try:
            with open('{}/config.json'.format(ROOTDIR), 'r') as c:
                self.config = json.load(c)

        except (FileNotFoundError, json.decoder.JSONDecodeError) as e:
            self.logger.error('{}: Could not open config.json - loading default configuration'.format(e))
            with open('{}/default_config.json'.format(ROOTDIR), 'r') as c:
                self.config = json.load(c)

        try:
            self.logger.setLevel(self.config["log_level"].upper())

        except KeyError:
            pass

        try:
            if self.config["fw_gui_only"] == 0:
                activate = 1

        except KeyError:
            activate = 1

        try:
            if self.config["preserve_rules"] == 1:
                preserve = 1
            else:
                preserve = 0

        except KeyError:
            preserve = 0

        try:
            if self.config["block_lan"] == 1:
                block_lan = 1
            else:
                block_lan = 0

        except KeyError:
            block_lan = 0

        try:
            if activate == 1:
                firewall.apply_rules(self.config["firewall"], block_lan=block_lan, preserve=preserve)
            elif activate == 2:
                if self.config["fw_gui_only"] == 1:
                    firewall.apply_rules(0, block_lan=block_lan, preserve=1)
                    try:
                        bypass.delete_cgroup(self.default_interface_4, self.default_interface_6)
                    except AttributeError:
                        pass
            self.disable_ipv6(self.config["ipv6_disable"])

        except KeyError:
            self.logger.warning('Could not read all values from config file')

        self.dns = self.config["alt_dns1"]
        self.dns_2 = self.config["alt_dns2"]

    @dbus.service.method(BUS_NAME, in_signature='i', out_signature='')
    def disable_ipv6(self, i):
        if i == 1:
            Popen(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=1'])
            self.logger.info('Disabled ipv6')
        else:
            Popen(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0'])
            self.logger.info('(Re-)enabled ipv6')

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
                        logging.info("WireGuard: " + line.decode("utf-8").replace("\n", ""))

                except CalledProcessError:
                    pass

                wg_rules = [
                    ["-D", "INPUT", "-i", "wg_qomui", "-j", "ACCEPT"],
                    ["-D", "OUTPUT", "-o", "wg_qomui", "-j", "ACCEPT"]
                    ]

                for rule in wg_rules:
                    firewall.add_rule_6(rule)
                    firewall.add_rule(rule)

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

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='')
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
                f_dest = "{}/{}".format(ROOTDIR, f)
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
                    auth_file = "{}/certs/{}-auth.txt".format(ROOTDIR, provider)

                    with open(auth_file, "r") as auth:
                        up = auth.read().split("\n")
                        credentials["username"] = up[0]
                        credentials["password"] = up[1]

                except FileNotFoundError:
                    self.logger.error("Could not find {} - Aborting update".format(auth_file))

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
        dns_manager.dns_request_exception("-D", self.config["alt_dns1"], self.config["alt_dns2"], "53")

        with open('{}/{}.json'.format(self.homedir, provider), 'w') as p:
            json.dump(content, p)

        if provider in SUPPORTED_PROVIDERS:
            with open('{}/config.json'.format(ROOTDIR), 'w') as save_config:
                self.config["{}_last".format(provider)] = str(datetime.utcnow())
                json.dump(self.config, save_config)

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
    def bypass(self, ug):
        self.ug = ug
        default_routes = self.default_gateway_check()
        default_gateway_4 = default_routes["gateway"]
        default_gateway_6 = default_routes["gateway_6"]
        default_interface_4 = default_routes["interface"]
        default_interface_6 = default_routes["interface_6"]

        if default_gateway_4 != "None" or default_gateway_6 != "None":
            try:

                if default_interface_6 != "None":
                    self.interface = default_interface_6

                elif default_interface_4 != "None":
                    self.interface = default_interface_4

                else:
                    self.interface = "eth0"

                if self.config["bypass"] == 1:
                    bypass.create_cgroup(
                        self.ug["user"],
                        self.ug["group"],
                        self.interface,
                        gw=default_gateway_4,
                        gw_6=default_gateway_6,
                        default_int=self.interface
                        )

                    self.kill_dnsmasq()
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

    @dbus.service.method(BUS_NAME, in_signature='', out_signature='a{ss}')
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

        return {
            "gateway" : default_gateway_4,
            "gateway_6" : default_gateway_6,
            "interface" : default_interface_4,
            "interface_6" : default_interface_6
            }

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
                url = "{}archive/{}.zip".format(base.url, self.version)
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

    def vpn_thread(self):
        self.connect_status = 0
        ip = self.ovpn_dict["ip"]
        rule = (['-I', 'OUTPUT', '1', '-d', '{}'.format(ip), '-j', 'ACCEPT'])
        self.allow_ip(ip, rule)

        self.logger.info("iptables: created rule for {}".format(ip))

        try:
            if self.ovpn_dict["tunnel"] == "WireGuard":
                self.wireguard()
            else:
                self.openvpn()
        except KeyError:
            self.openvpn()

    def wireguard(self):
        oldmask = os.umask(0o077)
        path = "{}/wg_qomui.conf".format(ROOTDIR)
        if self.ovpn_dict["provider"] == "Mullvad":
            with open("{}/certs/mullvad_wg.conf".format(ROOTDIR), "r") as wg:
                conf = wg.readlines()
                conf.insert(8, "PublicKey = {}\n".format(self.ovpn_dict["public_key"]))
                conf.insert(9, "Endpoint = {}:{}\n".format(self.ovpn_dict["ip"], self.ovpn_dict["port"]))
                with open(path, "w") as temp_wg:
                    temp_wg.writelines(conf)

        else:
            shutil.copyfile("{}/{}".format(ROOTDIR, self.ovpn_dict["path"]), path)

        os.umask(oldmask)
        Popen(['chmod', '0600', path])

        self.wg(path)

    def openvpn(self):
        self.air_ssl_port = "1413"
        self.ws_ssl_port = "1194"
        path = "{}/temp.ovpn".format(ROOTDIR)
        cwd_ovpn = None
        provider = self.ovpn_dict["provider"]
        ip = self.ovpn_dict["ip"]

        try:
            port = self.ovpn_dict["port"]
            protocol = self.ovpn_dict["protocol"]

        except KeyError:
            pass

        path = "{}/temp.ovpn".format(ROOTDIR)
        if provider == "Airvpn":
            if protocol == "SSL":
                with open("{}/ssl_config".format(ROOTDIR), "r") as ssl_edit:
                    ssl_config = ssl_edit.readlines()
                    for line, value in enumerate(ssl_config):
                        if value.startswith("connect") is True:
                            ssl_config[line] = "connect = {}:{}\n".format(ip, port)
                        elif value.startswith("accept") is True:
                            ssl_config[line] = "accept = 127.0.0.1:{}\n".format(self.air_ssl_port)
                    ssl_config.append("verify = 3\n")
                    ssl_config.append("CAfile = /usr/share/qomui/certs/stunnel.crt")
                    with open("{}/temp.ssl".format(ROOTDIR), "w") as ssl_dump:
                        ssl_dump.writelines(ssl_config)
                        ssl_dump.close()
                    ssl_edit.close()
                self.write_config(self.ovpn_dict)
                self.ssl_thread = threading.Thread(target=self.ssl, args=(ip,))
                self.ssl_thread.start()
                logging.info("Started Stunnel process in new thread")
            elif protocol == "SSH":
                self.write_config(self.ovpn_dict)
                self.ssh_thread = threading.Thread(target=self.ssh, args=(ip,port,))
                self.ssh_thread.start()
                logging.info("Started SSH process in new thread")
                time.sleep(2)
            else:
                self.write_config(self.ovpn_dict)

        elif provider == "Mullvad":
            self.write_config(self.ovpn_dict)

        elif provider == "PIA":
            self.write_config(self.ovpn_dict)

        elif provider == "Windscribe":
            if protocol == "SSL":
                with open("{}/ssl_config".format(ROOTDIR), "r") as ssl_edit:
                    ssl_config = ssl_edit.readlines()
                    for line, value in enumerate(ssl_config):
                        if value.startswith("connect") is True:
                            ssl_config[line] = "connect = {}:{}\n".format(ip, port)
                        elif value.startswith("accept") is True:
                            ssl_config[line] = "accept = 127.0.0.1:{}\n".format(self.ws_ssl_port)
                    with open("{}/temp.ssl".format(ROOTDIR), "w") as ssl_dump:
                        ssl_dump.writelines(ssl_config)
                        ssl_dump.close()
                    ssl_edit.close()
                self.write_config(self.ovpn_dict)
                self.ssl_thread = threading.Thread(target=self.ssl, args=(ip,))
                self.ssl_thread.start()
                logging.info("Started Stunnel process in new thread")

            self.write_config(self.ovpn_dict)

        elif provider == "ProtonVPN":
            self.write_config(self.ovpn_dict)

        else:
            config_file = "{}/{}".format(ROOTDIR, self.ovpn_dict["path"])

            try:
                edit = "{}/temp".format(provider)
                self.write_config(self.ovpn_dict,
                                  edit=edit, path=config_file)

                path = "{}/{}/temp.ovpn".format(ROOTDIR, provider)

            except UnboundLocalError:
                path = config_file
            cwd_ovpn = os.path.dirname(config_file)

        if self.hop == "2":
            rule = (['-I', 'OUTPUT', '1', '-d', '{}'.format(self.hop_dict["ip"]), '-j', 'ACCEPT'])
            self.allow_ip(self.hop_dict["ip"], rule)

            if self.hop_dict["provider"] in SUPPORTED_PROVIDERS:
                hop_path = "{}/hop.ovpn".format(ROOTDIR)
                self.write_config(self.hop_dict, edit="hop")
            else:
                config_file = "{}/{}".format(ROOTDIR, self.hop_dict["path"])
                try:
                    edit = "{}/hop".format(self.hop_dict["provider"])
                    self.write_config(self.hop_dict, edit=edit, path=config_file)
                    hop_path = "{}/{}/temp.ovpn".format(ROOTDIR, self.hop_dict["provider"])

                except (UnboundLocalError, KeyError):
                    hop_path = config_file

                cwd_ovpn = os.path.dirname(config_file)
            self.hop_thread = threading.Thread(target=self.ovpn, args=(hop_path,
                                                                       "1", cwd_ovpn,))
            self.hop_thread.start()
            while self.connect_status == 0:
                time.sleep(1)

        self.ovpn(path, self.hop, cwd_ovpn)

    def write_config(self, ovpn_dict, edit="temp", path=None):
        provider = ovpn_dict["provider"]
        ip = ovpn_dict["ip"]
        port = ovpn_dict["port"]
        protocol = ovpn_dict["protocol"]

        if path is None:
            ovpn_file = "{}/{}_config".format(ROOTDIR, provider)
        else:
            ovpn_file = path

        with open(ovpn_file, "r") as ovpn_edit:
            config = ovpn_edit.readlines()

            if protocol == "SSL":
                config.insert(13, "route {} 255.255.255.255 net_gateway\n".format(ip))
                ip = "127.0.0.1"

                if provider == "Airvpn":
                    port = self.air_ssl_port

                elif provider == "Windscribe":
                    port = self.ws_ssl_port

                protocol = "tcp"

            elif protocol == "SSH":
                config.insert(13, "route {} 255.255.255.255 net_gateway\n".format(ip))
                ip = "127.0.0.1"
                port = "1412"
                protocol = "tcp"

            if "bypass" in ovpn_dict:

                if ovpn_dict["bypass"] == "1":
                    config.append("iproute /usr/share/qomui/bypass_route.sh\n")
                    #config.append("route-noexec\n")
                    config.append("script-security 2\n")
                    config.append("route-up /usr/share/qomui/bypass_up.sh\n")

            for line, value in enumerate(config):
                if value.startswith("proto ") is True:

                    try:
                        if ovpn_dict["ipv6"] == "on":
                            config.append("setenv UV_IPV6 yes \n")
                            config[line] = "proto {}6 \n".format(protocol.lower())

                        else:
                            config[line] = "proto {} \n".format(protocol.lower())

                    except KeyError:
                        config[line] = "proto {} \n".format(protocol.lower())

                elif value.startswith("remote ") is True:
                    config[line] = "remote {} {} \n".format(ip.replace("\n", ""), port)

            if provider == "Airvpn":
                try:

                    if ovpn_dict["tlscrypt"] == "on":
                        config.append("tls-crypt {}/certs/tls-crypt.key \n".format(ROOTDIR))
                        config.append("auth sha512")

                    else:
                        config.append("tls-auth {}/certs/ta.key 1 \n".format(ROOTDIR))

                except KeyError:
                    config.append("tls-auth {}/certs/ta.key 1 \n".format(ROOTDIR))

            with open("{}/{}.ovpn".format(ROOTDIR, edit), "w") as ovpn_dump:
                    ovpn_dump.writelines(config)
                    ovpn_dump.close()

            ovpn_edit.close()

        logging.debug("Temporary config file(s) for requested server written")


    def wg(self, wg_file):
        name = self.ovpn_dict["name"]
        self.logger.info("Establishing connection to {}".format(name))

        wg_rules = [["-I", "INPUT", "2", "-i", "wg_qomui", "-j", "ACCEPT"],
                    ["-I", "OUTPUT", "2", "-o", "wg_qomui", "-j", "ACCEPT"]
                    ]

        for rule in wg_rules:
            firewall.add_rule_6(rule)
            firewall.add_rule(rule)

        time.sleep(1)

        try:
            self.tun = "wg_qomui"
            cmd_wg = Popen(['wg-quick', 'up', '{}'.format(wg_file)], stdout=PIPE, stderr=STDOUT)
            for line in cmd_wg.stdout:
                logging.info("WireGuard: " + line.decode("utf-8").replace("\n", ""))
            self.wg_connect = 1

            with open("{}/wg_qomui.conf".format(ROOTDIR), "r") as dns_check:
                lines = dns_check.readlines()

                for line in lines:
                    if line.startswith("DNS ="):
                        dns_servers = line.split("=")[1].replace(" ", "").split(",")
                        self.dns = dns_servers[0].split("\n")[0]

                        try:
                            self.dns_2 = dns_servers[1].split("\n")[0]

                        except IndexError:
                            self.dns_2 = None

            if self.tun_bypass is not None:
                bypass.create_cgroup(
                        self.ug["user"],
                        self.ug["group"],
                        self.tun_bypass,
                        default_int=self.interface
                        )

                self.configure_dnsmasq()

            else:
                dns_manager.set_dns(self.dns, server_2=self.dns_2)

            #Necessary, otherwise bypass mode breaks
            if self.config["bypass"] == 1:

                try:
                    check_call(["ip", "rule", "del", "fwmark", "11", "table", "bypass_qomui"])
                    check_call(["ip", "-6", "rule", "del", "fwmark", "11", "table", "bypass_qomui"])

                except CalledProcessError:
                    pass

                try:
                    check_call(["ip", "rule", "add", "fwmark", "11", "table", "bypass_qomui"])
                    check_call(["ip", "-6", "rule", "add", "fwmark", "11", "table", "bypass_qomui"])
                    self.logger.debug("Packet classification for bypass table reset")

                except CalledProcessError:
                    self.logger.warning("Could not reset packet classification for bypass table")

            self.reply("connected")

        except (CalledProcessError, FileNotFoundError):
            self.reply("fail")

    def ovpn(self, ovpn_file, h, cwd_ovpn):
        logging.info("Establishing new OpenVPN tunnel")
        name = self.ovpn_dict["name"]
        last_ip = self.ovpn_dict["ip"]
        add = ""

        if h == "1":
            add = "_hop"
            name = self.hop_dict["name"]
            self.logger.info("Establishing connection to {} - first hop".format(name))
            last_ip = self.hop_dict["ip"]
            cmd_ovpn = ['openvpn',
                        '--config', '{}'.format(ovpn_file),
                        '--route-nopull',
                        '--script-security', '2',
                        '--up', '/usr/share/qomui/hop.sh -f {} {}'.format(self.hop_dict["ip"],
                                                                     self.ovpn_dict["ip"]
                                                                     ),
                        '--down', '/usr/share/qomui/hop_down.sh {}'.format(self.hop_dict["ip"])
                        ]

        elif h == "2":
            self.logger.info("Establishing connection to {} - second hop".format(name))
            cmd_ovpn = ['openvpn',
                        '--config', '{}'.format(ovpn_file),
                        '--route-nopull',
                        '--script-security', '2',
                        '--up', '{}/hop.sh -s'.format(ROOTDIR)
                        ]

        else:
            self.logger.info("Establishing connection to {}".format(name))
            cmd_ovpn = ['openvpn', '{}'.format(ovpn_file)]

        if "bypass" in self.ovpn_dict:
            add = "_bypass"
            self.dns_bypass = self.config["alt_dns1"]
            self.dns_2_bypass = self.config["alt_dns2"]

        else:
            self.dns = self.config["alt_dns1"]
            self.dns_2 = self.config["alt_dns2"]

        ovpn_exe = Popen(cmd_ovpn, stdout=PIPE, stderr=STDOUT,
                         cwd=cwd_ovpn, bufsize=1, universal_newlines=True
                         )

        self.logger.debug("OpenVPN pid: {}".format(ovpn_exe.pid))
        self.add_pid((ovpn_exe.pid, "OpenVPN{}".format(add)))
        line = ovpn_exe.stdout.readline()

        while line.find("SIGTERM[hard,] received, process exiting") == -1:
            self.conn_info(line.replace('\n', ''))
            line_format = ("OpenVPN:" + line.replace('{}'.format(time.asctime()), '').replace('\n', ''))
            logging.info(line_format)

            if line.find("Initialization Sequence Completed") != -1:
                self.connect_status = 1
                if self.tun_bypass is not None:
                    bypass.create_cgroup(
                        self.ug["user"],
                        self.ug["group"],
                        self.tun_bypass,
                        default_int=self.interface
                        )

                    self.configure_dnsmasq()

                self.reply("connected{}".format(add))
                self.logger.info("Successfully connected to {}".format(name))

            elif line.find('TUN/TAP device') != -1:
                setattr(self, "tun{}".format(add), line_format.split(" ")[3])

            elif line.find('PUSH: Received control message:') != -1:
                dns_option_1 = line_format.find('dhcp-option')

                if dns_option_1 != -1:
                    option = line_format[dns_option_1:].split(",")[0]
                    setattr(self, "dns{}".format(add), option.split(" ")[2])
                    dns_option_2 = line_format.find('dhcp-option', dns_option_1+20)
                    self.logger.debug("Found DNS server in OpenVPN push: ".format(self.dns))

                    if dns_option_2 != -1:
                        option = line_format[dns_option_2:].split(",")[0]
                        setattr(self, "dns_2{}".format(add), option.split(" ")[2])
                        self.logger.debug("Found DNS server in OpenVPN push: ".format(self.dns_2))

                    else:
                        setattr(self, "dns_2{}".format(add), None)

                dns_manager.set_dns(self.dns, server_2=self.dns_2)

            elif line.find("Restart pause, 10 second(s)") != -1:
                self.reply("fail{}".format(add))
                self.logger.info("Connection attempt failed")

            elif line.find('SIGTERM[soft,auth-failure]') != -1:
                self.reply("fail_auth{}".format(add))
                self.logger.info("Authentication error while trying to connect")

            elif line.find('write UDP: Operation not permitted') != -1:
                ips = []

                try:
                    hop_ip = self.hop_dict["ip"]
                    ips.append(hop_ip)

                except:
                    pass

                remote_ip = self.ovpn_dict["ip"]
                ips.append(remote_ip)

                for ip in ips:
                    rule = (['-I', 'OUTPUT', '1', '-d', '{}'.format(ip), '-j', 'ACCEPT'])
                    self.allow_ip(ip, rule)

            elif line == '':
                break

            line = ovpn_exe.stdout.readline()

        logging.info("OpenVPN:" + line.replace('{}'.format(time.asctime()), '').replace('\n', ''))
        ovpn_exe.stdout.close()
        self.reply("killed{}".format(add))
        self.logger.info("OpenVPN - process killed")
        rule = (['-D', 'OUTPUT', '-d', '{}'.format(last_ip), '-j', 'ACCEPT'])
        self.allow_ip(last_ip, rule)

        if add == "_bypass":
            setattr(self, "dns{}".format(add), self.config["alt_dns1"])
            setattr(self, "dns{}_2".format(add), self.config["alt_dns2"])
            firewall.cgroup_vpn_firewall(0, self.interface)
            bypass.set_bypass_vpn(self.interface, "-A", self.tun_bypass, "-D")
            setattr(self, "tun{}".format(add), None)
            self.configure_dnsmasq()

        else:
            setattr(self, "tun{}".format(add), None)

    def ssl(self, ip):
        cmd_ssl = ['stunnel', '{}'.format("{}/temp.ssl".format(ROOTDIR))]
        ssl_exe = Popen(cmd_ssl, stdout=PIPE, stderr=STDOUT, bufsize=1, universal_newlines=True)
        self.logger.debug("Stunnel pid: {}".format(ssl_exe.pid))
        self.add_pid((ssl_exe.pid, "stunnel"))
        line = ssl_exe.stdout.readline()

        while line.find('SIGINT') == -1:
            logging.info("Stunnel: " + line.replace('\n', ''))
            if line == '':
                break

            elif line.find("Configuration succesful") != -1:
                logging.info("Stunnel: Successfully opened SSL tunnel to {}".format(self.ip))

            line = ssl_exe.stdout.readline()
        ssl_exe.stdout.close()

    def ssh(self, ip, port):
        cmd_ssh = "ssh -i {}/certs/sshtunnel.key -L 1412:127.0.0.1:2018 sshtunnel@{} -p {} -N -T -v".format(ROOTDIR, ip, port)
        ssh_exe = pexpect.spawn(cmd_ssh)
        ssh_newkey = b'Are you sure you want to continue connecting'
        ssh_success = 'Forced command'
        self.logger.debug("SSH pid: {}".format(ssh_exe.pid))
        self.add_pid((ssh_exe.pid, "ssh"))
        i = ssh_exe.expect([ssh_newkey, ssh_success])

        if i == 0:
            ssh_exe.sendline('yes')
            logging.info("SSH: Accepted SHA fingerprint from {}".format(ip))

        before = ssh_exe.before.decode("utf-8")
        after = ssh_exe.after.decode("utf-8")
        full = (before + after)

        for line in full.split("\n"):
            logging.info("SSH: " + line.replace("\r", ""))

        logging.info("SSH: Successfully opened SSH tunnel to {}".format(ip))
        ssh_exe.wait()

    def configure_dnsmasq(self):
        if self.tun is not None:
            interface = self.tun

        else:
            interface = self.interface

        if self.tun_bypass is not None:
            interface_bypass = self.tun_bypass

        else:
            interface_bypass = self.interface


        self.kill_dnsmasq()

        dns_manager.dnsmasq(
                            interface,
                            "53",
                            self.dns,
                            self.dns_2,
                            ""
                            )

        dns_manager.dnsmasq(
                            interface_bypass,
                            "5354",
                            self.dns_bypass,
                            self.dns_2_bypass,
                            "_bypass"
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

    def allow_ip(self, ip, rule):

        try:
            if len(ip.split(".")) == 4:
                firewall.add_rule(rule)

            elif len(ip.split(":")) >= 4:
                firewall.add_rule_6(rule)
        except:
            pass

def main():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    DBusQtMainLoop(set_as_default=True)
    app = QtCore.QCoreApplication([])
    service = QomuiDbus()
    app.exec_()

if __name__ == '__main__':
    main()
