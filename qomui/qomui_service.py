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
from subprocess import Popen, PIPE, check_output, check_call, CalledProcessError, STDOUT

import pexpect
import psutil
import requests
from PyQt5 import QtCore
import dbus
import dbus.service
from dbus.mainloop.pyqt5 import DBusQtMainLoop

from qomui import firewall, bypass

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
    tun = "tun0"
    tun_hop = "tun0"
    connect_status = 0
    config = {}
    wg_connect = 0
    version = "None"

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

    @dbus.service.method(BUS_NAME)
    def restart(self):
        Popen(["systemctl", "daemon-reload"])
        Popen(["systemctl", "restart", "qomui"])

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
        if tun == "tun":
            return self.tun
        elif tun == "hop":
            return self.tun_hop

    @dbus.service.method(BUS_NAME, in_signature='', out_signature='')
    def disconnect(self):
        self.restore_default_dns()
        for i in self.pid_list:
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
        elif provider == "ProtonVPN":
            server.append("account.protonvpn.com")
        self.allow_dns()
        if len(server) > 0:
            for s in server:
                self.logger.info("iptables: Temporarily creating rule to allow access to {}".format(s))
                try:
                    dig_cmd = ["dig", "+time=2", "+tries=1", "{}".format(s), "+short"]
                    answer = check_output(dig_cmd).decode("utf-8")
                    parse = answer.split("\n")
                    ip = parse[len(parse)-2]
                    firewall.add_rule(['-I', 'OUTPUT', '1', '-d', '{}'.format(ip), '-j', 'ACCEPT'])
                except CalledProcessError as e:
                    self.logger.error("{}: Could not resolve {}".format(e, s))

    def allow_dns(self):
        self.logger.debug("iptables: temporarily allowing DNS requests")
        firewall.add_rule(
            ['-I', 'OUTPUT', '1', '-p', 'udp', '-d',
             self.config["alt_dns1"], '--dport', '53', '-j', 'ACCEPT']
            )
        firewall.add_rule(
            ['-I', 'INPUT', '2', '-p', 'udp', '-s',
             self.config["alt_dns1"], '--sport', '53', '-j', 'ACCEPT']
            )
        firewall.add_rule(
            ['-I', 'OUTPUT', '3', '-p', 'udp', '-d',
             self.config["alt_dns2"], '--dport', '53', '-j', 'ACCEPT']
            )
        firewall.add_rule(
            ['-I', 'INPUT', '4', '-p', 'udp', '-s',
             self.config["alt_dns2"], '--sport', '53', '-j', 'ACCEPT']
            )
        self.update_dns()

    @dbus.service.method(BUS_NAME, in_signature='', out_signature='')
    def block_dns(self):
        self.logger.debug("iptables: deleting exception for DNS requests")
        firewall.add_rule(
            ['-D', 'OUTPUT','-p', 'udp', '-d',
             self.config["alt_dns1"], '--dport', '53', '-j', 'ACCEPT']
            )
        firewall.add_rule(
            ['-D', 'INPUT','-p', 'udp', '-s',
             self.config["alt_dns1"], '--sport', '53', '-j', 'ACCEPT']
            )
        firewall.add_rule(
            ['-D', 'OUTPUT','-p', 'udp', '-d',
             self.config["alt_dns2"], '--dport', '53',' -j', 'ACCEPT']
            )
        firewall.add_rule(
            ['-D', 'INPUT','-p', 'udp', '-s',
             self.config["alt_dns2"], '--sport', '53', '-j', 'ACCEPT']
            )

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

    @dbus.service.method(BUS_NAME, in_signature='ss', out_signature='s')
    def copy_rootdir(self, provider, certpath):
        oldmask = os.umask(0o077)
        if not os.path.exists("{}/certs".format(ROOTDIR)):
            os.makedirs("{}/certs".format(ROOTDIR))

        if provider == "Airvpn":
            shutil.copyfile("{}/sshtunnel.key".format(certpath),
                            "{}/certs/sshtunnel.key".format(ROOTDIR))
            shutil.copyfile("{}/stunnel.crt".format(certpath),
                            "{}/certs/stunnel.crt".format(ROOTDIR))
            shutil.copyfile("{}/ca.crt".format(certpath),
                            "{}/certs/ca.crt".format(ROOTDIR))
            shutil.copyfile("{}/ta.key".format(certpath),
                            "{}/certs/ta.key".format(ROOTDIR))
            shutil.copyfile("{}/user.key".format(certpath),
                            "{}/certs/user.key".format(ROOTDIR))
            shutil.copyfile("{}/user.crt".format(certpath),
                            "{}/certs/user.crt".format(ROOTDIR))
            shutil.copyfile("{}/tls-crypt.key".format(certpath),
                            "{}/certs/tls-crypt.key".format(ROOTDIR))

        elif provider == "Mullvad":
            shutil.copyfile("{}/ca.crt".format(certpath),
                            "{}/certs/mullvad_ca.crt".format(ROOTDIR))
            shutil.copyfile("{}/crl.pem".format(certpath),
                            "{}/certs/mullvad_crl.pem".format(ROOTDIR))
            shutil.copyfile("{}/mullvad_userpass.txt".format(certpath),
                            "{}/certs/mullvad_userpass.txt".format(ROOTDIR))
            try:
                shutil.copyfile("{}/mullvad_wg.conf".format(certpath),
                                "{}/certs/mullvad_wg.conf".format(ROOTDIR))
            except FileNotFoundError:
                pass

        elif provider == "PIA":
            shutil.copyfile("{}/crl.rsa.4096.pem".format(certpath),
                            "{}/certs/pia_crl.rsa.4096.pem".format(ROOTDIR))
            shutil.copyfile("{}/ca.rsa.4096.crt".format(certpath),
                            "{}/certs/pia_ca.rsa.4096.crt".format(ROOTDIR))
            shutil.copyfile("{}/pia_userpass.txt".format(certpath),
                            "{}/certs/pia_userpass.txt".format(ROOTDIR))

        elif provider == "Windscribe":
            shutil.copyfile("{}/ca.crt".format(certpath),
                            "{}/certs/ca_ws.crt".format(ROOTDIR))
            shutil.copyfile("{}/ta.key".format(certpath),
                            "{}/certs/ta_ws.key".format(ROOTDIR))
            shutil.copyfile("{}/windscribe_userpass.txt".format(certpath),
                            "{}/certs/windscribe_userpass.txt".format(ROOTDIR))

        elif provider == "ProtonVPN":
            shutil.copyfile("{}/proton_ca.crt".format(certpath),
                            "{}/certs/proton_ca.crt".format(ROOTDIR))
            shutil.copyfile("{}/proton_ta.key".format(certpath),
                            "{}/certs/proton_ta.key".format(ROOTDIR))
            shutil.copyfile("{}/proton_userpass.txt".format(certpath),
                            "{}/certs/proton_userpass.txt".format(ROOTDIR))

        elif provider.find("CHANGE") != -1:
            provider = provider.split("_")[1]
            for f in os.listdir(certpath):
                f_source = "{}/{}".format(certpath, f)
                if provider in SUPPORTED_PROVIDERS:
                    f_dest = "{}/{}".format(ROOTDIR, f)
                else:
                    f_dest = "{}/{}/{}".format(ROOTDIR, provider, f)
                shutil.copyfile(f_source, f_dest)
                self.logger.debug("copied {} to {}".format(f, f_dest))

        else:
            for f in os.listdir(certpath):
                f_source = "{}/{}".format(certpath, f)
                f_dest = "{}/{}/{}".format(ROOTDIR, provider, f)
                if os.path.isfile(f_source):

                    try:
                        shutil.copyfile(f_source, f_dest)
                        self.logger.debug("copied {} to {}".format(f, f_dest))

                    except FileNotFoundError:
                        if not os.path.exists("{}/{}".format(ROOTDIR, provider)):
                            os.makedirs("{}/{}".format(ROOTDIR, provider))

                        shutil.copyfile(f_source,f_dest)
                        self.logger.debug("copied {} to {}".format(f, f_dest))

                elif os.path.isdir(f_source):

                    try:
                        shutil.rmtree(f_dest)

                    except (NotADirectoryError, FileNotFoundError):
                        pass

                    shutil.copytree(f_source, f_dest)
                    self.logger.debug("copied folder {} to {}".format(f, f_dest))

            try:
                auth_file = "{}/{}/{}-auth.txt".format(ROOTDIR, provider, provider)
                shutil.copyfile(auth_file, "{}/certs/{}-auth.txt".format(ROOTDIR, provider))
                os.remove(auth_file)

            except FileNotFoundError:
                pass

        self.logger.debug("Copied certificates and keys to {}/certs".format(ROOTDIR))
        self.logger.debug("Removed temporary files")
        for key in [file for file in os.listdir("{}/certs".format(ROOTDIR))]:
            Popen(['chown', 'root', '{}/certs/{}'.format(ROOTDIR, key)])
            Popen(['chmod', '0600', '{}/certs/{}'.format(ROOTDIR, key)])
        os.umask(oldmask)
        return "copied"

    @dbus.service.method(BUS_NAME, in_signature='s', out_signature='')
    def delete_provider(self, provider):
        path = "{}/{}".format(ROOTDIR, provider)
        if os.path.exists(path):
            shutil.rmtree(path)
            try:
                os.remove("{}/certs/{}-auth.txt".format(ROOTDIR, provider))
            except FileNotFoundError:
                pass

    def update_dns(self, dns1=None, dns2=None):
        dns = open("/etc/resolv.conf", "w")

        try:
            alt_dns = self.config["alt_dns"]
        except KeyError:
            alt_dns = 0

        if dns1 is not None and alt_dns == 0:
            if dns2 is not None:
                dns.write("nameserver {}\nnameserver {}\n".format(dns1, dns2))
            else:
                dns.write("nameserver {}\n".format(dns1))
        else:
            dns1 = self.config["alt_dns1"]
            dns2 = self.config["alt_dns2"]
            dns.write("nameserver {}\nnameserver {}\n".format(dns1, dns2))
        self.logger.info("DNS: Overwriting /etc/resolv.conf with {} and {}".format(dns1, dns2))

    @dbus.service.method(BUS_NAME, in_signature='a{ss}', out_signature='')
    def bypass(self, ug):
        self.ug = ug
        try:
            self.kill_pid(self.dnsmasq_pid)
        except AttributeError:
            pass

        default_routes = self.default_gateway_check()
        default_gateway_4 = default_routes["gateway"]
        default_gateway_6 = default_routes["gateway_6"]
        self.default_interface_4 = default_routes["interface"]
        self.default_interface_6 = default_routes["interface_6"]

        if default_gateway_4 != "None" or default_gateway_6 != "None":
            try:
                if self.config["bypass"] == 1:
                    bypass.create_cgroup(
                        self.ug["user"],
                        self.ug["group"],
                        self.default_interface_4,
                        default_gateway_4,
                        self.default_interface_6,
                        default_gateway_6
                        )

                    if self.default_interface_4 != "None":
                        interface = self.default_interface_4

                    else:
                        interface = self.default_interface_6

                    try:
                        dnsmasq = Popen(
                                        ["dnsmasq", "--port=5354", "--interface={}".format(interface),
                                         "--server={}".format(self.config["alt_dns1"]),
                                         "--server={}".format(self.config["alt_dns2"])]
                                         )

                        self.logger.debug(dnsmasq.pid +2)
                        self.dnsmasq_pid = (dnsmasq.pid +2, "dnsmasq")

                    except CalledProcessError:
                        logging.error("Failed to start dnsmasq for cgroup qomui_bypass")

                elif self.config["bypass"] == 0:

                    try:
                        bypass.delete_cgroup(self.default_interface_4, self.default_interface_6)
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

        self.logger.info("(ip)tables: created rule for {}".format(ip))

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

            self.update_dns(dns1=self.dns, dns2=self.dns_2)

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

            self.reply("success")

        except (CalledProcessError, FileNotFoundError):
            self.reply("fail1")



    def ovpn(self, ovpn_file, h, cwd_ovpn):
        logging.info("Establishing new OpenVPN tunnel")
        name = self.ovpn_dict["name"]
        last_ip = self.ovpn_dict["ip"]
        if h == "1":
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

        ovpn_exe = Popen(cmd_ovpn, stdout=PIPE, stderr=STDOUT,
                         cwd=cwd_ovpn, bufsize=1, universal_newlines=True
                         )

        self.add_pid((ovpn_exe.pid, "OpenVPN"))
        line = ovpn_exe.stdout.readline()
        while line.find("SIGTERM[hard,] received, process exiting") == -1:
            self.conn_info(line.replace('\n', ''))
            line_format = ("OpenVPN:" + line.replace('{}'.format(time.asctime()), '').replace('\n', ''))
            logging.info(line_format)
            if line.find("Initialization Sequence Completed") != -1:
                self.connect_status = 1
                self.reply("success")
                self.logger.info("Successfully connected to {}".format(name))
            elif line.find('TUN/TAP device') != -1:
                if h == "2":
                    self.tun = line_format.split(" ")[3]
                elif h == "1":
                    self.tun_hop = line_format.split(" ")[3]
                else:
                    self.tun = line_format.split(" ")[3]
            elif line.find('PUSH: Received control message:') != -1:
                dns_option_1 = line_format.find('dhcp-option')
                if dns_option_1 != -1:
                    option = line_format[dns_option_1:].split(",")[0]
                    self.dns = option.split(" ")[2]
                    dns_option_2 = line_format.find('dhcp-option', dns_option_1+20)
                    if dns_option_2 != -1:
                        option = line_format[dns_option_2:].split(",")[0]
                        self.dns_2 = option.split(" ")[2]
                        self.update_dns(dns1=self.dns, dns2=self.dns_2)
                    else:
                        self.dns_2 = None
                        self.update_dns(dns1=self.dns)
                else:
                    self.update_dns()
            elif line.find("Restart pause, 10 second(s)") != -1:
                self.reply("fail1")
                self.logger.info("Connection attempt failed")
            elif line.find("SIGTERM[soft,auth-failure]") != -1:
                self.reply("fail1")
                self.logger.info("Connection attempt failed")
            elif line.find('SIGTERM[soft,auth-failure]') != -1:
                self.reply("fail2")
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
        self.reply("kill")
        self.logger.info("OpenVPN - process killed")
        rule = (['-D', 'OUTPUT', '-d', '{}'.format(last_ip), '-j', 'ACCEPT'])
        self.allow_ip(last_ip, rule)

    def ssl(self, ip):
        cmd_ssl = ['stunnel', '{}'.format("{}/temp.ssl".format(ROOTDIR))]
        ssl_exe = Popen(cmd_ssl, stdout=PIPE, stderr=STDOUT, bufsize=1, universal_newlines=True)
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
