#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import threading
import shutil
import shlex
from subprocess import Popen, PIPE, STDOUT, CalledProcessError, check_call, run
import pexpect
from PyQt5 import QtCore
from qomui import firewall, dns_manager

ROOTDIR = "/usr/share/qomui"
SUPPORTED_PROVIDERS = ["Airvpn", "Mullvad", "ProtonVPN", "PIA", "Windscribe"]

class TunnelThread(QtCore.QThread):
    log = QtCore.pyqtSignal(tuple)
    status = QtCore.pyqtSignal(str)
    dev = QtCore.pyqtSignal(tuple)
    dnsserver = QtCore.pyqtSignal(tuple)
    bypass = QtCore.pyqtSignal()
    pid = QtCore.pyqtSignal(tuple)
    tun = None
    tun_hop = None
    tun_bypass = None

    def __init__(self, server_dict, hop_dict, config):
        QtCore.QThread.__init__(self)
        self.server_dict = server_dict
        self.hop = self.server_dict["hop"]
        self.hop_dict = hop_dict
        self.config = config

    def run(self):
        self.connect_status = 0
        ip = self.server_dict["ip"]
        firewall.allow_dest_ip(ip, "-I")

        self.log.emit(("info", "iptables: created rule for {}".format(ip)))

        try:
            if self.server_dict["tunnel"] == "WireGuard":
                self.wireguard()
            else:
                self.openvpn()
        except KeyError:
            self.openvpn()

    def wireguard(self):
        #make sure temporary wg conf is not world readable
        oldmask = os.umask(0o077)
        path = "{}/wg_qomui.conf".format(ROOTDIR)
        if self.server_dict["provider"] == "Mullvad":
            with open("{}/certs/mullvad_wg.conf".format(ROOTDIR), "r") as wg:
                conf = wg.readlines()
                conf.insert(8, "PublicKey = {}\n".format(self.server_dict["public_key"]))
                conf.insert(9, "Endpoint = {}:{}\n".format(self.server_dict["ip"], self.server_dict["port"]))
                with open(path, "w") as temp_wg:
                    temp_wg.writelines(conf)

        else:
            shutil.copyfile("{}/{}".format(ROOTDIR, self.server_dict["path"]), path)

        os.umask(oldmask)
        Popen(['chmod', '0600', path])
        self.wg(path)

    def openvpn(self):
        self.air_ssl_port = "1413"
        self.ws_ssl_port = "1194"
        path = "{}/temp.ovpn".format(ROOTDIR)
        cwd_ovpn = None
        provider = self.server_dict["provider"]
        ip = self.server_dict["ip"]

        try:
            port = self.server_dict["port"]
            protocol = self.server_dict["protocol"]

        except KeyError:
            pass

        if "bypass" in self.server_dict.keys():
            path = "{}/bypass.ovpn".format(ROOTDIR)
            time.sleep(2)

        else:
            path = "{}/temp.ovpn".format(ROOTDIR)

        if provider == "Airvpn":

            #create temp ssl config
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
                self.write_config(self.server_dict)
                self.ssl_thread = threading.Thread(target=self.ssl, args=(ip,))
                self.ssl_thread.start()
                self.log.emit(("info", "Started Stunnel process in new thread"))

            #create temp ssh config
            elif protocol == "SSH":
                self.write_config(self.server_dict)
                self.ssh_thread = threading.Thread(target=self.ssh, args=(ip,port,))
                self.ssh_thread.start()
                self.log.emit(("info", "Started SSH process in new thread"))
                time.sleep(2)
            else:
                self.write_config(self.server_dict)

        elif provider == "Mullvad":
            self.write_config(self.server_dict)

        elif provider == "PIA":
            self.write_config(self.server_dict)

        elif provider == "Windscribe":

            #create temp ssl config
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
                self.write_config(self.server_dict)
                self.ssl_thread = threading.Thread(target=self.ssl, args=(ip,))
                self.ssl_thread.start()
                self.log.emit(("info", "Started Stunnel process in new thread"))

            self.write_config(self.server_dict)

        elif provider == "ProtonVPN":
            self.write_config(self.server_dict)

        else:
            config_file = "{}/{}".format(ROOTDIR, self.server_dict["path"])

            try:
                edit = "{}/temp".format(provider)
                self.write_config(self.server_dict,
                                  edit=edit, path=config_file)

                path = "{}/{}/temp.ovpn".format(ROOTDIR, provider)

            except UnboundLocalError:
                path = config_file

            #setting cwd for OpenVPN is important if certifacte/key files separate from config file
            cwd_ovpn = os.path.dirname(config_file)

        if self.hop == "2":
            firewall.allow_dest_ip(self.hop_dict["ip"], "-I")

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

            #wait until first hop is connected
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

            #additional routes need to be defined for OpenVPN over SSL/SSH
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

            #set additional arguments for bypass in temp config
            if "bypass" in ovpn_dict:
                edit = "bypass"
                if ovpn_dict["bypass"] == "1":
                    config.append("iproute /usr/share/qomui/bypass_route.sh\n")
                    config.append("script-security 2\n")
                    config.append("route-up /usr/share/qomui/bypass_up.sh\n")

            for line, value in enumerate(config):
                if value.startswith("proto ") is True:

                    #ipv6 is currently Airvpn only
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

            #check if tls-crypt is used and update config accordingly
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

        self.log.emit(("debug", "Temporary config file(s) for requested server written"))


    def wg(self, wg_file):
        exe_custom_scripts("pre", self.server_dict["provider"], self.config)
        name = self.server_dict["name"]
        self.log.emit(("info", "Establishing connection to {}".format(name)))

        #allow traffic via wg interface
        wg_rules = [["-I", "INPUT", "2", "-i", "wg_qomui", "-j", "ACCEPT"],
                    ["-I", "OUTPUT", "2", "-o", "wg_qomui", "-j", "ACCEPT"]
                    ]

        for rule in wg_rules:
            firewall.add_rule_6(rule)
            firewall.add_rule(rule)

        time.sleep(1)

        try:
            self.dev.emit(("tun", "wg_qomui"))
            cmd_wg = Popen(['wg-quick', 'up', '{}'.format(wg_file)], stdout=PIPE, stderr=STDOUT)

            for line in cmd_wg.stdout:
                self.log.emit(("info", "WireGuard: " + line.decode("utf-8").replace("\n", "")))

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

                dns_manager.set_dns(self.dns, self.dns_2)
                self.dnsserver.emit(("", self.dns, self.dns_2))

            #Necessary, otherwise bypass mode breaks - need to investigate
            if self.config["bypass"] == 1:

                try:
                    check_call(["ip", "rule", "del", "fwmark", "11", "table", "bypass_qomui"])
                    check_call(["ip", "-6", "rule", "del", "fwmark", "11", "table", "bypass_qomui"])

                except CalledProcessError:
                    pass

                try:
                    check_call(["ip", "rule", "add", "fwmark", "11", "table", "bypass_qomui"])
                    check_call(["ip", "-6", "rule", "add", "fwmark", "11", "table", "bypass_qomui"])
                    self.log.emit(("debug", "Packet classification for bypass table reset"))

                except CalledProcessError:
                    self.log.emit(("warning", "Could not reset packet classification for bypass table"))

            self.bypass.emit()

            #we can't be sure of that
            exe_custom_scripts("up", self.server_dict["provider"], self.config)
            self.status.emit("connection_established")

        except (CalledProcessError, FileNotFoundError):
            self.status.emit("fail")

    def ovpn(self, ovpn_file, h, cwd_ovpn):
        self.log.emit(("info", "Establishing new OpenVPN tunnel"))
        name = self.server_dict["name"]
        last_ip = self.server_dict["ip"]
        add = ""

        if "bypass" not in self.server_dict and h != 1:
             exe_custom_scripts("pre", self.server_dict["provider"], self.config)

        #if doublehop is selected additional arguments are needed for OpenVPN
        if h == "1":
            add = "_hop"
            name = self.hop_dict["name"]
            self.log.emit(("info", "Establishing connection to {} - first hop".format(name)))
            last_ip = self.hop_dict["ip"]
            cmd_ovpn = ['openvpn',
                        '--config', '{}'.format(ovpn_file),
                        '--route-nopull',
                        '--script-security', '2',
                        '--up', '/usr/share/qomui/hop.sh -f {} {}'.format(self.hop_dict["ip"],
                                                                     self.server_dict["ip"]
                                                                     ),
                        '--down', '/usr/share/qomui/hop_down.sh {}'.format(self.hop_dict["ip"])
                        ]

        elif h == "2":
            self.log.emit(("info", "Establishing connection to {} - second hop".format(name)))
            cmd_ovpn = ['openvpn',
                        '--config', '{}'.format(ovpn_file),
                        '--route-nopull',
                        '--script-security', '2',
                        '--up', '{}/hop.sh -s'.format(ROOTDIR)
                        ]

        else:
            self.log.emit(("info", "Establishing connection to {}".format(name)))
            cmd_ovpn = ['openvpn', '{}'.format(ovpn_file)]

        if "bypass" in self.server_dict:
            add = "_bypass"
            self.dns_bypass = self.config["alt_dns1"]
            self.dns_2_bypass = self.config["alt_dns2"]

        else:
            self.dns = self.config["alt_dns1"]
            self.dns_2 = self.config["alt_dns2"]

        ovpn_exe = Popen(cmd_ovpn, stdout=PIPE, stderr=STDOUT,
                         cwd=cwd_ovpn, bufsize=1, universal_newlines=True
                         )

        self.log.emit(("debug", "OpenVPN pid: {}".format(ovpn_exe.pid)))
        self.pid.emit((ovpn_exe.pid, "OpenVPN{}".format(add)))
        line = ovpn_exe.stdout.readline()
        self.status.emit("starting_timer{}".format(add))

        #keep this thread as long as openvpn process has not been terminated
        #disconnection from gui will kill the openvpn process and break the loop
        while line.find("SIGTERM[hard,] received, process exiting") == -1:
            time_measure = time.time()
            line_format = ("OpenVPN:" + line.replace('{}'.format(time.asctime()), '').replace('\n', ''))
            self.log.emit(("info", line_format))

            #signals that tunnel has been successfully established
            if line.find("Initialization Sequence Completed") != -1:
                if "bypass" not in self.server_dict and h != 1:
                     exe_custom_scripts("up", self.server_dict["provider"], self.config)
                self.connect_status = 1
                self.bypass.emit()
                self.status.emit("connection_established{}".format(add))
                self.log.emit(("info", "Successfully connected to {}".format(name)))

            elif line.find('TUN/TAP device') != -1:
                setattr(self, "tun{}".format(add), line_format.split(" ")[3])
                self.dev.emit(("tun{}".format(add), getattr(self, "tun{}".format(add))))

            #read dns servers pushed by OpenVPN server
            #if not found: fallback to alternatives ones from config file
            elif line.find('PUSH: Received control message:') != -1:
                dns_option_1 = line_format.find('dhcp-option')

                if dns_option_1 != -1 and self.config["alt_dns"] == 0:
                    option = line_format[dns_option_1:].split(",")[0]
                    setattr(self, "dns{}".format(add), option.split(" ")[2])
                    dns_option_2 = line_format.find('dhcp-option', dns_option_1+20)

                    if dns_option_2 != -1:
                        option = line_format[dns_option_2:].split(",")[0]
                        setattr(self, "dns_2{}".format(add), option.split(" ")[2])

                    else:
                        setattr(self, "dns_2{}".format(add), None)

                dns_manager.set_dns(getattr(self, "dns{}".format(add)), getattr(self, "dns_2{}".format(add)))
                self.dnsserver.emit((add, getattr(self, "dns{}".format(add)), getattr(self, "dns_2{}".format(add))))

            #might be redundant as gui checks for timeout anyway
            elif line.find("Restart pause, 10 second(s)") != -1:
                self.status.emit("conn_attempt_failed{}".format(add))
                self.log.emit(("info" ,"Connection attempt failed"))

            elif line.find('SIGTERM[soft,auth-failure]') != -1:
                self.status.emit("conn_attempt_failed{}".format(add))
                self.log.emit(("info", "Authentication error while trying to connect"))

            #bugfix for double-hop
            #sometimes whitelisting servers via iptables fails so we retry
            #need to investigate further
            elif line.find('write UDP: Operation not permitted') != -1:
                ips = []

                try:
                    hop_ip = self.hop_dict["ip"]
                    ips.append(hop_ip)

                except:
                    pass

                remote_ip = self.server_dict["ip"]
                ips.append(remote_ip)

                for ip in ips:
                    firewall.allow_dest_ip(ip, "-I")

            elif line.find("Exiting due to fatal error") != -1:
                self.status.emit("conn_attempt_failed{}".format(add))
                self.log.emit(("info", "Connection attempt failed due to fatal error"))

            #break if openvpn emits empty lines to avoid clogging log
            elif line == '':
                break

            line = ovpn_exe.stdout.readline()

        if "bypass" not in self.server_dict and h != 1:
             exe_custom_scripts("down", self.server_dict["provider"], self.config)
        self.log.emit(("info", "OpenVPN:" + line.replace('{}'.format(time.asctime()), '').replace('\n', '')))
        ovpn_exe.stdout.close()
        self.status.emit("tunnel_terminated{}".format(add))
        self.log.emit(("info", "OpenVPN - process killed"))

        #delete outbound rule for this server
        firewall.allow_dest_ip(last_ip, "-D")

        #reset bypass so it can work without second OpenVPN tunnel
        if add == "_bypass":
            setattr(self, "dns{}".format(add), self.config["alt_dns1"])
            setattr(self, "dns{}_2".format(add), self.config["alt_dns2"])
            setattr(self, "tun{}".format(add), None)
            self.dnsserver.emit((add, self.config["alt_dns1"], self.config["alt_dns2"]))
            self.dev.emit(("tun{}".format(add), getattr(self, "tun{}".format(add))))
            self.bypass.emit()

        else:
            setattr(self, "tun{}".format(add), None)
            self.dev.emit(("tun{}".format(add), getattr(self, "tun{}".format(add))))

    def ssl(self, ip):
        cmd_ssl = ['stunnel', '{}'.format("{}/temp.ssl".format(ROOTDIR))]
        ssl_exe = Popen(cmd_ssl, stdout=PIPE, stderr=STDOUT, bufsize=1, universal_newlines=True)
        self.log.emit(("debug", "Stunnel pid: {}".format(ssl_exe.pid)))
        self.pid.emit((ssl_exe.pid, "stunnel"))
        line = ssl_exe.stdout.readline()

        #SIGINT signals ssl tunnel has terminated
        while line.find('SIGINT') == -1:
            self.log.emit(("info", "Stunnel: " + line.replace('\n', '')))
            if line == '':
                break

            elif line.find("Configuration succesful") != -1:
                self.log.emit(("info", "Stunnel: Successfully opened SSL tunnel to {}".format(self.ip)))

            line = ssl_exe.stdout.readline()
        ssl_exe.stdout.close()

    #using pexpect instead of subprocess to accept SHA fingerprint
    def ssh(self, ip, port):
        cmd_ssh = "ssh -i {}/certs/sshtunnel.key -L 1412:127.0.0.1:2018 sshtunnel@{} -p {} -N -T -v".format(ROOTDIR, ip, port)
        ssh_exe = pexpect.spawn(cmd_ssh)
        ssh_newkey = b'Are you sure you want to continue connecting'
        ssh_success = 'Forced command'
        self.log.emit(("debug", "SSH pid: {}".format(ssh_exe.pid)))
        self.pid.emit((ssh_exe.pid, "ssh"))
        i = ssh_exe.expect([ssh_newkey, ssh_success])

        if i == 0:
            ssh_exe.sendline('yes')
            self.log.emit(("info", "SSH: Accepted SHA fingerprint from {}".format(ip)))

        before = ssh_exe.before.decode("utf-8")
        after = ssh_exe.after.decode("utf-8")
        full = (before + after)

        for line in full.split("\n"):
            self.log.emit(("info", "SSH: " + line.replace("\r", "")))

        self.log.emit(("info", "SSH: Successfully opened SSH tunnel to {}".format(ip)))
        ssh_exe.wait()

def exe_custom_scripts(stage, provider, config):
    import logging

    try:
        script = config["{}_scripts".format(provider)][stage]

        try:
            run(shlex.split(cmd))
            logging.info("Executed {}".format(script))
            #self.log.emit(("info", "Executed {}".format(script)))

        except (CalledProcessError, FileNotFoundError):
            logging.warning("Executing {} failed".format(script))
           # self.log.emit(("info", "Executing {} failed".format(script)))

    except KeyError:
        logging.debug("No {} script defined for {}".format(stage, provider))
        #self.log.emit(("debug", "No {} script defined for {}".format(stage, provider)))
