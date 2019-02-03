#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import zipfile
import gzip
import tarfile
import requests
import os
import re
import io
import logging
import shutil
import uuid

from PyQt5 import QtCore
from bs4 import BeautifulSoup
from subprocess import PIPE, Popen, check_output, CalledProcessError, run

from qomui import firewall

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

ROOTDIR = "/usr/share/qomui"
TEMPDIR = "/usr/share/qomui/temp"
SUPPORTED_PROVIDERS = ["Airvpn", "AzireVPN", "Mullvad", "PIA", "ProtonVPN", "Windscribe"]

def country_translate(cc):
    try:
        with open("{}/countries.json".format(ROOTDIR), "r") as c_json:
            cc_lib = json.load(c_json)

        country = cc_lib[cc.upper()]
        return country

    except KeyError:
        return "Unknown"


class AddServers(QtCore.QThread):
    started = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal(object)
    failed = QtCore.pyqtSignal(str)
    log = QtCore.pyqtSignal(tuple)
    extensions = ['.ovpn', '.conf', '.key', '.cert', '.pem']

    def __init__(self, credentials, folderpath=None):
        QtCore.QThread.__init__(self)
        self.username = credentials["username"]
        self.password = credentials["password"]
        self.provider = credentials["provider"]
        self.folderpath = credentials["folderpath"]
        self.update = credentials["update"]
        self.temp_path = "{}/{}".format(TEMPDIR, self.provider)
        self.allowed_ips = []

        try:
            self.key = credentials["key"]
        except KeyError:
            self.key = "Default"

    def run(self):
        self.started.emit(self.provider)
        self.log.emit(("debug", "Started new thread to import {}".format(self.provider)))
        if os.path.exists(self.temp_path):
            shutil.rmtree(self.temp_path)

        os.makedirs(self.temp_path)
        if self.provider in SUPPORTED_PROVIDERS:
            getattr(self, self.provider.lower())()
        else:
            self.add_folder()

    def airvpn(self):
        import base64
        import time
        from xml.etree import ElementTree as et
        from lxml import etree
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization, hashes, asymmetric, ciphers

        self.log.emit(("info", "Creating temporary rule to access Airvpn API"))
        firewall.allow_dest_ip("54.93.175.114", "-I")
        self.allowed_ips.append("54.93.175.114")
        self.airvpn_servers = {}
        self.airvpn_protocols = {}
        self.backend = default_backend()

        #Those are sent with AES-256-CBC encryption
        data_params = {
                        "login" : self.username,
                        "password" : self.password,
                        "system" : "linux_x64",
                        "version" : "999"
                     }

        certificates = {
                        "ssh_key": "sshtunnel.key",
                        "ssl_crt": "stunnel.crt",
                        "ca" : "ca.crt",
                        "ta" : "ta.key",
                        "key" : "user.key",
                        "crt" : "user.crt",
                        "tls_crypt" : "tls-crypt.key"
                        }

        #Loading public RSA key
        with open("{}/airvpn_api.pem".format(ROOTDIR), "rb") as pem:
            rsa_pub_key = serialization.load_pem_public_key(
            pem.read(),
            backend=self.backend
            )

        #Generating random AES key
        self.aes_key = os.urandom(32)
        self.aes_iv = os.urandom(16)
        self.cipher = ciphers.Cipher(ciphers.algorithms.AES(self.aes_key), ciphers.modes.CBC(self.aes_iv), backend=self.backend)

        aes_params = {"key" : self.aes_key, "iv" : self.aes_iv}
        a = b''
        for k,v in aes_params.items():
            a = a + base64.b64encode(k.encode('utf-8')) + b':' + base64.b64encode(v) + b'\n'

        #Encrypting AES key with RSA
        aes_params_crypt = rsa_pub_key.encrypt(a, asymmetric.padding.PKCS1v15())
        data_params["act"] = "user"
        user_params_crypt = self.encrypt_data_params(data_params)
        payload = {
                "s" :  base64.b64encode(aes_params_crypt).decode("utf-8"),
                "d" :  base64.b64encode(user_params_crypt).decode("utf-8")
                }

        try:
            cert_xml = self.call_air_api(payload)
            decrypt_server = self.cipher.decryptor()
            decrypt_user = self.cipher.decryptor()
            cert_xml = decrypt_user.update(cert_xml.content) + decrypt_user.finalize()
            parser = etree.XMLParser(recover=True)
            cert_xml_root = et.fromstring(cert_xml, parser=parser)

            for a in cert_xml_root.attrib:
                if cert_xml_root.attrib[a] == "Wrong login/password.":
                    raise ValueError("Wrong credentials")
                if a != "login" and a != "expirationdate":
                    try:
                        with open("{}/{}".format(self.temp_path, certificates[a]), "w") as c:
                            c.write(cert_xml_root.attrib[a])
                    except KeyError:
                        pass

            key_index = 0
            keys_available = len(cert_xml_root[0])
            for k in range(keys_available):
                for n in cert_xml_root[0][k].attrib:
                    if n == "name" and cert_xml_root[0][k].attrib[n] == self.key:
                        key_index = k

            user_key = cert_xml_root[0][key_index]

            for a in user_key.attrib:
                if a == "crt" or a == "key":
                    with open("{}/{}".format(self.temp_path, certificates[a]), "w") as c:
                        c.write(user_key.attrib[a])

            data_params["act"] = "manifest"
            data_params["ts"] = "0"
            server_params_crypt = self.encrypt_data_params(data_params)
            payload["d"] = base64.b64encode(server_params_crypt).decode("utf-8")
            server_xml = self.call_air_api(payload)
            decrypt_server = self.cipher.decryptor()
            server_xml = decrypt_server.update(server_xml.content) + decrypt_server.finalize()
            server_xml = server_xml.decode("utf-8").split("</manifest>")[0] + "</manifest>"
            server_xml_root = et.fromstring(server_xml, parser=parser)
            for i, child in enumerate(server_xml_root):
                if child.tag == "modes":
                    modes = i
                elif child.tag == "servers":
                    servers = i

            n = 1
            for mode in server_xml_root[modes]:
                try:
                    self.airvpn_protocols["protocol_{}".format(n)] = {
                                        "protocol" : mode.attrib["protocol"].upper(),
                                        "port" : mode.attrib["port"],
                                        "ip" : "ip" + str(int(mode.attrib["entry_index"])+1),
                                        "ipv6" : "ipv4"
                                        }

                    n+=1
                    self.airvpn_protocols["protocol_{}".format(n)] = {
                                        "protocol" : mode.attrib["protocol"].upper(),
                                        "port" : mode.attrib["port"],
                                        "ip" : "ip" + str(int(mode.attrib["entry_index"])+1),
                                        "ipv6" : "ipv6"
                                        }
                    n+=1
                except KeyError:
                    pass

            entry_ips = ["ip1", "ip2", "ip3", "ip4", "ip1_6", "ip2_6", "ip3_6", "ip4_6"]

            for server in server_xml_root[servers]:
                try:
                    country = country_translate(server.attrib["country_code"])
                    self.airvpn_servers[server.attrib["name"]] = {
                                        "name" : server.attrib["name"],
                                        "provider": "Airvpn",
                                        "city": server.attrib["location"],
                                        "country" : country,
                                        "tunnel" : "OpenVPN"
                                        }

                    self.log.emit(("debug", "Importing {}".format(server.attrib["name"])))
                    ips = server.attrib["ips_entry"].split(",")
                    for index, entry in enumerate(ips):
                        self.airvpn_servers[server.attrib["name"]][entry_ips[index]] = entry

                except KeyError:
                    pass


            airvpn_data = {
                            "server" : self.airvpn_servers,
                            "protocol" : self.airvpn_protocols,
                            "provider" : "Airvpn",
                            "airvpn_key" : self.key
                            }

            self.copy_certs(self.provider)
            self.finished.emit(airvpn_data)

        except ValueError as e:
            self.log.emit(("debug", e.args))
            m = "Airvpn download failed&Perhaps the credentials you entered are wrong&{}".format(self.provider)
            self.remove_temp_dir(self.provider)
            self.failed.emit(m)


        except Exception as e:
            self.log.emit(("debug", e.args))
            self.log.emit(("info", "Airvpn: Request failed - aborting"))
            self.remove_temp_dir(self.provider)
            self.failed.emit("Sorry, something went wrong")

    def encrypt_data_params(self, params):
        import base64
        from cryptography.hazmat.primitives import padding

        d = b''
        for k,v in params.items():
            d = d + base64.b64encode(k.encode('utf-8')) + b':' + base64.b64encode(v.encode('utf-8')) + b'\n'

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(d) + padder.finalize()
        encryptor = self.cipher.encryptor()
        encrypted = encryptor.update(padded_data) + encryptor.finalize()

        return encrypted

    def call_air_api(self, payload):
        try:
            xml = requests.post(
                                "http://54.93.175.114",
                                data=payload,
                                cert="{}/airvpn_cacert.pem".format(ROOTDIR),
                                timeout=2
                                )
            return xml

        except requests.exceptions.RequestException as e:
            self.log.emit(("error", "Network error: Unable to retrieve data from Airvpn"))
            self.remove_temp_dir(self.provider)
            self.failed.emit("Network error&No internet connection&{}".format(self.provider))

    def mullvad(self):
        self.allow_ip(["api.mullvad.net", "mullvad.net", "raw.githubusercontent.com"])
        self.mullvad_servers = {}
        self.password = "m"
        self.log.emit(("info", "Downloading certificates for Mullvad"))
        auth = 0
        certificates = {"ca.crt":"mullvad_ca.crt" ,"api_root_ca.pem":"mullvad_crl.pem"}
        with requests.Session() as self.session:
            try:
                certfiles = ["ca.crt", "api_root_ca.pem"]
                git_raw = "https://raw.githubusercontent.com/mullvad/mullvadvpn-app/master/dist-assets/"

                for c in certfiles:
                    certificate = self.session.get("{}{}".format(git_raw, c), timeout=2)

                    with open("{}/{}".format(self.temp_path, certificates[c]), 'w') as cert_file:
                        cert_file.write(certificate.content.decode("utf-8"))

                page = self.session.get('https://www.mullvad.net/en/servers/', timeout=2)
                self.log.emit(("info", "Fetching server list for Mullvad"))
                server_page = BeautifulSoup(page.content, "lxml")
                server_parse = server_page.find_all("div", {"class":"section-content server-table"})

                for entry in server_parse[0].find_all('tr'):
                    info = entry.find_all('td')
                    name = info[0].string

                    if info[1].string != "Country":
                        server = "{}.mullvad.net".format(info[0].string)
                        country_raw = info[1].string
                        city = info[2].string
                        ip = info[3].string
                        country = self.cc_translate(country_raw)
                        self.log.emit(("debug", "importing {}".format(server)))
                        self.mullvad_servers[server] = {
                                                            "name" : server,
                                                            "provider" : "Mullvad",
                                                            "city" : city,
                                                            "country" : country,
                                                            "ip" : ip,
                                                            "tunnel" : "OpenVPN"
                                                            }

                self.mullvad_protocols = {
                                        "protocol_1" : {"protocol": "UDP", "port": "1194"},
                                        "protocol_2" : {"protocol": "UDP", "port": "53"},
                                        "protocol_3" : {"protocol": "TCP", "port": "80"},
                                        "protocol_4" : {"protocol": "TCP", "port": "443"}
                                        }
                try:
                    self.log.emit(("info", "Creating WireGuard config files for Mullvad"))
                    wg_list = []
                    wg_api = "https://api.mullvad.net/public/relays/wireguard/v1/"
                    wg_get = self.session.get(wg_api, timeout=2)
                    wg_dict = wg_get.json()
                    for c in wg_dict["countries"]:
                        for k,v in c.items():
                            country_raw = c["name"]
                            country = self.cc_translate(country_raw)
                            for cc in c["cities"]:
                                city = cc["name"].split(",")[0]
                                for relay in cc["relays"]:
                                    server = relay["hostname"] + "-mullvad"
                                    wg_list.append(server)
                                    ip = relay["ipv4_addr_in"]
                                    public_key = relay["public_key"]
                                    port = "51820"
                                    self.log.emit(("debug", "importing {}".format(server)))
                                    self.mullvad_servers[server] = {
                                                                        "name" : server,
                                                                        "provider" : "Mullvad",
                                                                        "city" : city,
                                                                        "country" : country,
                                                                        "ip" : ip,
                                                                        "port" : port,
                                                                        "public_key" : public_key,
                                                                        "tunnel" : "WireGuard"
                                                                        }

                    wg_file = "mullvad_wg.conf"
                    wg_keys = self.gen_wg_key(wg_file)
                    if wg_keys is not None:
                        data = [('account', self.username),
                                ('pubkey', wg_keys[1])
                                ]

                        pub_up = self.session.post("https://api.mullvad.net/wg/", data=data)
                        if pub_up.status_code < 400:
                            wg_address = pub_up.content.decode("utf-8").split("\n")[0]

                            wg_conf = [
                                        "[Interface]\n",
                                        "DNS = 193.138.219.228\n",
                                        "\n",
                                        "[Peer]\n",
                                        "AllowedIPs = 0.0.0.0/0, ::/0\n"
                                        ]

                            with open("{}/{}".format(self.temp_path, wg_file), "w") as wg:
                                wg_conf.insert(1, "PrivateKey = {}\n".format(wg_keys[0]))
                                wg_conf.insert(2, "Address = {}\n".format(wg_address))
                                wg.writelines(wg_conf)

                        else:
                            m = "Mullvad: Authentication failed&Perhaps the credentials you entered are wrong&{}".format(self.provider)
                            self.remove_temp_dir(self.provider)
                            self.failed.emit(m)
                            auth = 1


                except (CalledProcessError, FileNotFoundError) as e:
                    self.log.emit(("info", "WireGuard is not installed/not found - skipping"))
                    for s in wg_list:
                        self.mullvad_servers.pop(s, None)

                if auth == 0:
                    Mullvad_dict = {
                                    "server" : self.mullvad_servers,
                                    "protocol" : self.mullvad_protocols,
                                    "provider" : "Mullvad"
                                    }

                    self.copy_certs(self.provider)
                    self.finished.emit(Mullvad_dict)

            except requests.exceptions.RequestException as e:
                self.log.emit(("error", "Network error: Unable to retrieve data from mullvad.net"))
                self.remove_temp_dir(self.provider)
                self.failed.emit("Network error&No internet connection&{}".format(self.provider))


    def cc_translate(self, country_raw):
        if country_raw == "UK":
            country = "United Kingdom"
        elif country_raw == "USA":
            country = "United States"
        else:
            country = country_raw

        return country

    def pia(self):
        self.allow_ip(["www.privateinternetaccess.com"])
        self.pia_servers = {}
        self.pia_protocols = {}
        self.log.emit(("info", "Downloading PIA config files"))
        url_ip = "https://www.privateinternetaccess.com/openvpn/openvpn-ip.zip"
        url_strong =  "https://www.privateinternetaccess.com/openvpn/openvpn-strong.zip"

        try:
            with requests.Session() as self.session:
                download_ip = self.session.get(url_ip, timeout=2)
                filepath = "{}/ip".format(self.temp_path)
                z = zipfile.ZipFile(io.BytesIO(download_ip.content))
                z.extractall(filepath)

            vpnfiles = sorted([f for f in os.listdir(filepath) if f.endswith('.ovpn')])
            for ovpn in vpnfiles:
                f = "{}/{}".format(filepath, ovpn)
                filedata = open(f, "r").read()
                ipsearch = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
                result = ipsearch.findall(filedata)

                for i in result:
                    ip = i

                raw_name = os.path.splitext(ovpn)[0]
                name = "PIA-{}".format(raw_name)

                try:
                    parse_country = raw_name.split(" ")[0]
                    if len(parse_country) == 2:

                        if parse_country == "UK":
                            parse_country = "GB"
                        country = country_translate(parse_country)

                    else:
                        country = raw_name

                except AttributeError:
                    country = raw_name

                self.log.emit(("debug", "importing {}".format(name)))
                self.pia_servers[name] = {
                                            "name" : name,
                                            "country" : country,
                                            "ip" : ip,
                                            "city" : "",
                                            "provider" : "PIA",
                                            "tunnel" : "OpenVPN"
                                            }

            with requests.Session() as self.session:
                download_ip = self.session.get(url_strong, timeout=2)
                filepath = "{}/strong".format(self.temp_path)
                z = zipfile.ZipFile(io.BytesIO(download_ip.content))
                z.extractall(filepath)

            self.pia_protocols = {
                                    "protocol_1" : {"protocol": "UDP", "port": "1197"},
                                    "protocol_2" : {"protocol": "TCP", "port": "502"}
                                    }

            pia_dict = {
                        "server" : self.pia_servers,
                        "protocol" : self.pia_protocols,
                        "provider" : "PIA",
                        "tunnel" : "OpenVPN"
                        }

            certificates = {
                            "{}/strong/crl.rsa.4096.pem".format(self.temp_path) :"{}/pia_crl.rsa.4096.pem".format(self.temp_path),
                            "{}/strong/ca.rsa.4096.crt".format(self.temp_path) :"{}/pia_ca.rsa.4096.crt".format(self.temp_path)
                            }

            for orig, dest in certificates.items():
                try:
                    shutil.copyfile(orig, dest)

                except FileNotFoundError as e:
                    self.log.emit(("error", e))

            try:
                shutil.rmtree("{}/ip".format(self.temp_path))
                shutil.rmtree("{}/strong".format(self.temp_path))

            except FileNotFoundError as e:
                self.log.emit(("error", e))

            self.copy_certs(self.provider)
            self.finished.emit(pia_dict)

        except requests.exceptions.RequestException as e:
            self.log.emit(("error", "Network error: Unable to retrieve data from privateinternetaccess.com"))
            self.remove_temp_dir(self.provider)
            self.failed.emit("Network error&No internet connection&{}".format(self.provider))

    def windscribe(self):
        self.allow_ip(["windscribe.com", "assets.windscribe.com", "res.windscribe.com"])
        self.windscribe_servers = {}
        self.windscribe_protocols = {}
        self.header = {
                        "User-Agent" : "Mozilla/5.0 (X11; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0",
                        "Accept" : "*/*",
                        "Accept-Language" : "en-US,en;q=0.5",
                        "Accept-Encoding" : "gzip, deflate, br",
                        "Connection" : "keep-alive"
                        }

        login_url = "https://windscribe.com/login"
        self.log.emit(("info", "Logging into windscribe.com"))

        try:
            with requests.Session() as self.session:
                self.session.headers.update(self.header)
                self.session.get(login_url, timeout=2)
                self.session.headers.update({"Host" : "res.windscribe.com",
                                            "Origin" : "https://windscribe.com"})
                post = self.session.post("https://res.windscribe.com/res/logintoken")
                csrf = json.loads(post.content.decode("utf-8"))
                self.session.headers.pop("Host", None)
                self.session.headers.pop("Origin", None)

                payload = {
                            'login' : '1',
                            'upgrade' : '0',
                            'username' : self.username,
                            'password' : self.password,
                            'csrf_token' : csrf["csrf_token"],
                            'csrf_time' : csrf["csrf_time"]
                            }

                post = self.session.post(login_url, data=payload)
                cred_url = "https://windscribe.com/getconfig/credentials"
                get_cred = self.session.get(cred_url, timeout=2)
                userpass = json.loads(get_cred.content.decode("utf-8"))

                try:
                    self.log.emit(("info", "Created Windscribe credentials for OpenVPN"))
                    with open("{}/windscribe_userpass.txt".format(self.temp_path), "w") as cd:
                        cd.write("{}\n{}\n".format(userpass["username"], userpass["password"]))
                        self.log.emit(("debug", "Windscribe OpenVPN credentials written to {}/windscribe_userpass.txt".format(self.temp_path)))

                    self.windscribe_get_servers()

                except KeyError:
                    self.log.emit(("info", "Windscribe: Login failed"))
                    m = "Windscribe: Authentication failed&Perhaps the credentials you entered are wrong&{}".format(self.provider)
                    self.remove_temp_dir(self.provider)
                    self.failed.emit(m)

        except requests.exceptions.RequestException as e:
            self.log.emit(("error", "Network error: Unable to retrieve data from windscribe.com"))
            self.remove_temp_dir(self.provider)
            self.failed.emit("Network error&No internet connection&{}".format(self.provider))

    def windscribe_get_servers(self):
        self.log.emit(("info", "Generating server list for Windscribe"))
        cert_url = "https://assets.windscribe.com/desktop/other/openvpn_cert.zip"
        get_certs = self.session.get(cert_url, timeout=2)
        z = zipfile.ZipFile(io.BytesIO(get_certs.content))
        z.extractall(self.temp_path)

        uid = uuid.uuid4()
        random = uid.hex
        api_url = "https://assets.windscribe.com/serverlist/openvpn/1/{}".format(random)

        data = json.loads(self.session.get(api_url, timeout=2).content.decode("utf-8"))

        for s in data["data"]:

            try:
                windflix = 0
                countrycode = s["country_code"]
                if s["name"].split(" ")[0] == "WINDFLIX":
                    windflix = 1

                for n in s["nodes"]:
                    city = n["group"].split("-")[0]
                    group = n["group"].split("- ")[1]
                    ip = n["ip2"]
                    ip2 = n["ip3"]

                    if windflix == 0:
                        name = n["hostname"].split(".")[0] + "-" + group

                    else:
                        name = n["hostname"].split(".")[0] + "-Windflix-" + group

                    country = country_translate(countrycode)
                    self.log.emit(("debug", "importing {}".format(name)))
                    self.windscribe_servers[name] = {
                                                "name" : name,
                                                "country" : country,
                                                "ip" : ip,
                                                "ip2" : ip2,
                                                "city" : city,
                                                "provider" : "Windscribe",
                                                "tunnel" : "OpenVPN"
                                                }

            except KeyError:
                pass

        self.windscribe_protocols = {
                                    "protocol_1" : {"protocol": "UDP", "port": "443"},
                                    "protocol_2" : {"protocol": "UDP", "port": "80"},
                                    "protocol_3" : {"protocol": "UDP", "port": "53"},
                                    "protocol_4" : {"protocol": "UDP", "port": "1194"},
                                    "protocol_5" : {"protocol": "UDP", "port": "54783"},
                                    "protocol_6" : {"protocol": "TCP", "port": "443"},
                                    "protocol_7" : {"protocol": "TCP", "port": "587"},
                                    "protocol_8" : {"protocol": "TCP", "port": "21"},
                                    "protocol_9" : {"protocol": "TCP", "port": "22"},
                                    "protocol_10" : {"protocol": "TCP", "port": "80"},
                                    "protocol_11" : {"protocol": "TCP", "port": "143"},
                                    "protocol_12" : {"protocol": "TCP", "port": "3306"},
                                    "protocol_13" : {"protocol": "TCP", "port": "8080"},
                                    "protocol_14" : {"protocol": "TCP", "port": "54783"},
                                    "protocol_15" : {"protocol": "TCP", "port": "1194"},
                                    "protocol_16" : {"protocol": "SSL", "port": "443"}
                                    }

        ws_dict = {"server" : self.windscribe_servers,
                    "protocol" : self.windscribe_protocols,
                    "provider" : "Windscribe"
                    }

        self.copy_certs(self.provider)
        self.finished.emit(ws_dict)

    def protonvpn(self):
        self.allow_ip(["api.protonmail.ch"])
        self.proton_servers = {}
        self.log.emit(("info", "Downloading ProtonVPN server configs"))

        headers = {'x-pm-appversion': 'Other',
                   'x-pm-apiversion': '3',
                   'Accept': 'application/vnd.protonmail.v1+json'
                  }

        try:
            with requests.Session() as self.session:
                self.session.headers.update(headers)
                api_url = "https://api.protonmail.ch/vpn/logicals"
                get_servers = json.loads(self.session.get(api_url, timeout=2).content.decode("utf-8"))

                for s in get_servers["LogicalServers"]:
                    tor = 0
                    p2p = 0
                    secure_core = 0
                    host = s["Domain"]
                    features = s["Features"]
                    tier = s["Tier"]

                    if features == 4:
                        p2p = 1
                    elif features == 2:
                        tor = 1
                    elif features == 1:
                        secure_core = 1

                    if tier == 2:
                        tier = "Plus"

                    elif tier == 1:
                        tier = "Basic"

                    elif tier == 0:
                        tier = "Free"

                    if p2p == 1:
                        name = host.split(".")[0] + "-ProtonVPN-" + tier + "-P2P"
                    elif tor == 1:
                        name = host.split(".")[0] + "-ProtonVPN-" + tier + "-TOR"
                    elif secure_core == 1:
                        name = host.split(".")[0] + "-ProtonVPN-" + "SecureCore"
                    else:
                        name = host.split(".")[0] + "-ProtonVPN-" + tier

                    server_id = s["ID"]
                    cc = s["ExitCountry"]
                    if cc == "UK":
                        cc = "GB"
                    country = country_translate(cc)
                    city = s["City"]
                    if city is None:
                        city = ""

                    ip = s["Servers"][0]["EntryIP"]
                    self.log.emit(("debug", "importing {}".format(name)))
                    self.proton_servers[name] = {
                                                    "name" : name,
                                                    "country" : country,
                                                    "city": city,
                                                    "ip" : ip,
                                                    "provider" : "ProtonVPN",
                                                    "tunnel": "OpenVPN"
                                                    }


                cert_url = "https://api.protonmail.ch/vpn/config?Platform=Linux&LogicalID={}&Protocol=udp".format(server_id)
                ovpn = requests.get(cert_url, timeout=2).content.decode("utf-8")

                ca_cert = BeautifulSoup(ovpn, "lxml").find("ca")
                with open("{}/proton_ca.crt".format(self.temp_path), "w") as ca:
                    ca.write(str(ca_cert))

                ta_key = "<tls-auth>\n{}".format(ovpn.split("<tls-auth>")[1])
                with open("{}/proton_ta.key".format(self.temp_path), "w") as ta:
                    ta.write(str(ta_key))

                self.proton_protocols = {
                                        "protocol_1" : {"protocol": "UDP", "port": "1194"},
                                        "protocol_2" : {"protocol": "TCP", "port": "443"}
                                        }

                proton_dict = {"server" : self.proton_servers,
                                "protocol" : self.proton_protocols,
                                "provider" : "ProtonVPN"
                                }

                self.copy_certs(self.provider)
                self.finished.emit(proton_dict)

        except requests.exceptions.RequestException as e:
            self.log.emit(("error", "Network error: Unable to retrieve data from api.protonmail.ch"))
            self.remove_temp_dir(self.provider)
            self.failed.emit("Network error&No internet connection&{}".format(self.provider))

    def azirevpn(self):
        self.az_servers = {}
        self.allow_ip(["azirevpn.net"])

        try:

            try:
                self.log.emit(("info", "Downloading AzireVPN OpenVPN configs"))
                az_api_url = "https://api.azirevpn.com/v1/locations"
                az_servers = json.loads(requests.get(az_api_url, timeout=2).content.decode("utf-8"))

            except requests.exceptions.RequestException as e:
                az_servers = {"locations" : []}
                self.log.emit(("error", "Network error: Unable to retrieve data from api.azirevpn.com"))
                self.remove_temp_dir(self.provider)
                self.failed.emit("Network error&No internet connection&{}".format(self.provider))

            for s in az_servers["locations"]:
                name = s["name"] + "-openvpn" + "-azirevpn"
                wg_name = s["name"] + "-wireguard" + "-azirevpn"
                country = country_translate(s["iso"])
                hostname = s["endpoints"]["openvpn"][0]["hostname"]
                ip = resolve(hostname)[0]
                self.log.emit(("info", "Importing {}".format(name)))

                if ip != "Failed to resolve":
                    self.az_servers[name] = {
                                            "name": name,
                                            "provider" : self.provider,
                                            "city" : s["city"],
                                            "ip" : ip,
                                            "country" : country,
                                            "tunnel" : "OpenVPN"
                                            }

                    crt_url = s["openvpn-ca"]
                    crt_file = "{}/{}.crt".format(self.temp_path, name)
                    crt = requests.get(crt_url, timeout=2).content.decode("utf-8")
                    with open(crt_file, "w") as c:
                        c.write(crt)

                    tls_url = s["openvpn-tls-key"]
                    tls_file = "{}/{}.key".format(self.temp_path, name)
                    tls = requests.get(tls_url, timeout=2).content.decode("utf-8")
                    with open(tls_file, "w") as t:
                        t.write(tls)

                else:
                    self.log.emit(("Error: Could not resolve {} - skipping".format(hostname)))

                try:
                    wg_file = "{}.conf".format(wg_name)
                    wg_api_url = s["endpoints"]["wireguard"]
                    wg_keys = self.gen_wg_key(wg_file)

                    if wg_keys is not None:
                        data = {
                                'username' : str(self.username),
                                'password' : str(self.password),
                                'pubkey' : wg_keys[1]
                                }

                        pub_up = requests.post(wg_api_url, data=data, timeout=10)
                        if pub_up.status_code == 200:
                            api_resp = json.loads(pub_up.content.decode("utf-8"))

                            if api_resp["status"] != "error":
                                wg_ip = resolve(api_resp["data"]["Endpoint"].split(":")[0])[0]
                                wg_conf = [
                                                "[Interface]\n",
                                                "PrivateKey = {}\n".format(wg_keys[0]),
                                                "Address = {}\n".format(api_resp["data"]["Address"]),
                                                "DNS = {}\n".format(api_resp["data"]["DNS"]),
                                                "\n",
                                                "[Peer]\n",
                                                "PublicKey = {}\n".format(api_resp["data"]["PublicKey"]),
                                                "Endpoint = {}:51820\n".format(wg_ip),
                                                "AllowedIPs = 0.0.0.0/0, ::/0\n"
                                                ]

                                self.az_servers[wg_name] = {
                                                "name": wg_name,
                                                "provider" : self.provider,
                                                "city" : s["city"],
                                                "ip" : wg_ip,
                                                "country" : country,
                                                "tunnel" : "WireGuard",
                                                "path" : "{}/{}.conf".format(self.provider, wg_name)
                                                }

                                with open("{}/{}".format(self.temp_path, wg_file), "w") as wg:
                                    wg.writelines(wg_conf)

                        else:
                            m = "AzireVPN: Authentication failed&Perhaps the credentials you entered are wrong&{}".format(self.provider)
                            self.log.emit(("error", m))
                            self.remove_temp_dir(self.provider)
                            self.failed.emit(m)

                except (CalledProcessError, FileNotFoundError) as e:
                    self.log.emit(("info", "WireGuard is not installed/not found - skipping"))

                except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
                    self.log.emit(("debug", e))
                    self.log.emit(("info", "Network error: Uploading WireGuard public key failed"))

        except Exception as e:
            self.log.emit(("debug", e))
            self.log.emit(("error", "An unexpected error occured: Aborting"))
            self.remove_temp_dir(self.provider)
            self.failed.emit("AzireVPN import failed&An unknown error occured&{}".format(self.provider))

        else:
            az_protocols = {
                            "protocol_1" : {"protocol": "UDP", "port": "1194"},
                            "protocol_2" : {"protocol": "TCP", "port": "1194"},
                            "protocol_3" : {"protocol": "UDP", "port": "443"},
                            "protocol_4" : {"protocol": "TCP", "port": "443"}
                            }

            azire_dict = {
                            "server" : self.az_servers,
                            "protocol" : az_protocols,
                            "provider" : "AzireVPN"
                            }

            self.copy_certs(self.provider)
            self.finished.emit(azire_dict)

    def add_folder(self):
        self.conf_files = [f for f in os.listdir(self.folderpath) if f.endswith('.ovpn') or f.endswith('.conf')]
        self.cert_files = [f for f in os.listdir(self.folderpath) if f.endswith('.ovpn') or f.endswith('.conf')]

        if len(self.conf_files) == 0:
            m = "Import Error&No config files found or folder seems\nto contain many unrelated files&{}".format(self.provider)
            self.remove_temp_dir(self.provider)
            self.failed.emit(m)
            self.log.emit(("error", "No config files found in {}".format(self.folderpath)))

        elif self.sanity_check(self.folderpath) >= 10:
            self.log.emit(("error", "{} seems to contain many unrelated files - aborting".format(self.folderpath)))
            m = "Import Error&No config files found or folder seems\nto contain many unrelated files&{}".format(self.provider)
            self.remove_temp_dir(self.provider)
            self.failed.emit(m)

        else:
            shutil.copytree(self.folderpath, "{}/copy/".format(self.temp_path))
            self.import_configs()

    def import_configs(self):
        self.log.emit(("info", "Parsing config files"))
        custom_servers = {}
        failed_list = []

        for f in self.conf_files:
            tunnel = "OpenVPN"
            name = os.path.splitext(f)[0]
            conf_copy = "{}/copy/{}".format(self.temp_path, f)
            ip = 0
            protocol_found = 0

            with open(conf_copy, "r") as config:
                modify = config.readlines()

                for index, line in enumerate(modify):
                    if line.startswith("remote "):
                        if ip == 0:

                            try:
                                protocol = line.split(" ")[3]

                            except IndexError:
                                protocol = "udp\n"

                            port = line.split(" ")[2]
                            ipsearch = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
                            result = ipsearch.search(line)

                            if result is not None:
                                ip = result.group()

                            else:
                                server = line.split(" ")[1]
                                ip = resolve(server)[0]

                                if ip != "Failed to resolve":
                                    modify[index] = "remote {} {}\n".format(ip, port)

                                else:
                                    self.log.emit(("warning", "Failed to resolve {}".format(server)))
                                    failed_list.append(server)

                        else:
                            modify[index] = "#{}".format(line)

                    elif line.startswith("auth-user-pass"):
                        auth_file = '{}/certs/{}-auth.txt'.format(ROOTDIR, self.provider)
                        modify[index] = 'auth-user-pass {}\n'.format(auth_file)

                    elif line.startswith("verb "):
                        modify[index] = 'verb 3\n'

                    elif line.startswith("up ") or line.startswith("down "):
                        modify[index] = "#{}".format(line)

                    elif line.startswith("proto "):
                        protocol = line.split(" ")[1]
                        protocol_found = 1

                    #WireGuard
                    elif line.startswith("Endpoint ="):
                        tunnel = "WireGuard"
                        protocol_found = 1
                        ip_port = line.split(" = ")[1]
                        ipsearch = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
                        result = ipsearch.search(line)
                        port = ip_port.split(":")[1]
                        server = ip_port.split(":")[0]
                        protocol = "UDP"

                        if result is not None:
                            ip = result.group()

                        else:
                            ip = resolve(server)[0]
                            if ip != "Failed to resolve":
                                modify[index] = "Endpoint = {}:{}\n".format(ip, port)

                            else:
                                failed_list.append(server)

                if protocol_found == 0:
                    modify.insert(0, "proto {}".format(protocol.lower()))

                config.close()

                with open (conf_copy, "w") as file_edit:
                    file_edit.writelines(modify)
                    file_edit.close()

                if ip != 0:

                    country_check = check_output(["geoiplookup", "{}".format(ip)]).decode("utf-8")
                    cc = country_check.split(" ")[3].split(",")[0]
                    country = country_translate(cc)
                    self.log.emit(("debug", "importing {}".format(name)))
                    custom_servers[name] = {
                                                "name": name,
                                                "provider" : self.provider,
                                                "city" : "",
                                                "path" : "{}/{}".format(self.provider, f),
                                                "ip" : ip,
                                                "country" : country,
                                                "tunnel" : tunnel,
                                                "port": port.upper().split("\n")[0],
                                                "protocol": protocol.upper().split("\n")[0]
                                                }

                else:
                    pass

        custom_dict = {
                        "server" : custom_servers,
                        "provider" : self.provider,
                        "failed" : failed_list
                        }

        self.copy_certs(self.provider)
        self.finished.emit(custom_dict)

    def sanity_check(self, path):
        unrelated_files = 0

        for dirpath, dirnames, filenames in os.walk(path):
            for f in filenames:

                try:
                    ext = os.path.splitext(f)[1]
                    if ext not in self.extensions:
                       unrelated_files += 1

                except IndexError:
                    unrelated_files += 1

        return unrelated_files

    def gen_wg_key(self, config):
        #check if key already exists
        if os.path.exists("{}/{}/{}".format(ROOTDIR, self.provider, config)) and self.update == "0":
            self.log.emit(("debug", "WireGuard keys for {} have already been generated".format(config.split("/")[-1])))
            wg_keys = None

        else:
            self.log.emit(("info", "Generating WireGuard keys for {}".format(config.split("/")[-1])))

            try:
                private_key = check_output(["wg", "genkey"]).decode("utf-8").split("\n")[0]
                pubgen = run(["wg", "pubkey"], stdout=PIPE, input=private_key, encoding='ascii')
                public_key = pubgen.stdout.split("\n")[0]
                wg_keys = (private_key, public_key)
            except (CalledProcessError, FileNotFoundError) as e:
                wg_keys = None
                self.log.emit(("info", "WireGuard is not installed/not found - skipping"))

        return wg_keys

    def allow_ip(self, hosts):
        for host in hosts:
            self.log.emit(("info", "Creating temporary rule to access {}".format(host)))
            ips = resolve(host)
            for i in ips:
                if i != "" and i != "Failed to resolve":
                    firewall.allow_dest_ip(i, "-I")
                    self.allowed_ips.append(i)

    def copy_certs(self, provider):
        for i in self.allowed_ips:
            firewall.allow_dest_ip(i, "-D")

        provider_dir = "{}/{}".format(ROOTDIR, provider)
        if not os.path.exists(provider_dir):
            os.makedirs(provider_dir)

        oldmask = os.umask(0o077)
        with open("{}/{}-auth.txt".format(provider_dir, self.provider) , "w") as passfile:
            passfile.write('{}\n{}\n'.format(self.username, self.password))

        if provider in SUPPORTED_PROVIDERS:

            for f in os.listdir(self.temp_path):
                shutil.copyfile("{}/{}".format(self.temp_path, f), "{}/{}".format(provider_dir, f))
                Popen(['chown', 'root', '{}/{}'.format(provider_dir, f)])
                Popen(['chmod', '0600', '{}/{}'.format(provider_dir, f)])

            try:
                openvpn_orig_conf = "{}/{}_config".format(ROOTDIR, provider)
                openvpn_dest_conf = "{}/{}/openvpn.conf".format(ROOTDIR, provider)
                if not os.path.exists(openvpn_dest_conf):
                    shutil.copyfile(openvpn_orig_conf, openvpn_dest_conf)
                    Popen(['chmod', '0655', openvpn_dest_conf])

            except FileNotFoundError:
                self.log.emit(("error", "{} does not exist".format(openvpn_orig_conf)))

        else:
            path = "{}/copy/".format(self.temp_path)
            for f in os.listdir(path):
                f_source = "{}/{}".format(path, f)
                f_dest = "{}/{}/{}".format(ROOTDIR, provider, f)
                if os.path.isfile(f_source):

                    try:
                        shutil.copyfile(f_source, f_dest)
                        self.log.emit(("debug", "copied {} to {}".format(f, f_dest)))

                    except FileNotFoundError:
                        if not os.path.exists("{}/{}".format(ROOTDIR, provider)):
                            os.makedirs("{}/{}".format(ROOTDIR, provider))

                        shutil.copyfile(f_source,f_dest)
                        self.log.emit(("debug", "copied {} to {}".format(f, f_dest)))

                elif os.path.isdir(f_source):

                    try:
                        shutil.rmtree(f_dest)

                    except (NotADirectoryError, FileNotFoundError):
                        pass

                    shutil.copytree(f_source, f_dest)
                    self.log.emit(("debug", "copied folder {} to {}".format(f, f_dest)))

        os.umask(oldmask)
        self.remove_temp_dir(self.provider)

    def remove_temp_dir(self, provider):
        try:
            shutil.rmtree(self.temp_path)
            self.log.emit(("debug", "Removed temporary download directory for {}".format(provider)))

        except FileNotFoundError:
            pass

def resolve(host):
    try:
        dig_cmd = ["dig", "+time=2", "+tries=2", "{}".format(host), "+short"]
        ip = check_output(dig_cmd).decode("utf-8")
        ip = ip.split("\n")

    except (FileNotFoundError, CalledProcessError):
        ip = ["Failed to resolve"]

    return ip


class UpdateCheck(QtCore.QThread):
    release_found = QtCore.pyqtSignal(str)
    log = QtCore.pyqtSignal(tuple)

    def __init__(self):
        QtCore.QThread.__init__(self)

    def run(self):
        url = "https://api.github.com/repos/corrad1nho/qomui/releases/latest"
        try:
            check_version = requests.get(url, timeout=2)
            latest_release = check_version.json()["tag_name"]
            self.release_found.emit(latest_release)
        except:
            self.log.emit(("error", "Failed to check if update is available"))
