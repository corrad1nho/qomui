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


try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

ROOTDIR = "/usr/share/qomui"
TEMPDIR = "/usr/share/qomui/temp"
CERTDIR = "/usr/share/qomui/certs"
SUPPORTED_PROVIDERS = ["Airvpn", "Mullvad", "ProtonVPN", "PIA", "Windscribe"]

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
        self.temp_path = "{}/{}".format(TEMPDIR, self.provider)

    def run(self):
        self.started.emit(self.provider)
        self.log.emit(("debug", "Started new thread to import {}".format(self.provider)))
        if os.path.exists("{}/{}".format(TEMPDIR, self.provider)):
            shutil.rmtree("{}/{}".format(TEMPDIR, self.provider))
            os.makedirs("{}/{}".format(TEMPDIR, self.provider))

        else:
            os.makedirs("{}/{}".format(TEMPDIR, self.provider))

        if self.provider in SUPPORTED_PROVIDERS:
            getattr(self, self.provider.lower())()

        else:
            self.add_folder()

    def airvpn(self):
        self.airvpn_servers = {}
        self.airvpn_protocols = {}
        self.url = "https://airvpn.org"
        self.log.emit(("info", "Logging into airvpn.org"))

        try:
            with requests.Session() as self.session:
                auth_parse = BeautifulSoup(self.session.get(self.url, timeout=2).content, "lxml")
                auth = auth_parse.find("input", {"type": "hidden"}).get("value")
                payload = {
                            'auth_key' : auth,
                            'referer' : self.url,
                            'ips_username' : self.username,
                            'ips_password' : self.password
                            }

                url = "https://airvpn.org/index.php?app=core&module=global&section=login&do=process"
                self.session.post(url, data=payload)
                cook = self.session.cookies.get_dict()

                if "coppa" in cook:
                    self.log.emit(("info", "Airvpn: Login successful"))
                    self.airvpn_parse_info()
                else:
                    self.log.emit(("info", "Airvpn: Login failed - aborting"))
                    self.remove_temp_dir(self.provider)
                    m = "Authentication failed&Perhaps the credentials you entered are wrong&{}".format(self.provider)
                    self.failed.emit(m)

        except requests.exceptions.RequestException as e:
            self.log.emit(("error", "Network error: Unable to retrieve data from airvpn.org"))
            self.remove_temp_dir(self.provider)
            self.failed.emit("Network error&No internet connection&{}".format(self.provider))

    def airvpn_parse_info(self):
        csrf_parse = BeautifulSoup(self.session.get('{}/generator'.format(self.url), timeout=2).content, "lxml")
        self.csrf = csrf_parse.find("input", {"type" : "hidden"}).get("value")
        mode_list = self.session.get('{}/generator'.format(self.url), timeout=2)
        mode_list_parse = BeautifulSoup(mode_list.content, "lxml")
        self.log.emit(("info", "Parsing Airvpn protocols"))

        for row in mode_list_parse.find("table", {"class":"data"}).findAll('tr'):
            protocols = row('td')
            if len(protocols) != 0:
                number = protocols[0].find('input').get('id')
                mode = protocols[1].string
                port = protocols[2].string
                self.airvpn_protocols[number] = {
                                                    "protocol" : mode,
                                                     "port" : port,
                                                     "ip" : "ip{}".format(protocols[3].string),
                                                     "ipv6" : "ipv4"
                                                     }

                self.airvpn_protocols["{}-v6".format(number)] = {
                                                            "protocol" : mode,
                                                            "port" : port,
                                                            "ip" : "ip{}".format(protocols[3].string),
                                                            "ipv6" : "ipv6",
                                                            }


        get_list = requests.get('{}/status'.format(self.url), timeout=2)
        get_list_parse = BeautifulSoup(get_list.content, "lxml")
        servers = get_list_parse.findAll("div", {"class":"air_server_box_1"})
        self.log.emit(("info", "Generating server list"))
        for item in servers:
            name = item.find("a").get('href').split("/")[2]
            city = item.find("span", {"style":"font-size:0.7em;"}).text
            country = item.find("img").get("alt")
            self.airvpn_servers[name] = {
                                            "name" : name,
                                             "provider": "Airvpn",
                                             "city": city,
                                             "country" : country,
                                             "tunnel" : "OpenVPN"
                                             }

        self.airvpn_download()

    def airvpn_download(self):
        download_form = {
                    "customdirectives" : "",
                    "download_index" : "0",
                    "download_mode" : "zip",
                    "fileprefix" : "",
                    "noembedkeys" : "on",
                    "proxy_mode" : "none",
                    "resolve" : "on",
                    "system" : "linux",
                    "tosaccept" : "on",
                    "tosaccept2" : "on",
                    "withbinary" : "",
                    "do" : "javascript:Download('zip');"
                    }

        download_form["csrf_token"] = self.csrf
        for key, value in self.airvpn_servers.items():
            server_chosen = "server_" + key.lower()
            download_form[server_chosen] = "on"

        try:
            self.log.emit(("info", "Donwloading Airvpn Openvpn config files"))
            download_form["protocol_14"] = "on"
            download_form["protocol_18"] = "on"
            download_form["protocol_31"] = "on"
            download_form["protocol_39"] = "on"
            download_form["iplayer"] = "ipv4"

            download = self.session.post("https://airvpn.org/generator/",
                                         data=download_form
                                         )

            path = "{}/{}".format(self.temp_path, self.provider)
            z = zipfile.ZipFile(io.BytesIO(download.content))
            z.extractall(path)

            download_form["iplayer"] = "ipv6_ipv4"
            download = self.session.post("https://airvpn.org/generator/",
                                         data=download_form
                                         )

            path_6 = "{}/ipv6".format(self.temp_path, self.provider)

            if not os.path.exists(path_6):
                os.makedirs(path_6)

            z = zipfile.ZipFile(io.BytesIO(download.content))
            z.extractall(path_6)

            vpnfiles = sorted([f for f in os.listdir(path) if f.endswith('.ovpn')])
            vpn6files = sorted([f for f in os.listdir(path_6) if f.endswith('.ovpn')])

            for ovpn in vpnfiles:
                server = ovpn.split("_")[2]
                self.log.emit(("debug", "importing {}".format(server)))
                fullpath = "{}/{}".format(path, ovpn)
                with open(fullpath, "r") as o:
                    lines = o.readlines()
                    for line in lines:

                        if ovpn.endswith('SSL-443.ovpn'):
                            if line.startswith("route "):
                                self.airvpn_servers[server]["ip2"] = line.split(" ")[1]

                        elif ovpn.endswith('SSH-22.ovpn'):
                            if line.startswith("route "):
                                self.airvpn_servers[server]["ip1"] = line.split(" ")[1]

                        elif ovpn.endswith('Entry3.ovpn'):
                            if line.startswith("remote "):
                                self.airvpn_servers[server]["ip3"] = line.split(" ")[1]

                        elif ovpn.endswith('Entry4.ovpn'):
                            if line.startswith("remote "):
                                self.airvpn_servers[server]["ip4"] = line.split(" ")[1]

            for ovpn in vpn6files:
                server = ovpn.split("_")[2]
                fullpath = "{}/{}".format(path_6, ovpn)
                with open(fullpath, "r") as o:
                    lines = o.readlines()
                    for line in lines:

                        if ovpn.endswith('SSL-443.ovpn'):
                            if line.startswith("route "):
                                self.airvpn_servers[server]["ip2_6"] = line.split(" ")[1]

                        elif ovpn.endswith('SSH-22.ovpn'):
                            if line.startswith("route "):
                                self.airvpn_servers[server]["ip1_6"] = line.split(" ")[1]

                        elif ovpn.endswith('Entry3.ovpn'):
                            if line.startswith("remote "):
                                self.airvpn_servers[server]["ip3_6"] = line.split(" ")[1]

                        elif ovpn.endswith('Entry4.ovpn'):
                            if line.startswith("remote "):
                                self.airvpn_servers[server]["ip4_6"] = line.split(" ")[1]

            airvpn_data = {
                        "server" : self.airvpn_servers,
                        "protocol" : self.airvpn_protocols,
                        "provider" : "Airvpn"
                        }

            self.copy_certs(self.provider)
            self.finished.emit(airvpn_data)

        except requests.exceptions.RequestException as e:
            self.log.emit(("error", "Network error: Unable to retrieve data from airvpn.org"))
            self.remove_temp_dir(self.provider)
            self.failed.emit("Network error&No internet connection&{}".format(self.provider))

    def mullvad(self):
        self.mullvad_servers = {}
        self.password = "m"
        self.log.emit(("info", "Downloading certificates for Mullvad"))
        auth = 0
        with requests.Session() as self.session:

            try:
                certfiles = ["ca.crt", "crl.pem"]
                git_raw = "https://raw.githubusercontent.com/mullvad/mullvadvpn-app/master/dist-assets/"

                for c in certfiles:
                    certificate = self.session.get("{}{}".format(git_raw, c), timeout=2)

                    with open("{}/{}".format(self.temp_path, c), 'w') as cert_file:
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


                    private_key = check_output(["wg", "genkey"]).decode("utf-8").split("\n")[0]
                    pubgen = run(["wg", "pubkey"], stdout=PIPE, input=private_key, encoding='ascii')
                    pubkey = pubgen.stdout.split("\n")[0]
                    data = [('account', self.username),
                            ('pubkey', pubkey)
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

                        with open("{}/mullvad_wg.conf".format(self.temp_path), "w") as wg:
                            wg_conf.insert(1, "PrivateKey = {}\n".format(private_key))
                            wg_conf.insert(2, "Address = {}\n".format(wg_address))
                            wg.writelines(wg_conf)

                    else:
                        m = "Authentication failed&Perhaps the credentials you entered are wrong&{}".format(self.provider)
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

            self.copy_certs(self.provider)
            self.finished.emit(pia_dict)

        except requests.exceptions.RequestException as e:
            self.log.emit(("error", "Network error: Unable to retrieve data from privateinternetaccess.com"))
            self.remove_temp_dir(self.provider)
            self.failed.emit("Network error&No internet connection&{}".format(self.provider))

    def windscribe(self):
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

                    with open("{}/windscribe_userpass.txt".format(CERTDIR), "w") as cd:
                        cd.write("{}\n{}\n".format(userpass["username"], userpass["password"]))
                        self.log.emit(("debug", "Windscribe OpenVPN credentials written to {}/windscribe_userpass.txt".format(CERTDIR)))
                        self.windscribe_get_servers()

                except KeyError:

                    self.log.emit(("info", "Windscribe: Login failed"))
                    m = "Authentication failed&Perhaps the credentials you entered are wrong&{}".format(self.provider)
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
                                ip = resolve(server)

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
                            ip = resolve(server)
                            if ip != "Failed to resolve":
                                modify[index] = "Endpoint = {}:{}\n".format(ip, port)

                            else:
                                failed_list.append(server)

                if protocol_found == 0:
                    modify.insert(0, "proto {}".format(protocol.lower)())

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

    def copy_certs(self, provider):
        oldmask = os.umask(0o077)

        if not os.path.exists("{}/certs".format(ROOTDIR)):
            os.makedirs("{}/certs".format(ROOTDIR))

        with open("{}/{}-auth.txt".format(CERTDIR, self.provider) , "w") as passfile:
            passfile.write('{}\n{}\n'.format(self.username, self.password))

        if provider in SUPPORTED_PROVIDERS:

            self.Airvpn_files =     [
                                    ("Airvpn/sshtunnel.key", "sshtunnel.key"),
                                    ("Airvpn/stunnel.crt", "stunnel.crt"),
                                    ("Airvpn/ca.crt", "ca.crt"),
                                    ("Airvpn/ta.key", "ta.key"),
                                    ("Airvpn/user.key", "user.key"),
                                    ("Airvpn/user.crt", "user.crt"),
                                    ("Airvpn/tls-crypt.key", "tls-crypt.key")
                                    ]

            self.Mullvad_files =    [
                                    ("ca.crt", "mullvad_ca.crt"),
                                    ("crl.pem", "mullvad_crl.pem"),
                                    ("mullvad_wg.conf", "mullvad_wg.conf")
                                    ]

            self.PIA_files =        [
                                    ("strong/crl.rsa.4096.pem", "pia_crl.rsa.4096.pem"),
                                    ("strong/ca.rsa.4096.crt", "pia_ca.rsa.4096.crt")
                                    ]

            self.Windscribe_files = [
                                    ("ca.crt", "ca_ws.crt"),
                                    ("ta.key", "ta_ws.key"),
                                    ]

            self.ProtonVPN_files =  [
                                    ("proton_ca.crt", "proton_ca.crt"),
                                    ("proton_ta.key", "proton_ta.key")
                                    ]

            for cert in getattr(self, "{}_files".format(provider)):

                try:
                    origin = "{}/{}".format(self.temp_path, cert[0])
                    dest = "{}/{}".format(CERTDIR, cert[1])
                    shutil.copyfile(origin, dest)
                    self.log.emit(("debug", "Copied {} to {}".format(origin, dest)))

                except FileNotFoundError:
                    self.log.emit(("error", "Copying {} to {} failed: No such file".format(cert, CERTDIR)))

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

            #doesn't work if importing existing provider
            #shutil.copytree("{}/copy/".format(self.temp_path), "{}/{}/".format(ROOTDIR, provider))

        for key in [f for f in os.listdir("{}/certs".format(ROOTDIR))]:
            Popen(['chown', 'root', '{}/certs/{}'.format(ROOTDIR, key)])
            Popen(['chmod', '0600', '{}/certs/{}'.format(ROOTDIR, key)])

        os.umask(oldmask)
        self.remove_temp_dir(self.provider)

    def remove_temp_dir(self, provider):
        try:
            shutil.rmtree(self.temp_path)
            self.log.emit(("debug", "Removed temporary directory"))

        except FileNotFoundError:
            pass

def resolve(host):
    try:
        dig_cmd = ["dig", "+time=2", "+tries=2", "{}".format(host), "+short"]
        ip = check_output(dig_cmd).decode("utf-8")
        ip = ip.split("\n")[0]

    except (FileNotFoundError, CalledProcessError):
        ip = "Failed to resolve"

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
