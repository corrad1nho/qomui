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
from subprocess import PIPE, check_output, CalledProcessError, run


try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

ROOTDIR = "/usr/share/qomui"
DIRECTORY = "{}/.qomui".format(os.path.expanduser("~"))
SUPPORTED_PROVIDERS = ["Airvpn", "Mullvad", "ProtonVPN", "PIA", "Windscribe", "Manually add config files"]

def country_translate(cc):
    try:
        with open("countries.json", "r") as c_json:
            cc_lib = json.load(c_json)

        country = cc_lib[cc.upper()]
        return country

    except KeyError:
        return "Unknown"


class AddServers(QtCore.QThread):
    finished = QtCore.pyqtSignal(object)
    failed = QtCore.pyqtSignal(tuple)
    log = QtCore.pyqtSignal(tuple)
    extensions = ['.ovpn', '.conf', '.key', '.cert', '.pem']

    def __init__(self, username, password, provider, folderpath=None):
        QtCore.QThread.__init__(self)
        self.username = username
        self.password = password
        self.provider = provider
        self.folderpath = folderpath

    def run(self):
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
                payload = {'auth_key' : auth,
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
                    self.failed.emit(("AuthError", "Airvpn"))

        except requests.exceptions.RequestException as e:
            self.log.emit(("error", "Network error: Unable to retrieve data from airvpn.org"))
            self.failed.emit(("Network error: no internet connection", "Airvpn"))

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
            download_form["iplayer"] = "ipv4"

            download = self.session.post("https://airvpn.org/generator/",
                                         data=download_form
                                         )
            filepath = "{}/temp".format(DIRECTORY)
            z = zipfile.ZipFile(io.BytesIO(download.content))
            z.extractall(filepath)
            temp = "{}/temp".format(DIRECTORY)

            download_form["protocol_31"] = "on"
            download_form["protocol_39"] = "on"

            download = self.session.post("https://airvpn.org/generator/",
                                         data=download_form
                                         )
            z = zipfile.ZipFile(io.BytesIO(download.content))
            z.extractall(filepath)
            temp = "{}/temp".format(DIRECTORY)

            download_form["iplayer"] = "ipv6_ipv4"
            download = self.session.post("https://airvpn.org/generator/",
                                         data=download_form
                                         )

            filepath_6 = "{}/temp/ipv6".format(DIRECTORY)
            if not os.path.exists(filepath_6):
                os.makedirs(filepath_6)

            z = zipfile.ZipFile(io.BytesIO(download.content))
            z.extractall(filepath_6)
            temp = "{}/temp".format(DIRECTORY)
            vpnfiles = sorted([f for f in os.listdir(temp) if f.endswith('.ovpn')])
            vpn6files = sorted([f for f in os.listdir(filepath_6) if f.endswith('.ovpn')])

            for ovpn in vpnfiles:
                server = ovpn.split("_")[2]
                fullpath = "{}/temp/{}".format(DIRECTORY, ovpn)
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
                fullpath = "{}/temp/ipv6/{}".format(DIRECTORY, ovpn)
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
                        "provider" : "Airvpn",
                        "path" : filepath
                        }

            self.finished.emit(airvpn_data)

        except requests.exceptions.RequestException as e:
            self.log.emit(("error", "Network error: Unable to retrieve data from airvpn.org"))
            self.failed.emit(("Network error: no internet connection", "Airvpn"))

    def mullvad(self):
        self.mullvad_servers = {}
        self.log.emit(("info", "Downloading certificates for Mullvad"))
        auth = 0
        with requests.Session() as self.session:

            try:
                url = "https://mullvad.net/download/latest/source/"
                src = self.session.get(url, timeout=2)
                with open("{}/temp/tar".format(DIRECTORY), 'wb') as temp_file:
                    temp_file.write(gzip.decompress(src.content))
                    tar = tarfile.open("{}/temp/tar".format(DIRECTORY))
                    tar.extractall(path="{}/temp/".format(DIRECTORY))

                certpath = "{}/temp/{}/src/mullvad/ssl/".format(DIRECTORY, tar.getnames()[0])
                with open("{}/mullvad_userpass.txt".format(certpath), "w") as passfile:
                    passfile.write("{}\nm".format(self.username))

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

                        with open("{}/mullvad_wg.conf".format(certpath), "w") as wg:
                            wg_conf.insert(1, "PrivateKey = {}\n".format(private_key))
                            wg_conf.insert(2, "Address = {}\n".format(wg_address))
                            wg.writelines(wg_conf)

                    else:
                        self.failed.emit(("AuthError", "Mullvad"))
                        auth = 1


                except (CalledProcessError, FileNotFoundError) as e:
                    self.log.emit(("info", "WireGuard is not installed/not found - skipping"))
                    for s in wg_list:
                        self.mullvad_servers.pop(s, None)

                if auth == 0:
                    Mullvad_dict = {
                                    "server" : self.mullvad_servers,
                                    "protocol" : self.mullvad_protocols,
                                    "provider" : "Mullvad",
                                    "path" : certpath
                                    }

                    self.finished.emit(Mullvad_dict)

            except requests.exceptions.RequestException as e:
                self.log.emit(("error", "Network error: Unable to retrieve data from mullvad.net"))
                self.failed.emit(("Network error: no internet connection", "Mullvad"))


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
                filepath = "{}/temp/ip".format(DIRECTORY)
                z = zipfile.ZipFile(io.BytesIO(download_ip.content))
                z.extractall(filepath)

            vpnfiles = sorted([f for f in os.listdir(filepath) if f.endswith('.ovpn')])
            for ovpn in vpnfiles:
                f = "{}/temp/ip/{}".format(DIRECTORY, ovpn)
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
                filepath = "{}/temp/strong".format(DIRECTORY)
                z = zipfile.ZipFile(io.BytesIO(download_ip.content))
                z.extractall(filepath)

            with open("{}/pia_userpass.txt".format(filepath), "w") as passfile:
                    passfile.write("{}\n{}".format(self.username, self.password))

            self.pia_protocols = {
                                    "protocol_1" : {"protocol": "UDP", "port": "1197"},
                                    "protocol_2" : {"protocol": "TCP", "port": "502"}
                                    }

            pia_dict = {
                        "server" : self.pia_servers,
                        "protocol" : self.pia_protocols,
                        "provider" : "PIA",
                        "path" : filepath,
                        "tunnel" : "OpenVPN"
                        }

            self.finished.emit(pia_dict)

        except requests.exceptions.RequestException as e:
            self.log.emit(("error", "Network error: Unable to retrieve data from privateinternetaccess.com"))
            self.failed.emit(("Network error: no internet connection", "PIA"))

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
                self.temp = "{}/temp".format(DIRECTORY)
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
                credentials = json.loads(get_cred.content.decode("utf-8"))

                try:
                    self.log.emit(("info", "Created Windscribe credentials for OpenVPN"))
                    with open("{}/windscribe_userpass.txt".format(self.temp), "w") as cd:
                        cd.write("{}\n{}".format(credentials["username"], credentials["password"]))
                        self.windscribe_get_servers()
                except KeyError:
                    self.log.emit(("info", "Windscribe: Login failed"))
                    self.failed.emit(("AuthError", "Windscribe"))

        except requests.exceptions.RequestException as e:
            self.log.emit(("error", "Network error: Unable to retrieve data from windscribe.com"))
            self.failed.emit(("Network error: no internet connection", "Windscribe"))

    def windscribe_get_servers(self):
        self.log.emit(("info", "Generating server list for Windscribe"))
        cert_url = "https://assets.windscribe.com/desktop/other/openvpn_cert.zip"
        get_certs = self.session.get(cert_url, timeout=2)
        z = zipfile.ZipFile(io.BytesIO(get_certs.content))
        z.extractall(self.temp)

        uid = uuid.uuid4()
        random = uid.hex
        api_url = "https://assets.windscribe.com/serverlist/openvpn/1/{}".format(random)

        data = json.loads(self.session.get(api_url, timeout=2).content.decode("utf-8"))

        for s in data["data"]:
            try:
                countrycode = s["country_code"]
                for n in s["nodes"]:
                    city = n["group"].split("-")[0]
                    ip = n["ip2"]
                    ip2 = n["ip3"]
                    name = n["hostname"].replace("staticnetcontent", "windscribe")
                    country = country_translate(countrycode)
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
                    "provider" : "Windscribe",
                    "path" : self.temp
                    }

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
                path = "{}/temp".format(DIRECTORY)
                api_url = "https://api.protonmail.ch/vpn/logicals"
                get_servers = json.loads(self.session.get(api_url, timeout=2).content.decode("utf-8"))

                for s in get_servers["LogicalServers"]:
                    name = s["Domain"]
                    server_id = s["ID"]
                    cc = s["ExitCountry"]
                    if cc == "UK":
                        cc = "GB"
                    country = country_translate(cc)
                    city = s["City"]
                    if city is None:
                        city = ""

                    ip = s["Servers"][0]["EntryIP"]
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
                with open("{}/proton_ca.crt".format(path), "w") as ca:
                    ca.write(str(ca_cert))

                ta_key = "<tls-auth>\n{}".format(ovpn.split("<tls-auth>")[1])
                with open("{}/proton_ta.key".format(path), "w") as ta:
                    ta.write(str(ta_key))

                with open("{}/proton_userpass.txt".format(path), "w") as up:
                    up.write('{}\n{}'.format(self.username, self.password))

                self.proton_protocols = {
                                            "protocol_1" : {"protocol": "UDP", "port": "1194"},
                                            "protocol_2" : {"protocol": "TCP", "port": "443"}
                                            }

                proton_dict = {"server" : self.proton_servers,
                                "protocol" : self.proton_protocols,
                                "provider" : "ProtonVPN",
                                "path" : path
                                }

                self.finished.emit(proton_dict)

        except requests.exceptions.RequestException as e:
            self.log.emit(("error", "Network error: Unable to retrieve data from api.protonmail.ch"))
            self.failed.emit(("Network error: no internet connection", "ProtonVPN"))

    def add_folder(self):
        self.configs = [f for f in os.listdir(self.folderpath) if f.endswith('.ovpn') or f.endswith('.conf')]
        if len(self.configs) == 0:
            self.failed.emit(("nothing", self.provider))
            self.log.emit(("Error", "No config files found in {}".format(self.folderpath)))

        elif self.sanity_check(self.folderpath) >= 10:
            self.log.emit(("Warning", "{} seems to contain many unrelated files - aborting".format(self.folderpath)))
            self.failed.emit(("nothing", self.provider))

        else:
            if os.path.exists("{}/temp/{}".format(DIRECTORY, self.provider)):
                shutil.rmtree("{}/temp/{}".format(DIRECTORY, self.provider))
            shutil.copytree(self.folderpath, "{}/temp/{}".format(DIRECTORY, self.provider))
            self.import_configs()

    def import_configs(self):
        self.log.emit(("info", "Parsing config files"))
        custom_servers = {}
        failed_list = []
        temp_path = "{}/temp/{}".format(DIRECTORY, self.provider)
        for f in self.configs:
            tunnel = "OpenVPN"
            name = os.path.splitext(f)[0]
            copied_file = "{}/{}".format(temp_path, f)
            ip_found = 0
            proto_line = 0
            with open(copied_file, "r") as config:
                modify = config.readlines()
                for index, line in enumerate(modify):
                    if line.startswith("remote "):
                        if ip_found == 0:

                            try:
                                protocol = line.split(" ")[3]
                            except IndexError:
                                protocol = "udp\n"

                            port = line.split(" ")[2]
                            ipsearch = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
                            result = ipsearch.search(line)
                            if result is not None:
                                ip = result.group()
                                ip_found = 1
                            else:
                                server = line.split(" ")[1]
                                ip = resolve(server)
                                if ip != "Failed to resolve":
                                    modify[index] = "remote {} {}\n".format(ip, port)
                                    ip_found = 1
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
                        proto_line = 1

                    #WireGuard
                    elif line.startswith("Endpoint ="):
                        tunnel = "WireGuard"
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
                                ip_found = 1
                            else:
                                failed_list.append(server)
                        proto_line = 1

                if proto_line == 0:
                    modify.insert(0, "proto {}".format(protocol.lower)())

                config.close()

                with open (copied_file, "w") as file_edit:
                    file_edit.writelines(modify)
                    file_edit.close()

                if ip_found != 0:
                    country_check = check_output(["geoiplookup", "{}".format(ip)]).decode("utf-8")
                    cc = country_check.split(" ")[3].split(",")[0]
                    country = country_translate(cc)
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


        with open("{}/{}-auth.txt".format(temp_path, self.provider) , "w") as passfile:
            passfile.write('{}\n{}'.format(self.username, self.password))

        custom_dict = {
                        "server" : custom_servers,
                        "provider" : self.provider,
                        "path" : temp_path,
                        "failed" : failed_list
                        }

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


def resolve(host):
    try:
        dig_cmd = ["dig", "+time=2", "+tries=2", "{}".format(host), "+short"]
        ip = check_output(dig_cmd).decode("utf-8")
        ip = ip.split("\n")[0]
    except CalledProcessError:
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
