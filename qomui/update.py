#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from PyQt5 import QtCore
import requests
import os
from bs4 import BeautifulSoup
import json
import time
import zipfile
import gzip
import tarfile
from subprocess import Popen, PIPE, check_output, CalledProcessError, check_call, run
import re
import sys
import io
import logging
import shutil
import pycountry
import uuid


try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s

DIRECTORY = "%s/.qomui" % (os.path.expanduser("~"))
ROOTDIR = "/usr/share/qomui"
supported_providers = ["Airvpn", "Mullvad", "ProtonVPN", "PIA", "Windscribe", "Manually add config files"]

def country_translate(cc):
    try:
        country = pycountry.countries.get(alpha_2=cc).name
        
        if country == "Czechia":
            country = "Czech Republic"
        elif country == "Russian Federation":
            country = "Russia"
        elif country == "Taiwan, Province of China":
            country = "Taiwan"
        elif country == "Moldova, Republic of":
            country = "Moldova"
        elif country == "Korea, Republic of":
            country = "South Korea"
        
        return country
    
    except KeyError:
        return "Unknown"

class AirVPNDownload(QtCore.QThread):
    down_finished = QtCore.pyqtSignal(object)
    importFail = QtCore.pyqtSignal(str)
    download_form = {"customdirectives" : "",
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
                     "do" : "javascript:Download('zip');"}
    
    def __init__(self, username, password):
        QtCore.QThread.__init__(self)
        self.username = username
        self.password = password
        self.Airvpn_server_dict = {}
        self.Airvpn_protocol_dict = {}
        self.url = "https://airvpn.org"

    def run(self):
        try:
            with requests.Session() as self.session:
                auth_parse = BeautifulSoup(self.session.get(self.url).content, "lxml")
                auth = auth_parse.find("input", {"type": "hidden"}).get("value")
                payload = {'auth_key' : auth,
                        'referer' : self.url,
                        'ips_username' : self.username,
                        'ips_password' : self.password
                            }
                
                url = "https://airvpn.org/index.php?app=core&module=global&section=login&do=process"
                post = self.session.post(url, data=payload)
                cook = self.session.cookies.get_dict()
                
                if "coppa" in cook:
                    self.parse()
                else:
                    self.importFail.emit("Airvpn")
                    
        except requests.exceptions.RequestException as e:
            self.importFail.emit("Network error: no internet connection")
           
    def parse(self):
        csrf_parse = BeautifulSoup(self.session.get('%s/generator' % (self.url)).content, "lxml")
        self.csrf = csrf_parse.find("input", {"type" : "hidden"}).get("value")
        mode_list = self.session.get('%s/generator' % (self.url))
        mode_list_parse = BeautifulSoup(mode_list.content, "lxml")
        for row in mode_list_parse.find("table", {"class":"data"}).findAll('tr'):  
            protocols = row('td')
            if len(protocols) != 0:
                number = protocols[0].find('input').get('id')
                mode = protocols[1].string
                port = protocols[2].string
                self.Airvpn_protocol_dict[number] = {"protocol" : mode,
                                                     "port" : port,
                                                     "ip" : "ip%s" %protocols[3].string,
                                                     "ipv6" : "ipv4"
                                                     }
                
                self.Airvpn_protocol_dict["%s-v6" %number] = {"protocol" : mode,
                                                            "port" : port,
                                                            "ip" : "ip%s" %protocols[3].string,
                                                            "ipv6" : "ipv6",
                                                            }
                
                           
        get_list = requests.get('%s/status' % (self.url))
        get_list_parse = BeautifulSoup(get_list.content, "lxml")
        servers = get_list_parse.findAll("div", {"class":"air_server_box_1"})
        for item in servers:
            name = item.find("a").get('href').split("/")[2]
            city = item.find("span", {"style":"font-size:0.7em;"}).text
            country = item.find("img").get("alt")
            self.Airvpn_server_dict[name] = {"name" : name,
                                             "provider": "Airvpn",
                                             "city": city,
                                             "country" : country,
                                             "tunnel" : "OpenVPN"}
   
        self.Download()

    def Download(self):
        self.download_form["csrf_token"] = self.csrf
        for key, value in self.Airvpn_server_dict.items():
            server_chosen = "server_" + key.lower() 
            self.download_form[server_chosen] = "on"
            
        try:
            self.download_form["protocol_14"] = "on"
            self.download_form["protocol_18"] = "on"
            self.download_form["iplayer"] = "ipv4"
            
            download = self.session.post("https://airvpn.org/generator/", 
                                         data=self.download_form
                                         )
            filepath = "%s/temp" %(DIRECTORY)
            z = zipfile.ZipFile(io.BytesIO(download.content))
            z.extractall(filepath)
            temp = "%s/temp" %DIRECTORY
            
            self.download_form["protocol_31"] = "on"
            self.download_form["protocol_39"] = "on"
            
            download = self.session.post("https://airvpn.org/generator/", 
                                         data=self.download_form
                                         )
            z = zipfile.ZipFile(io.BytesIO(download.content))
            z.extractall(filepath)
            temp = "%s/temp" %DIRECTORY
            
            self.download_form["iplayer"] = "ipv6_ipv4"
            download = self.session.post("https://airvpn.org/generator/", 
                                         data=self.download_form
                                         )
            
            filepath_6 = "%s/temp/ipv6" %(DIRECTORY)
            if not os.path.exists(filepath_6):
                os.makedirs(filepath_6)

            z = zipfile.ZipFile(io.BytesIO(download.content))
            z.extractall(filepath_6)
            temp = "%s/temp" %DIRECTORY
            vpnfiles = sorted([f for f in os.listdir(temp) if f.endswith('.ovpn')])
            vpn6files = sorted([f for f in os.listdir(filepath_6) if f.endswith('.ovpn')])
            
            for ovpn in vpnfiles:
                server = ovpn.split("_")[2]
                fullpath = "%s/temp/%s" % (DIRECTORY, ovpn)
                with open(fullpath, "r") as o:
                    lines = o.readlines()
                    for line in lines:
                        
                        if ovpn.endswith('SSL-443.ovpn'):
                            if line.startswith("route "):
                                self.Airvpn_server_dict[server]["ip2"] = line.split(" ")[1]
                                
                        elif ovpn.endswith('SSH-22.ovpn'):
                            if line.startswith("route "):
                                self.Airvpn_server_dict[server]["ip1"] = line.split(" ")[1]
                        
                        elif ovpn.endswith('Entry3.ovpn'):
                            if line.startswith("remote "):
                                self.Airvpn_server_dict[server]["ip3"] = line.split(" ")[1]
                                
                        elif ovpn.endswith('Entry4.ovpn'):
                            if line.startswith("remote "):
                                self.Airvpn_server_dict[server]["ip4"] = line.split(" ")[1]
                            
            for ovpn in vpn6files:
                server = ovpn.split("_")[2]
                fullpath = "%s/temp/ipv6/%s" % (DIRECTORY, ovpn)
                with open(fullpath, "r") as o:
                    lines = o.readlines()
                    for line in lines:
                        
                        if ovpn.endswith('SSL-443.ovpn'):
                            if line.startswith("route "):
                                self.Airvpn_server_dict[server]["ip2_6"] = line.split(" ")[1]

                        elif ovpn.endswith('SSH-22.ovpn'):
                            if line.startswith("route "):
                                self.Airvpn_server_dict[server]["ip1_6"] = line.split(" ")[1]
                        
                        elif ovpn.endswith('Entry3.ovpn'):
                            if line.startswith("remote "):
                                self.Airvpn_server_dict[server]["ip3_6"] = line.split(" ")[1]
                                
                        elif ovpn.endswith('Entry4.ovpn'):
                            if line.startswith("remote "):
                                self.Airvpn_server_dict[server]["ip4_6"] = line.split(" ")[1]
                            

            Airvpn_dict = {"server" : self.Airvpn_server_dict,
                        "protocol" : self.Airvpn_protocol_dict,
                        "provider" : "Airvpn", 
                        "path" : filepath
                        }
            
            self.down_finished.emit(Airvpn_dict)
            
        except requests.exceptions.RequestException as e:
            self.importFail.emit("Network error: no internet connection")

class MullvadDownload(QtCore.QThread):
     down_finished = QtCore.pyqtSignal(object)
     importFail = QtCore.pyqtSignal(str)
    
     def __init__(self, accountnumber):
        QtCore.QThread.__init__(self)
        self.accountnumber = accountnumber
        self.Mullvad_server_dict = {}
        self.Mullvad_protocol_dict = {}

     def run(self):
        auth = 0
        with requests.Session() as self.session:
            
            try:
                url = "https://mullvad.net/download/latest/source/"
                src = self.session.get(url)
                with open("%s/temp/tar" %DIRECTORY, 'wb') as temp_file:
                    temp_file.write(gzip.decompress(src.content))
                    tar = tarfile.open("%s/temp/tar" %(DIRECTORY))
                    tar.extractall(path="%s/temp/" %(DIRECTORY))

                certpath = "%s/temp/%s/src/mullvad/ssl/" %(DIRECTORY, tar.getnames()[0])
                with open("%s/mullvad_userpass.txt" %(certpath), "w") as passfile:
                    passfile.write("%s\nm" %(self.accountnumber))

                page = self.session.get('https://www.mullvad.net/en/servers/')
                server_page = BeautifulSoup(page.content, "lxml")
                server_parse = server_page.find_all("div", {"class":"section-content server-table"})
                for entry in server_parse[0].find_all('tr'):
                    info = entry.find_all('td')
                    name = info[0].string
                    if info[1].string != "Country":
                        server = "%s.mullvad.net" %info[0].string
                        country_raw = info[1].string
                        city = info[2].string
                        ip = info[3].string
                        country = self.cc_translate(country_raw)
                        self.Mullvad_server_dict[server] = {"name" : server,
                                                            "provider" : "Mullvad",
                                                            "city" : city,
                                                            "country" : country,
                                                            "ip" : ip,
                                                            "tunnel" : "OpenVPN"
                                                            }
                        
                self.Mullvad_protocol_dict = {"protocol_1" : {"protocol": "UDP", "port": "1194"}, 
                                            "protocol_2" : {"protocol": "UDP", "port": "53"},
                                            "protocol_3" : {"protocol": "TCP", "port": "80"},
                                            "protocol_4" : {"protocol": "TCP", "port": "443"}
                                            }
                try:
                    wg_list = []
                    wg_api = "https://api.mullvad.net/public/relays/wireguard/v1/"
                    wg_get = self.session.get(wg_api)
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
                                    self.Mullvad_server_dict[server] = {"name" : server,
                                                                "provider" : "Mullvad",
                                                                "city" : city,
                                                                "country" : country,
                                                                "ip" : ip,
                                                                "port" : port,
                                                                "public_key" : public_key,
                                                                "tunnel" : "Wireguard"}
                                    
                    
                    private_key = check_output(["wg", "genkey"]).decode("utf-8").split("\n")[0]
                    pubgen = run(["wg", "pubkey"], stdout=PIPE, input=private_key, encoding='ascii')
                    pubkey = pubgen.stdout.split("\n")[0]
                    data = [('account', self.accountnumber),
                            ('pubkey', pubkey)
                            ]
                    
                    pub_up = self.session.post("https://api.mullvad.net/wg/", data=data)
                    if pub_up.status_code < 400:
                        wg_address = pub_up.content.decode("utf-8").split("\n")[0]
                        
                        wg_conf = ["[Interface]\n",
                                    "DNS = 193.138.219.228\n",
                                    "\n",
                                    "[Peer]\n",
                                    "AllowedIPs = 0.0.0.0/0, ::/0\n"
                                    ]
                    
                        with open("%s/mullvad_wg.conf" %certpath, "w") as wg:
                            wg_conf.insert(1, "PrivateKey = %s\n" %private_key)
                            wg_conf.insert(2, "Address = %s\n" %wg_address)
                            wg.writelines(wg_conf)
                    
                    else:
                        self.importFail.emit("Airvpn")
                        auth = 1
                        
                    
                except (CalledProcessError, FileNotFoundError) as e:
                    for s in wg_list:
                        self.Mullvad_server_dict.pop(s, None)
                    
                
                if auth == 0:
                    Mullvad_dict = {"server" : self.Mullvad_server_dict, 
                                            "protocol" : self.Mullvad_protocol_dict, 
                                            "provider" : "Mullvad", 
                                            "path" : certpath
                                            }

                    self.down_finished.emit(Mullvad_dict)
        
            except requests.exceptions.RequestException as e:
                self.importFail.emit("Network error: no internet connection")
                
            
     def cc_translate(self, country_raw):
        if country_raw == "UK":
            country = "United Kingdom"
        elif country_raw == "USA":
            country = "United States"
        else:
            country = country_raw
        
        return country
                
class PiaDownload(QtCore.QThread):
    down_finished = QtCore.pyqtSignal(object)
    importFail = QtCore.pyqtSignal(str)
    
    def __init__(self, username, password):
        QtCore.QThread.__init__(self)
        self.username = username
        self.password = password
        self.pia_server_dict = {}
        self.pia_protocol_dict = {}
    
    def run(self):
        url_ip = "https://www.privateinternetaccess.com/openvpn/openvpn-ip.zip"
        url_strong =  "https://www.privateinternetaccess.com/openvpn/openvpn-strong.zip"
        try:
            with requests.Session() as self.session:
                download_ip = self.session.get(url_ip)
                filepath = "%s/temp/ip" %(DIRECTORY)
                z = zipfile.ZipFile(io.BytesIO(download_ip.content))
                z.extractall(filepath)
                
            vpnfiles = sorted([f for f in os.listdir(filepath) if f.endswith('.ovpn')])
            for ovpn in vpnfiles:
                f = "%s/temp/ip/%s" % (DIRECTORY, ovpn)
                filedata = open(f, "r").read()
                ipsearch = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
                result = ipsearch.findall(filedata)
                for i in result:
                    ip = i
                raw_name = os.path.splitext(ovpn)[0]
                name = "PIA-%s" %raw_name
                
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
            
                self.pia_server_dict[name] = {"name" : name, "country" : country, 
                                              "ip" : ip, "city" : "", "provider" : "PIA", "tunnel" : "OpenVPN"
                                                  }
            
            with requests.Session() as self.session:
                download_ip = self.session.get(url_strong)
                filepath = "%s/temp/strong" %(DIRECTORY)
                z = zipfile.ZipFile(io.BytesIO(download_ip.content))
                z.extractall(filepath)
                
            with open("%s/pia_userpass.txt" %(filepath), "w") as passfile:
                    passfile.write("%s\n%s" %(self.username, self.password))
                    
            self.pia_protocol_dict = {"protocol_1" : {"protocol": "UDP", "port": "1197"}, 
                                        "protocol_2" : {"protocol": "TCP", "port": "502"}}
                
            pia_dict = {"server" : self.pia_server_dict, 
                        "protocol" : self.pia_protocol_dict, 
                        "provider" : "PIA", 
                        "path" : filepath,
                        "tunnel" : "OpenVPN"
                        }
            
            self.down_finished.emit(pia_dict)   
            
        except requests.exceptions.RequestException as e:
            self.importFail.emit("Network error: no internet connection")
            
class WsDownload(QtCore.QThread):
    down_finished = QtCore.pyqtSignal(object)
    importFail = QtCore.pyqtSignal(str)
    header = {"User-Agent" : "Mozilla/5.0 (X11; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0",
            "Accept" : "*/*",
            "Accept-Language" : "en-US,en;q=0.5",
            "Accept-Encoding" : "gzip, deflate, br",
            "Connection" : "keep-alive"
            }
    
    def __init__(self, username, password):
        QtCore.QThread.__init__(self)
        self.username = username
        self.password = password
        self.ws_server_dict = {}
        self.ws_protocol_dict = {}
    
    def run(self):
        init_url = "https://res.windscribe.com/res/init"
        login_url = "https://windscribe.com/login"
        
        try:
            with requests.Session() as self.session:            
                self.session.headers.update(self.header)
                self.temp = "%s/temp" %DIRECTORY
                self.session.get(login_url)
                self.session.headers.update({"Host" : "res.windscribe.com",
                                            "Origin" : "https://windscribe.com"})
                post = self.session.post("https://res.windscribe.com/res/logintoken")
                csrf = json.loads(post.content.decode("utf-8"))
                self.session.headers.pop("Host", None)
                self.session.headers.pop("Origin", None)
                
                payload = {'login' : '1',
                            'upgrade' : '0',
                            'username' : self.username,
                            'password' : self.password,
                            'csrf_token' : csrf["csrf_token"],
                            'csrf_time' : csrf["csrf_time"]
                            }
                
                post = self.session.post(login_url, data=payload)
                cred_url = "https://windscribe.com/getconfig/credentials"
                get_cred = self.session.get(cred_url)
                credentials = json.loads(get_cred.content.decode("utf-8"))
                
                try:
                    with open("%s/windscribe_userpass.txt" %self.temp, "w") as cd:
                        cd.write("%s\n%s" %(credentials["username"], credentials["password"]))
                        self.get_servers()
                except KeyError:
                    self.importFail.emit("Airvpn")
                    
        except requests.exceptions.RequestException as e:
            self.importFail.emit("Network error: no internet connection")
                    
    def get_servers(self):            
        cert_url = "https://assets.windscribe.com/desktop/other/openvpn_cert.zip"
        get_certs = self.session.get(cert_url)
        z = zipfile.ZipFile(io.BytesIO(get_certs.content))
        z.extractall(self.temp)
        
        uid = uuid.uuid4()
        random = uid.hex
        api_url = "https://assets.windscribe.com/serverlist/openvpn/1/%s" %random

        data = json.loads(self.session.get(api_url).content.decode("utf-8"))
        
        for s in data["data"]:
            try:
                countrycode = s["country_code"]
                for n in s["nodes"]:
                    city = n["group"].split("-")[0]
                    ip = n["ip2"]
                    ip2 = n["ip3"]
                    name = n["hostname"].replace("staticnetcontent", "windscribe")
                    country = country_translate(countrycode)
                    self.ws_server_dict[name] = {"name" : name, "country" : country, 
                                        "ip" : ip, "ip2" : ip2, "city" : city, "provider" : "Windscribe", "tunnel" : "OpenVPN"
                                            }
            except KeyError:
                pass
                
        self.ws_protocol_dict = {"protocol_1" : {"protocol": "UDP", "port": "443"},
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
        
        ws_dict = {"server" : self.ws_server_dict, 
                    "protocol" : self.ws_protocol_dict, 
                    "provider" : "Windscribe", 
                    "path" : self.temp
                    }
        
        self.down_finished.emit(ws_dict) 
                    
class ProtonDownload(QtCore.QThread):
    down_finished = QtCore.pyqtSignal(object)
    importFail = QtCore.pyqtSignal(str)

    def __init__(self, username, password):
        QtCore.QThread.__init__(self)
        self.username = username
        self.password = password
        self.proton_server_dict = {}
        
    def run(self):
        
        headers = {'x-pm-appversion': 'Other',
                   'x-pm-apiversion': '3',
                   'Accept': 'application/vnd.protonmail.v1+json'
                  } 
        
        try:
            with requests.Session() as self.session:
                self.session.headers.update(headers)
                path = "%s/temp" %DIRECTORY
                api_url = "https://api.protonmail.ch/vpn/logicals"
                get_servers = json.loads(self.session.get(api_url).content.decode("utf-8"))
                
                with open ("%s/s.json" %path, "w") as s:
                    json.dump(get_servers, s)
                
                for s in get_servers["LogicalServers"]:
                    name = s["Domain"]
                    cc = s["ExitCountry"]
                    if cc == "UK":
                        cc = "GB"
                    country = country_translate(cc)
                    city = s["City"]
                    if city is None:
                        city = ""
                        
                    ip = s["Servers"][0]["EntryIP"]
                    self.proton_server_dict[name] = {"name" : name, "country" : country, "city": city, "ip" : ip, "provider" : "ProtonVPN", "tunnel": "OpenVPN"}

                    
                cert_url = "https://account.protonvpn.com/api/vpn/config?ID=34&Platform=Linux"
                ovpn = requests.get(cert_url).content.decode("utf-8")

                ca_cert = BeautifulSoup(ovpn, "lxml").find("ca")
                with open("%s/proton_ca.crt" %path, "w") as ca:
                    ca.write(str(ca_cert))
                
                ta_key = "<tls-auth>\n%s" %ovpn.split("<tls-auth>")[1]
                with open("%s/proton_ta.key" %path, "w") as ta:
                    ta.write(str(ta_key))
                    
                with open("%s/proton_userpass.txt" %path, "w") as up:
                    up.write('%s\n%s' % (self.username, self.password))
                    
                self.proton_protocol_dict = {"protocol_1" : {"protocol": "UDP", "port": "1194"},
                                                "protocol_2" : {"protocol": "TCP", "port": "443"}
                                                }
                
                proton_dict = {"server" : self.proton_server_dict, 
                                "protocol" : self.proton_protocol_dict, 
                                "provider" : "ProtonVPN", 
                                "path" : path
                                }
                    
                self.down_finished.emit(proton_dict)
            
        except requests.exceptions.RequestException as e:
            self.importFail.emit("Network error: no internet connection")
            
            
class AddFolder(QtCore.QThread):
    down_finished = QtCore.pyqtSignal(dict)
    importFail = QtCore.pyqtSignal(str)
    extensions = ['.ovpn', '.conf', '.key', '.cert', '.pem']
    
    def __init__(self, credentials, folderpath):
        QtCore.QThread.__init__(self)
        self.username = credentials[0]
        self.password = credentials[1]
        self.provider = credentials[2]
        self.folderpath = folderpath
    
    def run(self):
        self.configs = [f for f in os.listdir(self.folderpath) if f.endswith('.ovpn') or f.endswith('.conf')]
        if len(self.configs) == 0:
            self.importFail.emit("nothing")
            
        elif self.sanity_check(self.folderpath) >= 10:
                self.importFail.emit("nothing")
        
        else:
            if os.path.exists("%s/temp/%s" % (DIRECTORY, self.provider)):
                shutil.rmtree("%s/temp/%s" % (DIRECTORY, self.provider))
            shutil.copytree(self.folderpath, "%s/temp/%s" % (DIRECTORY, self.provider)) 
            self.import_configs()
    
    def import_configs(self):
        custom_server_dict = {}
        failed_list = []
        temp_path = "%s/temp/%s" % (DIRECTORY, self.provider)
        for f in self.configs:
            tunnel = "OpenVPN"
            name = os.path.splitext(f)[0]
            copied_file = "%s/%s" % (temp_path, f)
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
                                    modify[index] = "remote %s %s\n" %(ip, port)
                                    ip_found = 1
                                else:
                                    failed_list.append(server)

                        else:
                            modify[index] = "#%s" %line
                    elif line.startswith("auth-user-pass"):
                        auth_file = '%s/certs/%s-auth.txt' %(ROOTDIR, self.provider)
                        modify[index] = 'auth-user-pass %s\n' % auth_file
                    elif line.startswith("verb "):
                        modify[index] = 'verb 3\n'
                    elif line.startswith("up ") or line.startswith("down "):
                        modify[index] = "#%s" %line
                    elif line.startswith("proto "):
                        protocol = line.split(" ")[1]
                        proto_line = 1
                    
                    #Wireguard
                    elif line.startswith("Endpoint ="):
                        tunnel = "Wireguard"
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
                                modify[index] = "Endpoint = %s:%s\n" %(ip, port)
                                ip_found = 1
                            else:
                                failed_list.append(server)
                        proto_line = 1
                        
                if proto_line == 0:
                    modify.insert(0, "proto %s" %protocol.lower())
    
                config.close()
                        
                with open (copied_file, "w") as file_edit:
                    file_edit.writelines(modify)
                    file_edit.close()
                    
                if ip_found != 0:
                    country_check = check_output(["geoiplookup", "%s" %ip]).decode("utf-8")
                    cc = country_check.split(" ")[3].split(",")[0]
                    country = country_translate(cc)
                    custom_server_dict[name] = {"name": name, 
                                                "provider" : self.provider, 
                                                "city" : "",
                                                "path" : "%s/%s" %(self.provider, f), 
                                                "ip" : ip, 
                                                "country" : country,
                                                "tunnel" : tunnel,
                                                "port": port.upper().split("\n")[0], 
                                                "protocol": protocol.upper().split("\n")[0]
                                                }
                    
                else:
                    pass
                    
        
        with open("%s/%s-auth.txt" % (temp_path, self.provider) , "w") as passfile:
            passfile.write('%s\n%s' % (self.username, self.password))
            
        custom_dict = {"server" : custom_server_dict, "provider" : self.provider, "path" : temp_path, "failed" : failed_list}
        self.down_finished.emit(custom_dict) 
 
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
        dig_cmd = ["dig", "+time=2", "+tries=2", "%s" %host, "+short"]
        ip = check_output(dig_cmd).decode("utf-8")
        ip = ip.split("\n")[0]
    except CalledProcessError:
        ip = "Failed to resolve"
        logging.warning("dig: resolving servername failed")
        
    return ip
    
    
class UpdateCheck(QtCore.QThread):
    release_found = QtCore.pyqtSignal(str)
    
    def __init__(self):
        QtCore.QThread.__init__(self)
    
    def run(self):
        url = "https://api.github.com/repos/corrad1nho/qomui/releases/latest"
        try:
            check_version = requests.get(url)
            latest_release = check_version.json()["tag_name"]
            self.release_found.emit(latest_release)
        except:
            logging.info("ConnectionError: Checking for update failed")
    

