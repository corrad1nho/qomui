#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from PyQt5 import QtCore, QtGui, Qt, QtWidgets
import requests
import os
from bs4 import BeautifulSoup
import zipfile
import gzip
import tarfile
from subprocess import Popen, PIPE, check_output, CalledProcessError, check_call
import re
import sys
import io
import logging
import shutil
import pycountry

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    def _fromUtf8(s):
        return s
    
try:
    _encoding = QtWidgets.QApplication.UnicodeUTF8
    def _translate(context, text, disambig):
        return QtWidgets.QApplication.translate(context, text, disambig, _encoding)
except AttributeError:
    def _translate(context, text, disambig):
        return QtWidgets.QApplication.translate(context, text, disambig)
            

DIRECTORY = "%s/.qomui" % (os.path.expanduser("~"))
ROOTDIR = "/usr/share/qomui"
supported_providers = ["Airvpn", "Mullvad", "PIA", "Manually add config files"]

def country_translate(cc):
    try:
        country = pycountry.countries.get(alpha_2=cc).name
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
                     "protocol_14" : "on",
                     "protocol_18" : "on",
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
        with requests.Session() as self.session:
            auth_parse = BeautifulSoup(self.session.get(self.url).content, "lxml")
            auth = auth_parse.find("input", {"type": "hidden"}).get("value")
            payload = {'auth_key' : auth,
                       'referer' : self.url,
                       'ips_username' : self.username,
                       'ips_password' : self.password
                        }
            post = self.session.post("https://airvpn.org/index.php?app=core&module=global&section=login&do=process",
                                     data=payload)
            cook = self.session.cookies.get_dict()
            
            if "coppa" in cook:
                self.parse()
            else:
                self.importFail.emit("Airvpn")
           
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
                if protocols[3].string == "1":
                    ip = "Primary"
                    self.Airvpn_protocol_dict[number] = {"protocol" : mode,
                                                     "port" : port,
                                                     "ip" : ip}
                elif protocols[3].string == "2":
                    ip = "Alternative"
                    self.Airvpn_protocol_dict[number] = {"protocol" : mode,
                                                     "port" : port,
                                                     "ip" : ip}
                           
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
                                             "country" : country}
   
        self.Download()

    def Download(self):
        self.download_form["csrf_token"] = self.csrf
        for key, value in self.Airvpn_server_dict.items():
            server_chosen = "server_" + key.lower() 
            self.download_form[server_chosen] = "on"
            
        download = self.session.post("https://airvpn.org/generator/", data=self.download_form)
        filepath = "%s/temp" %(DIRECTORY)
        z = zipfile.ZipFile(io.BytesIO(download.content))
        z.extractall(filepath)

        vpnfiles = sorted([file for file in os.listdir("%s/temp" % (DIRECTORY)) if file.endswith('.ovpn')])
        for ovpn in vpnfiles:
            file = "%s/temp/%s" % (DIRECTORY, ovpn)
            filedata = open(file, "r").read()
            server = ovpn.split("_")[2]
            if ovpn.endswith('_SSL-443.ovpn') == True:
                ipsearch = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
                result = ipsearch.findall(filedata)
                alt_ip = "0.0.0.0"
                for i in result:
                    if i != "127.0.0.1" and i != "255.255.255.255":
                     alt_ip = i

                self.Airvpn_server_dict[server]["alt_ip"] = alt_ip

            else:
                ipsearch = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
                result = ipsearch.findall(filedata)
                ip = "0.0.0.0"
                for j in result:
                    if j != "127.0.0.1" and j != "255.255.255.255":
                        ip = j

                self.Airvpn_server_dict[server]["prim_ip"] = ip

        Airvpn_dict = {"server" : self.Airvpn_server_dict, "protocol" : self.Airvpn_protocol_dict, "provider" : "Airvpn", "path" : filepath}
        self.down_finished.emit(Airvpn_dict)   

class MullvadDownload(QtCore.QThread):
     down_finished = QtCore.pyqtSignal(object)
     importFail = QtCore.pyqtSignal(str)
    
     def __init__(self, accountnumber):
        QtCore.QThread.__init__(self)
        self.accountnumber = accountnumber
        self.Mullvad_server_dict = {}
        self.Mullvad_protocol_dict = {}

     def run(self):
        with requests.Session() as self.session:
            self.session.headers.update({"User-Agent" :	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36",
                                         "Accept" : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                         "Accept-Language" : "en-US,en;q=0.5",
                                         "Accept-Encoding" : "gzip, deflate, br"
                                         })
            
            url = "https://mullvad.net/download/latest/source/"
            src = self.session.get(url)
            with open("%s/temp/tar" %(DIRECTORY), 'wb') as temp_file:
                temp_file.write(gzip.decompress(src.content))
                tar = tarfile.open("%s/temp/tar" %(DIRECTORY))
                tar.extractall(path="%s/temp/" %(DIRECTORY))

            certpath = "%s/temp/%s/src/mullvad/ssl/" %(DIRECTORY, tar.getnames()[0])
            with open("%s/mullvad_userpass.txt" %(certpath), "w") as passfile:
                passfile.write("%s\nm" %(self.accountnumber))

            page = self.session.get('https://www.mullvad.net/en/servers/')
            server_page = BeautifulSoup(page.content, "lxml")
            server_parse = server_page.find("div", {"class":"section-content server-table"}).findAll('tr')
            for entry in server_parse:
                info = entry.findAll('td')
                if info[1].string != "Country":
                    server = "%s.mullvad.net" %info[0].string
                    country_raw = info[1].string
                    city = info[2].string
                    ip = info[3].string
                    if country_raw == "UK":
                        country = "United Kingdom"
                    elif country_raw == "USA":
                        country = "United States"
                    elif country_raw == "Czech Rep.":
                        country = "Czechia"
                    else:
                        country = country_raw
                    self.Mullvad_server_dict[server] = {"name" : server,
                                                        "provider" :"Mullvad",
                                                        "city" : city,
                                                        "country" : country,
                                                        "ip" : ip}
                    
            self.Mullvad_protocol_dict = {"protocol_1" : {"protocol": "UDP", "port": "1194"}, "protocol_2" : {"protocol": "UDP", "port": "53"},
                                        "protocol_3" : {"protocol": "TCP", "port": "80"}, "protocol_4" : {"protocol": "TCP", "port": "443"}}

            Mullvad_dict = {"server" : self.Mullvad_server_dict, "protocol" : self.Mullvad_protocol_dict, "provider" : "Mullvad", "path" : certpath}
            self.down_finished.emit(Mullvad_dict)
            

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
        with requests.Session() as self.session:
            download_ip = self.session.get(url_ip)
            filepath = "%s/temp/ip" %(DIRECTORY)
            z = zipfile.ZipFile(io.BytesIO(download_ip.content))
            z.extractall(filepath)
            
        vpnfiles = sorted([file for file in os.listdir(filepath) if file.endswith('.ovpn')])
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
                parse_country = raw_name.split(" ")
                if parse_country[0] == "US":
                    country = "United States"
                elif parse_country[0] == "UK":
                    country = "United Kingdom"
                elif parse_country[0] == "CA":
                    country = "Canada"
                elif parse_country[0] == "AU":
                    country = "Australia"
                else:
                    country = raw_name
            except AttributeError:
                country = raw_name
          
            self.pia_server_dict[name] = {"name" : name, "country" : country, "ip" : ip, "city" : "", "provider" : "PIA"}
        
        with requests.Session() as self.session:
            download_ip = self.session.get(url_strong)
            filepath = "%s/temp/strong" %(DIRECTORY)
            z = zipfile.ZipFile(io.BytesIO(download_ip.content))
            z.extractall(filepath)
            
        with open("%s/pia_userpass.txt" %(filepath), "w") as passfile:
                passfile.write("%s\n%s" %(self.username, self.password))
                
        self.pia_protocol_dict = {"protocol_1" : {"protocol": "UDP", "port": "1197"}, 
                                       "protocol_2" : {"protocol": "TCP", "port": "502"}}
            
        pia_dict = {"server" : self.pia_server_dict, "protocol" : self.pia_protocol_dict, "provider" : "PIA", "path" : filepath}
        
        self.down_finished.emit(pia_dict)   


class AddThread(QtCore.QThread):
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
            self.importFail.emit(self.provider)
            
        elif self.sanity_check(self.folderpath) >= 10:
                self.importFail.emit(self.provider)
        
        else:
            if os.path.exists("%s/temp/%s" % (DIRECTORY, self.provider)):
                shutil.rmtree("%s/temp/%s" % (DIRECTORY, self.provider))
            shutil.copytree(self.folderpath, "%s/temp/%s" % (DIRECTORY, self.provider)) 
            self.import_configs()
    
    def import_configs(self):
        custom_server_dict = {}
        temp_path = "%s/temp/%s" % (DIRECTORY, self.provider)
        for f in self.configs:
            name = os.path.splitext(f)[0]
            copied_file = "%s/%s" % (temp_path, f)
            ip_found = 0
            with open(copied_file, "r") as config:
                modify = config.readlines()
                for index, line in enumerate(modify):
                    if line.startswith("remote "):
                        if ip_found == 0:
                            ipsearch = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
                            result = ipsearch.search(line)
                            if result is not None:
                                ip = result.group()
                                ip_found = 1
                            else:
                                server = line.split(" ")[1]
                                port = line.split(" ")[2]
                                try:
                                    dig_cmd = ["dig", "%s" %(server), "+short"]
                                    ip = check_output(dig_cmd).decode("utf-8")
                                    ip = ip.split("\n")[0]
                                    modify[index] = "remote %s %s\n" %(ip, port)
                                    ip_found = 1
                                except CalledProcessError:
                                    ip = line.split(" ")[1]
                                    logging.warning("dig: resolving servername failed")
                        else:
                            modify[index] = "#%s" %line
                    elif line.startswith("auth-user-pass"):
                        auth_file = '%s/certs/%s-auth.txt' %(ROOTDIR, self.provider)
                        modify[index] = 'auth-user-pass %s\n' % auth_file
                    elif line.startswith("verb "):
                        modify[index] = 'verb 3\n'
                    elif line.startswith("up ") or line.startswith("down "):
                        modify[index] = "#%s" %line
                config.close()
                            
                with open (copied_file, "w") as file_edit:
                    file_edit.writelines(modify)
                    file_edit.close()
                    
                if ip_found != 0:
                    country_check = check_output(["geoiplookup", "%s" %ip]).decode("utf-8")
                    cc = country_check.split(" ")[3].split(",")[0]
                    country = country_translate(cc)
                    
                    custom_server_dict[name] = {"name": name, "provider" : self.provider, "city" : "",
                                                "path" : "%s/%s" %(self.provider, f), "ip" : ip, "country" : country}
                    
                else:
                    pass
                    
        
        with open("%s/%s-auth.txt" % (temp_path, self.provider) , "w") as passfile:
            passfile.write('%s\n%s' % (self.username, self.password))
            
        custom_dict = {"server" : custom_server_dict, "provider" : self.provider, "path" : temp_path}
        
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
    
