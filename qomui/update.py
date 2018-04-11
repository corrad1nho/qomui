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

class Login(QtWidgets.QDialog):
    downloaded = QtCore.pyqtSignal(dict)
    wait = QtCore.pyqtSignal(tuple)
    
    def __init__ (self, parent, provider):
        super(Login, self).__init__(parent)
        self.provider = provider
        self.setupUi(self)
 
    def setupUi(self, Form):
        Form.setObjectName(_fromUtf8("Form"))
        Form.setMinimumSize(QtCore.QSize(270, 75))
        self.gridLayout = QtWidgets.QGridLayout(Form)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.user_edit = QtWidgets.QLineEdit(Form)
        self.user_edit.setObjectName(_fromUtf8("user_edit"))
        self.gridLayout.addWidget(self.user_edit, 0, 0, 1, 2)
        self.download_bt = QtWidgets.QPushButton(Form)
        self.download_bt.setObjectName(_fromUtf8("download_bt"))
        self.gridLayout.addWidget(self.download_bt, 0, 2, 1, 1)
        self.pass_edit = QtWidgets.QLineEdit(Form)
        self.pass_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.pass_edit.setObjectName(_fromUtf8("pass_edit"))
        if self.provider == "mullvad":
            self.pass_edit.setVisible(False)
            self.warn_label = QtWidgets.QLabel(Form)
            self.warn_label.setObjectName(_fromUtf8("warn_label"))
            self.gridLayout.addWidget(self.warn_label, 1, 0, 1, 2)
        self.gridLayout.addWidget(self.pass_edit, 1, 0, 1, 2)
        self.cancel_bt = QtWidgets.QPushButton(Form)
        self.cancel_bt.setObjectName(_fromUtf8("cancel_bt"))
        self.gridLayout.addWidget(self.cancel_bt, 1, 2, 1, 1)
        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)
        self.download_bt.clicked.connect(self.login)
        self.cancel_bt.clicked.connect(self.cancel)

    def retranslateUi(self, Form):
        Form.setWindowTitle(_translate("Form", "Credentials for %s" %self.provider, None))
        if self.provider == "airvpn":
            self.user_edit.setPlaceholderText(_translate("Form", "Username", None))
        elif self.provider == "mullvad":
            self.user_edit.setPlaceholderText(_translate("Form", "Account number", None))
            self.warn_label.setText(_translate("Form", "Info: Validity of account\nwill not be verified.", None))
        self.download_bt.setText(_translate("Form", "Download", None))
        self.pass_edit.setPlaceholderText(_translate("Form", "Password", None))
        self.cancel_bt.setText(_translate("Form", "Cancel", None))

    def cancel(self):
        self.wait.emit(("stop", None))
        self.hide()

    def login(self):
        self.wait.emit(("start", self.provider))
        if self.provider == "airvpn":
            username = self.user_edit.text()
            password = self.pass_edit.text()
            self.down_thread = AirVPNDownload(username, password)
        elif self.provider == "mullvad":
            account_number = self.user_edit.text()
            self.down_thread = MullvadDownload(account_number)
        QtWidgets.QApplication.setOverrideCursor(QtGui.QCursor(QtCore.Qt.WaitCursor))
        self.hide()
        self.down_thread.auth_fail.connect(self.authfail)
        self.down_thread.down_finished.connect(self.finished)
        self.down_thread.start()

    def authfail(self):
        QtWidgets.QApplication.restoreOverrideCursor()
        self.wait.emit(("stop", None))
        fail_msg = QtWidgets.QMessageBox.information(self,
                                                "Authentication failed",
                                                "Perhaps the credentials you entered are wrong",
                                                QtWidgets.QMessageBox.Ok)
    def finished(self, download_dict):
        QtWidgets.QApplication.restoreOverrideCursor()
        self.wait.emit(("stop", None))
        self.downloaded.emit(download_dict)

class AirVPNDownload(QtCore.QThread):
    down_finished = QtCore.pyqtSignal(object)
    auth_fail = QtCore.pyqtSignal()
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
        self.airvpn_server_dict = {}
        self.airvpn_protocol_dict = {}
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
                self.auth_fail.emit()
           
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
                    self.airvpn_protocol_dict[number] = {"protocol" : mode,
                                                     "port" : port,
                                                     "ip" : ip}
                elif protocols[3].string == "2":
                    ip = "Alternative"
                    self.airvpn_protocol_dict[number] = {"protocol" : mode,
                                                     "port" : port,
                                                     "ip" : ip}
                           
        get_list = requests.get('%s/status' % (self.url))
        get_list_parse = BeautifulSoup(get_list.content, "lxml")
        servers = get_list_parse.findAll("div", {"class":"air_server_box_1"})
        for item in servers:
            name = item.find("a").get('href').split("/")[2]
            city = item.find("span", {"style":"font-size:0.7em;"}).text
            country = item.find("img").get("alt")
            self.airvpn_server_dict[name] = {"name" : name,
                                             "provider": "airvpn",
                                             "city": city,
                                             "country" : country}
   
        self.Download()

    def Download(self):
        if not os.path.exists("%s/temp" % (DIRECTORY)):
               os.makedirs("%s/temp" % (DIRECTORY))
        self.download_form["csrf_token"] = self.csrf
        for key, value in self.airvpn_server_dict.items():
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

                self.airvpn_server_dict[server]["alt_ip"] = alt_ip

            else:
                ipsearch = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
                result = ipsearch.findall(filedata)
                ip = "0.0.0.0"
                for j in result:
                    if j != "127.0.0.1" and j != "255.255.255.255":
                        ip = j

                self.airvpn_server_dict[server]["prim_ip"] = ip

        airvpn_dict = {"server" : self.airvpn_server_dict, "protocol" : self.airvpn_protocol_dict, "provider" : "airvpn", "path" : filepath}
        self.down_finished.emit(airvpn_dict)   

class MullvadDownload(QtCore.QThread):
     down_finished = QtCore.pyqtSignal(object)
     auth_fail = QtCore.pyqtSignal()
     auth_success = QtCore.pyqtSignal()
    
     def __init__(self, accountnumber):
        QtCore.QThread.__init__(self)
        self.accountnumber = accountnumber
        self.mullvad_server_dict = {}
        self.mullvad_protocol_dict = {}

     def run(self):
        self.auth_success.emit()
        if not os.path.exists("%s/temp" % (DIRECTORY)):
               os.makedirs("%s/temp" % (DIRECTORY))
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

            page = self.session.get('https://mullvad.net/guides/our-vpn-servers/')
            server_page = BeautifulSoup(page.content, "lxml")
            server_parse = server_page.find("pre").get_text()
            formatted = io.StringIO(server_parse)
            lines = formatted.readlines()[6:]
            for line in lines:
                if re.search(r" | ", line) is not None:
                    results = line.split("|")
                    server = results[0].replace(" ", "") + ".mullvad.net"
                    dig_cmd = ["dig", "%s" %(server), "+short"]
                    ip = check_output(dig_cmd).decode("utf-8")
                    country_raw = results[1].strip()
                    if country_raw == "UK":
                        country = "United Kingdom"
                    elif country_raw == "USA":
                        country = "United States"
                    elif country_raw == "Czech Rep.":
                        country = "Czech Republic"
                    else:
                        country = country_raw
                    city = results[2].strip()
                    self.mullvad_server_dict[server] = {"name" : server,
                                                        "provider" :"mullvad",
                                                        "city" : city,
                                                        "country" : country,
                                                        "ip" : ip}
                    
            self.mullvad_protocol_dict = {"protocol_1" : {"protocol": "UDP", "port": "1194"}, "protocol_2" : {"protocol": "UDP", "port": "53"},
                                        "protocol_3" : {"protocol": "TCP", "port": "80"}, "protocol_4" : {"protocol": "TCP", "port": "443"}}

            mullvad_dict = {"server" : self.mullvad_server_dict, "protocol" : self.mullvad_protocol_dict, "provider" : "mullvad", "path" : certpath}
            self.down_finished.emit(mullvad_dict)
            
            

class AuthEdit(QtWidgets.QDialog):
    auth = QtCore.pyqtSignal(tuple)
    
    def __init__ (self, parent=None):
        super(AuthEdit, self).__init__(parent)
        self.setupUi(self)
 
    def setupUi(self, Form):
        Form.setObjectName(_fromUtf8("Form"))
        Form.setMinimumSize(QtCore.QSize(270, 75))
        self.gridLayout = QtWidgets.QGridLayout(Form)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.info_lbl = QtWidgets.QLabel(Form)
        self.info_lbl.setObjectName(_fromUtf8("info_lbl"))
        self.gridLayout.addWidget(self.info_lbl, 0, 0, 1, 2)                            
        self.user_edit = QtWidgets.QLineEdit(Form)
        self.user_edit.setObjectName(_fromUtf8("user_edit"))
        self.gridLayout.addWidget(self.user_edit, 1, 0, 1, 1)
        self.confirm_bt = QtWidgets.QPushButton(Form)
        self.confirm_bt.setObjectName(_fromUtf8("confirmbt"))
        self.gridLayout.addWidget(self.confirm_bt, 1, 1, 1, 1)
        self.pass_edit = QtWidgets.QLineEdit(Form)
        self.pass_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.pass_edit.setObjectName(_fromUtf8("pass_edit"))
        self.gridLayout.addWidget(self.pass_edit, 2, 0, 1, 1)
        self.cancel_bt = QtWidgets.QPushButton(Form)
        self.cancel_bt.setObjectName(_fromUtf8("cancel_bt"))
        self.gridLayout.addWidget(self.cancel_bt, 2, 1, 1, 1)
        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)
        self.confirm_bt.clicked.connect(self.auth_signal)
        self.cancel_bt.clicked.connect(self.cancel)
        
    def retranslateUi(self, Form):
        Form.setWindowTitle(_translate("Form", "Add Config File(s)", None))
        self.info_lbl.setText(_translate("Form", "Please enter the user and password\nfor the OpenVPN-server(s) you want to add", None))
        self.user_edit.setPlaceholderText(_translate("Form", "Username", None))
        self.confirm_bt.setText(_translate("Form", "Ok", None))
        self.pass_edit.setPlaceholderText(_translate("Form", "Password", None))
        self.cancel_bt.setText(_translate("Form", "Cancel", None))
        
    def auth_signal(self):
        credentials = (self.user_edit.text(), self.pass_edit.text())
        self.auth.emit(credentials)
        self.hide()
    
    def cancel(self):
        self.hide()
            
            
class AddThread(QtCore.QThread):
    added = QtCore.pyqtSignal(dict)
    copyauth = QtCore.pyqtSignal(str)
    
    def __init__(self, service, files, username, password):
        QtCore.QThread.__init__(self)
        self.ovpn_service = service
        self.files = files
        self.username = username
        self.password = password
    
    def run(self):
        custom_server_dict = {}
        for filename in self.files:
            path = os.path.dirname(filename)
            ovpn_only = os.path.basename(filename)
            name = os.path.splitext(ovpn_only)[0]
            path_modified = "%s/Qomui-%s" % (path, ovpn_only)
            ip_found = 0
            with open(filename, "r") as config:
                modify = config.readlines()
                for index, line in enumerate(modify):
                    if line.startswith("remote "):
                        ipsearch = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
                        result = ipsearch.search(line)
                        if result is not None:
                            if ip_found == 0:
                                ip = result.group()
                                ip_found = 1
                            else:
                                modify[index] = "#%s" %line
                        else:
                            if ip_found == 0:
                                server = line.split(" ")[1]
                                port = line.split(" ")[2]
                                try:
                                    dig_cmd = ["dig", "%s" %(server), "+short"]
                                    ip = check_output(dig_cmd).decode("utf-8")
                                    ip = ip.split("\n")[0]
                                    modify[index] = "remote %s %s" %(ip, port)
                                    ip_found = 1
                                except CalledProcessError:
                                    logging.warning("dig: resolving servername failed")
                            else:
                                line = "#%s" %line
                    elif line.startswith("auth-user-pass"):
                        auth_file = '%s/authfiles/%s_auth.txt' %(ROOTDIR, name)
                        modify[index] = 'auth-user-pass %s\n' % auth_file
                        self.copyauth.emit(auth_file)
                        
                    with open (path_modified, "w") as file_edit:
                        file_edit.writelines(modify)
                        file_edit.close()
                        config.close
                        
            country_check = check_output(["geoiplookup", "%s" %ip]).decode("utf-8")
            cc = country_check.split(" ")[3].split(",")[0]
            
            try:
                country = pycountry.countries.get(alpha_2=cc).name
            except KeyError:
                country = "undefined"
            
            custom_server_dict[name] = {"name": name, "provider" : "custom", 
                                                "path" : path_modified, "ip" : ip, "country" : country}
                
        self.added.emit(custom_server_dict)
