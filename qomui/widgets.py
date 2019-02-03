#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import math
import json
import re
import time
import logging
import psutil
import configparser
import requests
import shlex
import logging
from PyQt5 import QtCore, QtWidgets, QtGui

from qomui import update

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

ROOTDIR = "/usr/share/qomui"
HOMEDIR = "{}/.qomui".format(os.path.expanduser("~"))
SUPPORTED_PROVIDERS = ["Airvpn", "AzireVPN", "Mullvad", "PIA", "ProtonVPN", "Windscribe"]

class favouriteButton(QtWidgets.QAbstractButton):
    def __init__(self, parent=None):
        super(favouriteButton, self).__init__(parent)
        self.star = QtGui.QPolygonF([QtCore.QPointF(1.0, 0.5)])
        for i in range(5):
            self.star << QtCore.QPointF(0.5 + 0.5 * math.cos(0.8 * i * math.pi),
                                        0.5 + 0.5 * math.sin(0.8 * i * math.pi)
                                        )

    def paintEvent(self, event):
        painter = QtGui.QPainter(self)
        rect = self.rect()
        palette = self.palette()
        painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        painter.setPen(QtCore.Qt.NoPen)
        if self.isChecked() == True:
            painter.setBrush(palette.highlight())
        else:
            painter.setBrush(palette.buttonText())
        yOffset = (rect.height() - 25) /2
        painter.translate(rect.x(), rect.y() + yOffset)
        painter.scale(25, 25)
        painter.drawPolygon(self.star, QtCore.Qt.WindingFill)
        painter.translate(1.0, 0.0)

    def enterEvent(self, event):
        self.update()

    def leaveEvent(self, event):
        self.update()

    def sizeHint(self):
        return QtCore.QSize(25, 25)

class ServerWidget(QtWidgets.QWidget):
    server_chosen = QtCore.pyqtSignal(str)
    set_hop_signal = QtCore.pyqtSignal(str)
    changed_favourite_signal = QtCore.pyqtSignal(tuple)

    def __init__ (self, show=None, parent=None):
        super(ServerWidget, self).__init__(parent=None)
        self.hidden = False
        self.fav = 0
        self.show = show
        self.setMouseTracking(True)
        self.setupUi(self)

    def setupUi(self, Form):
        Form.setObjectName(_fromUtf8("Form"))
        self.horizontalLayout = QtWidgets.QHBoxLayout(Form)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.iconLabel = QtWidgets.QLabel(Form)
        self.iconLabel.setFixedSize(QtCore.QSize(30, 30))
        self.iconLabel.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.iconLabel.setObjectName(_fromUtf8("iconLabel"))
        self.horizontalLayout.addWidget(self.iconLabel)
        self.nameLabel = QtWidgets.QLabel(Form)
        self.nameLabel.setObjectName(_fromUtf8("nameLabel"))
        self.horizontalLayout.addWidget(self.nameLabel)
        self.cityLabel = QtWidgets.QLabel(Form)
        self.cityLabel.setObjectName(_fromUtf8("cityLabel"))
        self.horizontalLayout.addWidget(self.cityLabel)
        self.horizontalLayout.addStretch()
        self.favouriteButton = favouriteButton(Form)
        self.favouriteButton.setVisible(False)
        self.favouriteButton.setCheckable(True)
        self.favouriteButton.setObjectName(_fromUtf8("favouriteButton"))
        self.horizontalLayout.addWidget(self.favouriteButton)
        self.hop_bt = QtWidgets.QPushButton(Form)
        self.hop_bt.setVisible(False)
        self.hop_bt.setObjectName(_fromUtf8("hop_bt"))
        self.horizontalLayout.addWidget(self.hop_bt)
        self.connect_bt = QtWidgets.QPushButton(Form)
        if self.show == None:
            self.connect_bt.setVisible(False)
        self.connect_bt.setObjectName(_fromUtf8("connect_bt"))
        self.horizontalLayout.addWidget(self.connect_bt)
        QtCore.QMetaObject.connectSlotsByName(Form)
        self.connect_bt.clicked.connect(self.signal)
        self.hop_bt.clicked.connect(self.hop_signal)
        self.favouriteButton.toggled.connect(self.fav_change)

    def setText(self, name, provider, country, city, button = "connect", fav = 0):
        self.name = name
        self.provider = provider
        self.city = city
        self.fav = fav

        if self.provider != "bypass":

            try:
                self.iconLabel.setPixmap(country)

            except TypeError:
                flag = '{}/flags/{}.png'.format(ROOTDIR, country)
                if not os.path.isfile(flag):
                    flag = '{}/flags/Unknown.png'.format(ROOTDIR)
                pixmap = QtGui.QPixmap(flag).scaled(25, 25,
                                                    transformMode=QtCore.Qt.SmoothTransformation
                                                    )
                self.iconLabel.setPixmap(pixmap)
        else:
            icon = QtGui.QIcon.fromTheme(country)
            self.iconLabel.setPixmap(icon.pixmap(25,25))

        bold_font = QtGui.QFont()
        bold_font.setBold(True)
        bold_font.setWeight(75)
        bold_font.setPointSize(11)

        if self.fav == "on":
            self.favouriteButton.setChecked(True)

        self.nameLabel.setFont(bold_font)
        self.nameLabel.setText(self.name)
        self.cityLabel.setText(self.city)

        try:
            self.connect_bt.setText(_translate("Form", button, None))

        except AttributeError:
            pass

        try:
            self.hop_bt.setText(_translate("Form", "hop", None))

        except AttributeError:
            pass

    def hide_button(self, choice=None):
        self.choice = choice
        #self.horizontalLayout.removeWidget(self.hop_bt)
        self.hop_bt = None

        if choice == 1:
            self.connect_bt.setVisible(False)
            self.horizontalLayout.removeWidget(self.connect_bt)
            self.connect_bt = None

    def enterEvent(self, event):
        if self.show == None:

            try:
                self.connect_bt.setVisible(True)

            except AttributeError:
                pass

            try:
                self.hop_bt.setVisible(True)
            except AttributeError:
                pass

            self.cityLabel.setVisible(False)

            if self.fav != 0:
                self.favouriteButton.setVisible(True)

    def leaveEvent(self, event):
        if self.show == None:

            try:
                self.connect_bt.setVisible(False)

            except AttributeError:
                pass

            try:
                self.hop_bt.setVisible(False)

            except AttributeError:
                pass

            self.cityLabel.setVisible(True)
            self.favouriteButton.setVisible(False)

    def signal(self):
        self.server_chosen.emit(self.name)

    def display_latency(self, latency):
        self.latency = latency

        if self.city != "":
            self.cityLabel.setText("{} - {}".format(self.city, self.latency))

        else:
            self.cityLabel.setText(latency)

    def setHidden(self, state):
        self.hidden = state

    def isHidden(self):
        return self.hidden

    def hop_signal(self):
        self.set_hop_signal.emit(self.name)

    def fav_change(self, change):
        self.changed_favourite_signal.emit((self.name, change))

    def sizeHint(self):
        return QtCore.QSize(100, 50)

class HopWidget(QtWidgets.QWidget):
    clear = QtCore.pyqtSignal()

    def __init__ (self, parent=None):
        super(HopWidget, self).__init__(parent)
        self.setupUi(self)

    def setupUi(self, Form):
        Form.setObjectName(_fromUtf8("Form"))
        Form.resize(100, 100)
        self.setAutoFillBackground(True)
        self.setBackgroundRole(self.palette().Base)
        self.verticalLayout = QtWidgets.QVBoxLayout(Form)
        self.hopLabel = QtWidgets.QLabel(Form)
        bold_font = QtGui.QFont()
        bold_font.setBold(True)
        bold_font.setWeight(75)
        self.hopLabel.setFont(bold_font)
        self.verticalLayout.addWidget(self.hopLabel)
        self.activeHopWidget = ServerWidget()
        self.verticalLayout.addWidget(self.activeHopWidget)
        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)
        self.activeHopWidget.server_chosen.connect(self.signal)

    def retranslateUi(self, Form):
        Form.setWindowTitle(_translate("Form", "Form", None))
        self.hopLabel.setText(_translate("Form", "Current selection for first hop:", None))

    def setText(self, server_dict):
        try:
            city = server_dict["city"]

        except KeyError:
            city = None

        self.activeHopWidget.setText(server_dict["name"], server_dict["provider"],
                               server_dict["country"], city, button="clear")

        self.activeHopWidget.hide_button(0)

    def signal(self):
        self.clear.emit()

class ProgressBarWidget(QtWidgets.QWidget):
    abort = QtCore.pyqtSignal(str)

    def __init__ (self, parent=None):
        super(ProgressBarWidget, self).__init__(parent)
        self.setupUi(self)

    def setupUi(self, ProgessBarWidget):
        self.horizontalLayout = QtWidgets.QHBoxLayout(ProgessBarWidget)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.taskLabel = QtWidgets.QLabel(ProgessBarWidget)
        self.taskLabel.setObjectName(_fromUtf8("taskLabel"))
        bold_font = QtGui.QFont()
        bold_font.setPointSize(13)
        bold_font.setBold(True)
        bold_font.setWeight(75)
        self.taskLabel.setFont(bold_font)
        self.horizontalLayout.addWidget(self.taskLabel)
        self.waitBar = QtWidgets.QProgressBar(ProgessBarWidget)
        self.waitBar.setObjectName(_fromUtf8("waitBar"))
        self.horizontalLayout.addWidget(self.waitBar)
        self.cancelButton = QtWidgets.QPushButton(ProgessBarWidget)
        self.cancelButton.setObjectName(_fromUtf8("cancelButton"))
        self.horizontalLayout.addWidget(self.cancelButton)

        self.cancelButton.clicked.connect(self.cancel)
        self.waitBar.setRange(0, 0)

    def setText(self, text, action=None):
        self.action = action
        self.cancelButton.setText("cancel")
        if action == "upgrade":
            self.cancelButton.setVisible(False)
        self.taskLabel.setText(_translate("ProgessBarWidget", text, None))

    def cancel(self):
        self.abort.emit(self.action)

class ActiveWidget(QtWidgets.QWidget):
    disconnect = QtCore.pyqtSignal()
    reconnect = QtCore.pyqtSignal()
    check_update = QtCore.pyqtSignal()

    def __init__ (self, text, parent=None):
        super(ActiveWidget, self).__init__(parent)
        self.setupUi(self)
        self.text = text
        self.bypass = None

    def setupUi(self, ConnectionWidget):
        ConnectionWidget.setObjectName(_fromUtf8("ConnectionWidget"))
        self.verticalLayout = QtWidgets.QVBoxLayout(ConnectionWidget)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
        self.statusLabel = QtWidgets.QLabel(ConnectionWidget)
        bold_font = QtGui.QFont()
        bold_font.setPointSize(12)
        bold_font.setBold(True)
        bold_font.setWeight(75)
        self.statusLabel.setFont(bold_font)
        self.statusLabel.setObjectName(_fromUtf8("statusLabel"))
        self.horizontalLayout_3.addWidget(self.statusLabel)
        self.ipExtLabel = QtWidgets.QLabel(ConnectionWidget)
        self.ipExtLabel.setObjectName(_fromUtf8("ipExtLabel"))
        self.horizontalLayout_3.addWidget(self.ipExtLabel)
        self.horizontalLayout_3.addStretch()
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        self.ServerWidget = ServerWidget(show=True, parent=ConnectionWidget)
        self.verticalLayout.addWidget(self.ServerWidget)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.downloadLabel = QtWidgets.QLabel(ConnectionWidget)
        bold_font = QtGui.QFont()
        bold_font.setBold(True)
        bold_font.setWeight(75)
        self.downloadLabel.setFont(bold_font)
        self.downloadLabel.setObjectName(_fromUtf8("downloadLabel"))
        self.horizontalLayout.addWidget(self.downloadLabel)
        self.downStatLabel = QtWidgets.QLabel(ConnectionWidget)
        self.downStatLabel.setObjectName(_fromUtf8("downStatLabel"))
        self.horizontalLayout.addWidget(self.downStatLabel)
        self.uploadLabel = QtWidgets.QLabel(ConnectionWidget)
        bold_font = QtGui.QFont()
        bold_font.setBold(True)
        bold_font.setWeight(75)
        self.uploadLabel.setFont(bold_font)
        self.uploadLabel.setObjectName(_fromUtf8("uploadLabel"))
        self.horizontalLayout.addWidget(self.uploadLabel)
        self.upStatLabel = QtWidgets.QLabel(ConnectionWidget)
        self.upStatLabel.setObjectName(_fromUtf8("upStatLabel"))
        self.horizontalLayout.addWidget(self.upStatLabel)
        self.timeLabel = QtWidgets.QLabel(ConnectionWidget)
        self.timeLabel.setObjectName(_fromUtf8("timeLabel"))
        self.timeLabel.setFont(bold_font)
        self.horizontalLayout.addWidget(self.timeLabel)
        self.timeStatLabel = QtWidgets.QLabel(ConnectionWidget)
        self.timeStatLabel.setObjectName(_fromUtf8("timeStatLabel"))
        self.horizontalLayout.addWidget(self.timeStatLabel)
        self.horizontalLayout.addStretch()
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName(_fromUtf8("horizontalLayout_4"))
        self.hopActiveLabel = QtWidgets.QLabel(ConnectionWidget)
        bold_font = QtGui.QFont()
        bold_font.setPointSize(13)
        bold_font.setBold(True)
        bold_font.setWeight(75)
        self.hopActiveLabel.setFont(bold_font)
        self.hopActiveLabel.setObjectName(_fromUtf8("hopActiveLabel"))
        self.hopActiveLabel.setMinimumSize(QtCore.QSize(30, 30))
        self.hopActiveLabel.setMaximumSize(QtCore.QSize(30, 30))
        self.hopActiveLabel.setVisible(False)
        self.horizontalLayout_4.addWidget(self.hopActiveLabel)
        self.activeHopWidget = ServerWidget(ConnectionWidget)
        self.activeHopWidget.setVisible(False)
        self.horizontalLayout_4.addWidget(self.activeHopWidget)
        self.verticalLayout.addLayout(self.horizontalLayout_4)
        self.line = LineWidget(ConnectionWidget)
        self.line.setObjectName(_fromUtf8("line"))
        self.verticalLayout.addWidget(self.line)
        self.retranslateUi(ConnectionWidget)
        QtCore.QMetaObject.connectSlotsByName(ConnectionWidget)
        self.ServerWidget.server_chosen.connect(self.signal)

    def retranslateUi(self, ConnectionWidget):
        ConnectionWidget.setWindowTitle(_translate("ConnectionWidget", "Form", None))
        #self.statusLabel.setText(_translate("ConnectionWidget", "", None))
        self.downloadLabel.setText(_translate("ConnectionWidget", "Download:", None))
        self.uploadLabel.setText(_translate("ConnectionWidget", "Upload:", None))
        self.timeLabel.setText(_translate("ConnectionWidget", "Time:", None))

    def setText(self, server_dict, hop_dict, tun, tun_hop=None, bypass=None):
        self.tun = tun
        self.tun_hop = tun_hop
        self.bypass = bypass
        self.statusLabel.setText(self.text)
        city = self.city_port_label(server_dict)
        self.ServerWidget.setText(server_dict["name"], server_dict["provider"],
                               server_dict["country"], city, button="disconnect")

        if hop_dict is not None:
            self.activeHopWidget.setVisible(True)
            self.hopActiveLabel.setVisible(True)
            self.hopActiveLabel.setText(_translate("HopWidget", "via", None))
            hop_city = self.city_port_label(hop_dict)
            self.activeHopWidget.setText(hop_dict["name"], hop_dict["provider"],
                               hop_dict["country"], hop_city)
            self.activeHopWidget.hide_button(1)
        else:
            self.activeHopWidget.setVisible(False)
            self.hopActiveLabel.setVisible(False)

        self.ServerWidget.hide_button(0)
        self.calcThread = TunnelMon(self.tun, self.bypass, tun_hop=self.tun_hop)
        self.calcThread.stat.connect(self.show_stats)
        self.calcThread.ip.connect(self.show_ip)
        self.calcThread.log.connect(self.log_from_thread)
        self.calcThread.time.connect(self.update_time)
        self.calcThread.check.connect(self.check_for_update)
        self.calcThread.lost.connect(self.reconnect_signal)
        self.calcThread.start()
        logging.debug("Monitoring thread initialized")

    def log_from_thread(self, msg):
        getattr(logging, msg[0])(msg[1])

    def reconnect_signal(self):
        self.reconnect.emit()

    def city_port_label(self, server_dict):
        try:
            protocol = server_dict["protocol"]
            port = server_dict["port"]

        except KeyError:
            protocol = ""
            port = ""

        try:
            city = server_dict["city"]
            if city != "":
                (city) = "{} -".format(city)

        except KeyError:
            city = ""

        return "{} {} {}".format(city, protocol, port)

    def show_ip(self, ips):
        if ips[0] is None:
            self.ipExtLabel.setText("")

        elif ips[1] is None:
            self.ipExtLabel.setText("IP: {}".format(ips[0]))

        elif ips[0] == ips[1]:
            self.ipExtLabel.setText("IP: {}".format(ips[0]))

        else:
            self.ipExtLabel.setText("IP: {} - {}".format(ips[0], ips[1]))

    def update_time(self, t):
        self.timeStatLabel.setText(t)

    def check_for_update(self):
        self.check_update.emit()

    def show_stats(self, update):
        DLrate = update[0]
        DLacc = update[1]
        ULrate = update[2]
        ULacc = update[3]
        unit_dl = "kB/s"
        unit_ul = "kB/s"
        unit_acc_up = "MB"
        unit_acc_down = "MB"

        if ULrate / 1024 >= 1:
            ULrate = ULrate / 1024
            unit_ul = "MB/s"

        if DLrate / 1024 >= 1:
            DLrate = DLrate / 1024
            unit_dl = "MB/s"

        if DLacc / 1024 >= 1:
            DLacc = DLacc / 1024
            unit_acc_down = "GB"

        if ULacc / 1024 >= 1:
            ULacc = ULacc / 1024
            unit_acc_up = "GB"

        self.upStatLabel.setText("{} {}- {} {}".format(
                                                        round(ULrate, 1),
                                                        unit_ul,
                                                        round(ULacc, 1),
                                                        unit_acc_up)
                                                        )
        self.downStatLabel.setText("{} {} - {} {}".format(
                                                        round(DLrate, 1),
                                                        unit_dl,
                                                        round(DLacc, 1),
                                                        unit_acc_down)
                                                        )

    def signal(self):
        self.disconnect.emit()

class LineWidget(QtWidgets.QWidget):

    def __init__ (self, parent=None):
        super(LineWidget, self).__init__(parent)
        self.setupUi(self)

    def setupUi(self, LineWidget):
        self.setAutoFillBackground(True)
        self.setFixedHeight(1)
        #self.setBackgroundRole(self.palette().Highlight)

class TunnelMon(QtCore.QThread):
    stat = QtCore.pyqtSignal(list)
    ip = QtCore.pyqtSignal(tuple)
    time = QtCore.pyqtSignal(str)
    check = QtCore.pyqtSignal()
    lost = QtCore.pyqtSignal()
    log = QtCore.pyqtSignal(tuple)

    def __init__(self, tun, bypass, tun_hop=None):
        QtCore.QThread.__init__(self)
        self.tun = tun
        self.bypass = bypass
        self.tun_hop = tun_hop

    def run(self):
        connected = True
        check_url = "https://ipv4.ipleak.net/json"
        check_url_6 = "https://ipv6.ipleak.net/json"
        check_url_alt = "https://ipv4.icanhazip.com/"
        check_url_alt_6 = "https://ipv6.icanhazip.com/"

        if self.bypass is None:

            try:
                query = requests.get(check_url, timeout=1).content.decode("utf-8")
                ip = json.loads(query)["ip"]

            except (KeyError, requests.exceptions.RequestException, json.decoder.JSONDecodeError):

                try:
                    ip = requests.get(check_url_alt, timeout=1).content.decode("utf-8").replace("\n", "")

                except requests.exceptions.RequestException:
                    self.log.emit(("info", "Could not determine external ipv4 address"))
                    ip = None

            try:
                query = requests.get(check_url_6, timeout=1).content.decode("utf-8")
                ip_6 = json.loads(query)["ip"]

            except (KeyError, requests.exceptions.RequestException, json.decoder.JSONDecodeError):

                try:
                    ip_6 = requests.get(check_url_alt_6, timeout=1).content.decode("utf-8").replace("\n", "")

                except requests.exceptions.RequestException:
                    self.log.emit(("info", "Could not determine external ipv6 address"))
                    ip_6 = None

            self.log.emit(("info", "External ip = {} - {}".format(ip, ip_6)))
            self.ip.emit((ip, ip_6))

        t0 = time.time()
        accum = (0, 0)
        start_time = time.time()

        try:
            counter = psutil.net_io_counters(pernic=True)[self.tun]
            stat = (counter.bytes_recv, counter.bytes_sent)

        except KeyError:
            stat = (0,0)

        while connected is True:
            last_stat = stat
            time.sleep(1)
            time_measure = time.time()
            elapsed = time_measure - start_time

            if int(elapsed) % 900 == 0:
                self.check.emit()

            return_time = self.time_format(int(elapsed))
            self.time.emit(return_time)

            try:
                counter = psutil.net_io_counters(pernic=True)[self.tun]
                if self.tun_hop is not None:
                    tun_hop_test = psutil.net_io_counters(pernic=True)[self.tun_hop]
                t1 = time.time()
                stat = (counter.bytes_recv, counter.bytes_sent)
                DLrate, ULrate = [(now - last) / (t1 - t0) / 1024.0 for now, last in zip(stat, last_stat)]
                DLacc, ULacc = [(now + last) / (1024*1024) for now, last in zip(stat, last_stat)]
                t0 = time.time()
                self.stat.emit([DLrate, DLacc, ULrate, ULacc])

            except (KeyError, OSError):
                break

        connected = False
        self.log.emit(("info", "Interface {} does not exist anymore".format(self.tun)))
        self.lost.emit()

    def time_format(self, e):
        calc = '{:02d}d {:02d}h {:02d}m {:02d}s'.format(e // 86400,
                                                        (e % 86400 // 3600),
                                                        (e % 3600 // 60),
                                                        e % 60
                                                        )
        split = calc.split(" ")

        if split[0] == "00d" and split[1] == "00h":
            return ("{} {}".format(split[2], split[3]))

        elif split[0] == "00d" and split[1] != "00h":
            return ("{} {}".format(split[1], split[2]))

        else:
            return ("{} {}".format(split[0], split[1]))

class FirewallEditor(QtWidgets.QDialog):
    fw_change = QtCore.pyqtSignal(dict)
    options = [
            "block_lan",
            "preserve_rules",
            "fw_gui_only"
            ]

    def __init__ (self, config, parent=None):
        super(FirewallEditor, self).__init__(parent)
        try:
            with open('{}/firewall.json'.format(ROOTDIR), 'r') as fload:
                self.firewall_dict = json.load(fload)
        except FileNotFoundError:
            with open('{}/firewall_default.json'.format(ROOTDIR), 'r') as fload:
                self.firewall_dict = json.load(fload)

        self.config_dict = config
        self.setupUi(self)
        self.display_rules()

    def setupUi(self, Form):
        Form.setObjectName(_fromUtf8("Form"))
        Form.resize(600, 700)
        self.verticalLayout = QtWidgets.QVBoxLayout(Form)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.headerLabel = QtWidgets.QLabel(Form)
        bold_font = QtGui.QFont()
        bold_font.setPointSize(12)
        bold_font.setBold(True)
        bold_font.setWeight(75)
        self.headerLabel.setFont(bold_font)
        self.headerLabel.setObjectName(_fromUtf8("headerLabel"))
        self.verticalLayout.addWidget(self.headerLabel)
        self.block_lan_check = QtWidgets.QCheckBox()
        self.block_lan_check.setObjectName(_fromUtf8("headerLabel"))
        self.verticalLayout.addWidget(self.block_lan_check)
        self.fw_gui_only_check = QtWidgets.QCheckBox()
        self.fw_gui_only_check.setObjectName(_fromUtf8("headerLabel"))
        self.verticalLayout.addWidget(self.fw_gui_only_check)
        self.preserve_rules_check = QtWidgets.QCheckBox()
        self.preserve_rules_check.setObjectName(_fromUtf8("headerLabel"))
        self.verticalLayout.addWidget(self.preserve_rules_check)
        self.warnLabel = QtWidgets.QLabel(Form)
        self.warnLabel.setObjectName(_fromUtf8("warnLabel"))
        self.verticalLayout.addWidget(self.warnLabel)
        self.line = QtWidgets.QFrame(Form)
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName(_fromUtf8("line"))
        self.verticalLayout.addWidget(self.line)
        self.ipv4Label = QtWidgets.QLabel(Form)
        bold_font = QtGui.QFont()
        bold_font.setBold(True)
        bold_font.setWeight(75)
        self.ipv4Label.setFont(bold_font)
        self.ipv4Label.setObjectName(_fromUtf8("ipv4_on_lbl"))
        self.verticalLayout.addWidget(self.ipv4Label)
        self.ipv4Edit = QtWidgets.QPlainTextEdit(Form)
        self.ipv4Edit.setObjectName(_fromUtf8("ipv4_on_edit"))
        self.verticalLayout.addWidget(self.ipv4Edit)
        self.ipv6Label = QtWidgets.QLabel(Form)
        bold_font = QtGui.QFont()
        bold_font.setBold(True)
        bold_font.setWeight(75)
        self.ipv6Label.setFont(bold_font)
        self.ipv6Label.setObjectName(_fromUtf8("ipv6_on_lbl_2"))
        self.verticalLayout.addWidget(self.ipv6Label)
        self.ipv6Edit = QtWidgets.QPlainTextEdit(Form)
        self.ipv6Edit.setObjectName(_fromUtf8("ipv6_on_edit"))
        self.verticalLayout.addWidget(self.ipv6Edit)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.horizontalLayout.addStretch()
        self.restoreButton = QtWidgets.QPushButton(Form)
        self.restoreButton.setObjectName(_fromUtf8("saveButton"))
        self.horizontalLayout.addWidget(self.restoreButton)
        self.saveButton = QtWidgets.QPushButton(Form)
        self.saveButton.setObjectName(_fromUtf8("saveButton"))
        self.horizontalLayout.addWidget(self.saveButton)
        self.cancelButton = QtWidgets.QPushButton(Form)
        self.cancelButton.setObjectName(_fromUtf8("cancelButton"))
        self.horizontalLayout.addWidget(self.cancelButton)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.retranslateUi(Form)
        self.set_options()
        QtCore.QMetaObject.connectSlotsByName(Form)
        self.cancelButton.clicked.connect(self.cancel)
        self.saveButton.clicked.connect(self.save_rules)
        self.restoreButton.clicked.connect(self.restore)

    def retranslateUi(self, Form):
        Form.setWindowTitle(_translate("Form", "Edit firewall", None))
        self.headerLabel.setText(_translate("Form", "Configure firewall", None))
        self.warnLabel.setText(_translate("Form", "Warning: Only for advanced users ", None))
        self.block_lan_check.setText(_translate("Form", "Block lan/private networks", None))
        self.fw_gui_only_check.setText(_translate("Form", "Activate firewall only when gui is running", None))
        self.preserve_rules_check.setText(_translate("Form", "Preserve pre-existing firewall rules", None))
        self.ipv4Label.setText(_translate("Form", "IPv4 rules", None))
        self.ipv6Label.setText(_translate("Form", "IPv6 rules", None))
        self.saveButton.setText(_translate("Form", "Save", None))
        self.saveButton.setIcon(QtGui.QIcon.fromTheme("dialog-ok"))
        self.cancelButton.setText(_translate("Form", "Cancel", None))
        self.cancelButton.setIcon(QtGui.QIcon.fromTheme("dialog-no"))
        self.restoreButton.setText(_translate("Form", "Restore defaults", None))
        self.restoreButton.setIcon(QtGui.QIcon.fromTheme("view-refresh"))

    def set_options(self):
        for option in self.options:
            try:
                if self.config_dict[option] == 1:
                    getattr(self, "{}_check".format(option)).setCheckState(2)
                else:
                    getattr(self, "{}_check".format(option)).setCheckState(0)

            except KeyError:
                getattr(self, "{}_check".format(option)).setCheckState(0)

    def display_rules(self):
        for rule in self.firewall_dict["ipv4rules"]:
            self.ipv4Edit.appendPlainText(' '.join(rule))

        for rule in self.firewall_dict["ipv6rules"]:
            self.ipv6Edit.appendPlainText(' '.join(rule))

    def restore(self):
        self.ipv4Edit.clear()
        self.ipv6Edit.clear()

        with open('{}/firewall_default.json'.format(ROOTDIR), 'r') as fload:
            self.firewall_dict = json.load(fload)

        self.display_rules()

    def save_rules(self):
        new_ipv4_rules = []
        new_ipv6_rules = []

        for line in self.ipv4Edit.toPlainText().split("\n"):
                new_ipv4_rules.append(shlex.split(line))

        for line in self.ipv6Edit.toPlainText().split("\n"):
                new_ipv6_rules.append(shlex.split(line))

        self.firewall_dict["ipv4rules"] = new_ipv4_rules
        self.firewall_dict["ipv6rules"] = new_ipv6_rules

        with open ("{}/firewall_temp.json".format(HOMEDIR), "w") as firedump:
                json.dump(self.firewall_dict, firedump)

        for option in self.options:
            if getattr(self, "{}_check".format(option)).checkState() == 2:
                self.config_dict[option] = 1
            else:
                self.config_dict[option] = 0

        self.hide()
        self.fw_change.emit(self.config_dict)

    def cancel(self):
        self.hide()


class AppSelector(QtWidgets.QDialog):
    app_chosen = QtCore.pyqtSignal(tuple)

    def __init__ (self, parent=None):
        super(AppSelector, self).__init__(parent)
        self.setupUi(self)
        self.get_desktop_files()

    def setupUi(self, Form):
        Form.setObjectName(_fromUtf8("Form"))
        Form.resize(600, 700)
        self.verticalLayout = QtWidgets.QVBoxLayout(Form)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.installedLabel = QtWidgets.QLabel(Form)
        self.verticalLayout.addWidget(self.installedLabel)
        self.appListWidget = QtWidgets.QListWidget(Form)
        self.verticalLayout.addWidget(self.appListWidget)
        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        Form.setWindowTitle(_translate("Form", "Choose an application", None))
        self.installedLabel.setText(_translate("Form",
                                               "Applications installed on your system:",
                                               None
                                               ))

    def get_desktop_files(self):
        self.bypassAppList = []
        directories = ["{}/.local/share/applications".format(os.path.expanduser("~")),
                       "/usr/share/applications",
                       "/usr/local/share/applications"
                       ]

        for d in directories:
            try:
                for f in os.listdir(d):
                    if f.endswith(".desktop"):
                        desktop_file = os.path.join(d, f)
                        c = configparser.ConfigParser()
                        c.read(desktop_file)

                        try:

                            if c["Desktop Entry"]["NoDisplay"] == "true":
                                pass

                            else:
                                name = c["Desktop Entry"]["Name"]
                                icon = c["Desktop Entry"]["Icon"]
                                logging.debug("Adding {} to bypass app list".format(name))
                                self.bypassAppList.append((name, icon, desktop_file))

                        except KeyError:
                            name = c["Desktop Entry"]["Name"]
                            icon = c["Desktop Entry"]["Icon"]
                            logging.debug("Adding {} to bypass app list".format(name))
                            self.bypassAppList.append((name, icon, desktop_file))
            except Exception as e:
                logging.error(e)
                logging.error("Failed to add {} to bypass app list".format(name))

        self.bypassAppList = sorted(self.bypassAppList)
        self.pop_AppList()

    def pop_AppList(self):
        self.appListWidget.clear()
        for entry in self.bypassAppList:
            item = QtWidgets.QListWidgetItem()
            self.appListWidget.addItem(item)
            item.setText(entry[0])
            item.setIcon(QtGui.QIcon.fromTheme(entry[1]))
        self.appListWidget.itemClicked.connect(self.chosen)

    def chosen(self):
        self.app_chosen.emit(self.bypassAppList[self.appListWidget.currentRow()])
        self.hide()

class ModifyServer(QtWidgets.QDialog):
    modified = QtCore.pyqtSignal(dict)

    def __init__ (self, key=None, server_info=None, parent=None):
        super(ModifyServer, self).__init__(parent)
        self.key = key
        self.server_info = server_info
        self.config_change = 0
        self.provider = self.server_info["provider"]
        self.setupUi(self)
        self.load_config_file()

    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(419, 480)
        self.verticalLayout = QtWidgets.QVBoxLayout(Dialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.nameLabel = QtWidgets.QLabel(Dialog)
        bold_font = QtGui.QFont()
        bold_font.setBold(True)
        bold_font.setWeight(75)
        self.nameLabel.setFont(bold_font)
        self.nameLabel.setObjectName("nameLabel")
        self.verticalLayout.addWidget(self.nameLabel)
        self.nameEdit = QtWidgets.QLineEdit(Dialog)
        self.nameEdit.setObjectName("nameEdit")
        self.verticalLayout.addWidget(self.nameEdit)
        self.iconLabel = QtWidgets.QLabel(Dialog)
        bold_font = QtGui.QFont()
        bold_font.setBold(True)
        bold_font.setWeight(75)
        self.iconLabel.setFont(bold_font)
        self.iconLabel.setObjectName("iconLabel")
        self.verticalLayout.addWidget(self.iconLabel)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.countryEdit = QtWidgets.QLineEdit(Dialog)
        self.countryEdit.setObjectName("countryEdit")
        self.horizontalLayout.addWidget(self.countryEdit)
        self.countryHintLabel = QtWidgets.QLabel(Dialog)
        self.countryHintLabel.setObjectName("countryHintLabel")
        self.horizontalLayout.addWidget(self.countryHintLabel)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.line = QtWidgets.QFrame(Dialog)
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.verticalLayout.addWidget(self.line)
        self.configLabel = QtWidgets.QLabel(Dialog)
        bold_font = QtGui.QFont()
        bold_font.setBold(True)
        bold_font.setWeight(75)
        self.configLabel.setFont(bold_font)
        self.configLabel.setObjectName("configLabel")
        self.verticalLayout.addWidget(self.configLabel)
        self.changeAllBox = QtWidgets.QCheckBox(Dialog)
        self.changeAllBox.setCheckable(True)
        self.changeAllBox.setChecked(True)
        self.changeAllBox.setObjectName("changeAllBox")
        self.verticalLayout.addWidget(self.changeAllBox)
        self.configBrowser = QtWidgets.QTextEdit(Dialog)
        self.configBrowser.setObjectName("configBrowser")
        self.verticalLayout.addWidget(self.configBrowser)
        self.buttonBox = QtWidgets.QDialogButtonBox(Dialog)
        self.buttonBox.setOrientation(QtCore.Qt.Horizontal)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.verticalLayout.addWidget(self.buttonBox)
        self.retranslateUi(Dialog)
        self.changeAllBox.toggled.connect(self.block_option)
        self.buttonBox.accepted.connect(self.accept_change)
        self.buttonBox.rejected.connect(self.reject_change)
        self.configBrowser.textChanged.connect(self.config_changed)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Edit server"))
        self.nameLabel.setText(_translate("Dialog", "Name:"))
        self.nameEdit.setText(self.server_info["name"])
        self.iconLabel.setText(_translate("Dialog", "Country:"))
        self.countryHintLabel.setText(_translate("Dialog", "Preferably use country codes\n"
                                                 "Example: US for United States"))
        self.countryEdit.setText(self.server_info["country"])
        self.configLabel.setText(_translate("Dialog", "Edit Configuration File:"))
        self.changeAllBox.setText(_translate("Dialog",
                                             "Apply changes to all configuration files of {}".format(self.provider)))

    def block_option(self, state):
        if self.provider in SUPPORTED_PROVIDERS and state is False:
            self.changeAllBox.setChecked(True)

    def load_config_file(self):
        try:
            if self.server_info["tunnel"] == "WireGuard":
                self.configBrowser.setVisible(False)
                self.configLabel.setVisible(False)
                self.changeAllBox.setVisible(False)
                self.resize(419, 150)

            else:
                self.display_config()

        except KeyError:
            self.display_config()

    def display_config(self):
        if self.provider in SUPPORTED_PROVIDERS:
            config = "{}/{}/openvpn.conf".format(ROOTDIR, self.provider)

        else:
            config = "{}/{}".format(ROOTDIR, self.server_info["path"])

        splt = os.path.splitext(config)
        mod = "{}_MOD.{}".format(splt[0], splt[1])
        if os.path.exists(mod):
            config = mod

        with open (config, "r") as config_edit:
            self.old_config = config_edit.readlines()
            for line in self.old_config:
                self.configBrowser.append(line.split("\n")[0])

    def config_changed(self):
        self.config_change = 1

    def reject_change(self):
        self.hide()

    def accept_change(self):
        change_all = 0
        self.server_info["name"] = self.nameEdit.text()
        country_change = self.countryEdit.text()

        if len(country_change) == 2:
            country = update.country_translate(country_change)
            if country == "Unknown":
                country = country_change

        else:
            country = country_change

        self.server_info["country"] = country

        if self.config_change == 1:
            new_config = []
            remote_index = 0
            new_config = self.configBrowser.toPlainText().split("\n")
            for index, line in enumerate(new_config):

                if line.startswith("remote "):
                    remote_index = index

                line_format = "{}\n".format(line)
                new_config[index] = line_format
            if new_config != self.old_config:

                if self.provider in SUPPORTED_PROVIDERS:
                    temp_file = "{}_config".format(self.provider)

                else:
                    temp_file = self.server_info["path"].split("/")[1]

                temp_folder = "{}/temp".format(HOMEDIR)

                if not os.path.exists(temp_folder):
                    os.makedirs(temp_folder)

                with open("{}/{}".format(temp_folder, temp_file), "w") as update_config:
                    update_config.writelines(new_config)

        else:
            remote_index = 0
            new_config = []

        if self.changeAllBox.isChecked() == True:
            change_all = 1

        change_dict = {"info_update" : self.server_info, "key" : self.key,
                       "config_change" : new_config,
                       "index" : remote_index, "apply_all" : change_all
                       }

        self.modified.emit(change_dict)
        self.hide()

