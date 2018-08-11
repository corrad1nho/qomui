#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import math
import json
import re
import dbus
import shutil
import time
import random
import logging
from PyQt5 import QtCore, QtGui, Qt, QtWidgets
from dbus.mainloop.pyqt5 import DBusQtMainLoop
from subprocess import CalledProcessError, check_call, check_output, Popen
import psutil
import shlex
import glob
import configparser
import requests
import bisect
import signal

from qomui import update, latency, utils


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

class DbusLogHandler(logging.Handler):
    def __init__(self, qomui_service, parent = None):
        super(DbusLogHandler, self).__init__()
        self.qomui_service = qomui_service

    def emit(self, record):
        try:
            msg = json.dumps(dict(record.__dict__))
            self.qomui_service.share_log(msg)
        except (dbus.exceptions.DBusException, TypeError):
            pass

if __debug__:
    ROOTDIR = "%s/resources" %(os.getcwd())
else:
    ROOTDIR = "/usr/share/qomui"

HOMEDIR = "%s/.qomui" % (os.path.expanduser("~"))
SUPPORTED_PROVIDERS = ["Airvpn", "Mullvad", "ProtonVPN", "PIA", "Windscribe"]
JSON_FILE_LIST = [("config_dict", "%s/config.json" %ROOTDIR),
                  ("server_dict", "%s/server.json" %HOMEDIR), 
                  ("protocol_dict", "%s/protocol.json" %HOMEDIR), 
                  ("bypass_dict", "%s/bypass_apps.json" %HOMEDIR)
                  ]


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

class QomuiGui(QtWidgets.QWidget):
    status = "inactive"
    server_dict = {}
    protocol_dict = {}
    country_list = ["All countries"]
    provider_list = ["All providers"]
    firewall_rules_changed = False
    hop_active = 0
    hop_log_monitor = 0
    tun_hop = None
    hop_server_dict = None
    bypass_dict = {}
    config_dict = {}
    packetmanager = None
    tunnel_list = ["OpenVPN", "WireGuard"]
    config_list = [
                   "firewall",
                   "autoconnect",
                   "minimize",
                   "ipv6_disable",
                   "alt_dns",
                   "bypass",
                   "ping",
                   "simpletray"
                   ]

    def __init__(self, parent = None):
        super(QomuiGui, self).__init__(parent)
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.DEBUG)
        self.setWindowIcon(QtGui.QIcon.fromTheme("qomui"))
        self.setWindowState(QtCore.Qt.WindowMinimized)
        self.setupUi(self)
        self.dbus = dbus.SystemBus()

        try:
            self.qomui_dbus = self.dbus.get_object('org.qomui.service', '/org/qomui/service')
            self.logger.debug('Successfully connected to DBUS system service')
        except dbus.exceptions.DBusException:
            self.logger.error('DBus Error: Qomui-Service is currently not available')

            ret = self.messageBox("Error: Qomui-service is not active",
                                  "Do you want to start it, enable it permanently or close Qomui?",
                                  buttons = ["Enable", "Start", "Close"],
                                  icon = "Question"
                                  )

            if ret == 0:
                try:
                    check_call(["pkexec", "systemctl", "enable", "--now", "qomui"])
                    self.qomui_dbus = self.dbus.get_object('org.qomui.service', 
                                                           '/org/qomui/service'
                                                           )
                except CalledProcessError:
                    QtWidgets.QMessageBox.critical(self,
                                                    "Error",
                                                    "Failed to start Qomui service",
                                                    QtWidgets.QMessageBox.Ok)
                    sys.exit(1)

            elif ret == 1:
                try:
                    check_call(["pkexec", "systemctl", "start", "qomui.service"])
                    self.qomui_dbus = self.dbus.get_object('org.qomui.service', '/org/qomui/service')
                except CalledProcessError:
                    QtWidgets.QMessageBox.critical(self,
                                                    "Error",
                                                    "Failed to start Qomui service",
                                                    QtWidgets.QMessageBox.Ok)
                    sys.exit(1)

            elif ret == 2:
                sys.exit(1)

        self.qomui_service = dbus.Interface(self.qomui_dbus, 'org.qomui.service')
        self.qomui_service.connect_to_signal("send_log", self.receive_log)
        self.qomui_service.connect_to_signal("reply", self.openvpn_log_monitor)
        self.qomui_service.connect_to_signal("updated", self.restart)
        nm = self.dbus.get_object('org.freedesktop.NetworkManager', '/org/freedesktop/NetworkManager')
        nm_iface = dbus.Interface(nm, 'org.freedesktop.NetworkManager')
        nm_iface.connect_to_signal("StateChanged", self.networkstate)

        handler = DbusLogHandler(self.qomui_service)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)
        primay_screen = QtWidgets.QDesktopWidget().primaryScreen()
        primary_screen_geometry = QtWidgets.QDesktopWidget().availableGeometry(primay_screen)
        positioning = primary_screen_geometry.bottomRight()
        self.setGeometry(QtCore.QRect(positioning.x()-600, positioning.y()-750,
                                      600, 750
                                      ))
        self.qomui_service.disconnect()
        self.qomui_service.save_default_dns()
        self.load_saved_files()
        self.systemtray()

    def receive_log(self, msg):
        self.logText.appendPlainText(msg)

    def setupUi(self, Form):
        Form.setObjectName(_fromUtf8("Form"))
        self.gridLayout = QtWidgets.QGridLayout(Form)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.ActiveWidget = ActiveWidget(Form)
        self.gridLayout.addWidget(self.ActiveWidget, 0, 0, 1, 2)
        self.ActiveWidget.setVisible(False)
        self.WaitBar = WaitBarWidget(Form)
        self.gridLayout.addWidget(self.WaitBar, 1, 0, 1, 2)
        self.WaitBar.setVisible(False)
        self.verticalLayout_3 = QtWidgets.QVBoxLayout()
        self.verticalLayout_3.setObjectName(_fromUtf8("verticalLayout_3"))
        self.tabButtonGroup = QtWidgets.QButtonGroup(Form)
        self.tabButtonGroup.setExclusive(True)
        self.serverTabBt = QtWidgets.QCommandLinkButton(Form)
        self.serverTabBt.setMinimumSize(QtCore.QSize(100, 0))
        self.serverTabBt.setMaximumSize(QtCore.QSize(100, 100))
        self.serverTabBt.setCheckable(True)
        self.tabButtonGroup.addButton(self.serverTabBt)
        self.serverTabBt.setObjectName(_fromUtf8("serverTabBt"))
        self.verticalLayout_3.addWidget(self.serverTabBt)
        self.providerTabBt = QtWidgets.QCommandLinkButton(Form)
        self.providerTabBt.setMinimumSize(QtCore.QSize(100, 0))
        self.providerTabBt.setMaximumSize(QtCore.QSize(100, 100))
        self.providerTabBt.setCheckable(True)
        self.tabButtonGroup.addButton(self.providerTabBt)
        self.providerTabBt.setObjectName(_fromUtf8("providerTabBt"))
        self.verticalLayout_3.addWidget(self.providerTabBt)
        self.optionsTabBt = QtWidgets.QCommandLinkButton(Form)
        self.optionsTabBt.setMinimumSize(QtCore.QSize(100, 0))
        self.optionsTabBt.setMaximumSize(QtCore.QSize(100, 100))
        self.optionsTabBt.setCheckable(True)
        self.tabButtonGroup.addButton(self.optionsTabBt)
        self.optionsTabBt.setObjectName(_fromUtf8("optionsTabBt"))
        self.verticalLayout_3.addWidget(self.optionsTabBt)
        self.logTabBt = QtWidgets.QCommandLinkButton(Form)
        self.logTabBt.setMinimumSize(QtCore.QSize(100, 0))
        self.logTabBt.setMaximumSize(QtCore.QSize(100, 100))
        self.logTabBt.setCheckable(True)
        self.tabButtonGroup.addButton(self.logTabBt)
        self.logTabBt.setObjectName(_fromUtf8("logTabBt"))
        self.verticalLayout_3.addWidget(self.logTabBt)
        self.bypassTabBt = QtWidgets.QCommandLinkButton(Form)
        self.bypassTabBt.setVisible(False)
        self.bypassTabBt.setMinimumSize(QtCore.QSize(100, 0))
        self.bypassTabBt.setMaximumSize(QtCore.QSize(100, 100))
        self.bypassTabBt.setCheckable(True)
        self.tabButtonGroup.addButton(self.bypassTabBt)
        self.bypassTabBt.setObjectName(_fromUtf8("bypassTabBt"))
        self.verticalLayout_3.addWidget(self.bypassTabBt)
        self.aboutTabBt = QtWidgets.QCommandLinkButton(Form)
        self.aboutTabBt.setMinimumSize(QtCore.QSize(100, 0))
        self.aboutTabBt.setMaximumSize(QtCore.QSize(100, 100))
        self.aboutTabBt.setCheckable(True)
        self.tabButtonGroup.addButton(self.aboutTabBt)
        self.aboutTabBt.setObjectName(_fromUtf8("aboutTabBt"))
        self.verticalLayout_3.addWidget(self.aboutTabBt)
        spacerItem = QtWidgets.QSpacerItem(20, 40, 
                                           QtWidgets.QSizePolicy.Minimum, 
                                           QtWidgets.QSizePolicy.Expanding
                                           )
        self.verticalLayout_3.addItem(spacerItem)
        self.gridLayout.addLayout(self.verticalLayout_3, 2, 0, 1, 1)
        self.tabWidget = QtWidgets.QStackedWidget(Form)
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))
        self.serverTab = QtWidgets.QWidget()
        self.serverTab.setObjectName(_fromUtf8("serverTab"))
        self.verticalLayout = QtWidgets.QVBoxLayout(self.serverTab)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
        self.countryBox = QtWidgets.QComboBox(self.serverTab)
        self.countryBox.setObjectName(_fromUtf8("countryBox"))
        self.horizontalLayout_3.addWidget(self.countryBox)
        self.providerBox = QtWidgets.QComboBox(self.serverTab)
        self.providerBox.setObjectName(_fromUtf8("providerBox"))
        self.horizontalLayout_3.addWidget(self.providerBox)
        self.tunnelBox = QtWidgets.QComboBox(self.serverTab)
        self.tunnelBox.setObjectName(_fromUtf8("tunnelBox"))
        self.tunnelBox.setVisible(False)
        self.horizontalLayout_3.addWidget(self.tunnelBox)
        self.favouriteButton = favouriteButton(self.serverTab)
        self.favouriteButton.setCheckable(True)
        self.favouriteButton.setMinimumSize(QtCore.QSize(25, 25))
        self.favouriteButton.setMaximumSize(QtCore.QSize(25, 25))
        self.favouriteButton.setObjectName(_fromUtf8("favouriteButton"))
        self.horizontalLayout_3.addWidget(self.favouriteButton)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        self.serverListWidget = QtWidgets.QListWidget(self.serverTab)
        self.serverListWidget.setObjectName(_fromUtf8("serverListWidget"))
        self.serverListWidget.setBatchSize(10)
        self.serverListWidget.setUniformItemSizes(True)
        self.verticalLayout.addWidget(self.serverListWidget)
        self.serverHopWidget = HopWidget(self.serverTab)
        self.serverHopWidget.setVisible(False)
        self.verticalLayout.addWidget(self.serverHopWidget)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, 
                                            QtWidgets.QSizePolicy.Expanding, 
                                            QtWidgets.QSizePolicy.Minimum
                                            )
        self.horizontalLayout.addItem(spacerItem1)
        self.randomSeverBt = QtWidgets.QPushButton(self.serverTab)
        self.randomSeverBt.setObjectName(_fromUtf8("randomSeverBt"))
        self.randomSeverBt.setVisible(False)
        self.horizontalLayout.addWidget(self.randomSeverBt)
        self.addServerBt = QtWidgets.QPushButton(self.serverTab)
        self.addServerBt.setObjectName(_fromUtf8("addServerBt"))
        self.horizontalLayout.addWidget(self.addServerBt)
        self.modify_serverBt = QtWidgets.QPushButton(self.serverTab)
        self.modify_serverBt.setObjectName(_fromUtf8("modify_serverBt"))
        self.horizontalLayout.addWidget(self.modify_serverBt)
        self.delServerBt = QtWidgets.QPushButton(self.serverTab)
        self.delServerBt.setObjectName(_fromUtf8("delServerBt"))
        self.horizontalLayout.addWidget(self.delServerBt)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.tabWidget.addWidget(self.serverTab)
        self.logTab = QtWidgets.QWidget()
        self.logTab.setObjectName(_fromUtf8("logTab"))
        self.gridLayout_2 = QtWidgets.QGridLayout(self.logTab)
        self.gridLayout_2.setObjectName(_fromUtf8("gridLayout_2"))
        self.logText = QtWidgets.QPlainTextEdit(self.logTab)
        self.logText.setReadOnly(True)
        self.gridLayout_2.addWidget(self.logText, 2, 0, 1, 1)
        self.tabWidget.addWidget(self.logTab)
        self.optionsTab = QtWidgets.QWidget()
        self.optionsTab.setObjectName(_fromUtf8("optionsTab"))
        self.tabWidget.addWidget(self.optionsTab)
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.optionsTab)
        self.verticalLayout_5.setObjectName(_fromUtf8("verticalLayout_5"))
        bold_font = QtGui.QFont()
        bold_font.setBold(True)
        bold_font.setWeight(75)
        bold_font.setKerning(False)
        italic_font = QtGui.QFont()
        italic_font.setItalic(True)
        self.autoconnectOptCheck = QtWidgets.QCheckBox(self.optionsTab)
        self.autoconnectOptCheck.setObjectName(_fromUtf8("autoconnectOptCheck"))
        self.autoconnectOptCheck.setFont(bold_font)
        self.verticalLayout_5.addWidget(self.autoconnectOptCheck)
        self.autoconnectOptLabel = QtWidgets.QLabel(self.optionsTab)
        self.autoconnectOptLabel.setObjectName(_fromUtf8("autoconnectOptLabel"))
        self.autoconnectOptLabel.setWordWrap(True)
        self.autoconnectOptLabel.setIndent(20)
        self.autoconnectOptLabel.setFont(italic_font)
        self.verticalLayout_5.addWidget(self.autoconnectOptLabel)
        self.minimizeOptCheck = QtWidgets.QCheckBox(self.optionsTab)
        self.minimizeOptCheck.setFont(bold_font)
        self.minimizeOptCheck.setObjectName(_fromUtf8("minimizeOptCheck"))
        self.verticalLayout_5.addWidget(self.minimizeOptCheck)
        self.minimizeOptLabel = QtWidgets.QLabel(self.optionsTab)
        self.minimizeOptLabel.setObjectName(_fromUtf8("minimizeOptLabel"))
        self.minimizeOptLabel.setWordWrap(True)
        self.minimizeOptLabel.setIndent(20)
        self.minimizeOptLabel.setFont(italic_font)
        self.verticalLayout_5.addWidget(self.minimizeOptLabel)
        self.simpletrayOptCheck = QtWidgets.QCheckBox(self.optionsTab)
        self.simpletrayOptCheck.setObjectName(_fromUtf8("simpletrayOptCheck"))
        self.simpletrayOptCheck.setFont(bold_font)
        self.verticalLayout_5.addWidget(self.simpletrayOptCheck)
        self.simpletrayOptLabel = QtWidgets.QLabel(self.optionsTab)
        self.simpletrayOptLabel.setObjectName(_fromUtf8("simpletrayOptLabel"))
        self.simpletrayOptLabel.setWordWrap(True)
        self.simpletrayOptLabel.setIndent(20)
        self.simpletrayOptLabel.setFont(italic_font)
        self.verticalLayout_5.addWidget(self.simpletrayOptLabel)
        self.pingOptCheck = QtWidgets.QCheckBox(self.optionsTab)
        self.pingOptCheck.setFont(bold_font)
        self.pingOptCheck.setObjectName(_fromUtf8("pingOptCheck"))
        self.verticalLayout_5.addWidget(self.pingOptCheck)
        self.pingOptLabel = QtWidgets.QLabel(self.optionsTab)
        self.pingOptLabel.setObjectName(_fromUtf8("pingOptLabel"))
        self.pingOptLabel.setWordWrap(True)
        self.pingOptLabel.setIndent(20)
        self.pingOptLabel.setFont(italic_font)
        self.verticalLayout_5.addWidget(self.pingOptLabel)
        self.ipv6_disableOptCheck = QtWidgets.QCheckBox(self.optionsTab)
        self.ipv6_disableOptCheck.setFont(bold_font)
        self.ipv6_disableOptCheck.setObjectName(_fromUtf8("ipv6_disableOptCheck"))
        self.verticalLayout_5.addWidget(self.ipv6_disableOptCheck)
        self.ipv6_disableOptLabel = QtWidgets.QLabel(self.optionsTab)
        self.ipv6_disableOptLabel.setObjectName(_fromUtf8("ipv6_disableOptLabel"))
        self.ipv6_disableOptLabel.setWordWrap(True)
        self.ipv6_disableOptLabel.setIndent(20)
        self.ipv6_disableOptLabel.setFont(italic_font)
        self.verticalLayout_5.addWidget(self.ipv6_disableOptLabel)
        self.bypassOptCheck = QtWidgets.QCheckBox(self.optionsTab)
        self.bypassOptCheck.setFont(bold_font)
        self.bypassOptCheck.setObjectName(_fromUtf8("bypassOptCheck"))
        self.verticalLayout_5.addWidget(self.bypassOptCheck)
        self.bypassOptLabel = QtWidgets.QLabel(self.optionsTab)
        self.bypassOptLabel.setObjectName(_fromUtf8("bypassOptLabel"))
        self.bypassOptLabel.setWordWrap(True)
        self.bypassOptLabel.setIndent(20)
        self.bypassOptLabel.setFont(italic_font)
        self.verticalLayout_5.addWidget(self.bypassOptLabel)
        self.horizontalLayout_9 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_9.setObjectName(_fromUtf8("horizontalLayout_9"))
        self.firewallOptCheck = QtWidgets.QCheckBox(self.optionsTab)
        self.firewallOptCheck.setFont(bold_font)
        self.firewallOptCheck.setObjectName(_fromUtf8("firewallOptCheck"))
        self.horizontalLayout_9.addWidget(self.firewallOptCheck)
        self.firewallEditBt = QtWidgets.QPushButton(self.optionsTab)
        self.firewallEditBt.setObjectName(_fromUtf8("firewallEditBt"))
        self.horizontalLayout_9.addWidget(self.firewallEditBt)
        spacerItem9 = QtWidgets.QSpacerItem(40, 20, 
                                            QtWidgets.QSizePolicy.Expanding, 
                                            QtWidgets.QSizePolicy.Minimum
                                            )
        self.horizontalLayout_9.addItem(spacerItem9)
        self.horizontalLayout_9.setObjectName(_fromUtf8("horizontalLayout_9"))
        self.verticalLayout_5.addLayout(self.horizontalLayout_9)
        self.firewallOptLabel = QtWidgets.QLabel(self.optionsTab)
        self.firewallOptLabel.setObjectName(_fromUtf8("firewallOptLabel"))
        self.firewallOptLabel.setWordWrap(True)
        self.firewallOptLabel.setIndent(20)
        self.firewallOptLabel.setFont(italic_font)
        self.verticalLayout_5.addWidget(self.firewallOptLabel)
        self.alt_dnsOptLabel = QtWidgets.QLabel(self.optionsTab)
        bold_font = QtGui.QFont()
        bold_font.setBold(True)
        bold_font.setWeight(75)
        bold_font.setKerning(False)
        self.alt_dnsOptLabel.setFont(bold_font)
        self.alt_dnsOptLabel.setObjectName(_fromUtf8("alt_dnsOptLabel"))
        self.verticalLayout_5.addWidget(self.alt_dnsOptLabel)
        self.alt_dnsOptCheck = QtWidgets.QCheckBox(self.optionsTab)
        self.alt_dnsOptCheck.setFont(bold_font)
        self.alt_dnsOptCheck.setObjectName(_fromUtf8("alt_dnsOptCheck"))
        self.verticalLayout_5.addWidget(self.alt_dnsOptCheck)
        self.horizontalLayout_20 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_20.setObjectName(_fromUtf8("horizontalLayout_20"))
        self.altDnsEdit1 = QtWidgets.QLineEdit(self.optionsTab)
        self.altDnsEdit1.setObjectName(_fromUtf8("altDnsEdit1"))
        self.horizontalLayout_20.addWidget(self.altDnsEdit1)
        self.altDnsEdit2 = QtWidgets.QLineEdit(self.optionsTab)
        self.altDnsEdit2.setObjectName(_fromUtf8("altDnsEdit2"))
        self.horizontalLayout_20.addWidget(self.altDnsEdit2)
        self.verticalLayout_5.addLayout(self.horizontalLayout_20)
        self.dnsInfoLabel = QtWidgets.QLabel(self.optionsTab)
        self.dnsInfoLabel.setObjectName(_fromUtf8("dnsInfoLabel"))
        self.dnsInfoLabel.setWordWrap(True)
        self.dnsInfoLabel.setFont(italic_font)
        self.verticalLayout_5.addWidget(self.dnsInfoLabel)
        spacerItem8 = QtWidgets.QSpacerItem(20, 40, 
                                            QtWidgets.QSizePolicy.Minimum, 
                                            QtWidgets.QSizePolicy.Expanding
                                            )
        self.verticalLayout_5.addItem(spacerItem8)
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setObjectName(_fromUtf8("horizontalLayout_6"))
        spacerItem4 = QtWidgets.QSpacerItem(40, 20, 
                                            QtWidgets.QSizePolicy.Expanding, 
                                            QtWidgets.QSizePolicy.Minimum
                                            )
        self.horizontalLayout_6.addItem(spacerItem4)
        self.restoreDefaultOptBt = QtWidgets.QPushButton(self.optionsTab)
        self.restoreDefaultOptBt.setObjectName(_fromUtf8("restoreDefaultOptBt"))
        self.horizontalLayout_6.addWidget(self.restoreDefaultOptBt)
        self.applyOptBt = QtWidgets.QPushButton(self.optionsTab)
        self.applyOptBt.setObjectName(_fromUtf8("applyOptBt"))
        self.horizontalLayout_6.addWidget(self.applyOptBt)
        self.cancelOptBt = QtWidgets.QPushButton(self.optionsTab)
        self.cancelOptBt.setObjectName(_fromUtf8("cancelOptBt"))
        self.horizontalLayout_6.addWidget(self.cancelOptBt)
        self.verticalLayout_5.addLayout(self.horizontalLayout_6)
        self.providerTab = QtWidgets.QWidget()
        self.providerTab.setObjectName(_fromUtf8("providerTab"))
        self.verticalLayout_30 = QtWidgets.QVBoxLayout(self.providerTab)
        self.verticalLayout_30.setObjectName("verticalLayout_30")
        bold_font = QtGui.QFont()
        bold_font.setBold(True)
        bold_font.setWeight(75)
        self.addProviderLabel = QtWidgets.QLabel(self.providerTab)
        self.addProviderLabel.setFont(bold_font)
        self.addProviderLabel.setObjectName("addProviderLabel")
        self.verticalLayout_30.addWidget(self.addProviderLabel)
        self.addProviderBox = QtWidgets.QComboBox(self.providerTab)
        self.addProviderBox.setObjectName(_fromUtf8("addProviderBox"))
        self.verticalLayout_30.addWidget(self.addProviderBox)
        self.addProviderEdit = QtWidgets.QLineEdit(self.providerTab)
        self.addProviderEdit.setObjectName(_fromUtf8("addProviderEdit"))
        self.addProviderEdit.setVisible(False)
        self.verticalLayout_30.addWidget(self.addProviderEdit)
        self.gridLayout_3 = QtWidgets.QGridLayout(self.providerTab)
        self.gridLayout_3.setObjectName(_fromUtf8("gridLayout_3"))
        self.addProviderUserEdit = QtWidgets.QLineEdit(self.providerTab)
        self.addProviderUserEdit.setObjectName(_fromUtf8("addProviderUserEdit"))
        self.gridLayout_3.addWidget(self.addProviderUserEdit, 0, 0, 1, 2)
        self.addProviderDownloadBt = QtWidgets.QPushButton(self.providerTab)
        self.addProviderDownloadBt.setObjectName(_fromUtf8("addProviderDownloadBt"))
        self.gridLayout_3.addWidget(self.addProviderDownloadBt, 0, 2, 1, 1)
        self.addProviderPassEdit = QtWidgets.QLineEdit(self.providerTab)
        self.addProviderPassEdit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.addProviderPassEdit.setObjectName(_fromUtf8("addProviderPassEdit"))
        self.gridLayout_3.addWidget(self.addProviderPassEdit, 1, 0, 1, 2)
        self.verticalLayout_30.addLayout(self.gridLayout_3)
        self.delProviderLabel = QtWidgets.QLabel(self.providerTab)
        self.delProviderLabel.setFont(bold_font)
        self.delProviderLabel.setObjectName("delProviderLabel")
        self.verticalLayout_30.addWidget(self.delProviderLabel)
        self.horizontalLayout_32 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_32.setObjectName("horizontalLayout_32")
        self.delProviderBox = QtWidgets.QComboBox(self.providerTab)
        self.delProviderBox.setObjectName("delProviderBox")
        self.horizontalLayout_32.addWidget(self.delProviderBox)
        self.delProviderBt = QtWidgets.QPushButton(self.providerTab)
        self.delProviderBt.setObjectName("delProviderBt")
        self.horizontalLayout_32.addWidget(self.delProviderBt)
        spacerItem10 = QtWidgets.QSpacerItem(40, 20, 
                                             QtWidgets.QSizePolicy.Expanding, 
                                             QtWidgets.QSizePolicy.Minimum
                                             )
        self.horizontalLayout_32.addItem(spacerItem10)
        self.verticalLayout_30.addLayout(self.horizontalLayout_32)
        self.protocolLabel = QtWidgets.QLabel(self.providerTab)
        self.protocolLabel.setFont(bold_font)
        self.protocolLabel.setObjectName("protocolLabel")
        self.verticalLayout_30.addWidget(self.protocolLabel)
        self.providerProtocolBox = QtWidgets.QComboBox(self.providerTab)
        self.providerProtocolBox.setObjectName("providerProtocolBox")
        self.verticalLayout_30.addWidget(self.providerProtocolBox)
        self.protocolListWidget = QtWidgets.QListWidget(self.providerTab)
        self.protocolListWidget.setObjectName("protocolListWidget")
        self.verticalLayout_30.addWidget(self.protocolListWidget)
        self.overrorMsgideCheck = QtWidgets.QCheckBox(self.providerTab)
        self.overrorMsgideCheck.setObjectName("overrorMsgideCheck")
        self.overrorMsgideCheck.setVisible(False)
        self.verticalLayout_30.addWidget(self.overrorMsgideCheck)
        self.horizontalLayout_31 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_31.setObjectName("horizontalLayout_31")
        self.chooseProtocolBox = QtWidgets.QComboBox(self.providerTab)
        self.chooseProtocolBox.setObjectName("chooseProtocolBox")
        self.chooseProtocolBox.addItem("UDP")
        self.chooseProtocolBox.addItem("TCP")
        self.chooseProtocolBox.setVisible(False)
        self.horizontalLayout_31.addWidget(self.chooseProtocolBox)
        self.portOverrideLabel = QtWidgets.QLabel(self.providerTab)
        self.portOverrideLabel.setObjectName("portOverrideLabel")
        self.portOverrideLabel.setVisible(False)
        self.horizontalLayout_31.addWidget(self.portOverrideLabel)
        self.portEdit = QtWidgets.QLineEdit(self.providerTab)
        self.portEdit.setObjectName("portEdit")
        self.portEdit.setVisible(False)
        self.horizontalLayout_31.addWidget(self.portEdit)
        self.verticalLayout_30.addLayout(self.horizontalLayout_31)
        self.savePortButton = QtWidgets.QPushButton(self.providerTab)
        self.savePortButton.setObjectName("savePortButton")
        self.savePortButton.setVisible(False)
        self.horizontalLayout_31.addWidget(self.savePortButton)
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, 
                                            QtWidgets.QSizePolicy.Expanding, 
                                            QtWidgets.QSizePolicy.Minimum
                                            )
        self.horizontalLayout_31.addItem(spacerItem1)
        spacerItem = QtWidgets.QSpacerItem(20, 40, 
                                           QtWidgets.QSizePolicy.Minimum, 
                                           QtWidgets.QSizePolicy.Expanding
                                           )
        self.verticalLayout_30.addItem(spacerItem)
        self.tabWidget.addWidget(self.providerTab)
        self.bypassTab = QtWidgets.QWidget()
        self.bypassTab.setObjectName(_fromUtf8("bypassTab"))
        self.verticalLayout_8 = QtWidgets.QVBoxLayout(self.bypassTab)
        self.verticalLayout_8.setObjectName(_fromUtf8("verticalLayout_8"))
        self.bypassInfoLabel = QtWidgets.QLabel(self.optionsTab)
        self.bypassInfoLabel.setObjectName(_fromUtf8("bypassOptCheck"))
        self.bypassInfoLabel.setWordWrap(True)
        self.bypassInfoLabel.setFont(italic_font)
        self.verticalLayout_8.addWidget(self.bypassInfoLabel)
        self.bypassAppList = QtWidgets.QListWidget(self.bypassTab)
        self.bypassAppList.setObjectName(_fromUtf8("bypassAppList"))
        self.bypassAppList.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.verticalLayout_8.addWidget(self.bypassAppList)
        self.horizontalLayout_10= QtWidgets.QHBoxLayout()
        self.horizontalLayout_10.setObjectName(_fromUtf8("horizontalLayout_10"))
        spacerItem3 = QtWidgets.QSpacerItem(40, 20,
                                            QtWidgets.QSizePolicy.Expanding, 
                                            QtWidgets.QSizePolicy.Minimum
                                            )
        self.horizontalLayout_10.addItem(spacerItem3)
        self.addBypassAppBt = QtWidgets.QPushButton(self.bypassTab)
        self.addBypassAppBt.setObjectName(_fromUtf8("addBypassAppBt"))
        self.horizontalLayout_10.addWidget(self.addBypassAppBt)
        self.delBypassAppBt = QtWidgets.QPushButton(self.bypassTab)
        self.delBypassAppBt.setObjectName(_fromUtf8("delBypassAppBt"))
        self.horizontalLayout_10.addWidget(self.delBypassAppBt)
        self.verticalLayout_8.addLayout(self.horizontalLayout_10)
        self.tabWidget.addWidget(self.bypassTab)

        self.aboutTab = QtWidgets.QWidget()
        self.aboutTab.setObjectName(_fromUtf8("aboutTab"))
        self.tabWidget.addWidget(self.aboutTab)

        self.aboutTab.setObjectName("self.aboutTab")
        self.aboutTab.setObjectName("self.aboutTab")
        self.aboutTab.resize(630, 409)
        self.aboutGLayout = QtWidgets.QGridLayout(self.aboutTab)
        self.aboutGLayout.setObjectName("aboutGLayout")
        self.aboutGLayout_2 = QtWidgets.QGridLayout()
        self.aboutGLayout_2.setObjectName("aboutGLayout_2")
        spacerItem = QtWidgets.QSpacerItem(20, 20, QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Minimum)
        self.aboutGLayout_2.addItem(spacerItem, 0, 1, 1, 1)
        self.qomuiInfo = QtWidgets.QLabel(self.aboutTab)
        font = QtGui.QFont()
        font.setItalic(True)
        self.qomuiInfo.setFont(font)
        self.qomuiInfo.setAlignment(QtCore.Qt.AlignCenter)
        self.qomuiInfo.setObjectName("qomuiInfo")
        self.aboutGLayout_2.addWidget(self.qomuiInfo, 1, 2, 1, 1)
        self.qIconLabel = QtWidgets.QLabel(self.aboutTab)
        self.qIconLabel.setObjectName("qIconLabel")
        self.aboutGLayout_2.addWidget(self.qIconLabel, 0, 0, 2, 1)
        self.qomuiLabel = QtWidgets.QLabel(self.aboutTab)
        font = QtGui.QFont()
        font.setPointSize(20)
        font.setBold(True)
        font.setWeight(75)
        self.qomuiLabel.setFont(font)
        self.qomuiLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.qomuiLabel.setObjectName("qomuiLabel")
        self.aboutGLayout_2.addWidget(self.qomuiLabel, 0, 2, 1, 1)
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.aboutGLayout_2.addItem(spacerItem1, 0, 3, 1, 1)
        self.aboutGLayout.addLayout(self.aboutGLayout_2, 0, 1, 1, 1)
        self.line = QtWidgets.QFrame(self.aboutTab)
        self.line.setLineWidth(5)
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName("line")
        self.aboutGLayout.addWidget(self.line, 1, 1, 1, 1)
        spacerItem2 = QtWidgets.QSpacerItem(115, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.aboutGLayout.addItem(spacerItem2, 2, 0, 1, 1)
        self.aboutGLayout_3 = QtWidgets.QGridLayout()
        self.aboutGLayout_3.setObjectName("aboutGLayout_3")
        self.versionLabel = QtWidgets.QLabel(self.aboutTab)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.versionLabel.setFont(font)
        self.versionLabel.setObjectName("versionLabel")
        self.aboutGLayout_3.addWidget(self.versionLabel, 0, 0, 1, 1)
        self.licenseLabel = QtWidgets.QLabel(self.aboutTab)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.licenseLabel.setFont(font)
        self.licenseLabel.setObjectName("licenseLabel")
        self.aboutGLayout_3.addWidget(self.licenseLabel, 2, 0, 1, 1)
        self.licenseInfo = QtWidgets.QLabel(self.aboutTab)
        self.licenseInfo.setIndent(10)
        self.licenseInfo.setObjectName("licenseInfo")
        self.aboutGLayout_3.addWidget(self.licenseInfo, 2, 1, 1, 1)
        self.homepageInfo = QtWidgets.QLabel(self.aboutTab)
        self.homepageInfo.setIndent(10)
        self.homepageInfo.setObjectName("homepageInfo")
        self.aboutGLayout_3.addWidget(self.homepageInfo, 1, 1, 1, 1)
        self.urlLabel = QtWidgets.QLabel(self.aboutTab)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.urlLabel.setFont(font)
        self.urlLabel.setObjectName("urlLabel")
        self.aboutGLayout_3.addWidget(self.urlLabel, 1, 0, 1, 1)
        self.versionInfo = QtWidgets.QLabel(self.aboutTab)
        self.versionInfo.setIndent(10)
        self.versionInfo.setObjectName("versionInfo")
        self.aboutGLayout_3.addWidget(self.versionInfo, 0, 1, 1, 1)
        spacerItem3 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.aboutGLayout_3.addItem(spacerItem3, 1, 2, 1, 1)
        self.aboutGLayout.addLayout(self.aboutGLayout_3, 2, 1, 1, 1)
        spacerItem4 = QtWidgets.QSpacerItem(115, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.aboutGLayout.addItem(spacerItem4, 2, 2, 1, 1)
        self.line_2 = QtWidgets.QFrame(self.aboutTab)
        self.line_2.setLineWidth(5)
        self.line_2.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_2.setObjectName("line_2")
        self.aboutGLayout.addWidget(self.line_2, 3, 1, 1, 1)
        self.aboutVLayout = QtWidgets.QHBoxLayout()
        self.aboutVLayout.setObjectName("aboutVLayout")
        spacerItem5 = QtWidgets.QSpacerItem(28, 18, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.aboutVLayout.addItem(spacerItem5)
        self.newVersionLabel = QtWidgets.QLabel(self.aboutTab)
        self.newVersionLabel.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.newVersionLabel.setObjectName("newVersionLabel")
        self.aboutVLayout.addWidget(self.newVersionLabel)
        self.updateQomuiBt = QtWidgets.QPushButton(self.aboutTab)
        self.updateQomuiBt.setObjectName("updateQomuiBt")
        self.newVersionLabel.setVisible(False)
        self.updateQomuiBt.setVisible(False)
        self.aboutVLayout.addWidget(self.updateQomuiBt)
        self.aboutGLayout.addLayout(self.aboutVLayout, 4, 1, 1, 1)
        spacerItem6 = QtWidgets.QSpacerItem(17, 191, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.aboutGLayout.addItem(spacerItem6, 5, 1, 1, 1)

        self.gridLayout.addWidget(self.tabWidget, 2, 1, 1, 1) 
        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

        self.providerProtocolBox.activated[str].connect(self.pop_ProtocolListWidget)
        self.addServerBt.clicked.connect(self.switch_providerTab)
        self.delServerBt.clicked.connect(self.del_single_server)
        self.countryBox.activated[str].connect(self.filter_servers)
        self.providerBox.activated[str].connect(self.filter_servers)
        self.tunnelBox.activated[str].connect(self.filter_servers)
        self.serverTabBt.clicked.connect(self.tab_switch)
        self.bypassTabBt.clicked.connect(self.tab_switch)
        self.aboutTabBt.clicked.connect(self.tab_switch)
        self.optionsTabBt.clicked.connect(self.tab_switch)
        self.logTabBt.clicked.connect(self.tab_switch)
        self.providerTabBt.clicked.connect(self.tab_switch)
        self.applyOptBt.clicked.connect(self.applyoptions)
        self.cancelOptBt.clicked.connect(self.cancelOptions)
        self.restoreDefaultOptBt.clicked.connect(self.restoreDefaults)
        self.firewallEditBt.clicked.connect(self.show_firewall_editor)
        self.addBypassAppBt.clicked.connect(self.select_application)
        self.delBypassAppBt.clicked.connect(self.del_bypass_app)
        self.favouriteButton.toggled.connect(self.show_favourite_servers)
        self.overrorMsgideCheck.toggled.connect(self.override_protocol_show)
        self.delProviderBt.clicked.connect(self.del_provider)
        self.addProviderBox.activated[str].connect(self.providerChosen)
        self.addProviderDownloadBt.clicked.connect(self.add_server_configs)
        self.randomSeverBt.clicked.connect(self.choose_random_server)
        self.savePortButton.clicked.connect(self.override_protocol)
        self.modify_serverBt.clicked.connect(self.modify_server)
        self.updateQomuiBt.clicked.connect(self.update_qomui)

    def retranslateUi(self, Form):
        s = ""
        Form.setWindowTitle(_translate("Form", "Qomui", None))
        self.serverTabBt.setText(_translate("Form", "Server", None))
        self.logTabBt.setText(_translate("Form", "Log", None))
        self.providerTabBt.setText(_translate("Form", "Provider", None))
        self.bypassTabBt.setText(_translate("Form", "Bypass", None))
        self.aboutTabBt.setText(_translate("Form", "About", None))
        self.optionsTabBt.setText(_translate("Form", "Options", None))
        self.randomSeverBt.setText(_translate("Form", "Random", None))
        self.randomSeverBt.setIcon(QtGui.QIcon.fromTheme("view-refresh"))
        self.addServerBt.setText(_translate("Form", "Add Servers", None))
        self.addServerBt.setIcon(QtGui.QIcon.fromTheme("list-add"))
        self.modify_serverBt.setText(_translate("Form", "Modify", None))
        self.modify_serverBt.setIcon(QtGui.QIcon.fromTheme("edit"))
        self.delServerBt.setText(_translate("Form", "Delete", None))
        self.delServerBt.setIcon(QtGui.QIcon.fromTheme("edit-delete"))
        self.autoconnectOptCheck.setText(_translate("Form", "Autoconnect/reconnect", None))
        self.simpletrayOptCheck.setText(_translate("Form", "System tray: simple mode", None))
        self.minimizeOptCheck.setText(_translate("Form", "Start minimized", None))
        self.firewallOptCheck.setText(_translate("Form", "Activate Firewall     ", None))
        self.bypassOptCheck.setText(_translate("Form", "Allow OpenVPN bypass", None))
        self.pingOptCheck.setText(_translate("Form", "Perform latency check", None))
        self.ipv6_disableOptCheck.setText(_translate("Form", "Disable IPv6", None))
        self.alt_dnsOptCheck.setText(_translate("Form", "Use always", None))
        self.alt_dnsOptLabel.setText(_translate("Form", "Alternative DNS Servers:", None))
        self.restoreDefaultOptBt.setText(_translate("Form", "Restore defaults", None))
        self.restoreDefaultOptBt.setIcon(QtGui.QIcon.fromTheme("document-revert"))
        self.applyOptBt.setText(_translate("Form", "Apply", None))
        self.applyOptBt.setIcon(QtGui.QIcon.fromTheme("dialog-ok"))
        self.cancelOptBt.setText(_translate("Form", "Cancel", None))
        self.cancelOptBt.setIcon(QtGui.QIcon.fromTheme("dialog-no"))
        self.firewallEditBt.setText(_translate("Form", "Edit firewall rules", None))
        self.firewallEditBt.setIcon(QtGui.QIcon.fromTheme("edit"))
        self.addBypassAppBt.setText(_translate("Form", "Add Application", None))
        self.addBypassAppBt.setIcon(QtGui.QIcon.fromTheme("list-add"))
        self.delBypassAppBt.setText(_translate("Form", "Remove", None))
        self.delBypassAppBt.setIcon(QtGui.QIcon.fromTheme("edit-delete"))
        self.protocolLabel.setText(_translate("Form", "Choose protocol and port:", None))
        self.addProviderLabel.setText(_translate("Form", "Add/update provider:", None))
        self.delProviderLabel.setText(_translate("Form", "Delete provider:", None))
        self.delProviderBt.setText(_translate("Form", "Delete", None))
        self.delProviderBt.setIcon(QtGui.QIcon.fromTheme("edit-delete"))
        self.overrorMsgideCheck.setText(_translate("Form", 
                                        "Override settings from config file", None))
        self.portOverrideLabel.setText(_translate("Form", "Port", None))
        self.savePortButton.setText(_translate("Form", "Save", None))
        self.savePortButton.setIcon(QtGui.QIcon.fromTheme("dialog-ok"))
        self.addProviderUserEdit.setPlaceholderText(_translate("Form", "Username", None))
        self.addProviderDownloadBt.setText(_translate("Form", "Download", None))
        self.addProviderDownloadBt.setIcon(QtGui.QIcon.fromTheme("list-add"))
        self.addProviderPassEdit.setPlaceholderText(_translate("Form", "Password", None))
        icon = QtGui.QIcon.fromTheme("qomui")
        self.qIconLabel.setPixmap(icon.pixmap(60,60))
        self.qomuiLabel.setText(_translate("Form", "QOMUI", None))
        self.qomuiInfo.setText(_translate("Form", "Easy-to-use OpenVPN Gui", None))
        self.versionLabel.setText(_translate("Form", "Version:", None))
        self.urlLabel.setText(_translate("Form", "Homepage:", None))
        self.homepageInfo.setText(_translate("Form", "https://github.com/corrad1nho/qomui", None))
        self.licenseLabel.setText(_translate("Form", "License:", None))
        self.licenseInfo.setText(_translate("Form", "GPLv3", None))
        self.newVersionLabel.setText(_translate("Form", "A new version is available!", None))

        self.autoconnectOptLabel.setText(_translate("Form", 
                                          "Automatically (re-)connect to last server", 
                                          None))
        self.minimizeOptLabel.setText(_translate("Form", 
                                          "Only works if system tray is available", 
                                          None))
        self.simpletrayOptLabel.setText(_translate("Form", 
                                          "Use only if tray icon is not displayed correctly", 
                                          None))
        self.ipv6_disableOptLabel.setText(_translate("Form", 
                                          "Disables ipv6 stack systemwide", 
                                          None))
        self.pingOptLabel.setText(_translate("Form", 
                                          "Sort servers by latency - allow ping", 
                                          None))
        self.bypassOptLabel.setText(_translate("Form", 
                                          "Allow applications to run outside VPN tunnel", 
                                          None))
        self.firewallOptLabel.setText(_translate("Form", 
                                          "Block connections outside VPN tunnel - leak protection", 
                                          None))

        text = "By default Qomui will try to use the DNS server by your provider. \
                Otherwise, it will fall back to the alternative DNS servers"

        self.dnsInfoLabel.setText(_translate("Form", 
                                          s.join(text.replace("    ", "")), 
                                          None))

        text = 'To use an application outside the VPN tunnel, \
                you can simply add a program to the list below \
                and launch it from there. Alternatively, you can \
                run commands from a console by prepending \
                "cgexec -g net_cls:bypass_qomui $yourcommand". \
                Be aware that some applications including Firefox \
                will not launch a second instance in bypass mode \
                if they are already running.'

        self.bypassInfoLabel.setText(_translate("Form", 
                                          s.join(text.replace("    ", "")), 
                                          None))

        for provider in SUPPORTED_PROVIDERS:
            self.addProviderBox.addItem(provider)
        self.addProviderBox.addItem("Manually add config file folder")

    def messageBox(self, text, info, buttons=[], icon="Question"):
        box = QtWidgets.QMessageBox(self)
        box.setText(text)
        box.setInformativeText(info)
        box.setIcon(getattr(QtWidgets.QMessageBox, icon))

        box.addButton(QtWidgets.QPushButton(buttons[0]), 
                                            QtWidgets.QMessageBox.NoRole
                                            )
        try:
            box.addButton(QtWidgets.QPushButton(buttons[1]), 
                                            QtWidgets.QMessageBox.YesRole
                                            )
        except:
            pass

        try:                                    
            box.addButton(QtWidgets.QPushButton(buttons[2]), 
                                            QtWidgets.QMessageBox.RejectRole
                                            )
        except:
            pass

        ret = box.exec_()
        return ret

    def restart(self, new_version):
        self.update_bar("stop", "Qomui")
        if new_version != "failed":
            self.versionInfo.setText(new_version)
            self.newVersionLabel.setVisible(False)
            self.updateQomuiBt.setVisible(False)
            ret = self.messageBox("Qomui has been updated",
                                "Do you want to restart Qomui?",
                                buttons=["Later", "Now"],
                                icon = "Question"
                                )
            if ret == 1:
                self.kill()
                self.qomui_service.restart()
                os.execl(sys.executable, sys.executable, * sys.argv)
        else:
            self.show_failmsg("Upgrade failed", "See log for further details")

    def check_update(self):
        if self.packetmanager in ["None", "DEB", "RPM"]:
            self.check_thread = update.UpdateCheck()
            self.check_thread.release_found.connect(self.release_compare)
            self.check_thread.start()

    def release_compare(self, release):
        self.release = release
        try:
            split = self.release[1:].split(".")
            latest = int("".join(split))
            split = self.installed[1:].split(".")
            installed = int("".join(split))

            if (latest > installed) is True:
                self.updateQomuiBt.setText("Upgrade to %s" %self.release)
                self.updateQomuiBt.setVisible(True)
                self.newVersionLabel.setVisible(True)

        except ValueError:
            pass

    def update_qomui(self):
        self.qomui_service.update_qomui(self.release, self.packetmanager)
        self.update_bar("upgrade", "Qomui")

    def tab_switch(self):
        button = self.sender().text().replace("&", "")
        if button == "Server":
            self.tabWidget.setCurrentIndex(0)
        elif button == "Log":
            self.tabWidget.setCurrentIndex(1)
            self.logText.verticalScrollBar().setValue(self.logText.verticalScrollBar().maximum())
        elif button == "Options":
            self.setOptiontab(self.config_dict)
            self.tabWidget.setCurrentIndex(2)
        elif button == "Provider":
            self.tabWidget.setCurrentIndex(3) 
        elif button == "Bypass":
            self.tabWidget.setCurrentIndex(4)  
        elif button == "About":
            self.tabWidget.setCurrentIndex(5)  
            self.check_update()

    def switch_providerTab(self):
        self.tabWidget.setCurrentIndex(3) 

    def systemtray(self):
        try:
            if self.config_dict["simpletray"] == 0:
                self.trayIcon = QtGui.QIcon.fromTheme("qomui")
            else:
                self.trayIcon = QtGui.QIcon.fromTheme("qomui_off")
        except KeyError:
            self.trayIcon = QtGui.QIcon.fromTheme("qomui")

        self.tray = QtWidgets.QSystemTrayIcon()
        if self.tray.isSystemTrayAvailable() == False:
            self.setWindowState(QtCore.Qt.WindowActive)
            self.showNormal()
        else:    
            self.tray.setIcon(self.trayIcon)
            self.trayMenu = QtWidgets.QMenu()
            show = self.trayMenu.addAction("Show")
            exit = self.trayMenu.addAction("Quit")
            show.triggered.connect(self.show)
            exit.triggered.connect(self.shutdown)
            self.tray.setContextMenu(self.trayMenu)
            self.tray.show()
            self.tray.setToolTip("Status: disconnected")
            self.tray.activated.connect(self.restoreUi)

    def shutdown(self):
        self.tray.hide()
        self.kill()
        sys.exit()

    def restoreUi(self, reason):
        if self.isVisible() is True:
            self.setWindowState(QtCore.Qt.WindowMinimized)
            self.hide()
        else:
            self.setWindowState(QtCore.Qt.WindowActive)
            self.showNormal()

    def closeEvent(self, event):
        self.exit_event = event
        self.confirm = QtWidgets.QMessageBox()
        self.timeout = 5
        self.confirm.setText("Do you want to exit program or minimize to tray?")
        info = "Closing in %s seconds" %self.timeout
        self.confirm.setInformativeText(info)
        self.confirm.setIcon(QtWidgets.QMessageBox.Question)
        self.confirm.addButton(QtWidgets.QPushButton("Minimize"), QtWidgets.QMessageBox.NoRole)
        self.confirm.addButton(QtWidgets.QPushButton("Exit"), QtWidgets.QMessageBox.YesRole)
        self.confirm.addButton(QtWidgets.QPushButton("Cancel"), QtWidgets.QMessageBox.RejectRole)
        self.timer = QtCore.QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.change_timeout)
        self.timer.start()

        ret = self.confirm.exec_()
        self.timer.stop()

        if ret == 2:
            self.exit_event.ignore()

        elif ret == 0:
            self.hide()

        elif ret == 1:
            self.tray.hide()
            self.kill()
            self.exit_event.accept()

    def change_timeout(self):
        self.timeout -= 1
        info = "Closing in %s seconds" %self.timeout
        self.confirm.setInformativeText(info)
        if self.timeout <= 0:
            self.timer.stop()
            self.confirm.hide()
            self.tray.hide()
            self.kill()
            self.exit_event.accept()

    def load_json(self, json_file):
        try:
            with open(json_file, 'r') as j:
                return json.load(j)
        except (FileNotFoundError,json.decoder.JSONDecodeError) as e:
            self.logger.warning('%s: Could not open %s' % (e, json_file))
            return {}

    def connect_last_server(self):
        try:
            if self.config_dict["autoconnect"] == 1:
                self.kill()
                last_server_dict = self.load_json("%s/last_server.json" %HOMEDIR)
                self.ovpn_dict = last_server_dict["last"]
                self.hop_server_dict = last_server_dict["hop"]
                if self.hop_server_dict is not None:
                    self.show_hop_widget()
                try: 
                    if self.ovpn_dict["random"] == "on":
                        self.choose_random_server()
                except KeyError:
                    self.establish_connection(self.ovpn_dict)
                try:
                    if self.ovpn_dict["favourite"] == "on":
                        self.favouriteButton.setChecked(True)
                except KeyError:
                    pass

        except KeyError:
            pass

    def load_saved_files(self):
        try:
            with open("%s/VERSION" %ROOTDIR, "r") as v:
                version = v.read().split("\n")
                self.installed = version[0]
                self.versionInfo.setText(self.installed)
                try:
                    pm_check = version[1]
                    if pm_check != "":
                        self.packetmanager = pm_check
                    else:
                        self.packetmanager = "None"
                except IndexError:
                    pass

        except FileNotFoundError:
            self.logger.warning("%s/VERSION does not exist" % ROOTDIR)
            self.versionInfo.setText("N.A.")

        for saved_file in JSON_FILE_LIST:
            setattr(self, saved_file[0], self.load_json(saved_file[1]))

        if not bool(self.config_dict):
            setattr(self, "config_dict", self.load_json('%s/default_config.json' % ROOTDIR))
            self.logger.info('Loading default configuration')

        try:
            if self.config_dict["minimize"] == 0:
                self.setWindowState(QtCore.Qt.WindowActive)
        except KeyError:
            pass

        try:
            if self.config_dict["bypass"] == 1:
                self.qomui_service.bypass(utils.get_user_group())
                self.bypassTabBt.setVisible(True) 
        except KeyError:
            pass

        self.setOptiontab(self.config_dict)
        self.pop_boxes(country='All countries')
        self.pop_bypassAppList()
        self.connect_last_server()

    def setOptiontab(self, config):
        try:
            self.altDnsEdit1.setText(config["alt_dns1"])
            self.altDnsEdit2.setText(config["alt_dns2"])
        except KeyError:
            pass

        for k, v in config.items():
            try:
                if v == 0:
                    getattr(self, "%sOptCheck" %k).setChecked(False)
                elif v == 1:
                    getattr(self, "%sOptCheck" %k).setChecked(True)
            except AttributeError:
                pass

    def restoreDefaults(self):
        default_config_dict = self.load_json('%s/default_config.json' % (ROOTDIR))
        self.setOptiontab(default_config_dict)

    def cancelOptions(self):
        self.setOptiontab(self.config_dict)

    def applyoptions(self):
        temp_config_dict = {}
        temp_config_dict["alt_dns1"] = self.altDnsEdit1.text().replace("\n", "")
        temp_config_dict["alt_dns2"] = self.altDnsEdit2.text().replace("\n", "")

        for option in self.config_list:
            if getattr(self, "%sOptCheck" %option).checkState() == 2:
                temp_config_dict[option] = 1
            elif getattr(self, "%sOptCheck" %option).checkState() == 0:
                temp_config_dict[option] = 0

        with open ('%s/config_temp.json' % (HOMEDIR), 'w') as config:
            json.dump(temp_config_dict, config)

        update_cmd = ['pkexec', sys.executable, '-m', 'qomui.mv_config',
                      '-d', '%s' %(HOMEDIR)]

        if self.firewall_rules_changed is True:
            update_cmd.append('-f')

        try:
            check_call(update_cmd)
            self.logger.info("Configuration changes applied successfully")
            self.qomui_service.load_firewall()
            self.qomui_service.bypass(utils.get_user_group())
            QtWidgets.QMessageBox.information(self,
                                            "Updated",
                                            "Configuration updated successfully",
                                            QtWidgets.QMessageBox.Ok)

            if temp_config_dict["ping"] == 1:
                self.get_latencies()

            if temp_config_dict["bypass"] == 1:
                self.bypassTabBt.setVisible(True)
            else:
                self.bypassTabBt.setVisible(False)

            self.config_dict = temp_config_dict

        except CalledProcessError as e:
            self.logger.info("Non-zero exit status: configuration changes not applied")
            QtWidgets.QMessageBox.information(self,
                                                "Authentication failure",
                                                "Configuration not updated",
                                                QtWidgets.QMessageBox.Ok)

    def networkstate(self, networkstate):
        if networkstate == 70 or networkstate == 60:
            self.logger.info("Detected new network connection")
            self.qomui_service.save_default_dns()
            self.get_latencies()
            if self.ovpn_dict is not None:
                self.kill()
                self.establish_connection(self.ovpn_dict)
                self.qomui_service.bypass(utils.get_user_group())
        elif networkstate != 70 and networkstate != 60:
            self.logger.info("Lost network connection - VPN tunnel terminated")
            self.kill()

    def providerChosen(self):
        provider = self.addProviderBox.currentText()

        p_txt = {"Airvpn" : ("Username", "Password"),
                "PIA" : ("Username", "Password"),
                "Windscribe" : ("Username", "Password"),
                "Mullvad" : ("Account Numner", "N.A. - Leave empty"),
                "ProtonVPN" : ("OpenVPN username", "OpenVPN password")
                }

        if provider in SUPPORTED_PROVIDERS:
            self.addProviderEdit.setVisible(False)
            self.addProviderUserEdit.setPlaceholderText(_translate("Form", p_txt[provider][0], None))
            self.addProviderPassEdit.setPlaceholderText(_translate("Form", p_txt[provider][1], None))
            if provider in self.provider_list:
                self.addProviderDownloadBt.setText(_translate("Form", "Update", None))
            else:
                self.addProviderDownloadBt.setText(_translate("Form", "Download", None))

        else:
            self.addProviderEdit.setVisible(True)
            self.addProviderEdit.setPlaceholderText(_translate("Form", 
                                                               "Specify name of provider", 
                                                               None
                                                               ))
            self.addProviderUserEdit.setPlaceholderText(_translate("Form", "Username", None))
            self.addProviderPassEdit.setPlaceholderText(_translate("Form", "Password", None))
            self.addProviderDownloadBt.setText(_translate("Form", "Add Folder", None))

    def add_server_configs(self):
        if not os.path.exists("%s/temp" % (HOMEDIR)):
               os.makedirs("%s/temp" % (HOMEDIR))

        provider = self.addProviderBox.currentText()
        if provider not in SUPPORTED_PROVIDERS:
            provider = self.addProviderEdit.text()

        self.qomui_service.allow_provider_ip(provider)
        if provider == "Airvpn":
            username = self.addProviderUserEdit.text()
            password = self.addProviderPassEdit.text()
            self.down_thread = update.AirVPNDownload(username, password)
            QtWidgets.QApplication.setOverrideCursor(QtGui.QCursor(QtCore.Qt.WaitCursor))
            self.down_thread.importFail.connect(self.import_fail)
            self.down_thread.down_finished.connect(self.downloaded)
            self.down_thread.start()
            self.update_bar("start", provider)
        elif provider == "Mullvad":
            account_number = self.addProviderUserEdit.text()
            self.down_thread = update.MullvadDownload(account_number)
            QtWidgets.QApplication.setOverrideCursor(QtGui.QCursor(QtCore.Qt.WaitCursor))
            self.down_thread.importFail.connect(self.import_fail)
            self.down_thread.down_finished.connect(self.downloaded)
            self.down_thread.start()
            self.update_bar("start", provider)
        elif provider == "ProtonVPN":
            username = self.addProviderUserEdit.text()
            password = self.addProviderPassEdit.text()
            self.down_thread = update.ProtonDownload(username, password)
            QtWidgets.QApplication.setOverrideCursor(QtGui.QCursor(QtCore.Qt.WaitCursor))
            self.down_thread.importFail.connect(self.import_fail)
            self.down_thread.down_finished.connect(self.downloaded)
            self.down_thread.start()
            self.update_bar("start", provider)
        elif provider == "PIA":
            username = self.addProviderUserEdit.text()
            password = self.addProviderPassEdit.text()
            self.down_thread = update.PiaDownload(username, password)
            QtWidgets.QApplication.setOverrideCursor(QtGui.QCursor(QtCore.Qt.WaitCursor))
            self.down_thread.importFail.connect(self.import_fail)
            self.down_thread.down_finished.connect(self.downloaded)
            self.down_thread.start()
            self.update_bar("start", provider)
        elif provider == "Windscribe":
            username = self.addProviderUserEdit.text()
            password = self.addProviderPassEdit.text()
            self.down_thread = update.WsDownload(username, password)
            QtWidgets.QApplication.setOverrideCursor(QtGui.QCursor(QtCore.Qt.WaitCursor))
            self.down_thread.importFail.connect(self.import_fail)
            self.down_thread.down_finished.connect(self.downloaded)
            self.down_thread.start()
            self.update_bar("start", provider)

        else:
            provider = self.addProviderEdit.text()
            if provider == "":
                QtWidgets.QMessageBox.critical(self,
                                                "Error",
                                                "Please enter a provider name",
                                                QtWidgets.QMessageBox.Ok)

            elif provider in SUPPORTED_PROVIDERS:
                self.provider = provider
                self.add_server_configs()

            else:
                credentials = (self.addProviderUserEdit.text(), 
                               self.addProviderPassEdit.text(), 
                               self.addProviderEdit.text()
                               )
                try:
                    dialog = QtWidgets.QFileDialog.getOpenFileName(self,
                                caption="Choose Folder",
                                directory = os.path.expanduser("~"),
                                filter=self.tr('OpenVPN (*.ovpn *conf);;All files (*.*)'),
                                options=QtWidgets.QFileDialog.ReadOnly)

                    folderpath = QtCore.QFileInfo(dialog[0]).absolutePath()
                    if folderpath != "":
                        self.thread = update.AddFolder(credentials, folderpath)
                        self.thread.down_finished.connect(self.downloaded)
                        self.thread.importFail.connect(self.import_fail)
                        self.thread.start()
                        self.update_bar("start", provider)
                except TypeError:
                    pass

    def import_fail(self, info):
        QtWidgets.QApplication.restoreOverrideCursor()
        self.update_bar("stop", None)
        if info == "Airvpn":
            header = "Authentication failed"
            msg = "Perhaps the credentials you entered are wrong"
        elif info == "nothing":
            header = "Import Error"
            msg = "No config files found or folder seems\nto contain many unrelated files" 
        else:
            header = "Import failed"
            msg = info

        QtWidgets.QMessageBox.information(self,
                                            header,
                                            msg,
                                            QtWidgets.QMessageBox.Ok)

        try:
            shutil.rmtree("%s/temp/" % (HOMEDIR))
        except FileNotFoundError:
            pass

    def del_provider(self):
        confirmDialog = QtWidgets.QMessageBox()
        confirmDialog.setText("Are you sure?")
        confirmDialog.addButton(QtWidgets.QPushButton("No"), QtWidgets.QMessageBox.NoRole)
        confirmDialog.addButton(QtWidgets.QPushButton("Yes"), QtWidgets.QMessageBox.YesRole)
        ret = confirmDialog.exec_()
        provider = self.delProviderBox.currentText()
        del_list = []
        if ret == 1:
            for k, v in self.server_dict.items():
                if v["provider"] == provider:
                    del_list.append(k)
            for k in del_list:
                self.server_dict.pop(k)
            try:
                self.protocol_dict.pop(provider)
            except KeyError:
                pass
            self.qomui_service.delete_provider(provider)
            with open ("%s/server.json" % HOMEDIR, "w") as s:
                json.dump(self.server_dict, s)
            self.pop_boxes()

    def update_bar(self, text, provider):
        if text == "stop":
            self.WaitBar.setVisible(False)
        elif text == "start":
            self.WaitBar.setVisible(True)
            self.WaitBar.setText("Importing %s" %provider)
        elif text == "upgrade":
            self.WaitBar.setVisible(True)
            self.WaitBar.setText("Updating %s" %provider)

    def downloaded(self, content):
        provider = content["provider"]
        if provider not in self.provider_list:
            self.provider_list.append(provider)
        self.copy_rootdir(provider, content["path"])

        for k, v in content["server"].items():
            try:
                if self.server_dict[k]["favourite"] == "on":
                    content["server"][k]["favourite"] = "on"
            except KeyError:
                pass

        if provider in SUPPORTED_PROVIDERS:
            del_list = []
            for k, v in self.server_dict.items():
                if v["provider"] == provider:
                    del_list.append(k)
            for k in del_list:
                self.server_dict.pop(k)

        self.server_dict.update(content["server"])

        try:
            if 'selected' in self.protocol_dict[provider].keys():
                content["protocol"]["selected"] = self.protocol_dict[provider]["selected"]
            else:
                content["protocol"]["selected"] = "protocol_1"
        except KeyError:
            pass

        try:
            self.protocol_dict[provider] = (content["protocol"])
        except KeyError:
            pass

        with open ("%s/server.json" % HOMEDIR, "w") as s:
            json.dump(self.server_dict, s)

        with open ("%s/protocol.json" % HOMEDIR, "w") as p:
            json.dump(self.protocol_dict, p) 
        self.pop_boxes()

        self.update_bar("stop", None)
        QtWidgets.QApplication.restoreOverrideCursor()
        txt = "List of available servers updated"
        try:
            for s in content["failed"]:
                txt = txt + "\nFailed to resolve %s - server not added" %s
        except KeyError:
            pass

        down_msg = QtWidgets.QMessageBox.information(self,
                                                "Import successful",
                                                txt,
                                                QtWidgets.QMessageBox.Ok)

    def del_single_server(self):
        for item in self.serverListWidget.selectedItems():
            data = item.data(QtCore.Qt.UserRole)
            index = self.serverListWidget.row(item)
            try:
                self.server_dict.pop(data, None)
                self.serverListWidget.takeItem(index)
            except KeyError:
                pass
        with open ("%s/server.json" % HOMEDIR, "w") as s:
            json.dump(self.server_dict, s)

    def copy_rootdir(self, provider, path):
        self.qomui_service.block_dns()
        copy = self.qomui_service.copy_rootdir(provider, path)
        if copy == "copied":
            shutil.rmtree("%s/temp/" % (HOMEDIR))

    def set_flag(self, country):
        flag = '%s/flags/%s.png' % (ROOTDIR, country)
        if not os.path.isfile(flag):
            flag = '%s/flags/Unknown.png' % ROOTDIR
        pixmap = QtGui.QPixmap(flag).scaled(25, 25, 
                                            transformMode=QtCore.Qt.SmoothTransformation
                                            )
        setattr(self, country + "_pixmap", pixmap)


    def pop_boxes(self, country=None):
        self.country_list = ["All countries"]
        self.provider_list = ["All providers"]
        self.tunnel_list = ["OpenVPN"]
        self.tunnelBox.clear()

        for k,v in (self.server_dict.items()):
            if v["country"] not in self.country_list:
                self.country_list.append(v["country"])
                self.set_flag(v["country"])
            elif v["provider"] not in self.provider_list:
                self.provider_list.append(v["provider"])
            try:
                if v["tunnel"] == "WireGuard" and "WireGuard" not in self.tunnel_list:
                    self.tunnel_list.append("WireGuard")
                    for t in self.tunnel_list:
                        self.tunnelBox.addItem(t)
                    self.tunnelBox.setVisible(True)
                else:
                    if len(self.tunnel_list) == 2:
                        self.tunnelBox.setVisible(True)
                    else:
                        self.tunnelBox.setVisible(False)
            except KeyError:
                pass

        self.pop_providerProtocolBox()
        self.pop_delProviderBox()
        self.countryBox.clear()
        self.providerBox.clear()
        if len(self.provider_list) <= 2 :
            self.providerBox.setVisible(False)
        else:
            self.providerBox.setVisible(True)
        for index, country in enumerate(sorted(self.country_list)):
            self.countryBox.addItem(country)
            self.countryBox.setItemText(index, country)
        for index, provider in enumerate(self.provider_list):
            self.providerBox.addItem(provider)
            self.providerBox.setItemText(index, provider)
        self.filter_servers(display="all")
        try:
            if self.config_dict["ping"] == 1:
                self.get_latencies()
            else:
                self.check_update()
        except KeyError:
            pass

    def get_latencies(self):
        gateway = self.qomui_service.default_gateway_check()["interface"]
        if gateway != "None": 
            self.latency_list = []
            self.PingThread = latency.LatencyCheck(self.server_dict, gateway)
            self.PingThread.lat_signal.connect(self.display_latency)
            self.PingThread.finished.connect(self.check_update)
            self.PingThread.start()

    def display_latency(self, result):
        hidden = False
        server = result[0]
        latency_string = result[1]
        latency_float = result[2]
        try:
            old_index = self.index_list.index(server)
            bisect.insort(self.latency_list, latency_float)
            update_index = self.latency_list.index(latency_float)
            rm = self.index_list.index(server)
            self.index_list.pop(rm)
            self.index_list.insert(update_index, server)
            if getattr(self, server).isHidden() == True:
                hidden = True
            self.serverListWidget.takeItem(old_index)
            self.add_server_widget(server, self.server_dict[server], insert=update_index)
            self.serverListWidget.setRowHidden(update_index, hidden)
            getattr(self, server).display_latency(latency_string)
        except ValueError:
            pass

    def show_favourite_servers(self, state):
        self.randomSeverBt.setVisible(True)
        if state == True:
            i = 0
            for key, val in self.server_dict.items():
                index = self.index_list.index(key)
                try:
                    if val["favourite"] == "on":
                        self.serverListWidget.setRowHidden(index, False)
                        getattr(self, key).setHidden(False)
                    else:
                        self.serverListWidget.setRowHidden(index, True)
                        getattr(self, key).setHidden(True)
                except KeyError:
                    self.serverListWidget.setRowHidden(index, True)
                    getattr(self, key).setHidden(True)
        elif state == False:
            self.filter_servers()

    def filter_servers(self, *arg, display="filter"):
        self.randomSeverBt.setVisible(False)
        country = self.countryBox.currentText()
        provider = self.providerBox.currentText()
        if self.tunnelBox.isVisible() is True:
            tunnel = self.tunnelBox.currentText()
        else:
            tunnel = "OpenVPN"
        if self.favouriteButton.isChecked() == True:
            self.favouriteButton.setChecked(False)
        if display == "all":
            self.index_list = []
            self.serverListWidget.clear()
            for key,val in sorted(self.server_dict.items(), key=lambda s: s[0].upper()):
                try:
                    val.pop("index")
                except KeyError:
                    pass
                self.index_list.append(key)
                self.add_server_widget(key, val)
        else:
            for key, val in self.server_dict.items():
                index = self.index_list.index(key)
                if val["provider"] == provider or provider == "All providers":
                    if val["country"] == country or country == "All countries":
                        try:
                            if val["tunnel"] == tunnel:
                                self.serverListWidget.setRowHidden(index, False)
                                getattr(self, key).setHidden(False)
                            else:
                                self.serverListWidget.setRowHidden(index, True)
                                getattr(self, key).setHidden(True)
                        except KeyError:
                            if tunnel == "OpenVPN":
                                self.serverListWidget.setRowHidden(index, False)
                                getattr(self, key).setHidden(False)
                            elif tunnel == "WireGuard":
                                self.serverListWidget.setRowHidden(index, True)
                                getattr(self, key).setHidden(True)
                    else:
                        self.serverListWidget.setRowHidden(index, True)
                        getattr(self, key).setHidden(True)
                else:
                    self.serverListWidget.setRowHidden(index, True)
                    getattr(self, key).setHidden(True)

    def add_server_widget(self, key, val, insert=None):
        setattr(self, key, ServerWidget())
        self.ListItem = QtWidgets.QListWidgetItem()
        self.ListItem.setData(QtCore.Qt.UserRole, key)
        self.ListItem.setSizeHint(QtCore.QSize(100, 50))
        if insert is None:
            self.serverListWidget.addItem(self.ListItem)
        else:
            self.serverListWidget.insertItem(insert, self.ListItem)
        self.serverListWidget.setItemWidget(self.ListItem, getattr(self, key))
        try: 
            fav = val["favourite"]
        except KeyError:
            fav = 1

        try:
            getattr(self, key).setText(val["name"], val["provider"], 
                            getattr(self, "%s_pixmap" %val["country"]), 
                            val["city"], fav=fav)
        except AttributeError:
            self.set_flag(val["country"])
            getattr(self, key).setText(val["name"], val["provider"], 
                            getattr(self, "%s_pixmap" %val["country"]), 
                            val["city"], fav=fav)

        try:
            if val["tunnel"] == "WireGuard":
                getattr(self, key).hide_button(0)
        except KeyError:
            pass

        getattr(self, key).item_chosen_signal.connect(self.item_chosen_signal)
        getattr(self, key).set_hop_signal.connect(self.set_hop)
        getattr(self, key).changed_favourite_signal.connect(self.change_favourite)

    def pop_providerProtocolBox(self):
        self.providerProtocolBox.clear()
        for provider in sorted(self.provider_list):
            if provider != "All providers":
                self.providerProtocolBox.addItem(provider)
                self.pop_ProtocolListWidget(self.providerProtocolBox.currentText())

    def pop_ProtocolListWidget(self, provider):
        if provider in SUPPORTED_PROVIDERS:
            self.protocolListWidget.setVisible(True)
            self.overrorMsgideCheck.setVisible(False)
            self.portOverrideLabel.setVisible(False)
            self.chooseProtocolBox.setVisible(False)
            self.portEdit.setVisible(False)
            self.savePortButton.setVisible(False)
            self.protocolListWidget.clear()
            self.protocolListWidget.itemClicked.connect(self.protocol_change)
            try:
                current = self.protocol_dict[provider]["selected"]
            except KeyError:
                current = self.protocol_dict[provider]["protocol_1"]
            for k,v in sorted(self.protocol_dict[provider].items()):
                if k != "selected":
                    try:
                        ipv6 = ", connect with %s" %v["ipv6"]
                        mode = v["protocol"] + " " + v["port"] + ", " + v["ip"] + ipv6
                    except KeyError:
                        mode = v["protocol"] + " " + v["port"]

                    item = QtWidgets.QListWidgetItem()
                    item.setText(mode)
                    item.setData(QtCore.Qt.UserRole, k)
                    item.setFlags(item.flags() | QtCore.Qt.ItemIsUserCheckable)
                    if k == current:
                        item.setCheckState(QtCore.Qt.Checked)
                    else:
                        item.setCheckState(QtCore.Qt.Unchecked)
                    self.protocolListWidget.addItem(item)
        else:
            self.protocolListWidget.setVisible(False)
            self.overrorMsgideCheck.setVisible(True)
            try:
                protocol = self.protocol_dict[provider]["protocol"]
                port = self.protocol_dict[provider]["port"]
                self.override_protocol_show(True, protocol=protocol, port=port)
                self.overrorMsgideCheck.setChecked(True)
            except KeyError:
                pass

    def protocol_change(self, selection):
        provider = self.providerProtocolBox.currentText()
        if provider in SUPPORTED_PROVIDERS:
            self.protocol_dict[provider]["selected"] = selection.data(QtCore.Qt.UserRole)
            with open ("%s/protocol.json" % HOMEDIR, "w") as p:
                json.dump(self.protocol_dict, p)
            for item in range(self.protocolListWidget.count()):
                if self.protocolListWidget.item(item) != selection:
                    self.protocolListWidget.item(item).setCheckState(QtCore.Qt.Unchecked)
                else:
                    self.protocolListWidget.item(item).setCheckState(QtCore.Qt.Checked)

    def override_protocol_show(self, state, protocol=None, port=None):
        if state == True:
            self.portOverrideLabel.setVisible(True)
            self.chooseProtocolBox.setVisible(True)
            self.portEdit.setVisible(True)
            self.savePortButton.setVisible(True)
            if protocol is not None:
                if protocol == "UDP":
                    self.chooseProtocolBox.setCurrentIndex(0)
                elif protocol == "TCP":
                    self.chooseProtocolBox.setCurrentIndex(1)
                self.portEdit.setText(port)

        elif state == False:
            try:
                self.protocol_dict.pop(self.providerProtocolBox.currentText(), None)
                with open ("%s/protocol.json" % HOMEDIR, "w") as p:
                    json.dump(self.protocol_dict, p)
            except KeyError:
                pass

    def override_protocol(self):
        protocol = self.chooseProtocolBox.currentText()
        port = self.portEdit.text()
        provider = self.providerProtocolBox.currentText()
        if self.overrorMsgideCheck.checkState() == 2:
            self.protocol_dict[provider] = {"protocol" : protocol, "port": port}
            with open ("%s/protocol.json" % HOMEDIR, "w") as p:
                json.dump(self.protocol_dict, p) 

    def pop_delProviderBox(self):
        self.delProviderBox.clear()
        for provider in self.provider_list:
            if provider != "All providers":
                self.delProviderBox.addItem(provider)

    def change_favourite(self, change):
        if change[1] == True:
            self.server_dict[change[0]].update({"favourite" : "on"})
        elif change[1] == False:
            self.server_dict[change[0]].update({"favourite" : "off"})
            if self.favouriteButton.isChecked() == True:
                self.show_favourite_servers(True)
        with open ("%s/server.json" % HOMEDIR, "w") as s:
            json.dump(self.server_dict, s) 

    def set_hop(self, server):
        try:
            current_dict = self.server_dict[server].copy()
            self.hop_server_dict = utils.create_server_dict(current_dict, self.protocol_dict)
            self.show_hop_widget()
        except KeyError:
            self.show_failmsg("Server not found",
                              "Server does not exist (anymore)\nHave you deleted the server?")

    def show_hop_widget(self):
        self.hop_active = 2
        self.hop_server_dict.update({"hop":"1"})
        self.serverHopWidget.setVisible(True)
        self.serverHopWidget.setText(self.hop_server_dict)
        self.serverHopWidget.clear.connect(self.delete_hop)
        self.qomui_service.set_hop(self.hop_server_dict)

    def delete_hop(self):
        self.hop_active = 0
        self.hop_server_dict = None
        self.serverHopWidget.setVisible(False)
        index = self.tabWidget.currentIndex()
        self.filter_servers()

    def choose_random_server(self):
        random_list = []
        for key, val in self.server_dict.items():
            try:
                if val["favourite"] == "on":
                    random_list.append(key)
            except KeyError:
                pass

        if len(random_list) != 0:
            self.item_chosen_signal(random.choice(random_list), random="on")

    def item_chosen_signal(self, server, random=None):
        try:
            current_dict = self.server_dict[server].copy()
            self.ovpn_dict = utils.create_server_dict(current_dict, self.protocol_dict)

            try:
                if self.ovpn_dict["tunnel"] == "WireGuard":
                    self.delete_hop()
            except KeyError:
                pass

            self.kill()
            if self.hop_active == 2 and self.hop_server_dict is not None:
                self.ovpn_dict.update({"hop":"2"})
            else:
                self.ovpn_dict.update({"hop":"0"})

            if random is not None:
                self.ovpn_dict.update({"random" : "on"})

            self.establish_connection(self.ovpn_dict)

        except KeyError:
            self.show_failmsg("Server not found",
                              "Server does not exist (anymore)\nHave you deleted the server?")

            QtWidgets.QApplication.restoreOverrideCursor()

    def openvpn_log_monitor(self, reply):
        if reply == "success":
            if self.hop_active != 2 or self.hop_log_monitor == 1:
                self.status = "active"
                self.hop_log_monitor = 0
                self.WaitBar.setVisible(False)
                try:
                    if self.config_dict["simpletray"] == 0:
                        self.trayIcon = QtGui.QIcon('%s/flags/%s.png' % (ROOTDIR, 
                                                                         self.ovpn_dict["country"]
                                                                         ))
                    else:
                        self.trayIcon = QtGui.QIcon.fromTheme("qomui")
                except KeyError:
                    self.trayIcon = QtGui.QIcon('%s/flags/%s.png' % (ROOTDIR,
                                                                     self.ovpn_dict["country"]
                                                                    ))
                finally:
                    self.tray.setIcon(QtGui.QIcon(self.trayIcon))
                    self.show_active_connection(self.ovpn_dict, self.hop_server_dict, tun_hop=self.tun_hop)
                    self.tun_hop = None

            elif self.hop_active == 2 and self.hop_log_monitor != 1:
                self.tun_hop = self.qomui_service.return_tun_device("hop")
                self.hop_log_monitor = 1

            with open('%s/last_server.json' % (HOMEDIR), 'w') as lserver:
                last_server_dict = {}
                last_server_dict["last"] = self.ovpn_dict
                last_server_dict["hop"] = self.hop_server_dict
                json.dump(last_server_dict, lserver)
                lserver.close()

        elif reply == "fail1":
            self.kill()
            self.show_failmsg("Connection attempt failed",
                              "Application was unable to connect to server\nSee log for further information")
            QtWidgets.QApplication.restoreOverrideCursor()

        elif reply == "fail2":
            self.kill()
            self.show_failmsg("Connection attempt failed",
                              "Authentication error while trying to connect\nMaybe your account is expired or connection limit is exceeded")
            QtWidgets.QApplication.restoreOverrideCursor()

        elif reply == "kill":
            try:
                if self.config_dict["simpletray"] == 0:
                    self.trayIcon = QtGui.QIcon.fromTheme("qomui")
                else:
                    self.trayIcon = QtGui.QIcon.fromTheme("qomui_off")
            except KeyError:
                self.trayIcon = QtGui.QIcon.fromTheme("qomui")
            self.tray.setIcon(self.trayIcon)
            QtWidgets.QApplication.restoreOverrideCursor()
            self.ActiveWidget.setVisible(False)

    def show_failmsg(self, text, information):
        self.failmsg = QtWidgets.QMessageBox(self)
        self.failmsg.setIcon(QtWidgets.QMessageBox.Critical)
        self.failmsg.setText(text)
        self.failmsg.setInformativeText(information)
        self.failmsg.setWindowModality(QtCore.Qt.WindowModal)
        self.failmsg.show()

    def show_active_connection(self, current_server, hop_dict, tun_hop=None):
        self.tray.setToolTip("Connected to %s" %self.ovpn_dict["name"])
        QtWidgets.QApplication.restoreOverrideCursor()
        tun = self.qomui_service.return_tun_device("tun")
        self.ActiveWidget.setVisible(True)
        self.ActiveWidget.setText(self.ovpn_dict, self.hop_server_dict, tun, tun_hop)
        self.ActiveWidget.disconnect.connect(self.kill)
        self.ActiveWidget.reconnect.connect(self.reconnect)
        self.gridLayout.addWidget(self.ActiveWidget, 0, 0, 1, 3)

    def reconnect(self):
        if self.status == "active":
            self.status = "inactive"
            self.kill()
            self.connect_last_server()

    def kill(self):
        self.status = "inactive"
        self.hop_log_monitor = 0
        self.qomui_service.disconnect()
        self.WaitBar.setVisible(False)
        self.ActiveWidget.setVisible(False)
        try:
            if self.config_dict["simpletray"] == 0:
                self.trayIcon = QtGui.QIcon.fromTheme("qomui")
            else:
                self.trayIcon = QtGui.QIcon.fromTheme("qomui_off")
            self.tray.setIcon(self.trayIcon)
            self.tray.setToolTip("Status: disconnected")
        except (KeyError, AttributeError):
            pass

    def establish_connection(self, server_dict):
        QtWidgets.QApplication.setOverrideCursor(QtGui.QCursor(QtCore.Qt.WaitCursor))
        self.logger.info("Connecting to %s...." %server_dict["name"])
        self.WaitBar.setText("Connecting to %s" %server_dict["name"])
        self.WaitBar.setVisible(True)
        self.hop_log_monitor = 0
        provider = server_dict["provider"]
        try:
            self.qomui_service.connect_to_server(server_dict)
        except dbus.exceptions.DBusException as e:
            self.logger.info("Dbus-service not available")

    def show_firewall_editor(self):
        editor = FirewallEditor()
        editor.rule_change.connect(self.firewall_update)
        editor.exec_()

    def firewall_update(self):
        self.firewall_rules_changed = True  

    def select_application(self):
        selector = AppSelector()
        selector.app_chosen.connect(self.add_bypass_app)
        selector.exec_()

    def add_bypass_app(self, app_info):
        self.bypass_dict[app_info[0]] = [app_info[1], app_info[2]]
        with open ("%s/bypass_apps.json" %HOMEDIR, "w") as save_bypass:
            json.dump(self.bypass_dict, save_bypass)
        self.pop_bypassAppList()

    def del_bypass_app(self):
        for item in self.bypassAppList.selectedItems():
            data = item.data(QtCore.Qt.UserRole)
            try:
                self.bypass_dict.pop(data, None)
                self.bypassAppList.removeItemWidget(item)
            except KeyError:
                pass
        with open ("%s/bypass_apps.json" %HOMEDIR, "w") as save_bypass:
            json.dump(self.bypass_dict, save_bypass)
        self.pop_bypassAppList()

    def pop_bypassAppList(self):
        self.bypassAppList.clear()
        for k,v in self.bypass_dict.items():
            self.Item = ServerWidget()
            self.ListItem = QtWidgets.QListWidgetItem(self.bypassAppList)
            self.ListItem.setSizeHint(QtCore.QSize(100, 50))
            self.Item.setText(k, "bypass", v[0], None, button="bypass")
            self.ListItem.setData(QtCore.Qt.UserRole, k)
            self.Item.hide_button(0)
            self.bypassAppList.addItem(self.ListItem)
            self.bypassAppList.setItemWidget(self.ListItem, self.Item)
            self.Item.item_chosen_signal.connect(self.bypass_tunnel)

    def bypass_tunnel(self, app):
        desktop_file = self.bypass_dict[app][1]
        with open (desktop_file, "r") as cmd_ret:
            search = cmd_ret.readlines()
            found = 0
            for line in search:
                if line.startswith("Exec") and found !=1:
                    #cmd = line.split("=")[1].split(" ")[0].replace("\n", "")
                    cmd = line.replace("Exec=", "").replace("\n", "")
                    cmd = re.sub(r"%[\w]", "", cmd)
                    found = 1

        temp_bash = "%s/bypass_temp.sh" %HOMEDIR
        with open (temp_bash, "w") as temp_sh:
            lines = ["#!/bin/bash \n",
                     "nohup cgexec -g net_cls:bypass_qomui %s & \n" %cmd,
                     "#test"
                     ]
            temp_sh.writelines(lines)
            temp_sh.close()
            os.chmod(temp_bash, 0o774)
        try:
            check_call([temp_bash])
        except CalledProcessError:
            self.logger.warning("Could not start %s" %app)

    def modify_server(self):
        if self.serverListWidget.isVisible() is False:
            item = self.serverListFilterWidget.currentItem()
            data = item.data(QtCore.Qt.UserRole)
            self.modify_row = self.serverListFilterWidget.row(item)
        else:
            item = self.serverListWidget.currentItem()
            data = item.data(QtCore.Qt.UserRole)
            self.modify_row = self.serverListWidget.row(item)
        try:
            editor = ModifyServer(key=data, 
                                  server_info=self.server_dict[data])
            editor.modified.connect(self.apply_edit)
            editor.exec_()
        except (UnboundLocalError, KeyError):
            pass

    def apply_edit(self, modifications):
        key = modifications["key"]
        val = modifications["info_update"]
        provider = val["provider"]
        new_config =  modifications["config_change"]
        row = self.modify_row
        self.server_dict.pop(key)
        key_update = val["name"]
        self.server_dict[key_update] = val
        rm = self.index_list.index(key)
        self.index_list.pop(rm)
        self.index_list.insert(rm, key_update)
        self.serverListWidget.takeItem(row)
        self.add_server_widget(key_update, val, insert=row)

        if val["country"] not in self.country_list:
            self.country_list.append(val["country"])
            self.countryBox.clear()
            for index, country in enumerate(sorted(self.country_list)):
                self.countryBox.addItem(country)
                self.countryBox.setItemText(index, country)

        with open ("%s/server.json" % HOMEDIR, "w") as s:
            json.dump(self.server_dict, s) 

        if len(new_config) != 0:
            try:
                if provider in SUPPORTED_PROVIDERS:
                    temp_file = "%s/temp/%s_config" %(HOMEDIR, provider)
                    with open(temp_file, "w") as config_change:
                        config_change.writelines(new_config)
                else:
                    temp_file = "%s/temp/%s" %(HOMEDIR, val["path"].split("/")[1])
                    if modifications["apply_all"] == 1:
                        for k, v in self.server_dict.items():
                            if v["provider"] == provider:
                                path = "%s/temp/%s" %(HOMEDIR, v["path"].split("/")[1])
                                with open(path, "w") as config_change:
                                    index = modifications["index"]
                                    rpl = new_config[index].split(" ")
                                    ip_insert = "%s %s %s" %(rpl[0], v["ip"], rpl[2])
                                    new_config[index] = ip_insert
                                    config_change.writelines(new_config)

                self.qomui_service.copy_rootdir("CHANGE_%s" %provider, "%s/temp" %(HOMEDIR))

            except FileNotFoundError:
                pass

    def search_listitem(self, key):
        for row in range(self.serverListWidget.count()):
            if self.serverListWidget.item(row).data(QtCore.Qt.UserRole) == key:
                return row

class ServerWidget(QtWidgets.QWidget):
    item_chosen_signal = QtCore.pyqtSignal(str)
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
        spacerItem = QtWidgets.QSpacerItem(105, 20, 
                                           QtWidgets.QSizePolicy.Expanding, 
                                           QtWidgets.QSizePolicy.Minimum
                                           )
        self.horizontalLayout.addItem(spacerItem)
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
                flag = '%s/flags/%s.png' % (ROOTDIR, country)
                if not os.path.isfile(flag):
                    flag = '%s/flags/Unknown.png' % ROOTDIR
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
        self.item_chosen_signal.emit(self.name)

    def display_latency(self, latency):
        self.latency = latency
        if self.city != "":
            self.cityLabel.setText("%s - %s" %(self.city, self.latency))
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
        self.activeHopWidget.item_chosen_signal.connect(self.signal)

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

class WaitBarWidget(QtWidgets.QWidget):
    def __init__ (self, parent=None):
        super(WaitBarWidget, self).__init__(parent)
        self.setupUi(self)

    def setupUi(self, WaitBarWidget):
        self.horizontalLayout = QtWidgets.QHBoxLayout(WaitBarWidget)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.taskLabel = QtWidgets.QLabel(WaitBarWidget)
        self.taskLabel.setObjectName(_fromUtf8("taskLabel"))
        bold_font = QtGui.QFont()
        bold_font.setPointSize(13)
        bold_font.setBold(True)
        bold_font.setWeight(75)
        self.taskLabel.setFont(bold_font)
        self.horizontalLayout.addWidget(self.taskLabel)
        self.waitBar = QtWidgets.QProgressBar(WaitBarWidget)
        self.waitBar.setObjectName(_fromUtf8("waitBar"))
        self.horizontalLayout.addWidget(self.waitBar)
        self.waitBar.setRange(0, 0)

    def setText(self, text):
        self.taskLabel.setText(_translate("WaitBarWidget", text, None))

class ActiveWidget(QtWidgets.QWidget):
    disconnect = QtCore.pyqtSignal()
    reconnect = QtCore.pyqtSignal()

    def __init__ (self, parent=None):
        super(ActiveWidget, self).__init__(parent)
        self.setupUi(self)

    def setupUi(self, ConnectionWidget):
        ConnectionWidget.setObjectName(_fromUtf8("ConnectionWidget"))
        self.verticalLayout = QtWidgets.QVBoxLayout(ConnectionWidget)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
        self.statusLabel = QtWidgets.QLabel(ConnectionWidget)
        bold_font = QtGui.QFont()
        bold_font.setPointSize(13)
        bold_font.setBold(True)
        bold_font.setWeight(75)
        self.statusLabel.setFont(bold_font)
        self.statusLabel.setObjectName(_fromUtf8("statusLabel"))
        self.horizontalLayout_3.addWidget(self.statusLabel)
        spacerItem = QtWidgets.QSpacerItem(40, 20, 
                                           QtWidgets.QSizePolicy.Expanding, 
                                           QtWidgets.QSizePolicy.Minimum
                                           )
        self.horizontalLayout_3.addItem(spacerItem)
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
        spacerItem2 = QtWidgets.QSpacerItem(40, 20, 
                                            QtWidgets.QSizePolicy.Expanding, 
                                            QtWidgets.QSizePolicy.Minimum
                                            )
        self.horizontalLayout.addItem(spacerItem2)
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
        self.ServerWidget.item_chosen_signal.connect(self.signal)

    def retranslateUi(self, ConnectionWidget):
        ConnectionWidget.setWindowTitle(_translate("ConnectionWidget", "Form", None))
        self.statusLabel.setText(_translate("ConnectionWidget", "Active Connection", None))
        self.downloadLabel.setText(_translate("ConnectionWidget", "Download:", None))
        self.uploadLabel.setText(_translate("ConnectionWidget", "Upload:", None))
        self.timeLabel.setText(_translate("ConnectionWidget", "Time:", None))

    def setText(self, server_dict, hop_dict, tun, tun_hop=None):
        self.tun = tun
        self.tun_hop = tun_hop
        self.statusLabel.setText("Active Connection")
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
        self.calcThread = NetMon(self.tun, self.tun_hop)
        self.calcThread.stat.connect(self.show_stats)
        self.calcThread.ip.connect(self.show_ip)
        self.calcThread.time.connect(self.update_time)
        self.calcThread.lost.connect(self.reconnect_signal)
        self.calcThread.start()

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
                city = "%s -" %city
        except KeyError:
            city = ""

        return "%s %s %s" %(city, protocol, port)

    def show_ip(self, ip):
        self.statusLabel.setText("Active connection - IP: %s" %ip)

    def update_time(self, t):
        self.timeStatLabel.setText(t)

    def show_stats(self, update):
        DLrate = update[0]
        DLacc = update[1]
        ULrate = update[2]
        ULacc = update[3]
        self.upStatLabel.setText("%s kB/s - %s mb" % (round(ULrate, 1), round(ULacc, 1)))
        self.downStatLabel.setText("%s kB/s - %s mb" % (round(DLrate, 1), round(DLacc, 1)))

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

class NetMon(QtCore.QThread):
    stat = QtCore.pyqtSignal(list)
    ip = QtCore.pyqtSignal(str)
    time = QtCore.pyqtSignal(str)
    lost = QtCore.pyqtSignal()

    def __init__(self, tun, tun_hop=None):
        QtCore.QThread.__init__(self)
        self.tun = tun
        self.tun_hop = tun_hop

    def run(self):
        connected = True
        check_url = "https://ipinfo.io/ip"
        try:
            ip = requests.get(check_url).content.decode("utf-8").split("\n")[0]
            self.ip.emit(ip)
        except:
            logging.debug("Could not determine external ip address")

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
        self.lost.emit()

    def time_format(self, e):
        calc = '{:02d}d {:02d}h {:02d}m {:02d}s'.format(e // 86400,
                                                        (e % 86400 // 3600), 
                                                        (e % 3600 // 60), 
                                                        e % 60
                                                        )
        split = calc.split(" ")
        if split[0] == "00d" and split[1] == "00h":
            return ("%s %s" % (split[2], split[3]))
        elif split[0] == "00d" and split[1] != "00h":
            return ("%s %s" % (split[1], split[2]))
        else:
            return ("%s %s" % (split[0], split[1]))

class FirewallEditor(QtWidgets.QDialog):
    rule_change = QtCore.pyqtSignal()

    def __init__ (self, parent=None):
        super(FirewallEditor, self).__init__(parent)
        try:
            with open('%s/firewall.json' %ROOTDIR, 'r') as fload:
                self.firewall_dict = json.load(fload)
        except FileNotFoundError:
            with open('%s/firewall_default.json' %ROOTDIR, 'r') as fload:
                self.firewall_dict = json.load(fload)

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
        spacerItem = QtWidgets.QSpacerItem(40, 20, 
                                           QtWidgets.QSizePolicy.Expanding,
                                           QtWidgets.QSizePolicy.Minimum
                                           )
        self.horizontalLayout.addItem(spacerItem)
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
        QtCore.QMetaObject.connectSlotsByName(Form)
        self.cancelButton.clicked.connect(self.cancel)
        self.saveButton.clicked.connect(self.save_rules)
        self.restoreButton.clicked.connect(self.restore)

    def retranslateUi(self, Form):
        Form.setWindowTitle(_translate("Form", "Edit firewall", None))
        self.headerLabel.setText(_translate("Form", "Edit firewall rules", None))
        self.warnLabel.setText(_translate("Form", "Warning: Only for advanced users ", None))
        self.ipv4Label.setText(_translate("Form", "IPv4 rules", None))
        self.ipv6Label.setText(_translate("Form", "IPv6 rules", None))
        self.saveButton.setText(_translate("Form", "Save", None))
        self.saveButton.setIcon(QtGui.QIcon.fromTheme("dialog-ok"))
        self.cancelButton.setText(_translate("Form", "Cancel", None))
        self.cancelButton.setIcon(QtGui.QIcon.fromTheme("dialog-no"))
        self.restoreButton.setText(_translate("Form", "Restore defaults", None))
        self.restoreButton.setIcon(QtGui.QIcon.fromTheme("view-refresh"))

    def display_rules(self):
        for rule in self.firewall_dict["ipv4rules"]:
            self.ipv4Edit.appendPlainText(' '.join(rule))
        for rule in self.firewall_dict["ipv6rules"]:
            self.ipv6Edit.appendPlainText(' '.join(rule))

    def restore(self):
        self.ipv4Edit.clear()
        self.ipv6Edit.clear()
        with open('%s/firewall_default.json' %ROOTDIR, 'r') as fload:
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

        with open ("%s/firewall_temp.json" % HOMEDIR, "w") as firedump:
                json.dump(self.firewall_dict, firedump)

        self.rule_change.emit()
        self.hide()

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
        directories = ["%s/.local/share/applications" % (os.path.expanduser("~")),
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
                                self.bypassAppList.append((name, icon, desktop_file))
                        except KeyError:
                            name = c["Desktop Entry"]["Name"]
                            icon = c["Desktop Entry"]["Icon"]
                            self.bypassAppList.append((name, icon, desktop_file))
            except:
                pass

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
                                             "Apply changes to all configuration files of %s" %self.provider))

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
            config = "%s/%s_config" %(ROOTDIR, self.provider)
        else:
            config = "%s/%s" %(ROOTDIR, self.server_info["path"])

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
                line_format = "%s\n" %(line)
                new_config[index] = line_format
            if new_config != self.old_config:
                if self.provider in SUPPORTED_PROVIDERS:
                    temp_file = "%s_config" %self.provider
                else:
                    temp_file = self.server_info["path"].split("/")[1]
                temp_folder = "%s/temp" % HOMEDIR
                if not os.path.exists(temp_folder):
                    os.makedirs(temp_folder)
                with open("%s/%s" %(temp_folder, temp_file), "w") as update_config:
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


def main():
    if not os.path.exists("%s/.qomui" % (os.path.expanduser("~"))):
        os.makedirs("%s/.qomui" % (os.path.expanduser("~")))
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    app = QtWidgets.QApplication(sys.argv)
    DBusQtMainLoop(set_as_default=True)
    ex = QomuiGui()
    ex.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
