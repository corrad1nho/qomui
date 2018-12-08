#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import json
import re
import dbus
import shutil
import time
import random
import logging
from functools import partial
from datetime import datetime, date
from subprocess import CalledProcessError, check_call, check_output
from PyQt5 import QtCore, QtWidgets, QtGui
from dbus.mainloop.pyqt5 import DBusQtMainLoop
import bisect
import signal

from qomui import update, latency, utils, firewall, widgets, profiles


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
SUPPORTED_PROVIDERS = ["Airvpn", "Mullvad", "ProtonVPN", "PIA", "Windscribe"]
JSON_FILE_LIST = [("config_dict", "{}/config.json".format(ROOTDIR)),
                  ("server_dict", "{}/server.json".format(HOMEDIR)),
                  ("protocol_dict", "{}/protocol.json".format(HOMEDIR)),
                  ("bypass_dict", "{}/bypass_apps.json".format(HOMEDIR)),
                  ("profile_dict", "{}/profile.json".format(HOMEDIR))
                  ]

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

class QomuiGui(QtWidgets.QWidget):
    network_state = 0
    server_dict = {}
    protocol_dict = {}
    profile_dict = {}
    country_list = ["All countries"]
    provider_list = ["All providers"]
    firewall_rules_changed = False
    hop_active = 0
    tun_hop = None
    ovpn_dict = None
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
                   "auto_update"
                   ]

    routes = {       
            "gateway" : "None",
            "gateway_6" : "None",
            "interface" : "None",
            "interface_6" : "None"
            }

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

            ret = self.messageBox(
                                "Error: Qomui-service is not active",
                                "Do you want to start it, enable it permanently or close Qomui?",
                                buttons = [
                                            ("Enable", "NoRole"),
                                            ("Start", "YesRole"),
                                            ("Close", "RejectRole")
                                            ],
                                icon = "Question"
                                )

            if ret == 0:

                try:
                    check_call(["pkexec", "systemctl", "enable", "--now", "qomui"])
                    self.qomui_dbus = self.dbus.get_object('org.qomui.service',
                                                           '/org/qomui/service'
                                                           )

                except (CalledProcessError, FileNotFoundError):
                    self.notify("Error", "Failed to start qomui-service", icon="Error")
                    sys.exit(1)

            elif ret == 1:

                try:
                    check_call(["pkexec", "systemctl", "start", "qomui.service"])
                    self.qomui_dbus = self.dbus.get_object('org.qomui.service', '/org/qomui/service')

                except (CalledProcessError, FileNotFoundError):
                    self.notify("Error", "Failed to start qomui-service", icon="Error")
                    sys.exit(1)

            elif ret == 2:
                sys.exit(1)

        self.qomui_service = dbus.Interface(self.qomui_dbus, 'org.qomui.service')
        self.qomui_service.connect_to_signal("send_log", self.receive_log)
        self.qomui_service.connect_to_signal("reply", self.openvpn_log_monitor)
        self.qomui_service.connect_to_signal("updated", self.restart)
        self.qomui_service.connect_to_signal("imported", self.downloaded)
        self.qomui_service.connect_to_signal("progress_bar", self.start_progress_bar)

        handler = DbusLogHandler(self.qomui_service)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)
        primay_screen = QtWidgets.QDesktopWidget().primaryScreen()
        primary_screen_geometry = QtWidgets.QDesktopWidget().availableGeometry(primay_screen)
        positioning = primary_screen_geometry.bottomRight()
        self.setGeometry(QtCore.QRect(positioning.x()-600, positioning.y()-750,
                                      600, 750
                                      ))

        self.qomui_service.disconnect("main")
        self.qomui_service.disconnect("bypass")
        self.qomui_service.save_default_dns()
        self.load_saved_files()
        self.systemtray()

        self.net_mon_thread = NetMon()
        self.net_mon_thread.log.connect(self.log_from_thread)
        self.net_mon_thread.net_state_change.connect(self.network_change)
        self.net_mon_thread.start()

    def receive_log(self, msg):
        self.logText.appendPlainText(msg)

    def setupUi(self, Form):
        Form.setObjectName(_fromUtf8("Form"))
        self.gridLayout = QtWidgets.QGridLayout(Form)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.showActive = widgets.ActiveWidget("Active Connection", Form)
        self.gridLayout.addWidget(self.showActive, 0, 0, 1, 2)
        self.showActive.setVisible(False)
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.gridLayout.addLayout(self.verticalLayout_2, 1, 0, 1, 2)
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
        self.profileTabBt = QtWidgets.QCommandLinkButton(Form)
        self.profileTabBt.setMinimumSize(QtCore.QSize(100, 0))
        self.profileTabBt.setMaximumSize(QtCore.QSize(100, 100))
        self.profileTabBt.setCheckable(True)
        self.tabButtonGroup.addButton(self.profileTabBt)
        self.profileTabBt.setObjectName(_fromUtf8("profileTabBt"))
        self.verticalLayout_3.addWidget(self.profileTabBt)
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
        self.verticalLayout_3.addStretch()
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
        self.favouriteButton = widgets.favouriteButton(self.serverTab)
        self.favouriteButton.setCheckable(True)
        self.favouriteButton.setMinimumSize(QtCore.QSize(25, 25))
        self.favouriteButton.setMaximumSize(QtCore.QSize(25, 25))
        self.favouriteButton.setObjectName(_fromUtf8("favouriteButton"))
        self.horizontalLayout_3.addWidget(self.favouriteButton)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        self.searchLine = QtWidgets.QLineEdit(self.serverTab)
        self.searchLine.setObjectName(_fromUtf8("searchLine"))
        self.verticalLayout.addWidget(self.searchLine)
        self.serverListWidget = QtWidgets.QListWidget(self.serverTab)
        self.serverListWidget.setObjectName(_fromUtf8("serverListWidget"))
        self.serverListWidget.setBatchSize(10)
        self.serverListWidget.setUniformItemSizes(True)
        self.verticalLayout.addWidget(self.serverListWidget)
        self.showHop = widgets.HopWidget(self.serverTab)
        self.showHop.setVisible(False)
        self.verticalLayout.addWidget(self.showHop)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.horizontalLayout.addStretch()
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
        self.profileTab = QtWidgets.QWidget()
        self.profileTab.setObjectName(_fromUtf8("profileTab"))
        self.verticalLayout50 = QtWidgets.QVBoxLayout(self.profileTab)
        self.verticalLayout50.setObjectName("verticalLayout50")
        self.scrollProfiles = QtWidgets.QScrollArea()
        self.scrollProfiles.setWidgetResizable(True)
        self.scrollProfiles.setObjectName("scrollProfiles")
        self.scrollProfilesContents = QtWidgets.QWidget(self.scrollProfiles)
        self.scrollProfilesContents.setObjectName("scrollProfilesContents")
        self.verticalLayout_58 = QtWidgets.QVBoxLayout(self.scrollProfilesContents)
        self.verticalLayout_58.addStretch()
        self.scrollProfiles.setWidget(self.scrollProfilesContents)
        self.verticalLayout50.addWidget(self.scrollProfiles)
        self.horizontalLayout50 = QtWidgets.QHBoxLayout()
        self.horizontalLayout50.setObjectName("horizontalLayout50")
        spacerItem = QtWidgets.QSpacerItem(368, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout50.addItem(spacerItem)
        self.addProfileBt = QtWidgets.QPushButton(self.profileTab)
        self.addProfileBt.setObjectName("addProfileBt")
        self.horizontalLayout50.addWidget(self.addProfileBt)
        self.verticalLayout50.addLayout(self.horizontalLayout50)
        self.tabWidget.addWidget(self.profileTab)
        self.logTab = QtWidgets.QWidget()
        self.logTab.setObjectName(_fromUtf8("logTab"))
        self.gridLayout_2 = QtWidgets.QGridLayout(self.logTab)
        self.gridLayout_2.setObjectName(_fromUtf8("gridLayout_2"))
        self.logText = QtWidgets.QPlainTextEdit(self.logTab)
        self.logText.setReadOnly(True)
        self.gridLayout_2.addWidget(self.logText, 0, 0, 1, 4)
        self.logBox = QtWidgets.QComboBox(self.logTab)
        self.logBox.setObjectName(_fromUtf8("logBox"))
        self.gridLayout_2.addWidget(self.logBox, 1, 3, 1, 1)
        self.tabWidget.addWidget(self.logTab)
        self.optionsTab = QtWidgets.QScrollArea()
        self.optionsTab.setWidgetResizable(True)
        self.optionsTab.setObjectName(_fromUtf8("optionsTab"))
        self.tabWidget.addWidget(self.optionsTab)
        self.optionsTab.setObjectName("optionsTab")
        self.optionsTabWidgetContents = QtWidgets.QWidget()
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.optionsTabWidgetContents)
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
        self.auto_updateOptCheck = QtWidgets.QCheckBox(self.optionsTab)
        self.auto_updateOptCheck.setObjectName(_fromUtf8("auto_updateOptCheck"))
        self.auto_updateOptCheck.setFont(bold_font)
        self.verticalLayout_5.addWidget(self.auto_updateOptCheck)
        self.auto_updateOptLabel = QtWidgets.QLabel(self.optionsTab)
        self.auto_updateOptLabel.setObjectName(_fromUtf8("auto_updateOptLabel"))
        self.auto_updateOptLabel.setWordWrap(True)
        self.auto_updateOptLabel.setIndent(20)
        self.auto_updateOptLabel.setFont(italic_font)
        self.verticalLayout_5.addWidget(self.auto_updateOptLabel)
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
        self.horizontalLayout_9.addStretch()
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
        self.verticalLayout_5.addStretch()
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setObjectName(_fromUtf8("horizontalLayout_6"))
        self.horizontalLayout_6.addStretch()
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
        self.optionsTab.setWidget(self.optionsTabWidgetContents)
        self.providerTab = QtWidgets.QScrollArea()
        self.providerTab.setObjectName(_fromUtf8("providerTab"))
        self.providerTab.setMaximumHeight(1000)
        self.verticalLayout_30 = QtWidgets.QVBoxLayout(self.providerTab)
        self.verticalLayout_30.setObjectName("verticalLayout_30")
        self.providerTab.setWidgetResizable(True)
        self.providerTabContents= QtWidgets.QWidget()
        self.providerTabContents.setObjectName("providerTabContents")
        self.verticalLayout_30 = QtWidgets.QVBoxLayout(self.providerTabContents)
        self.providerTab.setWidget(self.providerTabContents)
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
        self.gridLayout_3 = QtWidgets.QGridLayout()
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
        self.horizontalLayout_32.addStretch()
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
        self.overrideCheck = QtWidgets.QCheckBox(self.providerTab)
        self.overrideCheck.setObjectName("overrideCheck")
        self.overrideCheck.setVisible(False)
        self.verticalLayout_30.addWidget(self.overrideCheck)
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
        self.horizontalLayout_31.addStretch()
        self.scriptLabel = QtWidgets.QLabel(self.providerTab)
        self.scriptLabel.setFont(bold_font)
        self.scriptLabel.setObjectName("scriptLabel")
        self.verticalLayout_30.addWidget(self.scriptLabel)
        self.gridLayout10 = QtWidgets.QGridLayout(Form)
        self.gridLayout10.setObjectName("gridLayout")
        self.preCheck = QtWidgets.QLabel(Form)
        self.preCheck.setObjectName("preCheck")
        self.gridLayout10.addWidget(self.preCheck, 0, 0, 1, 1)
        self.preEdit = QtWidgets.QLineEdit(Form)
        self.preEdit.setObjectName("preEdit")
        self.gridLayout10.addWidget(self.preEdit, 0, 1, 1, 1)
        self.upCheck = QtWidgets.QLabel(Form)
        self.upCheck.setObjectName("upCheck")
        self.gridLayout10.addWidget(self.upCheck, 1, 0, 1, 1)
        self.upEdit = QtWidgets.QLineEdit(Form)
        self.upEdit.setObjectName("upEdit")
        self.gridLayout10.addWidget(self.upEdit, 1, 1, 1, 1)
        self.downCheck = QtWidgets.QLabel(Form)
        self.downCheck.setObjectName("downCheck")
        self.gridLayout10.addWidget(self.downCheck, 2, 0, 1, 1)
        self.downEdit = QtWidgets.QLineEdit(Form)
        self.downEdit.setObjectName("downEdit")
        self.gridLayout10.addWidget(self.downEdit, 2, 1, 1, 1)
        self.verticalLayout_30.addLayout(self.gridLayout10)
        self.horizontalLayout_32 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_32.setObjectName("horizontalLayout_32")
        spacerItem3 = QtWidgets.QSpacerItem(40, 20,
                                            QtWidgets.QSizePolicy.Expanding,
                                            QtWidgets.QSizePolicy.Minimum
                                            )
        self.horizontalLayout_32.addItem(spacerItem3)
        self.confirmScripts = QtWidgets.QDialogButtonBox(self.providerTab)
        self.confirmScripts.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Save)
        self.confirmScripts.setObjectName("confirmScripts")
        self.horizontalLayout_32.addWidget(self.confirmScripts)
        self.verticalLayout_30.addLayout(self.horizontalLayout_32)
        self.verticalLayout_30.addStretch()
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
        self.horizontalLayout_11= QtWidgets.QHBoxLayout()
        self.horizontalLayout_11.setObjectName(_fromUtf8("horizontalLayout_11"))
        self.bypassVpnBox = QtWidgets.QComboBox(self.bypassTab)
        self.bypassVpnBox.setObjectName(_fromUtf8("bypassVpnBox"))
        self.horizontalLayout_11.addWidget(self.bypassVpnBox)
        self.bypassVpnButton = QtWidgets.QPushButton(self.bypassTab)
        self.bypassVpnButton.setObjectName(_fromUtf8("bypassVpnButton"))
        self.bypassVpnButton.setMaximumWidth(120)
        self.horizontalLayout_11.addWidget(self.bypassVpnButton)
        self.verticalLayout_8.addLayout(self.horizontalLayout_11)
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
        self.profileTabBt.clicked.connect(self.tab_switch)
        self.providerTabBt.clicked.connect(self.tab_switch)
        self.applyOptBt.clicked.connect(self.read_option_change)
        self.cancelOptBt.clicked.connect(self.cancelOptions)
        self.restoreDefaultOptBt.clicked.connect(self.restoreDefaults)
        self.firewallEditBt.clicked.connect(self.show_firewall_editor)
        self.addBypassAppBt.clicked.connect(self.select_application)
        self.delBypassAppBt.clicked.connect(self.del_bypass_app)
        self.favouriteButton.toggled.connect(self.show_favourite_servers)
        self.overrideCheck.toggled.connect(self.override_protocol_show)
        self.delProviderBt.clicked.connect(self.del_provider)
        self.addProviderBox.activated[str].connect(self.providerChosen)
        self.addProviderDownloadBt.clicked.connect(self.add_server_configs)
        self.randomSeverBt.clicked.connect(self.choose_random_server)
        self.savePortButton.clicked.connect(self.override_protocol)
        self.modify_serverBt.clicked.connect(self.modify_server)
        self.updateQomuiBt.clicked.connect(self.update_qomui)
        self.logBox.activated[str].connect(self.log_level)
        self.searchLine.textEdited[str].connect(self.filter_by_text)
        self.bypassVpnButton.clicked.connect(self.set_bypass_vpn)
        self.addProfileBt.clicked.connect(self.add_profile)
        self.confirmScripts.accepted.connect(self.save_scripts)
        self.confirmScripts.rejected.connect(self.clear_scripts)

    def retranslateUi(self, Form):
        s = ""
        Form.setWindowTitle(_translate("Form", "Qomui", None))
        self.serverTabBt.setText(_translate("Form", "Server", None))
        self.logTabBt.setText(_translate("Form", "Log", None))
        self.profileTabBt.setText(_translate("Form", "Profiles", None))
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
        self.auto_updateOptCheck.setText(_translate("Form", "Auto-update", None))
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
        self.firewallEditBt.setText(_translate("Form", "Configure firewall", None))
        self.bypassVpnButton.setText(_translate("Form", "Connect", None))
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
        self.overrideCheck.setText(_translate("Form",
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
        self.searchLine.setPlaceholderText(_translate("Form", "Search", None))
        self.preCheck.setText(_translate("Form", "Pre:", None))
        self.upCheck.setText(_translate("Form", "Up:", None))
        self.downCheck.setText(_translate("Form", "Down:", None))
        self.addProfileBt.setText(_translate("Form", "Add Profile", None))
        self.addProfileBt.setIcon(QtGui.QIcon.fromTheme("list-add"))
        self.preEdit.setPlaceholderText("Enter script path")
        self.upEdit.setPlaceholderText("Enter script path")
        self.downEdit.setPlaceholderText("Enter script path")
        self.scriptLabel.setText(_translate("Form", "Add custom scripts:", None))

        self.autoconnectOptLabel.setText(_translate("Form",
                                          "Automatically (re-)connect to last server",
                                          None))
        self.minimizeOptLabel.setText(_translate("Form",
                                          "Only works if system tray is available",
                                          None))
        self.auto_updateOptLabel.setText(_translate("Form",
                                          "Enable automatic updates for supported providers",
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

        text = 'Add and start applications you want to bypass the VPN tunnel \
                from the list below. The same can be achieved via console by \
                prepending "cgexec -g net_cls:bypass_qomui $yourcommand". \
                Be aware that some applications such as Firefox will not launch \
                a second instance. Optionally, you can choose a starred server \
                to start a second OpenVPN session for bypass applications below.'

        self.bypassInfoLabel.setText(_translate("Form",
                                          s.join(text.replace("    ", "")),
                                          None))

        for provider in SUPPORTED_PROVIDERS:
            self.addProviderBox.addItem(provider)
        self.addProviderBox.addItem("Manually add config file folder")

        self.logBox.addItem("Info")
        self.logBox.addItem("Debug")

    def notify(self, header, text, icon="Question"):

        try:
            check_call(["notify-send", header, text, "--icon=dialog-{}".format(icon.lower())])

        except (CalledProcessError, FileNotFoundError):
            self.logger.warning("Desktop notifications not available")
            
    def messageBox(self, header, text, buttons=[], icon="Question"):
        box = QtWidgets.QMessageBox(self)
        box.setText(header)
        box.setInformativeText(text)
        box.setIcon(getattr(QtWidgets.QMessageBox, icon))

        for button in buttons:
            box.addButton(
                        QtWidgets.QPushButton(button[0]),
                        getattr(QtWidgets.QMessageBox, button[1])
                        )

        ret = box.exec_()
        return ret

    def log_level(self, level):
        self.logger.setLevel(getattr(logging, level.upper()))
        self.qomui_service.log_level_change(level)

    def restart(self, new_version):
        self.stop_progress_bar("upgrade")

        if new_version != "failed":
            self.versionInfo.setText(new_version)
            self.newVersionLabel.setVisible(False)
            self.updateQomuiBt.setVisible(False)
            ret = self.messageBox(
                                  "Qomui has been upgraded",
                                  "Do you want to restart Qomui?",
                                  buttons=[("Later", "NoRole"), ("Now", "YesRole")],
                                  icon = "Question"
                                  )

            if ret == 1:
                self.restart_qomui()

        else:
            self.notify(
                        "Upgrade failed",
                        "See log for further details",
                        icon="Error")

    def restart_qomui(self):
        self.kill()
        self.disconnect_bypass()

        try:
            systemctl_check = check_call(["systemctl", "is-active", "--quiet", "qomui"])

            if systemctl_check == 0:
                self.logger.debug("Qomui-service running as systemd service - restarting")
                self.notify("Qomui", "Restarting Qomui now...", icon="Information")
                self.qomui_service.restart()
                os.execl(sys.executable, sys.executable, * sys.argv)

            else:
                self.logger.debug("No instance of qomui-service running with systemd found")
                self.notify(
                            "Restarting qomui-service failed",
                            "Please restart qomui-gui and qomui-service manually",
                            icon="Error"
                            )

        except CalledProcessError as e:
            self.logger.debug("No instance of qomui-service running with systemd found")
            self.notify(
                        "Restarting qomui-service failed",
                        "Please restart qomui-gui and qomui-service manually",
                        icon="Error"
                        )


    def check_update(self):
        if self.packetmanager in ["None", "DEB", "RPM"]:
            self.check_thread = update.UpdateCheck()
            self.check_thread.log.connect(self.log_from_thread)
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
                self.updateQomuiBt.setText("Upgrade to {}".format(self.release))
                self.updateQomuiBt.setVisible(True)
                self.newVersionLabel.setVisible(True)

                self.notify(
                            'Qomui: Update available',
                            'Download version {} via "About" tab'.format(self.release),
                            icon="Information"
                            )

        except ValueError:
            pass

    def update_qomui(self):
        self.qomui_service.update_qomui(self.release, self.packetmanager)
        self.start_progress_bar("upgrade")

    def tab_switch(self):
        button = self.sender().text().replace("&", "")
        if button == "Server":
            self.tabWidget.setCurrentIndex(0)
        elif button == "Profiles":
            self.tabWidget.setCurrentIndex(1)
        elif button == "Log":
            self.tabWidget.setCurrentIndex(2)
            self.logText.verticalScrollBar().setValue(self.logText.verticalScrollBar().maximum())
        elif button == "Options":
            self.setOptiontab(self.config_dict)
            self.tabWidget.setCurrentIndex(3)
        elif button == "Provider":
            self.tabWidget.setCurrentIndex(4)
        elif button == "Bypass":
            self.tabWidget.setCurrentIndex(5)
            self.bypassVpnBox.clear()

            for k, v in self.server_dict.items():
                if "favourite" in v:
                    if v["favourite"] == "on":
                        self.bypassVpnBox.addItem(k)

        elif button == "About":
            self.tabWidget.setCurrentIndex(6)
            self.check_update()

    def switch_providerTab(self):
        self.tabWidget.setCurrentIndex(4)

    def systemtray(self):
        self.trayIcon = QtGui.QIcon.fromTheme("qomui")
        self.tray = QtWidgets.QSystemTrayIcon()

        if self.tray.isSystemTrayAvailable() == False:
            self.setWindowState(QtCore.Qt.WindowActive)
            self.showNormal()
        else:
            self.tray.setIcon(self.trayIcon)
            self.trayMenu = QtWidgets.QMenu()
            show = self.trayMenu.addAction("Show")
            self.trayMenu.addSeparator()
            for p,v in self.profile_dict.items():
                name = self.trayMenu.addAction(v["name"])
                name.triggered.connect(partial(self.connect_profile, p))
            self.trayMenu.addSeparator()
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
        self.confirm.setText("Do you really want to quit Qomui?")
        info = "Closing in {} seconds".format(self.timeout)
        self.confirm.setInformativeText(info)
        self.confirm.setIcon(QtWidgets.QMessageBox.Question)
        self.confirm.addButton(QtWidgets.QPushButton("Exit"), QtWidgets.QMessageBox.YesRole)
        self.confirm.addButton(QtWidgets.QPushButton("Cancel"), QtWidgets.QMessageBox.NoRole)
        if self.tray.isSystemTrayAvailable() == True:
            self.confirm.addButton(QtWidgets.QPushButton("Minimize"), QtWidgets.QMessageBox.RejectRole)
        self.exit_timer = QtCore.QTimer(self)
        self.exit_timer.setInterval(1000)
        self.exit_timer.timeout.connect(self.change_timeout)
        self.exit_timer.start()

        ret = self.confirm.exec_()
        self.exit_timer.stop()

        if ret == 1:
            self.exit_event.ignore()

        elif ret == 2:
            self.hide()

        elif ret == 0:
            self.tray.hide()
            self.kill()
            self.disconnect_bypass()
            self.qomui_service.load_firewall(2)
            with open ("{}/server.json".format(HOMEDIR), "w") as s:
                json.dump(self.server_dict, s)
            self.exit_event.accept()

    def change_timeout(self):
        self.timeout -= 1
        info = "Closing in {} seconds".format(self.timeout)
        self.confirm.setInformativeText(info)
        if self.timeout <= 0:
            self.exit_timer.stop()
            self.confirm.hide()
            self.tray.hide()
            self.kill()
            self.disconnect_bypass()
            self.exit_event.accept()

    def load_json(self, json_file):
        try:
            with open(json_file, 'r') as j:
                return json.load(j)

        except (FileNotFoundError,json.decoder.JSONDecodeError) as e:
            self.logger.warning('{}: Could not open {}'.format(e, json_file))
            return {}

    def connect_last_server(self):
        try:
            if self.config_dict["autoconnect"] == 1:
                self.kill()
                self.disconnect_bypass()
                last_server_dict = self.load_json("{}/last_server.json".format(HOMEDIR))

                if self.network_state == 1:

                    if "last" in last_server_dict.keys():
                        self.ovpn_dict = last_server_dict["last"]

                        if "hop" in last_server_dict.keys():
                            if last_server_dict["hop"] is not None:
                                self.hop_server_dict = last_server_dict["hop"]
                                self.show_hop_widget()

                        try:
                            if self.ovpn_dict["random"] == "on":
                                self.choose_random_server()
                        
                        except KeyError:

                            if "profile" in self.ovpn_dict.keys():
                                self.connect_profile(self.ovpn_dict["profile"])
                            
                            else:
                                self.establish_connection(self.ovpn_dict)

                        try:
                            if self.ovpn_dict["favourite"] == "on":
                                self.favouriteButton.setChecked(True)

                        except KeyError:
                            pass

                    if "bypass" in last_server_dict.keys():
                        self.bypass_ovpn_dict = last_server_dict["bypass"]
                        self.establish_connection(self.bypass_ovpn_dict, bar="_bypass")

        except KeyError:
            pass

    def load_saved_files(self):
        try:
            with open("{}/VERSION".format(ROOTDIR), "r") as v:
                version = v.read().split("\n")
                self.installed = version[0]
                self.logger.info("Qomui version {}".format(self.installed))

                try:
                    service_version = self.qomui_service.get_version()

                except dbus.exceptions.DBusException:
                    service_version = self.installed
                    self.logger.error("Checking version of qomui-service failed")

                if service_version != self.installed and service_version != "None":
                    self.notify(
                                "Qomui: Version discrepancy detected",
                                "Qomui-Gui and qomui-service not running the same version",
                                icon="Warning")
                    self.logger.warning("qomui-service is running different version than qomui-gui: {} vs {}".format(service_version,
                                                                                                                    self.installed))
                    self.logger.info("Restarting qomui-gui and qomui-service")
                    self.restart_qomui()

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
            self.logger.warning("{}/VERSION does not exist".format(ROOTDIR))
            self.versionInfo.setText("N.A.")

        for saved_file in JSON_FILE_LIST:
            setattr(self, saved_file[0], self.load_json(saved_file[1]))

        if not bool(self.config_dict):
            setattr(self, "config_dict", self.load_json('{}/default_config.json'.format(ROOTDIR)))
            self.logger.info('Loading default configuration')

        try:
            if self.config_dict["minimize"] == 0:
                self.setWindowState(QtCore.Qt.WindowActive)

        except KeyError:
            pass

        try:
            if self.config_dict["firewall"] == 1 and self.config_dict["fw_gui_only"] == 1:
                self.qomui_service.load_firewall(1)

        except KeyError:
            pass

        try:
            self.logger.setLevel(getattr(logging, self.config_dict["log_level"].upper()))
            if self.config_dict["log_level"] == "Debug":
                self.logBox.setCurrentIndex(1)

        except KeyError:
            pass

        try:
            if self.config_dict["bypass"] == 1:
                self.bypassTabBt.setVisible(True)

        except KeyError:
            pass

        for p in self.profile_dict.keys():
            self.display_profile(p)

        self.setOptiontab(self.config_dict)
        self.pop_boxes(country='All countries')
        self.pop_bypassAppList()
        #self.connect_last_server()

    def setOptiontab(self, config):

        try:
            self.altDnsEdit1.setText(config["alt_dns1"])
            self.altDnsEdit2.setText(config["alt_dns2"])
        except KeyError:
            pass

        for k, v in config.items():
            try:
                if v == 0:
                    getattr(self, "{}OptCheck".format(k)).setChecked(False)
                elif v == 1:
                    getattr(self, "{}OptCheck".format(k)).setChecked(True)
            except AttributeError:
                pass

    def restoreDefaults(self):
        default_config_dict = self.load_json('{}/default_config.json'.format(ROOTDIR))
        self.setOptiontab(default_config_dict)

    def cancelOptions(self):
        self.setOptiontab(self.config_dict)

    def read_option_change(self):
        temp_config_dict = {}
        temp_config_dict["alt_dns1"] = self.altDnsEdit1.text().replace("\n", "")
        temp_config_dict["alt_dns2"] = self.altDnsEdit2.text().replace("\n", "")

        for option in self.config_list:
            if getattr(self, "{}OptCheck".format(option)).checkState() == 2:
                temp_config_dict[option] = 1
            elif getattr(self, "{}OptCheck".format(option)).checkState() == 0:
                temp_config_dict[option] = 0

        self.save_options(temp_config_dict)

    def save_options(self, temp_config, firewall=None):

        for k, v in self.config_dict.items():
            if k not in temp_config:
                temp_config[k] = v

        with open ('{}/config_temp.json'.format(HOMEDIR), 'w') as config:
            json.dump(temp_config, config)

        update_cmd = ['pkexec', sys.executable, '-m', 'qomui.mv_config',
                      '-d', '{}'.format(HOMEDIR)]

        if firewall is not None:
            update_cmd.append('-f')

        try:
            check_call(update_cmd)
            self.logger.info("Configuration changes applied successfully")
            self.qomui_service.load_firewall(1)
            self.qomui_service.bypass({**self.routes, **utils.get_user_group()})
            self.notify(
                        "Qomui: configuration changed",
                        "Configuration updated successfully",
                        icon="Information"
                        )

            if temp_config["ping"] == 1:
                self.get_latencies()

            if temp_config["bypass"] == 1:
                self.bypassTabBt.setVisible(True)
            else:
                self.bypassTabBt.setVisible(False)

            self.config_dict = temp_config

            return "updated"

        except CalledProcessError as e:
            self.logger.info("Non-zero exit status: configuration changes not applied")

            self.notify(
                        "Qomui: Authentication failure",
                        "Configuration not updated",
                        icon="Error"
                        )

            return "failed"

    def network_change(self, state, routes):
        self.network_state = state

        if self.network_state != 0:
            self.routes = routes
            print(self.routes)
            self.logger.info("Detected new network connection")
            self.qomui_service.save_default_dns()
            if self.config_dict["ping"] == 1:
                self.get_latencies()
            self.kill()
            self.disconnect_bypass()
            self.connect_last_server()
            self.qomui_service.bypass({**self.routes, **utils.get_user_group()})

        elif self.network_state == 0:
            self.logger.info("Lost network connection - VPN tunnel terminated")
            self.kill()
            self.disconnect_bypass()

    def providerChosen(self):
        self.addProviderUserEdit.setText("")
        self.addProviderPassEdit.setText("")
        provider = self.addProviderBox.currentText()

        p_txt = {
                "Airvpn" : ("Username", "Password"),
                "PIA" : ("Username", "Password"),
                "Windscribe" : ("Username", "Password"),
                "Mullvad" : ("Account Number", "N.A. - Leave empty"),
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
        if not os.path.exists("{}/temp".format(HOMEDIR)):
            os.makedirs("{}/temp".format(HOMEDIR))

        folderpath = "None"
        provider = self.addProviderBox.currentText()
        username = self.addProviderUserEdit.text()
        password = self.addProviderPassEdit.text()

        if provider not in SUPPORTED_PROVIDERS:
            provider = self.addProviderEdit.text()

            if provider == "":
                self.messageBox(
                                "Error",
                                "Please enter a provider name",
                                buttons=[("Ok", "YesRole")],
                                icon="Critical"
                                )

            else:

                try:
                    dialog = QtWidgets.QFileDialog.getOpenFileName(self,
                                caption="Choose Folder",
                                directory = os.path.expanduser("~"),
                                filter=self.tr('OpenVPN (*.ovpn *conf);;All files (*.*)'),
                                options=QtWidgets.QFileDialog.ReadOnly)

                    folderpath = QtCore.QFileInfo(dialog[0]).absolutePath()

                except TypeError:
                    folderpath = ""

        if folderpath != "" and provider != "":
            credentials = {
                            "provider" : provider,
                            "username" : username,
                            "password" : password,
                            "folderpath" : folderpath,
                            "homedir" : HOMEDIR
                            }

            self.addProviderUserEdit.setText("")
            self.addProviderPassEdit.setText("")
            self.qomui_service.import_thread(credentials)

    def log_from_thread(self, log):
        getattr(logging, log[0])(log[1])

    def del_provider(self):
        provider = self.delProviderBox.currentText()
        del_list = []
        ret = self.messageBox(
                        "Are you sure?", "",
                        buttons = [("No", "NoRole"), ("Yes", "YesRole")],
                        icon = "Question"
                        )

        if ret == 1:
            self.logger.info("Deleting {}".format(provider))
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

            with open ("{}/server.json".format(HOMEDIR), "w") as s:
                json.dump(self.server_dict, s)

            self.notify(
                        "Qomui: Deleted provider",
                        "Removed {} and deleted configuration files".format(provider),
                        icon="Information"
                        )

            self.pop_boxes()

    def add_profile(self, edit=0):
        dialog = profiles.EditProfile(
                                    self.tunnel_list,
                                    self.country_list,
                                    self.provider_list,
                                    selected=edit)
        dialog.save_profile.connect(self.new_profile)
        dialog.exec_()

    def del_profile(self, number):
        self.profile_dict.pop(number)
        with open ("{}/profile.json".format(HOMEDIR), "w") as s:
                json.dump(self.profile_dict, s)
        getattr(self, "{}_widget".format(number)).deleteLater()
        self.verticalLayout_58.removeWidget(getattr(self, "{}_widget".format(number)))

    def edit_profile(self, number):
        self.add_profile(edit=self.profile_dict[number])

    def new_profile(self, profile_dict):
        if "number" not in profile_dict.keys():
            n = len(self.profile_dict)
            if "profile_{}".format(n) not in self.profile_dict.keys():
                number = "profile_{}".format(n)
            elif "profile_{}".format(n-1) not in self.profile_dict.keys():
                number = "profile_{}".format(n-1)
            else:
                number = "profile_{}".format(n+1)
            self.profile_dict[number] = profile_dict
            self.profile_dict[number]["number"] = number
            self.display_profile(number)

        else:
            number = profile_dict["number"]
            self.profile_dict[number] = profile_dict
            getattr(self, "{}_widget".format(number)).setText(self.profile_dict[number])

        with open ("{}/profile.json".format(HOMEDIR), "w") as s:
                    json.dump(self.profile_dict, s)

    def display_profile(self, number):
        setattr(self, "{}_widget".format(number), profiles.ProfileWidget(self.profile_dict[number]))
        getattr(self, "{}_widget".format(number)).del_profile.connect(self.del_profile)
        getattr(self, "{}_widget".format(number)).edit_profile.connect(self.edit_profile)
        getattr(self, "{}_widget".format(number)).connect_profile.connect(self.connect_profile)
        self.verticalLayout_58.insertWidget(0, getattr(self, "{}_widget".format(number)))
        name = self.profile_dict[number]["name"]
 
    def connect_profile(self, p):
        result = None
        profile = self.profile_dict[p]
        temp_list = []
        for s, v in self.server_dict.items():
            if v["country"] in profile["countries"] and v["provider"] in profile["providers"]:
                if len(profile["filters"]) != 0:
                    for f in profile["filters"]:
                        search = "{}{}".format(s, v["city"])
                        if f.lower() in search.lower() and f != "":
                            if profile["protocol"] == v["tunnel"]:
                                temp_list.append(s)
                            elif profile["protocol"] == "All protocols":
                                temp_list.append(s)

                else:
                    if profile["protocol"] == v["tunnel"]:
                        temp_list.append(s)
                    elif profile["protocol"] == "All protocols":
                        temp_list.append(s)

        if temp_list:
            if profile["mode"] == "Fastest":
                fastest = 10000
                for s in temp_list:
                    try:
                        lat = float(self.server_dict[s]["latency"])
                    except KeyError:
                        lat = 1000
                    if lat <= fastest:
                        fastest = lat
                        result = s

            elif profile["mode"] == "Random":
                result = random.choice(temp_list)

            self.server_chosen(result, profile=p)

        else:
            self.notify("No match found", "No server fits your profile", icon="Error")


    def start_progress_bar(self, bar, server=None):
        action = bar

        if bar == "upgrade":
            text = "Upgrading Qomui"

        elif bar == "connecting":
            text = "Connecting to {}".format(server)
            bar = server

        elif bar == "connecting_bypass":
            text = "Connecting to {}".format(server)
            bar = server

        else:
            text = "Importing {}".format(bar)

        QtWidgets.QApplication.setOverrideCursor(QtGui.QCursor(QtCore.Qt.WaitCursor))

        try:
            getattr(self, "{}Bar".format(bar))
            self.stop_progress_bar(bar)

        except AttributeError:
            pass

        setattr(self, "{}Bar".format(bar), widgets.ProgressBarWidget())
        self.verticalLayout_2.addWidget(getattr(self, "{}Bar".format(bar)))
        getattr(self, "{}Bar".format(bar)).setText(text, action=action)
        getattr(self, "{}Bar".format(bar)).abort.connect(self.abort_action)

    def stop_progress_bar(self, bar, server=None):
        if server is not None:
            bar = server
        try:
            getattr(self, "{}Bar".format(bar)).setVisible(False)
            self.verticalLayout_2.removeWidget(getattr(self, "{}Bar".format(bar)))

        except AttributeError:
            pass

    def abort_action(self, action):
        QtWidgets.QApplication.restoreOverrideCursor()
        if action == "connecting":
            self.kill()

        elif action == "connecting_bypass":
            self.kill_bypass()

        elif action == "upgrade":
            pass

        else:
            self.stop_progress_bar(action)
            self.logger.info("Importing {} aborted".format(action))
            self.qomui_service.cancel_import(action)

    def downloaded(self, msg):
        split = msg.split("&")

        if len(split) >= 2:
            self.stop_progress_bar(split[2])
            QtWidgets.QApplication.restoreOverrideCursor()
            self.notify(split[0], split[1], icon="Error")

        else:
            self.config_dict = self.load_json("{}/config.json".format(ROOTDIR))

            with open("{}/{}.json".format(HOMEDIR, msg), "r") as p:
                content = json.load(p)

            provider = content["provider"]
            self.stop_progress_bar(provider)
            QtWidgets.QApplication.restoreOverrideCursor()

            txt = "List of available servers updated"

            try:
                for s in content["failed"]:
                    txt = txt + "\nFailed to resolve {} - server not added".format(s)

            except KeyError:
                pass

            self.notify("Qomui: Importing {} successful".format(provider), txt, icon="Information")
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

            with open ("{}/server.json".format(HOMEDIR), "w") as s:
                json.dump(self.server_dict, s)

            with open ("{}/protocol.json".format(HOMEDIR), "w") as p:
                json.dump(self.protocol_dict, p)

            os.remove("{}/{}.json".format(HOMEDIR, msg))
            self.pop_boxes()

    def del_single_server(self):
        for item in self.serverListWidget.selectedItems():
            data = item.data(QtCore.Qt.UserRole)
            index = self.serverListWidget.row(item)

            try:
                self.server_dict.pop(data, None)
                self.serverListWidget.takeItem(index)

            except KeyError:
                pass

        with open ("{}/server.json".format(HOMEDIR), "w") as s:
            json.dump(self.server_dict, s)

    def set_flag(self, country):
        flag = '{}/flags/{}.png'.format(ROOTDIR, country)

        if not os.path.isfile(flag):
            flag = '{}/flags/Unknown.png'.format(ROOTDIR)

        pixmap = QtGui.QPixmap(flag).scaled(25, 25,
                                            transformMode=QtCore.Qt.SmoothTransformation
                                            )

        setattr(self, country + "_pixmap", pixmap)


    def pop_boxes(self, country=None):
        malformed_entries = []
        self.country_list = []
        self.provider_list = ["All providers"]
        self.tunnel_list = ["All protocols"]
        self.tunnelBox.clear()
        server_count = len(self.server_dict.keys())
        self.logger.info("Total number of server: {}".format(server_count))

        for k,v in (self.server_dict.items()):

            try:

                if v["country"] not in self.country_list:
                    self.country_list.append(v["country"])
                    self.set_flag(v["country"])

                elif v["provider"] not in self.provider_list:
                    self.provider_list.append(v["provider"])

                elif v["tunnel"] not in self.tunnel_list:
                    self.tunnel_list.append(v["tunnel"])

            except KeyError:
                malformed_entries.append(k)
                self.logger.error("Malformed server entry: {} {}".format(k ,v))

        for e in malformed_entries:
            self.server_dict.pop(e)

        self.pop_providerProtocolBox()
        self.pop_delProviderBox()
        self.countryBox.clear()
        self.providerBox.clear()
        self.tunnelBox.clear()

        if len(self.provider_list) <= 2 :
            self.providerBox.setVisible(False)

        else:
            self.providerBox.setVisible(True)

        if len(self.tunnel_list) >= 2:
            self.tunnelBox.setVisible(True)

        else:
            self.tunnelBox.setVisible(False)

        self.countryBox.addItem("All countries")
        self.countryBox.setItemText(0, "All countries")

        for index, country in enumerate(sorted(self.country_list)):
            self.countryBox.addItem(country)
            self.countryBox.setItemText(index+1, country)

        for index, provider in enumerate(self.provider_list):
            self.providerBox.addItem(provider)
            self.providerBox.setItemText(index+1, provider)

        for index, provider in enumerate(self.tunnel_list):
            self.tunnelBox.addItem(provider)
            self.tunnelBox.setItemText(index, provider)

        self.index_list = []
        self.serverListWidget.clear()

        for key,val in sorted(self.server_dict.items(), key=lambda s: s[0].upper()):
            self.index_list.append(key)
            self.add_server_widget(key, val)

        try:
            if self.config_dict["ping"] == 1:
                self.get_latencies()

        except KeyError:
            pass

    def get_latencies(self):
        try:
            self.PingThread.terminate()
            self.PingThread.wait()
            self.logger.debug("Thread for latency checks terminated - Starting new one")

        except AttributeError:
            pass

        gateway = self.routes["interface"]
        print(gateway)

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
            self.server_dict[server]["latency"] = str(latency_float)
            old_index = self.index_list.index(server)
            bisect.insort(self.latency_list, latency_float)
            update_index = self.latency_list.index(latency_float)
            rm = self.index_list.index(server)
            self.index_list.pop(rm)
            self.index_list.insert(update_index, server)
            if getattr(self, server).isHidden() is True:
                hidden = True
            self.serverListWidget.takeItem(old_index)
            self.add_server_widget(server, self.server_dict[server], insert=update_index)
            self.serverListWidget.setRowHidden(update_index, hidden)
            getattr(self, server).display_latency(latency_string)

        except ValueError:
            pass

    def filter_by_text(self, text):
        self.countryBox.setCurrentIndex(0)
        self.providerBox.setCurrentIndex(0)
        self.tunnelBox.setCurrentIndex(0)
        self.randomSeverBt.setVisible(False)

        for k, v in self.server_dict.items():

            try:
                index = self.index_list.index(k)
                search = "{}{}".format(k, v["city"])

                if text.lower() in search.lower():
                    self.serverListWidget.setRowHidden(index, False)
                    getattr(self, k).setHidden(False)

                else:
                    self.serverListWidget.setRowHidden(index, True)
                    getattr(self, k).setHidden(True)

            except ValueError:
                pass

    def show_favourite_servers(self, state):
        self.countryBox.setCurrentIndex(0)
        self.providerBox.setCurrentIndex(0)
        self.tunnelBox.setCurrentIndex(0)
        self.randomSeverBt.setVisible(True)
        if state == True:
            i = 0

            try:
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

            except ValueError:
                pass

        elif state == False:
            self.filter_servers()

    def filter_servers(self, *arg, display="filter", text=None):
        self.searchLine.setText("")
        self.randomSeverBt.setVisible(False)
        country = self.countryBox.currentText()
        provider = self.providerBox.currentText()
        tunnel = self.tunnelBox.currentText()

        if self.favouriteButton.isChecked() == True:
            self.favouriteButton.setChecked(False)

        try:
            for key, val in self.server_dict.items():
                index = self.index_list.index(key)

                if val["provider"] == provider or provider == "All providers":
                    if val["country"] == country or country == "All countries":
                        if val["tunnel"] == tunnel or tunnel == "All protocols":
                            self.serverListWidget.setRowHidden(index, False)
                            getattr(self, key).setHidden(False)
                        else:
                            self.serverListWidget.setRowHidden(index, True)
                            getattr(self, key).setHidden(True)
                    else:
                        self.serverListWidget.setRowHidden(index, True)
                        getattr(self, key).setHidden(True)
                else:
                    self.serverListWidget.setRowHidden(index, True)
                    getattr(self, key).setHidden(True)

        except ValueError:
            pass

    def add_server_widget(self, key, val, insert=None):
        setattr(self, key, widgets.ServerWidget())
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
                            getattr(self, "{}_pixmap".format(val["country"])),
                            val["city"], fav=fav)

        except AttributeError:
            self.set_flag(val["country"])
            getattr(self, key).setText(val["name"], val["provider"],
                            getattr(self, "{}_pixmap".format(val["country"])),
                            val["city"], fav=fav)

        try:
            if val["tunnel"] == "WireGuard":
                getattr(self, key).hide_button(0)

        except KeyError:
            pass

        getattr(self, key).server_chosen.connect(self.server_chosen)
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
            self.overrideCheck.setVisible(False)
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

            protocol_list = []
            for k,v in sorted(self.protocol_dict[provider].items()):
                if k != "selected":

                    try:
                        ipv6 = ", connect with {}".format(v["ipv6"])
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
                    protocol_list.append(k)

            self.protocolListWidget.setMaximumHeight(len(protocol_list)*23)

        else:
            self.protocolListWidget.setVisible(False)
            self.overrideCheck.setVisible(True)

            try:
                protocol = self.protocol_dict[provider]["protocol"]
                port = self.protocol_dict[provider]["port"]
                self.override_protocol_show(True, protocol=protocol, port=port)
                self.overrideCheck.setChecked(True)

            except KeyError:
                pass

        self.clear_scripts()

    def protocol_change(self, selection):
        provider = self.providerProtocolBox.currentText()
        if provider in SUPPORTED_PROVIDERS:
            self.protocol_dict[provider]["selected"] = selection.data(QtCore.Qt.UserRole)

            with open ("{}/protocol.json".format(HOMEDIR), "w") as p:
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
                with open ("{}/protocol.json".format(HOMEDIR), "w") as p:
                    json.dump(self.protocol_dict, p)
            except KeyError:
                pass

    def override_protocol(self):
        protocol = self.chooseProtocolBox.currentText()
        port = self.portEdit.text()
        provider = self.providerProtocolBox.currentText()

        if self.overrideCheck.checkState() == 2:
            self.protocol_dict[provider] = {"protocol" : protocol, "port": port}
            with open ("{}/protocol.json".format(HOMEDIR), "w") as p:
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
        with open ("{}/server.json".format(HOMEDIR), "w") as s:
            json.dump(self.server_dict, s)

    def set_hop(self, server):
        try:
            current_dict = self.server_dict[server].copy()
            self.hop_server_dict = utils.create_server_dict(current_dict, self.protocol_dict)
            self.show_hop_widget()

        except KeyError:
            self.motify(
                        "Server not found",
                        "Server does not exist (anymore)\nHave you deleted the server?",
                        icon="Error")

    def show_hop_widget(self):
        self.hop_active = 2
        self.hop_server_dict.update({"hop":"1"})
        self.showHop.setVisible(True)
        self.showHop.setText(self.hop_server_dict)
        self.showHop.clear.connect(self.delete_hop)
        self.qomui_service.set_hop(self.hop_server_dict)

    def delete_hop(self):
        self.hop_active = 0
        self.hop_server_dict = None
        self.showHop.setVisible(False)
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
            self.server_chosen(random.choice(random_list), random="on")

    def set_bypass_vpn(self):
        server = self.bypassVpnBox.currentText()
        self.server_chosen(server, bypass=1)

    def server_chosen(self, server, random=None, bypass=None, profile=None):
        try:
            current_dict = self.server_dict[server].copy()

            if bypass == 1:
                self.disconnect_bypass()
                self.bypass_ovpn_dict = utils.create_server_dict(current_dict, self.protocol_dict)
                self.bypass_ovpn_dict.update({"bypass":"1", "hop":"0"})

                try:
                    if self.bypass_ovpn_dict["tunnel"] == "WireGuard":
                        self.notify(
                                    "Qomui",
                                    "WireGuard is currently not supported for secondary connections",
                                    icon="Info")

                    else:
                        self.establish_connection(self.bypass_ovpn_dict, bar="_bypass")

                except (KeyError, TypeError):
                    self.establish_connection(self.bypass_ovpn_dict, bar="_bypass")

            else:
                self.kill()
                self.ovpn_dict = utils.create_server_dict(current_dict, self.protocol_dict)

                try:
                    if self.ovpn_dict["tunnel"] == "WireGuard":
                        self.delete_hop()

                except KeyError:
                    pass

                if self.hop_active == 2 and self.hop_server_dict is not None:
                    self.ovpn_dict.update({"hop":"2"})

                else:
                    self.ovpn_dict.update({"hop":"0"})

                if random is not None:
                    self.ovpn_dict.update({"random" : "on"})

                if profile is not None:
                    self.ovpn_dict.update({"profile" : profile})

                if bypass == 1:
                    self.bypass_ovpn_dict.update({"hop":"0", "bypass":"1"})

                self.establish_connection(self.ovpn_dict)

        except KeyError:
            self.notify(
                        "Server not found",
                        "Server does not exist (anymore)\nHave you deleted the server?",
                        icon="Error"
                        )

    def openvpn_log_monitor(self, reply):
        if bool(self.conn_timer.isActive()):
            self.logger.debug("Stopping timer")
            self.conn_timer.stop()
        getattr(self, reply)()

    def set_tray_icon(self, icon):
        self.trayIcon = QtGui.QIcon(icon)
        self.tray.setIcon(QtGui.QIcon(self.trayIcon))

    def connection_established(self):
        self.tunnel_active = 1
        QtWidgets.QApplication.restoreOverrideCursor()
        self.stop_progress_bar("connection", server=self.ovpn_dict["name"])
        self.set_tray_icon('{}/flags/{}.png'.format(ROOTDIR, self.ovpn_dict["country"]))
        self.notify(
                    "Qomui",
                    "Connection to {} successfully established".format(self.ovpn_dict["name"]),
                    icon="Information"
                    )

        last_server_dict = self.load_json("{}/last_server.json".format(HOMEDIR))
        with open('{}/last_server.json'.format(HOMEDIR), 'w') as lserver:
            last_server_dict["last"] = self.ovpn_dict
            last_server_dict["hop"] = self.hop_server_dict
            json.dump(last_server_dict, lserver)
            lserver.close()

        tun = self.qomui_service.return_tun_device("tun")
        self.tray.setToolTip("Connected to {}".format(self.ovpn_dict["name"]))
        self.gridLayout.addWidget(self.showActive, 0, 0, 1, 3)
        self.showActive.setVisible(True)
        self.showActive.setText(self.ovpn_dict, self.hop_server_dict, tun, tun_hop=self.tun_hop, bypass=None)
        self.showActive.disconnect.connect(self.kill)
        self.showActive.reconnect.connect(self.reconnect)
        self.showActive.check_update.connect(self.update_check)

    def connection_established_hop(self):
        self.tunnel_hop_active = 1
        self.tun_hop = self.qomui_service.return_tun_device("tun_hop")
        self.notify(
                    "Qomui",
                    "First hop connected: {}".format(self.hop_server_dict["name"]),
                    icon="Information"
                    )

    def connection_established_bypass(self):
        self.tunnel_bypass_active = 1
        QtWidgets.QApplication.restoreOverrideCursor()
        self.stop_progress_bar("connection", server=self.bypass_ovpn_dict["name"])
        tun = self.qomui_service.return_tun_device("tun_bypass")
        self.notify(
                    "Qomui",
                    "Bypass connected to: {}".format(self.bypass_ovpn_dict["name"]),
                    icon="Information"
                    )

        last_server_dict = self.load_json("{}/last_server.json".format(HOMEDIR))
        with open('{}/last_server.json'.format(HOMEDIR), 'w') as lserver:
            last_server_dict["bypass"] = self.bypass_ovpn_dict
            json.dump(last_server_dict, lserver)
            lserver.close()

        try:
            self.BypassActive.setVisible(False)
            self.verticalLayout_2.removeWidget(self.BypassActive)

        except AttributeError:
            pass

        self.BypassActive = widgets.ActiveWidget("Secondary Connection")
        self.verticalLayout_2.addWidget(self.BypassActive)
        self.BypassActive.setVisible(True)
        self.BypassActive.setText(self.bypass_ovpn_dict, None, tun, tun_hop=None, bypass="1")
        self.BypassActive.disconnect.connect(self.kill_bypass)

    def conn_attempt_failed(self):
        self.kill()
        QtWidgets.QApplication.restoreOverrideCursor()
        self.notify(
                    "Qomui: Connection attempt failed",
                    "Unable to connecto to {}\nSee log for further information".format(self.ovpn_dict["name"]),
                    icon="Error"
                    )

    def conn_attempt_failed_hop(self):
        self.kill()
        QtWidgets.QApplication.restoreOverrideCursor()
        self.notify(
                    "Qomui: Connection attempt failed",
                    "Unable to connecto to {}\nSee log for further information".format(self.hop_server_dict["name"]),
                    icon="Error"
                    )

    def conn_attempt_failed_bypass(self):
        self.kill_bypass()
        QtWidgets.QApplication.restoreOverrideCursor()
        self.notify(
                    "Qomui: Connection attempt failed",
                    "Unable to connecto to {}\nSee log for further information".format(self.bypass_ovpn_dict["name"]),
                    icon="Error"
                    )

    def tunnel_terminated(self):
        QtWidgets.QApplication.restoreOverrideCursor()
        self.showActive.setVisible(False)
        self.logger.info("Openvpn connection closed")

    def tunnel_terminated_hop(self):
        QtWidgets.QApplication.restoreOverrideCursor()
        self.showActive.setVisible(False)
        self.logger.info("Openvpn connection closed")

    def tunnel_terminated_bypass(self):
        QtWidgets.QApplication.restoreOverrideCursor()
        self.BypassActive.setVisible(False)
        self.logger.info("Openvpn connection closed")

    def starting_timer(self):
        self.tunnel_active == 0
        self.start_timer()

    def starting_timer_hop(self):
        self.tunnel_hop_active == 0
        self.start_timer()

    def starting_timer_bypass(self):
        self.tunnel_bypass_active == 0
        self.start_timer()

    def start_timer(self):
        self.tunnel_bypass_active == 0
        self.conn_timer.start(15000)

    def timeout(self, tunnel, name):
        QtWidgets.QApplication.restoreOverrideCursor()
        self.logger.info("{}: Connection attempt timed out".format(name))
        self.notify(
                    "Qomui: Connection attempt failed",
                    "{}: Connection attempt timed out\nSee log for further information".format(name),
                    icon="Error"
                    )

        if getattr(self, "tunnel{}_active".format(tunnel)) == 0:
            getattr(self, "kill{}".format(tunnel))()

    def update_check(self):
        QtWidgets.QApplication.restoreOverrideCursor()
        for provider in SUPPORTED_PROVIDERS:
            if provider in self.provider_list:

                try:
                    get_last = self.config_dict["{}_last".format(provider)]
                    last_update = datetime.strptime(get_last, '%Y-%m-%d %H:%M:%S.%f')
                    time_now = datetime.utcnow()
                    delta = time_now.date() - last_update.date()
                    days_since = delta.days
                    self.logger.info("Last {} update: {} days ago".format(provider, days_since))

                    if days_since >= 5:
                        credentials = {
                                        "provider" : provider,
                                        "credentials" : "unknown",
                                        "folderpath" : "None",
                                        "homedir" : HOMEDIR
                                        }

                        if self.config_dict["auto_update"] == 1:
                            self.logger.info("Updating {}".format(provider))
                            self.qomui_service.import_thread(credentials)

                except KeyError:
                    self.logger.debug("Update timestamp for {} not found".format(provider))

    def reconnect(self):
        if self.tunnel_active == 1:
            self.tunnel_active = 0
            self.connect_last_server()

    def kill(self):
        self.tunnel_active = 0
        self.tunnel_hop_active = 0
        self.qomui_service.disconnect("main")
        self.showActive.setVisible(False)

        try:
            self.stop_progress_bar("connection", server=self.ovpn_dict["name"])

        except TypeError:
            pass

        try:
            self.trayIcon = QtGui.QIcon.fromTheme("qomui")
            self.tray.setIcon(self.trayIcon)
            self.tray.setToolTip("Status: disconnected")

        except (KeyError, AttributeError):
            pass

    def kill_hop():
        self.kill()

    def kill_bypass(self):
        last_server_dict = self.load_json("{}/last_server.json".format(HOMEDIR))

        if "bypass" in last_server_dict.keys():
            last_server_dict.pop("bypass")

        with open('{}/last_server.json'.format(HOMEDIR), 'w') as lserver:
            json.dump(last_server_dict, lserver)
            lserver.close()

        self.disconnect_bypass()

    def disconnect_bypass(self):
        self.tunnel_bypass_active = 0
        self.qomui_service.disconnect("bypass")

        try:
            self.stop_progress_bar("connection_bypass", server=self.bypass_ovpn_dict["name"])
            self.BypassActive.setVisible(False)
            self.verticalLayout_2.removeWidget(self.BypassActive)

        except (TypeError, AttributeError):
            pass

    def establish_connection(self, server_dict, bar=""):
        self.logger.info("Connecting to {}....".format(server_dict["name"]))
        self.start_progress_bar("connecting{}".format(bar), server=server_dict["name"])

        try:
            self.qomui_service.connect_to_server(server_dict)

        except dbus.exceptions.DBusException as e:
            self.logger.error("Dbus-service not available")

        self.conn_timer = QtCore.QTimer()
        self.conn_timer.setSingleShot(True)
        self.conn_timer.timeout.connect(lambda: self.timeout(bar, server_dict["name"]))

    def save_scripts(self):
        events = ["pre", "up", "down"]
        provider = self.providerProtocolBox.currentText()
        scripts = {}
        temp_config = {}

        for event in events:
            if getattr(self, "{}Edit".format(event)).text() != "":
                scripts[event] = getattr(self, "{}Edit".format(event)).text()

        temp_config["{}_scripts".format(provider)] = scripts
        ret = self.save_options(temp_config)

        if ret == "failed":
            self.clear_scripts()

    def clear_scripts(self):
        provider = self.providerProtocolBox.currentText()
        events = ["pre", "up", "down"]
        for e in events:
            try:
                if e in self.config_dict["{}_scripts".format(provider)].keys():
                    getattr(self, "{}Edit".format(e)).setText(
                        self.config_dict["{}_scripts".format(provider)][e]
                        )
                else:
                    getattr(self, "{}Edit".format(e)).clear()

            except KeyError:
                getattr(self, "{}Edit".format(e)).clear()

    def show_firewall_editor(self):
        other_firewalls = firewall.check_firewall_services()
        if len(other_firewalls) != 0:
            for fw in other_firewalls:
                self.notify(
                            "Qomui: Other firewall services detected",
                            "{} might interfere with Qomui's firewall".format(fw),
                            icon="Warning"
                            )

        editor = widgets.FirewallEditor(self.config_dict)
        editor.fw_change.connect(self.firewall_update)
        editor.exec_()

    def firewall_update(self, config):
        self.save_options(config, firewall="change")

    def select_application(self):
        selector = widgets.AppSelector()
        selector.app_chosen.connect(self.add_bypass_app)
        selector.exec_()

    def add_bypass_app(self, app_info):
        self.bypass_dict[app_info[0]] = [app_info[1], app_info[2]]

        with open ("{}/bypass_apps.json".format(HOMEDIR), "w") as save_bypass:
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

        with open ("{}/bypass_apps.json".format(HOMEDIR), "w") as save_bypass:
            json.dump(self.bypass_dict, save_bypass)

        self.pop_bypassAppList()

    def pop_bypassAppList(self):
        self.bypassAppList.clear()
        for k,v in self.bypass_dict.items():
            self.Item = widgets.ServerWidget()
            self.ListItem = QtWidgets.QListWidgetItem(self.bypassAppList)
            self.ListItem.setSizeHint(QtCore.QSize(100, 50))
            self.Item.setText(k, "bypass", v[0], None, button="bypass")
            self.ListItem.setData(QtCore.Qt.UserRole, k)
            self.Item.hide_button(0)
            self.bypassAppList.addItem(self.ListItem)
            self.bypassAppList.setItemWidget(self.ListItem, self.Item)
            self.Item.server_chosen.connect(self.bypass_tunnel)

    def bypass_tunnel(self, app):
        desktop_file = self.bypass_dict[app][1]

        try:
            with open (desktop_file, "r") as cmd_ret:
                search = cmd_ret.readlines()
                found = 0

                for line in search:
                    if line.startswith("Exec") and found !=1:
                        #cmd = line.split("=")[1].split(" ")[0].replace("\n", "")
                        cmd = line.replace("Exec=", "").replace("\n", "")
                        cmd = re.sub(r"%[\w]", "", cmd)
                        found = 1

            temp_bash = "{}/bypass_temp.sh".format(HOMEDIR)

            with open (temp_bash, "w") as temp_sh:
                lines = ["#!/bin/bash \n",
                        "nohup cgexec -g net_cls:bypass_qomui {} & \n".format(cmd)
                        ]

                temp_sh.writelines(lines)
                temp_sh.close()
                os.chmod(temp_bash, 0o774)

            try:
                check_call([temp_bash])
                self.logger.debug("Started {} in bypass".format(app))
                self.notify(
                        "Bypass Qomui",
                        "Started {} in bypass mode".format(app),
                        icon="Info"
                        )

            except CalledProcessError:
                self.logger.warning("Could not start {}".format(app))

        except:
            self.notify(
                        "Bypass Qomui: Starting {} failed".format(app),
                        "Try manual method via console",
                        icon="Error"
                        )

            self.logger.error("Starting {} in bypass-mode failed".format(app))


    def modify_server(self):
        try:
            if self.serverListWidget.isVisible() is False:
                item = self.serverListFilterWidget.currentItem()
                data = item.data(QtCore.Qt.UserRole)
                self.modify_row = self.serverListFilterWidget.row(item)
            else:
                item = self.serverListWidget.currentItem()
                data = item.data(QtCore.Qt.UserRole)
                self.modify_row = self.serverListWidget.row(item)

        except AttributeError:
            pass

        try:
            editor = widgets.ModifyServer(key=data,
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

            self.countryBox.addItem("All countries")
            self.countryBox.setItemText(0, "All countries")

            for index, country in enumerate(sorted(self.country_list)):
                self.countryBox.addItem(country)
                self.countryBox.setItemText(index+1, country)

        with open ("{}/server.json".format(HOMEDIR), "w") as s:
            json.dump(self.server_dict, s)

        if len(new_config) != 0:
            try:
                if provider in SUPPORTED_PROVIDERS:
                    temp_file = "{}/temp/{}_config".format(HOMEDIR, provider)
                    with open(temp_file, "w") as config_change:
                        config_change.writelines(new_config)

                else:
                    temp_file = "{}/temp/{}".format(HOMEDIR, val["path"].split("/")[1])
                    if modifications["apply_all"] == 1:
                        for k, v in self.server_dict.items():
                            if v["provider"] == provider:
                                path = "{}/temp/{}".format(HOMEDIR, v["path"].split("/")[1])
                                with open(path, "w") as config_change:
                                    index = modifications["index"]
                                    rpl = new_config[index].split(" ")
                                    ip_insert = "{} {} {}".format(rpl[0], v["ip"], rpl[2])
                                    new_config[index] = ip_insert
                                    config_change.writelines(new_config)

                self.qomui_service.change_ovpn_config(provider, "{}/temp".format(HOMEDIR))

            except FileNotFoundError:
                pass

    def search_listitem(self, key):
        for row in range(self.serverListWidget.count()):
            if self.serverListWidget.item(row).data(QtCore.Qt.UserRole) == key:
                return row

class NetMon(QtCore.QThread):
    net_state_change = QtCore.pyqtSignal(int, dict)
    log = QtCore.pyqtSignal(tuple)

    def __init__(self):
        QtCore.QThread.__init__(self)

    def run(self):
        net_iface_dir = "/sys/class/net/"
        net_check = 0
        i = "None"

        while True:
            prior = net_check
            i = "None"
            net_check = 0
            routes = {       
                        "gateway" : "None",
                        "gateway_6" : "None",
                        "interface" : "None",
                        "interface_6" : "None"
                        }

            try:
                for iface in os.listdir(net_iface_dir):
                    with open("{}{}/operstate".format(net_iface_dir, iface), "r") as n:

                        if n.read() == "up\n":
                            net_check = 1
                            i = iface

                if prior != net_check and net_check == 1:
                    routes = self.default_gateway_check()
                    gw = routes["gateway"]
                    gw_6 = routes["gateway_6"]

                    if gw != "None" or gw_6 != "None":
                        self.net_state_change.emit(net_check, routes)

                    else:
                        net_check = 0

                elif prior != net_check and net_check == 0:
                    self.net_state_change.emit(net_check, routes)

                time.sleep(2)

            except (FileNotFoundError, PermissionError) as e:
                self.log.emit(("error", e))

    def default_gateway_check(self):
        try:
            route_cmd = ["ip", "route", "show", "default", "0.0.0.0/0"]
            default_route = check_output(route_cmd).decode("utf-8")
            parse_route = default_route.split(" ")
            default_gateway_4 = parse_route[2]
            default_interface_4 = parse_route[4]

        except (CalledProcessError, IndexError):
            self.log.emit(('info', 'Could not identify default gateway - no network connectivity'))
            default_gateway_4 = "None"
            default_interface_4 = "None"

        try:
            route_cmd = ["ip", "-6", "route", "show", "default", "::/0"]
            default_route = check_output(route_cmd).decode("utf-8")
            parse_route = default_route.split(" ")
            default_gateway_6 = parse_route[2]
            default_interface_6 = parse_route[4]

        except (CalledProcessError, IndexError):
            self.log.emit(('error', 'Could not identify default gateway for ipv6 - no network connectivity'))
            default_gateway_6 = "None"
            default_interface_6 = "None"

        self.log.emit(("debug", "Network interface - ipv4: {}".format(default_interface_4)))
        self.log.emit(("debug","Default gateway - ipv4: {}".format(default_gateway_4)))
        self.log.emit(("debug","Network interface - ipv6: {}".format(default_interface_6)))
        self.log.emit(("debug","Default gateway - ipv6: {}".format(default_gateway_6)))

        return {
            "gateway" : default_gateway_4,
            "gateway_6" : default_gateway_6,
            "interface" : default_interface_4,
            "interface_6" : default_interface_6
            }

def main():
    if not os.path.exists("{}/.qomui".format(os.path.expanduser("~"))):
        os.makedirs("{}/.qomui".format(os.path.expanduser("~")))

    signal.signal(signal.SIGINT, signal.SIG_DFL)
    app = QtWidgets.QApplication(sys.argv)
    DBusQtMainLoop(set_as_default=True)
    ex = QomuiGui()
    ex.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
