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
from datetime import datetime, date
from subprocess import CalledProcessError, check_call
from PyQt5 import QtCore, QtGui, Qt, QtWidgets
from dbus.mainloop.pyqt5 import DBusQtMainLoop
import psutil
import shlex
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


ROOTDIR = "/usr/share/qomui"
HOMEDIR = "{}/.qomui".format(os.path.expanduser("~"))
SUPPORTED_PROVIDERS = ["Airvpn", "Mullvad", "ProtonVPN", "PIA", "Windscribe"]
JSON_FILE_LIST = [("config_dict", "{}/config.json".format(ROOTDIR)),
                  ("server_dict", "{}/server.json".format(HOMEDIR)),
                  ("protocol_dict", "{}/protocol.json".format(HOMEDIR)),
                  ("bypass_dict", "{}/bypass_apps.json".format(HOMEDIR))
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
    network_state = 0
    status = "inactive"
    server_dict = {}
    protocol_dict = {}
    country_list = ["All countries"]
    provider_list = ["All providers"]
    firewall_rules_changed = False
    hop_active = 0
    hop_log_monitor = 0
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

        #deprecated - replaced by monitoring sysfs
        #nm = self.dbus.get_object('org.freedesktop.NetworkManager', '/org/freedesktop/NetworkManager')
        #nm_iface = dbus.Interface(nm, 'org.freedesktop.NetworkManager')
        #nm_iface.connect_to_signal("StateChanged", self.network_change)

        handler = DbusLogHandler(self.qomui_service)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)
        primay_screen = QtWidgets.QDesktopWidget().primaryScreen()
        primary_screen_geometry = QtWidgets.QDesktopWidget().availableGeometry(primay_screen)
        positioning = primary_screen_geometry.bottomRight()
        self.setGeometry(QtCore.QRect(positioning.x()-600, positioning.y()-750,
                                      600, 750
                                      ))

        self.net_mon_thread = NetMon()
        self.net_mon_thread.log.connect(self.log_from_thread)
        self.net_mon_thread.net_state_change.connect(self.network_change)
        self.net_mon_thread.start()

        self.qomui_service.disconnect("main")
        self.qomui_service.disconnect("bypass")
        self.qomui_service.save_default_dns()
        self.load_saved_files()
        self.systemtray()

    def receive_log(self, msg):
        self.logText.appendPlainText(msg)

    def setupUi(self, Form):
        Form.setObjectName(_fromUtf8("Form"))
        self.gridLayout = QtWidgets.QGridLayout(Form)
        self.gridLayout.setObjectName(_fromUtf8("gridLayout"))
        self.ActiveWidget = ActiveWidget("Active Connection", Form)
        self.gridLayout.addWidget(self.ActiveWidget, 0, 0, 1, 2)
        self.ActiveWidget.setVisible(False)
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.gridLayout.addLayout(self.verticalLayout_2, 1, 0, 1, 2)
        #self.WaitBar = ProgessBarWidget(Form)
        #self.verticalLayout_2.addWidget(self.WaitBar)
        #self.WaitBar.setVisible(False)
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
        self.searchLine = QtWidgets.QLineEdit(self.serverTab)
        self.searchLine.setObjectName(_fromUtf8("searchLine"))
        self.verticalLayout.addWidget(self.searchLine)
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
        self.gridLayout_2.addWidget(self.logText, 0, 0, 1, 4)
        self.logBox = QtWidgets.QComboBox(self.logTab)
        self.logBox.setObjectName(_fromUtf8("logBox"))
        self.gridLayout_2.addWidget(self.logBox, 1, 3, 1, 1)
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
        self.horizontalLayout_11= QtWidgets.QHBoxLayout()
        self.horizontalLayout_11.setObjectName(_fromUtf8("horizontalLayout_11"))
        self.bypassVpnBox = QtWidgets.QComboBox(self.bypassTab)
        self.bypassVpnBox.setObjectName(_fromUtf8("bypassVpnBox"))
        self.horizontalLayout_11.addWidget(self.bypassVpnBox)
        self.bypassVpnButton = QtWidgets.QPushButton(self.bypassTab)
        self.bypassVpnButton.setObjectName(_fromUtf8("bypassVpnButton"))
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
        #self.WaitBar.abort.connect(self.abort_action)
        self.logBox.activated[str].connect(self.log_level)
        self.searchLine.textEdited[str].connect(self.filter_by_text)
        self.bypassVpnButton.clicked.connect(self.set_bypass_vpn)

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

        self.logBox.addItem("Info")
        self.logBox.addItem("Debug")

    def notify(self, header, text, icon="Question"):

        try:
            check_call(["notify-send", header, text, "--icon=dialog-{}".format(icon.lower())])

        except (CalledProcessError, FileNotFoundError):

            if icon == "Error":
                icon = "Critical"

            self.messageBox(header, text, buttons=[("Ok", "YesRole")], icon="Question")

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
            self.show_failmsg("Upgrade failed", "See log for further details")

    def restart_qomui(self):
        self.kill()
        self.kill_bypass_vpn()

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
            self.bypassVpnBox.clear()

            for k, v in self.server_dict.items():
                if "favourite" in v:
                    if v["favourite"] == "on":
                        self.bypassVpnBox.addItem(k)

        elif button == "About":
            self.tabWidget.setCurrentIndex(5)
            self.check_update()

    def switch_providerTab(self):
        self.tabWidget.setCurrentIndex(3)

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
        info = "Closing in {} seconds".format(self.timeout)
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
            self.kill_bypass_vpn()
            self.qomui_service.load_firewall(2)
            self.exit_event.accept()

    def change_timeout(self):
        self.timeout -= 1
        info = "Closing in {} seconds".format(self.timeout)
        self.confirm.setInformativeText(info)
        if self.timeout <= 0:
            self.timer.stop()
            self.confirm.hide()
            self.tray.hide()
            self.kill()
            self.kill_bypass_vpn()
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
                last_server_dict = self.load_json("{}/last_server.json".format(HOMEDIR))
                self.ovpn_dict = last_server_dict["last"]
                self.hop_server_dict = last_server_dict["hop"]

                if self.hop_server_dict is not None:
                    self.show_hop_widget()

                if self.network_state == 1:

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
            if self.config_dict["bypass"] == 1:
                self.qomui_service.bypass(utils.get_user_group())
                self.bypassTabBt.setVisible(True)

        except KeyError:
            pass

        try:
            self.logger.setLevel(getattr(logging, self.config_dict["log_level"].upper()))
            if self.config_dict["log_level"] == "Debug":
                self.logBox.setCurrentIndex(1)

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
            self.qomui_service.bypass(utils.get_user_group())
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

        except CalledProcessError as e:
            self.logger.info("Non-zero exit status: configuration changes not applied")

            self.notify(
                        "Qomui: Authentication failure",
                        "Configuration not updated",
                        icon="Error"
                        )

    def network_change(self, state):
        self.network_state = state

        if self.network_state == 1:
            self.logger.info("Detected new network connection")
            self.qomui_service.save_default_dns()
            self.get_latencies()

            if self.ovpn_dict is not None:
                self.kill()
                self.kill_bypass_vpn()
                self.establish_connection(self.ovpn_dict)
                self.qomui_service.bypass(utils.get_user_group())

        elif self.network_state == 0:
            self.logger.info("Lost network connection - VPN tunnel terminated")
            self.kill()
            self.kill_bypass_vpn()

        #deprecated - replaced by monitoring sysfs
        """if network_change == 70 or network_change == 60:
            self.logger.info("Detected new network connection")
            self.qomui_service.save_default_dns()
            self.get_latencies()

            if self.ovpn_dict is not None:
                self.kill()
                self.establish_connection(self.ovpn_dict)
                self.qomui_service.bypass(utils.get_user_group())

        elif network_change != 70 and network_change != 60:
            self.logger.info("Lost network connection - VPN tunnel terminated")
            self.kill()"""

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
                                button=[("Ok", "YesRole")],
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
                    pass

        if folderpath != "":
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
        setattr(self, "{}Bar".format(bar), ProgessBarWidget(self))
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
            self.kill_bypass_vpn()

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

        self.filter_servers(display="all")

        """
        try:
            if self.config_dict["ping"] == 1:
                self.get_latencies()

            else:
                self.check_update()

        except KeyError:
            pass
        """

    def get_latencies(self):
        try:
            self.PingThread.terminate()
            self.PingThread.wait()
            self.logger.debug("Thread for latency checks terminated - Starting new one")

        except AttributeError:
            pass

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
            index = self.index_list.index(k)
            search = "{}{}".format(k, v["city"])

            if text.lower() in search.lower():
                self.serverListWidget.setRowHidden(index, False)
                getattr(self, k).setHidden(False)

            else:
                self.serverListWidget.setRowHidden(index, True)
                getattr(self, k).setHidden(True)

    def show_favourite_servers(self, state):
        self.countryBox.setCurrentIndex(0)
        self.providerBox.setCurrentIndex(0)
        self.tunnelBox.setCurrentIndex(0)
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

    def filter_servers(self, *arg, display="filter", text=None):
        self.searchLine.setText("")
        self.randomSeverBt.setVisible(False)
        country = self.countryBox.currentText()
        provider = self.providerBox.currentText()
        tunnel = self.tunnelBox.currentText()

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
            self.server_chosen(random.choice(random_list), random="on")

    def set_bypass_vpn(self):
        server = self.bypassVpnBox.currentText()
        self.server_chosen(server, bypass=1)

    def server_chosen(self, server, random=None, bypass=None):

        try:
            current_dict = self.server_dict[server].copy()

            if bypass == 1:
                self.kill_bypass_vpn()
                self.bypass_ovpn_dict = utils.create_server_dict(current_dict, self.protocol_dict)
                self.bypass_ovpn_dict.update({"bypass":"1", "hop":"0"})

                try:
                    if self.bypass_ovpn_dict["tunnel"] == "WireGuard":
                        self.notify(
                                    "Qomui",
                                    "WireGuard is currently not supported for secondary connections",
                                    icon="Info")

                    elif self.bypass_ovpn_dict["name"] == self.ovpn_dict["name"]:
                        self.notify(
                                    "Qomui",
                                    "Please choose another server",
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

                if bypass == 1:
                    self.bypass_ovpn_dict.update({"hop":"0", "bypass":"1"})

                self.establish_connection(self.ovpn_dict)

        except KeyError:
            self.show_failmsg("Server not found",
                              "Server does not exist (anymore)\nHave you deleted the server?")

            QtWidgets.QApplication.restoreOverrideCursor()

    def openvpn_log_monitor(self, reply):
        QtWidgets.QApplication.restoreOverrideCursor()
        if reply == "connected":
            if self.hop_active != 2 or self.hop_log_monitor == 1:
                self.status = "active"
                self.hop_log_monitor = 0
                self.stop_progress_bar("connection", server=self.ovpn_dict["name"])
                self.notify(
                            "Qomui",
                            "Connection to {} established".format(self.ovpn_dict["name"]),
                            icon="Information"
                            )

                self.trayIcon = QtGui.QIcon('{}/flags/{}.png'.format(ROOTDIR,
                                                                    self.ovpn_dict["country"]
                                                                ))
                self.tray.setIcon(QtGui.QIcon(self.trayIcon))
                self.show_active_connection(self.ovpn_dict, hop_dict=self.hop_server_dict, tun_hop=self.tun_hop)
                self.tun_hop = None

            elif self.hop_active == 2 and self.hop_log_monitor != 1:
                self.tun_hop = self.qomui_service.return_tun_device("tun_hop")
                self.hop_log_monitor = 1

            with open('{}/last_server.json'.format(HOMEDIR), 'w') as lserver:
                last_server_dict = {}
                last_server_dict["last"] = self.ovpn_dict
                last_server_dict["hop"] = self.hop_server_dict
                json.dump(last_server_dict, lserver)
                lserver.close()

            QtWidgets.QApplication.restoreOverrideCursor()

        elif reply == "connected_bypass":
            self.status_bypass_vpn = "active"
            self.stop_progress_bar("connection", server=self.bypass_ovpn_dict["name"])
            self.show_active_connection(self.bypass_ovpn_dict, tun="tun_bypass", widget="BypassActive")
            QtWidgets.QApplication.restoreOverrideCursor()

        elif reply == "fail":
            self.kill()
            self.show_failmsg("Connection attempt failed",
                              "Application was unable to connect to server\nSee log for further information")
            QtWidgets.QApplication.restoreOverrideCursor()

        elif reply == "fail_auth":
            self.kill()
            self.show_failmsg("Connection attempt failed",
                              "Authentication error while trying to connect\nMaybe your account is expired or connection limit is exceeded")
            QtWidgets.QApplication.restoreOverrideCursor()

        elif reply == "killed":
            self.trayIcon = QtGui.QIcon.fromTheme("qomui")
            self.tray.setIcon(self.trayIcon)
            QtWidgets.QApplication.restoreOverrideCursor()
            self.ActiveWidget.setVisible(False)

        elif reply == "fail_bypass":
            self.kill_bypass_vpn()
            self.show_failmsg("Connection attempt failed",
                              "Application was unable to connect to server\nSee log for further information")
            QtWidgets.QApplication.restoreOverrideCursor()

        elif reply == "fail_auth_bypass":
            self.kill_bypass_vpn()
            self.show_failmsg("Connection attempt failed",
                              "Authentication error while trying to connect\nMaybe your account is expired or connection limit is exceeded")
            QtWidgets.QApplication.restoreOverrideCursor()

        elif reply == "killed_bypass":
            QtWidgets.QApplication.restoreOverrideCursor()

            try:
                self.BypassActive.setVisible(False)
                self.verticalLayout2.removeWidget(self.BypassActive)

            except AttributeError:
                pass

    def show_failmsg(self, text, information):
        self.notify(text, information, icon="Error")

    def show_active_connection(self, server_dict, hop_dict=None, tun="tun", tun_hop=None, widget="ActiveWidget"):
        QtWidgets.QApplication.restoreOverrideCursor()
        tun = self.qomui_service.return_tun_device(tun)

        if widget == "ActiveWidget":
            self.tray.setToolTip("Connected to {}".format(server_dict["name"]))
            self.gridLayout.addWidget(getattr(self, widget), 0, 0, 1, 3)
            getattr(self, widget).setVisible(True)
            getattr(self, widget).setText(server_dict, hop_dict, tun, tun_hop)
            getattr(self, widget).disconnect.connect(self.kill)
            getattr(self, widget).reconnect.connect(self.reconnect)
            getattr(self, widget).check_update.connect(self.update_check)

        elif widget == "BypassActive":
            self.BypassActive = ActiveWidget("Secondary Connection")
            self.verticalLayout_2.addWidget(self.BypassActive)
            getattr(self, widget).setVisible(True)
            getattr(self, widget).setText(server_dict, hop_dict, tun, tun_hop)
            getattr(self, widget).disconnect.connect(self.kill_bypass_vpn)
            #getattr(self, widget).reconnect.connect(self.reconnect_bypass_vpn)

    def update_check(self):
        for provider in SUPPORTED_PROVIDERS:

            try:
                get_last = self.config_dict["{}_last".format(provider)]
                last_update = datetime.strptime(get_last, '%Y-%m-%d %H:%M:%S.%f')
                time_now = datetime.utcnow()
                delta = time_now.date() - last_update.date()
                days_since = delta.days
                self.logger.info("Last {} update: {} days ago".format(provider, days_since))

                if days_since >= 7:
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
        if self.status == "active":
            self.status = "inactive"
            self.kill()
            self.connect_last_server()

    def kill(self):
        self.status = "inactive"
        self.hop_log_monitor = 0
        self.qomui_service.disconnect("main")
        self.ActiveWidget.setVisible(False)

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

    def kill_bypass_vpn(self):
        self.qomui_service.disconnect("bypass")

        try:
            self.BypassActive.setVisible(False)
            self.verticalLayout_2.removeWidget(self.BypassActive)
            self.stop_progress_bar("connection", server=self.bypass_ovpn_dict["name"])

        except (TypeError, AttributeError):
            pass

    def establish_connection(self, server_dict, bar=None):
        QtWidgets.QApplication.setOverrideCursor(QtGui.QCursor(QtCore.Qt.WaitCursor))
        self.logger.info("Connecting to {}....".format(server_dict["name"]))
        self.start_progress_bar("connecting".format(bar), server=server_dict["name"])
        self.hop_log_monitor = 0

        try:
            self.qomui_service.connect_to_server(server_dict)

        except dbus.exceptions.DBusException as e:
            self.logger.error("Dbus-service not available")

    def show_firewall_editor(self):
        editor = FirewallEditor(self.config_dict)
        editor.fw_change.connect(self.firewall_update)
        editor.exec_()

    def firewall_update(self, config):
        self.save_options(config, firewall="change")

    def select_application(self):
        selector = AppSelector()
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
            self.Item = ServerWidget()
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
    net_state_change = QtCore.pyqtSignal(int)
    log = QtCore.pyqtSignal(tuple)

    def __init__(self):
        QtCore.QThread.__init__(self)

    def run(self):
        net_iface_dir = "/sys/class/net/"
        current_state = 0

        while True:
            prior = current_state
            current_state = 0

            try:
                for iface in os.listdir(net_iface_dir):
                    with open("{}{}/operstate".format(net_iface_dir, iface), "r") as n:

                        if n.read() == "up\n":
                            current_state = 1

                if prior != current_state:
                    print(iface)
                    self.net_state_change.emit(current_state)

                time.sleep(2)

            except (FileNotFoundError, PermissionError) as e:
                self.log.emit(("error", e))

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

class ProgessBarWidget(QtWidgets.QWidget):
    abort = QtCore.pyqtSignal(str)

    def __init__ (self, parent=None):
        super(ProgessBarWidget, self).__init__(parent)
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
        self.ServerWidget.server_chosen.connect(self.signal)

    def retranslateUi(self, ConnectionWidget):
        ConnectionWidget.setWindowTitle(_translate("ConnectionWidget", "Form", None))
        #self.statusLabel.setText(_translate("ConnectionWidget", "", None))
        self.downloadLabel.setText(_translate("ConnectionWidget", "Download:", None))
        self.uploadLabel.setText(_translate("ConnectionWidget", "Upload:", None))
        self.timeLabel.setText(_translate("ConnectionWidget", "Time:", None))

    def setText(self, server_dict, hop_dict, tun, tun_hop=None):
        self.tun = tun
        self.tun_hop = tun_hop
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
        self.calcThread = TunnelMon(self.tun, self.tun_hop)
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
        self.upStatLabel.setText("{} kB/s - {} mb".format(round(ULrate, 1), round(ULacc, 1)))
        self.downStatLabel.setText("{} kB/s - {} mb".format(round(DLrate, 1), round(DLacc, 1)))

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

    def __init__(self, tun, tun_hop=None):
        QtCore.QThread.__init__(self)
        self.tun = tun
        self.tun_hop = tun_hop

    def run(self):
        connected = True
        check_url = "https://ipv4.ipleak.net/json"
        check_url_6 = "https://ipv6.ipleak.net/json"
        check_url_alt = "https://ipv4.icanhazip.com/"
        check_url_alt_6 = "https://ipv6.icanhazip.com/"

        try:

            try:
                query = requests.get(check_url, timeout=2).content.decode("utf-8")
                ip = json.loads(query)["ip"]

            except (KeyError, requests.exceptions.RequestException):

                try:
                    ip = requests.get(check_url_alt, timeout=2).content.decode("utf-8").replace("\n", "")

                except requests.exceptions.RequestException:
                    self.log.emit(("info", "Could not determine external ipv4 address"))
                    ip = None

            try:
                query = requests.get(check_url_6, timeout=2).content.decode("utf-8")
                ip_6 = json.loads(query)["ip"]

            except requests.exceptions.RequestException:

                try:
                    ip_6 = requests.get(check_url_alt_6, timeout=2).content.decode("utf-8").replace("\n", "")

                except requests.exceptions.RequestException:
                    self.log.emit(("info", "Could not determine external ipv6 address"))
                    ip_6 = None

            self.log.emit(("info", "External ip = {} - {}".format(ip, ip_6)))
            self.ip.emit((ip, ip_6))

        except:
            self.log.emit(("error", "Could not determine external ip address"))

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

            if int(elapsed) % 3600 == 0:
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
            config = "{}/{}_config".format(ROOTDIR, self.provider)

        else:
            config = "{}/{}".format(ROOTDIR, self.server_info["path"])

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
