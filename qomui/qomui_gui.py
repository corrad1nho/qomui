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

from qomui import config, update, latency, utils, firewall, widgets, profiles, monitor

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

JSON_FILE_LIST = [
    ("server_dict", "{}/server.json".format(config.HOMEDIR)),
    ("protocol_dict", "{}/protocol.json".format(config.HOMEDIR)),
    ("bypass_dict", "{}/bypass_apps.json".format(config.HOMEDIR)),
    ("profile_dict", "{}/profile.json".format(config.HOMEDIR))
]


class DbusLogHandler(logging.Handler):
    def __init__(self, qomui_service, parent=None):
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
    queue = []
    tunnel_list = ["OpenVPN", "WireGuard"]
    config_list = [
        "firewall",
        "autoconnect",
        "minimize",
        "ipv6_disable",
        "alt_dns",
        "bypass",
        "ping",
        "auto_update",
        "no_dnsmasq",
        "dns_off"
    ]

    routes = {
        "gateway": "None",
        "gateway_6": "None",
        "interface": "None",
        "interface_6": "None"
    }

    def __init__(self, parent=None):
        super(QomuiGui, self).__init__(parent)
        self.latency_list = []
        self.exit_timer = QtCore.QTimer(self)
        self.exit_event = event
        self.confirm = QtWidgets.QMessageBox()
        self.timeout = 5
        self.tray = QtWidgets.QSystemTrayIcon()
        self.trayIcon = QtGui.QIcon.fromTheme("qomui")
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.DEBUG)
        self.setWindowIcon(QtGui.QIcon.fromTheme("qomui"))
        self.setWindowState(QtCore.Qt.WindowMinimized)
        self.setupUi(self)
        self.dbus = dbus.SystemBus()

        try:
            self.qomui_dbus = self.dbus.get_object('org.qomui.service', '/org/qomui/service')

        except dbus.exceptions.DBusException:
            self.logger.error('DBus Error: Qomui-Service is currently not available')
            ret = self.messageBox(
                "Error: Qomui-service is not active",
                "Do you want to start it, enable it permanently or close Qomui?",
                buttons=[
                    ("Enable", "NoRole"),
                    ("Start", "YesRole"),
                    ("Close", "RejectRole")
                ],
                icon="Question"
            )

            if ret == 0:
                self.initalize_service("enable", "--now")

            elif ret == 1:
                self.initalize_service("start")

            elif ret == 2:
                sys.exit(1)

        self.create_dbus_object()
        handler = DbusLogHandler(self.qomui_service)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)
        primay_screen = QtWidgets.QDesktopWidget().primaryScreen()
        primary_screen_geometry = QtWidgets.QDesktopWidget().availableGeometry(primay_screen)
        positioning = primary_screen_geometry.bottomRight()
        self.setGeometry(QtCore.QRect(positioning.x() - 600, positioning.y() - 750,
                                      600, 750
                                      ))

        self.logger.debug('Successfully connected to qomui-service via DBus')
        self.dbus_call("disconnect", "main")
        self.dbus_call("disconnect", "bypass")
        self.dbus_call("save_default_dns")
        self.check_other_instance()
        self.load_saved_files()
        self.systemtray()
        self.net_mon_thread = monitor.NetMon()
        self.net_mon_thread.log.connect(self.log_from_thread)
        self.net_mon_thread.net_state_change.connect(self.network_change)
        self.net_mon_thread.start()

    def check_other_instance(self):
        try:
            pids = check_output(["pgrep", "qomui-gui"]).decode("utf-8").split("\n")
            if len(pids) > 0:
                this_instance = str(os.getpid())
                for pid in pids:
                    if pid != this_instance and pid != '':
                        check_call(["kill", pid])
                        self.logger.info("Closed instance of qomui-gui with pid {}".format(pid))

        except (CalledProcessError, FileNotFoundError):
            self.logger.error("Failed to identify or close other instances of qomui-gui")

    def dbus_call(self, cmd, *args):
        try:
            call = getattr(self.qomui_service, cmd)(*args)
            return call

        except dbus.exceptions.DBusException as e:
            print(e)
            if e.get_dbus_name() == "org.freedesktop.DBus.Error.ServiceUnknown":
                self.notify("Qomui: Dbus Error", "No reply from qomui-service. It may have crashed.", icon="Warning")
                ret = self.messageBox(
                    "Error: Qomui-service is not available",
                    "Do you want restart it or quit Qomui?",
                    buttons=[
                        ("Quit", "NoRole"),
                        ("Restart", "YesRole")
                    ],
                    icon="Question"
                )

                if ret == 0:
                    sys.exit(1)

                elif ret == 1:
                    self.initialize_service("restart")
                    time.sleep(3)

                    try:
                        if config.settings["bypass"] == 1:
                            self.dbus_call("bypass", {**self.routes, **utils.get_user_group()})

                    except KeyError:
                        pass

                    retry = self.dbus_call(cmd, *args)
                    return retry

            else:
                self.logger.error("Dbus Error: {}".format(e))
                self.notify("Qomui: Dbus Error", "An error occured. See log for details", icon="Warning")

        except Exception as e:
            self.logger.error("Dbus Error: {}".format(e))
            self.notify("Qomui: Dbus Error", "An unknown error occured. See log for details", icon="Warning")

    def initialize_service(self, *args):
        try:
            check_call(["pkexec", "systemctl", *args, "qomui"])
            self.qomui_dbus = self.dbus.get_object('org.qomui.service',
                                                   '/org/qomui/service'
                                                   )
            self.create_dbus_object()

        except (CalledProcessError, FileNotFoundError):
            self.logger.info("Failed to start qomui-service via systemd: Is systemd installed?")
            self.logger.info("Trying to start qomui-service without systemd")
            self.notify("Qomui: Systemd not available", "Starting qomui-service directly", icon="Info")

            try:
                temp_bash = "{}/start_service.sh".format(config.HOMEDIR)
                with open(temp_bash, "w") as temp_sh:
                    lines = ["#!/bin/bash \n", "nohup qomui-service & \n"]
                    temp_sh.writelines(lines)
                    temp_sh.close()
                    os.chmod(temp_bash, 0o774)
                    check_call(["pkexec", temp_bash])
                    self.create_dbus_object()

            except (CalledProcessError, FileNotFoundError):
                self.logger.error("Starting qomui-service failed: Exiting...")
                self.notify("Qomui: Failed to start service", "Exiting...", icon="Error")
                sys.exit(1)

    def create_dbus_object(self):
        self.qomui_dbus = self.dbus.get_object('org.qomui.service', '/org/qomui/service')
        self.qomui_service = dbus.Interface(self.qomui_dbus, 'org.qomui.service')
        self.qomui_service.connect_to_signal("send_log", self.receive_log)
        self.qomui_service.connect_to_signal("reply", self.openvpn_log_monitor)
        self.qomui_service.connect_to_signal("updated", self.restart)
        self.qomui_service.connect_to_signal("imported", self.downloaded)
        self.qomui_service.connect_to_signal("progress_bar", self.start_progress_bar)

    def receive_log(self, msg):
        self.logText.appendPlainText(msg)

    def setupUi(self, Form):
        Form.setObjectName(_fromUtf8("Form"))
        self.gLayoutMain = QtWidgets.QGridLayout(Form)
        self.gLayoutMain.setObjectName(_fromUtf8("gLayoutMain"))
        self.showActive = widgets.ActiveWidget("Active Connection", Form)
        self.gLayoutMain.addWidget(self.showActive, 0, 0, 1, 2)
        self.showActive.setVisible(False)
        self.vLayoutMain = QtWidgets.QVBoxLayout()
        self.vLayoutMain.setObjectName(_fromUtf8("vLayoutMain"))
        self.gLayoutMain.addLayout(self.vLayoutMain, 1, 0, 1, 2)
        self.vLayoutMain_2 = QtWidgets.QVBoxLayout()
        self.vLayoutMain_2.setObjectName(_fromUtf8("vLayoutMain_2"))

        # Tab section
        self.tabButtonGroup = QtWidgets.QButtonGroup(Form)
        self.tabButtonGroup.setExclusive(True)
        self.statusTabBt = QtWidgets.QCommandLinkButton(Form)
        self.statusTabBt.setMinimumSize(QtCore.QSize(100, 0))
        self.statusTabBt.setMaximumSize(QtCore.QSize(100, 100))
        self.statusTabBt.setCheckable(True)
        self.tabButtonGroup.addButton(self.statusTabBt)
        self.statusTabBt.setObjectName(_fromUtf8("statusTabBt"))
        self.vLayoutMain_2.addWidget(self.statusTabBt)
        self.serverTabBt = QtWidgets.QCommandLinkButton(Form)
        self.serverTabBt.setMinimumSize(QtCore.QSize(100, 0))
        self.serverTabBt.setMaximumSize(QtCore.QSize(100, 100))
        self.serverTabBt.setCheckable(True)
        self.tabButtonGroup.addButton(self.serverTabBt)
        self.serverTabBt.setObjectName(_fromUtf8("serverTabBt"))
        self.vLayoutMain_2.addWidget(self.serverTabBt)
        self.profileTabBt = QtWidgets.QCommandLinkButton(Form)
        self.profileTabBt.setMinimumSize(QtCore.QSize(100, 0))
        self.profileTabBt.setMaximumSize(QtCore.QSize(100, 100))
        self.profileTabBt.setCheckable(True)
        self.tabButtonGroup.addButton(self.profileTabBt)
        self.profileTabBt.setObjectName(_fromUtf8("profileTabBt"))
        self.vLayoutMain_2.addWidget(self.profileTabBt)
        self.providerTabBt = QtWidgets.QCommandLinkButton(Form)
        self.providerTabBt.setMinimumSize(QtCore.QSize(100, 0))
        self.providerTabBt.setMaximumSize(QtCore.QSize(100, 100))
        self.providerTabBt.setCheckable(True)
        self.tabButtonGroup.addButton(self.providerTabBt)
        self.providerTabBt.setObjectName(_fromUtf8("providerTabBt"))
        self.vLayoutMain_2.addWidget(self.providerTabBt)
        self.optionsTabBt = QtWidgets.QCommandLinkButton(Form)
        self.optionsTabBt.setMinimumSize(QtCore.QSize(100, 0))
        self.optionsTabBt.setMaximumSize(QtCore.QSize(100, 100))
        self.optionsTabBt.setCheckable(True)
        self.tabButtonGroup.addButton(self.optionsTabBt)
        self.optionsTabBt.setObjectName(_fromUtf8("optionsTabBt"))
        self.vLayoutMain_2.addWidget(self.optionsTabBt)
        self.logTabBt = QtWidgets.QCommandLinkButton(Form)
        self.logTabBt.setMinimumSize(QtCore.QSize(100, 0))
        self.logTabBt.setMaximumSize(QtCore.QSize(100, 100))
        self.logTabBt.setCheckable(True)
        self.tabButtonGroup.addButton(self.logTabBt)
        self.logTabBt.setObjectName(_fromUtf8("logTabBt"))
        self.vLayoutMain_2.addWidget(self.logTabBt)
        self.bypassTabBt = QtWidgets.QCommandLinkButton(Form)
        self.bypassTabBt.setVisible(False)
        self.bypassTabBt.setMinimumSize(QtCore.QSize(100, 0))
        self.bypassTabBt.setMaximumSize(QtCore.QSize(100, 100))
        self.bypassTabBt.setCheckable(True)
        self.tabButtonGroup.addButton(self.bypassTabBt)
        self.bypassTabBt.setObjectName(_fromUtf8("bypassTabBt"))
        self.vLayoutMain_2.addWidget(self.bypassTabBt)
        self.vLayoutMain_2.addStretch()
        self.gLayoutMain.addLayout(self.vLayoutMain_2, 2, 0, 1, 1)
        self.tabWidget = QtWidgets.QStackedWidget(Form)
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))

        # Status tab
        self.statusTab = QtWidgets.QWidget()
        self.statusTab.setObjectName(_fromUtf8("statusTab"))
        self.vLayoutStatus = QtWidgets.QVBoxLayout(self.statusTab)
        self.statusOffWidget = widgets.StatusOffWidget(self.statusTab)
        self.statusOnWidget = widgets.StatusOnWidget(self.statusTab)
        self.statusOnWidget.setVisible(False)
        self.vLayoutStatus.addWidget(self.statusOffWidget)
        self.vLayoutStatus.addWidget(self.statusOnWidget)
        self.hLayoutStatus = QtWidgets.QHBoxLayout(self.statusTab)
        self.versionLabel = QtWidgets.QLabel(self.statusTab)
        self.versionLabel.setObjectName(_fromUtf8("versionLabel"))
        self.updateQomuiBt = QtWidgets.QPushButton(self.statusTab)
        self.updateQomuiBt.setObjectName("updateQomuiBt")
        self.updateQomuiBt.setVisible(False)
        self.hLayoutStatus.addWidget(self.versionLabel)
        self.hLayoutStatus.addWidget(self.updateQomuiBt)
        self.hLayoutStatus.addStretch()
        self.homepageLabel = QtWidgets.QLabel(self.statusTab)
        self.homepageLabel.setObjectName(_fromUtf8("homepageLabel"))
        self.vLayoutStatus.addWidget(self.homepageLabel)
        self.vLayoutStatus.addLayout(self.hLayoutStatus)
        self.vLayoutStatus.addStretch()
        self.tabWidget.addWidget(self.statusTab)

        # Server tab
        self.serverTab = QtWidgets.QWidget()
        self.serverTab.setObjectName(_fromUtf8("serverTab"))
        self.vLayoutServer = QtWidgets.QVBoxLayout(self.serverTab)
        self.vLayoutServer.setObjectName(_fromUtf8("vLayoutServer"))
        self.hLayoutServer = QtWidgets.QHBoxLayout()
        self.hLayoutServer.setObjectName(_fromUtf8("hLayoutServer"))
        self.countryBox = QtWidgets.QComboBox(self.serverTab)
        self.countryBox.setObjectName(_fromUtf8("countryBox"))
        self.hLayoutServer.addWidget(self.countryBox)
        self.providerBox = QtWidgets.QComboBox(self.serverTab)
        self.providerBox.setObjectName(_fromUtf8("providerBox"))
        self.hLayoutServer.addWidget(self.providerBox)
        self.tunnelBox = QtWidgets.QComboBox(self.serverTab)
        self.tunnelBox.setObjectName(_fromUtf8("tunnelBox"))
        self.tunnelBox.setVisible(False)
        self.hLayoutServer.addWidget(self.tunnelBox)
        self.favouriteButton = widgets.favouriteButton(self.serverTab)
        self.favouriteButton.setCheckable(True)
        self.favouriteButton.setMinimumSize(QtCore.QSize(25, 25))
        self.favouriteButton.setMaximumSize(QtCore.QSize(25, 25))
        self.favouriteButton.setObjectName(_fromUtf8("favouriteButton"))
        self.hLayoutServer.addWidget(self.favouriteButton)
        self.vLayoutServer.addLayout(self.hLayoutServer)
        self.searchLine = QtWidgets.QLineEdit(self.serverTab)
        self.searchLine.setObjectName(_fromUtf8("searchLine"))
        self.vLayoutServer.addWidget(self.searchLine)
        self.serverListWidget = QtWidgets.QListWidget(self.serverTab)
        self.serverListWidget.setObjectName(_fromUtf8("serverListWidget"))
        self.serverListWidget.setBatchSize(10)
        self.serverListWidget.setUniformItemSizes(True)
        self.vLayoutServer.addWidget(self.serverListWidget)
        self.showHop = widgets.HopWidget(self.serverTab)
        self.showHop.setVisible(False)
        self.vLayoutServer.addWidget(self.showHop)
        self.hLayoutServer_2 = QtWidgets.QHBoxLayout()
        self.hLayoutServer_2.setObjectName(_fromUtf8("hLayoutServer_2"))
        self.hLayoutServer_2.addStretch()
        self.randomSeverBt = QtWidgets.QPushButton(self.serverTab)
        self.randomSeverBt.setObjectName(_fromUtf8("randomSeverBt"))
        self.randomSeverBt.setVisible(False)
        self.hLayoutServer_2.addWidget(self.randomSeverBt)
        self.addServerBt = QtWidgets.QPushButton(self.serverTab)
        self.addServerBt.setObjectName(_fromUtf8("addServerBt"))
        self.hLayoutServer_2.addWidget(self.addServerBt)
        self.modify_serverBt = QtWidgets.QPushButton(self.serverTab)
        self.modify_serverBt.setObjectName(_fromUtf8("modify_serverBt"))
        self.hLayoutServer_2.addWidget(self.modify_serverBt)
        self.delServerBt = QtWidgets.QPushButton(self.serverTab)
        self.delServerBt.setObjectName(_fromUtf8("delServerBt"))
        self.hLayoutServer_2.addWidget(self.delServerBt)
        self.vLayoutServer.addLayout(self.hLayoutServer_2)
        self.tabWidget.addWidget(self.serverTab)

        # Profile tab
        self.profileTab = QtWidgets.QWidget()
        self.profileTab.setObjectName(_fromUtf8("profileTab"))
        self.vLayoutProfile = QtWidgets.QVBoxLayout(self.profileTab)
        self.vLayoutProfile.setObjectName("vLayoutProfile")
        self.scrollProfiles = QtWidgets.QScrollArea()
        self.scrollProfiles.setWidgetResizable(True)
        self.scrollProfiles.setObjectName("scrollProfiles")
        self.scrollProfilesContents = QtWidgets.QWidget(self.scrollProfiles)
        self.scrollProfilesContents.setObjectName("scrollProfilesContents")
        self.vLayoutProfile_2 = QtWidgets.QVBoxLayout(self.scrollProfilesContents)
        self.vLayoutProfile_2.addStretch()
        self.scrollProfiles.setWidget(self.scrollProfilesContents)
        self.vLayoutProfile.addWidget(self.scrollProfiles)
        self.hLayoutProfile = QtWidgets.QHBoxLayout()
        self.hLayoutProfile.setObjectName("hLayoutProfile")
        spacerItem = QtWidgets.QSpacerItem(368, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.hLayoutProfile.addItem(spacerItem)
        self.addProfileBt = QtWidgets.QPushButton(self.profileTab)
        self.addProfileBt.setObjectName("addProfileBt")
        self.hLayoutProfile.addWidget(self.addProfileBt)
        self.vLayoutProfile.addLayout(self.hLayoutProfile)
        self.tabWidget.addWidget(self.profileTab)

        # Log tab
        self.logTab = QtWidgets.QWidget()
        self.logTab.setObjectName(_fromUtf8("logTab"))
        self.gLayoutLog = QtWidgets.QGridLayout(self.logTab)
        self.gLayoutLog.setObjectName(_fromUtf8("gLayoutLog"))
        self.logText = QtWidgets.QPlainTextEdit(self.logTab)
        self.logText.setReadOnly(True)
        self.gLayoutLog.addWidget(self.logText, 0, 0, 1, 4)
        self.logBox = QtWidgets.QComboBox(self.logTab)
        self.logBox.setObjectName(_fromUtf8("logBox"))
        self.gLayoutLog.addWidget(self.logBox, 1, 3, 1, 1)
        self.tabWidget.addWidget(self.logTab)

        # Option tab
        self.optionsTab = QtWidgets.QWidget()
        self.optionsTab.setObjectName(_fromUtf8("optionsTab"))
        self.vLayoutOption = QtWidgets.QVBoxLayout(self.optionsTab)
        self.vLayoutOption.setObjectName(_fromUtf8("vLayoutOption"))
        self.optionsScroll = QtWidgets.QScrollArea()
        self.optionsScroll.setWidgetResizable(True)
        self.optionsScroll.setObjectName(_fromUtf8("optionsScroll"))
        self.vLayoutOption.addWidget(self.optionsScroll)
        self.optionsScrollContents = QtWidgets.QWidget()
        self.optionsScroll.setWidget(self.optionsScrollContents)
        self.vLayoutOption_2 = QtWidgets.QVBoxLayout(self.optionsScrollContents)
        self.vLayoutOption_2.setObjectName(_fromUtf8("vLayoutOption_2"))
        bold_font = QtGui.QFont()
        bold_font.setBold(True)
        bold_font.setWeight(75)
        bold_font.setKerning(False)
        italic_font = QtGui.QFont()
        italic_font.setItalic(True)
        self.autoconnectOptCheck = QtWidgets.QCheckBox(self.optionsScroll)
        self.autoconnectOptCheck.setObjectName(_fromUtf8("autoconnectOptCheck"))
        self.autoconnectOptCheck.setFont(bold_font)
        self.vLayoutOption_2.addWidget(self.autoconnectOptCheck)
        self.autoconnectOptLabel = QtWidgets.QLabel(self.optionsScroll)
        self.autoconnectOptLabel.setObjectName(_fromUtf8("autoconnectOptLabel"))
        self.autoconnectOptLabel.setWordWrap(True)
        self.autoconnectOptLabel.setIndent(20)
        self.autoconnectOptLabel.setFont(italic_font)
        self.vLayoutOption_2.addWidget(self.autoconnectOptLabel)
        self.minimizeOptCheck = QtWidgets.QCheckBox(self.optionsScroll)
        self.minimizeOptCheck.setFont(bold_font)
        self.minimizeOptCheck.setObjectName(_fromUtf8("minimizeOptCheck"))
        self.vLayoutOption_2.addWidget(self.minimizeOptCheck)
        self.minimizeOptLabel = QtWidgets.QLabel(self.optionsScroll)
        self.minimizeOptLabel.setObjectName(_fromUtf8("minimizeOptLabel"))
        self.minimizeOptLabel.setWordWrap(True)
        self.minimizeOptLabel.setIndent(20)
        self.minimizeOptLabel.setFont(italic_font)
        self.vLayoutOption_2.addWidget(self.minimizeOptLabel)
        self.auto_updateOptCheck = QtWidgets.QCheckBox(self.optionsScroll)
        self.auto_updateOptCheck.setObjectName(_fromUtf8("auto_updateOptCheck"))
        self.auto_updateOptCheck.setFont(bold_font)
        self.vLayoutOption_2.addWidget(self.auto_updateOptCheck)
        self.auto_updateOptLabel = QtWidgets.QLabel(self.optionsScroll)
        self.auto_updateOptLabel.setObjectName(_fromUtf8("auto_updateOptLabel"))
        self.auto_updateOptLabel.setWordWrap(True)
        self.auto_updateOptLabel.setIndent(20)
        self.auto_updateOptLabel.setFont(italic_font)
        self.vLayoutOption_2.addWidget(self.auto_updateOptLabel)
        self.pingOptCheck = QtWidgets.QCheckBox(self.optionsScroll)
        self.pingOptCheck.setFont(bold_font)
        self.pingOptCheck.setObjectName(_fromUtf8("pingOptCheck"))
        self.vLayoutOption_2.addWidget(self.pingOptCheck)
        self.pingOptLabel = QtWidgets.QLabel(self.optionsScroll)
        self.pingOptLabel.setObjectName(_fromUtf8("pingOptLabel"))
        self.pingOptLabel.setWordWrap(True)
        self.pingOptLabel.setIndent(20)
        self.pingOptLabel.setFont(italic_font)
        self.vLayoutOption_2.addWidget(self.pingOptLabel)
        self.ipv6_disableOptCheck = QtWidgets.QCheckBox(self.optionsScroll)
        self.ipv6_disableOptCheck.setFont(bold_font)
        self.ipv6_disableOptCheck.setObjectName(_fromUtf8("ipv6_disableOptCheck"))
        self.vLayoutOption_2.addWidget(self.ipv6_disableOptCheck)
        self.ipv6_disableOptLabel = QtWidgets.QLabel(self.optionsScroll)
        self.ipv6_disableOptLabel.setObjectName(_fromUtf8("ipv6_disableOptLabel"))
        self.ipv6_disableOptLabel.setWordWrap(True)
        self.ipv6_disableOptLabel.setIndent(20)
        self.ipv6_disableOptLabel.setFont(italic_font)
        self.vLayoutOption_2.addWidget(self.ipv6_disableOptLabel)
        self.bypassOptCheck = QtWidgets.QCheckBox(self.optionsScroll)
        self.bypassOptCheck.setFont(bold_font)
        self.bypassOptCheck.setObjectName(_fromUtf8("bypassOptCheck"))
        self.vLayoutOption_2.addWidget(self.bypassOptCheck)
        self.bypassOptLabel = QtWidgets.QLabel(self.optionsScroll)
        self.bypassOptLabel.setObjectName(_fromUtf8("bypassOptLabel"))
        self.bypassOptLabel.setWordWrap(True)
        self.bypassOptLabel.setIndent(20)
        self.bypassOptLabel.setFont(italic_font)
        self.vLayoutOption_2.addWidget(self.bypassOptLabel)
        self.hLayoutOption = QtWidgets.QHBoxLayout()
        self.hLayoutOption.setObjectName(_fromUtf8("hLayoutOption"))
        self.firewallOptCheck = QtWidgets.QCheckBox(self.optionsScroll)
        self.firewallOptCheck.setFont(bold_font)
        self.firewallOptCheck.setObjectName(_fromUtf8("firewallOptCheck"))
        self.hLayoutOption.addWidget(self.firewallOptCheck)
        self.firewallEditBt = QtWidgets.QPushButton(self.optionsScroll)
        self.firewallEditBt.setObjectName(_fromUtf8("firewallEditBt"))
        self.hLayoutOption.addWidget(self.firewallEditBt)
        self.hLayoutOption.addStretch()
        self.hLayoutOption.setObjectName(_fromUtf8("hLayoutOption"))
        self.vLayoutOption_2.addLayout(self.hLayoutOption)
        self.firewallOptLabel = QtWidgets.QLabel(self.optionsScroll)
        self.firewallOptLabel.setObjectName(_fromUtf8("firewallOptLabel"))
        self.firewallOptLabel.setWordWrap(True)
        self.firewallOptLabel.setIndent(20)
        self.firewallOptLabel.setFont(italic_font)
        self.vLayoutOption_2.addWidget(self.firewallOptLabel)
        self.vLayoutOption_2.addSpacing(15)
        self.alt_dnsOptLabel = QtWidgets.QLabel(self.optionsScroll)
        bold_font = QtGui.QFont()
        bold_font.setBold(True)
        bold_font.setWeight(75)
        bold_font.setKerning(False)
        self.alt_dnsOptLabel.setFont(bold_font)
        self.alt_dnsOptLabel.setObjectName(_fromUtf8("alt_dnsOptLabel"))
        self.vLayoutOption_2.addWidget(self.alt_dnsOptLabel)
        self.dns_offOptCheck = QtWidgets.QCheckBox(self.optionsScroll)
        self.dns_offOptCheck.setFont(bold_font)
        self.dns_offOptCheck.setObjectName(_fromUtf8("dns_offOptCheck"))
        self.vLayoutOption_2.addWidget(self.dns_offOptCheck)
        self.no_dnsmasqOptCheck = QtWidgets.QCheckBox(self.optionsScroll)
        self.no_dnsmasqOptCheck.setFont(bold_font)
        self.no_dnsmasqOptCheck.setObjectName(_fromUtf8("no_dnsmasqOptCheck"))
        self.vLayoutOption_2.addWidget(self.no_dnsmasqOptCheck)
        self.alt_dnsOptCheck = QtWidgets.QCheckBox(self.optionsScroll)
        self.alt_dnsOptCheck.setFont(bold_font)
        self.alt_dnsOptCheck.setObjectName(_fromUtf8("alt_dnsOptCheck"))
        self.vLayoutOption_2.addWidget(self.alt_dnsOptCheck)
        self.hLayoutOption_2 = QtWidgets.QHBoxLayout()
        self.hLayoutOption_2.setObjectName(_fromUtf8("hLayoutOption_2"))
        self.altDnsEdit1 = QtWidgets.QLineEdit(self.optionsScroll)
        self.altDnsEdit1.setObjectName(_fromUtf8("altDnsEdit1"))
        self.hLayoutOption_2.addWidget(self.altDnsEdit1)
        self.altDnsEdit2 = QtWidgets.QLineEdit(self.optionsScroll)
        self.altDnsEdit2.setObjectName(_fromUtf8("altDnsEdit2"))
        self.hLayoutOption_2.addWidget(self.altDnsEdit2)
        self.vLayoutOption_2.addLayout(self.hLayoutOption_2)
        self.dnsInfoLabel = QtWidgets.QLabel(self.optionsScroll)
        self.dnsInfoLabel.setObjectName(_fromUtf8("dnsInfoLabel"))
        self.dnsInfoLabel.setWordWrap(True)
        self.dnsInfoLabel.setFont(italic_font)
        self.vLayoutOption_2.addWidget(self.dnsInfoLabel)
        self.vLayoutOption_2.addStretch()
        self.hLayoutOption_3 = QtWidgets.QHBoxLayout()
        self.hLayoutOption_3.setObjectName(_fromUtf8("hLayoutOption_3"))
        self.hLayoutOption_3.addStretch()
        self.restoreDefaultOptBt = QtWidgets.QPushButton(self.optionsScroll)
        self.restoreDefaultOptBt.setObjectName(_fromUtf8("restoreDefaultOptBt"))
        self.hLayoutOption_3.addWidget(self.restoreDefaultOptBt)
        self.applyOptBt = QtWidgets.QPushButton(self.optionsScroll)
        self.applyOptBt.setObjectName(_fromUtf8("applyOptBt"))
        self.hLayoutOption_3.addWidget(self.applyOptBt)
        self.cancelOptBt = QtWidgets.QPushButton(self.optionsScroll)
        self.cancelOptBt.setObjectName(_fromUtf8("cancelOptBt"))
        self.hLayoutOption_3.addWidget(self.cancelOptBt)
        self.vLayoutOption.addLayout(self.hLayoutOption_3)
        self.tabWidget.addWidget(self.optionsTab)

        # Provider tab
        self.providerTab = QtWidgets.QScrollArea()
        self.providerTab.setObjectName(_fromUtf8("providerTab"))
        self.providerTab.setMaximumHeight(1000)
        self.providerTab.setWidgetResizable(True)
        self.providerTabContents = QtWidgets.QWidget()
        self.providerTabContents.setObjectName("providerTabContents")
        self.vLayoutProvider = QtWidgets.QVBoxLayout(self.providerTabContents)
        self.providerTab.setWidget(self.providerTabContents)
        bold_font = QtGui.QFont()
        bold_font.setBold(True)
        bold_font.setWeight(75)
        self.addProviderLabel = QtWidgets.QLabel(self.providerTab)
        self.addProviderLabel.setFont(bold_font)
        self.addProviderLabel.setObjectName("addProviderLabel")
        self.vLayoutProvider.addWidget(self.addProviderLabel)
        self.addProviderBox = QtWidgets.QComboBox(self.providerTab)
        self.addProviderBox.setObjectName(_fromUtf8("addProviderBox"))
        self.vLayoutProvider.addWidget(self.addProviderBox)
        self.addProviderEdit = QtWidgets.QLineEdit(self.providerTab)
        self.addProviderEdit.setObjectName(_fromUtf8("addProviderEdit"))
        self.addProviderEdit.setVisible(False)
        self.vLayoutProvider.addWidget(self.addProviderEdit)
        self.gLayoutProvider = QtWidgets.QGridLayout()
        self.gLayoutProvider.setObjectName(_fromUtf8("gLayoutProvider"))
        self.addProviderUserEdit = QtWidgets.QLineEdit(self.providerTab)
        self.addProviderUserEdit.setObjectName(_fromUtf8("addProviderUserEdit"))
        self.gLayoutProvider.addWidget(self.addProviderUserEdit, 0, 0, 1, 2)
        self.addProviderDownloadBt = QtWidgets.QPushButton(self.providerTab)
        self.addProviderDownloadBt.setObjectName(_fromUtf8("addProviderDownloadBt"))
        self.gLayoutProvider.addWidget(self.addProviderDownloadBt, 0, 2, 1, 1)
        self.addProviderPassEdit = QtWidgets.QLineEdit(self.providerTab)
        self.addProviderPassEdit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.addProviderPassEdit.setObjectName(_fromUtf8("addProviderPassEdit"))
        self.gLayoutProvider.addWidget(self.addProviderPassEdit, 1, 0, 1, 2)
        self.airvpnKeyEdit = QtWidgets.QLineEdit(self.providerTab)
        self.airvpnKeyEdit.setObjectName(_fromUtf8("airvpnKeyEdit"))
        self.gLayoutProvider.addWidget(self.airvpnKeyEdit, 2, 0, 1, 2)
        self.vLayoutProvider.addLayout(self.gLayoutProvider)
        self.vLayoutProvider.addSpacing(10)
        self.delProviderLabel = QtWidgets.QLabel(self.providerTab)
        self.delProviderLabel.setFont(bold_font)
        self.delProviderLabel.setObjectName("delProviderLabel")
        self.vLayoutProvider.addWidget(self.delProviderLabel)
        self.hLayoutProvider2 = QtWidgets.QHBoxLayout()
        self.hLayoutProvider2.setObjectName("hLayoutProvider2")
        self.delProviderBox = QtWidgets.QComboBox(self.providerTab)
        self.delProviderBox.setObjectName("delProviderBox")
        self.hLayoutProvider2.addWidget(self.delProviderBox)
        self.delProviderBt = QtWidgets.QPushButton(self.providerTab)
        self.delProviderBt.setObjectName("delProviderBt")
        self.hLayoutProvider2.addWidget(self.delProviderBt)
        self.hLayoutProvider2.addStretch()
        self.vLayoutProvider.addLayout(self.hLayoutProvider2)
        self.vLayoutProvider.addSpacing(10)
        self.protocolLabel = QtWidgets.QLabel(self.providerTab)
        self.protocolLabel.setFont(bold_font)
        self.protocolLabel.setObjectName("protocolLabel")
        self.vLayoutProvider.addWidget(self.protocolLabel)
        self.providerProtocolBox = QtWidgets.QComboBox(self.providerTab)
        self.providerProtocolBox.setObjectName("providerProtocolBox")
        self.vLayoutProvider.addWidget(self.providerProtocolBox)
        self.protocolListWidget = QtWidgets.QListWidget(self.providerTab)
        self.protocolListWidget.setObjectName("protocolListWidget")
        self.vLayoutProvider.addWidget(self.protocolListWidget)
        self.overrideCheck = QtWidgets.QCheckBox(self.providerTab)
        self.overrideCheck.setObjectName("overrideCheck")
        self.overrideCheck.setVisible(False)
        self.vLayoutProvider.addWidget(self.overrideCheck)
        self.hLayoutProvider = QtWidgets.QHBoxLayout()
        self.hLayoutProvider.setObjectName("hLayoutProvider")
        self.chooseProtocolBox = QtWidgets.QComboBox(self.providerTab)
        self.chooseProtocolBox.setObjectName("chooseProtocolBox")
        self.chooseProtocolBox.addItem("UDP")
        self.chooseProtocolBox.addItem("TCP")
        self.chooseProtocolBox.setVisible(False)
        self.hLayoutProvider.addWidget(self.chooseProtocolBox)
        self.portOverrideLabel = QtWidgets.QLabel(self.providerTab)
        self.portOverrideLabel.setObjectName("portOverrideLabel")
        self.portOverrideLabel.setVisible(False)
        self.hLayoutProvider.addWidget(self.portOverrideLabel)
        self.portEdit = QtWidgets.QLineEdit(self.providerTab)
        self.portEdit.setObjectName("portEdit")
        self.portEdit.setVisible(False)
        self.hLayoutProvider.addWidget(self.portEdit)
        self.vLayoutProvider.addLayout(self.hLayoutProvider)
        self.savePortButton = QtWidgets.QPushButton(self.providerTab)
        self.savePortButton.setObjectName("savePortButton")
        self.savePortButton.setVisible(False)
        self.hLayoutProvider.addWidget(self.savePortButton)
        self.hLayoutProvider.addStretch()
        self.vLayoutProvider.addSpacing(10)
        self.scriptLabel = QtWidgets.QLabel(self.providerTab)
        self.scriptLabel.setFont(bold_font)
        self.scriptLabel.setObjectName("scriptLabel")
        self.vLayoutProvider.addWidget(self.scriptLabel)
        self.gLayoutProvider_2 = QtWidgets.QGridLayout(Form)
        self.gLayoutProvider_2.setObjectName("gLayoutMain")
        self.preCheck = QtWidgets.QLabel(Form)
        self.preCheck.setObjectName("preCheck")
        self.gLayoutProvider_2.addWidget(self.preCheck, 0, 0, 1, 1)
        self.preEdit = QtWidgets.QLineEdit(Form)
        self.preEdit.setObjectName("preEdit")
        self.gLayoutProvider_2.addWidget(self.preEdit, 0, 1, 1, 1)
        self.upCheck = QtWidgets.QLabel(Form)
        self.upCheck.setObjectName("upCheck")
        self.gLayoutProvider_2.addWidget(self.upCheck, 1, 0, 1, 1)
        self.upEdit = QtWidgets.QLineEdit(Form)
        self.upEdit.setObjectName("upEdit")
        self.gLayoutProvider_2.addWidget(self.upEdit, 1, 1, 1, 1)
        self.downCheck = QtWidgets.QLabel(Form)
        self.downCheck.setObjectName("downCheck")
        self.gLayoutProvider_2.addWidget(self.downCheck, 2, 0, 1, 1)
        self.downEdit = QtWidgets.QLineEdit(Form)
        self.downEdit.setObjectName("downEdit")
        self.gLayoutProvider_2.addWidget(self.downEdit, 2, 1, 1, 1)
        self.vLayoutProvider.addLayout(self.gLayoutProvider_2)
        self.hLayoutProvider2 = QtWidgets.QHBoxLayout()
        self.hLayoutProvider2.setObjectName("hLayoutProvider2")
        spacerItem3 = QtWidgets.QSpacerItem(40, 20,
                                            QtWidgets.QSizePolicy.Expanding,
                                            QtWidgets.QSizePolicy.Minimum
                                            )
        self.hLayoutProvider2.addItem(spacerItem3)
        self.confirmScripts = QtWidgets.QDialogButtonBox(self.providerTab)
        self.confirmScripts.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel | QtWidgets.QDialogButtonBox.Save)
        self.confirmScripts.setObjectName("confirmScripts")
        self.hLayoutProvider2.addWidget(self.confirmScripts)
        self.vLayoutProvider.addLayout(self.hLayoutProvider2)
        self.vLayoutProvider.addStretch()
        self.tabWidget.addWidget(self.providerTab)

        # Bypass tab
        self.bypassTab = QtWidgets.QWidget()
        self.bypassTab.setObjectName(_fromUtf8("bypassTab"))
        self.vLayoutBypass = QtWidgets.QVBoxLayout(self.bypassTab)
        self.vLayoutBypass.setObjectName(_fromUtf8("vLayoutBypass"))
        self.bypassInfoLabel = QtWidgets.QLabel(self.optionsTab)
        self.bypassInfoLabel.setObjectName(_fromUtf8("bypassOptCheck"))
        self.bypassInfoLabel.setWordWrap(True)
        self.bypassInfoLabel.setFont(italic_font)
        self.vLayoutBypass.addWidget(self.bypassInfoLabel)
        self.hLayoutBypass = QtWidgets.QHBoxLayout()
        self.hLayoutBypass.setObjectName(_fromUtf8("hLayoutBypass"))
        self.bypassVpnBox = QtWidgets.QComboBox(self.bypassTab)
        self.bypassVpnBox.setObjectName(_fromUtf8("bypassVpnBox"))
        self.hLayoutBypass.addWidget(self.bypassVpnBox)
        self.bypassVpnButton = QtWidgets.QPushButton(self.bypassTab)
        self.bypassVpnButton.setObjectName(_fromUtf8("bypassVpnButton"))
        self.bypassVpnButton.setMaximumWidth(120)
        self.hLayoutBypass.addWidget(self.bypassVpnButton)
        self.vLayoutBypass.addLayout(self.hLayoutBypass)
        self.bypassAppList = QtWidgets.QListWidget(self.bypassTab)
        self.bypassAppList.setObjectName(_fromUtf8("bypassAppList"))
        self.bypassAppList.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.vLayoutBypass.addWidget(self.bypassAppList)
        self.hLayoutBypass2 = QtWidgets.QHBoxLayout()
        self.hLayoutBypass2.setObjectName(_fromUtf8("hLayoutBypass2"))
        spacerItem3 = QtWidgets.QSpacerItem(40, 20,
                                            QtWidgets.QSizePolicy.Expanding,
                                            QtWidgets.QSizePolicy.Minimum
                                            )
        self.hLayoutBypass2.addItem(spacerItem3)
        self.addBypassAppBt = QtWidgets.QPushButton(self.bypassTab)
        self.addBypassAppBt.setObjectName(_fromUtf8("addBypassAppBt"))
        self.hLayoutBypass2.addWidget(self.addBypassAppBt)
        self.delBypassAppBt = QtWidgets.QPushButton(self.bypassTab)
        self.delBypassAppBt.setObjectName(_fromUtf8("delBypassAppBt"))
        self.hLayoutBypass2.addWidget(self.delBypassAppBt)
        self.vLayoutBypass.addLayout(self.hLayoutBypass2)
        self.tabWidget.addWidget(self.bypassTab)

        self.gLayoutMain.addWidget(self.tabWidget, 2, 1, 1, 1)
        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

        self.providerProtocolBox.activated[str].connect(self.pop_ProtocolListWidget)
        self.addServerBt.clicked.connect(self.switch_providerTab)
        self.delServerBt.clicked.connect(self.del_single_server)
        self.countryBox.activated[str].connect(self.filter_servers)
        self.providerBox.activated[str].connect(self.filter_servers)
        self.tunnelBox.activated[str].connect(self.filter_servers)
        self.statusTabBt.clicked.connect(self.tab_switch)
        self.serverTabBt.clicked.connect(self.tab_switch)
        self.bypassTabBt.clicked.connect(self.tab_switch)
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
        self.showActive.disconnect.connect(self.kill)
        self.showActive.reconnect.connect(self.reconnect)
        self.showActive.check_update.connect(self.update_check)

        self.tabWidget.setCurrentIndex(1)

    def retranslateUi(self, Form):
        s = ""
        Form.setWindowTitle(_translate("Form", "Qomui", None))
        self.statusTabBt.setText(_translate("Form", "Status", None))
        self.serverTabBt.setText(_translate("Form", "Server", None))
        self.logTabBt.setText(_translate("Form", "Log", None))
        self.profileTabBt.setText(_translate("Form", "Profiles", None))
        self.providerTabBt.setText(_translate("Form", "Provider", None))
        self.bypassTabBt.setText(_translate("Form", "Bypass", None))
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
        self.dns_offOptCheck.setText(_translate("Form", "Never change DNS servers", None))
        self.no_dnsmasqOptCheck.setText(_translate("Form", "Use same DNS servers for bypass", None))
        self.alt_dnsOptLabel.setText(_translate("Form", "DNS settings and alternative servers", None))
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
        self.versionLabel.setText(_translate("Form", "Version:", None))
        self.homepageLabel.setText(_translate("Form", "<b>Homepage:</b> https://github.com/corrad1nho/qomui", None))
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

        for provider in config.SUPPORTED_PROVIDERS:
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
        self.dbus_call("log_level_change", level)

    def restart(self, new_version):
        self.stop_progress_bar("upgrade")

        if new_version != "failed":
            self.versionLabel.setText("<b>Version:</b>: {}".format(new_version))
            self.updateQomuiBt.setVisible(False)
            ret = self.messageBox(
                "Qomui has been upgraded",
                "Do you want to restart Qomui?",
                buttons=[("Later", "NoRole"), ("Now", "YesRole")],
                icon="Question"
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
                self.dbus_call("restart")
                os.execl(sys.executable, sys.executable, *sys.argv)

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
                self.versionLabel.setText("<b>Version:</b> {} ({} is available)".format(self.installed, self.release))

                self.notify(
                    'Qomui: Update available',
                    'Download version {} via "Status" tab'.format(self.release),
                    icon="Information"
                )

        except ValueError:
            pass

    def update_qomui(self):
        self.dbus_call("update_qomui", self.release, self.packetmanager)
        self.start_progress_bar("upgrade")

    def tab_switch(self):
        button = self.sender().text().replace("&", "")
        if button == "Status":
            self.tabWidget.setCurrentIndex(0)
        elif button == "Server":
            self.tabWidget.setCurrentIndex(1)
        elif button == "Profiles":
            self.tabWidget.setCurrentIndex(2)
        elif button == "Log":
            self.tabWidget.setCurrentIndex(3)
            self.logText.verticalScrollBar().setValue(self.logText.verticalScrollBar().maximum())
        elif button == "Options":
            self.setOptiontab(config.settings)
            self.tabWidget.setCurrentIndex(4)
        elif button == "Provider":
            self.tabWidget.setCurrentIndex(5)
            self.providerChosen()
        elif button == "Bypass":
            self.tabWidget.setCurrentIndex(6)
            self.bypassVpnBox.clear()

            for k, v in self.server_dict.items():
                if "favourite" in v:
                    if v["favourite"] == "on":
                        self.bypassVpnBox.addItem(k)

    def switch_providerTab(self):
        self.tabWidget.setCurrentIndex(4)

    def systemtray(self):

        if not self.tray.isSystemTrayAvailable():
            self.setWindowState(QtCore.Qt.WindowActive)
            self.showNormal()
        else:
            self.tray.setIcon(self.trayIcon)
            self.trayMenu = QtWidgets.QMenu()
            self.pop_tray_menu()
            self.tray.setContextMenu(self.trayMenu)
            self.tray.show()
            self.tray.setToolTip("Status: disconnected")
            self.tray.activated.connect(self.restoreUi)

        # if self.windowState() == QtCore.Qt.WindowActive:
        #   self.trayMenu.insert(Action)

    def pop_tray_menu(self):
        self.trayMenu.clear()
        self.visibility_action = QtWidgets.QAction(self)
        self.visibility_action.setText("Hide")
        self.trayMenu.addAction(self.visibility_action)
        self.trayMenu.addSeparator()
        self.trayMenu.addSeparator()
        for p, v in self.profile_dict.items():
            name = self.trayMenu.addAction(v["name"])
            name.triggered.connect(partial(self.connect_profile, p))
        self.trayMenu.addSeparator()
        exit_action = self.trayMenu.addAction("Quit")
        self.visibility_action.triggered.connect(self.toggle_visibility)
        exit_action.triggered.connect(self.shutdown)

    def toggle_visibility(self):
        if self.visibility_action.text() == "Show":
            self.showNormal()
            self.visibility_action.setText("Hide")

        else:
            self.hide()
            self.visibility_action.setText("Show")

    def activate_window(self):
        self.setWindowState(QtCore.Qt.WindowActive)
        self.showNormal()

    def shutdown(self):
        self.tray.hide()
        self.kill()
        self.disconnect_bypass()
        self.dbus_call("load_firewall", 2)
        with open("{}/server.json".format(config.HOMEDIR), "w") as s:
            json.dump(self.server_dict, s)
        sys.exit()

    def restoreUi(self, reason):
        if self.isVisible() is True:
            self.setWindowState(QtCore.Qt.WindowMinimized)
            self.hide()
        else:
            self.setWindowState(QtCore.Qt.WindowActive)
            self.showNormal()

    def closeEvent(self, event):
        self.confirm.setText("Do you really want to quit Qomui?")
        info = "Closing in {} seconds".format(self.timeout)
        self.confirm.setInformativeText(info)
        self.confirm.setIcon(QtWidgets.QMessageBox.Question)
        self.confirm.addButton(QtWidgets.QPushButton("Exit"), QtWidgets.QMessageBox.YesRole)
        self.confirm.addButton(QtWidgets.QPushButton("Cancel"), QtWidgets.QMessageBox.NoRole)
        if self.tray.isSystemTrayAvailable():
            self.confirm.addButton(QtWidgets.QPushButton("Minimize"), QtWidgets.QMessageBox.RejectRole)
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
            self.shutdown()
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

        except (FileNotFoundError, json.decoder.JSONDecodeError) as e:
            self.logger.warning('{}: Could not open {}'.format(e, json_file))
            return {}

    def connect_last_server(self):
        try:
            if config.settings["autoconnect"] == 1:
                self.kill()
                self.disconnect_bypass()
                last_server_dict = self.load_json("{}/last_server.json".format(config.HOMEDIR))

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
        config.load_config()
        self.logger.debug("Current configuration: {}".format(config.settings))

        try:
            with open("{}/VERSION".format(config.ROOTDIR), "r") as v:
                version = v.read().split("\n")
                self.installed = version[0]
                self.logger.info("Qomui version {}".format(self.installed))
                service_version = self.dbus_call("get_version")

                if service_version is None:
                    self.logger.error("Checking version of qomui-service failed")
                    service_version = "None"

                if service_version != self.installed and service_version != "None":
                    self.notify(
                        "Qomui: Version discrepancy detected",
                        "Qomui-Gui and qomui-service not running the same version",
                        icon="Warning")
                    self.logger.warning(
                        "qomui-service is running different version than qomui-gui: {} vs {}".format(service_version,
                                                                                                     self.installed))
                    self.logger.info("Restarting qomui-gui and qomui-service")
                    self.restart_qomui()

                self.versionLabel.setText("<b>Version:</b> {}".format(self.installed))

                try:
                    pm_check = version[1]
                    if pm_check != "":
                        self.packetmanager = pm_check
                    else:
                        self.packetmanager = "None"

                except IndexError:
                    pass

        except FileNotFoundError:
            self.logger.warning("{}/VERSION does not exist".format(config.ROOTDIR))
            self.versionInfo.setText("<b>Version:</b> N.A.")

        for saved_file in JSON_FILE_LIST:
            setattr(self, saved_file[0], self.load_json(saved_file[1]))

        try:
            if config.settings["minimize"] == 0:
                self.setWindowState(QtCore.Qt.WindowActive)

        except KeyError:
            pass

        try:
            if config.settings["firewall"] == 1 and config.settings["fw_gui_only"] == 1:
                self.dbus_call("load_firewall", 1)

        except KeyError:
            pass

        try:
            self.logger.setLevel(getattr(logging, config.settings["log_level"].upper()))
            if config.settings["log_level"] == "Debug":
                self.logBox.setCurrentIndex(1)

        except KeyError:
            pass

        try:
            if config.settings["bypass"] == 1:
                self.bypassTabBt.setVisible(True)

        except KeyError:
            pass

        for p in self.profile_dict.keys():
            self.display_profile(p)

        self.setOptiontab(config.settings)
        self.pop_boxes(country='All countries')
        self.pop_bypassAppList()
        # self.connect_last_server()

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
        default_config_dict = config.default_settings
        self.setOptiontab(default_config_dict)

    def cancelOptions(self):
        self.setOptiontab(config.settings)

    def read_option_change(self):
        temp_config_dict = {"alt_dns1": self.altDnsEdit1.text().replace("\n", ""),
                            "alt_dns2": self.altDnsEdit2.text().replace("\n", "")}
        print(self.config_list)
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

        with open('{}/config_temp.json'.format(config.HOMEDIR), 'w') as c:
            json.dump(temp_config, c)

        update_cmd = ['pkexec', sys.executable, '-m', 'qomui.mv_config',
                      '-d', '{}'.format(config.HOMEDIR)]

        if firewall is not None:
            update_cmd.append('-f')

        try:
            check_call(update_cmd)
            self.logger.info("Configuration changes applied successfully")
            self.dbus_call("load_firewall", 1)
            self.dbus_call("bypass", {**self.routes, **utils.get_user_group()})
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

            config.settings = temp_config

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
            self.logger.info("Detected new network connection")
            self.dbus_call("save_default_dns")
            if config.settings["ping"] == 1:
                self.get_latencies()
            self.kill()
            self.disconnect_bypass()
            self.connect_last_server()
            self.dbus_call("bypass", {**self.routes, **utils.get_user_group()})

        elif self.network_state == 0:
            self.logger.info("Lost network connection - VPN tunnel terminated")
            self.kill()
            self.disconnect_bypass()

    def providerChosen(self):
        self.addProviderUserEdit.setText("")
        self.addProviderPassEdit.setText("")
        provider = self.addProviderBox.currentText()

        p_txt = {
            "Airvpn": ("Username", "Password"),
            "PIA": ("Username", "Password"),
            "Windscribe": ("Username", "Password"),
            "AzireVPN": ("Username", "Password"),
            "Mullvad": ("Account Number", "N.A. - Leave empty"),
            "ProtonVPN": ("OpenVPN username", "OpenVPN password")
        }

        if provider in config.SUPPORTED_PROVIDERS:
            self.airvpnKeyEdit.setVisible(False)
            self.addProviderEdit.setVisible(False)
            self.addProviderUserEdit.setPlaceholderText(_translate("Form", p_txt[provider][0], None))
            self.addProviderPassEdit.setPlaceholderText(_translate("Form", p_txt[provider][1], None))
            if provider in self.provider_list:
                self.addProviderDownloadBt.setText(_translate("Form", "Update", None))
            else:
                self.addProviderDownloadBt.setText(_translate("Form", "Download", None))
            if provider == "Airvpn":
                self.airvpnKeyEdit.setPlaceholderText(_translate("Form", "Key/Device: Default", None))
                self.airvpnKeyEdit.setVisible(True)

        else:
            self.airvpnKeyEdit.setVisible(False)
            self.addProviderEdit.setVisible(True)
            self.addProviderEdit.setPlaceholderText(_translate("Form",
                                                               "Specify name of provider",
                                                               None
                                                               ))
            self.addProviderUserEdit.setPlaceholderText(_translate("Form", "Username", None))
            self.addProviderPassEdit.setPlaceholderText(_translate("Form", "Password", None))
            self.addProviderDownloadBt.setText(_translate("Form", "Add Folder", None))

    def add_server_configs(self):
        if not os.path.exists("{}/temp".format(config.HOMEDIR)):
            os.makedirs("{}/temp".format(config.HOMEDIR))

        folderpath = "None"
        provider = self.addProviderBox.currentText()
        username = self.addProviderUserEdit.text()
        password = self.addProviderPassEdit.text()

        if provider not in config.SUPPORTED_PROVIDERS:
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
                                                                   directory=os.path.expanduser("~"),
                                                                   filter=self.tr(
                                                                       'OpenVPN (*.ovpn *conf);;All files (*.*)'),
                                                                   options=QtWidgets.QFileDialog.ReadOnly)

                    folderpath = QtCore.QFileInfo(dialog[0]).absolutePath()

                except TypeError:
                    folderpath = ""

        if folderpath != "" and provider != "":
            credentials = {
                "provider": provider,
                "username": username,
                "password": password,
                "folderpath": folderpath,
                "homedir": config.HOMEDIR,
                "update": "1"
            }

            if provider == "Airvpn":
                if self.airvpnKeyEdit.text() != "":
                    credentials["key"] = self.airvpnKeyEdit.text()
                else:
                    credentials["key"] = "Default"

            self.addProviderUserEdit.setText("")
            self.addProviderPassEdit.setText("")
            self.dbus_call("import_thread", credentials)

    def log_from_thread(self, log):
        getattr(logging, log[0])(log[1])

    def del_provider(self):
        provider = self.delProviderBox.currentText()
        del_list = []
        ret = self.messageBox(
            "Are you sure?", "",
            buttons=[("No", "NoRole"), ("Yes", "YesRole")],
            icon="Question"
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

            self.dbus_call("delete_provider", provider)

            with open("{}/server.json".format(config.HOMEDIR), "w") as s:
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
        with open("{}/profile.json".format(config.HOMEDIR), "w") as s:
            json.dump(self.profile_dict, s)
        getattr(self, "{}_widget".format(number)).deleteLater()
        self.vLayoutProfile_2.removeWidget(getattr(self, "{}_widget".format(number)))

    def edit_profile(self, number):
        self.add_profile(edit=self.profile_dict[number])

    def new_profile(self, profile_dict):
        if "number" not in profile_dict.keys():
            n = len(self.profile_dict)
            if "profile_{}".format(n) not in self.profile_dict.keys():
                number = "profile_{}".format(n)
            elif "profile_{}".format(n - 1) not in self.profile_dict.keys():
                number = "profile_{}".format(n - 1)
            else:
                number = "profile_{}".format(n + 1)
            self.profile_dict[number] = profile_dict
            self.profile_dict[number]["number"] = number
            self.display_profile(number)

        else:
            number = profile_dict["number"]
            self.profile_dict[number] = profile_dict
            getattr(self, "{}_widget".format(number)).setText(self.profile_dict[number])

        with open("{}/profile.json".format(config.HOMEDIR), "w") as s:
            json.dump(self.profile_dict, s)

    def display_profile(self, number):
        setattr(self, "{}_widget".format(number), profiles.ProfileWidget(self.profile_dict[number]))
        getattr(self, "{}_widget".format(number)).del_profile.connect(self.del_profile)
        getattr(self, "{}_widget".format(number)).edit_profile.connect(self.edit_profile)
        getattr(self, "{}_widget".format(number)).connect_profile.connect(self.connect_profile)
        self.vLayoutProfile_2.insertWidget(0, getattr(self, "{}_widget".format(number)))
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

            elif profile["mode"] == "Fast/Random":
                l_list = []
                s_list = []
                counter = {}
                max_length = int(len(temp_list) * 0.20)
                for s in temp_list:
                    country = self.server_dict[s]["country"]
                    try:
                        lat = float(self.server_dict[s]["latency"])
                    except KeyError:
                        lat = 1000

                    bisect.insort(l_list, lat)
                    s_list.insert(l_list.index(lat), (s, country))

                s_list = s_list[:max_length + 1]
                from collections import Counter
                occs = [v for k, v in Counter(e[1] for e in s_list).items()]
                max_occ = sum(occs) / len(occs)
                for s, c in s_list:
                    counter[c] = counter.get(c, 0) + 1
                    if counter[c] <= max_occ:
                        s_list.remove((s, c))

                result = random.choice(s_list)[0]

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
        self.vLayoutMain.addWidget(getattr(self, "{}Bar".format(bar)))
        getattr(self, "{}Bar".format(bar)).setText(text, action=action)
        getattr(self, "{}Bar".format(bar)).abort.connect(self.abort_action)

    def stop_progress_bar(self, bar, server=None):
        if server is not None:
            bar = server
        try:
            getattr(self, "{}Bar".format(bar)).setVisible(False)
            self.vLayoutMain.removeWidget(getattr(self, "{}Bar".format(bar)))

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
            self.dbus_call("cancel_import", action)

    def downloaded(self, msg):
        split = msg.split("&")

        if len(split) >= 2:
            self.stop_progress_bar(split[2])
            QtWidgets.QApplication.restoreOverrideCursor()
            self.notify(split[0], split[1], icon="Error")

        else:
            config.settings = self.load_json("{}/config.json".format(config.ROOTDIR))

            with open("{}/{}.json".format(config.HOMEDIR, msg), "r") as p:
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

            if provider in config.SUPPORTED_PROVIDERS:
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

            with open("{}/server.json".format(config.HOMEDIR), "w") as s:
                json.dump(self.server_dict, s)

            with open("{}/protocol.json".format(config.HOMEDIR), "w") as p:
                json.dump(self.protocol_dict, p)

            os.remove("{}/{}.json".format(config.HOMEDIR, msg))
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

        with open("{}/server.json".format(config.HOMEDIR), "w") as s:
            json.dump(self.server_dict, s)

    def set_flag(self, country):
        flag = '{}/flags/{}.png'.format(config.ROOTDIR, country)

        if not os.path.isfile(flag):
            flag = '{}/flags/Unknown.png'.format(config.ROOTDIR)

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

        for k, v in (self.server_dict.items()):

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
                self.logger.error("Malformed server entry: {} {}".format(k, v))

        for e in malformed_entries:
            self.server_dict.pop(e)

        self.pop_providerProtocolBox()
        self.pop_delProviderBox()
        self.countryBox.clear()
        self.providerBox.clear()
        self.tunnelBox.clear()

        if len(self.provider_list) <= 2:
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
            self.countryBox.setItemText(index + 1, country)

        for index, provider in enumerate(self.provider_list):
            self.providerBox.addItem(provider)
            self.providerBox.setItemText(index + 1, provider)

        for index, provider in enumerate(self.tunnel_list):
            self.tunnelBox.addItem(provider)
            self.tunnelBox.setItemText(index, provider)

        self.index_list = []
        self.serverListWidget.clear()

        for key, val in sorted(self.server_dict.items(), key=lambda s: s[0].upper()):
            self.index_list.append(key)
            self.add_server_widget(key, val)

        try:
            if config.settings["ping"] == 1:
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
        if gateway != "None":
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
        if state:
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

        elif not state:
            self.filter_servers()

    def filter_servers(self, *arg, display="filter", text=None):
        self.searchLine.setText("")
        self.randomSeverBt.setVisible(False)
        country = self.countryBox.currentText()
        provider = self.providerBox.currentText()
        tunnel = self.tunnelBox.currentText()

        if self.favouriteButton.isChecked():
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
        if provider in config.SUPPORTED_PROVIDERS:
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
            for k, v in sorted(self.protocol_dict[provider].items()):
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

            self.protocolListWidget.setMaximumHeight(len(protocol_list) * 23)

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
        if provider in config.SUPPORTED_PROVIDERS:
            self.protocol_dict[provider]["selected"] = selection.data(QtCore.Qt.UserRole)

            with open("{}/protocol.json".format(config.HOMEDIR), "w") as p:
                json.dump(self.protocol_dict, p)

            for item in range(self.protocolListWidget.count()):
                if self.protocolListWidget.item(item) != selection:
                    self.protocolListWidget.item(item).setCheckState(QtCore.Qt.Unchecked)
                else:
                    self.protocolListWidget.item(item).setCheckState(QtCore.Qt.Checked)

    def override_protocol_show(self, state, protocol=None, port=None):
        if state:
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

        elif not state:
            try:
                self.protocol_dict.pop(self.providerProtocolBox.currentText(), None)
                with open("{}/protocol.json".format(config.HOMEDIR), "w") as p:
                    json.dump(self.protocol_dict, p)
            except KeyError:
                pass

    def override_protocol(self):
        protocol = self.chooseProtocolBox.currentText()
        port = self.portEdit.text()
        provider = self.providerProtocolBox.currentText()

        if self.overrideCheck.checkState() == 2:
            self.protocol_dict[provider] = {"protocol": protocol, "port": port}
            with open("{}/protocol.json".format(config.HOMEDIR), "w") as p:
                json.dump(self.protocol_dict, p)

    def pop_delProviderBox(self):
        self.delProviderBox.clear()
        for provider in self.provider_list:
            if provider != "All providers":
                self.delProviderBox.addItem(provider)

    def change_favourite(self, change):
        if change[1]:
            self.server_dict[change[0]].update({"favourite": "on"})
        elif not change[1]:
            self.server_dict[change[0]].update({"favourite": "off"})
            if self.favouriteButton.isChecked():
                self.show_favourite_servers(True)
        with open("{}/server.json".format(config.HOMEDIR), "w") as s:
            json.dump(self.server_dict, s)

    def set_hop(self, server):
        try:
            current_dict = self.server_dict[server].copy()
            self.hop_server_dict = utils.create_server_dict(current_dict, self.protocol_dict,
                                                            config.SUPPORTED_PROVIDERS)
            self.show_hop_widget()

        except KeyError:
            self.motify(
                "Server not found",
                "Server does not exist (anymore)\nHave you deleted the server?",
                icon="Error")

    def show_hop_widget(self):
        self.hop_active = 2
        self.hop_server_dict.update({"hop": "1"})
        self.showHop.setVisible(True)
        self.showHop.setText(self.hop_server_dict)
        self.showHop.clear.connect(self.delete_hop)
        self.dbus_call("set_hop", self.hop_server_dict)

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
                self.bypass_ovpn_dict = utils.create_server_dict(current_dict, self.protocol_dict,
                                                                 config.SUPPORTED_PROVIDERS)
                self.bypass_ovpn_dict.update({"bypass": "1", "hop": "0"})

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
                self.ovpn_dict = utils.create_server_dict(current_dict, self.protocol_dict, config.SUPPORTED_PROVIDERS)

                try:
                    if self.ovpn_dict["tunnel"] == "WireGuard":
                        self.delete_hop()

                except KeyError:
                    pass

                if self.hop_active == 2 and self.hop_server_dict is not None:
                    self.ovpn_dict.update({"hop": "2"})

                else:
                    self.ovpn_dict.update({"hop": "0"})

                if random is not None:
                    self.ovpn_dict.update({"random": "on"})

                if profile is not None:
                    self.ovpn_dict.update({"profile": profile})

                if bypass == 1:
                    self.bypass_ovpn_dict.update({"hop": "0", "bypass": "1"})

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
        self.set_tray_icon('{}/flags/{}.png'.format(config.ROOTDIR, self.ovpn_dict["country"]))
        self.notify(
            "Qomui",
            "Connection to {} successfully established".format(self.ovpn_dict["name"]),
            icon="Information"
        )

        last_server_dict = self.load_json("{}/last_server.json".format(config.HOMEDIR))
        with open('{}/last_server.json'.format(config.HOMEDIR), 'w') as lserver:
            last_server_dict["last"] = self.ovpn_dict
            last_server_dict["hop"] = self.hop_server_dict
            json.dump(last_server_dict, lserver)
            lserver.close()

        tun = self.dbus_call("return_tun_device", "tun")
        self.tray.setToolTip("Connected to {}".format(self.ovpn_dict["name"]))
        self.statusOffWidget.setVisible(False)
        self.statusOnWidget.setVisible(True)
        self.tabWidget.setCurrentIndex(0)
        self.statusOnWidget.monitor_conn(tun, self.ovpn_dict["name"])
        self.gLayoutMain.addWidget(self.showActive, 0, 0, 1, 3)
        self.showActive.setVisible(True)
        self.showActive.setText(self.ovpn_dict, self.hop_server_dict, tun, tun_hop=self.tun_hop, bypass=None)

    def connection_established_hop(self):
        self.tunnel_hop_active = 1
        self.tun_hop = self.dbus_call("return_tun_device", "tun_hop")
        self.notify(
            "Qomui",
            "First hop connected: {}".format(self.hop_server_dict["name"]),
            icon="Information"
        )

    def connection_established_bypass(self):
        self.tunnel_bypass_active = 1
        QtWidgets.QApplication.restoreOverrideCursor()
        self.stop_progress_bar("connection", server=self.bypass_ovpn_dict["name"])
        tun = self.dbus_call("return_tun_device", "tun_bypass")
        self.notify(
            "Qomui",
            "Bypass connected to: {}".format(self.bypass_ovpn_dict["name"]),
            icon="Information"
        )

        last_server_dict = self.load_json("{}/last_server.json".format(config.HOMEDIR))
        with open('{}/last_server.json'.format(config.HOMEDIR), 'w') as lserver:
            last_server_dict["bypass"] = self.bypass_ovpn_dict
            json.dump(last_server_dict, lserver)
            lserver.close()

        try:
            self.BypassActive.setVisible(False)
            self.vLayoutMain.removeWidget(self.BypassActive)

        except AttributeError:
            pass

        self.BypassActive = widgets.ActiveWidget("Bypass Connection")
        self.vLayoutMain.addWidget(self.BypassActive)
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

        if not self.queue:
            self.queue = [p for p in config.SUPPORTED_PROVIDERS if p in self.provider_list]

        provider = self.queue[0]

        try:
            get_last = config.settings["{}_last".format(provider)]
            last_update = datetime.strptime(get_last, '%Y-%m-%d %H:%M:%S.%f')
            time_now = datetime.utcnow()
            delta = time_now.date() - last_update.date()
            days_since = delta.days
            self.logger.info("Last {} update: {} days ago".format(provider, days_since))

            if days_since >= 5:
                credentials = {
                    "provider": provider,
                    "credentials": "unknown",
                    "folderpath": "None",
                    "config.HOMEDIR": config.HOMEDIR,
                    "update": "0"
                }

                if config.settings["auto_update"] == 1:
                    self.logger.info("Updating {}".format(provider))
                    self.dbus_call("import_thread", credentials)

        except KeyError:
            self.logger.debug("Update timestamp for {} not found".format(provider))

        finally:
            self.queue.remove(provider)

    def reconnect(self):
        if self.tunnel_active == 1:
            self.tunnel_active = 0
            self.connect_last_server()

    def kill(self):
        self.tabWidget.setCurrentIndex(1)
        self.statusOnWidget.setVisible(False)
        self.statusOffWidget.setVisible(True)
        self.statusOnWidget.reset_html()
        self.tunnel_active = 0
        self.tunnel_hop_active = 0
        self.dbus_call("disconnect", "main")
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

    def kill_hop(self):
        pass

    def kill_bypass(self):
        last_server_dict = self.load_json("{}/last_server.json".format(config.HOMEDIR))

        if "bypass" in last_server_dict.keys():
            last_server_dict.pop("bypass")

        with open('{}/last_server.json'.format(config.HOMEDIR), 'w') as lserver:
            json.dump(last_server_dict, lserver)
            lserver.close()

        self.disconnect_bypass()

    def disconnect_bypass(self):
        self.tunnel_bypass_active = 0
        self.dbus_call("disconnect", "bypass")

        try:
            self.stop_progress_bar("connection_bypass", server=self.bypass_ovpn_dict["name"])
            self.BypassActive.setVisible(False)
            self.vLayoutMain.removeWidget(self.BypassActive)

        except (TypeError, AttributeError):
            pass

    def establish_connection(self, server_dict, bar=""):
        self.logger.info("Connecting to {}....".format(server_dict["name"]))
        self.start_progress_bar("connecting{}".format(bar), server=server_dict["name"])
        self.dbus_call("connect_to_server", server_dict)
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
                if e in config.settings["{}_scripts".format(provider)].keys():
                    getattr(self, "{}Edit".format(e)).setText(
                        config.settings["{}_scripts".format(provider)][e]
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

        editor = widgets.FirewallEditor(config.settings)
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

        with open("{}/bypass_apps.json".format(config.HOMEDIR), "w") as save_bypass:
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

        with open("{}/bypass_apps.json".format(config.HOMEDIR), "w") as save_bypass:
            json.dump(self.bypass_dict, save_bypass)

        self.pop_bypassAppList()

    def pop_bypassAppList(self):
        self.bypassAppList.clear()
        for k, v in self.bypass_dict.items():
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
            with open(desktop_file, "r") as cmd_ret:
                search = cmd_ret.readlines()
                found = 0

                for line in search:
                    if line.startswith("Exec") and found != 1:
                        # cmd = line.split("=")[1].split(" ")[0].replace("\n", "")
                        cmd = line.replace("Exec=", "").replace("\n", "")
                        cmd = re.sub(r"%[\w]", "", cmd)
                        found = 1

            temp_bash = "{}/bypass_temp.sh".format(config.HOMEDIR)

            with open(temp_bash, "w") as temp_sh:
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
        new_config = modifications["config_change"]
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
                self.countryBox.setItemText(index + 1, country)

        with open("{}/server.json".format(config.HOMEDIR), "w") as s:
            json.dump(self.server_dict, s)

        if len(new_config) != 0:
            try:
                if provider in config.SUPPORTED_PROVIDERS:
                    temp_file = "{}/temp/{}_config".format(config.HOMEDIR, provider)
                    with open(temp_file, "w") as config_change:
                        config_change.writelines(new_config)

                else:
                    temp_file = "{}/temp/{}".format(config.HOMEDIR, val["path"].split("/")[1])
                    if modifications["apply_all"] == 1:
                        for k, v in self.server_dict.items():
                            if v["provider"] == provider:
                                path = "{}/temp/{}".format(config.HOMEDIR, v["path"].split("/")[1])
                                with open(path, "w") as config_change:
                                    index = modifications["index"]
                                    rpl = new_config[index].split(" ")
                                    ip_insert = "{} {} {}".format(rpl[0], v["ip"], rpl[2])
                                    new_config[index] = ip_insert
                                    config_change.writelines(new_config)

                self.dbus_call("change_ovpn_config", provider, "{}/temp".format(config.HOMEDIR))

            except FileNotFoundError:
                pass

    def search_listitem(self, key):
        for row in range(self.serverListWidget.count()):
            if self.serverListWidget.item(row).data(QtCore.Qt.UserRole) == key:
                return row


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
