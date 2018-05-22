#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from PyQt5 import QtCore, QtGui, Qt, QtWidgets
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
import psutil
from dbus.mainloop.pyqt5 import DBusQtMainLoop
from subprocess import CalledProcessError, check_call, check_output, Popen
import shutil
import shlex
import glob
import configparser
import requests
import bisect

from qomui import update, latency


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
        msg = json.dumps(dict(record.__dict__))
        try:
            self.qomui_service.share_log(msg)
        except dbus.exceptions.DBusException:
            pass


DIRECTORY = "%s/.qomui" % (os.path.expanduser("~"))
ROOTDIR = "/usr/share/qomui"
SUPPORTED_PROVIDERS = ["Airvpn", "Mullvad", "PIA"]


class FavouriteButton(QtWidgets.QAbstractButton):
    def __init__(self, parent=None):
        super(FavouriteButton, self).__init__(parent)
        self.star = QtGui.QPolygonF([QtCore.QPointF(1.0, 0.5)])
        for i in range(5):
            self.star << QtCore.QPointF(0.5 + 0.5 * math.cos(0.8 * i * math.pi), 0.5 + 0.5 * math.sin(0.8 * i * math.pi))

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
    server_dict = {}
    protocol_dict = {}
    country_list = ["All countries"]
    provider_list = ["All providers"]
    config_dict = {}
    fire_change = False
    hop_choice = 0
    log_count = 0
    hop_server_dict = None
    bypass_app_list = {}
    
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
            self.logger.warning('DBus Error: Qomui-Service is currently not available')
            
            dbus_err = QtWidgets.QMessageBox(self)
            dbus_err.setText("Error: Qomui background service is currently not running\nDo you want to start it, enable it permanently or close Qomui?")
            dbus_err.addButton(QtWidgets.QPushButton("Enable"), QtWidgets.QMessageBox.NoRole)
            dbus_err.addButton(QtWidgets.QPushButton("Start"), QtWidgets.QMessageBox.YesRole)
            dbus_err.addButton(QtWidgets.QPushButton("Close"), QtWidgets.QMessageBox.RejectRole)
            ret = dbus_err.exec_()
            if ret == 0:
                try:
                    check_call(["pkexec", "systemctl", "enable", "--now", "qomui"])
                    self.qomui_dbus = self.dbus.get_object('org.qomui.service', '/org/qomui/service')
                except CalledProcessError:
                    err = QtWidgets.QMessageBox.critical(self,
                                                "Error",
                                                "Failed to start Qomui service",
                                                QtWidgets.QMessageBox.Ok)
                    sys.exit(1)
            elif ret == 1:
                try:
                    check_call(["pkexec", "systemctl", "start", "qomui.service"])
                    self.qomui_dbus = self.dbus.get_object('org.qomui.service', '/org/qomui/service')
                except CalledProcessError:
                    err = QtWidgets.QMessageBox.critical(self,
                                                "Error",
                                                "Failed to start Qomui service",
                                                QtWidgets.QMessageBox.Ok)
                    sys.exit(1)
            elif ret == 2:
                sys.exit(1)
   
        self.qomui_service = dbus.Interface(self.qomui_dbus, 'org.qomui.service')
        self.qomui_service.connect_to_signal("send_log", self.receive_log)
        self.qomui_service.connect_to_signal("reply", self.log_check)
        nm = self.dbus.get_object('org.freedesktop.NetworkManager', '/org/freedesktop/NetworkManager')
        nm_iface = dbus.Interface(nm, 'org.freedesktop.NetworkManager')
        nm_iface.connect_to_signal("StateChanged", self.networkstate)
        
        handler = DbusLogHandler(self.qomui_service)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)
        primary_screen_geometry = QtWidgets.QDesktopWidget().availableGeometry(QtWidgets.QDesktopWidget().primaryScreen())
        positioning = primary_screen_geometry.bottomRight()
        self.setGeometry(QtCore.QRect(positioning.x(), positioning.y(), 550, 720))
        self.qomui_service.disconnect()
        self.qomui_service.save_default_dns()
        
        self.Load()
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
        self.tab_bt_group = QtWidgets.QButtonGroup(Form)
        self.tab_bt_group.setExclusive(True)
        self.server_tab_bt = QtWidgets.QCommandLinkButton(Form)
        self.server_tab_bt.setMinimumSize(QtCore.QSize(100, 0))
        self.server_tab_bt.setMaximumSize(QtCore.QSize(100, 100))
        self.server_tab_bt.setCheckable(True)
        self.tab_bt_group.addButton(self.server_tab_bt)
        self.server_tab_bt.setObjectName(_fromUtf8("server_tab_bt"))
        self.verticalLayout_3.addWidget(self.server_tab_bt)
        self.provider_tab_bt = QtWidgets.QCommandLinkButton(Form)
        self.provider_tab_bt.setMinimumSize(QtCore.QSize(100, 0))
        self.provider_tab_bt.setMaximumSize(QtCore.QSize(100, 100))
        self.provider_tab_bt.setCheckable(True)
        self.tab_bt_group.addButton(self.provider_tab_bt)
        self.provider_tab_bt.setObjectName(_fromUtf8("provider_tab_bt"))
        self.verticalLayout_3.addWidget(self.provider_tab_bt)
        self.options_tab_bt = QtWidgets.QCommandLinkButton(Form)
        self.options_tab_bt.setMinimumSize(QtCore.QSize(100, 0))
        self.options_tab_bt.setMaximumSize(QtCore.QSize(100, 100))
        self.options_tab_bt.setCheckable(True)
        self.tab_bt_group.addButton(self.options_tab_bt)
        self.options_tab_bt.setObjectName(_fromUtf8("options_tab_bt"))
        self.verticalLayout_3.addWidget(self.options_tab_bt)
        self.log_tab_bt = QtWidgets.QCommandLinkButton(Form)
        self.log_tab_bt.setMinimumSize(QtCore.QSize(100, 0))
        self.log_tab_bt.setMaximumSize(QtCore.QSize(100, 100))
        self.log_tab_bt.setCheckable(True)
        self.tab_bt_group.addButton(self.log_tab_bt)
        self.log_tab_bt.setObjectName(_fromUtf8("log_tab_bt"))
        self.verticalLayout_3.addWidget(self.log_tab_bt)
        self.bypass_tab_bt = QtWidgets.QCommandLinkButton(Form)
        self.bypass_tab_bt.setVisible(False)
        self.bypass_tab_bt.setMinimumSize(QtCore.QSize(100, 0))
        self.bypass_tab_bt.setMaximumSize(QtCore.QSize(100, 100))
        self.bypass_tab_bt.setCheckable(True)
        self.tab_bt_group.addButton(self.bypass_tab_bt)
        self.bypass_tab_bt.setObjectName(_fromUtf8("bypass_tab_bt"))
        self.verticalLayout_3.addWidget(self.bypass_tab_bt)
        spacerItem = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
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
        self.favouriteButton = FavouriteButton(self.serverTab)
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
        self.serverHopWidget = HopSelect(self.serverTab)
        self.serverHopWidget.setVisible(False)
        self.verticalLayout.addWidget(self.serverHopWidget)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem1)
        self.random_server_bt = QtWidgets.QPushButton(self.serverTab)
        self.random_server_bt.setObjectName(_fromUtf8("random_server_bt"))
        self.random_server_bt.setVisible(False)
        self.horizontalLayout.addWidget(self.random_server_bt)
        self.add_server_bt = QtWidgets.QPushButton(self.serverTab)
        self.add_server_bt.setObjectName(_fromUtf8("add_server_bt"))
        self.horizontalLayout.addWidget(self.add_server_bt)
        self.modify_server_bt = QtWidgets.QPushButton(self.serverTab)
        self.modify_server_bt.setObjectName(_fromUtf8("modify_server_bt"))
        self.horizontalLayout.addWidget(self.modify_server_bt)
        self.del_server_bt = QtWidgets.QPushButton(self.serverTab)
        self.del_server_bt.setObjectName(_fromUtf8("del_server_bt"))
        self.horizontalLayout.addWidget(self.del_server_bt)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.tabWidget.addWidget(self.serverTab)
        self.log_tab = QtWidgets.QWidget()
        self.log_tab.setObjectName(_fromUtf8("log_tab"))
        self.gridLayout_2 = QtWidgets.QGridLayout(self.log_tab)
        self.gridLayout_2.setObjectName(_fromUtf8("gridLayout_2"))
        self.logText = QtWidgets.QPlainTextEdit(self.log_tab)
        self.logText.setReadOnly(True)
        self.gridLayout_2.addWidget(self.logText, 2, 0, 1, 1)
        self.tabWidget.addWidget(self.log_tab)
        self.options_tab = QtWidgets.QWidget()
        self.options_tab.setObjectName(_fromUtf8("options_tab"))
        self.verticalLayout_5 = QtWidgets.QVBoxLayout(self.options_tab)
        self.verticalLayout_5.setObjectName(_fromUtf8("verticalLayout_5"))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        font.setKerning(False)
        self.autoconnect_check = QtWidgets.QCheckBox(self.options_tab)
        self.autoconnect_check.setObjectName(_fromUtf8("autoconnect_check"))
        self.autoconnect_check.setFont(font)
        self.verticalLayout_5.addWidget(self.autoconnect_check)
        self.autoconnect_label = QtWidgets.QLabel(self.options_tab)
        self.autoconnect_label.setObjectName(_fromUtf8("autoconnect_check"))
        self.autoconnect_label.setWordWrap(True)
        self.autoconnect_label.setIndent(20)
        cfont = QtGui.QFont()
        cfont.setItalic(True)
        self.autoconnect_label.setFont(cfont)
        self.verticalLayout_5.addWidget(self.autoconnect_label)
        self.minimize_check = QtWidgets.QCheckBox(self.options_tab)
        self.minimize_check.setFont(font)
        self.minimize_check.setObjectName(_fromUtf8("minimize_check"))
        self.verticalLayout_5.addWidget(self.minimize_check)
        self.minimize_label = QtWidgets.QLabel(self.options_tab)
        self.minimize_label.setObjectName(_fromUtf8("minimize_check"))
        self.minimize_label.setWordWrap(True)
        self.minimize_label.setIndent(20)
        self.minimize_label.setFont(cfont)
        self.verticalLayout_5.addWidget(self.minimize_label)
        self.lat_check = QtWidgets.QCheckBox(self.options_tab)
        self.lat_check.setFont(font)
        self.lat_check.setObjectName(_fromUtf8("lat_check"))
        self.verticalLayout_5.addWidget(self.lat_check)
        self.lat_label = QtWidgets.QLabel(self.options_tab)
        self.lat_label.setObjectName(_fromUtf8("lat_check"))
        self.lat_label.setWordWrap(True)
        self.lat_label.setIndent(20)
        self.lat_label.setFont(cfont)
        self.verticalLayout_5.addWidget(self.lat_label)
        self.ipv6_label = QtWidgets.QLabel(self.options_tab)
        self.ipv6_check = QtWidgets.QCheckBox(self.options_tab)
        self.ipv6_check.setFont(font)
        self.ipv6_check.setObjectName(_fromUtf8("ipv6_check"))
        self.verticalLayout_5.addWidget(self.ipv6_check)
        self.ipv6_label = QtWidgets.QLabel(self.options_tab)
        self.ipv6_label.setObjectName(_fromUtf8("ipv6_check"))
        self.ipv6_label.setWordWrap(True)
        self.ipv6_label.setIndent(20)
        self.ipv6_label.setFont(cfont)
        self.verticalLayout_5.addWidget(self.ipv6_label)
        self.bypass_check = QtWidgets.QCheckBox(self.options_tab)
        self.bypass_check.setFont(font)
        self.bypass_check.setObjectName(_fromUtf8("bypass_check"))
        self.verticalLayout_5.addWidget(self.bypass_check)
        self.bypass_label = QtWidgets.QLabel(self.options_tab)
        self.bypass_label.setObjectName(_fromUtf8("bypass_check"))
        self.bypass_label.setWordWrap(True)
        self.bypass_label.setIndent(20)
        self.bypass_label.setFont(cfont)
        self.verticalLayout_5.addWidget(self.bypass_label)
        self.horizontalLayout_9 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_9.setObjectName(_fromUtf8("horizontalLayout_9"))
        self.firewall_check = QtWidgets.QCheckBox(self.options_tab)
        self.firewall_check.setFont(font)
        self.firewall_check.setObjectName(_fromUtf8("firewall_check"))
        self.horizontalLayout_9.addWidget(self.firewall_check)
        self.firewall_edit_bt = QtWidgets.QPushButton(self.options_tab)
        self.firewall_edit_bt.setObjectName(_fromUtf8("firewall_edit_bt"))
        self.horizontalLayout_9.addWidget(self.firewall_edit_bt)
        spacerItem9 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_9.addItem(spacerItem9)
        self.horizontalLayout_9.setObjectName(_fromUtf8("horizontalLayout_9"))
        self.verticalLayout_5.addLayout(self.horizontalLayout_9)
        self.firewall_label = QtWidgets.QLabel(self.options_tab)
        self.firewall_label.setObjectName(_fromUtf8("firewall_check"))
        self.firewall_label.setWordWrap(True)
        self.firewall_label.setIndent(20)
        self.firewall_label.setFont(cfont)
        self.verticalLayout_5.addWidget(self.firewall_label)
        self.alt_dns_lbl = QtWidgets.QLabel(self.options_tab)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        font.setKerning(False)
        self.alt_dns_lbl.setFont(font)
        self.alt_dns_lbl.setObjectName(_fromUtf8("alt_dns_lbl"))
        self.verticalLayout_5.addWidget(self.alt_dns_lbl)
        self.dns_check = QtWidgets.QCheckBox(self.options_tab)
        self.dns_check.setFont(font)
        self.dns_check.setObjectName(_fromUtf8("dns_check"))
        self.verticalLayout_5.addWidget(self.dns_check)
        self.alt_dns_edit1 = QtWidgets.QLineEdit(self.options_tab)
        self.alt_dns_edit1.setObjectName(_fromUtf8("alt_dns_edit1"))
        self.verticalLayout_5.addWidget(self.alt_dns_edit1)
        self.alt_dns_edit2 = QtWidgets.QLineEdit(self.options_tab)
        self.alt_dns_edit2.setObjectName(_fromUtf8("alt_dns_edit2"))
        self.verticalLayout_5.addWidget(self.alt_dns_edit2)
        self.dns_label = QtWidgets.QLabel(self.options_tab)
        self.dns_label.setObjectName(_fromUtf8("dns_check"))
        self.dns_label.setWordWrap(True)
        self.dns_label.setFont(cfont)
        self.verticalLayout_5.addWidget(self.dns_label)
        spacerItem8 = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout_5.addItem(spacerItem8)
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setObjectName(_fromUtf8("horizontalLayout_6"))
        spacerItem4 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_6.addItem(spacerItem4)
        self.default_bt = QtWidgets.QPushButton(self.options_tab)
        self.default_bt.setObjectName(_fromUtf8("default_bt"))
        self.horizontalLayout_6.addWidget(self.default_bt)
        self.apply_bt = QtWidgets.QPushButton(self.options_tab)
        self.apply_bt.setObjectName(_fromUtf8("apply_bt"))
        self.horizontalLayout_6.addWidget(self.apply_bt)
        self.cancel_bt = QtWidgets.QPushButton(self.options_tab)
        self.cancel_bt.setObjectName(_fromUtf8("cancel_bt"))
        self.horizontalLayout_6.addWidget(self.cancel_bt)
        self.verticalLayout_5.addLayout(self.horizontalLayout_6)
        self.tabWidget.addWidget(self.options_tab)
        self.provider_tab = QtWidgets.QWidget()
        self.provider_tab.setObjectName(_fromUtf8("provider_tab"))
        self.verticalLayout_30 = QtWidgets.QVBoxLayout(self.provider_tab)
        self.verticalLayout_30.setObjectName("verticalLayout_30")
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.addProviderLabel = QtWidgets.QLabel(self.provider_tab)
        self.addProviderLabel.setFont(font)
        self.addProviderLabel.setObjectName("addProviderLabel")
        self.verticalLayout_30.addWidget(self.addProviderLabel)
        self.providerChoice = QtWidgets.QComboBox(Form)
        self.providerChoice.setObjectName(_fromUtf8("providerChoice"))
        self.verticalLayout_30.addWidget(self.providerChoice)
        self.provider_edit = QtWidgets.QLineEdit(Form)
        self.provider_edit.setObjectName(_fromUtf8("provider_edit"))
        self.provider_edit.setVisible(False)
        self.verticalLayout_30.addWidget(self.provider_edit)
        self.gridLayout_3 = QtWidgets.QGridLayout(Form)
        self.gridLayout_3.setObjectName(_fromUtf8("gridLayout_3"))
        self.user_edit = QtWidgets.QLineEdit(Form)
        self.user_edit.setObjectName(_fromUtf8("user_edit"))
        self.gridLayout_3.addWidget(self.user_edit, 0, 0, 1, 2)
        self.download_bt = QtWidgets.QPushButton(Form)
        self.download_bt.setObjectName(_fromUtf8("download_bt"))
        self.gridLayout_3.addWidget(self.download_bt, 0, 2, 1, 1)
        self.pass_edit = QtWidgets.QLineEdit(Form)
        self.pass_edit.setEchoMode(QtWidgets.QLineEdit.Password)
        self.pass_edit.setObjectName(_fromUtf8("pass_edit"))
        self.gridLayout_3.addWidget(self.pass_edit, 1, 0, 1, 2)
        self.verticalLayout_30.addLayout(self.gridLayout_3)
        self.delProviderLabel = QtWidgets.QLabel(self.provider_tab)
        self.delProviderLabel.setFont(font)
        self.delProviderLabel.setObjectName("delProviderLabel")
        self.verticalLayout_30.addWidget(self.delProviderLabel)
        self.horizontalLayout_32 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_32.setObjectName("horizontalLayout_32")
        self.delProviderBox = QtWidgets.QComboBox(self.provider_tab)
        self.delProviderBox.setObjectName("delProviderBox")
        self.horizontalLayout_32.addWidget(self.delProviderBox)
        self.delProviderButton = QtWidgets.QPushButton(self.provider_tab)
        self.delProviderButton.setObjectName("delProviderButton")
        self.horizontalLayout_32.addWidget(self.delProviderButton)
        spacerItem10 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_32.addItem(spacerItem10)
        self.verticalLayout_30.addLayout(self.horizontalLayout_32)
        self.protocolLabel = QtWidgets.QLabel(self.provider_tab)
        self.protocolLabel.setFont(font)
        self.protocolLabel.setObjectName("protocolLabel")
        self.verticalLayout_30.addWidget(self.protocolLabel)
        self.providerSelect = QtWidgets.QComboBox(self.provider_tab)
        self.providerSelect.setObjectName("providerSelect")
        self.verticalLayout_30.addWidget(self.providerSelect)
        self.protocolListWidget = QtWidgets.QListWidget(self.provider_tab)
        self.protocolListWidget.setObjectName("protocolListWidget")
        self.verticalLayout_30.addWidget(self.protocolListWidget)
        self.overrideCheck = QtWidgets.QCheckBox(self.provider_tab)
        self.overrideCheck.setObjectName("overrideCheck")
        self.overrideCheck.setVisible(False)
        self.verticalLayout_30.addWidget(self.overrideCheck)
        self.horizontalLayout_31 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_31.setObjectName("horizontalLayout_31")
        self.protocolBox = QtWidgets.QComboBox(self.provider_tab)
        self.protocolBox.setObjectName("protocolBox")
        self.protocolBox.addItem("UDP")
        self.protocolBox.addItem("TCP")
        self.protocolBox.setVisible(False)
        self.horizontalLayout_31.addWidget(self.protocolBox)
        self.portOverrideLabel = QtWidgets.QLabel(self.provider_tab)
        self.portOverrideLabel.setObjectName("portOverrideLabel")
        self.portOverrideLabel.setVisible(False)
        self.horizontalLayout_31.addWidget(self.portOverrideLabel)
        self.portEdit = QtWidgets.QLineEdit(self.provider_tab)
        self.portEdit.setObjectName("portEdit")
        self.portEdit.setVisible(False)
        self.horizontalLayout_31.addWidget(self.portEdit)
        self.verticalLayout_30.addLayout(self.horizontalLayout_31)
        self.savePortButton = QtWidgets.QPushButton(self.provider_tab)
        self.savePortButton.setObjectName("savePortButton")
        self.savePortButton.setVisible(False)
        self.horizontalLayout_31.addWidget(self.savePortButton)
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_31.addItem(spacerItem1)
        spacerItem = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout_30.addItem(spacerItem)
        
        self.tabWidget.addWidget(self.provider_tab)
        self.bypass_tab = QtWidgets.QWidget()
        self.bypass_tab.setObjectName(_fromUtf8("bypass_tab"))
        self.verticalLayout_8 = QtWidgets.QVBoxLayout(self.bypass_tab)
        self.verticalLayout_8.setObjectName(_fromUtf8("verticalLayout_8"))
        self.bypass_info = QtWidgets.QLabel(self.options_tab)
        self.bypass_info.setObjectName(_fromUtf8("bypass_check"))
        self.bypass_info.setWordWrap(True)
        self.bypass_info.setFont(cfont)
        self.verticalLayout_8.addWidget(self.bypass_info)
        self.app_list = QtWidgets.QListWidget(self.bypass_tab)
        self.app_list.setObjectName(_fromUtf8("app_list"))
        self.app_list.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.verticalLayout_8.addWidget(self.app_list)
        self.horizontalLayout_10= QtWidgets.QHBoxLayout()
        self.horizontalLayout_10.setObjectName(_fromUtf8("horizontalLayout_10"))
        spacerItem3 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_10.addItem(spacerItem3)
        self.add_app_bt = QtWidgets.QPushButton(self.bypass_tab)
        self.add_app_bt.setObjectName(_fromUtf8("add_app_bt"))
        self.horizontalLayout_10.addWidget(self.add_app_bt)
        self.del_app_bt = QtWidgets.QPushButton(self.bypass_tab)
        self.del_app_bt.setObjectName(_fromUtf8("del_app_bt"))
        self.horizontalLayout_10.addWidget(self.del_app_bt)
        self.verticalLayout_8.addLayout(self.horizontalLayout_10)
        self.tabWidget.addWidget(self.bypass_tab)
        self.gridLayout.addWidget(self.tabWidget, 2, 1, 1, 1) 
        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

        self.providerSelect.activated[str].connect(self.popProtocolList)
        self.add_server_bt.clicked.connect(self.switch_provider_tab)
        self.del_server_bt.clicked.connect(self.del_server_file)
        self.countryBox.activated[str].connect(self.filterList)
        self.providerBox.activated[str].connect(self.filterList)
        self.server_tab_bt.clicked.connect(self.tabswitch)
        self.bypass_tab_bt.clicked.connect(self.tabswitch)
        self.options_tab_bt.clicked.connect(self.tabswitch)
        self.log_tab_bt.clicked.connect(self.tabswitch)
        self.provider_tab_bt.clicked.connect(self.tabswitch)
        self.apply_bt.clicked.connect(self.applyoptions)
        self.cancel_bt.clicked.connect(self.cancelOptions)
        self.default_bt.clicked.connect(self.restoreDefaults)
        self.firewall_edit_bt.clicked.connect(self.show_firewalleditor)
        self.add_app_bt.clicked.connect(self.select_application)
        self.del_app_bt.clicked.connect(self.del_bypass_app)
        self.favouriteButton.toggled.connect(self.show_favs)
        self.overrideCheck.toggled.connect(self.protocol_override)
        self.delProviderButton.clicked.connect(self.del_provider)
        self.providerChoice.activated[str].connect(self.providerChosen)
        self.download_bt.clicked.connect(self.login)
        self.random_server_bt.clicked.connect(self.chooseRandomServer)
        self.savePortButton.clicked.connect(self.overrideProtocol)
        self.modify_server_bt.clicked.connect(self.modifyServer)

    def retranslateUi(self, Form):
        Form.setWindowTitle(_translate("Form", "Qomui", None))
        self.server_tab_bt.setText(_translate("Form", "Server", None))
        self.log_tab_bt.setText(_translate("Form", "Log", None))
        self.provider_tab_bt.setText(_translate("Form", "Provider", None))
        self.bypass_tab_bt.setText(_translate("Form", "Bypass", None))
        self.options_tab_bt.setText(_translate("Form", "Options", None))
        self.random_server_bt.setText(_translate("Form", "Choose Random", None))
        self.random_server_bt.setIcon(QtGui.QIcon.fromTheme("view-refresh"))
        self.add_server_bt.setText(_translate("Form", "Add Servers", None))
        self.add_server_bt.setIcon(QtGui.QIcon.fromTheme("list-add"))
        self.modify_server_bt.setText(_translate("Form", "Modify", None))
        self.modify_server_bt.setIcon(QtGui.QIcon.fromTheme("edit"))
        self.del_server_bt.setText(_translate("Form", "Delete", None))
        self.del_server_bt.setIcon(QtGui.QIcon.fromTheme("edit-delete"))
        self.autoconnect_check.setText(_translate("Form", "Autoconnect", None))
        self.minimize_check.setText(_translate("Form", "Start minimized", None))
        self.firewall_check.setText(_translate("Form", "Activate Firewall     ", None))
        self.bypass_check.setText(_translate("Form", "Allow OpenVPN bypass", None))
        self.lat_check.setText(_translate("Form", "Perform latency check", None))
        self.ipv6_check.setText(_translate("Form", "Disable IPv6", None))
        self.dns_check.setText(_translate("Form", "Use always", None))
        self.alt_dns_lbl.setText(_translate("Form", "Alternative DNS Servers:", None))
        self.default_bt.setText(_translate("Form", "Restore defaults", None))
        self.default_bt.setIcon(QtGui.QIcon.fromTheme("view-refresh"))
        self.apply_bt.setText(_translate("Form", "Apply", None))
        self.apply_bt.setIcon(QtGui.QIcon.fromTheme("dialog-ok"))
        self.cancel_bt.setText(_translate("Form", "Cancel", None))
        self.cancel_bt.setIcon(QtGui.QIcon.fromTheme("dialog-close"))
        self.firewall_edit_bt.setText(_translate("Form", "Edit firewall rules", None))
        self.firewall_edit_bt.setIcon(QtGui.QIcon.fromTheme("edit"))
        self.add_app_bt.setText(_translate("Form", "Add Application", None))
        self.add_app_bt.setIcon(QtGui.QIcon.fromTheme("list-add"))
        self.del_app_bt.setText(_translate("Form", "Remove", None))
        self.del_app_bt.setIcon(QtGui.QIcon.fromTheme("edit-delete"))
        self.protocolLabel.setText(_translate("Form", "Choose protocol and port:", None))
        self.addProviderLabel.setText(_translate("Form", "Add/update provider:", None))
        self.delProviderLabel.setText(_translate("Form", "Delete provider:", None))
        self.delProviderButton.setText(_translate("Form", "Delete", None))
        self.delProviderButton.setIcon(QtGui.QIcon.fromTheme("edit-delete"))
        self.overrideCheck.setText(_translate("Form", "Override settings from config file", None))
        self.portOverrideLabel.setText(_translate("Form", "Port", None))
        self.savePortButton.setText(_translate("Form", "Save", None))
        self.savePortButton.setIcon(QtGui.QIcon.fromTheme("dialog-ok"))
        self.user_edit.setPlaceholderText(_translate("Form", "Username", None))
        self.download_bt.setText(_translate("Form", "Download", None))
        self.download_bt.setIcon(QtGui.QIcon.fromTheme("list-add"))
        self.pass_edit.setPlaceholderText(_translate("Form", "Password", None))
        
        self.autoconnect_label.setText(_translate("Form", 
                                          "Automatically connect to last server", 
                                          None))
        self.minimize_label.setText(_translate("Form", 
                                          "Only works if system tray is available", 
                                          None))
        self.ipv6_label.setText(_translate("Form", 
                                          "Disables ipv6 stack systemwide", 
                                          None))
        self.lat_label.setText(_translate("Form", 
                                          "Sort servers by latency - allow ping", 
                                          None))
        self.bypass_label.setText(_translate("Form", 
                                          "Allow applications to run outside VPN tunnel", 
                                          None))
        self.firewall_label.setText(_translate("Form", 
                                          "Block connections outside VPN tunnel - leak protection", 
                                          None))
        self.dns_label.setText(_translate("Form", 
                                          "By default Qomui will try to use the DNS server by your provider. Otherwise, it will fall back to the alternative DNS servers", 
                                          None))
        self.bypass_info.setText(_translate("Form", 
                                          'To use an application outside the VPN tunnel, you can simply add a program to the list below and launch it from there. Alternatively, you can run commands from a console by prepending "cgexec -g net_cls:bypass_qomui $yourcommand". Be aware that some applications including Firefox will not launch a second instance in bypass mode if they are already running.', 
                                          None))
        
        for provider in SUPPORTED_PROVIDERS:
            self.providerChoice.addItem(provider)
        self.providerChoice.addItem("Manually add config file folder")


    def tabswitch(self):
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
    
    def switch_provider_tab(self):
        self.tabWidget.setCurrentIndex(3) 
    
    def systemtray(self):
        self.trayicon = QtGui.QIcon("%s/qomui.png" % (ROOTDIR))
        self.tray = QtWidgets.QSystemTrayIcon()
        if self.tray.isSystemTrayAvailable() == False:
            self.setWindowState(QtCore.Qt.WindowActive)
            self.showNormal()
        else:    
            self.tray.setIcon(self.trayicon)
            self.tray_menu = QtWidgets.QMenu()
            show = self.tray_menu.addAction("Show")
            exit = self.tray_menu.addAction("Quit")
            show.triggered.connect(self.show)
            exit.triggered.connect(self.shutdown)
            self.tray.setContextMenu(self.tray_menu)
            self.tray.show()
            self.tray.activated.connect(self.restoreUi)
    
    def shutdown(self):
        self.tray.hide()
        self.kill()
        sys.exit()
        
    def restoreUi(self, reason):
        if self.isVisible() is True:
            self.hide()
        else:
            self.setWindowState(QtCore.Qt.WindowActive)
            self.showNormal()

    def changeEvent(self, event):
        if event.type() == QtCore.QEvent.WindowStateChange:
            if self.windowState() & QtCore.Qt.WindowMinimized:
                if QtWidgets.QSystemTrayIcon.isSystemTrayAvailable() == False:
                    event.accept()
                else:
                    self.hide()
            elif self.windowState() & QtCore.Qt.WindowActive:
                self.setWindowState(QtCore.Qt.WindowActive)
                self.showNormal()

    def closeEvent(self, event):
        closemsg = QtWidgets.QMessageBox()
        closemsg.setText("Do you want to exit program or minimize to tray?")
        closemsg.addButton(QtWidgets.QPushButton("Minimize"), QtWidgets.QMessageBox.NoRole)
        closemsg.addButton(QtWidgets.QPushButton("Exit"), QtWidgets.QMessageBox.YesRole)
        closemsg.addButton(QtWidgets.QPushButton("Cancel"), QtWidgets.QMessageBox.RejectRole)
        ret = closemsg.exec_()
        if ret == 1:
            self.tray.hide()
            self.kill()
            event.accept()
        elif ret == 0:
            event.ignore()
            self.hide()
        elif ret == 2:
            event.ignore()

    def applyoptions(self):
        new_config_dict = {}
        new_config_dict["alt_dns1"] = self.alt_dns_edit1.text()
        new_config_dict["alt_dns2"] = self.alt_dns_edit2.text()
        
        if self.firewall_check.checkState() == 2:
            new_config_dict["firewall"] = 1
        elif self.firewall_check.checkState() == 0:
            new_config_dict["firewall"] = 0

        if self.autoconnect_check.checkState() == 2:
            new_config_dict["autoconnect"] = 1
        elif self.autoconnect_check.checkState() == 0:
            new_config_dict["autoconnect"] = 0
            
        if self.ipv6_check.checkState() == 2:
            new_config_dict["ipv6_disable"] = 1
        elif self.ipv6_check.checkState() == 0:
            new_config_dict["ipv6_disable"] = 0
            
        if self.minimize_check.checkState() == 2:
            new_config_dict["minimize"] = 1
        elif self.minimize_check.checkState() == 0:
            new_config_dict["minimize"] = 0
            
        if self.dns_check.checkState() == 2:
            new_config_dict["fallback"] = 1
        elif self.dns_check.checkState() == 0:
            new_config_dict["fallback"] = 0
            
        if self.lat_check.checkState() == 2:
            new_config_dict["latency_check"] = 1
        elif self.lat_check.checkState() == 0:
            new_config_dict["latency_check"] = 0
            
        if self.bypass_check.checkState() == 2:
            new_config_dict["bypass"] = 1
            self.bypass_tab_bt.setVisible(True)
        elif self.bypass_check.checkState() == 0:
            new_config_dict["bypass"] = 0
            self.bypass_tab_bt.setVisible(False)

        with open ('%s/config_temp.json' % (DIRECTORY), 'w') as config:
            json.dump(new_config_dict, config)

        update_cmd = ['pkexec', 'python3', '-m', 'qomui.mv_config',
                      '-d', '%s' %(DIRECTORY)]

        if self.fire_change is True:
            update_cmd.append('-f')

        try:
            update = check_call(update_cmd)
            self.logger.info("Configuration changes applied successfully")
            self.qomui_service.load_firewall()
            self.qomui_service.bypass(self.user, self.group)
            QtWidgets.QMessageBox.information(self,
                                            "Updated",
                                            "Configuration updated successfully",
                                            QtWidgets.QMessageBox.Ok)
            if new_config_dict["latency_check"] == 1 and self.config_dict["latency_check"] == 0:
                self.get_latency()
            self.config_dict = new_config_dict

        except CalledProcessError as e:
            self.logger.info("Non-zero exit status: configuration changes not applied")
            QtWidgets.QMessageBox.information(self,
                                                "Authentication failure",
                                                "Configuration not updated",
                                                QtWidgets.QMessageBox.Ok)
    
    def Load(self):
        self.user = check_output(['id', '-u', '-n']).decode("utf-8").split("\n")[0]
        self.group = check_output(['id', '-g', '-n']).decode("utf-8").split("\n")[0]
        self.logger.debug("Reading configuration files from %s" %(DIRECTORY))
        
        try:
            with open('%s/config.json' % (ROOTDIR), 'r') as config:
                self.config_dict = json.load(config)
                if self.config_dict["minimize"] == 0:
                    self.setWindowState(QtCore.Qt.WindowActive)
                if self.config_dict["bypass"] == 1:
                    self.qomui_service.bypass(self.user, self.group)
                    self.bypass_tab_bt.setVisible(True)
                self.setOptiontab(self.config_dict)        
        except (FileNotFoundError,json.decoder.JSONDecodeError, KeyError) as e:
            self.logger.error('%s: Could not open %s/config.json' % (e, DIRECTORY))
        
        try:
            with open('%s/protocol.json' % (DIRECTORY), 'r') as pload:
                self.protocol_dict = json.load(pload)
        except (FileNotFoundError,json.decoder.JSONDecodeError) as e:
            self.logger.error('%s: Could not open %s/_protocol.json' % (e, DIRECTORY))
        
        try:
            with open('%s/server.json' % (DIRECTORY), 'r') as sload:
                self.server_dict = json.load(sload)
                self.popBoxes(country='All countries')
    
        except (FileNotFoundError,json.decoder.JSONDecodeError) as e:
            self.logger.error('%s: Could not open %s/_server.json' % (e, DIRECTORY))
            
        try:
            with open('%s/bypass_apps.json' % (DIRECTORY), 'r') as sload:
                self.bypass_app_list = json.load(sload)
                self.popBypassApps()
        except (FileNotFoundError,json.decoder.JSONDecodeError) as e:
            self.logger.error('%s: Could not open %s/bypass_apps.json' % (e, DIRECTORY))

        try:
            with open('%s/last_server.json' % (DIRECTORY), 'r') as lserver:
                if self.config_dict["autoconnect"] == 1:
                    last_server_dict = json.load(lserver)
                    self.ovpn_dict = last_server_dict["last"]
                    self.hop_server_dict = last_server_dict["hop"]
                    if self.hop_server_dict is not None:
                        self.setHop()
                    try: 
                        if self.ovpn_dict["random"] == "on":
                            self.chooseRandomServer()
                    except KeyError:
                        self.connect_thread(self.ovpn_dict)
                    try:
                        if self.ovpn_dict["favourite"] == "on":
                            self.favouriteButton.setChecked(True)
                    except KeyError:
                        pass
                    
        except (FileNotFoundError,json.decoder.JSONDecodeError, KeyError) as e:
            self.logger.error('Could not open %s/last_server.json' % (DIRECTORY))


    def restoreDefaults(self):
        with open('%s/default_config.json' % (ROOTDIR), 'r') as config:
                default_config_dict = json.load(config)
        self.setOptiontab(default_config_dict)
    
    def cancelOptions(self):
        self.setOptiontab(self.config_dict)
    
    def setOptiontab(self, config):
        try:
            self.alt_dns_edit1.setText(config["alt_dns1"])
            self.alt_dns_edit2.setText(config["alt_dns2"])
        except KeyError:
            pass
        
        if config["autoconnect"] == 0:
            self.autoconnect_check.setChecked(False)
        elif config["autoconnect"] == 1:
            self.autoconnect_check.setChecked(True)
            
        if config["firewall"] == 0:
            self.firewall_check.setChecked(False)
        elif config["firewall"] == 1:
            self.firewall_check.setChecked(True)
            
        if config["ipv6_disable"] == 0:
            self.ipv6_check.setChecked(False)
        elif config["ipv6_disable"] == 1:
            self.ipv6_check.setChecked(True)
            
        if config["minimize"] == 0:
            self.minimize_check.setChecked(False)
        elif config["minimize"] == 1:
            self.minimize_check.setChecked(True)
            
        if config["latency_check"] == 0:
            self.lat_check.setChecked(False)
        elif config["latency_check"] == 1:
            self.lat_check.setChecked(True)
            
        if config["bypass"] == 0:
            self.bypass_check.setChecked(False)
        elif config["bypass"] == 1:
            self.bypass_check.setChecked(True)
            
        if config["fallback"] == 0:
            self.dns_check.setChecked(False)
        elif config["fallback"] == 1:
            self.dns_check.setChecked(True)
    
    
    def networkstate(self, networkstate):
        if networkstate == 70 or networkstate == 60:
            self.logger.info("Detected new network connection")
            self.qomui_service.save_default_dns()
            if self.ovpn_dict is not None:
                self.connect_thread(self.ovpn_dict)
                self.qomui_service.bypass(self.user, self.group)
        elif networkstate != 70 and networkstate != 60:
            self.logger.info("Lost network connection - VPN tunnel terminated")
            self.kill()
        
    def providerChosen(self):
        provider = self.providerChoice.currentText()
        if provider == "Airvpn" or provider == "PIA":
            self.provider_edit.setVisible(False)
            self.user_edit.setPlaceholderText(_translate("Form", "Username", None))
            self.pass_edit.setPlaceholderText(_translate("Form", "Password", None))
            if provider in self.provider_list:
                self.download_bt.setText(_translate("Form", "Update", None))
            else:
                self.download_bt.setText(_translate("Form", "Download", None))
        elif provider == "Mullvad":
            self.provider_edit.setVisible(False)
            self.user_edit.setPlaceholderText(_translate("Form", "Account Number", None))
            self.pass_edit.setPlaceholderText(_translate("Form", "N.A.", None))
            if provider in self.provider_list:
                self.download_bt.setText(_translate("Form", "Update", None))
            else:
                self.download_bt.setText(_translate("Form", "Download", None))
        else:
            self.provider_edit.setVisible(True)
            self.provider_edit.setPlaceholderText(_translate("Form", "Specify name of provider", None))
            self.user_edit.setPlaceholderText(_translate("Form", "Username", None))
            self.pass_edit.setPlaceholderText(_translate("Form", "Password", None))
            self.download_bt.setText(_translate("Form", "Add Folder", None))

    def login(self):
        if not os.path.exists("%s/temp" % (DIRECTORY)):
               os.makedirs("%s/temp" % (DIRECTORY))
        
        provider = self.providerChoice.currentText()
        if provider not in SUPPORTED_PROVIDERS:
            provider = self.provider_edit.text()
    
        self.qomui_service.allowUpdate(provider)
        if provider == "Airvpn":
            username = self.user_edit.text()
            password = self.pass_edit.text()
            self.down_thread = update.AirVPNDownload(username, password)
            QtWidgets.QApplication.setOverrideCursor(QtGui.QCursor(QtCore.Qt.WaitCursor))
            self.down_thread.importFail.connect(self.importFail)
            self.down_thread.down_finished.connect(self.downloaded)
            self.down_thread.start()
            self.update_bar("start", provider)
        elif provider == "Mullvad":
            account_number = self.user_edit.text()
            self.down_thread = update.MullvadDownload(account_number)
            QtWidgets.QApplication.setOverrideCursor(QtGui.QCursor(QtCore.Qt.WaitCursor))
            self.down_thread.importFail.connect(self.importFail)
            self.down_thread.down_finished.connect(self.downloaded)
            self.down_thread.start()
            self.update_bar("start", provider)
        elif provider == "PIA":
            username = self.user_edit.text()
            password = self.pass_edit.text()
            self.down_thread = update.PiaDownload(username, password)
            QtWidgets.QApplication.setOverrideCursor(QtGui.QCursor(QtCore.Qt.WaitCursor))
            self.down_thread.importFail.connect(self.importFail)
            self.down_thread.down_finished.connect(self.downloaded)
            self.down_thread.start()
            self.update_bar("start", provider)
        else:
            provider = self.provider_edit.text()
            if provider == "":
                err = QtWidgets.QMessageBox.critical(self,
                                                "Error",
                                                "Please enter a provider name",
                                                QtWidgets.QMessageBox.Ok)
                
            elif provider in SUPPORTED_PROVIDERS:
                self.provider = provider
                self.login()
                
            else:
                credentials = (self.user_edit.text(), self.pass_edit.text(), self.provider_edit.text())
                try:
                    dialog = QtWidgets.QFileDialog.getOpenFileName(self,
                                                                    caption="Choose Folder",
                                                                    directory = os.path.expanduser("~"),
                                                                    filter=self.tr('OpenVPN (*.ovpn *conf);;All files (*.*)'),
                                                                    options=QtWidgets.QFileDialog.ReadOnly)
                    
                    folderpath = QtCore.QFileInfo(dialog[0]).absolutePath()
                    if folderpath != "":
                        self.thread = update.AddThread(credentials, folderpath)
                        self.thread.down_finished.connect(self.downloaded)
                        self.thread.importFail.connect(self.importFail)
                        self.thread.start()
                        self.update_bar("start", provider)
                except TypeError:
                    pass
                    
    def importFail(self, provider):
        QtWidgets.QApplication.restoreOverrideCursor()
        self.update_bar("stop", None)
        if provider == "Airvpn":
            header = "Authentication failed"
            msg = "Perhaps the credentials you entered are wrong"
        else:
            header = "Import Error"
            msg = "No config files found or folder seems\nto contain many unrelated files" 
            
        fail_msg = QtWidgets.QMessageBox.information(self,
                                                header,
                                                msg,
                                                QtWidgets.QMessageBox.Ok)
        
        try:
            shutil.rmtree("%s/temp/" % (DIRECTORY))
        except FileNotFoundError:
            pass
        
    def del_provider(self):
        confirm = QtWidgets.QMessageBox()
        confirm.setText("Are you sure?")
        confirm.addButton(QtWidgets.QPushButton("No"), QtWidgets.QMessageBox.NoRole)
        confirm.addButton(QtWidgets.QPushButton("Yes"), QtWidgets.QMessageBox.YesRole)
        ret = confirm.exec_()
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
            self.qomui_service.deleteProvider(provider)
            with open ("%s/server.json" % DIRECTORY, "w") as s:
                json.dump(self.server_dict, s)
            self.popBoxes()
   
    def update_bar(self, text, provider):
        if text == "stop":
            self.WaitBar.setVisible(False)
        elif text == "start":
            self.WaitBar.setVisible(True)
            self.WaitBar.setText("Importing %s" %provider)

    def downloaded(self, content):
        self.update_bar("stop", None)
        QtWidgets.QApplication.restoreOverrideCursor()
        down_msg = QtWidgets.QMessageBox.information(self,
                                                "Import successful",
                                                "List of available servers updated",
                                                QtWidgets.QMessageBox.Ok)
        
        provider = content["provider"]
        if provider not in self.provider_list:
            self.provider_list.append(provider)
        self.copyfiles(provider, content["path"])
        find_favourites = []
        for k, v in content["server"].items():
            try:
                if self.server_dict[k]["favourite"] == "on":
                    content["server"][k]["favourite"] = "on"
            except KeyError:
                pass
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
        
        with open ("%s/server.json" % DIRECTORY, "w") as s:
            json.dump(self.server_dict, s)
        
        with open ("%s/protocol.json" % DIRECTORY, "w") as p:
            json.dump(self.protocol_dict, p) 
        self.popBoxes()
    
    def del_server_file(self):
        for item in self.serverListWidget.selectedItems():
            data = item.data(QtCore.Qt.UserRole)
            index = self.serverListWidget.row(item)
            try:
                self.server_dict.pop(data, None)
                self.serverListWidget.takeItem(index)
            except KeyError:
                pass
        with open ("%s/server.json" % DIRECTORY, "w") as s:
            json.dump(self.server_dict, s)
        
    def copyfiles(self, provider, path):
        self.qomui_service.block_dns()
        copy = self.qomui_service.copyCerts(provider, path)
        if copy == "copied":
            shutil.rmtree("%s/temp/" % (DIRECTORY))

    def popBoxes(self, country=None):
        self.country_list = ["All countries"]
        self.provider_list = ["All providers"]
        for k,v in (self.server_dict.items()):
            if v["country"] not in self.country_list:
                self.country_list.append(v["country"])
                flag = '%s/flags/%s.png' % (ROOTDIR, v["country"])
                if not os.path.isfile(flag):
                    flag = '%s/flags/Unknown.png' % ROOTDIR
                pixmap = QtGui.QPixmap(flag).scaled(25, 25, transformMode=QtCore.Qt.SmoothTransformation)
                setattr(self, v["country"] + "_pixmap", pixmap)
            elif v["provider"] not in self.provider_list:
                self.provider_list.append(v["provider"])
        self.popProviderBox()
        self.popDeleteProviderBox()
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
        self.filterList(display="all")
        print(self.config_dict)
        if self.config_dict["latency_check"] == 1:
            self.get_latency()
        
    def get_latency(self):
        gateway = self.qomui_service.default_gateway_check()["interface"]
        self.latency_list = []
        self.latThread = latency.LatencyCheck(self.server_dict, gateway)
        self.latThread.lat_signal.connect(self.show_latency)
        self.latThread.start()
        
    def show_latency(self, result):
        hidden = False
        server = result[0]
        latency_string = result[1]
        latency_float = result[2]
        old_index = self.index_list.index(server)
        bisect.insort(self.latency_list, latency_float)
        update_index = self.latency_list.index(latency_float)
        rm = self.index_list.index(server)
        self.index_list.pop(rm)
        self.index_list.insert(update_index, server)
        if getattr(self, server).isHidden() == True:
            hidden = True
        self.serverListWidget.takeItem(old_index)
        self.pop_ServerList(server, self.server_dict[server], insert=update_index)
        self.serverListWidget.setRowHidden(update_index, hidden)
        getattr(self, server).display_latency(latency_string)
        
        
    
    def show_favs(self, state):
        self.random_server_bt.setVisible(True)
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
            self.filterList()
                    

    def filterList(self, *arg, display="filter"):
        self.random_server_bt.setVisible(False)
        country = self.countryBox.currentText()
        provider = self.providerBox.currentText()
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
                self.pop_ServerList(key, val)
        else:
            for key, val in self.server_dict.items():
                index = self.index_list.index(key)
                if val["provider"] == provider or provider == "All providers":
                    if val["country"] == country or country == "All countries":
                        self.serverListWidget.setRowHidden(index, False)
                        getattr(self, key).setHidden(False)
                    else:
                        self.serverListWidget.setRowHidden(index, True)
                        getattr(self, key).setHidden(True)
                else:
                    self.serverListWidget.setRowHidden(index, True)
                    getattr(self, key).setHidden(True)

    
    def pop_ServerList(self, key, val, insert=None):
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
        getattr(self, key).setText(val["name"], val["provider"], 
                          getattr(self, "%s_pixmap" %val["country"]), 
                          val["city"], fav=fav)
        getattr(self, key).establish.connect(self.establish)
        getattr(self, key).establish_hop.connect(self.createHop)
        getattr(self, key).fav_sig.connect(self.change_favourite)

    def popProviderBox(self):
        self.providerSelect.clear()
        for provider in sorted(self.provider_list):
            if provider != "All providers":
                self.providerSelect.addItem(provider)
                self.popProtocolList(self.providerSelect.currentText())
            
    def popProtocolList(self, provider):
        if provider in SUPPORTED_PROVIDERS:
            self.protocolListWidget.setVisible(True)
            self.overrideCheck.setVisible(False)
            self.portOverrideLabel.setVisible(False)
            self.protocolBox.setVisible(False)
            self.portEdit.setVisible(False)
            self.savePortButton.setVisible(False)
            self.protocolListWidget.clear()
            self.protocolListWidget.itemClicked.connect(self.protocolChange)
            try:
                current = self.protocol_dict[provider]["selected"]
            except KeyError:
                current = self.protocol_dict[provider]["protocol_1"]
            for k,v in sorted(self.protocol_dict[provider].items()):
                if k != "selected":
                    try:
                        mode = v["protocol"] + " " + v["port"] + ", " + v["ip"]
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
                self.protocol_override(True, protocol=protocol, port=port)
                self.overrideCheck.setChecked(True)
            except KeyError:
                pass
            
    def protocolChange(self, selection):
        provider = self.providerSelect.currentText()
        if provider in SUPPORTED_PROVIDERS:
            self.protocol_dict[provider]["selected"] = selection.data(QtCore.Qt.UserRole)
            with open ("%s/protocol.json" % DIRECTORY, "w") as p:
                json.dump(self.protocol_dict, p)
            for item in range(self.protocolListWidget.count()):
                if self.protocolListWidget.item(item) != selection:
                    self.protocolListWidget.item(item).setCheckState(QtCore.Qt.Unchecked)
                else:
                    self.protocolListWidget.item(item).setCheckState(QtCore.Qt.Checked)
            
    def protocol_override(self, state, protocol=None, port=None):
        if state == True:
            self.portOverrideLabel.setVisible(True)
            self.protocolBox.setVisible(True)
            self.portEdit.setVisible(True)
            self.savePortButton.setVisible(True)
            if protocol is not None:
                if protocol == "UDP":
                    self.protocolBox.setCurrentIndex(0)
                elif protocol == "TCP":
                    self.protocolBox.setCurrentIndex(1)
                self.portEdit.setText(port)
                    
        elif state == False:
            try:
                self.protocol_dict.pop(self.providerSelect.currentText(), None)
                with open ("%s/protocol.json" % DIRECTORY, "w") as p:
                    json.dump(self.protocol_dict, p)
            except KeyError:
                pass
            
    def overrideProtocol(self):
        protocol = self.protocolBox.currentText()
        port = self.portEdit.text()
        provider = self.providerSelect.currentText()
        if self.overrideCheck.checkState() == 2:
            self.protocol_dict[provider] = {"protocol" : protocol, "port": port}
            with open ("%s/protocol.json" % DIRECTORY, "w") as p:
                json.dump(self.protocol_dict, p) 
        
            
    def popDeleteProviderBox(self):
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
                self.show_favs(True)
        with open ("%s/server.json" % DIRECTORY, "w") as s:
            json.dump(self.server_dict, s) 
            
    
    def createHop(self, server):
        try:
            current_dict = self.server_dict[server].copy()
            self.create_server_dict(current_dict, 1)
            self.setHop()
        except KeyError:
            self.show_failmsg("Server not found",
                              "Server does not exist (anymore)\nHave you deleted the server?")
        
    def setHop(self):
        self.hop_choice = 2
        self.hop_server_dict.update({"hop":"1"})
        self.serverHopWidget.setVisible(True)
        self.serverHopWidget.setText(self.hop_server_dict)
        self.serverHopWidget.clear.connect(self.clear_HopSelect)
        self.qomui_service.hopConnect(self.hop_server_dict)
        
    def clear_HopSelect(self):
        self.hop_choice = 0
        self.hop_server_dict = None
        self.serverHopWidget.setVisible(False)
        index = self.tabWidget.currentIndex()
        self.filterList()
        
    def chooseRandomServer(self):
        random_list = []
        for key, val in self.server_dict.items():
            try:
                if val["favourite"] == "on":
                    random_list.append(key)
            except KeyError:
                pass
        if len(random_list) != 0:
            self.establish(random.choice(random_list), random="on")
        
    
    def establish(self, server, random=None):
        try:
            current_dict = self.server_dict[server].copy()
        except KeyError:
            self.show_failmsg("Server not found",
                              "Server does not exist (anymore)\nHave you deleted the server?")
            
        QtWidgets.QApplication.restoreOverrideCursor()
        self.kill()
        self.create_server_dict(current_dict, 0)
        
        if self.hop_choice == 2 and self.hop_server_dict is not None:
            self.ovpn_dict.update({"hop":"2"})
        else:
            self.ovpn_dict.update({"hop":"0"})
            
        if random is not None:
            self.ovpn_dict.update({"random" : "on"})
        
        self.connect_thread(self.ovpn_dict)
        
    def create_server_dict(self, current_dict, h):
        provider = current_dict["provider"]
        if provider == "Airvpn":
            mode = self.protocol_dict["Airvpn"]["selected"]
            port = self.protocol_dict["Airvpn"][mode]["port"]
            protocol = self.protocol_dict["Airvpn"][mode]["protocol"]

            if self.protocol_dict["Airvpn"][mode]["ip"] == "Primary":
                ip = current_dict["prim_ip"]
            
            elif self.protocol_dict["Airvpn"][mode]["ip"] == "Alternative":
                ip = current_dict["alt_ip"]
            current_dict.update({"ip" : ip, "port": port, "protocol": protocol, "prot_index": mode})
            
        elif provider == "Mullvad":
            mode = self.protocol_dict["Mullvad"]["selected"]
            port = self.protocol_dict["Mullvad"][mode]["port"]
            protocol = self.protocol_dict["Mullvad"][mode]["protocol"]
            current_dict.update({"port": port, "protocol": protocol, "prot_index": mode})
            
        elif provider == "PIA":
            mode = self.protocol_dict["PIA"]["selected"]
            port = self.protocol_dict["PIA"][mode]["port"]
            protocol = self.protocol_dict["PIA"][mode]["protocol"]
            current_dict.update({"port": port, "protocol": protocol, "prot_index": mode})
        
        else:
            try: 
                port = self.protocol_dict[provider]["port"]
                protocol = self.protocol_dict[provider]["protocol"]
                current_dict.update({"port": port, "protocol": protocol})
            except KeyError:
                pass
            
        if h == 1:
            self.hop_server_dict = current_dict
        else:
            self.ovpn_dict = current_dict
          
    def log_check(self, reply):
        if reply == "success":
            if self.hop_choice != 2 or self.log_count == 1:
                self.log_count = 0
                self.WaitBar.setVisible(False)
                self.activeWidget(self.ovpn_dict, self.hop_server_dict)
                try:
                    self.tray.setIcon(QtGui.QIcon('%s/flags/%s.png' % (ROOTDIR, self.ovpn_dict["country"])))
                except KeyError:
                    self.tray.setIcon(QtGui.QIcon("%s/qomui.png" % (ROOTDIR)))
                
                QtWidgets.QApplication.restoreOverrideCursor()
            
            elif self.hop_choice == 2 and self.log_count != 1:
                self.log_count = 1
            
            with open('%s/last_server.json' % (DIRECTORY), 'w') as lserver:
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
            self.tray.setIcon(QtGui.QIcon("%s/qomui.png" % (ROOTDIR)))
            QtWidgets.QApplication.restoreOverrideCursor()
            self.ActiveWidget.setVisible(False)
            
    def show_failmsg(self, text, information):
        self.failmsg = QtWidgets.QMessageBox(self)
        self.failmsg.setIcon(QtWidgets.QMessageBox.Critical)
        self.failmsg.setText(text)
        self.failmsg.setInformativeText(information)
        self.failmsg.setWindowModality(QtCore.Qt.WindowModal)
        self.failmsg.show()
        
    def activeWidget(self, current_server, hop_dict):
        tun = self.qomui_service.return_tun_device()
        self.ActiveWidget.setText(current_server, hop_dict, tun)
        self.ActiveWidget.setVisible(True)
        self.ActiveWidget.disconnect.connect(self.kill)
        self.gridLayout.addWidget(self.ActiveWidget, 0, 0, 1, 3)

    def kill(self):
        self.WaitBar.setVisible(False)
        self.ActiveWidget.setVisible(False)
        try:
            self.tray.setIcon(QtGui.QIcon("%s/qomui.png" % (ROOTDIR)))
        except AttributeError:
            pass
        self.qomui_service.disconnect()

    def connect_thread(self, server_dict):
        QtWidgets.QApplication.setOverrideCursor(QtGui.QCursor(QtCore.Qt.WaitCursor))
        self.logger.info("Connecting to %s...." %server_dict["name"])
        self.WaitBar.setText("Connecting to %s" %server_dict["name"])
        self.WaitBar.setVisible(True)
        self.log_count = 0
        provider = server_dict["provider"]
        try:
            self.qomui_service.qomuiConnect(server_dict)
        except dbus.exceptions.DBusException as e:
            self.logger.error("Dbus-service not available")

    def show_firewalleditor(self):
        editor = FirewallEditor()
        editor.rule_change.connect(self.firewall_update)
        editor.exec_()

    def firewall_update(self):
        self.fire_change = True  
        
    def select_application(self):
        selector = AppSelector()
        selector.app_chosen.connect(self.add_bypass_app)
        selector.exec_()
            
    def add_bypass_app(self, app_info):
        self.bypass_app_list[app_info[0]] = [app_info[1], app_info[2]]
        with open ("%s/bypass_apps.json" %DIRECTORY, "w") as save_bypass:
            json.dump(self.bypass_app_list, save_bypass)
        self.popBypassApps()
        
    def del_bypass_app(self):
        for item in self.app_list.selectedItems():
            data = item.data(QtCore.Qt.UserRole)
            try:
                self.bypass_app_list.pop(data, None)
                self.app_list.removeItemWidget(item)
            except KeyError:
                pass
        with open ("%s/bypass_apps.json" %DIRECTORY, "w") as save_bypass:
            json.dump(self.bypass_app_list, save_bypass)
        self.popBypassApps()
        
    def popBypassApps(self):
        self.app_list.clear()
        for k,v in self.bypass_app_list.items():
            self.Item = ServerWidget()
            self.ListItem = QtWidgets.QListWidgetItem(self.app_list)
            self.ListItem.setSizeHint(QtCore.QSize(100, 50))
            self.Item.setText(k, "bypass", v[0], None, button="bypass")
            self.ListItem.setData(QtCore.Qt.UserRole, k)
            self.Item.removeButton(0)
            self.app_list.addItem(self.ListItem)
            self.app_list.setItemWidget(self.ListItem, self.Item)
            self.Item.establish.connect(self.runBypass)
            
    def runBypass(self, app):
        desktop_file = self.bypass_app_list[app][1]
        with open (desktop_file, "r") as cmd_ret:
            search = cmd_ret.readlines()
            found = 0
            for line in search:
                if line.startswith("Exec") and found !=1:
                    cmd = line.split("=")[1].split(" ")[0].replace("\n", "")
                    found = 1
        
        temp_bash = "%s/bypass_temp.sh" %DIRECTORY
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
            logging.error("Could not start %s" %app)
        
    def modifyServer(self):
        if self.serverListWidget.isVisible() is False:
            item = self.serverListFilterWidget.currentItem()
            data = item.data(QtCore.Qt.UserRole)
            self.modify_row = self.serverListFilterWidget.row(item)
        else:
            item = self.serverListWidget.currentItem()
            data = item.data(QtCore.Qt.UserRole)
            self.modify_row = self.serverListWidget.row(item)
        try:
            editor = ModifyServer(key=data, server_info=self.server_dict[data])
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
        self.serverListWidget.takeItem(row)
        self.pop_ServerList(key_update, val, insert=row)
        with open ("%s/server.json" % DIRECTORY, "w") as s:
            json.dump(self.server_dict, s) 
        
        if len(new_config) != 0:
            if provider in SUPPORTED_PROVIDERS:
                temp_file = "%s/temp/%s_config" %(DIRECTORY, provider)
                with open(temp_file, "w") as config_change:
                    config_change.writelines(new_config)
            else:
                temp_file = "%s/temp/%s" %(DIRECTORY, val["path"].split("/")[1])
                if modifications["apply_all"] == 1:
                    for k, v in self.server_dict.items():
                        if v["provider"] == provider:
                            with open("%s/temp/%s" %(DIRECTORY, v["path"].split("/")[1]), "w") as config_change:
                                index = modifications["index"]
                                rpl = new_config[index].split(" ")
                                ip_insert = "%s %s %s" %(rpl[0], v["ip"], rpl[2])
                                new_config[index] = ip_insert
                                config_change.writelines(new_config)
                    
            self.qomui_service.copyCerts("CHANGE_%s" %provider, "%s/temp" %(DIRECTORY))
                                
        
    def search_listitem(self, key):
        for row in range(self.serverListWidget.count()):
            if self.serverListWidget.item(row).data(QtCore.Qt.UserRole) == key:
                return row
        
class ServerWidget(QtWidgets.QWidget):
    establish = QtCore.pyqtSignal(str)
    establish_hop = QtCore.pyqtSignal(str)
    fav_sig = QtCore.pyqtSignal(tuple)
    
    def __init__ (self, parent=None):
        super(ServerWidget, self).__init__(parent=None)
        self.hidden = False
        self.fav = 0
        self.setMouseTracking(True)
        self.setupUi(self)
            
    def setupUi(self, Form):
        Form.setObjectName(_fromUtf8("Form"))
        self.horizontalLayout = QtWidgets.QHBoxLayout(Form)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.country_lbl = QtWidgets.QLabel(Form)
        self.country_lbl.setFixedSize(QtCore.QSize(30, 30))
        self.country_lbl.setLayoutDirection(QtCore.Qt.RightToLeft)
        self.country_lbl.setObjectName(_fromUtf8("country_lbl"))
        self.horizontalLayout.addWidget(self.country_lbl)
        self.name_lbl = QtWidgets.QLabel(Form)
        self.name_lbl.setObjectName(_fromUtf8("name_lbl"))
        self.horizontalLayout.addWidget(self.name_lbl)
        self.city_lbl = QtWidgets.QLabel(Form)
        self.city_lbl.setObjectName(_fromUtf8("city_lbl"))
        self.horizontalLayout.addWidget(self.city_lbl)
        self.stat_lbl = QtWidgets.QLabel(Form)
        self.stat_lbl.setObjectName(_fromUtf8("stat_lbl"))
        self.horizontalLayout.addWidget(self.stat_lbl)
        self.stat_lbl.setVisible(False)                            
        spacerItem = QtWidgets.QSpacerItem(105, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.FavouriteButton = FavouriteButton(Form)
        self.FavouriteButton.setVisible(False)
        self.FavouriteButton.setCheckable(True)
        self.FavouriteButton.setObjectName(_fromUtf8("FavouriteButton"))
        self.horizontalLayout.addWidget(self.FavouriteButton)
        self.hop_bt = QtWidgets.QPushButton(Form)
        self.hop_bt.setVisible(False)
        self.hop_bt.setObjectName(_fromUtf8("hop_bt"))
        self.horizontalLayout.addWidget(self.hop_bt)
        self.connect_bt = QtWidgets.QPushButton(Form)
        self.connect_bt.setVisible(False)
        self.connect_bt.setObjectName(_fromUtf8("connect_bt"))
        self.horizontalLayout.addWidget(self.connect_bt)
        QtCore.QMetaObject.connectSlotsByName(Form)
        self.connect_bt.clicked.connect(self.signal)
        self.hop_bt.clicked.connect(self.hop_signal)
        self.FavouriteButton.toggled.connect(self.fav_change)
    
    def setText(self, name, provider, country, city, button = "connect", fav = 0):
        self.name = name
        self.provider = provider
        self.city = city
        self.fav = fav
        if self.provider != "bypass":
            try:
                self.country_lbl.setPixmap(country)
            except TypeError:
                flag = '%s/flags/%s.png' % (ROOTDIR, country)
                if not os.path.isfile(flag):
                    flag = '%s/flags/Unknown.png' % ROOTDIR
                self.country_lbl.setPixmap(QtGui.QPixmap(flag).scaled(25, 25, transformMode=QtCore.Qt.SmoothTransformation))
        else:
            icon = QtGui.QIcon.fromTheme(country)
            self.country_lbl.setPixmap(icon.pixmap(25,25))
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        font.setPointSize(11)
        if self.fav == "on":
            self.FavouriteButton.setChecked(True)
        self.name_lbl.setFont(font)
        self.name_lbl.setText(self.name)
        self.city_lbl.setText(self.city)
        try:
            self.connect_bt.setText(_translate("Form", button, None))
        except AttributeError:
            pass
        try:
            self.hop_bt.setText(_translate("Form", "hop", None))
        except AttributeError:
            pass
        
    def removeButton(self, choice=None):
        self.choice = choice
        self.hop_bt = None
        if choice == 1:
            self.connect_bt = None
            
    def enterEvent(self, event):
        try:
            self.connect_bt.setVisible(True)
        except AttributeError:
            pass
        try:
            self.hop_bt.setVisible(True)
        except AttributeError:
            pass
        if self.fav != 0:
            self.FavouriteButton.setVisible(True)

    def leaveEvent(self, event):
        try:
            self.connect_bt.setVisible(False)
        except AttributeError:
            pass
        try:
            self.hop_bt.setVisible(False)
        except AttributeError:
            pass
        self.FavouriteButton.setVisible(False)

    def signal(self):
        self.establish.emit(self.name)
        
    def display_latency(self, latency):
        self.latency = latency
        if self.city != "":
            self.city_lbl.setText("%s - %s" %(self.city, self.latency))
        else:
            self.city_lbl.setText(latency)
        
    def setHidden(self, state):
        self.hidden = state
    
    def isHidden(self):
        return self.hidden
    
    def hop_signal(self):
        self.establish_hop.emit(self.name)
        
    def fav_change(self, change):
        self.fav_sig.emit((self.name, change))
        
    def sizeHint(self):
        return QtCore.QSize(100, 50)

class HopSelect(QtWidgets.QWidget):
    clear = QtCore.pyqtSignal()
    
    def __init__ (self, parent=None):
        super(HopSelect, self).__init__(parent)
        self.setupUi(self)
            
    def setupUi(self, Form):
        Form.setObjectName(_fromUtf8("Form"))
        Form.resize(100, 100)
        self.setAutoFillBackground(True)
        self.setBackgroundRole(self.palette().Base)
        self.verticalLayout = QtWidgets.QVBoxLayout(Form)
        self.hop_label = QtWidgets.QLabel(Form)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.hop_label.setFont(font)
        self.verticalLayout.addWidget(self.hop_label)
        self.hopWidget = ServerWidget()
        self.verticalLayout.addWidget(self.hopWidget)
        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)
        self.hopWidget.establish.connect(self.signal)

    def retranslateUi(self, Form):
        Form.setWindowTitle(_translate("Form", "Form", None))
        self.hop_label.setText(_translate("Form", "Current selection for first hop:", None))
        
    def setText(self, server_dict):
        try:
            city = server_dict["city"]
        except KeyError:
            city = None
        self.hopWidget.setText(server_dict["name"], server_dict["provider"],
                               server_dict["country"], city, button="clear")
        
        self.hopWidget.removeButton(0)

    def signal(self):
        self.clear.emit()

class WaitBarWidget(QtWidgets.QWidget):
    def __init__ (self, parent=None):
        super(WaitBarWidget, self).__init__(parent)
        self.setupUi(self)
        
    def setupUi(self, WaitBarWidget):
        self.horizontalLayout = QtWidgets.QHBoxLayout(WaitBarWidget)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.task_label = QtWidgets.QLabel(WaitBarWidget)
        self.task_label.setObjectName(_fromUtf8("task_label"))
        font = QtGui.QFont()
        font.setPointSize(13)
        font.setBold(True)
        font.setWeight(75)
        self.task_label.setFont(font)
        self.horizontalLayout.addWidget(self.task_label)
        self.wait_bar = QtWidgets.QProgressBar(WaitBarWidget)
        self.wait_bar.setObjectName(_fromUtf8("wait_bar"))
        self.horizontalLayout.addWidget(self.wait_bar)
        self.wait_bar.setRange(0, 0)
        
    def setText(self, text):
        self.task_label.setText(_translate("WaitBarWidget", text, None))


class ActiveWidget(QtWidgets.QWidget):
    disconnect = QtCore.pyqtSignal()
    
    def __init__ (self, parent=None):
        super(ActiveWidget, self).__init__(parent)
        self.setupUi(self)
    
    def setupUi(self, ConnectionWidget):
        ConnectionWidget.setObjectName(_fromUtf8("ConnectionWidget"))
        self.verticalLayout = QtWidgets.QVBoxLayout(ConnectionWidget)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
        self.status_label = QtWidgets.QLabel(ConnectionWidget)
        font = QtGui.QFont()
        font.setPointSize(13)
        font.setBold(True)
        font.setWeight(75)
        self.status_label.setFont(font)
        self.status_label.setObjectName(_fromUtf8("status_label"))
        self.horizontalLayout_3.addWidget(self.status_label)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_3.addItem(spacerItem)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        self.ServerWidget = ServerWidget(ConnectionWidget)
        self.verticalLayout.addWidget(self.ServerWidget)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.down_lbl = QtWidgets.QLabel(ConnectionWidget)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.down_lbl.setFont(font)
        self.down_lbl.setObjectName(_fromUtf8("down_lbl"))
        self.horizontalLayout.addWidget(self.down_lbl)
        self.down_stat_blb = QtWidgets.QLabel(ConnectionWidget)
        self.down_stat_blb.setObjectName(_fromUtf8("down_stat_blb"))
        self.horizontalLayout.addWidget(self.down_stat_blb)
        self.up_lbl = QtWidgets.QLabel(ConnectionWidget)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.up_lbl.setFont(font)
        self.up_lbl.setObjectName(_fromUtf8("up_lbl"))
        self.horizontalLayout.addWidget(self.up_lbl)
        self.up_stat_blb = QtWidgets.QLabel(ConnectionWidget)
        self.up_stat_blb.setObjectName(_fromUtf8("up_stat_blb"))
        self.horizontalLayout.addWidget(self.up_stat_blb)
        self.time_lbl = QtWidgets.QLabel(ConnectionWidget)
        self.time_lbl.setObjectName(_fromUtf8("time_lbl"))
        self.time_lbl.setFont(font)
        self.horizontalLayout.addWidget(self.time_lbl)
        self.time_stat_lbl = QtWidgets.QLabel(ConnectionWidget)
        self.time_stat_lbl.setObjectName(_fromUtf8("time_stat_lbl"))
        self.horizontalLayout.addWidget(self.time_stat_lbl)
        spacerItem2 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem2)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName(_fromUtf8("horizontalLayout_4"))
        self.status_hop_label = QtWidgets.QLabel(ConnectionWidget)
        font = QtGui.QFont()
        font.setPointSize(13)
        font.setBold(True)
        font.setWeight(75)
        self.status_hop_label.setFont(font)
        self.status_hop_label.setObjectName(_fromUtf8("status_hop_label"))
        self.status_hop_label.setMinimumSize(QtCore.QSize(30, 30))
        self.status_hop_label.setMaximumSize(QtCore.QSize(30, 30))
        self.status_hop_label.setVisible(False)
        self.horizontalLayout_4.addWidget(self.status_hop_label)
        self.hopWidget = ServerWidget(ConnectionWidget)
        self.hopWidget.setVisible(False)
        self.horizontalLayout_4.addWidget(self.hopWidget)
        self.verticalLayout.addLayout(self.horizontalLayout_4)
        self.line = LineWidget(ConnectionWidget)
        self.line.setObjectName(_fromUtf8("line"))
        self.verticalLayout.addWidget(self.line)
        self.retranslateUi(ConnectionWidget)
        QtCore.QMetaObject.connectSlotsByName(ConnectionWidget)
        self.ServerWidget.establish.connect(self.signal)

    def retranslateUi(self, ConnectionWidget):
        ConnectionWidget.setWindowTitle(_translate("ConnectionWidget", "Form", None))
        self.status_label.setText(_translate("ConnectionWidget", "Active Connection", None))
        self.down_lbl.setText(_translate("ConnectionWidget", "Download:", None))
        self.up_lbl.setText(_translate("ConnectionWidget", "Upload:", None))
        self.time_lbl.setText(_translate("ConnectionWidget", "Time:", None))

    def setText(self, server_dict, hop_dict, tun):
        self.tun = tun
        if hop_dict is not None:
            self.hopWidget.setVisible(True)
            self.status_hop_label.setVisible(True)
            self.status_hop_label.setText(_translate("HopWidget", "via", None))
            try:
                city = hop_dict["city"]
            except KeyError:
                city = None
            self.hopWidget.setText(hop_dict["name"], hop_dict["provider"],
                               hop_dict["country"], city)
            self.hopWidget.removeButton(1)
            
        else:
            self.hopWidget.setVisible(False)
            self.status_hop_label.setVisible(False)
        
        try:
            city = server_dict["city"]
        except KeyError:
            city = None
        self.ServerWidget.setText(server_dict["name"], server_dict["provider"],
                               server_dict["country"], city, button="disconnect")
        
        self.ServerWidget.removeButton(0)
            
        self.calc_Thread = NetMon(self.tun)
        self.calc_Thread.stat.connect(self.statcount)
        self.calc_Thread.ip.connect(self.show_ip)
        self.calc_Thread.time.connect(self.update_time)
        self.calc_Thread.start()
    
    def show_ip(self, ip):
        self.status_label.setText("Active connection - IP: %s" %ip)
        
    def update_time(self, t):
        self.time_stat_lbl.setText(t)
    
    def statcount(self, update):
        DLrate = update[0]
        DLacc = update[1]
        ULrate = update[2]
        ULacc = update[3]
        self.up_stat_blb.setText("%s kB/s - %s mb" % (round(ULrate, 1), round(ULacc, 1)))
        self.down_stat_blb.setText("%s kB/s - %s mb" % (round(DLrate, 1), round(DLacc, 1)))

    def signal(self):
        self.disconnect.emit()
        
class LineWidget(QtWidgets.QWidget):
    
    def __init__ (self, parent=None):
        super(LineWidget, self).__init__(parent)
        self.setupUi(self)
    
    def setupUi(self, LineWidget):
        self.setAutoFillBackground(True)
        self.setFixedHeight(1)
        self.setBackgroundRole(self.palette().Highlight)
        
class NetMon(QtCore.QThread):
    stat = QtCore.pyqtSignal(list)
    ip = QtCore.pyqtSignal(str)
    time = QtCore.pyqtSignal(str)
    
    def __init__(self, tun):
        QtCore.QThread.__init__(self)
        self.tun = tun
        
    def run(self):
        check_url = "https://ipinfo.io/ip"
        try:
            ip = requests.get(check_url).content.decode("utf-8").split("\n")[0]
            self.ip.emit(ip)
        except:
            logging.debug("Could not determine external ip address")
        t0 = time.time()
        counter = psutil.net_io_counters(pernic=True)['tun0']
        stat = (counter.bytes_recv, counter.bytes_sent)
        accum = (0, 0)
        start_time = time.time()
 
        while True:
            last_stat = stat
            time.sleep(1)
            time_measure = time.time()
            elapsed = time_measure - start_time
            return_time = self.time_format(int(elapsed))
            self.time.emit(return_time)
            
            try:
                counter = psutil.net_io_counters(pernic=True)['tun0']
                t1 = time.time()
                stat = (counter.bytes_recv, counter.bytes_sent)
                DLrate, ULrate = [(now - last) / (t1 - t0) / 1024.0 for now, last in zip(stat, last_stat)]
                DLacc, ULacc = [(now + last) / (1024*1024) for now, last in zip(stat, last_stat)]
                t0 = time.time()
                self.stat.emit([DLrate, DLacc, ULrate, ULacc])                     
            except KeyError:
                   break
               
    def time_format(self, e):
        calc = '{:02d}d {:02d}h {:02d}m {:02d}s'.format(e // 86400, (e % 86400 // 3600), (e % 3600 // 60), e % 60)
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
        with open('%s/firewall.json' %ROOTDIR, 'r') as fload:
            self.firewall_dict = json.load(fload)
        self.setupUi(self)
        self.displayRules()
        
    def setupUi(self, Form):
        Form.setObjectName(_fromUtf8("Form"))
        Form.resize(600, 700)
        self.verticalLayout = QtWidgets.QVBoxLayout(Form)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.fire_main_lbl = QtWidgets.QLabel(Form)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.fire_main_lbl.setFont(font)
        self.fire_main_lbl.setObjectName(_fromUtf8("fire_main_lbl"))
        self.verticalLayout.addWidget(self.fire_main_lbl)
        self.label = QtWidgets.QLabel(Form)
        self.label.setObjectName(_fromUtf8("label"))
        self.verticalLayout.addWidget(self.label)
        self.line = QtWidgets.QFrame(Form)
        self.line.setFrameShape(QtWidgets.QFrame.HLine)
        self.line.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line.setObjectName(_fromUtf8("line"))
        self.verticalLayout.addWidget(self.line)
        self.ipv4_lbl = QtWidgets.QLabel(Form)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.ipv4_lbl.setFont(font)
        self.ipv4_lbl.setObjectName(_fromUtf8("ipv4_on_lbl"))
        self.verticalLayout.addWidget(self.ipv4_lbl)
        self.ipv4_edit = QtWidgets.QPlainTextEdit(Form)
        self.ipv4_edit.setObjectName(_fromUtf8("ipv4_on_edit"))
        self.verticalLayout.addWidget(self.ipv4_edit)
        self.ipv6_lbl = QtWidgets.QLabel(Form)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.ipv6_lbl.setFont(font)
        self.ipv6_lbl.setObjectName(_fromUtf8("ipv6_on_lbl_2"))
        self.verticalLayout.addWidget(self.ipv6_lbl)
        self.ipv6_edit = QtWidgets.QPlainTextEdit(Form)
        self.ipv6_edit.setObjectName(_fromUtf8("ipv6_on_edit"))
        self.verticalLayout.addWidget(self.ipv6_edit)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.fire_edit_restore_bt = QtWidgets.QPushButton(Form)
        self.fire_edit_restore_bt.setObjectName(_fromUtf8("fire_edit_save_bt"))
        self.horizontalLayout.addWidget(self.fire_edit_restore_bt)
        self.fire_edit_save_bt = QtWidgets.QPushButton(Form)
        self.fire_edit_save_bt.setObjectName(_fromUtf8("fire_edit_save_bt"))
        self.horizontalLayout.addWidget(self.fire_edit_save_bt)
        self.fire_edit_cancel_bt = QtWidgets.QPushButton(Form)
        self.fire_edit_cancel_bt.setObjectName(_fromUtf8("fire_edit_cancel_bt"))
        self.horizontalLayout.addWidget(self.fire_edit_cancel_bt)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)
        self.fire_edit_cancel_bt.clicked.connect(self.cancel)
        self.fire_edit_save_bt.clicked.connect(self.saveRules)
        self.fire_edit_restore_bt.clicked.connect(self.restore)

    def retranslateUi(self, Form):
        Form.setWindowTitle(_translate("Form", "Edit firewall", None))
        self.fire_main_lbl.setText(_translate("Form", "Edit firewall rules", None))
        self.label.setText(_translate("Form", "Warning: Only for advanced users ", None))
        self.ipv4_lbl.setText(_translate("Form", "IPv4 rules", None))
        self.ipv6_lbl.setText(_translate("Form", "IPv6 rules", None))
        self.fire_edit_save_bt.setText(_translate("Form", "Save", None))
        self.fire_edit_save_bt.setIcon(QtGui.QIcon.fromTheme("dialog-ok"))
        self.fire_edit_cancel_bt.setText(_translate("Form", "Cancel", None))
        self.fire_edit_cancel_bt.setIcon(QtGui.QIcon.fromTheme("dialog-close"))
        self.fire_edit_restore_bt.setText(_translate("Form", "Restore defaults", None))
        self.fire_edit_restore_bt.setIcon(QtGui.QIcon.fromTheme("view-refresh"))

    def displayRules(self):
        for rule in self.firewall_dict["ipv4rules"]:
            self.ipv4_edit.appendPlainText(' '.join(rule))
        for rule in self.firewall_dict["ipv6rules"]:
            self.ipv6_edit.appendPlainText(' '.join(rule))
        
    def restore(self):
        self.ipv4_edit.clear()
        self.ipv6_edit.clear()
        with open('%s/firewall_default.json' %ROOTDIR, 'r') as fload:
            self.firewall_dict = json.load(fload)
        self.displayRules()
        
    def saveRules(self):
        new_ipv4_rules = []
        new_ipv6_rules = []
        
        for line in self.ipv4_edit.toPlainText().split("\n"):
                new_ipv4_rules.append(shlex.split(line))
        for line in self.ipv6_edit.toPlainText().split("\n"):
                new_ipv6_rules.append(shlex.split(line))

        self.firewall_dict["ipv4rules"] = new_ipv4_rules
        self.firewall_dict["ipv6rules"] = new_ipv6_rules

        with open ("%s/firewall_temp.json" % DIRECTORY, "w") as firedump:
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
        self.app_lbl = QtWidgets.QLabel(Form)
        self.verticalLayout.addWidget(self.app_lbl)
        self.app_list_widget = QtWidgets.QListWidget(Form)
        self.verticalLayout.addWidget(self.app_list_widget)
        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        Form.setWindowTitle(_translate("Form", "Choose an application", None))
        self.app_lbl.setText(_translate("Form", "Applications installed on your system:", None))
    
    def get_desktop_files(self):
        self.app_list = []
        directories = ["%s/.local/share/applications" % (os.path.expanduser("~")),
                       "/usr/share/applications",
                       "/usr/local/share/applications"
                       ]
        
        try:
            for d in directories:
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
                                self.app_list.append((name, icon, desktop_file))
                        except KeyError:
                            name = c["Desktop Entry"]["Name"]
                            icon = c["Desktop Entry"]["Icon"]
                            self.app_list.append((name, icon, desktop_file))
        except:
            pass
        
        self.app_list = sorted(self.app_list)
        self.popAppList()
        
    def popAppList(self):
        self.app_list_widget.clear()
        for entry in self.app_list:
            item = QtWidgets.QListWidgetItem()
            self.app_list_widget.addItem(item)
            item.setText(entry[0])
            item.setIcon(QtGui.QIcon.fromTheme(entry[1]))
        self.app_list_widget.itemClicked.connect(self.chosen)
            
    def chosen(self):
        self.app_chosen.emit(self.app_list[self.app_list_widget.currentRow()])
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
        self.loadConfig()
    
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(419, 480)
        self.verticalLayout = QtWidgets.QVBoxLayout(Dialog)
        self.verticalLayout.setObjectName("verticalLayout")
        self.nameLabel = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.nameLabel.setFont(font)
        self.nameLabel.setObjectName("nameLabel")
        self.verticalLayout.addWidget(self.nameLabel)
        self.nameEdit = QtWidgets.QLineEdit(Dialog)
        self.nameEdit.setObjectName("nameEdit")
        self.verticalLayout.addWidget(self.nameEdit)
        self.countryLabel = QtWidgets.QLabel(Dialog)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.countryLabel.setFont(font)
        self.countryLabel.setObjectName("countryLabel")
        self.verticalLayout.addWidget(self.countryLabel)
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
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.configLabel.setFont(font)
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
        self.changeAllBox.toggled.connect(self.blockOption)
        self.buttonBox.accepted.connect(self.acceptChange)
        self.buttonBox.rejected.connect(self.rejectChange)
        self.configBrowser.textChanged.connect(self.configChange)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Edit server"))
        self.nameLabel.setText(_translate("Dialog", "Name:"))
        self.nameEdit.setText(self.server_info["name"])
        self.countryLabel.setText(_translate("Dialog", "Country:"))
        self.countryHintLabel.setText(_translate("Dialog", "Preferably use country codes\n"
                                                 "Example: US for United States"))
        self.countryEdit.setText(self.server_info["country"])
        self.configLabel.setText(_translate("Dialog", "Edit Configuration File:"))
        self.changeAllBox.setText(_translate("Dialog", 
                                             "Apply changes to all configuration files of %s" %self.provider))
    
    def blockOption(self, state):
        if self.provider in SUPPORTED_PROVIDERS and state is False:
            self.changeAllBox.setChecked(True)
    
    def loadConfig(self):
        if self.provider in SUPPORTED_PROVIDERS:
            config = "%s/%s_config" %(ROOTDIR, self.provider)
        else:
            config = "%s/%s" %(ROOTDIR, self.server_info["path"])
            
        with open (config, "r") as config_edit:
            self.old_config = config_edit.readlines()
            for line in self.old_config:
                self.configBrowser.append(line.split("\n")[0])
                
    def configChange(self):
        self.config_change = 1
                    
    def rejectChange(self):
        self.hide()
        
    def acceptChange(self):
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
                temp_folder = "%s/temp" % DIRECTORY
                if not os.path.exists(temp_folder):
                    os.makedirs(temp_folder)
                with open("%s/%s" %(temp_folder, temp_file), "w") as update_config:
                    update_config.writelines(new_config)
            else:
                new_config = []
                
        if self.changeAllBox.isChecked() == True:
            change_all = 1
            
        change_dict = {"info_update" : self.server_info, "key" : self.key, "config_change" : new_config, 
                       "index" : remote_index, "apply_all" : change_all} 
        self.modified.emit(change_dict)
        self.hide()
                        
def main():
    if not os.path.exists("%s/.qomui" % (os.path.expanduser("~"))):
        os.makedirs("%s/.qomui" % (os.path.expanduser("~")))
    app = QtWidgets.QApplication(sys.argv)
    DBusQtMainLoop(set_as_default=True)
    ex = QomuiGui()
    ex.show()
    sys.exit(app.exec_())
    
if __name__ == '__main__':
    main()
