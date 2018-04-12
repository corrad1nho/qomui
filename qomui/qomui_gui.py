#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from PyQt5 import QtCore, QtGui, Qt, QtWidgets
import sys
import os
import json
import re
import dbus
import shutil
import time
import logging
import psutil
from dbus.mainloop.pyqt5 import DBusQtMainLoop
from subprocess import CalledProcessError, check_call
import shutil
import shlex

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

class QomuiGui(QtWidgets.QWidget):
    airvpn_server_dict = {}
    airvpn_protocol_dict = {}
    airvpn_country_list = ["All servers"]
    mullvad_server_dict = {}
    mullvad_protocol_dict = {}
    mullvad_country_list = ["All servers"]
    custom_server_dict = {}
    custom_country_list = ["All servers"]
    config_dict = {}
    fire_change = False
    hop_choice = 0
    log_count = 0
    hop_server_dict = None
    
    def __init__(self, parent = None):
        super(QomuiGui, self).__init__(parent)
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.DEBUG)
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
        self.setGeometry(QtCore.QRect(positioning.x(), positioning.y(), 450, 560))
        self.qomui_service.disconnect()
        self.qomui_service.save_default_dns()
        
        self.Load()
        self.systemtray()
        
    def hide_window(self):
        self.hide()
        
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
        self.airvpn_tab_bt = QtWidgets.QCommandLinkButton(Form)
        self.airvpn_tab_bt.setMinimumSize(QtCore.QSize(100, 0))
        self.airvpn_tab_bt.setMaximumSize(QtCore.QSize(100, 100))
        self.airvpn_tab_bt.setCheckable(True)
        self.tab_bt_group.addButton(self.airvpn_tab_bt)
        self.airvpn_tab_bt.setObjectName(_fromUtf8("airvpn_tab_bt"))
        self.verticalLayout_3.addWidget(self.airvpn_tab_bt)
        self.mullvad_tab_bt = QtWidgets.QCommandLinkButton(Form)
        self.mullvad_tab_bt.setMinimumSize(QtCore.QSize(100, 0))
        self.mullvad_tab_bt.setMaximumSize(QtCore.QSize(100, 100))
        self.mullvad_tab_bt.setCheckable(True)
        self.tab_bt_group.addButton(self.mullvad_tab_bt)
        self.mullvad_tab_bt.setObjectName(_fromUtf8("mullvad_tab_bt"))
        self.verticalLayout_3.addWidget(self.mullvad_tab_bt)
        self.custom_tab_bt = QtWidgets.QCommandLinkButton(Form)
        self.custom_tab_bt.setMinimumSize(QtCore.QSize(100, 0))
        self.custom_tab_bt.setMaximumSize(QtCore.QSize(100, 100))
        self.custom_tab_bt.setCheckable(True)
        self.tab_bt_group.addButton(self.custom_tab_bt)
        self.custom_tab_bt.setObjectName(_fromUtf8("custom_tab_bt"))
        self.verticalLayout_3.addWidget(self.custom_tab_bt)
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
        spacerItem = QtWidgets.QSpacerItem(20, 40, QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Expanding)
        self.verticalLayout_3.addItem(spacerItem)
        self.gridLayout.addLayout(self.verticalLayout_3, 2, 0, 1, 1)
        self.tabWidget = QtWidgets.QStackedWidget(Form)
        self.tabWidget.setObjectName(_fromUtf8("tabWidget"))
        self.AirVPN_tab = QtWidgets.QWidget()
        self.AirVPN_tab.setObjectName(_fromUtf8("AirVPN_tab"))
        self.verticalLayout = QtWidgets.QVBoxLayout(self.AirVPN_tab)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName(_fromUtf8("horizontalLayout_3"))
        self.airvpn_country_box = QtWidgets.QComboBox(self.AirVPN_tab)
        self.airvpn_country_box.setObjectName(_fromUtf8("airvpn_country_box"))
        self.horizontalLayout_3.addWidget(self.airvpn_country_box)
        self.airvpn_mode_box = QtWidgets.QComboBox(self.AirVPN_tab)
        self.airvpn_mode_box.setObjectName(_fromUtf8("airvpn_mode_box"))
        self.horizontalLayout_3.addWidget(self.airvpn_mode_box)
        self.verticalLayout.addLayout(self.horizontalLayout_3)
        self.airvpn_server_list = QtWidgets.QListWidget(self.AirVPN_tab)
        self.airvpn_server_list.setObjectName(_fromUtf8("airvpn_server_list"))
        self.verticalLayout.addWidget(self.airvpn_server_list)
        self.airvpn_hop_widget = HopSelect(self.AirVPN_tab)
        self.airvpn_hop_widget.setVisible(False)
        self.verticalLayout.addWidget(self.airvpn_hop_widget)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        spacerItem1 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem1)
        self.airvpn_update_bt = QtWidgets.QPushButton(self.AirVPN_tab)
        self.airvpn_update_bt.setObjectName(_fromUtf8("airvpn_update_bt"))
        self.horizontalLayout.addWidget(self.airvpn_update_bt)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.tabWidget.addWidget(self.AirVPN_tab)
        self.Mullvad_tab = QtWidgets.QWidget()
        self.Mullvad_tab.setObjectName(_fromUtf8("Mullvad_tab"))
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.Mullvad_tab)
        self.verticalLayout_2.setObjectName(_fromUtf8("verticalLayout_2"))
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName(_fromUtf8("horizontalLayout_4"))
        self.mullvad_country_box = QtWidgets.QComboBox(self.Mullvad_tab)
        self.mullvad_country_box.setObjectName(_fromUtf8("mullvad_country_box"))
        self.horizontalLayout_4.addWidget(self.mullvad_country_box)
        self.mullvad_mode_box = QtWidgets.QComboBox(self.Mullvad_tab)
        self.mullvad_mode_box.setObjectName(_fromUtf8("mullvad_mode_box"))
        self.horizontalLayout_4.addWidget(self.mullvad_mode_box)
        self.verticalLayout_2.addLayout(self.horizontalLayout_4)
        self.mullvad_server_list = QtWidgets.QListWidget(self.Mullvad_tab)
        self.mullvad_server_list.setObjectName(_fromUtf8("mullvad_server_list"))
        self.verticalLayout_2.addWidget(self.mullvad_server_list)
        self.mullvad_hop_widget = HopSelect(self.Mullvad_tab)
        self.mullvad_hop_widget.setVisible(False)
        self.verticalLayout_2.addWidget(self.mullvad_hop_widget)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName(_fromUtf8("horizontalLayout_2"))
        spacerItem2 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem2)
        self.mullvad_update_bt = QtWidgets.QPushButton(self.Mullvad_tab)
        self.mullvad_update_bt.setObjectName(_fromUtf8("mullvad_update_bt"))
        self.horizontalLayout_2.addWidget(self.mullvad_update_bt)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)
        self.tabWidget.addWidget(self.Mullvad_tab)
        self.custom_tab = QtWidgets.QWidget()
        self.custom_tab.setObjectName(_fromUtf8("custom_tab"))
        self.verticalLayout_4 = QtWidgets.QVBoxLayout(self.custom_tab)
        self.verticalLayout_4.setObjectName(_fromUtf8("verticalLayout_4"))
        self.custom_country_box = QtWidgets.QComboBox(self.Mullvad_tab)
        self.custom_country_box.setObjectName(_fromUtf8("custom_country_box"))
        self.verticalLayout_4.addWidget(self.custom_country_box)
        self.custom_server_list = QtWidgets.QListWidget(self.custom_tab)
        self.custom_server_list.setObjectName(_fromUtf8("custom_server_list"))
        self.custom_server_list.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.verticalLayout_4.addWidget(self.custom_server_list)
        self.custom_hop_widget = HopSelect(self.custom_tab)
        self.custom_hop_widget.setVisible(False)
        self.verticalLayout_4.addWidget(self.custom_hop_widget)
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setObjectName(_fromUtf8("horizontalLayout_5"))
        spacerItem3 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_5.addItem(spacerItem3)
        self.add_server_bt = QtWidgets.QPushButton(self.custom_tab)
        self.add_server_bt.setObjectName(_fromUtf8("add_server_bt"))
        self.horizontalLayout_5.addWidget(self.add_server_bt)
        self.del_server_bt = QtWidgets.QPushButton(self.custom_tab)
        self.del_server_bt.setObjectName(_fromUtf8("del_server_bt"))
        self.horizontalLayout_5.addWidget(self.del_server_bt)
        self.verticalLayout_4.addLayout(self.horizontalLayout_5)
        self.tabWidget.addWidget(self.custom_tab)
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
        self.autoconnect_check = QtWidgets.QCheckBox(self.options_tab)
        self.autoconnect_check.setObjectName(_fromUtf8("autoconnect_check"))
        self.verticalLayout_5.addWidget(self.autoconnect_check)
        self.minimize_check = QtWidgets.QCheckBox(self.options_tab)
        self.minimize_check.setObjectName(_fromUtf8("minimize_check"))
        self.verticalLayout_5.addWidget(self.minimize_check)
        self.ipv6_check = QtWidgets.QCheckBox(self.options_tab)
        self.ipv6_check.setObjectName(_fromUtf8("ipv6_check"))
        self.verticalLayout_5.addWidget(self.ipv6_check)
        self.horizontalLayout_9 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_9.setObjectName(_fromUtf8("horizontalLayout_9"))
        self.firewall_check = QtWidgets.QCheckBox(self.options_tab)
        self.firewall_check.setObjectName(_fromUtf8("firewall_check"))
        self.horizontalLayout_9.addWidget(self.firewall_check)
        self.firewall_edit_bt = QtWidgets.QPushButton(self.options_tab)
        #self.firewall_edit_bt.setFlat(True)
        self.firewall_edit_bt.setObjectName(_fromUtf8("firewall_edit_bt"))
        self.horizontalLayout_9.addWidget(self.firewall_edit_bt)
        spacerItem9 = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_9.addItem(spacerItem9)
        self.verticalLayout_5.addLayout(self.horizontalLayout_9)
        self.airdns_lbl = QtWidgets.QLabel(self.options_tab)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        font.setKerning(False)
        self.airdns_lbl.setFont(font)
        self.airdns_lbl.setObjectName(_fromUtf8("airdns_lbl"))
        self.verticalLayout_5.addWidget(self.airdns_lbl)
        self.airdns_edit1 = QtWidgets.QLineEdit(self.options_tab)
        self.airdns_edit1.setObjectName(_fromUtf8("airdns_edit1"))
        self.verticalLayout_5.addWidget(self.airdns_edit1)
        self.airdns_edit2 = QtWidgets.QLineEdit(self.options_tab)
        self.airdns_edit2.setObjectName(_fromUtf8("airdns_edit2"))
        self.verticalLayout_5.addWidget(self.airdns_edit2)
        self.mulldns_lbl = QtWidgets.QLabel(self.options_tab)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.mulldns_lbl.setFont(font)
        self.mulldns_lbl.setObjectName(_fromUtf8("mulldns_lbl"))
        self.verticalLayout_5.addWidget(self.mulldns_lbl)
        self.mulldns_edit1 = QtWidgets.QLineEdit(self.options_tab)
        self.mulldns_edit1.setObjectName(_fromUtf8("mulldns_edit1"))
        self.verticalLayout_5.addWidget(self.mulldns_edit1)
        self.mulldns_edit2 = QtWidgets.QLineEdit(self.options_tab)
        self.mulldns_edit2.setObjectName(_fromUtf8("mulldns_edit2"))
        self.verticalLayout_5.addWidget(self.mulldns_edit2)
        self.customdns_lbl = QtWidgets.QLabel(self.options_tab)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        self.customdns_lbl.setFont(font)
        self.customdns_lbl.setObjectName(_fromUtf8("customdns_lbl"))
        self.verticalLayout_5.addWidget(self.customdns_lbl)
        self.customdns_edit1 = QtWidgets.QLineEdit(self.options_tab)
        self.customdns_edit1.setObjectName(_fromUtf8("customdns_1"))
        self.verticalLayout_5.addWidget(self.customdns_edit1)
        self.customdns_edit2 = QtWidgets.QLineEdit(self.options_tab)
        self.customdns_edit2.setObjectName(_fromUtf8("custom_dns2"))
        self.verticalLayout_5.addWidget(self.customdns_edit2)
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
        self.gridLayout.addWidget(self.tabWidget, 2, 1, 1, 1)        
        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

        self.airvpn_update_bt.clicked.connect(self.airvpn_update)
        self.mullvad_update_bt.clicked.connect(self.mullvad_update)
        self.add_server_bt.clicked.connect(self.add_server_file)
        self.del_server_bt.clicked.connect(self.del_server_file)
        self.airvpn_country_box.activated[str].connect(self.airvpn_countryChosen)
        self.mullvad_country_box.activated[str].connect(self.mullvad_countryChosen)
        self.custom_country_box.activated[str].connect(self.custom_countryChosen)
        self.airvpn_tab_bt.clicked.connect(self.tabswitch)
        self.mullvad_tab_bt.clicked.connect(self.tabswitch)
        self.custom_tab_bt.clicked.connect(self.tabswitch)
        self.log_tab_bt.clicked.connect(self.tabswitch)
        self.options_tab_bt.clicked.connect(self.tabswitch)
        self.apply_bt.clicked.connect(self.applyoptions)
        self.cancel_bt.clicked.connect(self.cancelOptions)
        self.default_bt.clicked.connect(self.restoreDefaults)
        self.firewall_edit_bt.clicked.connect(self.show_firewalleditor)

    def retranslateUi(self, Form):
        Form.setWindowTitle(_translate("Form", "Qomui", None))
        self.airvpn_tab_bt.setText(_translate("Form", "Airvpn", None))
        self.mullvad_tab_bt.setText(_translate("Form", "Mullvad", None))
        self.custom_tab_bt.setText(_translate("Form", "Other", None))
        self.log_tab_bt.setText(_translate("Form", "Log", None))
        self.options_tab_bt.setText(_translate("Form", "Options", None))
        self.airvpn_update_bt.setText(_translate("Form", "Update", None))
        self.airvpn_update_bt.setIcon(QtGui.QIcon.fromTheme("view-refresh"))
        self.mullvad_update_bt.setText(_translate("Form", "Update", None))
        self.mullvad_update_bt.setIcon(QtGui.QIcon.fromTheme("view-refresh"))
        self.add_server_bt.setText(_translate("Form", "Add Config File(s)", None))
        self.add_server_bt.setIcon(QtGui.QIcon.fromTheme("list-add"))
        self.del_server_bt.setText(_translate("Form", "Delete", None))
        self.del_server_bt.setIcon(QtGui.QIcon.fromTheme("edit-delete"))
        self.autoconnect_check.setText(_translate("Form", "Autoconnect on startup", None))
        self.minimize_check.setText(_translate("Form", "Start minimized", None))
        self.firewall_check.setText(_translate("Form", "Activate Firewall", None))
        self.ipv6_check.setText(_translate("Form", "Disable IPv6", None))
        self.airdns_lbl.setText(_translate("Form", "AirVPN DNS Servers", None))
        self.mulldns_lbl.setText(_translate("Form", "Mullvad DNS Servers", None))
        self.customdns_lbl.setText(_translate("Form", " DNS for other servers", None))
        self.default_bt.setText(_translate("Form", "Restore defaults", None))
        self.default_bt.setIcon(QtGui.QIcon.fromTheme("view-refresh"))
        self.apply_bt.setText(_translate("Form", "Apply", None))
        self.apply_bt.setIcon(QtGui.QIcon.fromTheme("dialog-ok"))
        self.cancel_bt.setText(_translate("Form", "Cancel", None))
        self.cancel_bt.setIcon(QtGui.QIcon.fromTheme("dialog-close"))
        self.airdns_edit1.setText(_translate("Form", "10.5.0.1", None))
        self.airdns_edit2.setText(_translate("Form", "10.4.0.1", None))
        self.mulldns_edit1.setText(_translate("Form", "10.5.0.1", None))
        self.mulldns_edit2.setText(_translate("Form", "10.4.0.1", None))
        self.customdns_edit1.setText(_translate("Form", "10.5.0.1", None))
        self.customdns_edit2.setText(_translate("Form", "10.4.0.1", None))
        self.firewall_edit_bt.setText(_translate("Form", "Edit firewall rules", None))
        self.firewall_edit_bt.setIcon(QtGui.QIcon.fromTheme("configure"))

    def tabswitch(self):
        button = self.sender().text().replace("&", "")
        if button == "Airvpn":
            self.tabWidget.setCurrentIndex(0)
        elif button == "Mullvad":
            self.tabWidget.setCurrentIndex(1)
        elif button == "Other":
            self.tabWidget.setCurrentIndex(2)
        elif button == "Log":
            self.tabWidget.setCurrentIndex(3)
            self.logText.verticalScrollBar().setValue(self.logText.verticalScrollBar().maximum())
        elif button == "Options":
            self.setOptiontab(self.config_dict)
            self.tabWidget.setCurrentIndex(4)   
    
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
        new_config_dict["airdns1"] = self.airdns_edit1.text()
        new_config_dict["airdns2"] = self.airdns_edit2.text()
        new_config_dict["mulldns1"] = self.mulldns_edit1.text()
        new_config_dict["mulldns2"] = self.mulldns_edit2.text()
        new_config_dict["customdns1"] = self.customdns_edit1.text()
        new_config_dict["customdns2"] = self.customdns_edit2.text()
        
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

        with open ('%s/config_temp.json' % (DIRECTORY), 'w') as config:
            json.dump(new_config_dict, config)

        update_cmd = ['pkexec', 'python3', '-m', 'qomui.mv_config',
                      '-d', '%s' %(DIRECTORY)]

        if self.fire_change is True:
            update_cmd.append('-f')

        try:
            update = check_call(update_cmd)
            self.logger.info("Configuration changes applied successfully")
            if self.config_dict["firewall"] != new_config_dict["firewall"] or self.fire_change is True:
                self.qomui_service.load_firewall()
            self.qomui_service.disable_ipv6(new_config_dict["ipv6_disable"])
            QtWidgets.QMessageBox.information(self,
                                            "Updated",
                                            "Configuration updated successfully",
                                            QtWidgets.QMessageBox.Ok)
            self.config_dict = new_config_dict

        except CalledProcessError as e:
            self.logger.info("Non-zero exit status: configuration changes not applied")
            QtWidgets.QMessageBox.information(self,
                                                "Authentication failure",
                                                "Configuration not updated",
                                                QtWidgets.QMessageBox.Ok)
    
    def Load(self):
        self.logger.debug("Reading configuration files from %s" %(DIRECTORY))
        try:
            with open('%s/airvpn_server.json' % (DIRECTORY), 'r') as sload:
                self.airvpn_server_dict = json.load(sload)
                for k,v in self.airvpn_server_dict.items():
                    if v["country"] not in self.airvpn_country_list:
                        self.airvpn_country_list.append(v["country"])
                        self.popAirCountryBox()
        except (FileNotFoundError,json.decoder.JSONDecodeError) as e:
            self.logger.error('%s: Could not open %s/airvpn_server.json' % (e, DIRECTORY))

        try:
            with open('%s/airvpn_protocol.json' % (DIRECTORY), 'r') as pload:
                self.airvpn_protocol_dict = json.load(pload)
                self.popAirModeBox()
        except (FileNotFoundError,json.decoder.JSONDecodeError) as e:
            self.logger.error('%s: Could not open %s/airvpn_protocol.json' % (e, DIRECTORY))

        try:
            with open('%s/mullvad_server.json' % (DIRECTORY), 'r') as sload:
                self.mullvad_server_dict = json.load(sload)
                for k,v in self.mullvad_server_dict.items():
                    if v["country"] not in self.mullvad_country_list:
                        self.mullvad_country_list.append(v["country"])
                        self.popMullvadCountryBox()
        except (FileNotFoundError,json.decoder.JSONDecodeError) as e:
            self.logger.error('%s Could not open %s/mullvad_server.json' % (e, DIRECTORY))

        try:
            with open('%s/mullvad_protocol.json' % (DIRECTORY), 'r') as pload:
                self.mullvad_protocol_dict = json.load(pload)
                self.popMullvadModeBox()
        except (FileNotFoundError,json.decoder.JSONDecodeError) as e:
            self.logger.error('%s: Could not open %s/mullvad_protocol.json' % (e, DIRECTORY))


        try:
            with open('%s/custom_server.json' % (DIRECTORY), 'r') as sload:
                self.custom_server_dict = json.load(sload)
                for k,v in self.custom_server_dict.items():
                    if v["country"] not in self.custom_country_list:
                        self.custom_country_list.append(v["country"])
                        self.popCustomCountryBox()
        except (FileNotFoundError,json.decoder.JSONDecodeError) as e:
            self.logger.error('%s: Could not open %s/custom_server.json' % (e, DIRECTORY))

        try:
            with open('%s/config.json' % (ROOTDIR), 'r') as config:
                self.config_dict = json.load(config)
                if self.config_dict["minimize"] == 0:
                    self.setWindowState(QtCore.Qt.WindowActive)
                self.setOptiontab(self.config_dict)        
        except (FileNotFoundError,json.decoder.JSONDecodeError, KeyError) as e:
            self.logger.error('%s: Could not open %s/config.json' % (e, DIRECTORY))

        try:
            with open('%s/last_server.json' % (DIRECTORY), 'r') as lserver:
                if self.config_dict["autoconnect"] == 1:
                    last_server_dict = json.load(lserver)
                    self.ovpn_dict = last_server_dict["last"]
                    self.hop_server_dict = last_server_dict["hop"]
                    if self.hop_server_dict is not None:
                        self.setHop()
                    self.connect_thread(self.ovpn_dict)             
                    
                    
                    if self.ovpn_dict["provider"] == "airvpn":
                        self.tabWidget.setCurrentIndex(0)
                        self.airvpn_tab_bt.setChecked(True)
                        country = self.ovpn_dict["country"]
                        self.airvpn_country_box.setCurrentIndex(sorted(self.airvpn_country_list).index(country))
                        self.airvpn_countryChosen(country)
                        self.airvpn_mode_box.setCurrentIndex(int(self.ovpn_dict["prot_index"]))
                    elif self.ovpn_dict["provider"] == "mullvad":
                        self.tabWidget.setCurrentIndex(1)
                        self.mullvad_tab_bt.setChecked(True)
                        country = self.ovpn_dict["country"]
                        self.mullvad_country_box.setCurrentIndex(self.mullvad_country_list.index(country))
                        self.mullvad_countryChosen(country)
                        self.mullvad_mode_box.setCurrentIndex(int(self.ovpn_dict["prot_index"]))
                    elif self.ovpn_dict["provider"] == "custom":
                        self.tabWidget.setCurrentIndex(2)
                        self.custom_tab_bt.setChecked(True)
                    
                        
        except (FileNotFoundError,json.decoder.JSONDecodeError, KeyError) as e:
            self.logger.error('Could not open %s/last_server.json' % (DIRECTORY))


    def restoreDefaults(self):
        with open('%s/default_config.json' % (ROOTDIR), 'r') as config:
                default_config_dict = json.load(config)
        self.setOptiontab(default_config_dict)
    
    def cancelOptions(self):
        self.setOptiontab(self.config_dict)
    
    def setOptiontab(self, config):
        self.airdns_edit1.setText(config["airdns1"])
        self.airdns_edit2.setText(config["airdns2"])
        self.mulldns_edit1.setText(config["mulldns1"])
        self.mulldns_edit2.setText(config["mulldns2"])
        self.customdns_edit1.setText(config["customdns1"])
        self.customdns_edit2.setText(config["customdns2"])
        
        if config["autoconnect"] == 0:
            self.autoconnect_check.setChecked(False)
        elif config["autoconnect"] == 1:
            self.autoconnect_check.setChecked(True)
            
        if config["firewall"] == 0:
            self.firewall_check.setChecked(False)
        elif config["firewall"] == 1:
            self.firewall_check.setChecked(True)
        
        if config["minimize"] == 0:
            self.minimize_check.setChecked(False)
        elif config["minimize"] == 1:
            self.minimize_check.setChecked(True)
    
    def networkstate(self, networkstate):
        if networkstate == 70 or networkstate == 60:
            self.logger.info("Detected new network connection")
            self.qomui_service.save_default_dns()
            if self.ovpn_dict is not None:
                self.connect_thread(self.ovpn_dict)     
        elif networkstate != 70 and networkstate != 60:
            self.logger.info("Lost network connection - VPN tunnel terminated")
            self.kill()

    def airvpn_update(self):
        self.Login = update.Login(self, "airvpn")
        self.qomui_service.allowUpdate("airvpn")
        self.Login.wait.connect(self.update_bar)
        self.Login.downloaded.connect(self.downloaded)
        self.Login.exec_()

    def mullvad_update(self):
        self.Login = update.Login(self, "mullvad")
        self.qomui_service.allowUpdate("mullvad")
        self.Login.wait.connect(self.update_bar)
        self.Login.downloaded.connect(self.downloaded)
        self.Login.exec_()
        
    def update_bar(self, i):
        if i[0] == "stop":
            self.WaitBar.setVisible(False)
        elif i[0] == "start":
            self.WaitBar.setVisible(True)
            self.WaitBar.setText("Updating %s" %i[1].title())

    def downloaded(self, content):
        down_msg = QtWidgets.QMessageBox.information(self,
                                                "Download successful",
                                                "List of available servers updated",
                                                QtWidgets.QMessageBox.Ok)
        provider = content["provider"]
        if provider == "airvpn":
            self.airvpn_server_dict = content["server"]
            self.airvpn_protocol_dict = content["protocol"]
            with open ("%s/airvpn_server.json" % DIRECTORY, "w") as s:
                json.dump(self.airvpn_server_dict, s)
            with open ("%s/airvpn_protocol.json" % DIRECTORY, "w") as p:
                json.dump(self.airvpn_protocol_dict, p)
            self.popAirCountryBox()
            self.popAirModeBox()
        elif provider == "mullvad":
            self.mullvad_server_dict = content["server"]
            self.mullvad_protocol_dict = content["protocol"]
            with open ("%s/mullvad_server.json" % DIRECTORY, "w") as s:
                json.dump(self.mullvad_server_dict, s)
            with open ("%s/mullvad_protocol.json" % DIRECTORY, "w") as p:
                json.dump(self.mullvad_protocol_dict, p)            
            self.popMullvadCountryBox()
            self.popMullvadModeBox()

        self.copyfiles(provider, content["path"])   

    def add_server_file(self):
        self.AuthEdit = update.AuthEdit(self)
        self.AuthEdit.auth.connect(self.modify_config_file)
        self.AuthEdit.exec_()
        
        
    def modify_config_file(self, credentials):
        if not os.path.exists("%s/temp" % (DIRECTORY)):
               os.makedirs("%s/temp" % (DIRECTORY))
               
        with open("%s/temp/auth.txt" % (DIRECTORY) , "w") as passfile:
            passfile.write('%s\n%s' % (credentials[0], credentials[1]))
        
        try:
            ovpn_files = QtWidgets.QFileDialog.getOpenFileNames(self,
                                                         caption="Choose OVPN-File",
                                                         directory = os.path.expanduser("~"),
                                                         filter=self.tr('OpenVPN (*.ovpn *conf);;All files (*.*)'),
                                                         options=QtWidgets.QFileDialog.ReadOnly)
        except TypeError:
            pass
        
        self.qomui_service.allow_dns()
        try:
            files = ovpn_files[0]
            self.WaitBar.setVisible(True)
            self.WaitBar.setText("Adding Servers")
            self.thread = update.AddThread(self.qomui_service, files, credentials[0], credentials[1])
            self.thread.copyauth.connect(self.copy_auth_file)
            self.thread.added.connect(self.update_custom_servers)
            self.thread.start()
        except IndexError:
            pass
    
    def update_custom_servers(self, servers):
        self.custom_server_dict.update(servers)
        self.qomui_service.block_dns()
        with open ("%s/custom_server.json" % DIRECTORY, "w") as s:
            json.dump(self.custom_server_dict, s) 
        self.popCustomCountryBox()
        shutil.rmtree("%s/temp/" % (DIRECTORY))
        self.WaitBar.setVisible(False)
        
    def copy_auth_file(self, auth_file):
        copy = self.qomui_service.copyCerts("custom", "%s/temp/auth.txt %s" %(DIRECTORY, auth_file))
    
    def del_server_file(self):
        for item in self.custom_server_list.selectedItems():
            data = item.data(QtCore.Qt.UserRole)
            delete_file = self.custom_server_dict[data]["path"]
            try:
                os.remove(delete_file)
            except FileNotFoundError:
                pass
            try:
                self.custom_server_dict.pop(data, None)
                self.custom_server_list.removeItemWidget(item)
            except KeyError:
                pass
        with open ("%s/custom_server.json" % DIRECTORY, "w") as s:
            json.dump(self.custom_server_dict, s)
        self.popCustomCountryBox()

    def pop_custom_ServerList(self, country):
        self.custom_server_list.clear()
        if not self.custom_server_dict:
            empty_item = QtWidgets.QListWidgetItem(self.custom_server_list)
            empty_item.setText("No servers defined yet")
            empty_item2 = QtWidgets.QListWidgetItem(self.custom_server_list)
            empty_item2.setText("Please add servers via Add or Update")
            self.custom_server_list.addItem(empty_item)
            self.custom_server_list.addItem(empty_item2)
        else:
            for key, val in self.custom_server_dict.items():
                if val["country"] == country or country == "All servers":
                    self.Item = ServerWidget()
                    self.ListItem = QtWidgets.QListWidgetItem(self.custom_server_list)
                    self.ListItem.setData(QtCore.Qt.UserRole, key)
                    self.ListItem.setSizeHint(QtCore.QSize(100, 50))
                    self.Item.setText(val["name"], val["provider"], val["country"], None)
                    self.custom_server_list.addItem(self.ListItem)
                    self.custom_server_list.setItemWidget(self.ListItem, self.Item)
                    self.Item.establish.connect(self.establish)
                    self.Item.establish_hop.connect(self.createHop)
                
    def popCustomCountryBox(self):
        for k,v in self.custom_server_dict.items():
            if v["country"] not in self.custom_country_list:
                self.custom_country_list.append(v["country"])
        self.custom_country_box.clear()
        for index, country in enumerate(sorted(self.custom_country_list)):
            #icon = QtGui.QIcon('%s/flags/%s.png' % (ROOTDIR, country))
            self.custom_country_box.addItem(country)
            self.custom_country_box.setItemText(index, country)
            #self.custom_country_box.setItemIcon(index, QtGui.QIcon(icon))
        self.custom_countryChosen()
        
    def custom_countryChosen(self, *arg):
        if not arg:
            custom_country = self.custom_country_box.currentText()
        else:
            custom_country = arg[0]
        self.pop_custom_ServerList(custom_country)
        
    def copyfiles(self, provider, path):
        self.qomui_service.block_dns()
        if provider == "airvpn":
            copy = self.qomui_service.copyCerts(provider, path)
        elif provider == "mullvad":
            copy = self.qomui_service.copyCerts(provider, path)
        if copy == "copied":
            shutil.rmtree("%s/temp/" % (DIRECTORY))

    def popMullvadCountryBox(self):
        for k,v in self.mullvad_server_dict.items():
            if v["country"] not in self.mullvad_country_list:
                self.mullvad_country_list.append(v["country"])
        self.mullvad_country_box.clear()
        for index, country in enumerate(sorted(self.mullvad_country_list)):
            #BAD MEMORY LEAK -- TRIPLES MEMORY USAGE!!!!!!
            #icon = QtGui.QIcon('%s/flags/%s.png' % (ROOTDIR, country))
            self.mullvad_country_box.addItem(country)
            self.mullvad_country_box.setItemText(index, country)
            #self.mullvad_country_box.setItemIcon(index, QtGui.QIcon(icon))
        self.mullvad_countryChosen()

    def popMullvadModeBox(self):
        self.mullvad_mode_box.clear()
        index = -1
        for k, v in sorted(self.mullvad_protocol_dict.items()):
            index += 1
            mode = v["protocol"] + " " + v["port"]
            self.mullvad_mode_box.addItem(mode)
            self.mullvad_mode_box.setItemText(index, mode)
            self.mullvad_mode_box.setItemData(index, k, QtCore.Qt.UserRole)
    
    
    def popAirCountryBox(self):
        for k,v in self.airvpn_server_dict.items():
            if v["country"] not in self.airvpn_country_list:
                self.airvpn_country_list.append(v["country"])
                
        self.airvpn_country_box.clear()
        for index, country in enumerate(sorted(self.airvpn_country_list)):
            #icon = QtGui.QIcon('%s/flags/%s.png' % (ROOTDIR, country))
            self.airvpn_country_box.addItem(country)
            self.airvpn_country_box.setItemText(index, country)
            #self.airvpn_country_box.setItemIcon(index, QtGui.QIcon(icon))
        self.airvpn_countryChosen()
                
    def popAirModeBox(self):
        self.airvpn_mode_box.clear()
        index = -1
        for k, v in sorted(self.airvpn_protocol_dict.items()):
            index += 1
            mode = v["protocol"] + " " + v["port"] + ", " + v["ip"]
            self.airvpn_mode_box.addItem(mode)
            self.airvpn_mode_box.setItemText(index, mode)
            self.airvpn_mode_box.setItemData(index, k, QtCore.Qt.UserRole)

    def mullvad_countryChosen(self, *arg):
        if not arg:
            mullvad_country = self.mullvad_country_box.currentText()
        else:
            mullvad_country = arg[0]
        self.pop_mullvad_ServerList(mullvad_country)
        
    def airvpn_countryChosen(self, *arg):
        if not arg:
            airvpn_country = self.airvpn_country_box.currentText()
        else:
            airvpn_country = arg[0]
        airvpn_country = self.airvpn_country_box.currentText()
        self.pop_airvpn_ServerList(airvpn_country)
    
    def pop_airvpn_ServerList(self, country):
        self.airvpn_server_list.clear()
        for key, val in self.airvpn_server_dict.items():
            if val["country"] == country or country == "All servers":
                self.Item = ServerWidget()
                self.ListItem = QtWidgets.QListWidgetItem(self.airvpn_server_list)
                self.ListItem.setSizeHint(QtCore.QSize(100, 50))
                self.Item.setText(val["name"], val["provider"], val["country"], val["city"])
                self.airvpn_server_list.addItem(self.ListItem)
                self.airvpn_server_list.setItemWidget(self.ListItem, self.Item)
                self.Item.establish.connect(self.establish)
                self.Item.establish_hop.connect(self.createHop)

    def pop_mullvad_ServerList(self, country):
        self.mullvad_server_list.clear()
        for key, val in self.mullvad_server_dict.items():
            if val["country"] == country or country == "All servers":
                self.Item = ServerWidget()
                self.ListItem = QtWidgets.QListWidgetItem(self.mullvad_server_list)
                self.ListItem.setSizeHint(QtCore.QSize(100, 50))
                self.Item.setText(val["name"], val["provider"], val["country"], val["city"])
                self.mullvad_server_list.addItem(self.ListItem)
                self.mullvad_server_list.setItemWidget(self.ListItem, self.Item)
                self.Item.establish.connect(self.establish)
                self.Item.establish_hop.connect(self.createHop)
                
    def createHop(self, server):
        current_dict = getattr(self, "%s_server_dict"%(server[0]))[server[1]]
        self.create_server_dict(current_dict, 1)
        self.setHop()
        
    def setHop(self):
        self.hop_choice = 2
        self.hop_server_dict.update({"hop":"1"})
        self.airvpn_hop_widget.setVisible(True)
        self.airvpn_hop_widget.setText(self.hop_server_dict)
        self.mullvad_hop_widget.setVisible(True)
        self.mullvad_hop_widget.setText(self.hop_server_dict)
        self.custom_hop_widget.setVisible(True)
        self.custom_hop_widget.setText(self.hop_server_dict)
        self.custom_hop_widget.clear.connect(self.clear_HopSelect)
        self.airvpn_hop_widget.clear.connect(self.clear_HopSelect)
        self.mullvad_hop_widget.clear.connect(self.clear_HopSelect)
        self.qomui_service.hopConnect(self.hop_server_dict)
        
    def clear_HopSelect(self):
        self.hop_choice = 0
        self.hop_server_dict = None
        self.airvpn_hop_widget.setVisible(False)
        self.mullvad_hop_widget.setVisible(False)
        self.custom_hop_widget.setVisible(False)
        index = self.tabWidget.currentIndex()
        if index == 0:
            self.airvpn_countryChosen()
        elif index == 1:
            self.mullvad_countryChosen()
        elif index == 2:
            self.custom_countryChosen()
        
    
    def establish(self, server):
        current_dict = getattr(self, "%s_server_dict"%(server[0]))[server[1]]
        QtWidgets.QApplication.restoreOverrideCursor()
        self.kill()
        self.create_server_dict(current_dict, 0)
        
        if self.hop_choice == 2 and self.hop_server_dict is not None:
            self.ovpn_dict.update({"hop":"2"})
        else:
            self.ovpn_dict.update({"hop":"0"})
        self.connect_thread(self.ovpn_dict)
        
    def create_server_dict(self, current_dict, h):
        provider = current_dict["provider"]
        
        if provider == "airvpn":
            prot_index = self.airvpn_mode_box.currentIndex()
            mode = self.airvpn_mode_box.itemData(prot_index, QtCore.Qt.UserRole)
            port = self.airvpn_protocol_dict[mode]["port"]
            protocol = self.airvpn_protocol_dict[mode]["protocol"]

            if self.airvpn_protocol_dict[mode]["ip"] == "Primary":
                ip = current_dict["prim_ip"]
            
            elif self.airvpn_protocol_dict[mode]["ip"] == "Alternative":
                ip = current_dict["alt_ip"]
            current_dict.update({"ip" : ip, "port": port, "protocol": protocol, "prot_index": str(prot_index)})
            
        elif provider == "mullvad":
            prot_index = self.mullvad_mode_box.currentIndex()
            mode = self.mullvad_mode_box.itemData(prot_index, QtCore.Qt.UserRole)
            port = self.mullvad_protocol_dict[mode]["port"]
            protocol = self.mullvad_protocol_dict[mode]["protocol"]
            current_dict.update({"port": port, "protocol": protocol, "prot_index": str(prot_index)})
        
        elif provider == "custom":
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
            self.failmsg = QtWidgets.QMessageBox(self)
            self.failmsg.setIcon(QtWidgets.QMessageBox.Critical)
            self.failmsg.setText("Connection attempt failed")
            self.failmsg.setInformativeText("Application was unable to connect to server\nSee log for further information")
            self.failmsg.setWindowModality(QtCore.Qt.WindowModal)
            self.failmsg.show()
            QtWidgets.QApplication.restoreOverrideCursor()
    
        elif reply == "fail2":
            self.kill()
            self.failmsg = QtWidgets.QMessageBox(self)
            self.failmsg.setIcon(QtWidgets.QMessageBox.Critical)
            self.failmsg.setText("Connection attempt failed")
            self.failmsg.setInformativeText("Authentication error while trying to connect\nMaybe your account is expired or connection limit is exceeded")
            self.failmsg.setWindowModality(QtCore.Qt.WindowModal)
            self.failmsg.show()
            QtWidgets.QApplication.restoreOverrideCursor()
            
        elif reply == "kill":
            self.tray.setIcon(QtGui.QIcon("%s/qomui.png" % (ROOTDIR)))
            QtWidgets.QApplication.restoreOverrideCursor()
            self.ActiveWidget.setVisible(False)
            
    def activeWidget(self, current_server, hop_dict):
        tun = self.qomui_service.return_tun_device()
        self.ActiveWidget.setText(current_server, hop_dict, tun)
        self.ActiveWidget.setVisible(True)
        self.ActiveWidget.disconnect.connect(self.kill)
        self.gridLayout.addWidget(self.ActiveWidget, 0, 0, 1, 3)
        pop_list = getattr(self, 'pop_%s_ServerList' %(current_server["provider"]))
        try:
            pop_list(current_server["country"])
        except KeyError:
            pop_list()

    def kill(self):
        self.WaitBar.setVisible(False)
        self.ActiveWidget.setVisible(False)
        self.tray.setIcon(QtGui.QIcon("%s/qomui.png" % (ROOTDIR)))
        self.qomui_service.disconnect()

    def connect_thread(self, server_dict):
        QtWidgets.QApplication.setOverrideCursor(QtGui.QCursor(QtCore.Qt.WaitCursor))
        self.logger.info("Connecting to %s...." %server_dict["name"])
        self.WaitBar.setText("Connecting to %s" %server_dict["name"])
        self.WaitBar.setVisible(True)
        self.log_count = 0
        provider = server_dict["provider"]
        if provider == "airvpn":
            self.qomui_service.update_dns(self.config_dict["airdns1"], self.config_dict["airdns2"])
        elif provider == "mullvad":
            self.qomui_service.update_dns(self.config_dict["mulldns1"], self.config_dict["mulldns2"])
        elif provider == "custom":
            self.qomui_service.update_dns(self.config_dict["customdns1"], self.config_dict["customdns2"])
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
            
     
class ServerWidget(QtWidgets.QWidget):
    establish = QtCore.pyqtSignal(tuple)
    establish_hop = QtCore.pyqtSignal(tuple)
    
    def __init__ (self, parent=None):
        super(ServerWidget, self).__init__(parent)
        self.setMouseTracking(True)
        self.setupUi(self)
            
    def setupUi(self, Form):
        Form.setObjectName(_fromUtf8("Form"))
        Form.resize(100, 100)
        self.horizontalLayout = QtWidgets.QHBoxLayout(Form)
        self.horizontalLayout.setObjectName(_fromUtf8("horizontalLayout"))
        self.country_lbl = QtWidgets.QLabel(Form)
        self.country_lbl.setMinimumSize(QtCore.QSize(30, 30))
        self.country_lbl.setMaximumSize(QtCore.QSize(30, 30))
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
        self.hop_bt = QtWidgets.QPushButton(Form)
        self.hop_bt.setVisible(False)
        self.hop_bt.setObjectName(_fromUtf8("hop_bt"))
        self.horizontalLayout.addWidget(self.hop_bt)
        self.connect_bt = QtWidgets.QPushButton(Form)
        self.connect_bt.setVisible(False)
        self.connect_bt.setObjectName(_fromUtf8("connect_bt"))
        self.horizontalLayout.addWidget(self.connect_bt)
        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)
        self.connect_bt.clicked.connect(self.signal)
        self.hop_bt.clicked.connect(self.hop_signal)

    def retranslateUi(self, Form):
        Form.setWindowTitle(_translate("Form", "Form", None))
        
    def setText(self, name, provider, country, city, button = "connect"):
        self.name = name
        self.provider = provider
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
        if self.provider == "airvpn" or self.provider == "mullvad" or button == "disconnect":
            font.setPointSize(12)
        self.name_lbl.setFont(font)
        self.name_lbl.setText(self.name)
        self.city_lbl.setText(city)
        self.country_lbl.setPixmap(QtGui.QPixmap('%s/flags/%s.png' % (ROOTDIR, country)).scaled(25, 25, transformMode=QtCore.Qt.SmoothTransformation))
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

    def leaveEvent(self, event):
        try:
            self.connect_bt.setVisible(False)
        except AttributeError:
            pass
        try:
            self.hop_bt.setVisible(False)
        except AttributeError:
            pass

    def signal(self):
        self.establish.emit((self.provider, self.name))
    
    def hop_signal(self):
        self.establish_hop.emit((self.provider, self.name))


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
        self.hop_label.setText(_translate("Form", "Current selection for hop server:", None))
        
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
        self.Pinglabel = QtWidgets.QLabel(ConnectionWidget)
        font = QtGui.QFont()
        font.setBold(True)
        font.setWeight(75)
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
        self.down_lbl.setText(_translate("ConnectionWidget", "Download:", None))
        self.up_lbl.setText(_translate("ConnectionWidget", "Upload:", None))

    def setText(self, server_dict, hop_dict, tun):
        self.tun = tun
        if hop_dict is not None:
            self.status_label.setText(_translate("ConnectionWidget", 
                                                 "Active Connection - Double Hop", None))
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
            self.status_label.setText(_translate("ConnectionWidget", "Active Connection", None))
        
        try:
            city = server_dict["city"]
        except KeyError:
            city = None
        self.ServerWidget.setText(server_dict["name"], server_dict["provider"],
                               server_dict["country"], city, button="disconnect")
        
        self.ServerWidget.removeButton(0)
            
        self.calc_Thread = NetMon(self.tun)
        self.calc_Thread.stat.connect(self.statcount)
        self.calc_Thread.start()
        
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
    
    def __init__(self, tun):
        QtCore.QThread.__init__(self)
        self.tun = tun
        
    def run(self):
        t0 = time.time()
        counter = psutil.net_io_counters(pernic=True)['tun0']
        stat = (counter.bytes_recv, counter.bytes_sent)
        accum = (0, 0)
 
        while True:
            last_stat = stat
            time.sleep(1)
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
