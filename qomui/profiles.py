#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from PyQt5 import QtCore, QtWidgets, QtGui

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

class ComboCheckBox(QtWidgets.QComboBox):

    def __init__ (self, parent=None):
        super(ComboCheckBox, self).__init__(parent)
        self.view().pressed.connect(self.itemPressed)
        self.setModel(QtGui.QStandardItemModel(self))

    def itemPressed(self, index):
        item = self.model().itemFromIndex(index)
        if item.checkState == QtCore.Qt.Checked:
            item.setCheckState(QtCore.Qt.Unchecked)
        else:
            item.setCheckState(QtCore.Qt.Checked)

class EditProfile(QtWidgets.QDialog):
    save_profile = QtCore.pyqtSignal(dict)
    providers_selected = []
    countries_selected = []

    def __init__ (self, protocols=None, countries=None, providers=None, selected=0, parent=None):
        super(EditProfile, self).__init__(parent)
        self.protocols = protocols
        self.countries = countries
        self.providers = providers
        print(self.providers)
        print(self.countries)
        self.selected = selected
        self.setupUi(self)
        self.popBoxes()

    def setupUi(self, profileEdit):
        profileEdit.setObjectName("profileEdit")
        profileEdit.resize(439, 500)
        self.verticalLayout = QtWidgets.QVBoxLayout(profileEdit)
        self.verticalLayout.setObjectName("verticalLayout")
        self.profileLine = QtWidgets.QLineEdit(profileEdit)
        self.profileLine.setObjectName("profileLine")
        self.verticalLayout.addWidget(self.profileLine)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.chooseProtocolBox = QtWidgets.QComboBox(profileEdit)
        self.chooseProtocolBox.setObjectName("chooseProtocolBox")
        self.horizontalLayout_2.addWidget(self.chooseProtocolBox)
        self.modeBox = QtWidgets.QComboBox(profileEdit)
        self.modeBox.setObjectName("modeBox")
        self.horizontalLayout_2.addWidget(self.modeBox)
        self.verticalLayout.addLayout(self.horizontalLayout_2)
        self.choiceTable = QtWidgets.QTableWidget(profileEdit)
        self.choiceTable.setObjectName("choiceTable")
        self.choiceTable.setShowGrid(False)
        self.choiceTable.horizontalHeader().hide()
        self.choiceTable.verticalHeader().hide()
        self.verticalLayout.addWidget(self.choiceTable)
        self.filterLine = QtWidgets.QLineEdit(profileEdit)
        self.verticalLayout.addWidget(self.filterLine)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        spacerItem = QtWidgets.QSpacerItem(595, 17, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout.addItem(spacerItem)
        self.buttonBox = QtWidgets.QDialogButtonBox(profileEdit)
        self.buttonBox.setStandardButtons(QtWidgets.QDialogButtonBox.Cancel|QtWidgets.QDialogButtonBox.Ok)
        self.buttonBox.setObjectName("buttonBox")
        self.horizontalLayout.addWidget(self.buttonBox)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.retranslateUi(profileEdit)
        QtCore.QMetaObject.connectSlotsByName(profileEdit)

        self.choiceTable.itemChanged.connect(self.itemChanged)
        self.buttonBox.accepted.connect(self.confirm)
        self.buttonBox.rejected.connect(self.cancel)

    def retranslateUi(self, profileEdit):
        _translate = QtCore.QCoreApplication.translate
        profileEdit.setWindowTitle(_translate("profileEdit", "Edit profile"))
        self.profileLine.setPlaceholderText(_translate("profileEdit", "Enter profile name"))
        self.filterLine.setPlaceholderText("Enter keywords to filter server names: k1;k2;k3...")

    def popBoxes(self):
        for prot in self.protocols:
            self.chooseProtocolBox.addItem(prot)

        self.modeBox.addItem("Random")
        self.modeBox.addItem("Fastest")

        if self.selected != 0:
            self.countries_selected = self.selected["countries"]
            self.providers_selected = self.selected["providers"]
            self.modeBox.setCurrentText(self.selected["mode"])
            self.chooseProtocolBox.setCurrentText(self.selected["protocol"])
            self.profileLine.setText(self.selected["name"])
            if self.selected["filters"]:
                self.filterLine.setText(";".join(self.selected["filters"]))


        self.popchoiceTable()

    def popchoiceTable(self):
        self.choiceTable.clear()
        width = self.choiceTable.width()
        n = len(self.countries)-1
        cols = int(width / 120)
        if cols == 0:
            cols = 1
        rows = int(n / cols) + (n % cols> 0)
        np = len(self.providers)
        rows = rows + int(np / cols) + (np % cols> 0) +2
        self.choiceTable.setRowCount(rows)
        self.choiceTable.setColumnCount(cols)
        self.choiceTable.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.Stretch)
        r = 0
        c = 0
        item = QtWidgets.QTableWidgetItem()
        font = QtGui.QFont()
        font.setBold(True)
        item.setFont(font)
        item.setText("Choose providers:")
        self.choiceTable.setSpan(0,0,1,cols)
        self.choiceTable.setItem(0,0,item)
        r+=1
        for provider in self.providers:
            item = QtWidgets.QTableWidgetItem()
            item.setText(provider)
            item.setData(QtCore.Qt.UserRole, "providers")
            item.setFlags(item.flags() | QtCore.Qt.ItemIsUserCheckable)
            if provider in self.providers_selected:
                item.setCheckState(QtCore.Qt.Checked)
            else:
                item.setCheckState(QtCore.Qt.Unchecked)
            self.choiceTable.setSpan(r,c,1,1)
            self.choiceTable.setItem(r,c,item)
            if c == cols:
                r += 1
                c = 0
            else:
                c += 1

        c = 0
        r+=1
        item = QtWidgets.QTableWidgetItem()
        item.setFont(font)
        item.setText("Choose countries:")
        self.choiceTable.setSpan(r,0,1,cols)
        self.choiceTable.setItem(r,0,item)
        r+=1
        for country in self.countries:
            item = QtWidgets.QTableWidgetItem()
            item.setText(country)
            item.setData(QtCore.Qt.UserRole, "countries")
            item.setFlags(item.flags() | QtCore.Qt.ItemIsUserCheckable)
            if country in self.countries_selected:
                item.setCheckState(QtCore.Qt.Checked)
            else:
                item.setCheckState(QtCore.Qt.Unchecked)
            self.choiceTable.setSpan(r,c,1,1)
            self.choiceTable.setItem(r,c,item)
            if c == cols:
                r += 1
                c = 0
            else:
                c += 1

    def resizeEvent(self, event):
        self.popchoiceTable()

    def itemChanged(self, item):
        try:
            cat = item.data(QtCore.Qt.UserRole)
            txt = item.text()

            if item.checkState() == 2:
                if txt not in getattr(self, "{}_selected".format(cat)):
                    getattr(self, "{}_selected".format(cat)).append(txt)
            elif item.checkState() == 0:
                getattr(self, "{}_selected".format(cat)).remove(txt)

        except (TypeError, ValueError, AttributeError):
            pass

    def confirm(self):
        profile_dict = {}
        profile_dict["name"] = self.profileLine.text()
        profile_dict["providers"] = sorted(self.providers_selected)
        profile_dict["countries"] = sorted(self.countries_selected)
        profile_dict["mode"] = self.modeBox.currentText()
        profile_dict["protocol"] = self.chooseProtocolBox.currentText()
        profile_dict["filters"] = self.filterLine.text().split(";")[:-1]

        if self.selected != 0:
             profile_dict["number"] = self.selected["number"]

        if profile_dict["name"] == "" or len(self.providers_selected) == 0 or len(self.countries_selected) == 0:
            err = QtWidgets.QMessageBox.warning(
                self,
                "Profile incomplete",
                "Set a profile name & select at least one country and provider",
                QtWidgets.QMessageBox.Ok
                )
        else:
            self.save_profile.emit(profile_dict)
            self.hide()

    def cancel(self):
        self.hide()

class ProfileWidget(QtWidgets.QWidget):
    del_profile = QtCore.pyqtSignal(str)
    edit_profile = QtCore.pyqtSignal(str)
    connect_profile = QtCore.pyqtSignal(str)

    def __init__ (self, profile, parent=None):
        super(ProfileWidget, self).__init__(parent)
        self.profile = profile
        self.setupUi(self)

    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(610, 465)
        self.verticalLayout = QtWidgets.QVBoxLayout(Form)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.profileName = QtWidgets.QLabel(Form)
        font = QtGui.QFont()
        font.setPointSize(11)
        font.setBold(True)
        font.setWeight(75)
        self.profileName.setFont(font)
        self.profileName.setObjectName("profileName")
        self.horizontalLayout_2.addWidget(self.profileName)
        spacerItem = QtWidgets.QSpacerItem(40, 20, QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Minimum)
        self.horizontalLayout_2.addItem(spacerItem)
        self.editProfBt = QtWidgets.QPushButton(Form)
        self.editProfBt.setObjectName("editProfBt")
        self.horizontalLayout_2.addWidget(self.editProfBt)
        self.delProfBt = QtWidgets.QPushButton(Form)
        self.delProfBt.setObjectName("delProfBt")
        self.horizontalLayout_2.addWidget(self.delProfBt)
        self.connProfileBt = QtWidgets.QPushButton(Form)
        self.connProfileBt.setObjectName("connProfileBt")
        self.horizontalLayout_2.addWidget(self.connProfileBt)
        self.verticalLayout.addLayout(self.horizontalLayout_2)

        self.modeLabel = QtWidgets.QLabel(Form)
        self.modeLabel.setObjectName("modeLabel")
        self.modeLabel.setWordWrap(True)
        self.modeLabel.setIndent(20)
        self.verticalLayout.addWidget(self.modeLabel)

        self.protocolLabel = QtWidgets.QLabel(Form)
        self.protocolLabel.setObjectName("protocolLabel")
        self.protocolLabel.setWordWrap(True)
        self.protocolLabel.setIndent(20)
        self.verticalLayout.addWidget(self.protocolLabel)

        self.providerLabel = QtWidgets.QLabel(Form)
        self.providerLabel.setObjectName("providerLabel")
        self.providerLabel.setWordWrap(True)
        self.providerLabel.setIndent(20)
        self.verticalLayout.addWidget(self.providerLabel)

        self.countryLabel = QtWidgets.QLabel(Form)
        self.countryLabel.setObjectName("countryLabel")
        self.countryLabel.setWordWrap(True)
        self.countryLabel.setIndent(20)
        self.verticalLayout.addWidget(self.countryLabel)

        self.filterLabel = QtWidgets.QLabel(Form)
        self.filterLabel.setObjectName("filterLabel")
        self.filterLabel.setWordWrap(True)
        self.filterLabel.setIndent(20)
        self.verticalLayout.addWidget(self.filterLabel)

        spacerItem = QtWidgets.QSpacerItem(0, 0,
                                            QtWidgets.QSizePolicy.Minimum,
                                            QtWidgets.QSizePolicy.MinimumExpanding
                                            )
        self.verticalLayout.addItem(spacerItem)

        self.delProfBt.clicked.connect(self.delete)
        self.editProfBt.clicked.connect(self.edit)
        self.connProfileBt.clicked.connect(self.connect)
        self.setText(self.profile)
        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))


    def setText(self, profile):
        self.profileName.setText(profile["name"])
        self.connProfileBt.setText("connect")
        self.editProfBt.setIcon(QtGui.QIcon.fromTheme("edit"))
        self.delProfBt.setIcon(QtGui.QIcon.fromTheme("edit-delete"))

        self.modeLabel.setText("<b>Mode: </b>" + profile["mode"])
        self.protocolLabel.setText("<b>Protocol: </b>" + profile["protocol"])
        self.providerLabel.setText("<b>Provider: </b>" + ', '.join(profile["providers"]))
        self.countryLabel.setText("<b>Countries: </b>" + ', '.join(profile["countries"]))

        if profile["filters"]:
            self.filterLabel.setText("<b>Filter: </b>" + ', '.join(profile["filters"]))

    def connect(self):
        self.connect_profile.emit(self.profile["number"])

    def delete(self):
        self.del_profile.emit(self.profile["number"])

    def edit(self):
        self.edit_profile.emit(self.profile["number"])