#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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


class PlotArea(QtWidgets.QWidget):
    def __init__(self, parent = None):
        super(PlotArea, self).__init__(parent)
        self.down_values = []
        self.up_values = []
        self.max_val = 1
        self.x_off = 60
        self.offset = 5
        self.gap = 8
        bold_font = QtGui.QFont()
        bold_font.setPointSize(8)
        bold_font.setWeight(75)
        self.setFont(bold_font)
        self.up_path = QtGui.QPainterPath()
        self.down_path = QtGui.QPainterPath()
        self.setAutoFillBackground(True)
        self.wmax = self.width() - self.offset
        self.hmax = self.height() - self.offset

    def paintEvent(self, event):
        legend_painter = QtGui.QPainter(self)
        palette = self.palette()
        pen = QtGui.QPen(palette.color(QtGui.QPalette.Mid))
        pen.setWidth(1)
        legend_painter.setPen(pen)
        legend_painter.drawLine(self.offset, self.hmax, self.wmax-self.x_off, self.hmax)
        legend_painter.drawLine(self.offset, self.offset, self.wmax-self.x_off, self.offset)
        legend_painter.drawLine(self.offset, self.hmax/2, self.wmax-self.x_off, self.hmax/2)
        legend_painter.drawLine(self.wmax-self.x_off, self.offset, self.wmax-self.x_off, self.hmax)
        legend_painter.drawLine(self.offset, self.offset, self.offset, self.hmax)
        
        pen.setColor(palette.color(QtGui.QPalette.Text))
        legend_painter.setPen(pen)
        legend_painter.drawText(self.wmax-55, self.offset+8, "{} Mbps".format(self.max_val))
        legend_painter.drawText(self.wmax-55, self.hmax/2+4, "{} Mbps".format(self.max_val/2))
        legend_painter.drawText(self.wmax-55, self.hmax, "{} Mbps".format("0"))

        up_painter = QtGui.QPainter(self)
        pen = QtGui.QPen(QtGui.QColor(255,127,42,255))
        pen.setWidth(2)
        up_painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        up_painter.setPen(pen)
        up_painter.drawPath(self.down_path)

        down_painter = QtGui.QPainter(self)
        pen = QtGui.QPen(QtGui.QColor(44,142,216,255))
        pen.setWidth(2)
        down_painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        down_painter.setPen(pen)
        down_painter.drawPath(self.up_path)

    def addPoint(self, up, down):
        self.up_path = QtGui.QPainterPath()
        self.down_path = QtGui.QPainterPath()
        self.up_values.insert(0, up)
        self.down_values.insert(0, down)

        #check for highest value
        max_down = max(self.down_values)
        max_up = max(self.down_values)
        if max_down >= max_up:
            self.max_y = max_down
        else:
            self.max_y = max_up

        self.max_val = round(self.max_y/128, 1)
        if self.max_val < 0.1:
            self.max_val = 0.1 
        nx = int((self.wmax - self.x_off)/ self.gap)   
        if nx < (len(self.up_values)+1):
            self.up_values = self.up_values[:nx]
            self.down_values = self.down_values[:nx]

        scale_y = (self.max_y*1.1 / self.hmax) + 1
        start_x = self.wmax - self.x_off

        start_y = self.hmax - (self.up_values[0] / scale_y)
        self.up_path.moveTo(start_x, start_y)
        for i, p in enumerate(self.up_values[1:]):
            x = start_x - self.gap*(i+1)
            y = self.hmax - (p / scale_y)
            self.up_path.lineTo(x,y)

        start_y = self.hmax - (self.down_values[0] / scale_y)
        self.down_path.moveTo(start_x, start_y)
        for i, p in enumerate(self.down_values[1:]):
            x = start_x - self.gap*(i+1)
            y = self.hmax - (p / scale_y)
            self.down_path.lineTo(x,y)

        self.update()

    def resizeEvent(self, event):
        self.wmax = self.width() - self.offset
        self.hmax = self.height() - self.offset

    def sizeHint(self):
        return QtCore.QSize(100, 100)