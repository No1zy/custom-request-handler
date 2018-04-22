from burp import IBurpExtender
from burp import ISessionHandlingAction
from burp import IRequestInfo
from burp import ITab
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from javax import swing
from javax.swing import JSplitPane
from javax.swing import JPanel
from javax.swing import JTextField
from javax.swing import JLabel
from javax.swing import JScrollPane
from javax.swing import JButton
from javax.swing import BoxLayout
from javax.swing import JTextArea
from javax.swing.table import TableModel
from javax.swing.table import DefaultTableModel
from javax.swing import JTable
from javax.swing import BorderFactory
from javax.swing.border import LineBorder
from javax.swing.border import TitledBorder
from javax.swing import JFileChooser
from javax.swing import JCheckBox
from java.awt import FlowLayout
from java.awt import Component
from java.awt import Dimension
from java.awt.event import ActionListener
from java.awt import Font
from java.awt import Color
from java.awt import ComponentOrientation

import json
import sys
import collections
import re

class BurpExtender(IBurpExtender, ISessionHandlingAction, ITab, IContextMenuFactory, IContextMenuInvocation, ActionListener):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # save the helpers for later
        self.helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Session token example")
        callbacks.createTextEditor()
        callbacks.registerSessionHandlingAction(self)
        callbacks.registerContextMenuFactory(self)

        #The state was How far loaded the table 
        self.current_column_id = 0

        #GUI 
        self._split_main = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        self._split_top = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
        self._split_top.setPreferredSize(Dimension(100, 50))
        self._split_top.setDividerLocation(700)
        self._split_center = JSplitPane(JSplitPane.VERTICAL_SPLIT)

        boxVertical = swing.Box.createVerticalBox()
        box_top = swing.Box.createHorizontalBox()
        boxHorizontal = swing.Box.createHorizontalBox()
        buttonHorizontal = swing.Box.createHorizontalBox()
        boxVertical.add(boxHorizontal)

        box_regex = swing.Box.createVerticalBox()
        border = BorderFactory.createTitledBorder(LineBorder(Color.BLACK), "Extract from regex group", TitledBorder.LEFT, TitledBorder.TOP)
        box_regex.setBorder(border)

        self._add_btn = JButton("Add")
        self._add_btn.addActionListener(self)
        
        self._remove_btn = JButton("Remove")
        self._remove_btn.addActionListener(self)
        self._jLabel_param = JLabel("Name:")
        self._param_error = JLabel("Name is required")

        self._param_error.setVisible(False)
        self._param_error.setFont(Font(Font.MONOSPACED, Font.ITALIC, 12))
        self._param_error.setForeground(Color.red)
        self._jTextIn_param = JTextField(20)
        self._jLabel_regex = JLabel("Regex:")
        self._jTextIn_regex = JTextField(20)
        self._regex_error = JLabel("No group defined")
        self._regex_error.setVisible(False)
        self._regex_error.setFont(Font(Font.MONOSPACED, Font.ITALIC, 12))
        self._regex_error.setForeground(Color.red)
        self._param_panel = JPanel(FlowLayout(FlowLayout.LEADING))
        self._param_panel.add(self._jLabel_param)
        self._param_panel.add(self._jTextIn_param)
        self._param_panel.add(self._param_error)

        self._regex_panel = JPanel(FlowLayout(FlowLayout.LEADING))
        self._regex_panel.add(self._jLabel_regex)
        self._regex_panel.add(self._jTextIn_regex)
        self._regex_panel.add(self._regex_error)
        self._button_panel = JPanel()
        self._button_panel.add(self._add_btn)
        self._button_panel.add(self._remove_btn)
        box_regex.add(self._param_panel)
        box_regex.add(self._regex_panel)
        buttonHorizontal.add(self._button_panel)
        box_regex.add(buttonHorizontal)
        boxVertical.add(box_regex)
        box_top.add(boxVertical)

        box_file = swing.Box.createHorizontalBox()
        checkbox_panel = JPanel(FlowLayout(FlowLayout.LEADING))
        border = BorderFactory.createTitledBorder(LineBorder(Color.BLACK), 'Payload Sets [Simple list]', TitledBorder.LEFT, TitledBorder.TOP)
        box_file.setBorder(border)

        box_param = swing.Box.createVerticalBox()
        box_param.add(checkbox_panel)

        file_column_names = [ 
            "Name",
            "Value",
        ]
        data = []
        self.file_table_model = DefaultTableModel(data, file_column_names)
        self.file_table = JTable(self.file_table_model)
        self.file_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)

        column_model = self.file_table.getColumnModel()
        for count in xrange(column_model.getColumnCount()):
            column = column_model.getColumn(count)
            column.setPreferredWidth(250)

        self.file_table.preferredScrollableViewportSize = Dimension(500, 70)
        self.file_table.setFillsViewportHeight(True)
        box_param.add(JScrollPane(self.file_table))
        callbacks.customizeUiComponent(self.file_table)

        file_param_panel = JPanel(FlowLayout(FlowLayout.LEADING))

        self._file_param = JLabel("Name:")
        self._file_param_text = JTextField(20)
        
        file_param_panel.add(self._file_param)
        file_param_panel.add(self._file_param_text)
        self._error_message = JLabel("Name is required")
        self._error_message.setVisible(False)
        self._error_message.setFont(Font(Font.MONOSPACED, Font.ITALIC, 12))
        self._error_message.setForeground(Color.red)
        file_param_panel.add(self._error_message)
        box_param.add(file_param_panel)

        box_button_file = swing.Box.createVerticalBox()
        self._file_load_btn = JButton("Load")

        self._file_clear_btn = JButton("Clear")
        self._file_clear_btn.addActionListener(self)
        self._file_load_btn.addActionListener(self)
        box_button_file.add(self._file_load_btn)
        box_button_file.add(self._file_clear_btn)
        box_file.add(box_button_file)
        box_file.add(box_param)
        boxVertical.add(box_file)

        regex_column_names = [ 
            "Name",
            "Value",
            "Regex",
        ]
        #clear target.json
        with open("target.json", "w") as f:
            pass
        data = []
        self.target_table_model = DefaultTableModel(data, regex_column_names)
        self.target_table = JTable(self.target_table_model)
        self.target_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)
        column_model = self.target_table.getColumnModel()
        for count in xrange(column_model.getColumnCount()):
            column = column_model.getColumn(count)
            column.setPreferredWidth(170)

        self.target_table.preferredScrollableViewportSize = Dimension(500, 70)
        self.target_table.setFillsViewportHeight(True)
        callbacks.customizeUiComponent(self.target_table)
        callbacks.customizeUiComponent(boxVertical)
        table_panel = swing.Box.createVerticalBox()
        table_panel.add(JScrollPane(self.target_table))
        box_top.add(table_panel)

        self._jScrollPaneOut = JScrollPane()
        self._split_main.setBottomComponent(self._jScrollPaneOut)

        self._split_main.setTopComponent(box_top)
        self._split_main.setDividerLocation(380)
        callbacks.customizeUiComponent(self._split_main)
        callbacks.addSuiteTab(self)
        return

    def getTabCaption(self):
        return "CRH"

    def getUiComponent(self):
        return self._split_main

    def createMenuItems(self, invocation):
        menu = []
        ctx = invocation.getInvocationContext()
        menu.append(swing.JMenuItem("Send to CHR", None, actionPerformed=lambda x, inv=invocation: self.eventListener(inv)))
        return menu if menu else None

    def eventListener(self, invocation):
        try:
            invMessage = invocation.getSelectedMessages()
            message = invMessage[0].getResponse()
            res_info = self.helpers.analyzeResponse(message)
            send_res = message.tostring()
            self._req_panel = JTextArea(send_res)
            self._req_panel.setLineWrap(True)
            self._jScrollPaneOut.setViewportView(self._req_panel)
        except:
             print 'Failed to add data to JSON replacer tab.'

    #
    # Implement Action
    #
    def actionPerformed(self, actionEvent):
        if actionEvent.getSource() is self._add_btn:
            param = self._jTextIn_param.getText()
            if len(param) is 0:
                self._param_error.setVisible(True)
                return

            regex = self._jTextIn_regex.getText()
            req = self._req_panel.getText()
            try:
                pattern = re.compile(regex)
                match = pattern.search(req)
                value = match.group(1) if match else None
            except IndexError:
                self._regex_error.setVisible(True)
                return 

            data = [
                param,
                value,
                regex,
            ]
            self.target_table_model.addRow(data)

            with open("target.json", "r") as f:
                try:
                    json_data = json.load(f)
                except:
                    json_data = dict()

            with open("target.json", "w") as f:
                json_data.update({
                    param : regex,
                })
                f.write(json.dumps(json_data))

        if actionEvent.getSource() is self._remove_btn:
            rowno = self.target_table.getSelectedRow()
            if rowno != -1:
                column_model = self.target_table.getColumnModel()
                param_name = self.target_table_model.getValueAt(rowno, 0).encode('utf-8')
                regex = self.target_table_model.getValueAt(rowno, 2).encode('utf-8')

                self.target_table_model.removeRow(rowno)
                with open("target.json", 'r') as f:
                    try:
                        json_data = json.load(f)
                    except:
                        json_data = dict()

                with open("target.json", "w") as f:
                    for key, value in json_data.items():
                        if value.encode('utf-8') == regex and key.encode('utf-8') == param_name:
                            try:
                                del json_data[key]
                            except:
                                print('Error: {0}: No such json key.'.format(key))
                    f.write(json.dumps(json_data))
        
        if actionEvent.getSource() is self._file_load_btn:
            target_param = self._file_param_text.getText()

            if len(target_param) == 0:
                self._error_message.setVisible(True)
                return 
            chooser = JFileChooser()
            chooser.showOpenDialog(actionEvent.getSource())
            file_path = chooser.getSelectedFile().getAbsolutePath()
            with open(file_path, 'r') as f:
                line = f.readline()
                while line:
                    data = [
                        target_param,
                        line.strip(),
                    ]
                    self.file_table_model.addRow(data)
                    line = f.readline()
            with open('target.json', 'r') as f:
                try:
                    json_data = json.load(f)
                except:
                    json_data = dict()
            
            with open('target.json', 'w') as f:
                json_data.update({
                        target_param : 'Set payload',
                    })
                f.write(json.dumps(json_data))
        
        if actionEvent.getSource() is self._file_clear_btn:
            count = self.file_table.getRowCount()
            for i in xrange(count):
                self.file_table_model.removeRow(0)

            self.current_column_id = 0
            
            with open("target.json", 'r') as f:
                    try:
                        json_data = json.load(f)
                    except:
                        json_data = dict()

            with open("target.json", "w") as f:
                for key, value in json_data.items():
                    if value.encode('utf-8') == 'Set payload':
                        try:
                            del json_data[key]
                        except:
                            print('Error: {0}: No such json key.'.format(key))
                f.write(json.dumps(json_data))
    #
    # Implement ISessionHandlingAction
    #

    def getActionName(self):
        return "custom request handler"

    # current_request []byte
    # macro_items     
    def performAction(self, current_request, macro_items):

        if len(macro_items) == 0:
            return

        # extract the response headers
        final_response = macro_items[len(macro_items) - 1].getResponse()
        if final_response is None:
            return

        req = self.helpers.analyzeRequest(current_request)

        if IRequestInfo.CONTENT_TYPE_JSON != req.getContentType():
            return False

        body = current_request.getRequest()[req.getBodyOffset():].tostring()

        try:
            json_data = json.loads(body, object_pairs_hook=collections.OrderedDict)
            
            with open('target.json', 'r') as f:
                read_data = f.read()
                read_data = json.loads(read_data)
        except ValueError: 
            sys.stderr.write('Error: json.loads()')
            return

        target_keys = filter(lambda x: x in json_data.keys(), read_data.keys())

        if not target_keys:
            return

        req_data = json_data
        body_string = final_response.tostring()
        column_model = self.file_table.getColumnModel()
        row_count = self.file_table_model.getRowCount()
        for key in target_keys:
            if read_data[key] == 'Set payload':
                if row_count > self.current_column_id:
                    value = self.file_table_model.getValueAt(self.current_column_id, 1)
                    self.current_column_id += 1
            else:
                match = re.search(read_data[key], body_string)
                if match:
                    value = match.group(1)
                else:
                    continue
            req_data[key] = value
        req = current_request.getRequest()
        json_data_start = self.helpers.indexOf(req, bytearray(body), False, 0, len(req))

        # glue together first line + session token header + rest of request
        current_request.setRequest(
                    req[0:json_data_start] +
                    self.helpers.stringToBytes(json.dumps(req_data)))