from burp import IBurpExtender
from burp import ISessionHandlingAction
from burp import IRequestInfo
from burp import ITab
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from burp import ITextEditor
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
from javax.swing import JComboBox
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

class BurpExtender(IBurpExtender, ISessionHandlingAction, ITab, IContextMenuFactory, IContextMenuInvocation, ActionListener, ITextEditor):

    #
    # implement IBurpExtender
    #

    def registerExtenderCallbacks(self, callbacks):
        # save the helpers for later
        self.helpers = callbacks.getHelpers()
        
        # set our extension name
        callbacks.setExtensionName("Custom Request Handler")
        callbacks.registerSessionHandlingAction(self)
        callbacks.registerContextMenuFactory(self)
        self._text_editor = callbacks.createTextEditor()
        self._text_editor.setEditable(False)

        #How much loaded the table row 
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
        border = BorderFactory.createTitledBorder(LineBorder(Color.BLACK), "Extract target strings", TitledBorder.LEFT, TitledBorder.TOP)
        box_regex.setBorder(border)

        self._add_btn = JButton("Add")
        self._add_btn.addActionListener(self)  
        self._remove_btn = JButton("Remove")
        self._remove_btn.addActionListener(self)
        
        items = [
            'JSON',
            'Header',
        ]
        self._dropdown = JComboBox(items)
        type_panel = JPanel(FlowLayout(FlowLayout.LEADING))
        type_panel.add(JLabel('Type:'))
        type_panel.add(self._dropdown)

        self._jLabel_param = JLabel("Name:")
        self._param_error = JLabel("Name is required")

        self._param_error.setVisible(False)
        self._param_error.setFont(Font(Font.MONOSPACED, Font.ITALIC, 12))
        self._param_error.setForeground(Color.red)

        regex_checkbox = JPanel(FlowLayout(FlowLayout.LEADING))
        self._is_use_regex = JCheckBox("Extract from regex group")
        regex_checkbox.add(self._is_use_regex)
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
        button_panel = JPanel(FlowLayout(FlowLayout.LEADING))
        #padding
        button_panel.add(JPanel())
        button_panel.add(JPanel())
        button_panel.add(JPanel())
        button_panel.add(self._add_btn)
        button_panel.add(self._remove_btn)
        box_regex.add(type_panel)
        box_regex.add(self._param_panel)
        box_regex.add(regex_checkbox)
        box_regex.add(self._regex_panel)
        buttonHorizontal.add(button_panel)
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
            "Type",
            "Name",
            "Payload",
        ]
        data = []
        self.file_table_model = DefaultTableModel(data, file_column_names)
        self.file_table = JTable(self.file_table_model)
        self.file_table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF)

        column_model = self.file_table.getColumnModel()
        for count in xrange(column_model.getColumnCount()):
            column = column_model.getColumn(count)
            column.setPreferredWidth(160)

        self.file_table.preferredScrollableViewportSize = Dimension(500, 70)
        self.file_table.setFillsViewportHeight(True)

        panel_dropdown = JPanel(FlowLayout(FlowLayout.LEADING))
        self._file_dropdown = JComboBox(items)
        panel_dropdown.add(JLabel('Type:'))
        panel_dropdown.add(self._file_dropdown)
        box_param.add(panel_dropdown)
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
            "Type",
            "Name",
            "Regex",
            "Start at offset",
            "End at offset",
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
            column.setPreferredWidth(100)

        self.target_table.preferredScrollableViewportSize = Dimension(500, 70)
        self.target_table.setFillsViewportHeight(True)
        callbacks.customizeUiComponent(self.target_table)
        callbacks.customizeUiComponent(boxVertical)
        table_panel = swing.Box.createVerticalBox()
        table_panel.add(JScrollPane(self.target_table))
        box_top.add(table_panel)

        self._jScrollPaneOut = JScrollPane()
        #self._split_main.setBottomComponent(self._jScrollPaneOut)
        self._split_main.setBottomComponent(self._text_editor.getComponent())
        self._split_main.setTopComponent(box_top)
        self._split_main.setDividerLocation(450)
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
        menu.append(swing.JMenuItem("Send to CRH", None, actionPerformed=lambda x, inv=invocation: self.menu_action(inv)))
        return menu if menu else None

    #
    # Implementation of Menu Action
    #
    def menu_action(self, invocation):
        try:
            invMessage = invocation.getSelectedMessages()
            message = invMessage[0].getResponse()
            res_info = self.helpers.analyzeResponse(message)
            send_res = message.tostring()
            self._text_editor.setText(send_res)
        except:
            print('Failed to add data to JSON replacer tab.')

    #
    # Implementation of event action
    #
    def actionPerformed(self, actionEvent):

        # onclick add button of extract from regex group
        if actionEvent.getSource() is self._add_btn:
            start, end = self._text_editor.getSelectionBounds()
            value = None
            regex  = None
            item = self._dropdown.getSelectedItem()
            param = self._jTextIn_param.getText()

            if len(param) is 0:
                self._param_error.setVisible(True)
                return
            self._param_error.setVisible(False)
            is_selected = self._is_use_regex.isSelected()
            if is_selected:
                start = None
                end   = None
                regex = self._jTextIn_regex.getText()
                if len(regex) is 0:
                    self._regex_error.setVisible(True)
                    return

                req = self._text_editor.getText()
                try:
                    pattern = re.compile(regex)
                    match = pattern.search(req)
                    value = match.group(1) if match else None
                    if value is None:
                        raise IndexError
                except IndexError:
                    self._regex_error.setVisible(True)
                    return 
                self._regex_error.setVisible(False)

            data = [
                item,
                param,
                regex,
                start,
                end,
            ]
            self.target_table_model.addRow(data)

            with open("target.json", "r+") as f:
                try:
                    json_data = json.load(f)
                except ValueError:
                    json_data = dict()
                if is_selected:
                    data = {
                        param : [
                            item,
                            regex,
                        ]
                    }
                else:
                    data = {
                        param : [
                            item,
                            start,
                            end,
                        ]
                    }
                json_data.update(data)
                self.write_file(f, json.dumps(json_data))

        # onclick remove button of extract from regex group
        if actionEvent.getSource() is self._remove_btn:
            rowno = self.target_table.getSelectedRow()
            if rowno != -1:
                column_model = self.target_table.getColumnModel()
                param_name = self.target_table_model.getValueAt(rowno, 1)
                start = self.target_table_model.getValueAt(rowno, 3)

                self.target_table_model.removeRow(rowno)
                with open("target.json", 'r+') as f:
                    try:
                        json_data = json.load(f)
                    except:
                        json_data = dict()

                    for key, value in json_data.items():
                        if value[1] == start and key == param_name:
                            try:
                                del json_data[key]
                            except IndexError:
                                print('Error: {0}: No such json key.'.format(key))
                    self.write_file(f, json.dumps(json_data))

        # onclick load button of payload sets
        if actionEvent.getSource() is self._file_load_btn:
            #clear table
            self.remove_all(self.file_table_model)
            self.current_column_id = 0

            target_param = self._file_param_text.getText()
            item = self._file_dropdown.getSelectedItem()

            if len(target_param) == 0:
                self._error_message.setVisible(True)
                return 
            self._error_message.setVisible(False)

            chooser = JFileChooser()
            chooser.showOpenDialog(actionEvent.getSource())
            file_path = chooser.getSelectedFile().getAbsolutePath()
            with open(file_path, 'r') as f:
                while True:
                    line = f.readline().strip()
                    if not line:
                        break
                    data = [
                        item,
                        target_param,
                        line,
                    ]
                    self.file_table_model.addRow(data)

            with open('target.json', 'r+') as f:
                try:
                    json_data = json.load(f)
                except ValueError:
                    json_data = dict()
                
                json_data.update({
                        target_param : [
                            item,
                            'Set payload',
                        ]
                    })
                self.write_file(f, json.dumps(json_data))
        
        # onclick clear button of payload sets
        if actionEvent.getSource() is self._file_clear_btn:
            self.remove_all(self.file_table_model)

            self.current_column_id = 0
            
            with open("target.json", 'r+') as f:
                try:
                    json_data = json.load(f)
                except:
                    json_data = dict()

                for key, value in json_data.items():
                    if isinstance(value[1], unicode):
                        if value[1].encode('utf-8') == 'Set payload':
                            try:
                                del json_data[key]
                            except IndexError:
                                print('Error: {0}: No such json key.'.format(key))
                self.write_file(f, json.dumps(json_data))

    #
    # Implementaion of ISessionHandlingAction
    #
    def getActionName(self):
        return "custom request handler"

    def performAction(self, current_request, macro_items):

        if len(macro_items) == 0:
            return

        # extract the response headers
        final_response = macro_items[len(macro_items) - 1].getResponse()
        if final_response is None:
            return

        req = self.helpers.analyzeRequest(current_request)

        try:
            with open('target.json', 'r') as f:
                read_data = f.read()
                self.read_data = json.loads(read_data)
        except ValueError: 
            sys.stderr.write('Error: json.loads()')
            return

        for key, value in self.read_data.items():
            if value[0] == 'JSON':
                self.set_json_parameter(current_request, final_response, key, value)
            elif value[0] == 'Header':
                self.set_header(current_request, final_response, key, value)


    def set_json_parameter(self, current_request, final_response, key, value):
        req = self.helpers.analyzeRequest(current_request)

        if IRequestInfo.CONTENT_TYPE_JSON != req.getContentType():
            return False

        body = current_request.getRequest()[req.getBodyOffset():].tostring()
        json_data = json.loads(body, object_pairs_hook=collections.OrderedDict)

        target_keys = filter(lambda x: x == key, json_data.keys())
        if not target_keys:
            return

        req_data = json_data
        column_model = self.file_table.getColumnModel()
        row_count = self.file_table_model.getRowCount()
        for key in target_keys:
            if value[-1] == 'Set payload':
                if row_count > self.current_column_id:
                    req_value = self.file_table_model.getValueAt(self.current_column_id, 2)
                    self.current_column_id += 1
            else:
                # No selected regex 
                if len(value) > 2:
                    start, end = value[1:]
                    req_value = final_response[start:end].tostring()
                else:
                    regex = value[1]
                    match = re.search(regex, final_response.tostring())
                    req_value = match.group(1) if match else None

            req_data[key] = req_value

        req = current_request.getRequest()
        json_data_start = self.helpers.indexOf(req, bytearray(body), False, 0, len(req))

        # glue together header + customized json of request
        current_request.setRequest(
                req[0:json_data_start] +
                self.helpers.stringToBytes(json.dumps(req_data)))

    def set_header(self, current_request, final_response, key, value):
        req = self.helpers.analyzeRequest(current_request)
        headers = req.getHeaders()
        target_keys = []
        for header in headers:
            if header.startswith(key):
                target_keys += [key]

        if not target_keys:
            return

        column_model = self.file_table.getColumnModel()
        row_count = self.file_table_model.getRowCount()
        req = current_request.getRequest()
        
        for key in target_keys:
            if value[-1] == 'Set payload':
                if row_count > self.current_column_id:
                    req_value = self.file_table_model.getValueAt(self.current_column_id, 2)
                    self.current_column_id += 1
            else:
                # No selected regex
                if len(value) > 2:
                    start, end = value[1:]
                    req_value = final_response[start:end].tostring()
                else:
                    regex = value[1]
                    match = re.search(regex, final_response.string())
                    req_value = match.group(1) if match else None

            key_start = self.helpers.indexOf(req, bytearray(key.encode('utf-8')), False, 0, len(req))
            key_end = self.helpers.indexOf(req, bytearray('\r\n'), False, key_start, len(req))

            keylen = len(key)

        # glue together first line + customized hedaer + rest of request
        current_request.setRequest(
                req[0:key_start] +
                self.helpers.stringToBytes("%s: %s" % (key.encode('utf-8'), req_value)) +
                req[key_end:])

    #
    # Implementation of function for Remove all for specific table data 
    #
    def remove_all(self, model):
        count = model.getRowCount()
        for i in xrange(count):
            model.removeRow(0)

    #
    # Implementaion of function for write data for specific file
    #
    def write_file(self, f, data):
        f.seek(0)
        f.write(data)
        f.truncate()
        return