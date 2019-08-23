

import sys
sys.path.insert(0, '/usr/local/bin/pylib')
sys.path.insert(0, '/usr/local/bin')
sys.path.insert(0, '/etc/syslog-ng')

import json
import time
from datetime import datetime
import calendar
import subprocess
import logging
import logging.handlers
import ConfigParser
import os
import pickle

class DefenseStorm(object):



    def __init__(self, integration, log_level='INFO', testing=False, send_syslog=False, config_file=None):

        '''
        integration -- System/Solution integrating with.
                       This is used:
                           - app_name for logging ( ds-<integration> )
                           - integration.conf for config values
        '''
        self.CEF_custom_field_list = ['cs1','cs2','cs3','cs4','cs5','cs6','cn1','cn2','cn3','flexDate1','flexString1','flexString2']

        self.integration = integration
        self.state_file_name = '/state.obj'

        self.testing = testing
        self.send_syslog = send_syslog
        self.events_file = None

        self.start = time.time()

        self.count = 0

        self.logger = logging.getLogger(self.integration)
        self.logger.setLevel(logging.getLevelName(log_level))
        #Set handler to local syslog and facility local7
        handler = logging.handlers.SysLogHandler('/dev/log', facility=22)
        formatter = logging.Formatter('DS-' + self.integration + '[%(process)s]: %(message)s')
        handler.formatter = formatter
        self.logger.addHandler(handler)

        self.event_logger = logging.getLogger(self.integration + 'events')
        self.event_logger.setLevel(logging.getLevelName(log_level))
        #Set handler to local syslog and facility local7
        event_handler = logging.handlers.SysLogHandler('/dev/log', facility=23)
        event_formatter = logging.Formatter('DS-' + self.integration + '[%(process)s]: %(message)s')
        event_handler.formatter = event_formatter
        self.event_logger.addHandler(event_handler)

        if self.testing == False:
            self.log('INFO', 'Starting run')
        else:
            timestamp = str(calendar.timegm(time.gmtime()))
            self.log('INFO', 'Starting run in test mode.  Data will be written locally to output.' + timestamp)
            self.events_file = open('output.' + timestamp, 'w')

        if config_file == None:
            self.config_file = self.integration + ".conf"
        else:
            self.config_file = config_file

        self.config = ConfigParser.ConfigParser()
        self.log('INFO', 'Reading config file ' + self.config_file)
        try:
            self.config.read(self.config_file)
        except Exception ,e:
            traceback.print_exc()
            try:
                self.ds.log('ERROR', 'ERROR: ' + str(e))
            except:
                pass




    def __del__(self):
        end = time.time()
        secs = end - self.start
        self.log('INFO', 'Completed run of %d events in: %0.2f seconds' %(self.count, secs))

    def writeEvent(self, message):
        if self.testing == True:
            self.events_file.write(message + '\n')
        else:
            self.event_logger.info(message)
        self.count +=1

    def writeJSONEvent(self, json_event, JSON_field_mappings = None):
        json_event = self.flatten_json(json_event)
        json_event['app_name'] = self.config_get('json', 'app_name')

        if JSON_field_mappings != None:
            for item in JSON_field_mappings.keys():
                if JSON_field_mappings[item] != None:
                    try:
                        #if item in json_event.keys():
                        json_event[JSON_field_mappings[item]] = json_event[item]
                        del json_event[item]
                    except KeyError:
                        pass

        if self.testing == True:
            self.events_file.write("DS_INT " + self.config_get('json', 'version') + " " + json.dumps(json_event) + '\n')
        else:
            self.event_logger.info("DS_INT " + self.config_get('json', 'version') + " " + json.dumps(json_event))
        self.count +=1

    def writeCEFEvent(self, cef_version='', vendor='', product='', version='', type='', action='', severity='', dataDict={}, CEF_field_mappings=None, CEF_custom_field_labels=None):

        if cef_version == '':
            cef_version = self.config_get('cef', 'CEF_VERSION')
        if vendor == '':
            vendor = self.config_get('cef', 'VENDOR')
        if product == '':
            product = self.config_get('cef', 'PRODUCT')
        if version == '':
            version = self.config_get('cef', 'VERSION')
        if severity == '':
            severity = self.config_get('cef', 'SEVERITY')

        extension = {}

        if (CEF_field_mappings != None) and (CEF_custom_field_labels != None):
            for item in dataDict.keys():
                if item in CEF_field_mappings.keys():
                    if CEF_field_mappings[item] != None:
                        if CEF_field_mappings[item] == 'type':
                            type = str(dataDict[item])
                        elif CEF_field_mappings[item] == 'severity':
                            severity = str(dataDict[item])
                        elif CEF_field_mappings[item] == 'name':
                            name = str(dataDict[item])
                        else:
                            extension[CEF_field_mappings[item]] = str(dataDict[item])
                    if CEF_field_mappings[item] in self.CEF_custom_field_list:
                        extension[CEF_field_mappings[item] + 'Label'] = CEF_custom_field_labels[CEF_field_mappings[item] + 'Label']
                    del dataDict[item]
        First = True
        msg = ""
        for item in dataDict.keys():
            if First:
                msg += "%s\=%s" %(item, dataDict[item])
            else:
                msg += " %s\=%s" %(item, dataDict[item])

        if msg != "":
            extension['msg'] = msg

        extension_list = []

        for key in extension.keys():
            extension_list.extend([key + '=' + extension[key]])

        header = '|'.join([cef_version, vendor, product, version,
            type, name, severity]) + '|'
        msg = header + ' '.join(extension_list)
        self.writeEvent(msg)

    def log(self, level='INFO', msg=''):
        if self.send_syslog == True:
            if level == 'INFO':
                self.logger.info(msg)
            elif level == 'WARNING':
                self.logger.warning(msg)
            elif level == 'ERROR':
                self.logger.error(msg)
            elif level == 'CRITICAL':
                self.logger.critical(msg)
            elif level == 'DEBUG':
                self.logger.debug(msg)
        else:
            print "%s: %s" %(level, msg)

    def config_get(self, section, value):
        return self.config.get(section, value)

    def get_state(self, state_dir):
        state_file_path = state_dir + self.state_file_name
        try:
            with open (state_file_path, 'rb') as f:
                state = pickle.load(f)
        except:
            return None
        return state

    def set_state(self, state_dir, state):
        state_file_path = state_dir + self.state_file_name
        if not os.path.exists(state_dir):
            try:
                os.makedirs(state_dir)
            except OSError as e:
                self.log('ERROR', "Failed to create state dir: %s" %state_dir)
                return None
        try:
            with open(state_file_path, 'wb') as f:
                pickle.dump(state, f, protocol=2)
        except:
                self.log('ERROR', "Failed to save state to %s" %state_file_path)
        return True

    def flatten_json(self,y):
        out = {}

        def flatten(x, name=''):
            if type(x) is dict:
                for a in x:
                    flatten(x[a], name + a + '_')
            elif type(x) is list:
                i = 0
                for a in x:
                    flatten(a, name + str(i) + '_')
                i += 1
            else:
                out[name[:-1]] = x

        flatten(y)
        return out

