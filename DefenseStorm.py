

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
import configparser
import os
import pickle
import requests
import traceback

from http.cookiejar import Cookie, CookieJar

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

        self.cookieJar = CookieJar()
        self.bearer = None
        self.failure_count = 0
        self.max_failure_count = 3
        self.basic_auth = None

        try:
            if self.testing == False:
                self.logger = logging.getLogger()
                self.set_logLevel(log_level)
                handler = logging.handlers.SysLogHandler('/dev/log', facility=22)
                formatter = logging.Formatter('DS-' + self.integration + '[%(process)s]: %(message)s')
                handler.formatter = formatter
                self.logger.addHandler(handler)
                self.logger.info('Starting run')

                self.event_logger = logging.getLogger(self.integration + 'events')
                self.event_logger.setLevel(logging.getLevelName(log_level))
                #Set handler to local syslog and facility local7
                event_handler = logging.handlers.SysLogHandler('/dev/log', facility=23)
                event_formatter = logging.Formatter('DS-' + self.integration + '[%(process)s]: %(message)s')
                event_handler.formatter = event_formatter
                self.event_logger.addHandler(event_handler)

                self.logger.info('Starting run')
            else:
                self.logger = logging.getLogger()
                logFormatter = logging.Formatter(fmt='%(levelname)s: %(message)s')
                formatter = logging.Formatter('DS-' + self.integration + '[%(process)s]: %(message)s')
                handler = logging.StreamHandler(sys.stdout)
                handler.setFormatter(logFormatter)
                self.logger.addHandler(handler)
                self.set_logLevel(log_level)

                timestamp = str(calendar.timegm(time.gmtime()))
                self.logger.info('Starting run in test mode.  Data will be written locally to output.' + timestamp)
                self.events_file = open('output.' + timestamp, 'w')
        except:
            self.logger.error('ERROR: Failed setting up logging')
            self.logger.error("%s" %(traceback.format_exc().replace('\n',';')))



        if self.testing == False:
            self.logger.info('Starting run')
        else:
            timestamp = str(calendar.timegm(time.gmtime()))
            self.logger.info('Starting run in test mode.  Data will be written locally to output.' + timestamp)
            self.events_file = open('output.' + timestamp, 'w')

        if config_file == None:
            self.config_file = self.integration + ".conf"
        else:
            self.config_file = config_file

        self.config = configparser.ConfigParser()
        self.logger.info('Reading config file ' + self.config_file)
        try:
            self.config.read(self.config_file)
        except Exception as e:
            traceback.print_exc()
            try:
                self.ds.logger.error('ERROR: ' + str(e))
            except:
                pass


    def __del__(self):
        end = time.time()
        secs = end - self.start
        self.logger.info('Completed run of %d events in: %0.2f seconds' %(self.count, secs))

    def set_logLevel(self, log_level):
        if log_level == 'INFO':
            self.logger.setLevel(logging.INFO)
        elif log_level == 'WARNING':
            self.logger.setLevel(logging.WARNING)
        elif log_level == 'ERROR':
            self.logger.setLevel(logging.ERROR)
        elif log_level == 'CRITICAL':
            self.logger.setLevel(logging.CRITICAL)
        elif log_level == 'DEBUG':
            self.logger.setLevel(logging.DEBUG)

    def writeEvent(self, message):
        if self.testing == True:
            self.events_file.write(message + '\n')
        else:
            self.event_logger.info(message)
        self.count +=1

    def writeJSONEvent(self, json_event, JSON_field_mappings = None, flatten = True, app_name = None):
        if flatten == True:
            json_event = self.flatten_json(json_event)
        if app_name == None:
            json_event['app_name'] = self.config_get('json', 'app_name')
        else:
            json_event['app_name'] = app_name
            

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
                self.logger.error("Failed to create state dir: %s" %state_dir)
                return None
        try:
            with open(state_file_path, 'wb') as f:
                pickle.dump(state, f, protocol=2)
        except:
                self.logger.error("Failed to save state to %s" %state_file_path)
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

    def requests_get(self, url, auth = None, headers = {}, data = None, params = None, cookies = None, ssl_verify= True, proxies = None):
        if self.bearer != None:
            if 'Authorization' in headers.keys():
                self.logger.warning( "Received unexpected Authorization field in provided headers when bearer not none.  Overwriting")
            headers['Authorization'] = 'Bearer '+ self.bearer
        try:
            response = requests.get(url, auth=self.basic_auth, headers=headers, data=data, params = params, cookies = cookies, timeout=15, verify=ssl_verify, proxies = proxies)
        except Exception as e:
            self.failure_count += 1
            if self.failure_count < self.max_failure_count:
                self.logger.warn("Failure %d of %d" %(self.failure_count, self.max_failure_count))
                self.logger.warn("Exception {0}".format(str(e)))
            else:
                self.logger.error("Failure %d of %d" %(self.failure_count, self.max_failure_count))
                self.logger.error("Exception {0}".format(str(e)))
            return None
        if not response or response.status_code not in [200, 206]:
            self.logger.warning( "Received unexpected " + str(response) + " server {0}.".format(url))
            return None
        self.failure_count = 0
        return response


    def requests_post(self, url, auth = None, headers = None, data = None, params = None, cookies = None, files = None, ssl_verify= True, proxies = None):
        if self.bearer != None:
            headers['Authorization'] = 'Bearer '+ self.bearer
        try:
            response = requests.post(url, auth=auth, headers=headers, data=data, params = params, cookies = cookies, files = files, timeout=15, verify=ssl_verify, proxies = proxies)
        except Exception as e:
            self.failure_count += 1
            if self.failure_count < self.max_failure_count:
                self.logger.warn("Failure %d of %d" %(self.failure_count, self.max_failure_count))
                self.logger.warn("Exception {0}".format(str(e)))
                self.logger.warn("%s" %(traceback.format_exc().replace('\n',';')))
            else:
                self.logger.error("Failure %d of %d" %(self.failure_count, self.max_failure_count))
                self.logger.error("Exception {0}".format(str(e)))
            return None
        if not response or response.status_code not in [200, 206]:
            self.logger.warning( "Received unexpected " + str(response) + ':' + str(response.text)+ " server {0}.".format(url))
            return None
        self.failure_count = 0
        return response

    def requests_put(self, url, auth = None, headers = {}, data = None, params = None, cookies = None, ssl_verify= True, proxies = None, files = None, file_type = 'application/octet-stream'):
        try:
            response = requests.put(url, auth=self.basic_auth, headers=headers, data=data, params = params, cookies = cookies, timeout=15, verify=ssl_verify, proxies = proxies)
        except Exception as e:
            self.logger.error("%s" %(traceback.format_exc().replace('\n',';')))
            self.logger.error("Failure in put: " + url)
            self.logger.error("Exception {0}".format(str(e)))
            return None
        if not response or response.status_code not in [200, 206]:
            self.logger.warning( "Received unexpected " + str(response) + " server {0}.".format(url))
            return None
        return response

    def bakeCookie(self, name, value):
        cookie = Cookie(
                version = 0,
                name=name,
                port=None,
                port_specified=None,
                domain='defensestorm.com',
                domain_specified = None,
                domain_initial_dot = None,
                path = '/',
                path_specified = None,
                secure = False,
                discard = False,
                comment = 'key',
                comment_url = None,
                rest = None,
                expires = None,
                value = value)
        return cookie

    def searchTickets(self, slug_name = 'tasks', criteria = {}):
        #headers = {'Content-Type': 'application/json', 'User-Agent':'curl/7.68.0'}
        headers = {'Content-Type': 'application/json'}
        ak_cookie = self.bakeCookie( name = "AK", value = self.config_get('grid','key'))
        as_cookie = self.bakeCookie(name='AS', value = self.config_get('grid','secret'))
        self.cookieJar.set_cookie(ak_cookie)
        self.cookieJar.set_cookie(as_cookie)
        response = self.requests_post(url = 'https://api.defensestorm.com/ticket/v1/ticket/task/search', headers = headers, cookies = self.cookieJar, data = json.dumps(criteria))
        json_out = response.json()
        if 'tickets' in json_out.keys():
            return json_out['tickets']
        else:
            return None


    def uploadFileToTicket(self, ticket_id, file_name, slug_name='tasks'):
        #headers = {'Content-Type': 'multipart/form-data'}
        ak_cookie = self.bakeCookie( name = "AK", value = self.config_get('grid','key'))
        as_cookie = self.bakeCookie(name='AS', value = self.config_get('grid','secret'))
        self.cookieJar.set_cookie(ak_cookie)
        self.cookieJar.set_cookie(as_cookie)

        response = self.requests_get(url = 'https://api.defensestorm.com/ticket/v1/ticket/task/' + str(ticket_id) + '/file', cookies = self.cookieJar, params = {'contentType':'application/octet-stream'})
        r_data = response.json()
        if 'id' not in r_data.keys() or 'url' not in r_data.keys():
            self.logger.error('Problem with File Upload Request')
            return False
        headers = {'Content-Type': 'application/octet-stream', 'Content-Disposition':'attachment; filename="' + file_name + '"'}
        response = self.requests_put(url = r_data['url'], headers =headers, data=open(file_name, 'rb') )

        if response == None:
            self.logger.error('Problem with File PUT: ' + r_data['url'])
            return False

        r_data['filename'] = file_name
        r_data['size'] = 0

        headers = {'Content-Type': 'application/json'}
        response = self.requests_post(url = 'https://api.defensestorm.com/ticket/v1/ticket/task/' + str(ticket_id) + '/file', cookies = self.cookieJar, data = json.dumps(r_data), headers = headers)
        if response.status_code != 200:
            self.logger.error('Failed to upload ' + file_name + ' to ticket ' + str(ticket_id))
            return False
        else:
            self.logger.info('Uploaded ' + file_name + ' to ticket ' + str(ticket_id))
            return True

