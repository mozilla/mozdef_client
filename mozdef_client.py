#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2014 Mozilla Corporation
# Author: gdestuynder@mozilla.com

import os
import sys
import copy
from datetime import datetime
import pytz
import json
import socket
import syslog
try:
    from requests_futures.sessions import FuturesSession as Session
    futures_loaded = True
except ImportError:
    from requests import Session
    futures_loaded = False

class MozDefError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return repr(self.msg)

class MozDefMsg():
#Event types this library can handle
    MSGTYPE_UNKNOWN = 0
    MSGTYPE_EVENT = 1
    MSGTYPE_COMPLIANCE = 2
#If you need syslog emulation (flattens the msg and sends over syslog)
    sendToSyslog = False
#This disables sending to MozDef - Generally you'll want sendToSyslog set to True then
    syslogOnly = False
    httpsession = Session()
#Turns off needless and repetitive .netrc check for creds
    httpsession.trust_env = False
    debug = False
    verify_certificate = True
#Never fail (ie no unexcepted exceptions sent to user, such as server/network not responding)
    fire_and_forget_mode = True
#The type of message we will be sending with this object
    msgtype = MSGTYPE_EVENT
#Default fields utilized by the EVENT message type
    log_event = {}
    log_event['timestamp']   = pytz.timezone('UTC').localize(datetime.utcnow()).isoformat()
    log_event['hostname']    = socket.getfqdn()
    log_event['processid']   = os.getpid()
    log_event['processname'] = sys.argv[0]
    log_event['severity']    = 'INFO'
    log_event['summary']     = None
    log_event['category']    = 'event'
    log_event['tags']        = list()
    log_event['details']     = dict()

    def __init__(self, mozdef_hostname, summary=None, category='event', severity='INFO', tags=[], details={}, msgtype=None):
        self.summary = summary
        self.category = category
        self.severity = severity
        self.tags = tags
        self.details = details
        self.mozdef_hostname = mozdef_hostname
        if msgtype != None:
            self.msgtype = msgtype
        if self.msgtype != self.MSGTYPE_EVENT and \
            self.msgtype != self.MSGTYPE_COMPLIANCE:
            raise MozDefError('invalid msgtype')

    def prepare_event(self, summary, category, severity, tags, details):
        log_msg = copy.copy(self.log_event)

        if summary == None: log_msg['summary'] = self.summary
        else:               log_msg['summary'] = summary

        if category == None: log_msg['category'] = self.category
        else:                log_msg['category'] = category

        if severity == None: log_msg['severity'] = self.severity
        else:                log_msg['severity'] = severity

        if tags == None: log_msg['tags'] = self.tags
        else:            log_msg['tags'] = tags

        if details == None: log_msg['details'] = self.details
        else:               log_msg['details'] = details

        if type(log_msg['details']) != dict:
            raise MozDefError('details must be a dict')
        elif type(log_msg['tags']) != list:
            raise MozDefError('tags must be a list')
        elif log_msg['summary'] == None:
            raise MozDefError('Summary is a required field')

        return log_msg

    def send(self, summary=None, category=None, severity=None, tags=None, details=None):
        log_msg = None

        if self.msgtype == self.MSGTYPE_EVENT:
            log_msg = self.prepare_event(summary, category, severity, tags, details)
        elif self.msgtype == self.MSGTYPE_COMPLIANCE:
            if details == None:
                raise MozDefError('compliance message must have details parameter')
            log_msg = details

        if self.debug:
            print(json.dumps(log_msg, sort_keys=True, indent=4))

        if not self.syslogOnly:
            try:
                if futures_loaded:
                    r = self.httpsession.post(self.mozdef_hostname, json.dumps(log_msg, sort_keys=True, indent=4), verify=self.verify_certificate, background_callback=self.httpsession_cb)
                else:
                    r = self.httpsession.post(self.mozdef_hostname, json.dumps(log_msg, sort_keys=True, indent=4), verify=self.verify_certificate)
            except Exception as e:
                if not self.fire_and_forget_mode:
                    raise e

        if self.sendToSyslog:
            syslog_msg = ''
            syslog_severity = syslog.LOG_INFO
            for i in log_msg:
# If present and if possible convert severity to a syslog field
                if i == 'severity':
                    syslog_severity = self.str_to_syslog_severity(i)
                    continue
# These fields are already populated by syslog
                if i == 'hostname' or i == 'processid' or i == 'timestamp' or i == 'processname':
                    continue
                syslog_msg += str(i)+': \''+str(log_msg[i])+'\' '
            syslog.syslog(syslog_severity, syslog_msg)
            syslog.closelog()

    def str_to_syslog_severity(self, severity):
        if severity == 'INFO':
            return syslog.LOG_INFO
        elif severity == 'WARNING':
            return syslog.LOG_WARNING
        elif severity == 'CRIT' or severity == 'CRITICAL':
            return syslog.LOG_CRIT
        elif severity == 'ERR' or severity == 'ERROR':
            return syslog.LOG_ERR
        elif severity == 'DEBUG':
            return syslog.LOG_DEBUG
        return syslog.LOG_INFO

    def httpsession_cb(self, session, response):
        if response.result().status_code != 200:
            if not self.fire_and_forget_mode:
                raise MozDefError("HTTP POST failed with code %r" % response.result().status_code)

if __name__ == "__main__":
    print("Testing the MozDef logging module (no msg sent over the network)")
    print("Simple msg:")
    msg = MozDefMsg('https://127.0.0.1/events')
    # This prints out the msg in JSON to stdout
    msg.debug = True
    msg.send('test msg')
    msg.sendToSyslog = True
    msg.send('test syslog msg')

    print("Complex msg:")
    msg.sendToSyslog = False
    msg.send('new test msg', 'authentication', 'CRITICAL', ['bro', 'auth'], {'uid': 0, 'username': 'kang'})
    msg.sendToSyslog = True
    msg.send('new test msg', 'authentication', 'CRITICAL', ['bro', 'auth'], {'uid': 0, 'username': 'kang'})

    print("Modifying timestamp attribute:")
    msg.sendToSyslog = False
    msg.log['timestamp'] = pytz.timezone('Europe/Paris').localize(datetime.now()).isoformat()
    msg.send('another test msg')
    msg.sendToSyslog = True
    msg.send('another test msg')
