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
# Message types, safe guards
    MSGTYPE_NONE = 0
    MSGTYPE_EVENT = 1
    MSGTYPE_COMPLIANCE = 2
    MSGTYPE_VULNERABILITY = 3
    msgtype = MSGTYPE_NONE #unitinialized

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

    log = {}

    def init(self, *kargs):
        self.log = {}
        self.msgtype = self.MSGTYPE_NONE
        self.__init__(kargs)

    def __init__(self, mozdef_hostname, summary=None, category='event', severity='INFO', tags=[], details={}):
        self.summary = summary
        self.category = category
        self.severity = severity
        self.tags = tags
        self.details = details
        self.mozdef_hostname = mozdef_hostname

    def check_msgtype(self, owntype):
        if self.msgtype != self.MSGTYPE_NONE and self.msgtype != owntype:
            raise MozDefError('Please call init() again to change message type')
        else:
            self.msgtype = owntype

    def send(self, *kargs):
        self.send_event(kargs)

    def send_event(self, summary=None, category=None, severity=None, tags=None, details=None):
        self.check_msgtype(self.MSGTYPE_EVENT)
        self.log['timestamp'] = pytz.timezone('UTC').localize(datetime.utcnow()).isoformat()
        self.log['hostname']    = socket.getfqdn()
        self.log['processid']   = os.getpid()
        self.log['processname'] = sys.argv[0]
        self.log['severity']    = 'INFO'
        self.log['summary']     = None
        self.log['category']    = 'event'
        self.log['tags']        = list()
        self.log['details']     = dict()

        if summary == None: self.log['summary'] = self.summary
        else:               self.log['summary'] = summary

        if category == None: self.log['category'] = self.category
        else:                self.log['category'] = category

        if severity == None: self.log['severity'] = self.severity
        else:                self.log['severity'] = severity

        if tags == None: self.log['tags'] = self.tags
        else:            self.log['tags'] = tags

        if details == None: self.log['details'] = self.details
        else:               self.log['details'] = details

        if type(self.log['details']) != dict:
            raise MozDefError('details must be a dict')
        elif type(self.log['tags']) != list:
            raise MozDefError('tags must be a list')
        elif self.log['summary'] == None:
            raise MozDefError('Summary is a required field')

        self._send()

    def send_vulnerability(self, vulnmsg):
# Send a vulnerability event. We basically just do validation that all the required
# fields are set here, the message argument is not modified.
        def validate_vulnerability(message):
            for k in ['utctimestamp', 'description', 'vuln', 'asset']:
                if k not in message.keys():
                    return False
            for k in ['assetid', 'ipv4address', 'hostname', 'macaddress']:
                if k not in message['asset'].keys():
                    return False
            for k in ['status', 'vulnid', 'title', 'discovery_time', 'age_days',
                      'known_malware', 'known_exploits', 'cvss', 'cves']:
                if k not in message['vuln'].keys():
                    return False
            return True

        self.check_msgtype(self.MSGTYPE_VULNERABILITY)
        self.log = vulnmsg
        if not validate_vulnerability(self.log):
            raise MozDefError('message failed validation, check your fields')
        self._send()

    def send_compliance(self, target, policy, check, compliance, link="", tags=None):
        self.check_msgtype(self.MSGTYPE_COMPLIANCE)
        def validate_compliance(message):
            """
            Validate required fields are set in the compliance message; this function
            should align with the associated validation routine within the MozDef
            compliance item custom plugin
            """
            for key in ['target', 'policy', 'check', 'compliance',
                        'link', 'utctimestamp']:
                if key not in message.keys():
                    return False
            for key in ['level', 'name', 'url']:
                if key not in message['policy'].keys():
                    return False
            for key in ['description', 'location', 'name', 'test']:
                if key not in message['check'].keys():
                    return False
            for key in ['type', 'value']:
                if key not in message['check']['test'].keys():
                    return False
            return True

        self.log['target'] = target
        self.log['policy'] = policy
        self.log['check'] = check
        self.log['compliance'] = compliance
        self.log['link'] = link
        if tags != None:
            self.log['tags'] = tags
        self.log['utctimestamp'] = pytz.timezone('UTC').localize(datetime.utcnow()).isoformat()

        if not validate_compliance(self.log):
            raise MozDefError('message failed validation, check your fields')

        self._send()

    def _send(self):
        if self.debug:
            print(json.dumps(self.log, sort_keys=True, indent=4))

        if not self.syslogOnly:
            try:
                if futures_loaded:
                    r = self.httpsession.post(self.mozdef_hostname, json.dumps(self.log, sort_keys=True, indent=4),
                            verify=self.verify_certificate, background_callback=self.httpsession_cb)
                else:
                    r = self.httpsession.post(self.mozdef_hostname, json.dumps(self.log, sort_keys=True, indent=4),
                            verify=self.verify_certificate)

            except Exception as e:
                if not self.fire_and_forget_mode:
                    raise e

        if self.sendToSyslog:
            syslog_msg = ''
            syslog_severity = syslog.LOG_INFO
            for i in self.log:
# If present and if possible convert severity to a syslog field
                if i == 'severity':
                    syslog_severity = self.str_to_syslog_severity(self.log[i])
                    continue
# These fields are already populated by syslog
                if i == 'hostname' or i == 'processid' or i == 'timestamp' or i == 'utctimestamp' or i == 'processname':
                    continue
                syslog_msg += str(i)+': \''+str(self.log[i])+'\' '
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
    print("Simple msg using compat function:")
    msg = MozDefMsg('https://127.0.0.1/events')
    # This prints out the msg in JSON to stdout
    msg.debug = True
    msg.send('test msg')
    msg.sendToSyslog = True
    msg.send('test syslog msg')

    print("Complex msg:")
    msg.sendToSyslog = False
    msg.send_event('new test msg', 'authentication', 'CRITICAL', ['bro', 'auth'], {'uid': 0, 'username': 'kang'})
    msg.sendToSyslog = True
    msg.send_event('new test msg', 'authentication', 'CRITICAL', ['bro', 'auth'], {'uid': 0, 'username': 'kang'})

    print("Modifying timestamp attribute:")
    msg.sendToSyslog = False
    msg.log['timestamp'] = pytz.timezone('Europe/Paris').localize(datetime.now()).isoformat()
    msg.send_event('another test msg')
    msg.sendToSyslog = True
    msg.send_event('another test msg')

    print("Sending compliance message")
    msg.init('https://127.0.0.1/compliance')
    check = {
            'name': 'SSH root login',
            'test': {
                'type': 'Unknown',
                'value': 'grep RootLogin'
                },
            'location': 'Unknown',
            'description': 'Checks for ssh root login off',
            }
    policy = {
            'level': 'low',
            'name': 'System policy',
            'url': 'https://www.example.com/systempolicy/'
            }
    msg.send_compliance("agent.mozdef.com", policy, check, False,
                        "https://www.example.com/systempolicy/compliance_check_one")
