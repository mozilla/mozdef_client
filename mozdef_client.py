#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2014 Mozilla Corporation
# Author: gdestuynder@mozilla.com
# Author: ameihm@mozilla.com

import os
import sys
from datetime import datetime
import pytz
import json
import socket
import syslog

# http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/limits-messages.html
SQS_MAX_MESSAGE_SIZE = 256 * 1024

try:
    from requests_futures.sessions import FuturesSession as Session
    futures_loaded = True
except ImportError:
    from requests import Session
    futures_loaded = False
try:
    import boto3
    boto_loaded = True
except ImportError:
    boto_loaded = False

class MozDefError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return repr(self.msg)

class MozDefMessage(object):
    # Supported message types
    MSGTYPE_NONE            = 0
    MSGTYPE_EVENT           = 1
    MSGTYPE_COMPLIANCE      = 2
    MSGTYPE_VULNERABILITY   = 3
    MSGTYPE_ASSETHINT       = 4
    MSGTYPE_RRA             = 5

    def __init__(self, url):
        """This class is the new base class for MozDef messages. All other
        classes besides MozDefMsg derive from this class or from classes
        derived from this class (like MozDevEvent). This class shouldn't be
        used directly and the derived classes should be used instead.

        Note the very similar name between this class and the MozDefMsg
        class but the differing purposes between the two classes (see the
        MozDefMsg docstring)
        """
        self._msgtype = self.MSGTYPE_NONE

        self.log = {}
        self._sendlog = {}

        self._httpsession = Session()
        self._httpsession.trust_env = False
        self._url = url
        self.hostname = socket.getfqdn()
        # This is due to some systems incorrectly
        # setting the hostname field to localhost.localdomain
        # so, we add logic to use a different 'hostname' method
        # if that's the case
        if self.hostname == 'localhost.localdomain':
            self.hostname = socket.gethostname()

        # Set some default options
        self._send_to_syslog = False
        self._send_to_sqs = False
        self._syslog_only = False
        self._fire_and_forget = False
        self._verify_certificate = False
        self._verify_path = None

    def validate(self):
        return True

    def validate_log(self):
        return True

    def set_verify(self, f):
        self._verify_certificate = f

    def set_verify_path(self, p):
        self._verify_path = p

    def set_fire_and_forget(self, f):
        self._fire_and_forget = f

    def set_sqs_queue_name(self, f):
        self._sqs_queue_name = f

    def set_sqs_aws_account_id(self, f):
        self._sqs_aws_account_id = f

    def set_sqs_region(self, f):
        self._sqs_region = f

    def set_send_to_sqs(self, f):
        self._send_to_sqs = f

    def set_send_to_syslog(self, f, only_syslog=False):
        self._send_to_syslog = f
        self._syslog_only = only_syslog

    def syslog_convert(self):
        raise MozDefError('message type does not support syslog conversion')

    def construct(self):
        raise MozDefError('subclass of MozDefMessage must override construct()')

    def _httpsession_cb(self, session, response):
        if response.result().status_code != 200:
            if not self._fire_and_forget:
                raise MozDefError('POST failed with code %r' % \
                    response.result().status_code)

    def send_syslog(self):
        raise MozDefError('message type does not support syslog submission')

    def send(self):
        if not self.validate():
            raise MozDefError('message failed validation')
        self.construct()
        if not self.validate_log():
            raise MozDefError('message failed post construct validation')

        if self._send_to_syslog:
            self.send_syslog()
            if self._syslog_only:
                return

        if self._send_to_sqs:
            self.send_sqs()
            return

        vflag = self._verify_certificate
        if vflag:
            if self._verify_path != None:
                vflag = self._verify_path

        buf = json.dumps(self._sendlog, sort_keys=True, indent=4)
# Compatibility notes:
# When updating either path (futures_loaded or not loaded) please ensure both have the same functionality
# future_loaded is used by Python 2, the non-loaded version if for Python 3
        if futures_loaded:
            self._httpsession.post(self._url, buf,
                verify=vflag,
                background_callback=self._httpsession_cb)
        else:
           response = self._httpsession.post(self._url, buf,
                verify=vflag)
           if response.ok == False:
                if not self._fire_and_forget:
                    raise MozDefError('POST failed with code %r msg %s' % \
                        (response.status_code, response.text))

class MozDefMsg(object):
    def __init__(self, hostname, summary=None, category='event',
        severity='INFO', tags=[], details={}):
        """This class is a compatibility layer for code which uses the older
        MozDefMsg class interface. This class can be used to send messages
        to MozDef and is an alternative to the new classes (like MozDefEvent)
        which inherit MozDefMessage.

        Under the hood, this class instantiates a MozDefEvent object to build
        and send the message to MozDef. The MozDefEvent class is derived from
        the MozDefMessage class

        This class provides the simpler original interface but lacks message
        validation like the newer classes for specific types of messages.

        Note the very similar name between this class and the MozDefMessage
        class but the differing purposes between the two classes (see the
        MozDefMessage docstring)
        """
        self.summary = summary
        self.category = category
        self.details = details
        self.tags = tags
        self.severity = severity
        self.hostname = hostname

        self.log = {}
        self.log['details'] = {}
        self.log['tags'] = []

        self.fire_and_forget_mode = False
        self.verify_certificate = True
        self.sendToSyslog = False
        self.sendToSqs = False
        self.sqsQueueName = None
        self.sqsAWSAccountId = None
        self.sqsRegion = None
        self.syslogOnly = False

    def send(self, summary=None, category=None, severity=None, tags=None,
        details=None):
        tsummary = summary
        tcategory = category
        tseverity = severity
        ttags = tags
        tdetails = details

        if tsummary == None:
            tsummary = self.summary
        if tcategory == None:
            tcategory = self.category
        if tseverity == None:
            tseverity = self.severity
        if ttags == None:
            ttags = self.tags
        if tdetails == None:
            tdetails = self.details

        amsg = MozDefEvent(self.hostname)
        amsg.set_simple_update_log(self.log)
        amsg.summary = tsummary
        amsg.tags = ttags
        amsg.details = tdetails

        if type(self.verify_certificate) is str:
            amsg.set_verify(True)
            amsg.set_verify_path(self.verify_certificate)
        else:
            amsg.set_verify(self.verify_certificate)

        amsg.set_fire_and_forget(self.fire_and_forget_mode)

        amsg.set_category(tcategory)
        amsg.set_severity_from_string(tseverity)
        amsg.set_send_to_syslog(self.sendToSyslog,
            only_syslog=self.syslogOnly)
        amsg.set_sqs_queue_name(self.sqsQueueName)
        amsg.set_sqs_aws_account_id(self.sqsAWSAccountId)
        amsg.set_sqs_region(self.sqsRegion)
        amsg.set_send_to_sqs(self.sendToSqs)

        amsg.send()

class MozDefVulnerability(MozDefMessage):
    def validate_log(self):
        for k in ['utctimestamp', 'description', 'vuln', 'asset',
            'sourcename']:
            if k not in self._sendlog.keys():
                return False
        for k in ['assetid', 'ipv4address', 'hostname', 'macaddress']:
            if k not in self._sendlog['asset'].keys():
                return False
        for k in ['status', 'vulnid', 'title', 'discovery_time', 'age_days',
            'known_malware', 'known_exploits', 'cvss', 'cves']:
            if k not in self._sendlog['vuln'].keys():
                return False
        return True

    def construct(self):
        self._sendlog = self.log

    def __init__(self, url):
        MozDefMessage.__init__(self, url)
        self._msgtype = self.MSGTYPE_VULNERABILITY

class MozDefEvent(MozDefMessage):
    SEVERITY_INFO = 0
    SEVERITY_WARNING = 1
    SEVERITY_CRITICAL = 2
    SEVERITY_ERROR = 3
    SEVERITY_DEBUG = 4

    _sevmap = {
        SEVERITY_INFO: ['INFO', syslog.LOG_INFO],
        SEVERITY_WARNING: ['WARNING', syslog.LOG_WARNING],
        SEVERITY_CRITICAL: ['CRITICAL', syslog.LOG_CRIT],
        SEVERITY_ERROR: ['ERROR', syslog.LOG_ERR],
        SEVERITY_DEBUG: ['DEBUG', syslog.LOG_DEBUG],
    }

    def __init__(self, url):
        MozDefMessage.__init__(self, url)
        self._msgtype = self.MSGTYPE_EVENT
        self._category = 'event'
        self._process_name = sys.argv[0]
        self._process_id = os.getpid()
        self._severity = self.SEVERITY_INFO
        self.timestamp = None

        self._updatelog = None

        self.summary = None
        self.tags = []
        self.details = {}

    def validate(self):
        if self.summary == None or self.summary == '':
            return False
        return True

    def set_simple_update_log(self, l):
        self._updatelog = l

    def set_severity(self, x):
        self._severity = x

    def set_category(self, x):
        self._category = x

    def set_severity_from_string(self, x):
        self._severity = self.SEVERITY_INFO
        for i in self._sevmap:
            if self._sevmap[i][0] == x:
                self._severity = i

    def syslog_convert(self):
        s = json.dumps(self._sendlog)
        return s

    def send_syslog(self):
        syspri = syslog.LOG_INFO
        for i in self._sevmap:
            if i == self._severity:
                syspri = self._sevmap[i][1]
        syslog.syslog(self.syslog_convert())

    def send_sqs(self):
        if not boto_loaded:
            raise ImportError("boto3 not loaded")

        boto3.setup_default_session(region_name=self._sqs_region)
        sqs = boto3.resource('sqs')
        if (self._sqs_aws_account_id != None):
            queue = sqs.get_queue_by_name(QueueName=self._sqs_queue_name,
                    QueueOwnerAWSAccountId=self._sqs_aws_account_id)
        else:
            queue = sqs.get_queue_by_name(QueueName=self._sqs_queue_name)
        message_body = json.dumps(self._sendlog)
        if len(message_body) > SQS_MAX_MESSAGE_SIZE:
            raise MozDefError(
                'message length of %s is over the SQS maximum allowed message '
                'size of %s' % (len(message_body), SQS_MAX_MESSAGE_SIZE))
        try:
            response = queue.send_message(MessageBody=message_body)
        except (botocore.exceptions.ClientError,
                botocore.parsers.ResponseParserError) as e:
            raise MozDefError(
                'message failed to send to SQS due to %s' % e)
        return response

    def construct(self):
        self._sendlog = {}
        if self._updatelog != None:
            self._sendlog = self._updatelog
        if self.timestamp == None:
            self._sendlog['timestamp'] = \
                pytz.timezone('UTC').localize(datetime.utcnow()).isoformat()
        else:
            self._sendlog['timestamp'] = self.timestamp

        self._sendlog['processid'] = self._process_id
        self._sendlog['processname'] = self._process_name
        self._sendlog['hostname'] = self.hostname
        self._sendlog['category'] = self._category
        self._sendlog['details'] = self.details
        self._sendlog['summary'] = self.summary
        self._sendlog['tags'] = self.tags

        for i in self._sevmap:
            if i == self._severity:
                self._sendlog['severity'] = self._sevmap[i][0]


class MozDefRRA(MozDefEvent):
    def validate(self):
        if not MozDefEvent.validate(self):
            return False
        if self.category != 'rra_data':
            return False
        if len(self.details.keys()) == 0:
            return False
        return True

    def __init__(self, url):
        MozDefEvent.__init__(self, url)
        self._msgtype = self.MSGTYPE_RRA
        self._category = 'rra_data'

class MozDefAssetHint(MozDefEvent):
    def validate(self):
        if not MozDefEvent.validate(self):
            return False
        # A hint event should always have details
        if len(self.details.keys()) == 0:
            return False
        return True

    def __init__(self, url):
        MozDefEvent.__init__(self, url)
        self._msgtype = self.MSGTYPE_ASSETHINT
        self._category = 'asset_hint'

class MozDefCompliance(MozDefEvent):
    def validate_log(self):
        if 'details' not in self._sendlog:
            return False
        t = self._sendlog['details']
        for k in ['target', 'policy', 'check', 'compliance', 'link',
            'utctimestamp']:
            if k not in t.keys():
                return False
        for k in ['level', 'name', 'url']:
            if k not in t['policy'].keys():
                return False
        for k in ['description', 'location', 'name', 'test']:
            if k not in t['check'].keys():
                return False
        for k in ['type', 'value']:
            if k not in t['check']['test'].keys():
                return False
        return True

    def __init__(self, url):
        MozDefEvent.__init__(self, url)
        self._msgtype = self.MSGTYPE_COMPLIANCE
        self._category = 'complianceitems'