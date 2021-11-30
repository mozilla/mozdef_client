import os
import sys
from datetime import datetime
import pytz
import json
import syslog

from .message import MozDefMessage
from .error import MozDefError

# http://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/limits-messages.html
SQS_MAX_MESSAGE_SIZE = 256 * 1024

try:
    import boto3
    boto_loaded = True
except ImportError:
    boto_loaded = False


class MozDefEvent(MozDefMessage):
    SEVERITY_DEBUG = 0
    SEVERITY_INFO = 1
    SEVERITY_NOTICE = 2
    SEVERITY_WARNING = 3
    SEVERITY_ERROR = 4
    SEVERITY_CRITICAL = 5
    SEVERITY_ALERT = 6
    SEVERITY_EMERGENCY = 7

    _sevmap = {
        SEVERITY_DEBUG: ['DEBUG', syslog.LOG_DEBUG],
        SEVERITY_INFO: ['INFO', syslog.LOG_INFO],
        SEVERITY_NOTICE: ['NOTICE', syslog.LOG_NOTICE],
        SEVERITY_WARNING: ['WARNING', syslog.LOG_WARNING],
        SEVERITY_ERROR: ['ERROR', syslog.LOG_ERR],
        SEVERITY_CRITICAL: ['CRITICAL', syslog.LOG_CRIT],
        SEVERITY_ALERT: ['ALERT', syslog.LOG_ALERT],
        SEVERITY_EMERGENCY: ['EMERGENCY', syslog.LOG_EMERG],

    }

    def __init__(self, url):
        MozDefMessage.__init__(self, url)
        self._msgtype = self.MSGTYPE_EVENT
        self._category = 'event'
        self._source = None
        self._process_name = sys.argv[0]
        self._process_id = os.getpid()
        self._severity = self.SEVERITY_INFO
        self.timestamp = None

        self._updatelog = None

        self.summary = None
        self.tags = []
        self.details = {}

    def validate(self):
        if self.summary is None or self.summary == '':
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
        # syspri = syslog.LOG_INFO
        # for i in self._sevmap:
            # if i == self._severity:
                # syspri = self._sevmap[i][1]
        syslog.openlog()
        syslog.syslog(self.syslog_convert())

    def send_sqs(self):
        if not boto_loaded:
            raise ImportError("boto3 not loaded")

        boto3.setup_default_session(region_name=self._sqs_region)
        sqs = boto3.resource('sqs')
        if (self._sqs_aws_account_id is not None):
            queue = sqs.get_queue_by_name(QueueName=self._sqs_queue_name, QueueOwnerAWSAccountId=self._sqs_aws_account_id)
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
        self._sendlog['source'] = self._source
        self._sendlog['details'] = self.details
        self._sendlog['summary'] = self.summary
        self._sendlog['tags'] = self.tags

        for i in self._sevmap:
            if i == self._severity:
                self._sendlog['severity'] = self._sevmap[i][0]
