import json
import socket

from .error import MozDefError


try:
    from requests_futures.sessions import FuturesSession as Session
    futures_loaded = True
except ImportError:
    from requests import Session
    futures_loaded = False


class MozDefMessage(object):
    # Supported message types
    MSGTYPE_NONE = 0
    MSGTYPE_EVENT = 1
    MSGTYPE_COMPLIANCE = 2
    MSGTYPE_VULNERABILITY = 3
    MSGTYPE_ASSETHINT = 4
    MSGTYPE_RRA = 5

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
        self._httpsession.hooks['response'].append(self._httpsession_cb)
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
            self._httpsession.post(self._url, buf, verify=vflag)
        else:
           response = self._httpsession.post(self._url, buf, verify=vflag)
           if response.ok == False:
                if not self._fire_and_forget:
                    raise MozDefError('POST failed with code %r msg %s' % \
                        (response.status_code, response.text))
