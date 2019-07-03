from .event import MozDefEvent


class MozDefMsg(object):
    def __init__(self, hostname, summary=None, category='event', severity='INFO', source='mozdef_client', tags=[], details={}):
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
        self.source = source

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

    def send(self, summary=None, category=None, severity=None, tags=None, details=None, source=None):
        tsummary = summary
        tcategory = category
        tseverity = severity
        ttags = tags
        tdetails = details
        tsource = source

        if tsummary is None:
            tsummary = self.summary
        if tcategory is None:
            tcategory = self.category
        if tsource is None:
            tsource = self.source
        if tseverity is None:
            tseverity = self.severity
        if ttags is None:
            ttags = self.tags
        if tdetails is None:
            tdetails = self.details

        amsg = MozDefEvent(self.hostname)
        amsg.set_simple_update_log(self.log)
        amsg.summary = tsummary
        amsg.tags = ttags
        amsg.details = tdetails
        amsg.source = tsource

        if type(self.verify_certificate) is str:
            amsg.set_verify(True)
            amsg.set_verify_path(self.verify_certificate)
        else:
            amsg.set_verify(self.verify_certificate)

        amsg.set_fire_and_forget(self.fire_and_forget_mode)

        amsg.set_category(tcategory)
        amsg.set_severity_from_string(tseverity)
        amsg.set_send_to_syslog(self.sendToSyslog, only_syslog=self.syslogOnly)
        amsg.set_sqs_queue_name(self.sqsQueueName)
        amsg.set_sqs_aws_account_id(self.sqsAWSAccountId)
        amsg.set_sqs_region(self.sqsRegion)
        amsg.set_send_to_sqs(self.sendToSqs)

        amsg.send()
