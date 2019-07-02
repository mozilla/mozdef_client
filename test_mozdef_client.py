import unittest
from mozdef_client import MozDefMessage
from mozdef_client import MozDefError
from mozdef_client import MozDefEvent
from mozdef_client import MozDefVulnerability
from mozdef_client import MozDefCompliance
from mozdef_client import MozDefAssetHint
from mozdef_client import MozDefRRA
from mozdef_client import MozDefMsg
from mozdef_client import boto_loaded


class MozDefTests(unittest.TestCase):
    def create_valid_event(self):
        self.emsg_summary = 'a test event'
        self.emsg_tags = ['generic', 'test']
        self.emsg_details = {'one': 1, 'two': 'two'}

    def create_valid_vuln(self):
        self.vulnmsg = {}
        self.vulnmsg['description'] = 'system vulnerability management ' \
            'automation'
        self.vulnmsg['utctimestamp'] = '2015-01-21T15:33:51.136378+00:00'
        self.vulnmsg['sourcename'] = 'development'
        self.vulnmsg['asset'] = {}
        self.vulnmsg['asset']['assetid'] = 23
        self.vulnmsg['asset']['ipv4address'] = '1.2.3.4'
        self.vulnmsg['asset']['macaddress'] = ''
        self.vulnmsg['asset']['hostname'] = 'git.mozilla.com'
        self.vulnmsg['vuln'] = {}
        self.vulnmsg['vuln']['status'] = 'new'
        self.vulnmsg['vuln']['vulnid'] = 'nexpose:43883'
        self.vulnmsg['vuln']['title'] = \
            'RHSA-2013:1475: postgresql and postgresql84 security update'
        self.vulnmsg['vuln']['discovery_time'] = 1421845863
        self.vulnmsg['vuln']['age_days'] = 32.7
        self.vulnmsg['vuln']['known_malware'] = False
        self.vulnmsg['vuln']['known_exploits'] = False
        self.vulnmsg['vuln']['cvss'] = 8.5
        self.vulnmsg['vuln']['cves'] = ['CVE-2013-022', 'CVE-2013-1900']

    def create_valid_comp(self):
        self.compmsg = {}
        self.compmsg['target'] = 'www.mozilla.com'
        self.compmsg['utctimestamp'] = '2015-03-04T18:25:52.849272+00:00'
        self.compmsg['tags'] = {
            'operator': 'it',
            'autogroup': 'opsec'
        }
        self.compmsg['compliance'] = True
        self.compmsg['link'] = 'http://a.url'
        self.compmsg['policy'] = {
            'url': 'http://another.url',
            'name': 'system',
            'level': 'medium'
        }
        self.compmsg['check'] = {
            'test': {
                'type': 'nexpose',
                'name': 'assess',
                'value': 'nexpose'
            },
            'location': 'endpoint',
            'ref': 'sysmediumupdates1',
            'name': 'vulnerability scanner check',
            'description': 'validate system patch level'
        }

    def setUp(self):
        self.create_valid_vuln()
        self.create_valid_comp()
        self.create_valid_event()

    def testFailMessageSend(self):
        m = MozDefMessage('http://127.0.0.1')
        with self.assertRaises(MozDefError):
            m.send()

    def testFailEventSend(self):
        m = MozDefEvent('http://127.0.0.1:1/nonexistent')
        with self.assertRaises(Exception):
            m.send()

    def testMozdefMessage(self):
        m = MozDefMessage('http://127.0.0.1')
        self.assertIsNotNone(m)
        self.assertIsNotNone(m.hostname)
        self.assertEqual(m._url, 'http://127.0.0.1')
        m.hostname = 'examplehostname'
        self.assertEqual(m.hostname, 'examplehostname')

    def testMozdefEvent(self):
        m = MozDefEvent('http://127.0.0.1')
        self.assertIsNotNone(m)
        self.assertEqual(m._msgtype, MozDefMessage.MSGTYPE_EVENT)
        self.assertIsNotNone(m.hostname)
        self.assertEqual(m._url, 'http://127.0.0.1')
        m.hostname = 'examplehostname'
        self.assertEqual(m.hostname, 'examplehostname')

    def testMozdefEventValidate(self):
        m = MozDefEvent('http://127.0.0.1')
        self.assertFalse(m.validate())
        m.summary = 'test event'
        self.assertTrue(m.validate())

    def testMozdefEventConstruct(self):
        m = MozDefEvent('http://127.0.0.1')
        m.summary = 'test event'
        m.construct()
        self.assertEqual(m._sendlog['category'], 'event')
        self.assertEqual(m._sendlog['summary'], 'test event')

    def testMozdefEventHostname(self):
        m = MozDefEvent('http://127.0.0.1')
        m.hostname = 'samplehostname'
        self.assertEqual(m.hostname, 'samplehostname')

    def testMozdefVulnValidate(self):
        m = MozDefVulnerability('http://127.0.0.1')
        self.assertTrue(m.validate())
        m.construct()
        self.assertFalse(m.validate_log())
        m.log = self.vulnmsg
        m.construct()
        self.assertTrue(m.validate_log())

    def testMozdefComplianceValidate(self):
        m = MozDefCompliance('http://127.0.0.1')
        self.assertFalse(m.validate())
        m.summary = 'compliance item'
        self.assertTrue(m.validate())
        m.construct()
        self.assertFalse(m.validate_log())
        m.details = self.compmsg
        m.construct()
        self.assertTrue(m.validate_log())

    def testMozdefEventSyslog(self):
        m = MozDefEvent('http://127.0.0.1')
        m.summary = self.emsg_summary
        m.tags = self.emsg_tags
        m.details = self.emsg_details
        m.set_severity(MozDefEvent.SEVERITY_CRITICAL)
        m.construct()
        s = m.syslog_convert()
        self.assertIsNotNone(s)
        m.set_send_to_syslog(True, only_syslog=True)
        m.send()

    def testMozdefCompSyslog(self):
        m = MozDefCompliance('http://127.0.0.1')
        m.log = self.compmsg
        self.assertIsNotNone(m.syslog_convert())

    def testAssetHintValidate(self):
        m = MozDefAssetHint('http://127.0.0.1')
        self.assertFalse(m.validate())
        m.summary = 'an asset hint event'
        self.assertFalse(m.validate())
        m.details = {'hostname': 'test'}
        self.assertTrue(m.validate())

    def testAssetHint(self):
        m = MozDefAssetHint('http://127.0.0.1')
        self.assertIsNotNone(m)

    def testRRAValidate(self):
        m = MozDefRRA('http://127.0.0.1')
        self.assertFalse(m.validate())
        m.summary = 'an RRA event'
        m.category = 'rra_data'
        self.assertFalse(m.validate())
        m.details = {'metadata': {'service': 'test'}}
        self.assertTrue(m.validate())

    def testRRA(self):
        m = MozDefRRA('http://127.0.0.1')
        self.assertIsNotNone(m)

    def testSimpleMsg(self):
        m = MozDefMsg('http://127.0.0.1', tags=['openvpn', 'duosecurity'])
        self.assertIsNotNone(m)

    # def testSimpleSqs(self):
    #     m = MozDefMsg('http://127.0.0.1', tags=['openvpn', 'duosecurity'])
    #     if not boto_loaded:
    #         raise ImportError("Boto3 is not loaded")
    #     m.sendToSqs = True
    #     m.sqsRegion = 'us-west-1'
    #     m.sqsQueueName = 'test'
    #     m.sqsAWSAccountId = 'test'
    #     m.send('hi')
    #     self.assertIsNotNone(m)

    def testSimpleSyslog(self):
        m = MozDefMsg('http://127.0.0.1', tags=['openvpn', 'duosecurity'])
        m.sendToSyslog = True
        m.syslogOnly = True
        m.fire_and_forget_mode = True
        m.log['somefield'] = 'test'
        with self.assertRaises(MozDefError):
            m.send()
        m.send('hi')

    def testSimpleSyslogDetails(self):
        m = MozDefMsg('http://127.0.0.1')
        m.sendToSyslog = True
        m.syslogOnly = True
        m.fire_and_forget_mode = True
        m.send('hi', details={'username': 'user'}, tags=['y0'])

    def testMozdefCompSyslogSend(self):
        m = MozDefCompliance('http://127.0.0.1')
        m.summary = 'compliance item'
        m.details = self.compmsg
        m.set_send_to_syslog(True, only_syslog=True)
        m.send()


if __name__ == "__main__":
    unittest.main(verbosity=2)
