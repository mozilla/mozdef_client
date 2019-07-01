from mozdef_client import MozDefCompliance


class TestMozDefCompliance():

    def setup(self):
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

    def test_init(self):
        compliance = MozDefCompliance('http://127.0.0.1')
        assert compliance.validate() is False
        compliance.summary = 'compliance item'
        assert compliance.validate() is True
        compliance.construct()
        assert compliance.validate_log() is False
        compliance.details = self.compmsg
        compliance.construct()
        assert compliance.validate_log() is True

    def test_syslog_convert(self):
        compliance = MozDefCompliance('http://127.0.0.1')
        compliance.log = self.compmsg
        assert compliance.syslog_convert() is not None

    def test_syslog_send(self):
        compliance = MozDefCompliance('http://127.0.0.1')
        compliance.summary = 'compliance item'
        compliance.details = self.compmsg
        compliance.set_send_to_syslog(True, only_syslog=True)
        compliance.send()
