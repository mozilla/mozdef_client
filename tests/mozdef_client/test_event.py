import pytest

from mozdef_client import MozDefEvent


class TestMozDefEvent():
    def test_init(self):
        event = MozDefEvent('http://127.0.0.1')
        assert event._msgtype == 1
        assert event.hostname is not None
        assert event._url == 'http://127.0.0.1'

    def test_bad_send(self):
        event = MozDefEvent('http://127.0.0.1:1/nonexistent')
        with pytest.raises(Exception):
            event.send()

    def test_validate(self):
        event = MozDefEvent('http://127.0.0.1')
        assert event.validate() is False
        event.summary = 'test event'
        assert event.validate() is True

    def test_construct(self):
        event = MozDefEvent('http://127.0.0.1')
        event.summary = 'test event'
        event.construct()
        assert event._sendlog['category'] == 'event'
        assert event._sendlog['summary'] == 'test event'

    def test_event_hostname(self):
        event = MozDefEvent('http://127.0.0.1')
        assert event.hostname != 'examplehostname'
        event.hostname = 'examplehostname'
        assert event.hostname == 'examplehostname'

    def test_event_syslog(self):
        emsg_summary = 'a test event'
        emsg_tags = ['generic', 'test']
        emsg_details = {'one': 1, 'two': 'two'}
        event = MozDefEvent('http://127.0.0.1')
        event.summary = emsg_summary
        event.tags = emsg_tags
        event.details = emsg_details
        event.set_severity(MozDefEvent.SEVERITY_CRITICAL)
        event.construct()
        assert event.syslog_convert() is not None
        event.set_send_to_syslog(True, only_syslog=True)
        event.send()
