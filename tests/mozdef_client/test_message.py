import pytest

from mozdef_client import MozDefMessage, MozDefError


class TestMozDefMessage():
    def test_send(self):
        message = MozDefMessage('http://127.0.0.1')
        with pytest.raises(MozDefError):
            message.send()

    def test_hostname(self):
        message = MozDefMessage('http://127.0.0.1')
        assert message is not None
        assert message.hostname is not None
        assert message._url == 'http://127.0.0.1'
        message.hostname = 'examplehostname'
        assert message.hostname == 'examplehostname'
