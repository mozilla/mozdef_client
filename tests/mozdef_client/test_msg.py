import pytest

from mozdef_client import MozDefMsg, MozDefError


class TestMozDefMsg():

    def test_init(self):
        msg = MozDefMsg('http://127.0.0.1', tags=['openvpn', 'duosecurity'])
        assert msg.tags == ['openvpn', 'duosecurity']

    # def test_init_sqs(self):
    #     msg = MozDefMsg('http://127.0.0.1', tags=['openvpn', 'duosecurity'])
    #     msg.sendToSqs = True
    #     msg.sqsRegion = 'us-west-1'
    #     msg.sqsQueueName = 'test'
    #     msg.sqsAWSAccountId = 'test'
    #     msg.send('hi')
    #     assert msg is not None

    def test_simple_syslog(self):
        msg = MozDefMsg('http://127.0.0.1', tags=['openvpn', 'duosecurity'])
        msg.sendToSyslog = True
        msg.syslogOnly = True
        msg.fire_and_forget_mode = True
        msg.log['somefield'] = 'test'
        with pytest.raises(MozDefError):
            msg.send()
        msg.send('hi')

    def test_details_syslog(self):
        msg = MozDefMsg('http://127.0.0.1')
        msg.sendToSyslog = True
        msg.syslogOnly = True
        msg.fire_and_forget_mode = True
        msg.send('hi', details={'username': 'user'}, tags=['y0'])
