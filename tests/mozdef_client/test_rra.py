from mozdef_client import MozDefRRA


class TestMozDefRRA():
    def test_init(self):
        rra = MozDefRRA('http://127.0.0.1')
        assert rra._url == 'http://127.0.0.1'

    def test_validate(self):
        rra = MozDefRRA('http://127.0.0.1')
        assert rra.validate() is False
        rra.summary = 'an RRA event'
        rra.category = 'rra_data'
        assert rra.validate() is False
        rra.details = {'metadata': {'service': 'test'}}
        assert rra.validate() is True
