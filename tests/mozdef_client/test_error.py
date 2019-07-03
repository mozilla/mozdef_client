from mozdef_client import MozDefError


class TestMozDefError():
    def test_init(self):
        error_obj = MozDefError('test error')
        assert str(error_obj) == "'test error'"
