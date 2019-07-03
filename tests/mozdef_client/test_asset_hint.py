from mozdef_client import MozDefAssetHint


class TestMozDefAssetHint():
    def test_init(self):
        asset_hint = MozDefAssetHint('http://localhost')
        assert asset_hint._msgtype == 4
        assert asset_hint._category == 'asset_hint'

    def test_validate_no_details(self):
        asset_hint = MozDefAssetHint('http://localhost')
        assert asset_hint.validate() is False

    def test_validate(self):
        asset_hint = MozDefAssetHint('http://127.0.0.1')
        assert asset_hint.validate() is False
        asset_hint.summary = 'an asset hint event'
        assert asset_hint.validate() is False
        asset_hint.details = {'hostname': 'test'}
        assert asset_hint.validate() is True
