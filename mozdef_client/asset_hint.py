from .event import MozDefEvent


class MozDefAssetHint(MozDefEvent):
    def validate(self):
        if not MozDefEvent.validate(self):
            return False
        # A hint event should always have details
        if len(self.details.keys()) == 0:
            return False
        return True

    def __init__(self, url):
        MozDefEvent.__init__(self, url)
        self._msgtype = self.MSGTYPE_ASSETHINT
        self._category = 'asset_hint'
