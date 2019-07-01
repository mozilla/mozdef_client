from .event import MozDefEvent


class MozDefRRA(MozDefEvent):
    def validate(self):
        if not MozDefEvent.validate(self):
            return False
        if self.category != 'rra_data':
            return False
        if len(self.details.keys()) == 0:
            return False
        return True

    def __init__(self, url):
        MozDefEvent.__init__(self, url)
        self._msgtype = self.MSGTYPE_RRA
        self._category = 'rra_data'
