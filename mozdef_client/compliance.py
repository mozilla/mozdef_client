from .event import MozDefEvent


class MozDefCompliance(MozDefEvent):
    def validate_log(self):
        if 'details' not in self._sendlog:
            return False
        t = self._sendlog['details']
        for k in ['target', 'policy', 'check', 'compliance', 'link', 'utctimestamp']:
            if k not in t.keys():
                return False
        for k in ['level', 'name', 'url']:
            if k not in t['policy'].keys():
                return False
        for k in ['description', 'location', 'name', 'test']:
            if k not in t['check'].keys():
                return False
        for k in ['type', 'value']:
            if k not in t['check']['test'].keys():
                return False
        return True

    def __init__(self, url):
        MozDefEvent.__init__(self, url)
        self._msgtype = self.MSGTYPE_COMPLIANCE
        self._category = 'complianceitems'
