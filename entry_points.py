from androguard.core.apk import APK


class EntryPointDetector:

    def __init__(self, apk_path):
        self.apk = APK(apk_path)

    def get_entry_points(self):

        entries = []

        try:
            entries.extend(self.apk.get_activities())
            entries.extend(self.apk.get_services())
            entries.extend(self.apk.get_receivers())
        except:
            pass

        return entries
