from androguard.misc import AnalyzeAPK


class APKAnalyzer:

    def __init__(self, apk_path):
        self.apk_path = apk_path

    def analyze(self):
        print("[*] Loading APK...")

        a, d, dx = AnalyzeAPK(self.apk_path)

        print("[+] Package:", a.get_package())
        print("[+] Main Activity:", a.get_main_activity())

        return a, d, dx


    def list_methods(self, dx):

        print("[*] Discovering methods...")

        methods = []

        for method in dx.get_methods():
            m = method.get_method()
            methods.append(m)

        print("[+] Total methods:", len(methods))

        return methods
