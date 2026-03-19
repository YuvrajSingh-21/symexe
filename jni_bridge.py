class JNIBridge:

    def __init__(self, dx):
        self.dx = dx

    def find_native_methods(self):

        natives = []

        for m in self.dx.get_methods():

            method = m.get_method()

            try:

                access = method.get_access_flags_string()

                if "native" in access:

                    natives.append(str(method))

            except:
                pass

        return natives
