class JNIDetector:

    def find_native_methods(self, dx):

        natives = []

        for m in dx.get_methods():

            method = m.get_method()

            if "native" in str(method):

                natives.append(method)

        return natives
