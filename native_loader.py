import zipfile
import os


class NativeLoader:

    def extract_native_libs(self, apk_path):

        libs = []

        with zipfile.ZipFile(apk_path, 'r') as apk:

            for f in apk.namelist():

                if f.startswith("lib/") and f.endswith(".so"):

                    out = os.path.basename(f)

                    with open(out, "wb") as fp:
                        fp.write(apk.read(f))

                    libs.append(out)

        return libs
