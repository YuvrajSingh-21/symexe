class MethodSelector:

    def is_interesting(self, method_name):

        keywords = [
            "verify",
            "check",
            "auth",
            "login",
            "password",
            "compare",
            "decrypt",
            "encrypt",
            "validate",
            "secret",
            "token"
        ]

        for k in keywords:

            if k in method_name.lower():
                return True

        return False
