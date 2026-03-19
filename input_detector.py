class InputDetector:

    SOURCES = [
        "getIntent",
        "getStringExtra",
        "getText",
        "readLine",
        "nextLine"
    ]

    def detect_inputs(self, method):

        code = str(method)

        inputs = []

        for src in self.SOURCES:
            if src in code:
                inputs.append(src)

        return inputs
