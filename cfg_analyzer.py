class CFGAnalyzer:

    def build_cfg(self, method):

        # skip external methods
        try:
            code = method.get_code()
        except:
            return {}, []

        if code is None:
            return {}, []

        try:
            bc = code.get_bc()
            instructions = list(bc.get_instructions())
        except:
            return {}, []

        cfg = {}

        for i, instr in enumerate(instructions):

            name = instr.get_name()

            edges = []

            if name.startswith("if"):

                edges.append(i + 1)
                edges.append(i + 2)

            elif name.startswith("goto"):

                edges.append(i + 1)

            else:

                edges.append(i + 1)

            cfg[i] = edges

        return cfg, instructions
