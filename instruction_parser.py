class InstructionParser:

    def get_instructions(self, method_analysis):

        method = method_analysis.get_method()

        # Skip external methods (Android framework)
        if not hasattr(method, "get_code"):
            return []

        code = method.get_code()

        if code is None:
            return []

        bc = code.get_bc()

        if bc is None:
            return []

        instructions = []

        for instr in bc.get_instructions():
            instructions.append(instr)

        return instructions
