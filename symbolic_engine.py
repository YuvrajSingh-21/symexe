from z3 import *

class SymbolicEngine:

    def __init__(self):
        self.solver = Solver()

    def create_symbolic_input(self, name):

        return BitVec(name, 32)

    def execute_branch(self, condition):

        print("[*] Adding constraint:", condition)

        self.solver.add(condition)

    def solve(self):

        if self.solver.check() == sat:
            model = self.solver.model()
            print("[+] Solution:", model)
        else:
            print("[-] Unsatisfiable")
