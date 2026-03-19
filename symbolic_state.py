from z3 import *
import copy
from analysis_summary import summary

class SymbolicState:
    def __init__(self):
        self.registers = {}
        self.memory = {}
        self.symbolic_inputs = {}
        self.input_sources = {}
        self.tainted = set()
        self.solver = Solver()
        self.constraints_seen = set()
        
        # UPGRADE: Track execution flow
        self.history = [] 
        self.pc = 0 

    def get(self, reg):
        if reg not in self.registers:
            self.registers[reg] = BitVec(reg, 32)
        return self.registers[reg]

    def set(self, reg, value):
        self.registers[reg] = value

    def taint(self, reg):
        self.tainted.add(reg)

    def propagate_taint(self, dst, src):
        if src in self.tainted:
            self.tainted.add(dst)

    def add_constraint(self, constraint):
        # UPGRADE: Added try/except to prevent Z3 type collision crashes
        try:
            key = constraint.sexpr()
            if key in self.constraints_seen: return
            
            self.constraints_seen.add(key)
            summary.add_constraint(constraint)
            self.solver.add(constraint)
        except:
            pass

    def clone(self):
        # We use deepcopy to ensure history and solver are branch-independent
        return copy.deepcopy(self)

    def is_feasible(self):
        return self.solver.check() == sat

    def solve_inputs(self):
        if self.solver.check() != sat: return None
        model = self.solver.model()
        results = {}
        for name, sym in self.symbolic_inputs.items():
            try:
                results[name] = model.eval(sym, model_completion=True)
            except: pass
        return results
