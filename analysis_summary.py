from z3 import *

class AnalysisSummary:
    def __init__(self):
        self.entry_points = []
        self.symbolic_methods = []
        self.symbolic_inputs = []
        self.constraints = []
        self.results = [] # Now stores dicts with path info
        self.native_libs = []
        self.package = "Unknown"

    def add_entry(self, entry):
        if entry not in self.entry_points:
            self.entry_points.append(entry)

    def add_method(self, method):
        if method not in self.symbolic_methods:
            self.symbolic_methods.append(method)

    def add_input(self, inp):
        if inp not in self.symbolic_inputs:
            self.symbolic_inputs.append(inp)

    def add_constraint(self, constraint):
        self.constraints.append(str(constraint))

    def add_result(self, result_dict):
        # Upgrade: Store full context instead of just a string
        self.results.append(result_dict)

    def add_native(self, lib):
        self.native_libs.append(lib)

    def print_summary(self):
        print("\n" + "="*20 + " UPGRADED ANALYSIS SUMMARY " + "="*20)
        print(f"Package: {self.package}")
        
        print("\n[+] Entry Points Detected:")
        for e in self.entry_points:
            print(f"  -> {e}")

        print("\n[+] Vulnerabilities & Logic Bypasses:")
        for r in self.results:
            print(f"\n  TYPE: {r.get('type', 'Logic Flaw')}")
            print(f"  LOCATION: {r.get('method')}")
            print(f"  EXPLANATION: {r.get('details')}")
            
            # UPGRADE: Print the translated human-readable summary
            if 'human_summary' in r:
                print(f"  SIMPLIFIED FLOW: {r.get('human_summary')}")
                
            print(f"  SOLVER PAYLOAD: {r.get('model')}")
            
            if 'path' in r:
                print("  EXECUTION TRACE (The 'How'):")
                for step in r['path']:
                    print(f"    [at PC {step[0]}] {step[1]}")

        print("\n" + "="*60 + "\n")

    def print_input_details(self, states_list=None):
        # Refined version to show specific input sources
        print("\n" + "="*20 + " SYMBOLIC INPUT PROVENANCE " + "="*20)
        if not self.symbolic_inputs:
            print("No symbolic inputs tracked.")
            return

        for inp in self.symbolic_inputs:
            print(f"Input Name: {inp}")
        print("="*60 + "\n")

summary = AnalysisSummary()
