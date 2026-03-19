from z3 import *
import re
from analysis_summary import summary

SOURCES = ["getText", "getStringExtra", "getExtras", "readLine", "nextLine", "getInputStream", "getBytes", "getParameter"]

class DalvikInterpreter:
    def execute(self, instr, state, method_name):
        try:
            name = instr.get_name()
            out = instr.get_output()
        except:
            return [state]

        # TRACKING THE "WHERE": Store the instruction in the state path
        state.history.append((state.pc, str(instr)))

        if not out: return [state]

        if name.startswith("move"):
            parts = out.split()
            if len(parts) >= 2:
                dst = parts[0].replace(",", "")
                src = parts[1]
                state.set(dst, state.get(src))
                state.propagate_taint(dst, src)
            return [state]

        # UPGRADE: Added const-string parser to grab hardcoded app strings
        elif name.startswith("const-string"):
            parts = out.split(",")
            if len(parts) >= 2:
                reg = parts[0].strip()
                val = parts[1].strip().strip('"')
                state.set(reg, StringVal(val))
            return [state]

        elif name.startswith("const"):
            parts = out.split(",")
            if len(parts) >= 2:
                reg = parts[0].strip()
                val = parts[1].strip()
                try:
                    val = int(val, 16) if "0x" in val else int(val)
                    state.set(reg, BitVecVal(val, 32))
                except: pass
            return [state]

        elif name.startswith("if"):
            # The 'Why': Branches create the constraints
            parts = re.split('[, ]+', out)
            if len(parts) < 2: return [state]
            v1, v2 = state.get(parts[0]), state.get(parts[1])
            
            t_state, f_state = state.clone(), state.clone()
            
            # UPGRADE: Handle cases where Z3 can't compare an Int to a String
            try:
                t_state.add_constraint(v1 == v2)
                f_state.add_constraint(v1 != v2)
            except Z3Exception:
                return [state]
            
            res = []
            if t_state.is_feasible(): res.append(t_state)
            if f_state.is_feasible(): res.append(f_state)
            return res

        elif name.startswith("invoke"):
            for src_api in SOURCES:
                if src_api in out:
                    method_short = method_name.split("->")[-1].split("(")[0]
                    
                    # UPGRADE: Use the Instruction PC instead of a global counter
                    # This completely eliminates the 60x duplicate bug!
                    sym_name = f"sym_{method_short}_{src_api}_PC{state.pc}"

                    # UPGRADE: Use Z3 String instead of BitVec for text
                    sym_var = String(sym_name)
                    summary.add_input(sym_name)

                    state.symbolic_inputs[sym_name] = sym_var
                    state.input_sources[sym_name] = {
                        "method": method_name,
                        "instruction": out,
                        "register": "v0"
                    }

                    state.set("v0", sym_var)
                    state.taint("v0")
                    return [state]
            return [state]

        return [state]
