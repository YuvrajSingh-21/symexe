import angr
import claripy
import logging
import networkx as nx
import matplotlib.pyplot as plt
import os
from analysis_summary import summary

logging.getLogger("angr").setLevel(logging.ERROR)

class NativeSymbolicExecutor:

    def analyze(self, so_file):
        print("\n[+] Starting symbolic execution of native library:", so_file)
        summary.add_native(so_file)

        try:
            # load_options={'auto_load_libs': False} ensures we only analyze the specific library
            project = angr.Project(so_file, auto_load_libs=False)
        except Exception as e:
            print("[!] Failed to load library:", e)
            return

        # --- PICTORIAL GRAPH GENERATION ---
        self.generate_pictorial_graph(project, so_file)

        # --- SYMBOLIC EXPLORATION ---
        input_len = 32
        sym_input = claripy.BVS("input", 8 * input_len)
        state = project.factory.entry_state()
        state.memory.store(0x100000, sym_input)

        for i in range(input_len):
            byte = sym_input.get_byte(i)
            state.solver.add(byte >= 0x20)
            state.solver.add(byte <= 0x7e)

        simgr = project.factory.simulation_manager(state)
        print("[+] Exploring native execution paths...")

        try:
            simgr.explore(find=self.is_success, avoid=self.is_failure)
        except Exception as e:
            print("[!] Symbolic exploration error:", e)
            return

        if simgr.found:
            found = simgr.found[0]
            solution = found.solver.eval(sym_input, cast_to=bytes)
            try:
                solution = solution.decode(errors="ignore")
            except:
                pass
            print("\n🎉 SECRET FOUND:", solution)
            summary.add_result("Native secret: " + str(solution))
        else:
            print("[-] Secret not discovered")

    def generate_pictorial_graph(self, project, so_file):
        """Generates a visual representation of the native function callgraph."""
        print(f"[*] Generating pictorial call graph for: {os.path.basename(so_file)}")
        
        try:
            # Fast CFG generation for visualization
            cfg = project.analyses.CFGFast()
            callgraph = cfg.kb.functions.callgraph

            plt.figure(figsize=(12, 8))
            plt.title(f"Call Graph: {os.path.basename(so_file)}")

            # Create layout and draw nodes/edges
            pos = nx.spring_layout(callgraph, k=0.3)
            nx.draw(callgraph, pos, with_labels=True, 
                    node_color='skyblue', node_size=1500, 
                    edge_color='gray', font_size=7, 
                    arrows=True)

            output_name = f"graph_{os.path.basename(so_file)}.png"
            plt.savefig(output_name)
            plt.close()
            print(f"[+] Pictorial graph saved as: {output_name}")
            
        except Exception as e:
            print(f"[!] Graph generation failed: {e}")

    def is_success(self, state):
        try:
            output = state.posix.dumps(1)
            if b"Success" in output or b"Correct" in output:
                return True
        except: pass
        return False

    def is_failure(self, state):
        try:
            output = state.posix.dumps(1)
            if b"Wrong" in output or b"Error" in output:
                return True
        except: pass
        return False
