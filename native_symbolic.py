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
        print(f"[*] Generating pictorial call graph for: {os.path.basename(so_file)}")
        try:
            cfg = project.analyses.CFGFast()
            # Get a copy of the graph to modify it
            callgraph = cfg.kb.functions.callgraph.copy()
    
            # FIX 1: Remove any nodes that are 'None' to prevent comparison errors
            nodes_to_remove = [n for n in callgraph.nodes if n is None]
            callgraph.remove_nodes_from(nodes_to_remove)
    
            # FIX 2: Limit the graph size for large libraries to prevent crashes
            if len(callgraph.nodes) > 500:
                print("[!] Graph too large for full rendering. Subsampling first 500 nodes.")
                # Only keep the first 500 nodes to ensure the layout completes
                nodes = list(callgraph.nodes)[:500]
                callgraph = callgraph.subgraph(nodes)
    
            plt.figure(figsize=(15, 10))
            plt.title(f"Call Graph (Partial): {os.path.basename(so_file)}")
    
            # FIX 3: Use a more stable layout and handle None values in edge drawing
            pos = nx.kamada_kawai_layout(callgraph) 
            
            nx.draw(callgraph, pos, with_labels=False, # Labels on 500 nodes are unreadable
                    node_color='skyblue', node_size=50, 
                    edge_color='gray', width=0.5, alpha=0.5,
                    arrows=True)
    
            output_name = f"graph_{os.path.basename(so_file)}.png"
            plt.savefig(output_name, dpi=300)
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
