import sys
import gc # Added for stability/memory management

from apk_analyzer import APKAnalyzer
from path_explorer import PathExplorer
from cfg_analyzer import CFGAnalyzer
from callgraph_analyzer import CallGraphAnalyzer
from entry_points import EntryPointDetector
from method_selector import MethodSelector
from vulnerability_detector import VulnerabilityDetector
from analysis_summary import summary
from dalvik_interpreter import DalvikInterpreter
from jni_detector import JNIDetector
from native_loader import NativeLoader
from native_symbolic import NativeSymbolicExecutor

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <apk>")
        return

    apk_path = sys.argv[1]

    # 1. Static Analysis
    analyzer = APKAnalyzer(apk_path)
    a, d, dx = analyzer.analyze()
    summary.package = a.get_package()

    # 2. Entry Points
    entry = EntryPointDetector(apk_path)
    entry_points = entry.get_entry_points()
    for e in entry_points:
        summary.add_entry(e)

    # 3. Call Graph
    callgraph = CallGraphAnalyzer(dx)
    reachable_methods = callgraph.get_reachable_methods(entry_points)

    # 4. Symbolic Engine (Dalvik)
    interpreter = DalvikInterpreter()
    explorer = PathExplorer(interpreter)
    selector = MethodSelector()
    vuln = VulnerabilityDetector()
    cfg_builder = CFGAnalyzer()

    print("\n--- Dalvik Symbolic Execution ---")
    for m in dx.get_methods():
        method = m.get_method()
        name = str(method)

        if name in reachable_methods and hasattr(method, "get_code") and method.get_code():
            if selector.is_interesting(name):
                print("\n[+] Analyzing Method:", name)
                summary.add_method(name)
                cfg, instructions = cfg_builder.build_cfg(method)
                if instructions:
                    states = explorer.explore_cfg(cfg, instructions, name)
                    vuln.analyze_constraints(states)
                
                # Free memory after each method to prevent crashes on large APKs
                gc.collect()

    # 5. Native Analysis & Graph Generation
    print("\n--- Native Analysis ---")
    loader = NativeLoader()
    libs = loader.extract_native_libs(apk_path)
    executor = NativeSymbolicExecutor()

    for lib in libs:
        summary.add_native(lib)
        executor.analyze(lib) # This now generates the pictorial graph

    summary.print_summary()
    summary.print_input_details()

if __name__ == "__main__":
    main()
