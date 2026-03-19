from symbolic_state import SymbolicState


class PathExplorer:

    def __init__(self, interpreter):

        self.interpreter = interpreter

        self.max_states = 50
        self.max_depth = 200

    def explore_cfg(self, cfg, instructions, method_name):

        states = [(0, SymbolicState())]

        finished = []

        depth = 0

        while states and depth < self.max_depth:

            new_states = []

            for pc, state in states:

                if pc >= len(instructions):

                    finished.append(state)
                    continue

                instr = instructions[pc]

                results = self.interpreter.execute(instr, state, method_name)

                next_blocks = cfg.get(pc, [])

                for s in results:

                    if not s.is_feasible():
                        continue

                    for nb in next_blocks:

                        new_states.append((nb, s.clone()))

            if len(new_states) > self.max_states:
                new_states = new_states[:self.max_states]

            states = new_states

            depth += 1

        return finished
