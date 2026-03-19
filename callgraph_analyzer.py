class CallGraphAnalyzer:

    def __init__(self, dx):
        self.dx = dx

    def get_reachable_methods(self, entry_points):

        reachable = set()
        worklist = []

        # find starting methods
        for m in self.dx.get_methods():

            method = m.get_method()

            name = str(method)

            for ep in entry_points:
                if ep.replace(".", "/") in name:
                    reachable.add(name)
                    worklist.append(m)

        # traverse xrefs
        while worklist:

            m = worklist.pop()

            try:
                for _, callee, _ in m.get_xref_to():

                    name = str(callee)

                    if name not in reachable:
                        reachable.add(name)

                        for mm in self.dx.get_methods():
                            if str(mm.get_method()) == name:
                                worklist.append(mm)

            except:
                pass

        return reachable

