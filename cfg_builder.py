import networkx as nx

class CFGBuilder:

    def build_cfg(self, method_analysis):

        graph = nx.DiGraph()

        blocks = method_analysis.basic_blocks.get()

        for block in blocks:

            graph.add_node(block.name)

            for child in block.childs:
                graph.add_edge(block.name, child[2].name)

        return graph
