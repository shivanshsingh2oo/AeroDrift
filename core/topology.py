import networkx as nx


def build_topology(data):
    graph = nx.DiGraph()

    for resource in data["resources"]:
        graph.add_node(
            resource["id"],
            type=resource["type"],
            name=resource["name"]
        )

    for connection in data["connections"]:
        graph.add_edge(
            connection["source"],
            connection["target"]
        )

    return graph
def get_topology_diff(before_graph, after_graph):
    before_edges = set(before_graph.edges())
    after_edges = set(after_graph.edges())

    removed = before_edges - after_edges
    added = after_edges - before_edges

    return {
        "removed_connections": list(removed),
        "added_connections": list(added)
    }