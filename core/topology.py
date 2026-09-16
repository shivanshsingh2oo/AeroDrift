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


def find_network_path(graph, source, target):
    """
    Find the shortest network path between two resources.
    """

    if source not in graph or target not in graph:
        return []

    if not nx.has_path(graph, source, target):
        return []

    return nx.shortest_path(
        graph,
        source,
        target
    )


def get_topology_diff(before_graph, after_graph):
    before_edges = set(before_graph.edges())
    after_edges = set(after_graph.edges())

    removed = before_edges - after_edges
    added = after_edges - before_edges

    return {
        "removed_connections": list(removed),
        "added_connections": list(added)
    }