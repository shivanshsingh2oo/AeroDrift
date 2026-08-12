import networkx as nx


def detect_database_exposure(graph):
    source = "internet"
    target = "database"

    if nx.has_path(graph, source, target):
        path = nx.shortest_path(graph, source, target)

        return {
            "drift_detected": True,
            "message": "Private database is reachable from the internet.",
            "path": path
        }

    return {
        "drift_detected": False,
        "message": "Private database is not reachable from the internet.",
        "path": []
    }