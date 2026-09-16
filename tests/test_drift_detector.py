import networkx as nx

from detection.drift_detector import detect_database_exposure


def test_database_exposed_to_internet():
    graph = nx.DiGraph()

    graph.add_edge("internet", "database")

    result = detect_database_exposure(graph)

    assert result["drift_detected"] is True
    assert result["path"] == ["internet", "database"]


def test_database_not_exposed():
    graph = nx.DiGraph()

    graph.add_node("internet")
    graph.add_node("database")

    result = detect_database_exposure(graph)

    assert result["drift_detected"] is False
    assert result["path"] == []


def test_missing_nodes():
    graph = nx.DiGraph()

    result = detect_database_exposure(graph)

    assert result["drift_detected"] is False
    assert result["path"] == []