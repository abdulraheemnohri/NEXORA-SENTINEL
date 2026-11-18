"""Deadlock detector for declared wait-for graphs; unknown nodes fail closed."""


def has_cycle(graph: dict[str, set[str] | list[str]]) -> bool:
    if not isinstance(graph, dict) or any(not isinstance(node, str) for node in graph):
        raise ValueError("wait_graph_invalid")
    visiting, visited = set(), set()

    def visit(node):
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        for dependency in graph.get(node, []):
            if dependency not in graph:
                raise ValueError("wait_graph_unknown_node")
            if visit(dependency):
                return True
        visiting.remove(node)
        visited.add(node)
        return False

    return any(visit(node) for node in graph if node not in visited)
