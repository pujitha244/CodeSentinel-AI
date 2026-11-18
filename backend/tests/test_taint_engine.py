from pathlib import Path

from backend.app.analyzers.ast_engine import CodeParser
from backend.app.analyzers.call_graph_builder import CallGraphBuilder
from backend.app.analyzers.taint_engine import TaintEngine


def _analyze_project(root: Path, files: dict[str, str]):
    parsed_files = {}
    for relative_path, code in files.items():
        file_path = root / relative_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(code, encoding="utf-8")
        parsed_files[relative_path] = CodeParser.parse_python(relative_path, code)

    call_graph = CallGraphBuilder(str(root), parsed_files).build()
    return TaintEngine(str(root), parsed_files, call_graph).analyze()


def test_chain_requires_tainted_value_to_reach_sink(tmp_path):
    chains = _analyze_project(
        tmp_path,
        {
            "routes.py": """
def search_endpoint(q):
    value = q
    return service.search(value)
""",
            "services.py": """
def search(query):
    normalized = query.strip()
    return database.execute_raw_search(normalized)
""",
            "database.py": """
def execute_raw_search(search_term):
    query = f"SELECT * FROM users WHERE name = '{search_term}'"
    cursor.execute(query)
""",
        },
    )

    assert len(chains) == 1
    chain = chains[0]
    assert chain["source_file"] == "routes.py"
    assert chain["sink_file"] == "database.py"
    assert chain["confidence"] >= 0.85

    graph_files = [node["data"]["file"] for node in chain["nodes"]]
    assert graph_files == ["routes.py", "services.py", "database.py"]
    assert all(node["data"]["kind"] != "boundary" for node in chain["nodes"])
    assert len(chain["edges"]) == 2


def test_reachable_sink_is_not_a_chain_when_source_argument_is_dropped(tmp_path):
    chains = _analyze_project(
        tmp_path,
        {
            "routes.py": """
def search_endpoint(q):
    return execute("fixed")
""",
            "database.py": """
def execute(term):
    query = f"SELECT * FROM users WHERE name = '{term}'"
    cursor.execute(query)
""",
        },
    )

    assert chains == []


def test_taint_survives_conditional_overwrite_and_tracks_local_aliases(tmp_path):
    chains = _analyze_project(
        tmp_path,
        {
            "routes.py": """
def search_endpoint(q, replace):
    alias: str = q
    copied = alias
    if replace:
        copied = "fixed"
    return search_service(copied)
""",
            "service.py": """
def search_service(term):
    return execute_query(term)
""",
            "database.py": """
def execute_query(value):
    query = f"SELECT * FROM users WHERE name = '{value}'"
    cursor.execute(query)
""",
        },
    )

    assert len(chains) == 1
    assert [node["data"]["file"] for node in chains[0]["nodes"]] == [
        "routes.py",
        "service.py",
        "database.py",
    ]


def test_shlex_quoted_input_is_not_reported_as_command_injection(tmp_path):
    chains = _analyze_project(
        tmp_path,
        {
            "routes.py": """
import shlex

def command_endpoint(value):
    os.system(f"echo {shlex.quote(value)}")
""",
        },
    )

    assert chains == []


def test_unquoted_occurrence_is_not_hidden_by_quote_in_same_command(tmp_path):
    chains = _analyze_project(
        tmp_path,
        {
            "routes.py": """
import shlex

def command_endpoint(value):
    os.system(f"echo {shlex.quote(value)}; echo {value}")
""",
        },
    )

    assert len(chains) == 1
    assert chains[0]["vulnerability_type"] == "command_injection"


def test_unquoted_input_remains_a_command_injection_chain(tmp_path):
    chains = _analyze_project(
        tmp_path,
        {
            "routes.py": """
def command_endpoint(value):
    os.system(f"echo {value}")
""",
        },
    )

    assert len(chains) == 1
    assert chains[0]["vulnerability_type"] == "command_injection"


def test_keyword_arguments_and_aliases_reach_cross_file_sql_sink(tmp_path):
    chains = _analyze_project(
        tmp_path,
        {
            "routes.py": """
def search_endpoint(q):
    return search_service(term=q)
""",
            "service.py": """
def search_service(term):
    alias = term
    return execute_query(value=alias)
""",
            "database.py": """
def execute_query(value):
    cursor.execute(f"SELECT * FROM users WHERE name = '{value}'")
""",
        },
    )

    assert len(chains) == 1
    assert [node["data"]["file"] for node in chains[0]["nodes"]] == [
        "routes.py",
        "service.py",
        "database.py",
    ]


def test_taint_propagates_through_loop_target_alias(tmp_path):
    chains = _analyze_project(
        tmp_path,
        {
            "routes.py": """
def search_endpoint(values):
    for value in values:
        query_service(value)
""",
            "service.py": """
def query_service(term):
    query = f"SELECT * FROM users WHERE name = '{term}'"
    cursor.execute(query)
""",
        },
    )

    assert len(chains) == 1
    assert chains[0]["source_file"] == "routes.py"
    assert chains[0]["sink_file"] == "service.py"
