import sys
import types
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def _stub(name: str, **attrs: object) -> types.ModuleType:
    mod = types.ModuleType(name)
    mod.__dict__.update(attrs)
    sys.modules[name] = mod
    return mod


# Stub heavyweight optional deps so pure-logic tests run in plain CI without ROS/LangGraph/Qdrant.
try:
    import langgraph  # noqa: F401
except ImportError:
    _stub("langgraph")
    _stub("langgraph.graph", StateGraph=object, END="END")
try:
    import qdrant_client  # noqa: F401
except ImportError:
    _stub("qdrant_client", QdrantClient=object)
    _stub("qdrant_client.http")
    _stub("qdrant_client.http.models")
