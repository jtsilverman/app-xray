"""Tests for network call path tracing."""

from app_xray.extractors.network_paths import (
    _clean_class_name,
    _is_network_sink,
    _is_library_class,
    _chain_has_app_code,
    trace_network_calls,
)
from app_xray.models import NetworkCallPath


# --- _clean_class_name ---

def test_clean_class_name_dalvik_format():
    assert _clean_class_name("Lcom/example/Foo;") == "com.example.Foo"


def test_clean_class_name_already_clean():
    assert _clean_class_name("com/example/Foo") == "com.example.Foo"


def test_clean_class_name_simple():
    assert _clean_class_name("Foo") == "Foo"


# --- _is_network_sink ---

def test_is_network_sink_matching():
    assert _is_network_sink("java/net/URL", "openConnection") is True


def test_is_network_sink_okhttp():
    assert _is_network_sink("okhttp3/OkHttpClient", "newCall") is True


def test_is_network_sink_wrong_method():
    assert _is_network_sink("java/net/URL", "toString") is False


def test_is_network_sink_wrong_class():
    assert _is_network_sink("com/example/MyClass", "execute") is False


def test_is_network_sink_method_on_unrelated_class():
    """A network method name on a non-network class should not match."""
    assert _is_network_sink("com/myapp/Utils", "connect") is False


# --- _is_library_class ---

def test_is_library_class_okhttp():
    assert _is_library_class("okhttp3/internal/connection/RealCall") is True


def test_is_library_class_android():
    assert _is_library_class("Landroid/app/Activity") is True


def test_is_library_class_app_code():
    assert _is_library_class("com/myapp/network/ApiClient") is False


def test_is_library_class_kotlin_coroutines():
    assert _is_library_class("kotlinx/coroutines/Dispatchers") is True


def test_is_library_class_retrofit():
    assert _is_library_class("Lretrofit2/Call") is True


# --- _chain_has_app_code ---

def test_chain_has_app_code_with_app_class():
    chain = ["com.myapp.MainActivity.onCreate", "[library]", "java.net.URL.openConnection"]
    assert _chain_has_app_code(chain) is True


def test_chain_has_app_code_all_library():
    chain = ["[library]", "okhttp3.Call.execute"]
    # "[library]" itself doesn't resolve to a library class via the prefix check,
    # but the second entry does. Let's test with real library names.
    chain = ["android.app.Activity.onCreate", "okhttp3.OkHttpClient.newCall"]
    assert _chain_has_app_code(chain) is False


def test_chain_has_app_code_empty():
    assert _chain_has_app_code([]) is False


def test_chain_has_app_code_mixed():
    chain = [
        "com.example.MyService.doWork",
        "okhttp3.OkHttpClient.newCall",
        "java.net.URL.openConnection",
    ]
    assert _chain_has_app_code(chain) is True


# --- trace_network_calls with mock dx ---

class _FakeMethod:
    def __init__(self, cls_name, method_name):
        self._cls = cls_name
        self._name = method_name

    def get_class_name(self):
        return self._cls

    def get_name(self):
        return self._name


class _FakeMethodAnalysis:
    def __init__(self, cls_name, method_name, xrefs=None):
        self._method = _FakeMethod(cls_name, method_name)
        self._xrefs = xrefs or []

    def get_method(self):
        return self._method

    def get_xref_from(self):
        return self._xrefs


class _FakeVmClass:
    def __init__(self, superclass):
        self._super = superclass

    def get_superclassname(self):
        return self._super


class _FakeClassAnalysis:
    def __init__(self, name, superclass=None):
        self._name = name
        self._vm = _FakeVmClass(superclass) if superclass else None

    def get_vm_class(self):
        return self._vm

    @property
    def name(self):
        return self._name


class _FakeDx:
    def __init__(self, classes, methods):
        self._classes = classes
        self._methods = methods

    def get_classes(self):
        return self._classes

    def get_methods(self):
        return self._methods

    def get_class_analysis(self, name):
        for c in self._classes:
            if c.name == name:
                return c
        return None


def test_trace_no_sinks():
    """No network sinks means empty result."""
    app_cls = _FakeClassAnalysis("Lcom/myapp/Main;", "android/app/Activity")
    method = _FakeMethodAnalysis("Lcom/myapp/Main;", "onCreate")
    dx = _FakeDx([app_cls], [method])
    paths = trace_network_calls(dx)
    assert paths == []


def test_trace_simple_path():
    """A single caller -> sink path should be found."""
    # Sink: java/net/URL.openConnection
    sink = _FakeMethodAnalysis("java/net/URL", "openConnection")

    # Caller: com/myapp/NetHelper.fetchData -> calls sink
    caller = _FakeMethodAnalysis(
        "Lcom/myapp/NetHelper;", "fetchData",
        xrefs=[],
    )
    # Wire: sink is called from caller
    sink._xrefs = [("Lcom/myapp/NetHelper;", caller, 0)]

    # Entry point: com/myapp/MainActivity.onCreate -> calls caller
    entry_cls_name = "Lcom/myapp/MainActivity;"
    entry = _FakeMethodAnalysis(entry_cls_name, "onCreate", xrefs=[])
    caller._xrefs = [(entry_cls_name, entry, 0)]

    app_cls = _FakeClassAnalysis("Lcom/myapp/Main;", None)
    entry_cls = _FakeClassAnalysis(
        entry_cls_name,
        "android/app/Activity",
    )
    helper_cls = _FakeClassAnalysis("Lcom/myapp/NetHelper;", None)

    dx = _FakeDx(
        [app_cls, entry_cls, helper_cls],
        [sink, caller, entry],
    )
    paths = trace_network_calls(dx)
    assert len(paths) >= 1
    assert paths[0].entry_type == "Activity"
    assert "java.net.URL.openConnection" in paths[0].sink


def test_trace_respects_max_depth():
    """Chains deeper than max_depth should be pruned."""
    # Build a chain: sink <- m1 <- m2 <- ... <- mN <- entry
    sink = _FakeMethodAnalysis("java/net/URL", "openConnection")

    prev = sink
    methods = [sink]
    for i in range(12):
        m = _FakeMethodAnalysis(f"Lcom/myapp/C{i};", f"step{i}")
        prev._xrefs = [(f"Lcom/myapp/C{i};", m, 0)]
        methods.append(m)
        prev = m

    # Entry at the end
    entry_cls_name = "Lcom/myapp/EntryActivity;"
    entry = _FakeMethodAnalysis(entry_cls_name, "onCreate")
    prev._xrefs = [(entry_cls_name, entry, 0)]
    methods.append(entry)

    classes = [_FakeClassAnalysis(f"Lcom/myapp/C{i};", None) for i in range(12)]
    classes.append(_FakeClassAnalysis(entry_cls_name, "android/app/Activity"))

    dx = _FakeDx(classes, methods)
    # max_depth=3 means chains longer than 3 get cut before reaching entry
    paths = trace_network_calls(dx, max_depth=3)
    assert len(paths) == 0  # entry is too far away to reach


def test_trace_max_paths_limit():
    """Result should be capped at max_paths."""
    # Create multiple independent sink -> entry paths
    methods = []
    classes = []
    for i in range(5):
        sink = _FakeMethodAnalysis("java/net/URL", "openConnection")
        entry_cls = f"Lcom/myapp/Act{i};"
        entry = _FakeMethodAnalysis(entry_cls, "onCreate")
        sink._xrefs = [(entry_cls, entry, 0)]
        methods.extend([sink, entry])
        classes.append(_FakeClassAnalysis(entry_cls, "android/app/Activity"))

    dx = _FakeDx(classes, methods)
    paths = trace_network_calls(dx, max_paths=2)
    assert len(paths) <= 2
