"""Network call path tracing via call graph analysis."""

from app_xray.models import NetworkCallPath as CallPath


# Network sink methods and the classes they appear in
NETWORK_SINK_METHODS = {
    "openConnection", "execute", "connect", "getOutputStream",
    "newCall", "enqueue", "send", "write",
}

NETWORK_SINK_CLASSES = {
    "java/net/URL", "java/net/HttpURLConnection",
    "javax/net/ssl/HttpsURLConnection",
    "okhttp3/OkHttpClient", "okhttp3/Call", "okhttp3/RealCall",
    "io/ktor/client", "org/apache/http",
    "java/net/Socket", "javax/net/ssl/SSLSocket",
}

# Android entry point base classes
ENTRY_POINTS = {
    "android/app/Activity": "Activity",
    "android/app/Service": "Service",
    "android/content/BroadcastReceiver": "BroadcastReceiver",
    "android/app/IntentService": "Service",
    "androidx/appcompat/app/AppCompatActivity": "Activity",
    "androidx/fragment/app/Fragment": "Fragment",
    "android/app/Application": "Application",
}


def _clean_class_name(name: str) -> str:
    """Convert Lcom/example/Foo; to com.example.Foo."""
    if name.startswith("L") and name.endswith(";"):
        name = name[1:-1]
    return name.replace("/", ".")


def _is_network_sink(class_name: str, method_name: str) -> bool:
    """Check if a method is a network sink."""
    if method_name not in NETWORK_SINK_METHODS:
        return False
    for sink_cls in NETWORK_SINK_CLASSES:
        if sink_cls in class_name:
            return True
    return False


def _classify_entry(class_name: str, dx) -> str:
    """Determine if a class is an Android entry point."""
    # Check superclass chain
    cls_analysis = dx.get_class_analysis(class_name)
    if not cls_analysis:
        return "Other"

    vm_cls = cls_analysis.get_vm_class()
    if not vm_cls or not hasattr(vm_cls, "get_superclassname"):
        return "Other"

    superclass = vm_cls.get_superclassname()
    if superclass:
        for entry_cls, entry_type in ENTRY_POINTS.items():
            if entry_cls in superclass:
                return entry_type

    # Check the class name itself for common patterns
    clean = _clean_class_name(class_name)
    if "Activity" in clean:
        return "Activity"
    if "Service" in clean:
        return "Service"
    if "Receiver" in clean:
        return "BroadcastReceiver"

    return "Other"


# Common library packages to skip in chain display (still traverse them)
LIBRARY_PREFIXES = (
    "io/ktor/", "okhttp3/", "retrofit2/", "com/squareup/",
    "io/reactivex/", "kotlinx/coroutines/", "kotlin/coroutines/",
    "androidx/", "android/", "java/", "javax/",
    "com/google/android/gms/", "org/apache/http/",
    "fi/iki/elonen/",
)


def _is_library_class(class_name: str) -> bool:
    """Check if a class is from a known library (not app code)."""
    for prefix in LIBRARY_PREFIXES:
        if class_name.startswith("L" + prefix) or class_name.startswith(prefix):
            return True
    return False


def _chain_has_app_code(chain: list[str]) -> bool:
    """Check if a call chain includes at least one app-specific class."""
    for step in chain:
        cls = step.rsplit(".", 1)[0] if "." in step else step
        raw = cls.replace(".", "/")
        if not _is_library_class(raw):
            return True
    return False


def trace_network_calls(dx, max_depth: int = 8, max_paths: int = 20) -> list[CallPath]:
    """Trace call paths from entry points to network sinks.

    Walks the call graph backwards from network methods to find
    which user actions or app components trigger network calls.
    """
    # Detect the app's package from the most common non-library prefix
    app_packages = set()
    for cls in dx.get_classes():
        name = cls.name
        if name.startswith("L") and not _is_library_class(name):
            parts = name[1:].split("/")
            if len(parts) >= 2:
                app_packages.add("/".join(parts[:2]))

    # Find all network sink methods
    sinks = []
    for method in dx.get_methods():
        m = method.get_method()
        cls_name = m.get_class_name()
        method_name = m.get_name()
        if _is_network_sink(cls_name, method_name):
            sinks.append(method)

    paths = []
    seen_chains = set()

    for sink in sinks:
        sink_m = sink.get_method()
        sink_label = f"{_clean_class_name(sink_m.get_class_name())}.{sink_m.get_name()}"

        # BFS backwards through call graph
        queue = [(sink, [sink_label])]
        visited = {id(sink)}

        while queue and len(paths) < max_paths * 3:  # collect extra, filter later
            current, chain = queue.pop(0)

            if len(chain) > max_depth:
                continue

            xrefs = current.get_xref_from()

            for ref_cls, ref_method, _ in xrefs:
                if id(ref_method) in visited:
                    continue
                visited.add(id(ref_method))

                ref_m = ref_method.get_method()
                ref_cls_name = ref_m.get_class_name()
                ref_method_name = ref_m.get_name()
                caller_label = f"{_clean_class_name(ref_cls_name)}.{ref_method_name}"

                new_chain = [caller_label] + chain

                # Check if we reached an entry point
                entry_type = _classify_entry(ref_cls_name, dx)
                if entry_type != "Other":
                    chain_key = " -> ".join(new_chain)
                    if chain_key not in seen_chains:
                        seen_chains.add(chain_key)
                        paths.append(CallPath(
                            sink=sink_label,
                            chain=new_chain,
                            entry_type=entry_type,
                        ))
                else:
                    queue.append((ref_method, new_chain))

    # Filter: only keep paths that include app-specific code
    app_paths = [p for p in paths if _chain_has_app_code(p.chain)]

    # If no app-specific paths found, fall back to all paths but mark as library
    if not app_paths:
        app_paths = paths

    # Collapse library-internal steps for cleaner display
    for path in app_paths:
        collapsed = []
        for step in path.chain:
            cls = step.rsplit(".", 1)[0] if "." in step else step
            raw = cls.replace(".", "/")
            if _is_library_class(raw) and collapsed and collapsed[-1] == "[library]":
                continue  # skip consecutive library steps
            elif _is_library_class(raw):
                collapsed.append("[library]")
            else:
                collapsed.append(step)
        path.chain = collapsed

    # Sort: entry-point paths first, then by chain length
    entry_order = {"Activity": 0, "Service": 1, "BroadcastReceiver": 2, "Fragment": 3, "Application": 4, "Other": 5}
    app_paths.sort(key=lambda p: (entry_order.get(p.entry_type, 5), len(p.chain)))

    # Deduplicate after collapse
    final = []
    seen = set()
    for p in app_paths:
        key = " -> ".join(p.chain)
        if key not in seen:
            seen.add(key)
            final.append(p)

    return final[:max_paths]
