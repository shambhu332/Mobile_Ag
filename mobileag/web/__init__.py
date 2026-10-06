"""Web package. Importing policy/contracts must not construct an API server."""

def __getattr__(name):
    if name in {'app','run_server'}:
        from importlib import import_module
        module=import_module('mobileag.web.app')
        return getattr(module,name)
    raise AttributeError(name)
