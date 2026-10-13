"""Analysis agents loaded on demand; starting the dashboard never loads cloud SDKs."""
from importlib import import_module

_MODULES = {
    'APIMapper':'api_mapper', 'BinaryProtectionAuditor':'binary_protection_auditor',
    'CodeReviewer':'code_reviewer', 'DependencyScanner':'dependency_scanner',
    'ManifestAuditor':'manifest_auditor', 'NativeAnalyzer':'native_analyzer',
    'NetworkSecurityConfigAuditor':'network_security_config_auditor',
    'ReactNativeScanner':'react_native_scanner', 'SecretScanner':'secret_scanner',
    'TaintEngine':'taint_engine',
    'SymbolResolver':'symbol_resolver',
    'PendingIntentAuditor':'pending_intent_auditor',
    'IntentRedirectionAuditor':'intent_redirection_auditor',
    'FlutterEngineAnalyzer':'flutter_engine',
    'RaspResilienceAuditor':'rasp_resilience_auditor',
    'MobileSbomGenerator':'sbom_generator',
}
__all__ = list(_MODULES)

def __getattr__(name):
    if name not in _MODULES:
        raise AttributeError(name)
    value = getattr(import_module('.'+_MODULES[name],__name__),name)
    globals()[name] = value
    return value
