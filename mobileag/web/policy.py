"""Persisted operator restrictions may narrow, never expand environment scope."""
from urllib.parse import urlsplit
import re
from mobileag.web.security import configured_list

DYNAMIC_ACTIONS = {'connect','root','install','launch','deeplink','execute_adb','logcat','logcat/clear',
                   'automation_observe','automation_execute','screenshot','storage','providers','deeplinks','memory','crawl','frida','frida_status','fuzz'}
METHODS = {'GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'}

def validate_policy(value):
    fields = {'devices','packages','origins','methods','actions'}
    if not isinstance(value,dict) or set(value) != fields:
        raise ValueError('Provide devices, packages, origins, methods and actions')
    for key in fields:
        if not isinstance(value[key],list) or len(value[key]) > 100 or any(not isinstance(x,str) or len(x)>256 for x in value[key]):
            raise ValueError('Scope lists must contain at most 100 bounded strings')
    for key, env in [('devices','MOBILEAG_ALLOWED_DEVICES'),('origins','MOBILEAG_ALLOWED_ORIGINS')]:
        if not set(value[key]) <= configured_list(env):
            raise ValueError('UI scope cannot expand the server environment allowlist')
    if any(not re.fullmatch(r'[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+',p) for p in value['packages']):
        raise ValueError('Packages must be exact application IDs')
    if not set(value['methods']) <= METHODS or not set(value['actions']) <= DYNAMIC_ACTIONS:
        raise ValueError('Unknown HTTP method or device action')
    return {key:sorted(set(value[key])) for key in fields}

def check_action(policy, action, data):
    # No persisted scope means static-only, not unrestricted dynamic testing.
    if not policy or action not in policy['actions']:
        return False
    if action == 'connect':
        return True  # Additional environment host:port check in middleware.
    if data.get('serial') not in policy['devices']:
        return False
    package = data.get('package_name')
    if action == 'launch':
        package = str(data.get('component','')).split('/')[0]
    if action in {'storage','providers','deeplinks','memory','crawl','automation_observe','automation_execute','fuzz','launch','frida','deeplink','install','execute_adb'}:
        # Arbitrary shell / root / Frida remain powerful *device-wide* permissions.
        # A package field does not constrain arbitrary shell code. Explicit action approval
        # is a device-wide research authorization, not an ordinary-app boundary.
        if action not in {'execute_adb','install','frida'} and package not in policy['packages']:
            return False
    if action == 'fuzz' and any((str(c).split('/')[0] != package if '/' in str(c) else not str(c).startswith(package + '.') and not str(c).startswith('.')) for c in (data.get('activities') or [])):
        return False
    if package and package not in policy['packages']:
        return False
    return True

def check_replay(policy,url,method):
    p=urlsplit(url)
    return bool(policy and f'{p.scheme}://{p.netloc}' in policy['origins'] and method.upper() in policy['methods'])
