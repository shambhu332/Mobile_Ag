"""Bounded manifest URI inventory, not a runtime resolver or domain verifier."""
from itertools import product
import re

DATA_ATTRIBUTES = ('scheme','host','port','path','pathPrefix','pathPattern','pathAdvancedPattern',
                   'pathSuffix','mimeType','query','queryPrefix','queryPattern','querySuffix',
                   'queryAdvancedPattern','fragment','fragmentPrefix','fragmentPattern',
                   'fragmentSuffix','fragmentAdvancedPattern','ssp','sspPrefix','sspPattern')
PATH_ATTRIBUTES = ('path','pathPrefix','pathPattern','pathAdvancedPattern','pathSuffix')


def inventory_links(components, per_filter_limit=256, total_limit=2048):
    links = []
    report = {'status':'inventoried','filters':0,'combinations_reported':0,'truncated':False,
              'domain_verification':'not_tested','runtime_resolution':'not_tested',
              'relative_uri_groups':'preserved_not_evaluated','mime_only_filters':0}
    for component in components:
        for index, intent_filter in enumerate(component.get('intent_filters', [])):
            report['filters'] += 1
            data = intent_filter.get('data', [])
            schemes = list(dict.fromkeys(d['scheme'] for d in data if d.get('scheme')))
            authorities = list(dict.fromkeys((d['host'], d.get('port','')) for d in data if d.get('host')))
            paths = list(dict.fromkeys((key,d[key]) for d in data for key in PATH_ATTRIBUTES if d.get(key)))
            if not schemes:
                if any(d.get('mimeType') for d in data):report['mime_only_filters'] += 1
                continue
            # Scheme/path attributes merge across data elements. Authority ports
            # remain paired with their host; absent hosts make path/port inapplicable.
            combinations = len(schemes)*max(1,len(authorities))*(max(1,len(paths)) if authorities else 1)
            budget = min(per_filter_limit, max(0,total_limit-len(links)))
            if combinations > budget:report['truncated'] = True
            for count,(scheme,(host,port),(kind,path)) in enumerate(product(schemes,authorities or [('', '')],paths if authorities and paths else [('', '')])):
                if count >= budget:break
                relative = intent_filter.get('relative_uri_groups', [])
                supported_literal = bool(re.fullmatch(r'[A-Za-z][A-Za-z0-9+.-]*',scheme) and
                    not any(c in host for c in '*@{}') and (not port or port.isdecimal()) and
                    kind in {'','path','pathPrefix'} and not relative and
                    not any(d.get('ssp') or d.get('sspPrefix') or d.get('sspPattern') for d in data))
                uri = f'{scheme}://{host}'+(f':{port}' if host and port else '')+path if supported_literal else None
                links.append({'component':component['name'],'filter_index':index,'scheme':scheme,
                    'host':host,'port':port,'path':path,'path_kind':kind,'uri':uri,
                    'auto_verify':intent_filter.get('auto_verify'), 'exported':component.get('exported'),
                    'permission':component.get('permission'), 'actions':intent_filter.get('actions',[]),
                    'categories':intent_filter.get('categories',[]), 'relative_uri_groups':relative,
                    'uri_basis':'prefix_example_not_full_route' if kind=='pathPrefix' else 'literal_candidate' if uri else 'pattern_requires_researcher_example',
                    'runtime_verified':False, 'implicitly_authorized':False})
    report['combinations_reported'] = len(links)
    if report['truncated']:report['status']='partial'
    return links, report
