"""Bounded Android surface review. Pattern evidence is never exploit proof."""
from __future__ import annotations
import asyncio
import re
from pathlib import Path
from mobileag.reporting.finding import Finding, FindingStatus, Severity
from mobileag.analysis.bounded_sources import SourceInventory

MAX_FILES=5000
MAX_FILE_BYTES=2*1024*1024
MAX_SOURCE_BYTES=32*1024*1024
MAX_FINDINGS=500
PENDING_INTENT_CALL = re.compile(r'\bPendingIntent\s*\.\s*(?:getActivity|getActivities|getBroadcast|getService|getForegroundService)\s*\(')


def _call_arguments(masked_code: str, open_paren: int) -> str:
    """Return a bounded balanced call expression; not a Java/Kotlin parser."""
    depth = 0
    for end in range(open_paren, min(len(masked_code), open_paren + 8192)):
        if masked_code[end] == '(':
            depth += 1
        elif masked_code[end] == ')':
            depth -= 1
            if depth == 0:
                return masked_code[open_paren + 1:end]
    return masked_code[open_paren + 1:min(len(masked_code), open_paren + 8192)]


def _split_arguments(arguments: str) -> list[str]:
    """Split bounded call arguments at top-level commas; not a full parser."""
    stack = []
    start = 0
    result = []
    pairs = {"(": ")", "[": "]", "{": "}"}
    for index, char in enumerate(arguments):
        if char in pairs:
            stack.append(pairs[char])
        elif char in ")]}":
            if stack and char == stack[-1]:
                stack.pop()
            elif not stack:
                return []
        elif char == "," and not stack:
            result.append(arguments[start:index].strip())
            start = index + 1
    result.append(arguments[start:].strip())
    return result


def _last_call_argument(masked_code: str, open_paren: int) -> str | None:
    """Return only the final argument of a bounded call, or None if incomplete.

    PendingIntent's mutability flags are the final parameter for its factory
    overloads. Other arguments must not suppress a review candidate by merely
    containing the same constant name. This remains lexical, not overload
    resolution; complex expressions are retained for manual review.
    """
    stack = [")"]
    start = open_paren + 1
    last_start = start
    end = min(len(masked_code), open_paren + 8192)
    for pos in range(open_paren + 1, end):
        char = masked_code[pos]
        if char in "([{":
            stack.append({"(": ")", "[": "]", "{": "}"}[char])
        elif char in ")]}" :
            if not stack or char != stack[-1]:
                return None
            stack.pop()
            if not stack:
                return masked_code[last_start:pos].strip() if pos > open_paren + 1 else ""
        elif char == "," and len(stack) == 1:
            last_start = pos + 1
    return None


def _pending_intent_flag_aliases(masked_code: str) -> dict[str, str]:
    """Collect unique Java final-int or Kotlin const-int aliases with flag-only values."""
    patterns = (
        re.compile(r'\b(?:static\s+)?final\s+(?:int|Integer)\s+(\w+)\s*=\s*([^;]{1,512});'),
        re.compile(r'\bconst\s+val\s+(\w+)\s*:\s*Int\s*=\s*([^\n;]{1,512})'),
    )
    found: dict[str, list[str]] = {}
    for pattern in patterns:
        for match in pattern.finditer(masked_code):
            value = match.group(2).strip()
            if re.fullmatch(r'[\w.\s|()]+', value) and re.search(r'\bFLAG_(?:IMMUTABLE|MUTABLE)\b', value):
                found.setdefault(match.group(1), []).append(value)
    return {name: values[0] for name, values in found.items() if len(values) == 1}


def _resolve_pending_intent_flag_alias(expression: str | None, aliases: dict[str, str]) -> str | None:
    """Resolve bounded final-constant aliases; ambiguous or complex values remain unknown."""
    if expression is None:
        return None
    value = expression.strip()
    for _ in range(5):
        if re.search(r'\bFLAG_(?:IMMUTABLE|MUTABLE)\b', value):
            return value if re.fullmatch(r'[\w.\s|()]+', value) else None
        name = re.fullmatch(r'\(?\s*(\w+)\s*\)?', value)
        if not name or name.group(1) not in aliases:
            return None
        value = aliases[name.group(1)].strip()
    return value if re.search(r'\bFLAG_(?:IMMUTABLE|MUTABLE)\b', value) else None


def mask_non_code(source):
    """Mask comments and quoted literals without moving review line locations."""
    tokens=re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
    return tokens.sub(lambda match:''.join('\n' if char=='\n' else ' ' for char in match.group()),source)


def method_spans(code):
    # Lexical scopes only. Handles one-line bodies and balanced nested braces;
    # neither symbol resolution nor control-flow dominance is claimed.
    pattern=re.compile(r'(?m)(?:^|(?<=[{};]))\s*(?:@[\w.]+(?:\([^\n]*\))?\s*)*(?:(?:public|private|protected|static|final|override|suspend|open|synchronized)\s+)*(?:fun\s+|[\w<>?.\[\]]+\s+)(\w+)\s*\([^;{}]*\)\s*(?::\s*[\w<>?.\[\]]+)?\s*(?:throws\s+[\w.,\s]+)?\s*\{')
    for match in pattern.finditer(code):
        depth=1;end=match.end()
        while end<len(code) and depth:
            if code[end]=='{':depth+=1
            elif code[end]=='}':depth-=1
            end+=1
        if depth==0:yield match[1],match.start(),code[match.start():end]


def class_spans(code):
    """Yield bounded lexical class-like declarations and their source ranges."""
    pattern = re.compile(r'\b(?:class|interface|enum|object)\s+([A-Za-z_$][\w$]*)[^;{}]*\{')
    for match in pattern.finditer(code):
        depth = 1
        end = match.end()
        while end < len(code) and depth:
            if code[end] == '{':
                depth += 1
            elif code[end] == '}':
                depth -= 1
            end += 1
        if depth == 0:
            yield match.group(1), match.start(), end


RULES = [
    ('webview','file_origin_universal_access',r'\bsetAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)',
     'Review universal access from WebView file origins','CWE-669',
     'Disable universal access from file URLs. Use an HTTPS asset-loader origin and explicitly constrain untrusted content.'),
    ('webview','file_origin_file_access',r'\bsetAllowFileAccessFromFileURLs\s*\(\s*true\s*\)',
     'Review cross-file access from WebView file origins','CWE-669',
     'Disable cross-file access; verify that attacker-controlled content cannot read a sensitive synthetic file.'),
    ('webview','mixed_content',r'\bsetMixedContentMode\s*\(\s*(?:(?:\w+\.)?MIXED_CONTENT_ALWAYS_ALLOW|0)\s*\)',
     'Review WebView mixed-content allowance','CWE-319',
     'Disallow mixed content and validate the actual origin/content trust boundary before asserting impact.'),
    ('intent','launch_protection_opt_out',r'\bremoveLaunchSecurityProtection\s*\(',
     'Review intent launch-security opt-out','CWE-927',
     'Avoid opting out of platform launch protection; validate nested intent destinations and URI grants.'),
    ('webview','web_contents_debugging_enabled',r'\bsetWebContentsDebuggingEnabled\s*\(\s*true\s*\)',
     'Review WebView debugging enabled','CWE-489',
     'Disable WebView remote debugging in release builds; confirm the effective build variant and reachable WebView data before assessing impact.'),
    ('webview','safe_browsing_disabled',r'\bsetSafeBrowsingEnabled\s*\(\s*false\s*\)',
     'Review WebView Safe Browsing disabled','CWE-693',
     'Keep Safe Browsing enabled unless a documented compatibility requirement exists; verify platform/API behavior and user exposure.'),
]


class AndroidSurfaceAnalyzer:
    def analyze_source(self, source, path):
        code=mask_non_code(source);findings=[]
        pending_intent_aliases = _pending_intent_flag_aliases(code)
        sites={'webview':[], 'intent':[], 'deep_links':[], 'serialization':[], 'logging':[], 'storage':[]}
        for category,pattern in [('webview',r'\b(?:loadUrl|loadDataWithBaseURL|evaluateJavascript|addJavascriptInterface|setJavaScriptEnabled)\s*\('),
                                 ('intent',r'\b(?:startActivity|startService|sendBroadcast|getParcelableExtra|parseUri|registerReceiver)\s*\('),
                                 ('deep_links',r'\b(?:getData|getDataString|getQueryParameter|shouldOverrideUrlLoading)\s*\(')]:
            for match in list(re.finditer(pattern,code))[:100]:
                sites[category].append({'file':path,'line':code.count('\n',0,match.start())+1,'operation':match.group().split('(')[0].strip()})
        for match in list(re.finditer(r'\b(?:readObject|readParcelable|readSerializable|fromJson|readValue|load)\s*\(', code))[:100]:
            if any(token in match.group(0) for token in ('readObject', 'readParcelable', 'readSerializable', 'fromJson', 'readValue')):
                sites['serialization'].append({'file':path,'line':code.count('\n',0,match.start())+1,
                                                'operation':match.group(0).split('(')[0].strip()})
        log_call = re.compile(r'\b(?:(?:android\.util\.)?Log\s*\.\s*(?:v|d|i|w|e|wtf)|Timber\s*\.\s*(?:tag\s*\([^)]{0,256}\)\s*\.\s*)?(?:v|d|i|w|e|wtf)|System\s*\.\s*out\s*\.\s*print(?:ln)?)\s*\(')
        sensitive_name = re.compile(r'\b[\w$]*(?:token|password|passwd|secret|cookie|session[_$]?id|api[_$]?key|authorization)[\w$]*\b', re.I)
        for match in list(log_call.finditer(code))[:100]:
            arguments = _call_arguments(code, match.end() - 1)
            if sensitive_name.search(arguments):
                sites['logging'].append({'file':path,'line':code.count('\n',0,match.start())+1,
                                         'operation':match.group(0).split('(')[0].strip()})
        # A narrowly lexical lead for obvious preference writes whose key or
        # value uses a sensitive-looking identifier. This does not establish
        # persistence, encryption, backup inclusion, or data sensitivity.
        preference_write = re.compile(
            r'(?:\b[\w$]*(?:prefs?|preferences|settings?)\s*\.\s*'
            r'(?:edit\s*\(\s*\)\s*\.\s*)?|\.\s*edit\s*\(\s*\)\s*\.\s*)'
            r'put(?:String|StringSet|Int|Long|Float|Boolean)\s*\('
        )
        for match in list(preference_write.finditer(code))[:100]:
            arguments = _call_arguments(code, match.end() - 1)
            if sensitive_name.search(arguments):
                sites['storage'].append({'file':path,'line':code.count('\n',0,match.start())+1,
                                         'operation':match.group(0).split('(')[0].strip()})
        world_mode_call = re.compile(r'\b(?:openFileOutput|getSharedPreferences)\s*\(')
        for match in list(world_mode_call.finditer(code))[:100]:
            args = _split_arguments(_call_arguments(code, match.end() - 1))
            if len(args) >= 2 and re.search(r'\bMODE_WORLD_(?:READABLE|WRITEABLE)\b', args[1]):
                sites['storage'].append({'file':path,'line':code.count('\n',0,match.start())+1,
                                         'operation':match.group(0).split('(')[0].strip()})
        def add(category,check,title,cwe,fix,offset,context='configuration pattern'):
            line=source.count('\n',0,offset)+1
            findings.append(Finding(title=title,description=f'{context} was observed. External reachability, effective guards, attacker control and impact are not established. Review the actual call path and validate with synthetic data.',
                severity=Severity.INFO,cwe_id=cwe,file_path=path,line_number=line,
                code_snippet=source.splitlines()[line-1][:300],detection_method='AndroidSurfaceAnalyzer',
                status=FindingStatus.UNVERIFIED,remediation=fix,
                metadata={'category':category,'check_id':check,'proof_state':'not_proven',
                          'requires':['external reachability','attacker-controlled input','effective guard review','ordinary-app reproduction','positive and negative controls']}))
        for category,check,pattern,title,cwe,fix in RULES:
            for match in list(re.finditer(pattern,code))[:25]:add(category,check,title,cwe,fix,match.start())
        for match in list(PENDING_INTENT_CALL.finditer(code))[:50]:
            flags_argument = _resolve_pending_intent_flag_alias(
                _last_call_argument(code, match.end() - 1), pending_intent_aliases)
            # Unknown flag variables are not resolved; constants in context,
            # request-code or Intent arguments do not prove mutability flags.
            if flags_argument is not None and re.search(r'\bFLAG_MUTABLE\b', flags_argument):
                add('intent','pending_intent_mutable_flags_review',
                    'Review mutable PendingIntent flags', 'CWE-927',
                    'Use FLAG_IMMUTABLE unless fill-in behavior is required. If mutable is required, constrain who can obtain the PendingIntent and validate the effective fill-in fields, target SDK/platform behavior and authorization impact with positive and negative controls. The literal flag alone does not establish exploitability.',
                    match.start(),'PendingIntent factory final flags argument contains the literal FLAG_MUTABLE')
            elif flags_argument is None or not re.search(r'\bFLAG_(?:IMMUTABLE|MUTABLE)\b', flags_argument):
                add('intent','pending_intent_mutability_review',
                    'Review PendingIntent mutability flags', 'CWE-927',
                    'Review the effective flags expression against the app target and platform versions; use immutable by default and mutable only when required. Resolve constants/helpers and validate actual fill-in behavior before assessing impact.',
                    match.start(),'PendingIntent factory flags argument lacks a literal mutability flag or could not be lexically isolated')
        declared_classes = list(class_spans(code))
        bridge_methods = {}
        for name,offset,body in method_spans(code):
            header = body.split("{",1)[0]
            if (re.search(r'\bsetJavaScriptEnabled\s*\(\s*true\s*\)', body)
                    and re.search(r'\b(?:loadUrl|loadDataWithBaseURL|addJavascriptInterface)\s*\(', body)):
                add('webview','javascript_enabled_with_content_or_bridge_review',
                    'Review JavaScript-enabled WebView with content or bridge operations','CWE-749',
                    'Determine whether the loaded content can be attacker controlled and whether JavaScript bridges are registered; constrain origins, disable JavaScript when unnecessary, and validate message authorization with a controlled origin and negative control. Same-method co-occurrence is not dataflow or reachability proof.',
                    offset,'same method enables JavaScript and loads WebView content or registers a JavaScript interface')
            if re.search(r'@(?:android\.webkit\.)?JavascriptInterface\b',header):
                containing = [row for row in declared_classes if row[1] <= offset < row[2]]
                owner = min(containing, key=lambda row: row[2] - row[1])[0] if containing else None
                if owner:
                    bridge_methods.setdefault(owner, []).append(name[:128])
                sites['webview'].append({'file':path,'line':code.count('\n',0,offset)+1,
                                         'operation':'JavascriptInterface method',
                                         'method_name':name,
                                         'evidence':'annotation_inventory_only; registration and exposure unresolved'})
            for log_match in list(log_call.finditer(body))[:20]:
                args = _call_arguments(body, log_match.end() - 1)
                if sensitive_name.search(args):
                    add('logging','sensitive_identifier_in_log_review',
                        'Review possible sensitive value in log statement','CWE-532',
                        'Verify the logged value is actually sensitive and reachable in production; remove or safely redact it, and test log exposure without using real credentials. Identifier matching is heuristic and does not establish value flow or log accessibility.',
                        offset + log_match.start(),'log arguments reference a sensitive-looking identifier (value flow and log access not proven)')
                    break
            for storage_match in list(preference_write.finditer(body))[:20]:
                args = _call_arguments(body, storage_match.end() - 1)
                if sensitive_name.search(args):
                    add('storage','sensitive_identifier_in_preference_write_review',
                        'Review possible sensitive value in preference write','CWE-922',
                        'Determine whether this is persistent storage and whether the key/value is sensitive; review encryption/key management, backup/export behavior, access controls and lifecycle. Remove or protect sensitive data where required. Identifier matching is heuristic and establishes none of those properties.',
                        offset + storage_match.start(),
                        'preference-like write arguments reference a sensitive-looking identifier (storage and value flow not proven)')
                    break
            for mode_match in list(world_mode_call.finditer(body))[:20]:
                args = _split_arguments(_call_arguments(body, mode_match.end() - 1))
                if len(args) >= 2 and re.search(r'\bMODE_WORLD_(?:READABLE|WRITEABLE)\b', args[1]):
                    add('storage','world_accessible_app_file_mode_review',
                        'Review deprecated world-accessible app file mode','CWE-732',
                        'Remove world-readable/writeable modes and use private storage. Verify target SDK, runtime API behavior, file contents, backup rules and access path before assessing impact; this lexical configuration lead is not proof that another app can access the file.',
                        offset + mode_match.start(),
                        'file/preferences API mode argument contains a deprecated world-access constant (effective platform behavior not resolved)')
            if (re.search(r'\b(?:readObject|readParcelable|readSerializable|fromJson|readValue)\s*\(',body)
                    and re.search(r'\b(?:getIntent|getParcelableExtra|getSerializableExtra|getExtras|onReceive|onTransact|getInputStream)\s*\(',body)):
                add('serialization','untrusted_deserialization_source_sink_review',
                    'Review untrusted input near deserialization operation','CWE-502',
                    'Trace the specific untrusted value into the deserializer, validate type allowlists and object construction, then test only with a scoped synthetic payload and negative control. Same-method proximity is not dataflow proof.',
                    offset,'same-method deserialization operation and possible IPC/input source (dataflow not proven)')
            if (re.search(r'\baddJavascriptInterface\s*\(',body)
                    and re.search(r'\b(?:getIntent|getData|getQueryParameter)\s*\(',body)
                    and re.search(r'\b(?:loadUrl|loadDataWithBaseURL)\s*\(',body)):
                add('webview','external_input_webview_bridge_review',
                    'Review external input near WebView bridge and content load','CWE-749',
                    'Trace the exact external value to the loaded origin and bridge-exposed methods, validate scheme/host and message authorization, and reproduce with a controlled origin plus negative control. Co-location does not establish a flow or exploit.',
                    offset,'same-method external-input, JavaScript-interface and WebView load operations (dataflow not proven)')
            if name=='onReceivedSslError' and re.search(r'\b\w+\.proceed\s*\(',body):
                add('webview','ssl_error_proceed','Review SSL-error acceptance in WebView callback','CWE-295',
                    'Cancel SSL errors rather than proceeding; reproduce only with a researcher-controlled TLS endpoint.',offset,'SSL callback containing proceed()')
            if re.search(r'\b(?:loadUrl|shouldOverrideUrlLoading)\s*\(',body) and re.search(r'\.(?:startsWith|endsWith|contains)\s*\(',body):
                add('deep_links','weak_uri_guard','Review substring/prefix URI validation near WebView loading','CWE-20',
                    'Parse URIs and validate scheme and complete host against exact approved origins; verify this comparison actually guards the load.',offset,'URI-loading method with string-based comparisons (relationship not proven)')
            if re.search(r'\bIntent\.parseUri\s*\(',body) and re.search(r'\b(?:startActivity|startService|sendBroadcast)\s*\(',body):
                add('intent','parsed_intent_launch','Review parsed intent URI near component launch','CWE-927',
                    'Validate/sanitize the parsed intent, explicit destination, selector and URI permission flags before launch.',offset,'Parsed intent and launcher in one method (dataflow not proven)')
        registration_pattern = re.compile(r'\baddJavascriptInterface\s*\(')
        for registration in list(registration_pattern.finditer(code))[:50]:
            args = _split_arguments(_call_arguments(code, registration.end() - 1))
            type_match = (re.fullmatch(r'\s*(?:new\s+)?([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\([\s\S]*\)\s*', args[0])
                          if args else None)
            # Do not collapse qualified names to a basename: an external
            # package type could collide with an unrelated local declaration.
            simple_type = type_match.group(1) if type_match and '.' not in type_match.group(1) else None
            class_matches = [row for row in declared_classes if row[0] == simple_type] if simple_type else []
            status = ('same_file_constructor_type_match' if len(class_matches) == 1
                      else 'ambiguous_class_name' if len(class_matches) > 1
                      else 'dynamic_or_unresolved_object_expression')
            methods = bridge_methods.get(simple_type, [])[:50] if status == 'same_file_constructor_type_match' else []
            sites['webview'].append({
                'file':path,'line':code.count('\n',0,registration.start())+1,
                'operation':'addJavascriptInterface registration',
                'registered_object_type':simple_type[:128] if simple_type else None,
                'annotated_methods':methods,
                'association_status':status if not methods else 'same_file_constructor_type_has_annotated_methods',
                'evidence':'same_file_lexical_inventory_only; registration success, effective origin and invocation unresolved',
            })
        return findings,sites

    def scan(self, directory, manifest):
        findings=[];sites={'webview':[], 'intent':[], 'deep_links':[], 'serialization':[], 'logging':[], 'storage':[]};count=0;size=0;skipped=0;limited=False
        base=Path(directory) if directory else None
        inventory=SourceInventory(max_entries=MAX_FILES,max_file_bytes=MAX_FILE_BYTES,max_total_bytes=MAX_SOURCE_BYTES)
        if base and base.is_dir():
            for path,data in inventory.read(base,{'.java','.kt'}):
                count=inventory.coverage['source_files_analyzed'];size=inventory.coverage['source_bytes_analyzed']
                found,observed=self.analyze_source(data.decode('utf-8',errors='replace'),str(path.relative_to(base)))
                remaining=max(0,MAX_FINDINGS-len(findings))
                findings.extend(found[:remaining])
                if len(found)>remaining:inventory.coverage['limits_reached']=True
                for category in sites:sites[category].extend(observed[category][:max(0,500-len(sites[category]))])
        skipped=inventory.coverage['source_files_skipped'];limited=inventory.coverage['limits_reached']
        status=inventory.coverage['static_status']
        categories={category:{'static_status':status,'source_sites':values,'candidate_count':sum(f.metadata['category']==category for f in findings),
            'runtime_status':'not_tested','proof_status':'not_proven',
            'limitations':['bounded lexical review; not full control-flow/dataflow','native/reflection/runtime-loaded behavior not exhaustively analyzed','no ordinary-app exploit validator executed']} for category,values in sites.items()}
        categories['deep_links']['manifest_inventory']=manifest.get('deep_link_coverage',{'status':'unavailable'})
        categories['deep_links']['declared_routes']=len(manifest.get('deep_links',[]))
        return {'findings':findings,'coverage':{'categories':categories,'source_files_analyzed':count,
            'source_bytes_analyzed':size,'source_files_skipped':skipped,'limits_reached':limited,
            'source_file_skip_reasons':dict(inventory.coverage['source_file_skip_reasons']),
            'limit_reasons':dict(inventory.coverage['limit_reasons']),
            'exhaustive':False,'automatic_exploit_proof':False,'site_listing_limits':{'per_file_per_category':100,'per_category':500}}}

    async def analyze(self,directory,manifest):
        return await asyncio.to_thread(self.scan,directory,manifest)
