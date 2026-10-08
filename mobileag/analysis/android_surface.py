"""Bounded Android surface review. Pattern evidence is never exploit proof."""
from __future__ import annotations
import asyncio
import re
from pathlib import Path
from mobileag.reporting.finding import Finding, FindingStatus, Severity

MAX_FILES=5000
MAX_FILE_BYTES=2*1024*1024
MAX_SOURCE_BYTES=32*1024*1024
MAX_FINDINGS=500


def mask_non_code(source):
    """Mask comments and quoted literals without moving review line locations."""
    tokens=re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'')
    return tokens.sub(lambda match:''.join('\n' if char=='\n' else ' ' for char in match.group()),source)


def method_spans(code):
    # Lexical scopes only. Handles one-line bodies and balanced nested braces;
    # neither symbol resolution nor control-flow dominance is claimed.
    pattern=re.compile(r'(?m)(?:^|(?<=[{};]))\s*(?:(?:public|private|protected|static|final|override|suspend|open|synchronized)\s+)*(?:fun\s+|[\w<>?.\[\]]+\s+)(\w+)\s*\([^;{}]*\)\s*(?::\s*[\w<>?.\[\]]+)?\s*(?:throws\s+[\w.,\s]+)?\s*\{')
    for match in pattern.finditer(code):
        depth=1;end=match.end()
        while end<len(code) and depth:
            if code[end]=='{':depth+=1
            elif code[end]=='}':depth-=1
            end+=1
        if depth==0:yield match[1],match.start(),code[match.start():end]


RULES = [
    ('webview','file_origin_universal_access',r'\bsetAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)',
     'Review universal access from WebView file origins','CWE-749',
     'Disable universal access from file URLs. Use an HTTPS asset-loader origin and explicitly constrain untrusted content.'),
    ('webview','file_origin_file_access',r'\bsetAllowFileAccessFromFileURLs\s*\(\s*true\s*\)',
     'Review cross-file access from WebView file origins','CWE-22',
     'Disable cross-file access; verify that attacker-controlled content cannot read a sensitive synthetic file.'),
    ('webview','mixed_content',r'\bsetMixedContentMode\s*\(\s*(?:(?:\w+\.)?MIXED_CONTENT_ALWAYS_ALLOW|0)\s*\)',
     'Review WebView mixed-content allowance','CWE-319',
     'Disallow mixed content and validate the actual origin/content trust boundary before asserting impact.'),
    ('intent','launch_protection_opt_out',r'\bremoveLaunchSecurityProtection\s*\(',
     'Review intent launch-security opt-out','CWE-927',
     'Avoid opting out of platform launch protection; validate nested intent destinations and URI grants.'),
]


class AndroidSurfaceAnalyzer:
    def analyze_source(self, source, path):
        code=mask_non_code(source);findings=[]
        sites={'webview':[], 'intent':[], 'deep_links':[]}
        for category,pattern in [('webview',r'\b(?:loadUrl|loadDataWithBaseURL|evaluateJavascript|addJavascriptInterface|setJavaScriptEnabled)\s*\('),
                                 ('intent',r'\b(?:startActivity|startService|sendBroadcast|getParcelableExtra|parseUri|registerReceiver)\s*\('),
                                 ('deep_links',r'\b(?:getData|getDataString|getQueryParameter|shouldOverrideUrlLoading)\s*\(')]:
            for match in list(re.finditer(pattern,code))[:100]:
                sites[category].append({'file':path,'line':code.count('\n',0,match.start())+1,'operation':match.group().split('(')[0].strip()})
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
        for name,offset,body in method_spans(code):
            if name=='onReceivedSslError' and re.search(r'\b\w+\.proceed\s*\(',body):
                add('webview','ssl_error_proceed','Review SSL-error acceptance in WebView callback','CWE-295',
                    'Cancel SSL errors rather than proceeding; reproduce only with a researcher-controlled TLS endpoint.',offset,'SSL callback containing proceed()')
            if re.search(r'\b(?:loadUrl|shouldOverrideUrlLoading)\s*\(',body) and re.search(r'\.(?:startsWith|endsWith|contains)\s*\(',body):
                add('deep_links','weak_uri_guard','Review substring/prefix URI validation near WebView loading','CWE-20',
                    'Parse URIs and validate scheme and complete host against exact approved origins; verify this comparison actually guards the load.',offset,'URI-loading method with string-based comparisons (relationship not proven)')
            if re.search(r'\bIntent\.parseUri\s*\(',body) and re.search(r'\b(?:startActivity|startService|sendBroadcast)\s*\(',body):
                add('intent','parsed_intent_launch','Review parsed intent URI near component launch','CWE-927',
                    'Validate/sanitize the parsed intent, explicit destination, selector and URI permission flags before launch.',offset,'Parsed intent and launcher in one method (dataflow not proven)')
        return findings,sites

    def scan(self, directory, manifest):
        findings=[];sites={'webview':[], 'intent':[], 'deep_links':[]};count=0;size=0;skipped=0;limited=False
        base=Path(directory) if directory else None
        if base and base.is_dir():
            for path in base.rglob('*'):
                if path.suffix not in {'.java','.kt'}:continue
                if count+skipped>=MAX_FILES:limited=True;break
                try:
                    if path.is_symlink() or not path.is_file() or path.stat().st_size>MAX_FILE_BYTES:skipped+=1;continue
                    data=path.read_bytes()
                    if size+len(data)>MAX_SOURCE_BYTES:limited=True;break
                    size+=len(data);count+=1
                    found,observed=self.analyze_source(data.decode('utf-8',errors='replace'),str(path.relative_to(base)))
                    remaining=max(0,MAX_FINDINGS-len(findings))
                    findings.extend(found[:remaining])
                    if len(found)>remaining:limited=True
                    for category in sites:sites[category].extend(observed[category][:max(0,500-len(sites[category]))])
                except (OSError,UnicodeError):skipped+=1
        status='not_analyzed' if not count else 'partial' if limited or skipped else 'analyzed_heuristically'
        categories={category:{'static_status':status,'source_sites':values,'candidate_count':sum(f.metadata['category']==category for f in findings),
            'runtime_status':'not_tested','proof_status':'not_proven',
            'limitations':['bounded lexical review; not full control-flow/dataflow','native/reflection/runtime-loaded behavior not exhaustively analyzed','no ordinary-app exploit validator executed']} for category,values in sites.items()}
        categories['deep_links']['manifest_inventory']=manifest.get('deep_link_coverage',{'status':'unavailable'})
        categories['deep_links']['declared_routes']=len(manifest.get('deep_links',[]))
        return {'findings':findings,'coverage':{'categories':categories,'source_files_analyzed':count,
            'source_bytes_analyzed':size,'source_files_skipped':skipped,'limits_reached':limited,
            'exhaustive':False,'automatic_exploit_proof':False,'site_listing_limits':{'per_file_per_category':100,'per_category':500}}}

    async def analyze(self,directory,manifest):
        return await asyncio.to_thread(self.scan,directory,manifest)
