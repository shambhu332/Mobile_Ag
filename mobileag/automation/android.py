"""Explicit dedicated-device ADB adapter; never root, grant consent or clear data.

ADB input is device-wide and subject to foreground/input TOCTOU. Pre/post
package checks are guardrails, not a package isolation or ordinary-app boundary.
"""
import hashlib
import re
import uuid
import xml.etree.ElementTree as ET
from mobileag.dast.adb_manager import ADBManager

SAFE_LABELS={'Profile','Settings','Home','Search','Back','Cancel','Next','Login','Log in','Sign in','Register','Notifications','Menu','Help','About','Retry','Refresh'}
CANONICAL_LABELS={label.casefold():label for label in SAFE_LABELS}
DANGEROUS=re.compile(r'(?i)\b(delete|remove|wipe|reset|pay|buy|purchase|subscribe|transfer|send|submit|grant|allow|agree|accept|confirm|logout|log out|sign out|upload|download)\b')

def digest(value):return hashlib.sha256(value.encode()).hexdigest()[:24]

def parse_snapshot(xml,package):
    if len(xml.encode())>1024*1024:raise ValueError('Hierarchy limit exceeded')
    try:root=ET.fromstring(xml)
    except ET.ParseError:raise ValueError("Invalid hierarchy XML")
    nodes=list(root.iter('node'))
    if not nodes or len(nodes)>1000:raise ValueError('Hierarchy unavailable or too large')
    if any(n.get('package')!=package for n in nodes):raise PermissionError('System dialog or outside-package UI; operator must resolve it')
    elements=[]
    for node in nodes:
        a=node.attrib
        m=re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]',a.get('bounds',''))
        bounds=list(map(int,m.groups())) if m else []
        if bounds and not (0<=bounds[0]<bounds[2]<=20000 and 0<=bounds[1]<bounds[3]<=20000):bounds=[]
        cls=a.get('class','').split('.')[-1]
        if cls not in {'EditText','AutoCompleteTextView','Button','ImageButton','ScrollView','RecyclerView','TextView','LinearLayout','FrameLayout','Switch','CheckBox','RadioButton','Spinner','ProgressBar','ImageView','View'}:cls='CustomControl'
        editable=cls in {'EditText','AutoCompleteTextView'} or a.get('password')=='true'
        label=a.get('text') or a.get('content-desc') or ''
        # Android Button may render curated labels in ALL CAPS. Only canonical
        # allowlisted names are exposed; arbitrary text is never retained.
        safe_label=CANONICAL_LABELS.get(label.casefold())
        rid=a.get('resource-id','')
        elements.append({'locator':digest('rid:'+rid) if rid else digest('a11y:'+cls+'|'+safe_label) if safe_label and not editable else None,'locator_kind':'resource_id' if rid else 'unique_accessibility_name' if safe_label and not editable else 'unavailable','class':cls if cls.isalnum() and len(cls)<60 else 'Control',
            'label':safe_label if safe_label and not editable else 'Text input' if editable else 'Control',
            'label_hash':digest(label) if label and not editable else None,
            'editable':editable,'clickable':a.get('clickable')=='true','enabled':a.get('enabled','true')=='true',
            'scrollable':a.get('scrollable')=='true','named':bool(a.get('content-desc') or label),
            'dangerous':bool(DANGEROUS.search(label)),'bounds':bounds})
    signature=[(e['locator'],e['class'],e['label_hash'],e['clickable'],e['editable']) for e in elements]
    return {'id':digest(repr(signature)),'elements':elements}

class AndroidDriver:
    def __init__(self,adb:ADBManager,serial,package):self.adb,self.serial,self.package=adb,serial,package
    async def metadata(self):
        result={'adapter':'ADB/UIAutomator','ordinary_app_exploit_proof':False}
        for name,prop in [('android_version','ro.build.version.release'),('sdk_level','ro.build.version.sdk'),('fingerprint','ro.build.fingerprint')]:
            code,value,_=await self.adb._exec_cmd(['-s',self.serial,'shell','getprop',prop],timeout=2,output_limit=4096)
            result[name]=value.decode(errors='replace').strip()[:512] if not code else 'not_observed'
        code,identity,_=await self.adb._exec_cmd(['-s',self.serial,'shell','id'],timeout=2,output_limit=4096)
        result['root_shell_observed']=code==0 and b'uid=0(root)' in identity
        code,package,_=await self.adb._exec_cmd(['-s',self.serial,'shell','dumpsys','package',self.package],timeout=3,output_limit=1024*1024)
        text=package.decode(errors='replace') if not code else ''
        for field,pattern in [('version_name',r'versionName=([A-Za-z0-9_.+-]{1,128})'),('version_code',r'versionCode=(\d+)')]:
            match=re.search(pattern,text);result[field]=match[1] if match else 'not_observed'
        return result

    async def foreground(self):
        code,out,_=await self.adb._exec_cmd(['-s',self.serial,'shell','dumpsys','window','windows'],timeout=4,output_limit=1024*1024)
        text=out.decode(errors='replace')
        focused=re.search(r'mCurrentFocus=Window\{[^\n]*?\s([\w.]+)/',text)
        if code or not focused or focused[1]!=self.package:raise PermissionError('Foreground package is not the approved application')
    async def snapshot(self):
        await self.foreground()
        path='/data/local/tmp/mobileag-ui-'+uuid.uuid4().hex+'.xml'
        try:
            code,_,_=await self.adb._exec_cmd(['-s',self.serial,'shell','uiautomator','dump',path],timeout=15,output_limit=16384)
            if code:raise ValueError('UI hierarchy dump failed')
            code,out,_=await self.adb._exec_cmd(['-s',self.serial,'shell','cat',path],timeout=4,output_limit=1024*1024)
            if code:raise ValueError('UI hierarchy read failed')
            await self.foreground()
            return parse_snapshot(out.decode(errors='replace'),self.package)
        finally:
            await self.adb._exec_cmd(['-s',self.serial,'shell','rm','-f',path],timeout=3,output_limit=16384)
    async def launch(self,component):
        result=await self.adb.launch_activity(self.serial,component)
        if result['status']!='success':raise ValueError('Application launch failed or timed out')
    async def act(self,action,element=None):
        await self.foreground()
        if action=='back':args=['keyevent','4']
        else:
            if not element or not element['bounds']:raise ValueError('No safe current locator bounds')
            x1,y1,x2,y2=element['bounds'];x=(x1+x2)//2;y=(y1+y2)//2
            args=['tap',str(x),str(y)] if action=='tap' else ['swipe',str(x),str(y2-1),str(x),str(y1+1),'300']
        code,_,_=await self.adb._exec_cmd(['-s',self.serial,'shell','input',*args],timeout=3,output_limit=16384)
        if code:raise ValueError('UI input was not acknowledged')
