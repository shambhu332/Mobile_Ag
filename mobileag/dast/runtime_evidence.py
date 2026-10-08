"""Conservative log attribution. New target logs are observations, not causation proof."""
from collections import Counter
import re

_THREADTIME=re.compile(r'^\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+(\d+)\s+\d+\s+[VDIWEFA]\s+')
_PROCESS=re.compile(r'\bProcess:\s*([A-Za-z0-9_.:]+),\s*PID:\s*(\d+)\b')


def new_lines(before,after):
    old=Counter(before);fresh=[]
    for line in after:
        if old[line]:old[line]-=1
        else:fresh.append(line)
    return fresh


def attributed_crashes(lines,package):
    pids=set()
    for line in lines:
        process=_PROCESS.search(line)
        if process and (process[1]==package or process[1].startswith(package+':')):
            pids.add(process[2])
    return [line for line in lines if 'FATAL EXCEPTION' in line and
            (header:=_THREADTIME.match(line)) and header[1] in pids]
