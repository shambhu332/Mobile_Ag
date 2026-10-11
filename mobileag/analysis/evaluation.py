"""Instance-level offline evaluation for synthetic source fixtures.

A finding matches by CWE AND sink line. Multiple expected instances of the same
CWE are scored separately. Exceptions remain coverage failures and misses, never
clean passes. This is not APK exploit validation or a field accuracy estimate.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Callable


def validate_corpus(corpus: dict) -> None:
    if corpus.get('schema_version') != 1 or not isinstance(corpus.get('cases'), list) or not corpus['cases']:
        raise ValueError('Expected a nonempty schema_version=1 instance corpus')
    ids = set()
    for case in corpus['cases']:
        if not isinstance(case.get('id'), str) or not case['id'] or case['id'] in ids:
            raise ValueError('Case IDs must be unique nonempty strings')
        ids.add(case['id'])
        if case.get('language') not in {'java', 'kotlin'} or not isinstance(case.get('source'), str) or not case['source'].strip():
            raise ValueError('Cases require Java/Kotlin source')
        if not isinstance(case.get('expected'), list):
            raise ValueError('Cases require explicit expected instances, including [] for negatives')
        keys = []
        for expected in case['expected']:
            line = expected.get('sink_line')
            cwe = expected.get('cwe')
            if type(line) is not int or not 1 <= line <= len(case['source'].splitlines()) or not isinstance(cwe, str) or not cwe.startswith('CWE-'):
                raise ValueError('Expected instances require CWE and a valid sink line')
            keys.append((cwe, line))
        if len(keys) != len(set(keys)):
            raise ValueError('Ambiguous duplicate expected locations; use separate fixture lines')


def evaluate_instances(corpus: dict, analyze: Callable) -> dict:
    validate_corpus(corpus)
    totals = Counter(tp=0, fp=0, fn=0, duplicate_reports=0, failed_cases=0)
    rows = []
    groups = {}
    for case in corpus['cases']:
        expected = {(e['cwe'], e['sink_line']) for e in case['expected']}
        error = None
        try:
            findings = list(analyze(case['source'], f"evaluation/{case['id']}.{case['language']}"))
            # Invalid detector output is an execution failure, not an empty success.
            if any(not isinstance(f.cwe_id, str) or type(f.line_number) is not int or f.line_number < 1
                   for f in findings):
                raise ValueError('Detector returned an invalid finding location')
            observed_counts = Counter((f.cwe_id, f.line_number) for f in findings)
        except Exception as exc:
            observed_counts = Counter()
            error = type(exc).__name__  # no exception text/source/secrets in reports
        observed = set(observed_counts)
        scores = {'tp': len(expected & observed), 'fp': len(observed - expected),
                  'fn': len(expected - observed),
                  'duplicate_reports': sum(n - 1 for n in observed_counts.values()),
                  'failed_cases': int(error is not None)}
        totals.update(scores)
        row = {'id': case['id'], 'language': case['language'], **scores,
               'execution_status': 'error' if error else 'completed', 'error_type': error,
               'expected': [dict(cwe=c, sink_line=l) for c, l in sorted(expected)],
               'observed': [dict(cwe=c, sink_line=l) for c, l in sorted(observed, key=lambda x: (str(x[0]), str(x[1])))]}
        rows.append(row)
        for cwe in {c for c, _ in expected | observed}:
            counts = groups.setdefault(cwe, Counter(tp=0, fp=0, fn=0))
            counts.update(tp=sum(c == cwe for c, _ in expected & observed),
                          fp=sum(c == cwe for c, _ in observed - expected),
                          fn=sum(c == cwe for c, _ in expected - observed))
    def rates(counts):
        return {**counts, 'precision': counts['tp'] / (counts['tp'] + counts['fp']) if counts['tp'] + counts['fp'] else None,
                'recall': counts['tp'] / (counts['tp'] + counts['fn']) if counts['tp'] + counts['fn'] else None}
    return {'schema_version': 1, 'matching': 'case_cwe_sink_line',
            'corpus_sha256': hashlib.sha256(json.dumps(corpus, sort_keys=True).encode()).hexdigest(),
            'case_count': len(rows), **rates(totals),
            'by_cwe': {k: rates(v) for k, v in sorted(groups.items())}, 'cases': rows,
            'limitations': ['Synthetic source-level candidates only; no exploit validation.',
                            'Committed fixtures are regression tests, not a blind holdout.',
                            'No path, method, OS, backend or whole-APK coverage is inferred.']}


def assert_disjoint(corpus: dict, reference: dict) -> None:
    """Reject exact source/ID leakage against a training or regression corpus."""
    ids = {c['id'] for c in reference['cases']}
    sources = {c['source'].strip() for c in reference['cases']}
    if any(c['id'] in ids or c['source'].strip() in sources for c in corpus['cases']):
        raise ValueError('Evaluation overlaps reference IDs or source content')
