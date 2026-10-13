"""Instance-level offline evaluation for synthetic source fixtures.

A finding matches CWE, normalized source/sink paths, sink line, optional source
line, simple method names, lexical identities, and opt-in source-qualified Java
method labels. Multiple expected instances of the same CWE are scored separately.
Exceptions remain coverage failures and misses, never clean passes. This is not
APK exploit validation or a field accuracy estimate.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import PurePosixPath
from collections import Counter
from typing import Callable


def _normal_path(value: object) -> str | None:
    if not isinstance(value, str) or not value or "\x00" in value:
        return None
    value = value.replace("\\", "/")
    # PurePosixPath does not consider Windows drive paths absolute.
    if re.match(r"^[A-Za-z]:", value):
        return None
    path = PurePosixPath(value)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        return None
    return path.as_posix()


def _normal_method(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = " ".join(value.strip().split())
    return value if value and len(value) <= 256 else None


def _observed_path(trace: dict, finding: object, default_path: str, field: str) -> str:
    """Normalize recorded paths; invalid explicit paths are failures, not defaults."""
    trace_path = trace.get('file_path')
    if trace_path is not None:
        normalized = _normal_path(trace_path)
        if normalized is None:
            raise ValueError(f'Detector returned an invalid {field} path')
        return normalized
    finding_path = getattr(finding, 'file_path', None)
    if finding_path is not None:
        normalized = _normal_path(finding_path)
        if normalized is None:
            raise ValueError(f'Detector returned an invalid finding file path')
        return normalized
    return default_path


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
        if 'unsupported_constructs' in case:
            labels = case['unsupported_constructs']
            if not isinstance(labels, list) or len(labels) > 64:
                raise ValueError('unsupported_constructs must be a bounded list of construct labels')
            seen_labels = set()
            for label in labels:
                if not isinstance(label, dict) or set(label) - {'name', 'line'}:
                    raise ValueError('Unsupported-construct labels require only name and optional line')
                name = label.get('name')
                line = label.get('line')
                if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.:-]{0,127}', name):
                    raise ValueError('Unsupported-construct names must be bounded identifiers')
                if line is not None and (type(line) is not int or not 1 <= line <= len(case['source'].splitlines())):
                    raise ValueError('Unsupported-construct line must identify a source line')
                key = (name, line)
                if key in seen_labels:
                    raise ValueError('Duplicate unsupported-construct label per case')
                seen_labels.add(key)
        keys = []
        case_path = _normal_path(case.get('file_path') or f"evaluation/{case['id']}.{case['language']}")
        if case_path is None:
            raise ValueError('Case file_path must be a safe normalized relative source path')
        for expected in case['expected']:
            line = expected.get('sink_line')
            source_line = expected.get('source_line')
            cwe = expected.get('cwe')
            if type(line) is not int or not 1 <= line <= len(case['source'].splitlines()) or not isinstance(cwe, str) or not cwe.startswith('CWE-'):
                raise ValueError('Expected instances require CWE and a valid sink line')
            if source_line is not None and (type(source_line) is not int or not 1 <= source_line <= len(case['source'].splitlines())):
                raise ValueError('Optional source_line must identify a valid source line')
            source_file = _normal_path(expected.get('source_file', case_path))
            sink_file = _normal_path(expected.get('sink_file', case_path))
            source_method = _normal_method(expected.get('source_method')) if expected.get('source_method') is not None else None
            sink_method = _normal_method(expected.get('sink_method')) if expected.get('sink_method') is not None else None
            source_identity = _normal_method(expected.get('source_method_identity')) if expected.get('source_method_identity') is not None else None
            sink_identity = _normal_method(expected.get('sink_method_identity')) if expected.get('sink_method_identity') is not None else None
            source_qualified_identity = _normal_method(expected.get('source_qualified_method_identity')) if expected.get('source_qualified_method_identity') is not None else None
            sink_qualified_identity = _normal_method(expected.get('sink_qualified_method_identity')) if expected.get('sink_qualified_method_identity') is not None else None
            if source_file is None or sink_file is None:
                raise ValueError('Expected source/sink files must be safe normalized relative paths')
            if (expected.get('source_method') is not None and source_method is None) or (
                    expected.get('sink_method') is not None and sink_method is None):
                raise ValueError('Expected method identities must be nonempty bounded strings')
            for field, original, normalized in (
                ('source_method_identity', expected.get('source_method_identity'), source_identity),
                ('sink_method_identity', expected.get('sink_method_identity'), sink_identity),
                ('source_qualified_method_identity', expected.get('source_qualified_method_identity'), source_qualified_identity),
                ('sink_qualified_method_identity', expected.get('sink_qualified_method_identity'), sink_qualified_identity),
            ):
                if original is not None and normalized is None:
                    raise ValueError(f'Expected {field} must be a nonempty bounded string')
            keys.append((cwe, source_file, source_line, source_method, source_identity,
                         sink_file, line, sink_method, sink_identity,
                         source_qualified_identity, sink_qualified_identity))
        if len(keys) != len(set(keys)):
            raise ValueError('Ambiguous duplicate expected locations; use separate fixture lines')


def evaluate_instances(corpus: dict, analyze: Callable) -> dict:
    validate_corpus(corpus)
    totals = Counter(tp=0, fp=0, fn=0, duplicate_reports=0, failed_cases=0)
    rows = []
    groups = {}
    for case in corpus['cases']:
        default_path = _normal_path(case.get('file_path') or f"evaluation/{case['id']}.{case['language']}")
        expected = {(e['cwe'], _normal_path(e.get('source_file', default_path)), e.get('source_line'),
                     _normal_method(e.get('source_method')) if e.get('source_method') is not None else None,
                     _normal_method(e.get('source_method_identity')) if e.get('source_method_identity') is not None else None,
                     _normal_path(e.get('sink_file', default_path)), e['sink_line'],
                     _normal_method(e.get('sink_method')) if e.get('sink_method') is not None else None,
                     _normal_method(e.get('sink_method_identity')) if e.get('sink_method_identity') is not None else None,
                     _normal_method(e.get('source_qualified_method_identity')) if e.get('source_qualified_method_identity') is not None else None,
                     _normal_method(e.get('sink_qualified_method_identity')) if e.get('sink_qualified_method_identity') is not None else None)
                    for e in case['expected']}
        error = None
        try:
            findings = list(analyze(case['source'], default_path))
            # Invalid detector output is an execution failure, not an empty success.
            if any(not isinstance(f.cwe_id, str) or type(f.line_number) is not int or f.line_number < 1
                   for f in findings):
                raise ValueError('Detector returned an invalid finding location')
            instances = []
            for finding in findings:
                metadata = getattr(finding, 'metadata', {})
                trace = metadata.get('source_sink_trace', {}) if isinstance(metadata, dict) else {}
                source = trace.get('source', {}) if isinstance(trace, dict) else {}
                sink = trace.get('sink', {}) if isinstance(trace, dict) else {}
                source_line = source.get('line') if isinstance(source, dict) else None
                if type(source_line) is not int or source_line < 1:
                    source_line = None
                sink_line = sink.get('line') if isinstance(sink, dict) else None
                if type(sink_line) is not int or sink_line < 1:
                    sink_line = finding.line_number
                source_file = _observed_path(source if isinstance(source, dict) else {}, finding,
                                             default_path, 'source')
                sink_file = _observed_path(sink if isinstance(sink, dict) else {}, finding,
                                           default_path, 'sink')
                source_method = _normal_method(source.get('method') if isinstance(source, dict) else None)
                sink_method = _normal_method(sink.get('method') if isinstance(sink, dict) else None)
                source_identity = _normal_method(source.get('method_identity') if isinstance(source, dict) else None)
                sink_identity = _normal_method(sink.get('method_identity') if isinstance(sink, dict) else None)
                source_qualified_identity = _normal_method(source.get('source_qualified_method_identity') if isinstance(source, dict) else None)
                sink_qualified_identity = _normal_method(sink.get('source_qualified_method_identity') if isinstance(sink, dict) else None)
                instances.append((finding.cwe_id, source_file, source_line, source_method, source_identity,
                                  sink_file, sink_line, sink_method, sink_identity,
                                  source_qualified_identity, sink_qualified_identity))
            observed_counts = Counter(instances)
        except Exception as exc:
            observed_counts = Counter()
            error = type(exc).__name__  # no exception text/source/secrets in reports
        observed = set(observed_counts)
        # Expected records may omit optional source/method identity fields. A
        # broad expectation can therefore match the same output as a narrower
        # one. Greedy matching made scores depend on tuple sort order and could
        # undercount true positives; use deterministic maximum bipartite match.
        expected_order = sorted(expected, key=repr)
        observed_order = sorted(observed, key=repr)

        def compatible(expected_item, item):
            return (item[0] == expected_item[0] and item[6] == expected_item[6]
                    and item[1] == expected_item[1] and item[5] == expected_item[5]
                    and all(expected_item[index] is None or item[index] == expected_item[index]
                            for index in (2, 3, 4, 7, 8, 9, 10)))

        edges = {item: [candidate for candidate in observed_order if compatible(item, candidate)]
                 for item in expected_order}
        observed_owner = {}

        def assign(expected_item, seen):
            for candidate in edges[expected_item]:
                if candidate in seen:
                    continue
                seen.add(candidate)
                previous = observed_owner.get(candidate)
                if previous is None or assign(previous, seen):
                    observed_owner[candidate] = expected_item
                    return True
            return False

        for expected_item in expected_order:
            assign(expected_item, set())
        matched_expected = set(observed_owner.values())
        matched_observed = set(observed_owner)
        scores = {'tp': len(matched_expected), 'fp': len(observed - matched_observed),
                  'fn': len(expected - matched_expected),
                  'duplicate_reports': sum(n - 1 for n in observed_counts.values()),
                  'failed_cases': int(error is not None)}
        totals.update(scores)
        row = {'id': case['id'], 'language': case['language'], **scores,
               'unsupported_constructs': case.get('unsupported_constructs'),
               'execution_status': 'error' if error else 'completed', 'error_type': error,
               'expected': [dict(cwe=c, source_file=sf, source_line=sl, source_method=sm,
                                 source_method_identity=si, sink_file=kf, sink_line=kl,
                                 sink_method=km, sink_method_identity=ki,
                                 source_qualified_method_identity=sqi, sink_qualified_method_identity=kqi)
                            for c, sf, sl, sm, si, kf, kl, km, ki, sqi, kqi in sorted(expected, key=repr)],
               'observed': [dict(cwe=c, source_file=sf, source_line=sl, source_method=sm,
                                 source_method_identity=si, sink_file=kf, sink_line=kl,
                                 sink_method=km, sink_method_identity=ki,
                                 source_qualified_method_identity=sqi, sink_qualified_method_identity=kqi)
                            for c, sf, sl, sm, si, kf, kl, km, ki, sqi, kqi in sorted(observed, key=repr)]}
        rows.append(row)
        for cwe in {item[0] for item in expected | observed}:
            counts = groups.setdefault(cwe, Counter(tp=0, fp=0, fn=0))
            counts.update(tp=sum(item[0] == cwe for item in matched_expected),
                          fp=sum(item[0] == cwe for item in observed - matched_observed),
                          fn=sum(item[0] == cwe for item in expected - matched_expected))
    def rates(counts):
        return {**counts, 'precision': counts['tp'] / (counts['tp'] + counts['fp']) if counts['tp'] + counts['fp'] else None,
                'recall': counts['tp'] / (counts['tp'] + counts['fn']) if counts['tp'] + counts['fn'] else None}
    labeled_cases = sum('unsupported_constructs' in case for case in corpus['cases'])
    label_counts = Counter(label['name'] for case in corpus['cases']
                           for label in case.get('unsupported_constructs', []))
    label_status = ('not_measured' if labeled_cases == 0 else
                    'all_cases_labeled' if labeled_cases == len(corpus['cases']) else
                    'partial_corpus_labels')
    return {'schema_version': 5, 'matching': 'case_cwe_normalized_file_source_sink_optional_lexical_and_source_qualified_method_identity',
            'corpus_sha256': hashlib.sha256(json.dumps(corpus, sort_keys=True).encode()).hexdigest(),
            'case_count': len(rows), **rates(totals),
            'by_cwe': {k: rates(v) for k, v in sorted(groups.items())}, 'cases': rows,
            'input_coverage': {
                'corpus_cases_submitted': len(rows),
                'analyzer_invocations': len(rows),
                'cases_completed': len(rows) - totals['failed_cases'],
                'cases_failed': totals['failed_cases'],
                'cases_skipped': 0,
                'unsupported_constructs': {'status': 'not_measured', 'count': None},
                'unsupported_construct_labels': {
                    'status': label_status,
                    'cases_with_labels': labeled_cases,
                    'cases_submitted': len(corpus['cases']),
                    'label_occurrences': sum(label_counts.values()),
                    'by_construct': {name: {'case_occurrences': count} for name, count in sorted(label_counts.items())},
                    'scope': 'optional corpus-supplied annotations only; not automatic APK or language-coverage measurement',
                },
                'apk_extracted_source_files': {'status': 'not_in_scope', 'count': None},
            },
            'limitations': ['Synthetic source-level candidates only; no exploit validation.',
                            'Committed fixtures are regression tests, not a blind holdout.',
                            'Unsupported language constructs remain not_measured beyond optional corpus-supplied labels; APK extraction omissions are not enumerated.',
                            'Method identities are lexical Tree-sitter owner/signatures when available; no symbol resolution, OS, backend or whole-APK coverage is inferred.']}


def assert_disjoint(corpus: dict, reference: dict) -> None:
    """Reject exact source/ID leakage against a training or regression corpus."""
    ids = {c['id'] for c in reference['cases']}
    sources = {c['source'].strip() for c in reference['cases']}
    if any(c['id'] in ids or c['source'].strip() in sources for c in corpus['cases']):
        raise ValueError('Evaluation overlaps reference IDs or source content')
