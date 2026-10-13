#!/usr/bin/env python3
"""Offline location-aware candidate evaluation; accepts an external blind corpus."""
import argparse
import importlib.metadata
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mobileag.analysis.evaluation import evaluate_instances, assert_disjoint
from mobileag.analysis.taint_engine import TaintEngine


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--corpus', type=Path, required=True)
    parser.add_argument('--disjoint-from', type=Path, action='append', default=[])
    parser.add_argument('--lexical-only', action='store_true')
    args = parser.parse_args()
    corpus = json.loads(args.corpus.read_text())
    for reference in args.disjoint_from:
        assert_disjoint(corpus, json.loads(reference.read_text()))
    engine = TaintEngine()
    if args.lexical_only:
        engine._java_ast.available = False
    report = evaluate_instances(corpus, engine.analyze_source_content)
    report['backend'] = 'java_ast_plus_lexical' if engine._java_ast.available else 'lexical_fallback'
    report['parser_coverage'] = {
        **engine.ast_coverage,
        'coverage_scope': 'Java parser attempts in the source fixture corpus; no DEX/decompiler accounting',
    }
    report['python_version'] = sys.version.split()[0]
    report['corpus_file_sha256'] = hashlib.sha256(args.corpus.read_bytes()).hexdigest()
    root = Path(__file__).resolve().parents[1]
    report['analysis_source_sha256'] = {
        name: hashlib.sha256((root / 'mobileag/analysis' / name).read_bytes()).hexdigest()
        for name in ('taint_engine.py', 'java_ast_taint.py', 'source_syntax.py', 'evaluation.py')
    }
    report['tool_versions'] = {}
    for name in ('tree-sitter', 'tree-sitter-java'):
        try:
            report['tool_versions'][name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            report['tool_versions'][name] = 'not_installed'
    print(json.dumps(report, indent=2))
    return int(bool(report['fp'] or report['fn'] or report['failed_cases']))


if __name__ == '__main__':
    raise SystemExit(main())
