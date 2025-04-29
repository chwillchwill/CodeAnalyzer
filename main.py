import os
import re
import csv
import argparse
import hashlib
from collections import defaultdict

SUPPORTED_EXTENSIONS = ['.cs', '.vb', '.ts']
COMPLEXITY_KEYWORDS = ['if', 'for', 'while', 'case', 'catch', '&&', '||', '?']
hash_registry = defaultdict(list)
call_map = defaultdict(set)
method_complexity_map = {}

MAX_CRITICAL_DEPTH = 10


def get_files(root_dir):
    code_files = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            if any(file.endswith(ext) for ext in SUPPORTED_EXTENSIONS):
                code_files.append(os.path.join(root, file))
    return code_files


def normalize_code(lines):
    code = ' '.join(line.strip() for line in lines if line.strip() and not line.strip().startswith('//'))
    code = re.sub(r'\s+', ' ', code)
    return code


def get_code_hash(lines):
    normalized = normalize_code(lines)
    return hashlib.md5(normalized.encode('utf-8')).hexdigest()


def count_complexity(lines):
    complexity = 1
    for line in lines:
        for keyword in COMPLEXITY_KEYWORDS:
            complexity += line.count(keyword)
    return complexity


def check_solid_principles(lines):
    solid_score = 5
    for line in lines:
        if 'new ' in line and '(' in line:
            solid_score -= 1
        if 'static' in line:
            solid_score -= 1
        if 'interface' in line:
            solid_score += 1
        if 'abstract' in line:
            solid_score += 1
    return max(0, solid_score)


def check_hateoas_principles(lines):
    hateoas_score = 0
    for line in lines:
        if 'self' in line or 'rel=' in line or '/links' in line:
            hateoas_score += 1
    return hateoas_score


def calculate_health(complexity, solid, hateoas, copied):
    health = 10 - (complexity / 10) + (solid / 2) + (1 if hateoas > 0 else 0)
    if copied == 'YES':
        health -= 2
    return round(max(0, min(10, health)), 1)


def calculate_critical_path_score(name):
    visited = set()

    def dfs(n, depth):
        if depth > MAX_CRITICAL_DEPTH or n in visited:
            return 0
        visited.add(n)
        score = method_complexity_map.get(n, 0)
        for callee in call_map.get(n, []):
            score += dfs(callee, depth + 1)
        return score

    return round(dfs(name, 0), 2)


def extract_calls(lines):
    calls = set()
    for line in lines:
        matches = re.findall(r'\b(\w+)\s*\(', line)
        for m in matches:
            if m not in ['if', 'for', 'while', 'switch', 'return', 'catch', 'foreach']:
                calls.add(m)
    return calls


def analyze_file(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    results = []
    current_block = []
    block_name = None
    block_type = None

    for line in lines:
        stripped = line.strip()

        match_method = re.match(r'(public|private|protected|internal)?\s*(static)?\s*\w+\s+(\w+)\(.*\)\s*[{]?',
                                stripped)
        match_class = re.match(r'(public|private)?\s*(class|interface|abstract)\s+(\w+)', stripped)

        if match_method or match_class:
            if current_block and block_name:
                results.append(analyze_block(file_path, block_type, block_name, current_block))
                current_block = []

            if match_class:
                block_type = 'class'
                block_name = match_class.group(3)
            elif match_method:
                block_type = 'method'
                block_name = match_method.group(3)

        current_block.append(stripped)

    if current_block and block_name:
        results.append(analyze_block(file_path, block_type, block_name, current_block))

    return results


def analyze_block(file_path, block_type, block_name, lines):
    block_hash = get_code_hash(lines)
    hash_registry[block_hash].append((file_path, block_type, block_name))

    complexity = count_complexity(lines)
    solid = check_solid_principles(lines)
    hateoas = check_hateoas_principles(lines)
    copied = 'YES' if len(hash_registry[block_hash]) > 1 else 'NO'
    health = calculate_health(complexity, solid, hateoas, copied)

    if block_type == 'method':
        method_complexity_map[block_name] = complexity
        call_map[block_name] = extract_calls(lines)

    critical_path_score = calculate_critical_path_score(block_name) if block_type == 'method' else 0

    return {
        'file': file_path,
        'type': block_type,
        'name': block_name,
        'complexity': complexity,
        'solid_score': solid,
        'hateoas_score': hateoas,
        'copied': copied,
        'health_score': health,
        'critical_path_score': critical_path_score
    }


def export_to_csv(results, output_file):
    keys = ['file', 'type', 'name', 'complexity', 'solid_score', 'hateoas_score', 'copied', 'health_score',
            'critical_path_score']
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for row in results:
            writer.writerow(row)
    print(f"\nMain report saved to {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Analyze .NET and TypeScript code for quality and architecture.")
    parser.add_argument("path", help="Root directory of the codebase")
    parser.add_argument("--output", default="analysis_report.csv", help="CSV file to write the results to")
    args = parser.parse_args()

    all_results = []
    files = get_files(args.path)
    for file_path in files:
        results = analyze_file(file_path)
        all_results.extend(results)

    export_to_csv(all_results, args.output)


if __name__ == "__main__":
    main()
