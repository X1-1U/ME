"""Fetch public rule sources, preserve protected providers, deduplicate same-target rules."""
import concurrent.futures
import hashlib
import ipaddress
import json
import pathlib
import urllib.request
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[1]
ALLOWED = {('acl4ssr','acl4ssr'), ('metacubex','meta-rules-dat'), ('blackmatrix7','ios_rule_script'), ('liandu2024','clash')}

def validate_url(url):
    p = urllib.parse.urlsplit(url)
    parts = p.path.strip('/').split('/')
    if p.scheme != 'https' or p.hostname != 'raw.githubusercontent.com' or p.query or p.fragment or p.username or p.password or tuple(x.lower() for x in parts[:2]) not in ALLOWED:
        raise ValueError('Unapproved rule source')


def fetch(item):
    validate_url(item['source'])
    last = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(item['source'], timeout=45) as response:
                validate_url(response.url)
                raw = response.read(20_000_001)
            if len(raw) > 20_000_000:
                raise ValueError('Source too large')
            text = raw.decode('utf-8-sig')
            if '<html' in text[:1000].lower():
                raise ValueError('HTML instead of rules')
            lines = [x.strip() for x in text.splitlines() if x.strip() and not x.lstrip().startswith(('#', ';'))]
            if not lines:
                raise ValueError('Empty rule source')
            for line in lines:
                predicate(line, item['behavior'])
            return text, lines
        except Exception as exc:
            last = exc
    raise RuntimeError('Failed source: '+item['name']) from last


def predicate(line, behavior, flags=()):
    if behavior == 'domain':
        if line.startswith('+.'):
            p = ['DOMAIN-SUFFIX', line[2:].lower()]
        elif '*' not in line and not line.startswith('.'):
            p = ['DOMAIN', line.lower()]
        else:
            return ('DOMAIN-PATTERN', line.lower())
    elif behavior == 'ipcidr':
        p = ['IP-CIDR', str(ipaddress.ip_network(line, strict=False))]
    else:
        p = [x.strip() for x in line.split(',')]
        if len(p) < 2:
            raise ValueError('Malformed classical rule')
    if p[0] in ('DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD'):
        p[1] = p[1].lower()
    if p[0] in ('IP-CIDR', 'IP-CIDR6'):
        p[0] = 'IP-CIDR'
        p[1] = str(ipaddress.ip_network(p[1], strict=False))
        p = p[:2] + sorted(set(p[2:]) | set(flags))
    return tuple(p)


def build(manifest, fetched):
    output, entries, removed = {}, {}, {}
    by_name = {p['name']: p for p in manifest['providers']}
    for p in manifest['providers']:
        name = p['name']
        seen, clean = set(), []
        for line in fetched[name][1]:
            k = predicate(line, p['behavior'])
            if p['protected'] or k not in seen:
                clean.append(line)
            seen.add(k)
        entries[name] = clean
        removed[name] = len(fetched[name][1]) - len(clean)
    uses = {}
    for rule in manifest['rules']:
        q = rule.split(',')
        if q[0] == 'RULE-SET':
            uses[q[1]] = uses.get(q[1], 0) + 1
    seen_targets, visited = {}, set()
    for rule in manifest['rules']:
        q = rule.split(',')
        if q[0] != 'RULE-SET' or q[1] in visited:
            continue
        name, target = q[1:3]
        visited.add(name)
        if uses[name] != 1:
            continue
        p = by_name[name]
        prior = seen_targets.setdefault(target, set())
        clean = []
        for line in entries[name]:
            k = predicate(line, p['behavior'], q[3:])
            if p['protected'] or k not in prior:
                clean.append(line)
                prior.add(k)
            else:
                removed[name] += 1
        entries[name] = clean
    report = {}
    for p in manifest['providers']:
        name = p['name']
        if p['protected']:
            assert entries[name] == fetched[name][1]
        # Mylove remains its original root file. Never overwrite it.
        if p['output']:
            content = fetched[name][0] if p['protected'] else '\n'.join(entries[name])+'\n'
            output[p['output']] = content
        report[name] = {'source': p['source'], 'input': len(fetched[name][1]), 'output': len(entries[name]), 'removed': removed[name], 'protected': p['protected'], 'source_sha256': hashlib.sha256(fetched[name][0].encode()).hexdigest()}
    output['rules/managed/status.json'] = json.dumps(report, ensure_ascii=False, indent=2)+'\n'
    return output


def main():
    manifest = json.loads((ROOT/'rules-sources.json').read_text())
    # Fetch and validate every source before touching any published output.
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        values = list(pool.map(fetch, manifest['providers']))
    fetched = {p['name']: v for p, v in zip(manifest['providers'], values)}
    output = build(manifest, fetched)
    for name, content in output.items():
        path = ROOT/name
        if not path.resolve().is_relative_to((ROOT/'rules/managed').resolve()):
            raise ValueError('Unsafe output path')
    for name, content in output.items():
        path = ROOT/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')
    print('Synchronized', len(manifest['providers']), 'sources; protected added rules and Mylove')

if __name__ == '__main__':
    main()
