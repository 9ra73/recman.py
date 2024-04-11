#!/usr/bin/python3

"""
recman.py - Recording Manager for mirakc

This script manages recording schedules based on the ruleset defined in YAML.

"""

import argparse
import ast
import copy
import datetime
import http.client
import json
import logging
import pathlib
import re
import sys
import time
import unicodedata

import yaml

try:
    from fuzzywuzzy import fuzz  # Optional. Use rapidfuzz if available
except ModuleNotFoundError:
    pass

MIRAKC_HOST = 'localhost:40772'

logger = logging.getLogger('recman')


def update_schedule(services, ruleset, keep, dryrun):
    scheduled = {s['program']['id']: s for s in api_recording_list()}

    for service in services:
        now = time.time() * 1000

        for program in api_service_program_list(service['id']):
            if 'name' not in program:
                continue

            if program['startAt'] + program['duration'] < now:
                continue

            pid = program['id']

            rule = ruleset(service['id'], normalize(program['name']), combined_genres(program))
            if rule is None:
                if not keep and pid in scheduled and 'manual' not in scheduled[pid]['tags']:
                    if not dryrun:
                        api_recording_delete(pid)
                    logger.info('untracked %s', format_program(service, program))
                    scheduled.pop(pid)
                continue

            logger.debug('matched %s rule=%s', format_program(service, program), rule)

            tags = rule.get('tags', [])
            into = rule.get('into')
            priority = rule.get('priority', 1)
            exclude = rule.get('exclude', False)

            content_path = format_content_name(program)
            if into:
                content_path = str(pathlib.Path(into).joinpath(content_path))

            deleted = False

            if pid in scheduled:
                if program['startAt'] > now + 180_000:
                    if exclude or needs_update(scheduled[pid], content_path, priority, tags):
                        if not dryrun:
                            api_recording_delete(pid)
                        deleted = True
                        scheduled.pop(pid)

            if exclude:
                if deleted:
                    logger.info('canceled %s', format_program(service, program))
                continue

            if pid not in scheduled:
                if not dryrun:
                    schedule = api_recording_add(pid, content_path, priority, tags)
                else:
                    schedule = {
                        'state': 'scehduled',
                        'program': program,
                        'options': {
                            'contentPath': content_path,
                            'priority': priority,
                        },
                        'tags': tags,
                    }

                if deleted:
                    logger.info('updated %s', format_schedule(service, schedule))
                else:
                    logger.info('added %s', format_schedule(service, schedule))

                scheduled[pid] = schedule

    return scheduled.values()


def combined_genres(program):
    return set(
        g['lv1'] << 4 | g['lv2']
        for g in program.get('genres', [])
    )


def needs_update(schedule, content_path, priority, tags):
    if schedule['options']['contentPath'] != content_path:
        return True
    if schedule['options']['priority'] != priority:
        return True
    if set(schedule['tags']) != set(tags):
        return True
    return False


def compile_ruleset(path: pathlib.Path):
    with path.open() as fp:
        rules = yaml.safe_load(fp)

    func = ast.FunctionDef(
        name='ruleset',
        args=ast.arguments(
            posonlyargs=[],
            args=[ast.arg('sid'), ast.arg('name'), ast.arg('genres')],
            kwonlyargs=[],
            kw_defaults=[],
            defaults=[],
        ),
        body=[],
        decorator_list=[],
        type_params=[],
    )

    has_fuzz = 'fuzz' in globals()

    for i, rule in enumerate(rules):
        if rule.get('disabled', False):
            continue

        test = []

        if 'services' in rule:
            test.append(ast.Compare(
                left=ast.Name(id='sid', ctx=ast.Load()),
                ops=[ast.In()],
                comparators=[ast.Set(elts=[
                    ast.Constant(s) for s in rule['services']
                ])],
            ))

        if 'services!' in rule:
            test.append(ast.Compare(
                left=ast.Name(id='sid', ctx=ast.Load()),
                ops=[ast.NotIn()],
                comparators=[ast.Set(elts=[
                    ast.Constant(s) for s in rule['services!']
                ])],
            ))

        if 'genres' in rule:
            test.append(ast.BinOp(
                left=ast.Name(id='genres', ctx=ast.Load()),
                op=ast.BitAnd(),
                right=ast.Set(elts=[
                    ast.Constant(g) for g in rule['genres']
                ]),
            ))

        if 'genres!' in rule:
            test.append(ast.UnaryOp(op=ast.Not(), operand=ast.BinOp(
                left=ast.Name(id='genres', ctx=ast.Load()),
                op=ast.BitAnd(),
                right=ast.Set(elts=[
                    ast.Constant(g) for g in rule['genres!']
                ]),
            )))

        if 'prefix' in rule:
            test.append(bool_or([
                ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id='name', ctx=ast.Load()),
                        attr='startswith',
                        ctx=ast.Load()
                    ),
                    args=[ast.Constant(normalize(v))],
                    keywords=[],
                )
                for v in list_str(rule['prefix'])
            ]))

        if 'prefix!' in rule:
            test.append(bool_and([
                ast.UnaryOp(op=ast.Not(), operand=ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id='name', ctx=ast.Load()),
                        attr='startswith',
                        ctx=ast.Load(),
                    ),
                    args=[ast.Constant(normalize(v))],
                    keywords=[],
                ))
                for v in list_str(rule['prefix!'])
            ]))

        if 'suffix' in rule:
            test.append(bool_or([
                ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id='name', ctx=ast.Load()),
                        attr='endswith',
                        ctx=ast.Load(),
                    ),
                    args=[ast.Constant(normalize(v))],
                    keywords=[],
                )
                for v in list_str(rule['suffix'])
            ]))

        if 'suffix!' in rule:
            test.append(bool_and([
                ast.UnaryOp(op=ast.Not(), operand=ast.Call(
                    func=ast.Attribute(
                        value=ast.Name(id='name', ctx=ast.Load()),
                        attr='endswith',
                        ctx=ast.Load(),
                    ),
                    args=[ast.Constant(normalize(v))],
                    keywords=[],
                ))
                for v in list_str(rule['suffix!'])
            ]))

        if 'name' in rule:
            test.append(bool_or([
                ast.Compare(
                    left=ast.Constant(normalize(v)),
                    ops=[ast.In()],
                    comparators=[ast.Name(id='name', ctx=ast.Load())],
                )
                for v in list_str(rule['name'])
            ]))

        if 'name!' in rule:
            test.append(bool_and([
                ast.Compare(
                    left=ast.Constant(normalize(v)),
                    ops=[ast.NotIn()],
                    comparators=[ast.Name(id='name', ctx=ast.Load())],
                )
                for v in list_str(rule['name!'])
            ]))

        if 'fuzz' in rule:
            assert has_fuzz, f'fuzzy matching is not available. rule={rule}'

            test.append(bool_or([
                ast.Call(
                    func=ast.Name(id='partial_match', ctx=ast.Load()),
                    args=[
                        ast.Constant(normalize(v)),
                        ast.Name(id='name', ctx=ast.Load()),
                        ast.Constant(rule.get('fuzz_ratio', 90)),
                    ],
                    keywords=[],
                )
                for v in list_str(rule['fuzz'])
            ]))

        if 'fuzz!' in rule:
            assert has_fuzz, f'fuzzy matching is not available. rule={rule}'

            test.append(bool_and([
                ast.UnaryOp(op=ast.Not(), operand=ast.Call(
                    func=ast.Name(id='partial_match', ctx=ast.Load()),
                    args=[
                        ast.Constant(normalize(v)),
                        ast.Name(id='name', ctx=ast.Load()),
                        ast.Constant(rule.get('fuzz_ratio', 90)),
                    ],
                    keywords=[],
                ))
                for v in list_str(rule['fuzz!'])
            ]))

        func.body.append(ast.If(
            test=bool_and([t for t in test if t is not None]),
            body=[ast.Return(value=ast.Subscript(
                value=ast.Name(id='rules', ctx=ast.Load()),
                slice=ast.Constant(i),
                ctx=ast.Load(),
            ))],
            orelse=[],
        ))

    module = ast.Module(body=[func], type_ignores=[])
    ast.fix_missing_locations(module)

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug('compiled ruleset:\n%s', ast.unparse(module))

    scope = {'rules': rules, 'partial_match': partial_match}
    exec(compile(module, '<ruleset>', 'exec'), scope)
    return scope['ruleset']


def partial_match(a, b, th):
    r = fuzz.partial_ratio(a.upper(), b.upper())
    if r >= th:
        logger.debug('partial_ratio=%d %r', r, b)
        return True
    return False


def bool_and(v):
    if len(v) == 1:
        return v[0]
    if len(v) > 1:
        return ast.BoolOp(op=ast.And(), values=v)


def bool_or(v):
    if len(v) == 1:
        return v[0]
    if len(v) > 1:
        return ast.BoolOp(op=ast.Or(), values=v)


def list_str(v):
    if not isinstance(v, list):
        assert isinstance(v, str)
        return [v]
    return v


def batch_update(ruleset_path, keep, dryrun):
    ruleset = compile_ruleset(ruleset_path)

    with api_context():
        services = api_service_list()
        scheduled = list(update_schedule(services, ruleset, keep, dryrun))
        tuners = api_tuner_list()

    dump_scheduled(services, scheduled)
    dump_conflicted(services, scheduled, tuners)


def dump_scheduled(services, scheduled):
    scheduled = copy.copy(scheduled)
    scheduled.sort(key=lambda s: s['program']['startAt'])
    scheduled.sort(key=lambda s: index_service(services, s['program']))

    for s in scheduled:
        pid = s['program']['id']
        date = format_timestamp(s['program']['startAt'])
        sname = normalize(find_service(services, s['program'])['name'])
        pname = normalize(s['program']['name'])
        state = s['state']
        priority = s['options']['priority']
        print(f'{pid:15} {priority:2} {state:9} {date} {sname}: {pname}')


def dump_conflicted(services, scheduled, tuners):
    scheduled = copy.copy(scheduled)
    scheduled.sort(key=lambda s: s['program']['startAt'])

    checkpoints = set()
    conflicted = []

    for s in scheduled:
        checkpoints.add(s['program']['startAt'])
        checkpoints.add(s['program']['startAt'] + s['program']['duration'])

    for ts in sorted(checkpoints):
        recs, fails = [], []
        avails = [t['types'] for t in tuners]

        for s in scheduled:
            if s['program']['startAt'] <= ts < s['program']['startAt'] + s['program']['duration']:
                for tuner in avails:
                    if find_service(services, s['program'])['channel']['type'] in tuner:
                        recs.append(s)
                        avails.remove(tuner)
                        break
                else:
                    fails.append(s)

        if fails:
            conflicted.append((ts, recs, fails))

    for ts, recs, fails in conflicted:
        print()
        print('Tuner shortage detected at', format_timestamp(ts))
        dump_scheduled(services, recs + fails)


def watch_event(ruleset_path: pathlib.Path, keep, dryrun):
    conn = http.client.HTTPConnection(MIRAKC_HOST)

    wait_for_socket(conn)

    try:
        conn.request('GET', '/events')
        res = conn.getresponse()

        assert res.status == 200, f'HTTP {res.status} {res.reason}'
        assert res.getheader('Content-Type') == 'text/event-stream'
        assert res.getheader('Transfer-Encoding') == 'chunked'

        logger.info('watching event stream')

        ruleset_mtime = 0
        ruleset_size = 0
        ruleset_cache = None

        for msg in iter_event_message(res):
            event, data = msg['event'], json.loads(msg['data'])
            if event != 'epg.programs-updated':
                continue

            logger.info('handle %s event service_id=%d', event, data['serviceId'])

            if not ruleset_path.exists():
                logger.warning('ruleset not found: %s', ruleset_path)
                continue

            stat = ruleset_path.resolve().stat()
            if stat.st_mtime_ns != ruleset_mtime or stat.st_size != ruleset_size:
                try:
                    ruleset_cache = compile_ruleset(ruleset_path)
                    ruleset_mtime = stat.st_mtime_ns
                    ruleset_size = stat.st_size
                except Exception as e:
                    logger.error('failed to compile ruleset: %s', e)
                    continue

            with api_context():
                service = api_service_get(data['serviceId'])
                update_schedule([service], ruleset_cache, keep, dryrun)

    finally:
        conn.close()


def wait_for_socket(conn: http.client.HTTPConnection):
    for _ in range(10):
        try:
            conn.connect()
        except ConnectionRefusedError:
            logger.info('waiting for mirakc socket: %s', MIRAKC_HOST)
            time.sleep(3)
        else:
            break
    else:
        logger.error('failed to connect: %s', MIRAKC_HOST)
        sys.exit(1)


def iter_event_message(res: http.client.HTTPResponse):
    msg = {}
    for line in res:
        if line == b'\n':
            if msg:
                yield msg
                msg = {}
        elif line[0] != ord(':'):
            s = re.split(r':\s*', line.rstrip().decode('utf-8'), 1)
            n, v = s[0], s[1] if len(s) > 1 else ''
            if n in msg:
                v = msg[n] + '\n' + v
            msg[n] = v


class api_context:
    conn: http.client.HTTPConnection = None

    @classmethod
    def __enter__(cls):
        assert cls.conn is None, 'Nested api_context is not allowed'
        cls.conn = http.client.HTTPConnection(MIRAKC_HOST)

    @classmethod
    def __exit__(cls, exc_type, exc_value, traceback):
        cls.conn.close()
        cls.conn = None  # noqa


def api_service_list():
    api_context.conn.request('GET', '/api/services')
    res = api_context.conn.getresponse()
    assert res.status == 200, f'HTTP {res.status} {res.reason}'
    return json.load(res)


def api_service_get(sid):
    api_context.conn.request('GET', f'/api/services/{sid}')
    res = api_context.conn.getresponse()
    assert res.status == 200, f'HTTP {res.status} {res.reason}'
    return json.load(res)


def api_service_program_list(sid):
    api_context.conn.request('GET', f'/api/services/{sid}/programs')
    res = api_context.conn.getresponse()
    assert res.status == 200, f'HTTP {res.status} {res.reason}'
    return json.load(res)


def api_tuner_list():
    api_context.conn.request('GET', '/api/tuners')
    res = api_context.conn.getresponse()
    assert res.status == 200, f'HTTP {res.status} {res.reason}'
    return json.load(res)


def api_recording_list():
    api_context.conn.request('GET', '/api/recording/schedules')
    res = api_context.conn.getresponse()
    assert res.status == 200, f'HTTP {res.status} {res.reason}'
    return json.load(res)


def api_recording_add(pid, content_path, priority, tags):
    headers = {
        'Content-Type': 'application/json',
    }
    body = json.dumps({
        'programId': pid,
        'options': {
            'contentPath': content_path,
            'priority': priority,
        },
        'tags': tags,
    })
    api_context.conn.request('POST', '/api/recording/schedules', body=body, headers=headers)
    res = api_context.conn.getresponse()
    assert res.status == 201, f'HTTP {res.status} {res.reason}'
    return json.load(res)


def api_recording_delete(pid):
    api_context.conn.request('DELETE', f'/api/recording/schedules/{pid}')
    res = api_context.conn.getresponse()
    assert res.status == 200 or res.status == 404, f'HTTP {res.status} {res.reason}'
    res.read()


def index_service(services, program):
    nid = program['networkId']
    sid = program['serviceId']
    for i, s in enumerate(services):
        if s['serviceId'] == sid and s['networkId'] == nid:
            return i


def find_service(services, program):
    try:
        return services[index_service(services, program)]
    except IndexError:
        return None


def format_program(service, program):
    pid = program['id']
    sname = normalize(service['name'])
    pname = normalize(program['name'])
    return f'{pid} {sname}: {pname}'


def format_schedule(service, schedule):
    pid = schedule['program']['id']
    sname = normalize(service['name'])
    pname = normalize(schedule['program']['name'])
    state = schedule['state']
    return f'{pid} {state} {sname}: {pname}'


def format_content_name(program):
    pid = program['id']
    date = format_timestamp(program['startAt'], '%Y%m%d%H%M')
    name = safename(program['name'])
    return f'{name} {date}_{pid}.m2ts'


def format_timestamp(t, f='%Y-%m-%d %H:%M'):
    return datetime.datetime.fromtimestamp(t / 1000).strftime(f)


def normalize(s):
    return unicodedata.normalize('NFKC', s)


safename_table = str.maketrans({c: None for c in (
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
    0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x22,
    0x2a, 0x2f, 0x3a, 0x3c, 0x3e, 0x3f, 0x5c, 0x7c,
)})


def safename(name):
    return name.strip().translate(safename_table)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-k', '--keep', action='store_true', help='keep untracked schedules')
    parser.add_argument('-n', '--dryrun', action='store_true', help='dry-run mode')
    parser.add_argument('--watch', action='store_true', help='watch event stream')
    parser.add_argument('--debug', action='store_true', help='enable debug logging')
    parser.add_argument('ruleset', type=pathlib.Path, help='ruleset.yml')
    return parser.parse_args()


def main():
    args = parse_args()

    logging.basicConfig(format='[%(levelname)8s] %(name)s: %(message)s', level=logging.INFO)

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        # http.client.HTTPConnection.debuglevel = 1

    if args.watch:
        watch_event(args.ruleset, args.keep, args.dryrun)
    else:
        batch_update(args.ruleset, args.keep, args.dryrun)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('interrupted', file=sys.stderr)
