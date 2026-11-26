"""Mount a ShellCrash PF ruleset for the lifetime of its supervisor."""

import argparse
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import sys
import tempfile


PFCTL = "/sbin/pfctl"
ANCHOR = "shellcrash-pf-lab"
ABSENT = "rdr-anchor absent\nanchor absent\n"


def run(*argv, check=True):
    return subprocess.run(argv, text=True, capture_output=True, timeout=8, check=check)


def report(text):
    try:
        print(text, end='', flush=True)
    except BrokenPipeError:
        # A killed controller must not interrupt cleanup through its log pipe.
        with open(os.devnull, 'wb') as discard:
            os.dup2(discard.fileno(), sys.stdout.fileno())


def rollback(mount, token_path, nat=False):
    scope = ('--nat',) if nat else ()
    actions = [
        (PFCTL, "-a", ANCHOR, "-f", "/dev/null"),
        (mount, "main", "remove", *scope),
    ]
    if token_path.exists():
        actions.append((PFCTL, "-X", token_path.read_text()))
    failed = False
    for command in actions:
        try:
            result = run(*command, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            print(error, file=sys.stderr)
            failed = True
            continue
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr, end="")
            failed = True
    if run(mount, "main", "status", *scope).stdout != absent_calls(nat):
        print("FAIL project calls still attached", file=sys.stderr)
        return 1
    if failed:
        return 1
    token_path.unlink(missing_ok=True)
    token_path.parent.rmdir()
    report('PASS project anchor removed and PF token released\n')
    return 0


def stop_owned_core(pid, config):
    command = run('/bin/ps', '-ww', '-p', pid, '-o', 'command=', check=False)
    if command.returncode == 0 and command.stdout.strip().endswith(f' -f {config}'):
        try:
            os.kill(int(pid), signal.SIGTERM)
        except ProcessLookupError:
            pass


def absent_calls(nat):
    return ABSENT + ('nat-anchor absent\n' if nat else '')


def watchdog(mount, token, reader, timeout, nat, *owned_core):
    # An expired lease and EOF both schedule the same idempotent removal.
    select.select([reader], [], [], timeout if timeout >= 0 else None)
    status = rollback(mount, Path(token), nat)
    if status:
        print(f"PF rollback details retained in {Path(token).parent}", file=sys.stderr)
    elif owned_core:
        stop_owned_core(*owned_core)
    return status


def snapshot():
    return tuple(run(PFCTL, flag).stdout for flag in ("-sr", "-sn"))


@contextmanager
def managed_rules(mount, rules, core_pid, core_config):
    worker = subprocess.Popen([sys.executable, '-B', __file__, '--owned-core', core_pid, core_config,
                               mount, str(rules), '0', '/bin/cat'], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, text=True)
    try:
        if not select.select([worker.stdout], [], [], 12)[0] or 'calls mounted' not in worker.stdout.readline():
            raise RuntimeError('PF worker did not report readiness')
        yield worker
    finally:
        worker.stdin.close()
        try:
            status = worker.wait(timeout=35)
        except subprocess.TimeoutExpired:
            worker.terminate()
            status = worker.wait(timeout=10)
        with worker.stdout:
            text = worker.stdout.read()
        if text:
            report(text)
        if status:
            raise RuntimeError('PF worker exited unsuccessfully')


def lease(mount, rules, timeout, command, owned_core=(), nat=False):
    run(PFCTL, "-n", "-a", ANCHOR, "-f", rules)
    descriptor = os.open("/var/run/shellcrash-pf-lab.lock", os.O_CREAT | os.O_NOFOLLOW | os.O_RDONLY, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        scope = ('--nat',) if nat else ()
        if run(mount, "main", "status", *scope).stdout != absent_calls(nat):
            raise RuntimeError("project anchor already attached")
        for flag in ("-sr", "-sn", "-sAnchors"):
            if run(PFCTL, "-a", ANCHOR, flag).stdout.strip():
                raise RuntimeError("project anchor is not empty")
        before = snapshot()
        token_path = Path(tempfile.mkdtemp(prefix="shellcrash-pf-lease-"), "token")
        reader, writer = os.pipe()
        try:
            guard = subprocess.Popen(
                [sys.executable, __file__, "--watchdog", mount, str(token_path), str(reader),
                 str(timeout + 25 if timeout else -1), str(int(nat)), *owned_core],
                pass_fds=(reader, descriptor), start_new_session=True,
            )
        except OSError:
            os.close(writer)
            token_path.parent.rmdir()
            raise
        finally:
            os.close(reader)
        try:
            result = run(PFCTL, "-E")
            token = re.search(r"Token\s*:\s*(\d+)", result.stdout + result.stderr)
            if token is None:
                raise RuntimeError("pfctl did not report an enable token")
            token_path.write_text(token[1])
            run(mount, "main", "attach", *scope)
            run(PFCTL, "-a", ANCHOR, "-f", rules)
            print("PASS project filter and rdr calls mounted", flush=True)
            try:
                status = subprocess.run(command, timeout=timeout or None, check=False).returncode
            except subprocess.TimeoutExpired:
                print("PF lab command timed out", file=sys.stderr, flush=True)
                status = 124
        finally:
            os.close(writer)
            if guard.wait(timeout=30) != 0:
                raise RuntimeError("PF watchdog could not complete rollback")
            if snapshot() != before:
                raise RuntimeError("main PF rules differ after rollback")
            print("PASS main filter and translation rules restored", flush=True)
        return status
    finally:
        os.close(descriptor)


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


def main():
    if os.geteuid() != 0:
        raise SystemExit("run against the lab Mac as root")
    if len(sys.argv) in (7, 9) and sys.argv[1] == "--watchdog":
        return watchdog(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5]), sys.argv[6] == '1', *sys.argv[7:])

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owned-core", nargs=2, metavar=("PID", "CONFIG"))
    parser.add_argument("--nat", action="store_true", help="also attach the project's NAT anchor")
    parser.add_argument("mount", type=lambda value: str(Path(value).resolve()))
    parser.add_argument("rules", type=lambda value: str(Path(value).resolve()))
    parser.add_argument("timeout", type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not args.command or not 0 <= args.timeout <= 300:
        parser.error("provide a command and a lease of 0 to 300 seconds (0 lasts until the command exits)")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    if args.owned_core and (not args.owned_core[0].isdigit() or int(args.owned_core[0]) <= 1):
        parser.error("invalid owned core PID")
    return lease(args.mount, args.rules, args.timeout, args.command, args.owned_core or (), args.nat)


if __name__ == "__main__":
    raise SystemExit(main())
