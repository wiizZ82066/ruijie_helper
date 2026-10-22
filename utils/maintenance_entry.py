"""Small command-line tasks; never initialize the desktop or authentication service."""
import argparse
import ctypes
import os
from pathlib import Path


def _journal():
    from utils.connection_events import LocalJournal
    directory = Path(os.environ.get('APPDATA', str(Path.home()))) / 'CampusLogin'
    return LocalJournal(directory / 'logs' / 'maintenance')


def run_maintenance(arguments, *, entry_script=None):
    """Return None for ordinary UI startup, otherwise the maintenance exit code."""
    if not any(arg in ('--check-driver', '--setup-startup') or
               arg.startswith('--setup-startup=') for arg in arguments):
        return None
    parser = argparse.ArgumentParser(description='校园网助手维护任务')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--check-driver', action='store_true')
    group.add_argument('--setup-startup', choices=('enable', 'disable', 'remove-owned'))
    args = parser.parse_args(arguments)
    from utils.app_version import VERSION
    journal = _journal()
    operation = 'driver' if args.check_driver else 'startup_' + args.setup_startup
    journal.write('maintenance_start', '维护任务开始', operation=operation, reason=VERSION)
    code = 1
    try:
        if args.check_driver:
            from utils.driver_setup import probe_driver, EXIT_CODES
            code = EXIT_CODES[probe_driver()['state']]
        elif not ctypes.windll.shell32.IsUserAnAdmin():
            journal.write('maintenance_denied', '需要管理员权限', operation=operation)
        else:
            from utils.auth_startup import set_startup
            set_startup(args.setup_startup == 'enable', entry_script=entry_script,
                        remove_only_matching=args.setup_startup == 'remove-owned')
            code = 0
    except Exception as error:
        # Never serialize exception text, command arguments, paths or account data.
        journal.write('maintenance_failed', '维护任务失败', operation=operation,
                      error_type=type(error).__name__)
    finally:
        journal.write('maintenance_end', '维护任务结束', operation=operation,
                      outcome='ok' if code == 0 else 'failed', reason=str(code))
    return code
