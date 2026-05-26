"""Thread-safe IDA API execution wrapper.
All IDA API calls run in batch mode to suppress modal dialogs/warnings."""
import threading

import ida_kernwin

MFF_READ = ida_kernwin.MFF_READ
MFF_WRITE = ida_kernwin.MFF_WRITE

_batch_fn = None  # lazy-init: callable(int) -> old_value, or False if unavailable
IDA_SYNC_TIMEOUT = 180.0
_executor = None


def _get_batch_fn():
    """Lazily detect the batch mode API."""
    global _batch_fn
    if _batch_fn is not None:
        return _batch_fn
    # idc.batch(v) returns the previous batch value -- works on IDA 7.x-9.x
    try:
        import idc
        old = idc.batch(0)
        idc.batch(old)
        _batch_fn = idc.batch
        return _batch_fn
    except:
        pass
    try:
        import idaapi
        if hasattr(idaapi, 'cvar') and hasattr(idaapi.cvar, 'batch'):
            def _set(v):
                old = idaapi.cvar.batch
                idaapi.cvar.batch = v
                return old
            _batch_fn = _set
            return _batch_fn
    except:
        pass
    _batch_fn = False
    return _batch_fn


def set_executor(executor):
    """Install an alternate IDA execution backend.

    GUI IDA uses ida_kernwin.execute_sync. idalib has no UI event loop, so
    headless workers install a small main-thread executor instead.
    """
    global _executor
    _executor = executor


def clear_executor():
    """Remove the alternate IDA execution backend."""
    global _executor
    _executor = None


def _call_in_batch(fn, *args):
    batch = _get_batch_fn()
    prev = None
    try:
        if batch:
            prev = batch(1)
        return fn(*args)
    finally:
        if batch and prev is not None:
            batch(prev)


def run_in_ida(fn, *args, write=False):
    """Execute fn(*args) on IDA's main thread, blocking until done.
    Temporarily enables batch mode to suppress all dialogs."""
    executor = _executor
    if executor is not None:
        return executor.call(lambda: _call_in_batch(fn, *args), write=write)

    result = [None]
    exc = [None]
    ev = threading.Event()

    def _run():
        try:
            result[0] = _call_in_batch(fn, *args)
        except Exception as e:
            exc[0] = e
        finally:
            ev.set()
        return 0

    mode = MFF_WRITE if write else MFF_READ
    ida_kernwin.execute_sync(_run, mode)
    if not ev.wait(IDA_SYNC_TIMEOUT):
        raise TimeoutError(f'IDA main thread did not run callback within {IDA_SYNC_TIMEOUT}s')
    if exc[0]:
        raise exc[0]
    return result[0]


def read(fn, *args):
    """Shorthand for run_in_ida with MFF_READ."""
    return run_in_ida(fn, *args, write=False)


def write(fn, *args):
    """Shorthand for run_in_ida with MFF_WRITE."""
    return run_in_ida(fn, *args, write=True)
