"""Pre-built caches for expensive IDA queries.
Built once at activation in a SINGLE execute_sync call, invalidated on IDB changes.
Uses ida_strlist to read IDB's pre-built string list instead of re-scanning.
"""
import threading
import time

import idautils
import ida_funcs
import ida_bytes
import ida_nalt
import ida_segment
import ida_name
import ida_entry
import ida_strlist

from .thread_safe import read


class IdbCache:
    """Holds pre-built indexes for a single IDA instance."""

    def __init__(self):
        self._lock = threading.Lock()
        self._strings = None         # [(ea, string, strtype), ...]
        self._functions = None       # [(ea, name, size), ...]
        self._names = None           # [(ea, name), ...]
        self._imports = None         # [(module, name, ea, ord), ...]
        self._exports = None         # [(ea, name, ord), ...]
        self._segments = None        # [(start, end, name, cls, perm, bitness), ...]
        self._build_time = 0
        self._dirty = True

    def invalidate(self):
        with self._lock:
            self._dirty = True

    def ensure_built(self):
        """Build all caches if dirty. Single execute_sync call for all data."""
        with self._lock:
            if not self._dirty:
                return
            self._dirty = False

        t0 = time.time()

        def _build_all():
            result = {}

            # Strings: use ida_strlist (reads IDB's stored string list, no re-scan)
            strs = []
            qty = ida_strlist.get_strlist_qty()
            si = ida_strlist.string_info_t()
            for i in range(qty):
                if ida_strlist.get_strlist_item(si, i):
                    s = ida_bytes.get_strlit_contents(si.ea, si.length, si.type)
                    if s is not None:
                        try:
                            sv = s.decode('utf-8', errors='replace')
                        except:
                            sv = s.hex()
                        strs.append((si.ea, sv, si.type))
            result['strings'] = strs

            # Functions
            #
            # Do not use idautils.Functions() here. On large IDA 9.x databases it
            # can enumerate fewer starts than ida_funcs.get_func_qty() reports,
            # which makes paged list_functions exports incomplete. getn_func()
            # walks IDA's function array directly and stays consistent with
            # get_func_qty().
            funcs = []
            for i in range(ida_funcs.get_func_qty()):
                func = ida_funcs.getn_func(i)
                if not func:
                    continue
                ea = func.start_ea
                name = ida_funcs.get_func_name(ea)
                sz = func.size()
                funcs.append((ea, name, sz))
            result['functions'] = funcs

            # Names
            result['names'] = list(idautils.Names())

            # Imports
            imps = []
            nimps = ida_nalt.get_import_module_qty()
            for i in range(nimps):
                mod_name = ida_nalt.get_import_module_name(i)
                def _cb(ea, name, ordinal, mod=mod_name):
                    imps.append((mod, name or '', ea, ordinal))
                    return True
                ida_nalt.enum_import_names(i, _cb)
            result['imports'] = imps

            # Exports
            exps = []
            eqty = ida_entry.get_entry_qty()
            for i in range(eqty):
                ordinal = ida_entry.get_entry_ordinal(i)
                ea = ida_entry.get_entry(ordinal)
                name = ida_entry.get_entry_name(ordinal) or ''
                exps.append((ea, name, ordinal))
            result['exports'] = exps

            # Segments
            segs = []
            for i in range(ida_segment.get_segm_qty()):
                seg = ida_segment.getnseg(i)
                name = ida_segment.get_segm_name(seg)
                cls = ida_segment.get_segm_class(seg)
                segs.append((seg.start_ea, seg.end_ea, name, cls, seg.perm, seg.bitness))
            result['segments'] = segs

            return result

        data = read(_build_all)
        self._strings = data['strings']
        self._functions = data['functions']
        self._names = data['names']
        self._imports = data['imports']
        self._exports = data['exports']
        self._segments = data['segments']
        self._build_time = time.time() - t0

    # --- Query methods (pure in-memory, zero IDA API calls) ---

    def get_strings(self, q='', off=0, n=100):
        data = self._strings or []
        if q:
            ql = q.lower()
            data = [s for s in data if ql in s[1].lower()]
        return data[off:off + n]

    def get_functions(self, q='', off=0, n=100):
        data = self._functions or []
        if q:
            ql = q.lower()
            data = [f for f in data if ql in f[1].lower()]
        return data[off:off + n]

    def get_names(self, q='', n=50):
        data = self._names or []
        if q:
            ql = q.lower()
            results = []
            for ea, name in data:
                if ql in name.lower():
                    results.append((ea, name))
                    if len(results) >= n:
                        break
            return results
        return data[:n]

    def get_imports(self):
        return self._imports or []

    def get_exports(self):
        return self._exports or []

    def get_segments(self):
        return self._segments or []

    def get_build_time(self):
        return self._build_time


# Global cache instance per IDA process
_cache = IdbCache()


def get_cache():
    return _cache
