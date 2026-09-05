#!/usr/bin/env python
# -*- coding: utf-8 -*-"
# vim: set expandtab tabstop=4 shiftwidth=4:
"""
This file is part of the XSSer project, https://xsser.03c8.net

Copyright (c) 2010/2026 | psy <epsylon@riseup.net>

xsser is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free
Software Foundation version 3 of the License.

xsser is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
details.

You should have received a copy of the GNU General Public License along
with xsser; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
import sys, os, subprocess, importlib, sysconfig

PIP_FLAGS = ["--no-warn-script-location", "--root-user-action=ignore", "--break-system-packages"]

def externally_managed():
    marker = os.path.join(sysconfig.get_path("stdlib"), "EXTERNALLY-MANAGED")
    return os.path.exists(marker)

def autoinstall_allowed():
    if os.environ.get("XSSER_AUTOINSTALL") == "1":
        return True
    return not externally_managed()

def pip_install(pip_name):
    print("[Info] [AUTO-INSTALL] Trying to install missing lib: '" + pip_name + "' ... -> [WAIT!]")
    cmd = [sys.executable, "-m", "pip", "install", pip_name] + PIP_FLAGS
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except Exception as e:
        print("[Error] [AUTO-INSTALL] Could not run pip: " + str(e))
        return False
    if r.returncode != 0:
        err = (r.stderr or r.stdout or "").strip().splitlines()
        tail = "\n  ".join(err[-6:]) if err else "(no output)"
        print("[Error] [AUTO-INSTALL] pip install '" + pip_name + "' failed:")
        print("  " + tail)
        return False
    print("[Info] [AUTO-INSTALL] '" + pip_name + "' installed -> [OK!]")
    return True

def ensure(module_name, pip_name=None):
    pkg = pip_name or module_name
    try:
        return importlib.import_module(module_name)
    except ImportError:
        if not autoinstall_allowed():
            print("[Error] Missing lib: '" + pkg + "'. This looks like a system-managed Python (PEP 668).")
            print("        Install it with your package manager, or inside a venv, e.g.: python3 -m pip install " + pkg)
            print("        (or set XSSER_AUTOINSTALL=1 to let xsser install it automatically)")
            return None
        if not pip_install(pkg):
            print("[Error] You can install it manually with: python3 -m pip install " + pkg + " --break-system-packages")
            return None
        for cached in list(sys.modules):
            if cached == module_name or cached.startswith(module_name + "."):
                del sys.modules[cached]
        try:
            return importlib.import_module(module_name)
        except ImportError as e:
            print("[Error] Library still missing after install attempt: '" + module_name + "': " + str(e))
            return None
