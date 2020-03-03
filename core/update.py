#!/usr/bin/env python
# -*- coding: utf-8 -*-"
# vim: set expandtab tabstop=4 shiftwidth=4:
"""
This file is part of the XSSer project, https://xsser.03c8.net

Copyright (c) 2010/2020 | psy <epsylon@riseup.net>

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
import os
from subprocess import PIPE
from subprocess import Popen as execute
        
class Updater(object):
    """     
    Update XSSer automatically from a .git repository
    """     
    def __init__(self):
        GIT_REPOSITORY = "https://code.03c8.net/epsylon/xsser"
        GIT_REPOSITORY2 = "https://github.com/epsylon/xsser"
        rootDir = os.path.abspath(os.path.join(os.path.dirname( __file__ ), '..', ''))
        if not os.path.exists(".git"):
            print("Not any .git repository found!\n")
            print("="*30)
            print("\nTo have working this feature, you should clone XSSer with:\n")
            print("$ git clone %s" % GIT_REPOSITORY)
            print("\nAlso you can try this other mirror:\n")
            print("$ git clone %s" % GIT_REPOSITORY2 + "\n")
        else:
            checkout = execute("git checkout . && git pull", shell=True, stdout=PIPE, stderr=PIPE).communicate()[0]
            print("[Info] [GitHub] Reply:\n\n"+checkout.decode('utf-8'))
            if not b"Already up-to-date" in checkout:
                print("[Info] [AI] Congratulations!! XSSer has been updated... ;-)\n")
            else:
                print("[Info] [AI] Your XSSer doesn't need to be updated... ;-)\n")
