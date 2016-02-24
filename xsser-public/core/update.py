#!/usr/bin/env python
# -*- coding: utf-8 -*-"
# vim: set expandtab tabstop=4 shiftwidth=4:
"""
$Id$

This file is part of the xsser project, http://xsser.03c8.net

Copyright (c) 2011/2016 psy <epsylon@riseup.net>

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
        GIT_REPOSITORY = "https://github.com/epsylon/xsser-public"
        rootDir = os.path.abspath(os.path.join(os.path.dirname( __file__ ), '..', ''))
        if not os.path.exists(os.path.join(rootDir, ".git")):
            print "Not any .git repository found!\n"
            print "="*30
            print "\nYou should clone XSSer manually with:\n"
            print "$ git clone %s" % GIT_REPOSITORY + "\n"
        else:
            checkout = execute("git checkout .", shell=True, stdout=PIPE, stderr=PIPE).communicate()[0]
            if "fast-forwarded" in checkout:
                pull = execute("git pull %s HEAD" % GIT_REPOSITORY, shell=True, stdout=PIPE, stderr=PIPE).communicate()
                print "Congratulations!! XSSer has been updated to latest version ;-)\n"
            else:
                print "You are updated! ;-)\n"
