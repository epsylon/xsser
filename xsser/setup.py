#!/usr/bin/env python
# -*- coding: utf-8 -*-"
# vim: set expandtab tabstop=4 shiftwidth=4:
"""
$Id$

This file is part of the xsser project, https://xsser.03c8.net

Copyright (c) 2011/2018 psy <epsylon@riseup.net>

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
from setuptools import setup
import os

data_files = []

image_files = []
doc_files = []
gtk_doc_files = []
for afile in os.listdir('doc'):
    if afile != '.svn':
        doc_files.append('doc/' + afile)
for afile in os.listdir('gtk/docs'):
    if afile != '.svn':
        gtk_doc_files.append('gtk/docs/' + afile)

data_files = ['gtk/images/world.png', 'gtk/images/xsser.jpg',
              'gtk/images/xssericon_16x16.png',
              'gtk/images/xssericon_24x24.png']
gtk_files = ['gtk/xsser.ui']
gtk_app_files = ['gtk/xsser.desktop']

setup(
    name = "xsser",
    version = "1.7",
    packages = ['core', 'core.fuzzing', 'core.post'],
    data_files = [('/usr/share/doc/xsser/', doc_files), 
                  ('/usr/share/xsser/gtk/images/', data_files),
                  ('/usr/share/xsser/gtk/docs/', gtk_doc_files),
                  ('/usr/share/applications/', gtk_app_files),
                  ('/usr/share/xsser/gtk/', gtk_files)],
    scripts = ['xsser'],
    test_suite = "tests"
)

