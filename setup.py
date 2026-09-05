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
from setuptools import setup
import os
doc_files = ['doc/' + afile for afile in os.listdir('doc') if afile != '.svn']
gtk_doc_files = ['gtk/docs/' + afile for afile in os.listdir('gtk/docs') if afile != '.svn']
data_files = ['gtk/images/world.png', 'gtk/images/xsser.jpg',
              'gtk/images/xssericon_16x16.png',
              'gtk/images/xssericon_24x24.png',
              'gtk/map/GeoIP.dat']
gtk_files = ['gtk/xsser.ui']
gtk_app_files = ['gtk/xsser.desktop']
setup(
    data_files = [('/usr/share/doc/xsser/', doc_files),
                  ('/usr/share/xsser/gtk/images/', data_files),
                  ('/usr/share/xsser/gtk/docs/', gtk_doc_files),
                  ('/usr/share/applications/', gtk_app_files),
                  ('/usr/share/xsser/gtk/', gtk_files)],
    scripts = ['xsser'],
)
