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
data_files = []
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
              'gtk/images/xssericon_24x24.png',
              'gtk/map/GeoIP.dat']
gtk_files = ['gtk/xsser.ui']
gtk_app_files = ['gtk/xsser.desktop']
setup(
    name = "xsser",
    version = "1.9",
    description = "Cross Site Scripter (XSSer): automatic framework to detect, exploit and report XSS vulnerabilities in web-based applications",
    author = "psy",
    author_email = "epsylon@riseup.net",
    url = "https://xsser.03c8.net",
    license = "GPLv3",
    python_requires = ">=3.9",
    install_requires = ['beautifulsoup4>=4.12.3', 'pycurl>=7.45.3'],
    extras_require = {
        'pdf': ['fpdf2>=2.8.1'],
        'dork': ['ddgs>=9.0.0'],
        'dom': ['selenium>=4.20.0'],
        'gtk': ['PyGObject>=3.48.2', 'pycairo>=1.20', 'pygeoip>=0.3.2', 'Pillow>=9.0'],
        'full': ['fpdf2>=2.8.1', 'ddgs>=9.0.0', 'selenium>=4.20.0',
                 'PyGObject>=3.48.2', 'pycairo>=1.20', 'pygeoip>=0.3.2', 'Pillow>=9.0'],
    },
    packages = ['core', 'core.fuzzing', 'core.post', 'core.driver'],
    data_files = [('/usr/share/doc/xsser/', doc_files),
                  ('/usr/share/xsser/gtk/images/', data_files),
                  ('/usr/share/xsser/gtk/docs/', gtk_doc_files),
                  ('/usr/share/applications/', gtk_app_files),
                  ('/usr/share/xsser/gtk/', gtk_files)],
    scripts = ['xsser'],
    test_suite = "tests",
    classifiers = [
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
)
