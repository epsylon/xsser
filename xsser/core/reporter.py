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
class XSSerReporter(object):
    """
    Base class for objects wanting to receive report information from XSSer.
    It implements all callbacks so you will be safe ;)
    """
    def start_attack(self):
        pass
    def end_attack(self):
        pass
    def mosquito_crashed(self, dest_url, reason="unknown"):
        pass
    def report_state(self, state):
        pass
    def add_link(self, orig_url, dest_url):
        pass
    def report_error(self, error_msg):
        pass
    def start_token_check(self, dest_url):
        pass
    def start_crawl(self, dest_url):
        pass
    def post(self, msg):
        pass
    def token_arrived(self, token):
        pass
    def add_checked(self, dest_url):
        pass
    def add_success(self, dest_url):
        pass
    def add_failure(self, dest_url):
        pass
