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

## XXSer.py @@ DOM vectors @@ psy
#
## This file contains different XSS vectors to inject in the Document Object Model (DOM).
## If you have some new vectors, please email me to [root@lordepsylon.net - epsylon@riseup.net] and will be added to XSSer framework.
## Thats all.
###
## Happy Cross Hacking! ;)

DOMvectors = [
		{ 'payload' : """?notname=PAYLOAD""",
		  'browser' : """[Document Object Model Injection]"""},
		  
		{ 'payload' : """?notname=PAYLOAD&""",
		  'browser' : """[Document Object Model Injection]"""},
		  
		{ 'payload' : """?foobar=name=PAYLOAD&""",
		  'browser' : """[Document Object Model Injection]"""}
		]

