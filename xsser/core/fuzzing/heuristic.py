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

heuristic_test = [
		# ascii
		{ 'payload' : """XSS\\XSS""",
                  'browser' : """[Heuristic test]""" },

		{ 'payload' : """XSS/XSS""",
		  'browser' : """[Heuristic test]""" },
				
		{ 'payload' : """XSS>XSS""",
                  'browser' : """[Heuristic test]""" },

		{ 'payload' : """XSS<XSS""",
		  'browser' : """[Heuristic test]""" },

		{ 'payload' : """XSS;XSS""",
                  'browser' : """[Heuristic test]""" },

		{ 'payload' : """XSS'XSS""",
                  'browser' : """[Heuristic test]""" },

		{ 'payload' : '''XSS"XSS''',
                  'browser' : """[Heuristic test]""" },

		{ 'payload' : """XSS=XSS""",
                  'browser' : """[Heuristic test]""" },
                # hex/une
		{ 'payload' : """XSS%5CXSS""",
		  'browser' : """[Heuristic test]""" },
                # / is the same on Unicode than in ASCII
                #{ 'payload' : """XSS/XSS""",
                #  'browser' : """[Heuristic test]""" },

		{ 'payload' : """XSS%3EXSS""",
		  'browser' : """[Heuristic test]""" },

		{ 'payload' : """XSS%3CXSS""",
		  'browser' : """[Heuristic test]""" },
		
		{ 'payload' : """XSS%3BXSS""",
		  'browser' : """[Heuristic test]""" },

		{ 'payload' : """XSS%27XSS""",
		  'browser' : """[Heuristic test]""" },

		{ 'payload' : '''XSS%22XSS''',
		  'browser' : """[Heuristic test]""" },

		{ 'payload' : """XSS%3DXSS""",
		  'browser' : """[Heuristic test]""" },
                # dec
		{ 'payload' : """XSS&#92XSS""",
		  'browser' : """[Heuristic test]""" },
		
		{ 'payload' : """XSS&#47XSS""",
		  'browser' : """[Heuristic test]""" },

		{ 'payload' : """XSS&#62XSS""",
		  'browser' : """[Heuristic test]""" },

		{ 'payload' : """XSS&#60XSS""",
		  'browser' : """[Heuristic test]""" },

		{ 'payload' : """XSS&#59XSS""",
		  'browser' : """[Heuristic test]""" },

		{ 'payload' : """XSS&#39XSS""",
		  'browser' : """[Heuristic test]""" },

		{ 'payload' : '''XSS&#34XSS''',
                  'browser' : """[Heuristic test]""" },

		{ 'payload' : """XSS&#61XSS""",
		  'browser' : """[Heuristic test]""" }

		]


