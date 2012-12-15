#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
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
-------
Post processing filter to make reservations on shortered links.
"""
import urllib
import pycurl
from cStringIO import StringIO
from BeautifulSoup import BeautifulSoup

class ShortURLReservations(object):
    #options = [['-foo!', 'do stuff']]
    def __init__(self, service='tinyurl'):
        self._service = service
        self._parse_shortener()
        self._extra = {}

    def _parse_shortener(self):
        """
	List of valid links shorterers 
	"""
        if self._service == 'tinyurl' or not self._service:
            self._url = 'http://tinyurl.com/create.php'
            self._par = 'url'
            self._method = 'get'
        elif self._service == 'is.gd':
            self._url = 'http://is.gd/create.php'
            self._par = 'url'
            self._method = 'post'
	
    def process_url(self, url):
        dest = urllib.urlencode({self._par: url})
        out = StringIO()
        c = pycurl.Curl()
        if self._method == 'post':
            c.setopt(c.POST, 1)
            c.setopt(c.POSTFIELDS, dest)
            target = self._url
        else:
            target = self._url + '?' + dest
        c.setopt(c.URL, target)
        c.setopt(c.FOLLOWLOCATION, 1)
        c.setopt(c.WRITEFUNCTION, out.write)
        c.perform()
        c.close()

        soup = BeautifulSoup(out.getvalue())
        if self._service == 'tinyurl':
            return soup.findAll('blockquote')[1].findAll('a')[0]['href']
        elif self._service == 'is.gd':
            return soup.findAll('input', {'id':'short_url'})[0]['value']

if __name__ == "__main__":
    shortener = ShortURLReservations('tinyurl')
    print shortener.process_url('http://slashdot.org?foo')
    shortener = ShortURLReservations('is.gd')
    print shortener.process_url('http://slashdot.org?foo')
