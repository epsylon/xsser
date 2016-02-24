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
from random import randrange

class RandomIP(object):
    """
    Class to generate random valid IP's
    """
    def _generateip(self, string):
        notvalid = [10, 127, 169, 172, 192]
        first = randrange(1, 256)

        while first is notvalid:
            first = randrange(1, 256)

        _ip = ".".join([str(first), str(randrange(1, 256)),
        str(randrange(1, 256)), str(randrange(1, 256))])
        return _ip

if __name__ == "__main__":
    randomip = RandomIP()
    print randomip._generateip('')
