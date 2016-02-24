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
import gtk
import sys
import gobject
import subprocess
from threading import Thread
try:
    from gtkmozembed import MozEmbed
except:
    MozEmbed = None
    import webbrowser


class CheckerThread(Thread):
    def __init__(self, parent, url):
        Thread.__init__(self)
        self.daemon = True
        self._armed = True
        self._url = url
        self._parent = parent
    def shutdown(self):
        if self.result:
            self._armed = False
            self.result.terminate()
    def run(self):
        self.result = subprocess.Popen([sys.executable, __file__, self._url],
                                 stderr=subprocess.PIPE)
        self.result.wait()
        if self._armed:
            self._parent.on_net_stop()
        self.result = None

class MozChecker(object):
    def __init__(self, parent):
        self._busy = False
        self._urlqueue = []
        self._parent = parent
        self._armed = True
        if MozEmbed:
            pass
        else:
            self.open = self.open_webbrowser

    def remaining(self):
        return len(self._urlqueue)

    def init_mozembed(self):
        self.moz = MozEmbed()
        self.moz.connect('net-stop', self.on_net_stop)
        self.moz.connect('net-state', self.on_net_state)
        self.moz.connect('new-window', self.on_new_window)
        self.add(self.moz)
        self.moz.show()

    def on_new_window(self, widget, retval, chromemask):
        print("new window")
        print(widget, retval, chromemask)
        return False

    def open_webbrowser(self, url):
        webbrowser.open(url, 2, False)

    def open_job(self, url):
        if self._parent:
            self._parent.start_token_check(url)
        self._busy = CheckerThread(self, url)
        self._busy.start()

    def shutdown(self):
        if self._busy:
            self._armed = False
            self._busy.shutdown()
            self._busy.join()

    def open(self, url):
        if not self._busy:
            self.open_job(url)
        else:
            self._urlqueue.append(url)

    def on_js_status(self, widget):
        widget.get_js_status()

    def on_net_state(self, widget, flags, status):
        print("net_state", widget, flags, status)

    def on_net_stop(self, widget=None):
        gtk.gdk.threads_enter()
        gobject.timeout_add(0, self.process_next)
        gtk.gdk.threads_leave()

    def process_next(self):
        if self._urlqueue and self._armed:
            next_url = self._urlqueue.pop(0)
            self.open_job(next_url)
        else:
            self._busy = False

if __name__ == '__main__':
    win = gtk.Window()
    def finished(widget):
        gtk.main_quit()

    def alertkill():
        for a in gtk.window_list_toplevels():
            if a.get_title() and (a.get_title() == 'Alert' or 'says' in a.get_title() or 'Warning' in a.get_title()):
                print(a.get_children())
                a.hide()
                a.destroy()
                gtk.main_quit()
        gobject.timeout_add(100, alertkill)

    def bailout():
        gtk.main_quit()
        sys.exit()

    def unmap(widget):
        widget.hide()

    def new_window(widget, retval, mask):
        print("new window!!")

    gobject.timeout_add(30000, bailout)
    gobject.timeout_add(100, alertkill)

    win = gtk.Window()
    win.set_property('skip-taskbar-hint', True)
    win.set_property('skip-pager-hint', True)
    win.set_keep_below(True)
    win.connect('map', unmap)

    moz = MozEmbed()
    moz.load_url(sys.argv[1])

    moz.connect('net-stop', finished)
    moz.connect('new-window', new_window)

    win.set_title(sys.argv[1])

    win.add(moz)
    win.show_all()
    gtk.main()
