#!/usr/bin/env python
# -*- coding: utf-8 -*-"
# vim: set expandtab tabstop=4 shiftwidth=4:
"""
This file is part of the xsser project, https://xsser.03c8.net

Copyright (c) 2011/2016/2018 psy <epsylon@riseup.net>

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
import sys
import os, datetime 
import math
import gtk
import socket
import urlparse
import webbrowser
import threading
import gobject
from threading import Thread
from xml.dom import minidom

gtk.gdk.threads_init()

use_twisted = False

if use_twisted:
    from twisted.internet import gtk2reactor
    gtk2reactor.install()
    from twisted.internet import reactor
else:
    reactor = None

from core.main import xsser
from core.globalmap import GlobalMap
from core.reporter import XSSerReporter
from core.mozchecker import MozChecker

class Controller(XSSerReporter):
    def __init__(self, uifile, mothership, window='window1'):
        wTree = gtk.Builder()
        self.xsser = xsser()
        self.mothership = mothership
        self._flying = None
        self._quitting = False
        self.map = None
        self.wTree = wTree
        path = self.mothership.get_gtk_directory()
        wTree.add_from_file(os.path.join(path, uifile))
        self.fill_combos()
        wTree.connect_signals(self)
        window = wTree.get_object(window)
        window.set_size_request(800, 600)
        window.maximize()
        window.show()
        self._window = window
        self.output = wTree.get_object('textview_main')
        self.status = wTree.get_object('status_bar')
        self.output_wizard = wTree.get_object('textview_w_start')
        self._wizard_buffer = self.output_wizard.get_buffer()
        self.counters_label = wTree.get_object('counters_label')

        self._report_vulnerables = wTree.get_object('report_vulnerables').get_buffer()
        self._report_success = wTree.get_object('report_success').get_buffer()
        self._report_failed = wTree.get_object('report_failed').get_buffer()
        self._report_errors = wTree.get_object('report_errors').get_buffer()
        self._report_crawling = wTree.get_object('report_crawling').get_buffer()

        # GUI spinner inits
        threads_spin = self.wTree.get_object('threads')
        threads_spin.set_range(0,100)
        threads_spin.set_value(5)
        threads_spin.set_increments(1, 1)
        timeout_spin = self.wTree.get_object('timeout')
        timeout_spin.set_range(0,100)
        timeout_spin.set_value(30)
        timeout_spin.set_increments(1, 1)
        retries_spin = self.wTree.get_object('retries')
        retries_spin.set_range(0,10)
        retries_spin.set_value(1)
        retries_spin.set_increments(1, 1)
        delay_spin = self.wTree.get_object('delay')
        delay_spin.set_range(0,100)
        delay_spin.set_value(0)
        delay_spin.set_increments(1, 1)
        follow_spin = self.wTree.get_object('follow-limit')
        follow_spin.set_range(0,100)
        follow_spin.set_value(0)
        follow_spin.set_increments(1, 1)
        alive_spin = self.wTree.get_object('alive-limit')
        alive_spin.set_range(0,100)
        alive_spin.set_value(0)
        alive_spin.set_increments(1, 1)
        crawler2_spin = self.wTree.get_object('combobox5')
        crawler2_spin.set_range(1, 99999)
        crawler2_spin.set_value(50)
        crawler2_spin.set_increments(1, 1)
        window.connect("destroy", self.on_quit)
        # geoip + geomap inits
        self.domaintarget = ""        
        # wizard options inits
        self.text_ascii = ""
        # step 1
        self.target_option = ""
        self.dork_option = ""
        self.dorkengine_option = ""
        self.combo_step1_choose = ""
        # step 2
        self.payload_option = ""
        self.combo_step2_choose = ""
        # step 3
        self.combo_step3_choose = ""
        self.proxy_option = ""
        self.useragent_option = ""
        self.referer_option = ""
        # step 4
        self.combo_step4_choose = ""
        self.cem_option = ""
        # step 5
        self.combo_step5_choose = ""
        self.scripts_option = ""

        self.mothership.add_reporter(self)

        # text buffered on wizard startup 
        wizard_output = wTree.get_object('textview_w_start')
        buffer_wizard = wizard_output.get_buffer()
        file = self.open_wizard_file("wizard0")
        self.text_ascii = file.read()
        file.close()
        buffer_wizard.set_text(self.text_ascii)

        # text buffered on wizard1
        wizard1_output = wTree.get_object('textview_w_1')
        buffer = wizard1_output.get_buffer()
        file = self.open_wizard_file("wizard1")
        text_ascii = file.read()
        file.close()
        buffer.set_text(text_ascii)

        # text buffered on wizard2
        wizard2_output = wTree.get_object('textview_w_2')
        buffer = wizard2_output.get_buffer()
        file = self.open_wizard_file("wizard2")
        text_ascii = file.read()
        file.close()
        buffer.set_text(text_ascii)

        # text buffered on wizard3
        wizard3_output = wTree.get_object('textview_w_3')
        buffer = wizard3_output.get_buffer()
        file = self.open_wizard_file("wizard3")
        text_ascii = file.read()
        file.close()
        buffer.set_text(text_ascii)
       
        # text buffered on wizard4
        wizard4_output = wTree.get_object('textview_w_4')
        buffer = wizard4_output.get_buffer()
        file = self.open_wizard_file("wizard4")
        text_ascii = file.read()
        file.close()
        buffer.set_text(text_ascii)

        # text buffered on wizard5
        wizard5_output = wTree.get_object('textview_w_5')
        buffer = wizard5_output.get_buffer()
        file = self.open_wizard_file("wizard5")
        text_ascii = file.read()
        file.close()
        buffer.set_text(text_ascii)

        # text buffered on wizard end
        wizard_end_output = wTree.get_object('textview_w_end')
        buffer = wizard_end_output.get_buffer()
        file = self.open_wizard_file("wizard6")
        text_ascii = file.read()
        file.close()
        buffer.set_text(text_ascii)

        # text buffered on wizard about
        index_output = wTree.get_object('textview_about')
        buffer = index_output.get_buffer()
        file = self.open_wizard_file("about")
        text_ascii = file.read()
        file.close()
        buffer.set_text(text_ascii)
        self.setup_mozembed()

    def open_wizard_file(self, name):
        path = self.mothership.get_gtk_directory()
        file = open(os.path.join(path, 'docs', name+'.txt'), 'r')
        return file

    def fill_with_options(self, combobox, options):
        model = gtk.ListStore(str)
        for option in options:
            model.append([option])
        combobox.set_active(0)
        combobox.set_model(model)
        cell = gtk.CellRendererText()
        combobox.pack_start(cell, True)
        combobox.add_attribute(cell, 'text', 0)  

    def start_crawl(self, dest_url):
        gtk.gdk.threads_enter()
        self.status.set_text("scanning")
        self.status.pulse()
        gtk.gdk.threads_leave()
        self.add_report_text(self._report_crawling, dest_url)

    def add_checked(self, dest_url):
        self.add_report_text(self._report_success, dest_url)

    def add_success(self, dest_url):
        self.add_report_text(self._report_vulnerables, dest_url)
        totalhits = self.wTree.get_object('totalhits')
        totalhits.set_property("label", int(totalhits.get_property("label"))+1)
        successhits = self.wTree.get_object('successhits')
        successhits.set_property("label", int(successhits.get_property("label"))+1)

    def report_error(self, error_msg):
        self.add_report_text(self._report_failed, error_msg)

    def mosquito_crashed(self, dest_url, reason):
        self.add_report_text(self._report_errors, dest_url+" ["+reason+"]")

    def add_failure(self, dest_url):
        self.add_report_text(self._report_failed, dest_url)
        totalhits = self.wTree.get_object('totalhits')
        totalhits.set_property("label", int(totalhits.get_property("label"))+1)
        failedhits = self.wTree.get_object('failedhits')
        failedhits.set_property("label", int(failedhits.get_property("label"))+1)

    def add_report_text(self, gtkbuffer, text):
        gtk.gdk.threads_enter()
        iter = gtkbuffer.get_end_iter()
        gtkbuffer.insert(iter, text+'\n')
        gtk.gdk.threads_leave()

    def setup_mozembed(self):
        self.moz = MozChecker(self)
        self.mothership.set_webbrowser(self.moz)
        #self.moz.hide()

    def fill_combos(self):
        # ui comboboxes
        dorker2_options_w = self.wTree.get_object('combobox4')
        dorker3_options_w = self.wTree.get_object('combobox6')
        crawlerdeep_options_w = self.wTree.get_object('combobox_deep1')
        connect_geomap_w = self.wTree.get_object('combobox7')
        checkmethod_options_w = self.wTree.get_object('combobox1')
        # wizard steps comboboxes
        step1_options_w = self.wTree.get_object('combobox_step1')
        step2_options_w = self.wTree.get_object('combobox_step2')
        step3_options_w = self.wTree.get_object('combobox_step3')
        step4_options_w = self.wTree.get_object('combobox_step4')
        step5_options_w = self.wTree.get_object('combobox_step5')
        # ui comboboxes content
        dorker_options = [ 'yahoo', 'bing']
        crawlerdeep_options = ['1', '2', '3', '4', '5']
        checkmethod_options = ['GET', 'POST']
        connect_geomap = ['OFF', 'ON']
        # wizard comboboxes content
        step1_options = ['0', '1', '2']
        step2_options = ['0', '1', '2', '3', '4']
        step3_options = ['0', '1', '2', '3', '4']
        step4_options = ['0', '1', '2', '3', '4', '5']
        step5_options = ['0', '1', '2', '3']
        # all comboboxes handlered
        self.fill_with_options(dorker2_options_w, dorker_options)
        self.fill_with_options(dorker3_options_w, dorker_options)
        self.fill_with_options(crawlerdeep_options_w, crawlerdeep_options)
        self.fill_with_options(connect_geomap_w, connect_geomap)
        self.fill_with_options(checkmethod_options_w, checkmethod_options)
        self.fill_with_options(step1_options_w, step1_options)
        self.fill_with_options(step2_options_w, step2_options)
        self.fill_with_options(step3_options_w, step3_options)
        self.fill_with_options(step4_options_w, step4_options)
        self.fill_with_options(step5_options_w, step5_options)

    def on_set_clicked(self, widget):
        """
        Set your mosquito(s) options
        """
        # control authmode
        auth_none = self.wTree.get_object('auth_none')
        auth_cred = self.wTree.get_object('auth_cred')
        if auth_cred.get_property('text') == "":
            auth_none.set_property('active', True)
 
        commandsenter = self.wTree.get_object('commandsenter')
        cmd = self.generate_command()
        commandsenter.set_property("text"," ".join(cmd))
    
        app = xsser()
        options = app.create_options(cmd)
        app.set_options(options)
        
        app.set_reporter(self)
        pass

        # set visor counters to zero
        totalhits = self.wTree.get_object('totalhits')
        totalhits.set_property("label", "0")
        failedhits = self.wTree.get_object('failedhits')
        failedhits.set_property("label", "0")
        successhits = self.wTree.get_object('successhits')
        successhits.set_property("label", "0")

    def end_attack(self):
        #self._flying.join()
        gtk.gdk.threads_enter()
        self.status.set_text("idle")
        self.status.set_fraction(0.0)
        fly_button = self.wTree.get_object('fly')
        fly_button.set_label('FLY!!!')
        fly_button.set_sensitive(True)
        if self._quitting:
            pass
            #self.do_quit()
        else:
            gobject.timeout_add(0, self.park_mosquito)
        gtk.gdk.threads_leave()

    def park_mosquito(self):
        self._flying.join()
        self._flying = None

    def on_stop_attack(self):
        if self._flying:
            self._flying.app.land()

    def on_quit(self, widget, data=None):
        """
        Callback called when the window is destroyed (close button clicked)
        """
        if self._flying:
            print("Exiting xsser... please wait until all mosquitoes return to mothership!")
            self._quitting = True
            self.on_stop_attack()
            self.do_quit()
        else:
            print("\nbyezZZZzzzz!\n")
            self.do_quit()

    def do_quit(self):
        self.mothership.land(True)
        #if self.moz:
            #    self.moz.shutdown()
        if reactor:
            threadpool = reactor.getThreadPool()
            threadpool.stop()
            reactor.stop()
        else:
            # doing it here doesnt seem to give time to
            # the mothership to land but should be ok
            gtk.main_quit()

    def start_token_check(self, dest_url):
        self.update_counters_label()

    def update_counters_label(self):
        rem = str(self.moz.remaining())
        th_count = str(threading.activeCount()-1)
        if self._flying:
            work_count = str(len(self._flying.app.pool.workRequests))
            app = self._flying.app
            crawled = str(len(app.crawled_urls))+"/"+str(app.options.crawling)
        else:
            work_count = ""
            crawled = "X"
        pars = [crawled, rem, th_count, work_count]

        gtk.gdk.threads_enter()
        self.counters_label.set_text(" ".join(pars))
        if pars[3]:
            pars[3] = "\nworks in queue: %s"%(pars[3],)
        self.counters_label.set_tooltip_text('crawled during last attack: %s\nremaining checks: %s\nalive threads: %s %s' % tuple(pars))
        gtk.gdk.threads_leave()

    def report_state(self, state, val=-1):
        if not gtk:
            # exiting..
            return
        gtk.gdk.threads_enter()
        self.status.set_text(state)
        if val == -1:
            self.status.pulse()
        else:
            self.status.set_fraction(val)
        gtk.gdk.threads_leave()
        self.update_counters_label()

    def on_fly_clicked(self, widget):
        """
        Fly your mosquito(s)
        """
        fly_button = self.wTree.get_object('fly')
        if self._flying:
            self.on_stop_attack()
            fly_button.set_label('LANDING!!!')
            fly_button.set_sensitive(False)
            return
        self.output.get_buffer().set_property("text", "")
        auth_none = self.wTree.get_object('auth_none')
        auth_cred = self.wTree.get_object('auth_cred')
        if auth_cred.get_property('text') == "":
            auth_none.set_property('active', True)

        commandsenter = self.wTree.get_object('commandsenter')
        cmd = self.generate_command()
        commandsenter.set_property("text"," ".join(cmd))

        t = XSSerThread(cmd, self.mothership)
        t.daemon = True
        t.add_reporter(self)
        t.set_webbrowser(self.moz)
        if self.map:
            t.add_reporter(self.map)
            self.mothership.add_reporter(self.map)

        targetenter = self.wTree.get_object('targetenter')
        explorer_enter = self.wTree.get_object('explorer_enter')

        if t.app.options == None:
            pass
        elif targetenter.get_text() == None and explorer_enter.get_text() == None:
            pass
        else:
            t.start()
            self._flying = t
            fly_button.set_label('LAND!!!')

        # set visor counters to zero
        totalhits = self.wTree.get_object('totalhits')
        totalhits.set_property("label", "0")
        failedhits = self.wTree.get_object('failedhits')
        failedhits.set_property("label", "0")
        successhits = self.wTree.get_object('successhits')
        successhits.set_property("label", "0")

    # control on/off 'sensitive' switches
    def on_intruder_toggled(self, widget):
        """
        Active intruder mode
        """
        intruder = self.wTree.get_object('intruder')
        targetenter = self.wTree.get_object('targetenter')
        targetall = self.wTree.get_object('targetall')
        explorer_enter = self.wTree.get_object('explorer_enter')
        combobox4 = self.wTree.get_object('combobox4')
        if intruder.get_property('active') == True:
            targetenter.set_property('visible', True)
            targetall.set_property('visible', True)
            explorer_enter.set_property('visible', False)
            combobox4.set_property('visible', False)
        else:
            targetenter.set_property("text", "")
            targetenter.set_property('visible', False)
            targetall.set_property('visible', False)
            explorer_enter.set_property('visible', True)
            combobox4.set_property('visible', True)

    def on_explorer_toggled(self, widget):
        """
        Toggle ON/OFF explorer entry
        """
        explorer = self.wTree.get_object('explorer')
        targetenter = self.wTree.get_object('targetenter')
        targetall = self.wTree.get_object('targetall')
        explorer_enter = self.wTree.get_object('explorer_enter')
        combobox4 = self.wTree.get_object('combobox4')
        if explorer.get_property('active') == True: 
            explorer_enter.set_property('visible', True)
            targetenter.set_property('visible', False)
            targetall.set_property('visible', False)
            combobox4.set_property('visible', True)
        else:
            explorer_enter.set_property("text", "")
            explorer_enter.set_property("visible", False)
            targetenter.set_property('visible', True)
            targetall.set_property('visible', True)
            combobox4.set_property('visible', False)

    def on_targetall_toggled(self, widget):
        """
        Autoconfigure XSSer options to perform an automatic XSS pentesting
        """
        targetall = self.wTree.get_object('targetall')
        crawler = self.wTree.get_object('crawler')
        crawler2_spin = self.wTree.get_object('combobox5')
        localonly1 = self.wTree.get_object('localonly1')
        statistics = self.wTree.get_object('statistics')
        threads_spin = self.wTree.get_object('threads')
        timeout_spin = self.wTree.get_object('timeout')
        retries_spin = self.wTree.get_object('retries')
        delay_spin = self.wTree.get_object('delay')
        followredirects = self.wTree.get_object('followredirects')
        no_head = self.wTree.get_object('no-head')
        reverse_check = self.wTree.get_object('reverse-check')
        automatic_payload = self.wTree.get_object('automatic_payload')
        cookie_injection = self.wTree.get_object('cookie_injection')
        xas = self.wTree.get_object('xas')
        xsr = self.wTree.get_object('xsr')
        dom = self.wTree.get_object('dom')
        dcp = self.wTree.get_object('dcp')
        induced = self.wTree.get_object('induced')
        save = self.wTree.get_object('save')
        exportxml = self.wTree.get_object('exportxml')
        if targetall.get_property('active') == True:
            crawler.set_property("active", True)
            localonly1.set_property("active", True)
            crawler2_spin.set_value(99999)
            statistics.set_property("active", True)
            threads_spin.set_value(10)
            timeout_spin.set_value(60)
            retries_spin.set_value(2)
            delay_spin.set_value(5)
            followredirects.set_property("active", True)
            no_head.set_property("active", True)
            reverse_check.set_property("active", True)
            automatic_payload.set_property("active", True)
            cookie_injection.set_property("active", True)
            xas.set_property("active", True)
            xsr.set_property("active", True)
            dom.set_property("active", True)
            dcp.set_property("active", True)
            induced.set_property("active", True)
            save.set_property("active", True)
            exportxml.set_property("active", True)
        else:
            crawler.set_property("active", False)
            localonly1.set_property("active", True)
            crawler2_spin.set_value(50)
            statistics.set_property("active", True)
            threads_spin.set_value(5)
            timeout_spin.set_value(30)
            retries_spin.set_value(1)
            delay_spin.set_value(0)
            followredirects.set_property("active", False)
            no_head.set_property("active", False)
            reverse_check.set_property("active", False)
            automatic_payload.set_property("active", False)
            cookie_injection.set_property("active", False)
            xas.set_property("active", False)
            xsr.set_property("active", False)
            dom.set_property("active", False)
            dcp.set_property("active", False)
            induced.set_property("active", False)
            save.set_property("active", False)
            exportxml.set_property("active", False)

    def on_torproxy_toggled(self, widget):
        """
        Sync tor mode with expert visor
        """
        torproxy = self.wTree.get_object('torproxy')
        proxy = self.wTree.get_object('proxy')
        if torproxy.get_property('active') == True:
            proxy.set_property('text', 'http://127.0.0.1:8118')
        else:
            proxy.set_property('text', "")

    def on_automatic_toggled(self, widget):
        """
        Sync automatic mode with expert visor
        """
        automatic = self.wTree.get_object('automatic')
        automatic_payload = self.wTree.get_object('automatic_payload')
        if automatic.get_property('active') == True:
            automatic_payload.set_property('active', True)
        else:
            automatic_payload.set_property('active', False)

    def on_automatic_payload_toggled(self, widget):
        """
        Syn. automatic_payload mode with other automatic switches
        """
        automatic = self.wTree.get_object('automatic')
        automatic_payload = self.wTree.get_object('automatic_payload')
        if automatic_payload.get_property('active') == True:
            automatic.set_property('active', True)
        else:
            automatic.set_property('active', False)

    def on_crawler_toggled(self, widget):
        """
        Toggle ON/OFF crawling on main visor
        """
        crawler = self.wTree.get_object('crawler')
        combobox5 = self.wTree.get_object('combobox5')
        combobox_deep1 = self.wTree.get_object('combobox_deep1')
        localonly1 = self.wTree.get_object('localonly1')
        if crawler.get_property('active') == True:
            combobox5.set_property('visible', True)
            combobox_deep1.set_property('visible', True)
            localonly1.set_property('visible', True)
        else:
            connection_none = self.wTree.get_object('connection_none')
            connection_none.set_property('active', True)
            combobox5.set_property("visible", False)
            combobox_deep1.set_property('visible', False)
            localonly1.set_property('visible', False)

    def on_get_toggled(self, widget):
        """
        Toggle ON/OFF payloading entry for GET
        """
        get = self.wTree.get_object('get')
        hbox41 = self.wTree.get_object('hbox41')
        if get.get_property('active') == True:
            hbox41.set_property('visible', True)
        else:
            hbox41.set_property("visible", False)

    def on_post_toggled(self, widget):
        """
        Toggle ON/OFF payloading entry for POST
        """
        post = self.wTree.get_object('post')
        hbox41 = self.wTree.get_object('hbox41')
        if post.get_property('active') == True:
            hbox41.set_property('visible', True)
        else:
            hbox41.set_property('visible', False)

    def on_followredirects_toggled(self, widget):
        """
        Toggle ON/OFF follow redirects entry
        """
        followredirects = self.wTree.get_object('followredirects')
        follow_limit = self.wTree.get_object('follow-limit')
        hbox8 = self.wTree.get_object('hbox8')
        if followredirects.get_property('active') == True:
            hbox8.set_property('visible', True)
            follow_limit.set_value(50)
        else:
            hbox8.set_property('visible', False)
            follow_limit.set_value(0)

    def on_alive_toggled(self, widget):
        """
        Toggle ON/OFF alive checker
        """
        alive = self.wTree.get_object('alive')
        alive_limit = self.wTree.get_object('alive-limit')
        hbox58 = self.wTree.get_object('hbox58')
        hbox77 = self.wTree.get_object('hbox77')
        if alive.get_property('active') == True:
            hbox58.set_property('visible', True)
            hbox77.set_property('visible', False)
            alive_limit.set_value(5)
        else:
            hbox58.set_property('visible', False)
            hbox77.set_property('visible', True)
            alive_limit.set_value(0)

    def on_auth_none_toggled(self, widget):
        auth_cred = self.wTree.get_object('auth_cred')
        auth_cred.set_property('text', "")

    def on_auth_basic_toggled(self, widget):
        hbox17 = self.wTree.get_object('hbox17')
        auth_basic = self.wTree.get_object('auth_basic')
        if auth_basic.get_property('active') == True:
            hbox17.set_property('visible', True)
        else:
            hbox17.set_property('visible', False)

    def on_auth_digest_toggled(self, widget):
        hbox17 = self.wTree.get_object('hbox17')
        auth_digest = self.wTree.get_object('auth_digest')
        if auth_digest.get_property('active') == True:
            hbox17.set_property('visible', True)
        else:
            hbox17.set_property('visible', False)

    def on_auth_gss_toggled(self, widget):
        hbox17 = self.wTree.get_object('hbox17')
        auth_digest = self.wTree.get_object('auth_gss')
        if auth_digest.get_property('active') == True:
            hbox17.set_property('visible', True)
        else:
            hbox17.set_property('visible', False)

    def on_auth_ntlm_toggled(self, widget):
        hbox17 = self.wTree.get_object('hbox17')
        auth_digest = self.wTree.get_object('auth_ntlm')
        if auth_digest.get_property('active') == True:
            hbox17.set_property('visible', True)
        else:
            hbox17.set_property('visible', False)

    def on_finalnone_toggled(self, widget):
        payload_entry = self.wTree.get_object('payload_entry')
        payload_entry.set_property('text', "")

    def on_normalfinal_toggled(self, widget):
        hbox25 = self.wTree.get_object('hbox25')
        normalfinal = self.wTree.get_object('normalfinal')
        if normalfinal.get_property('active') == True:
            hbox25.set_property('visible', True)
        else:
            hbox25.set_property('visible', False)

    def on_remotefinal_toggled(self, widget):
        hbox25 = self.wTree.get_object('hbox25')
        remotefinal = self.wTree.get_object('remotefinal')
        if remotefinal.get_property('active') == True:
            hbox25.set_property('visible', True)
        else:
            hbox25.set_property('visible', False)

    # wizard helper buttons
    def on_startwizard_clicked(self, widget):
        self.output_wizard.set_buffer(self._wizard_buffer)
        step_view_start = self.wTree.get_object('vbox_start')
        step_view_start.set_property("visible", False)
        step_view1 = self.wTree.get_object('vbox_step1')
        step_view1.set_property("visible", True)
        commandsenter = self.wTree.get_object('commandsenter')
        commandsenter.set_property("text", "xsser")
        target_enter = self.wTree.get_object('targetenter')
        target_enter.set_property("text", "")
        explorer_enter = self.wTree.get_object('explorer_enter')
        explorer_enter.set_property("text", "")
        combo_choose1 = self.wTree.get_object('combobox_step1')
        combo_choose2 = self.wTree.get_object('combobox_step2')
        combo_choose3 = self.wTree.get_object('combobox_step3')
        combo_choose4 = self.wTree.get_object('combobox_step4')
        combo_choose5 = self.wTree.get_object('combobox_step5')
        #wizard auto-way options
        combo_choose1.set_active(2)
        combo_choose2.set_active(4)
        combo_choose3.set_active(3)
        combo_choose4.set_active(5)
        combo_choose5.set_active(3)
        combobox6 = self.wTree.get_object('combobox6')
        combobox6.set_active(0)
        combobox_deep1 = self.wTree.get_object('combobox_deep1')
        combobox_deep1.set_active(0)
        verbose = self.wTree.get_object('verbose')
        automatic = self.wTree.get_object('automatic')
        explorer = self.wTree.get_object('explorer')
        crawler = self.wTree.get_object('crawler')
        torproxy = self.wTree.get_object('torproxy')
        verbose.set_property("active", False)
        automatic.set_property("active", False)
        explorer.set_property("active", False)
        crawler.set_property("active", False)
        torproxy.set_property("active", False)    

        self.target_option = ""
        self.file_option = None
        self.dork_option = ""
        self.dorkengine_option = ""

    def on_combobox_step1_changed(self, widget):
        combo_choose = self.wTree.get_object('combobox_step1')
        vbox_step = self.wTree.get_object('vbox_step')
        hboxurl = self.wTree.get_object('hboxurl')
        vboxdork = self.wTree.get_object('vboxdork')
        next1 = self.wTree.get_object('next1')
        if combo_choose.get_active_text() == '0':
            vbox_step.set_property("visible", False)
            next1.set_property("visible", False)
        if combo_choose.get_active_text() == '1':
            vbox_step.set_property("visible", True)
            hboxurl.set_property("visible", True)
            vboxdork.set_property("visible", False)
            next1.set_property("visible", True)
        elif combo_choose.get_active_text() == '2':
            vbox_step.set_property("visible", True)
            hboxurl.set_property("visible", False)
            vboxdork.set_property("visible", True)
            next1.set_property("visible", True)

    def on_previous1_clicked(self, widget):
        step_view1 = self.wTree.get_object('vbox_step1')
        step_view1.set_property("visible", False)
        step_view_start = self.wTree.get_object('vbox_start')
        step_view_start.set_property("visible", True)
        alert_step1_url = self.wTree.get_object('alert_step1_url')
        alert_step1_url.set_property("visible", False)
        alert_step1_dork = self.wTree.get_object('alert_step1_dork')
        alert_step1_dork.set_property("visible", False)
        combo_choose = self.wTree.get_object('combobox_step1')
        step1_entry_url = self.wTree.get_object('step1_entry_url')
        step1_entry_dork = self.wTree.get_object('step1_entry_dork')
        step1_entry_url.set_property("text", "")
        step1_entry_dork.set_property("text", "")
        self.combo_step1_choose = ""
        self.target_option = ""
        self.dork_option = ""

    def on_next1_clicked(self, widget):
        step_view1 = self.wTree.get_object('vbox_step1')
        step_view2 = self.wTree.get_object('vbox_step2')
        combo_choose = self.wTree.get_object('combobox_step1')
        step1_entry_url = self.wTree.get_object('step1_entry_url')
        step1_entry_dork = self.wTree.get_object('step1_entry_dork')
        step1_entry_dorkengine = self.wTree.get_object('combobox6')
        alert_step1_url = self.wTree.get_object('alert_step1_url')
        alert_step1_dork = self.wTree.get_object('alert_step1_dork')

        if step1_entry_url.get_text() == '' and (combo_choose.get_active_text() == '1'):
            alert_step1_url.set_property("visible", True)
            step_view1.set_property("visible", True)
            step_view2.set_property("visible", False)

        elif step1_entry_dork.get_text() == '' and (combo_choose.get_active_text() == '2'):
            alert_step1_dork.set_property("visible", True)
            step_view1.set_property("visible", True)
            step_view2.set_property("visible", False)
        else:
            alert_step1_url.set_property("visible", False)
            alert_step1_dork.set_property("visible", False)
            step_view1.set_property("visible", False)
            step_view2.set_property("visible", True)

        self.combo_step1_choose = combo_choose.get_active_text()
        self.target_option = step1_entry_url.get_text()
        self.dork_option = step1_entry_dork.get_text()
        self.dorkengine_option = step1_entry_dorkengine.get_active_text()

    def on_combobox_step2_changed(self, widget):
        combo_choose = self.wTree.get_object('combobox_step2')
        vbox_step2 = self.wTree.get_object('vbox_step2_payload')
        step2_entry_payload = self.wTree.get_object('step2_entry_payload')
        alert_step2 = self.wTree.get_object('alert_step2')
        next2 = self.wTree.get_object('next2')
        if combo_choose.get_active_text() == '0':
            vbox_step2.set_property("visible", False)
            alert_step2.set_property("visible", False)
            next2.set_property("visible", False)
            step2_entry_payload.set_property("text", "")
        if combo_choose.get_active_text() == '1':
            vbox_step2.set_property("visible", True)
            alert_step2.set_property("visible", False)
            next2.set_property("visible", True)
            step2_entry_payload.set_property("text", "")
        elif combo_choose.get_active_text() == '2':
            vbox_step2.set_property("visible", True)
            next2.set_property("visible", True)
            alert_step2.set_property("visible", False)
            step2_entry_payload.set_property("text", "")
        elif combo_choose.get_active_text() == '3':
            vbox_step2.set_property("visible", False)
            next2.set_property("visible", True)
            alert_step2.set_property("visible", False)
        elif combo_choose.get_active_text() == '4':
            vbox_step2.set_property("visible", False)
            next2.set_property("visible", True)
            alert_step2.set_property("visible", False)

    def on_previous2_clicked(self, widget):
        step_view2 = self.wTree.get_object('vbox_step2')
        step_view2.set_property("visible", False)
        step_view1 = self.wTree.get_object('vbox_step1')
        step_view1.set_property("visible", True)
        alert_step2 = self.wTree.get_object('alert_step2')
        alert_step2.set_property("visible", False)
        step1_entry_url = self.wTree.get_object('step1_entry_url')
        step1_entry_url.set_property("text", "")
        step1_entry_dork = self.wTree.get_object('step1_entry_dork')
        step1_entry_dork.set_property("text", "")

        self.combo_step2_choose = ""
        self.target_option = ""
        self.dork_option = ""

        combo_choose = self.wTree.get_object('combobox_step2')
        step2_entry_payload = self.wTree.get_object('step2_entry_payload')
        step2_entry_payload.set_property("text", "")
        self.combo_step2_choose = ""
        self.payload_option = ""

    def on_next2_clicked(self, widget):
        step_view2 = self.wTree.get_object('vbox_step2')
        step_view3 = self.wTree.get_object('vbox_step3')
        combo_choose = self.wTree.get_object('combobox_step2')
        step2_entry_payload = self.wTree.get_object('step2_entry_payload')
        alert_step2 = self.wTree.get_object('alert_step2')
        if step2_entry_payload.get_text() == '' and (combo_choose.get_active_text() == '1' or combo_choose.get_active_text() == '2') :
            alert_step2.set_property("visible", True)
            step_view2.set_property("visible", True)
            step_view3.set_property("visible", False)
        else:
            alert_step2.set_property("visible", False)
            step_view2.set_property("visible", False) 
            step_view3.set_property("visible", True)

        self.combo_step2_choose = combo_choose.get_active_text()
        self.payload_option = step2_entry_payload.get_text()

    def on_combobox_step3_changed(self, widget):
        combo_choose = self.wTree.get_object('combobox_step3')
        vbox_step3 = self.wTree.get_object('vbox_st')
        step3_entry_proxy = self.wTree.get_object('step3_entry_proxy')
        alert_step3 = self.wTree.get_object('alert_step3')
        next3 = self.wTree.get_object('next3')
        if combo_choose.get_active_text() == '0':
            vbox_step3.set_property("visible", False)
            alert_step3.set_property("visible", False)
            next3.set_property("visible", False)
            step3_entry_proxy.set_property("text", "")
        if combo_choose.get_active_text() == '1':
            vbox_step3.set_property("visible", True)
            alert_step3.set_property("visible", False)
            next3.set_property("visible", True)
            step3_entry_proxy.set_property("text", "")
        elif combo_choose.get_active_text() == '2':
            vbox_step3.set_property("visible", False)
            next3.set_property("visible", True)
            alert_step3.set_property("visible", False)
        elif combo_choose.get_active_text() == '3':
            vbox_step3.set_property("visible", False)
            next3.set_property("visible", True)
            alert_step3.set_property("visible", False)
        elif combo_choose.get_active_text() == '4':
            vbox_step3.set_property("visible", False)
            next3.set_property("visible", True)
            alert_step3.set_property("visible", False)

    def on_previous3_clicked(self, widget):
        step_view3 = self.wTree.get_object('vbox_step3')
        step_view3.set_property("visible", False)
        step_view2 = self.wTree.get_object('vbox_step2')
        step_view2.set_property("visible", True)
        alert_step3 = self.wTree.get_object('alert_step3')
        alert_step3.set_property("visible", False)
        combo_choose = self.wTree.get_object('combobox_step3')
        step3_entry_proxy = self.wTree.get_object('step3_entry_proxy')
        step3_entry_proxy.set_property("text", "")
        self.combo_step3_choose = ""
        self.proxy_option = ""
        self.useragent_option = ""
        self.referer_option = ""

    def on_next3_clicked(self, widget):
        step_view3 = self.wTree.get_object('vbox_step3')
        step_view4 = self.wTree.get_object('vbox_step4')
        combo_choose = self.wTree.get_object('combobox_step3')
        step3_entry_proxy = self.wTree.get_object('step3_entry_proxy')
        alert_step3 = self.wTree.get_object('alert_step3')
        if step3_entry_proxy.get_text() == '' and combo_choose.get_active_text() == '1':
            alert_step3.set_property("visible", True)
            step_view3.set_property("visible", True)
            step_view4.set_property("visible", False)
        else:
            alert_step3.set_property("visible", False)
            step_view3.set_property("visible", False)
            step_view4.set_property("visible", True)

        self.combo_step3_choose = combo_choose.get_active_text()
        self.proxy_option = step3_entry_proxy.get_text()
        if combo_choose.get_active_text() == '2':
            self.proxy_option = "http://127.0.0.1:8118"

    def on_combobox_step4_changed(self, widget):
        combo_choose = self.wTree.get_object('combobox_step4')
        vbox_step4 = self.wTree.get_object('vboxstep4')
        step4_entry_cem = self.wTree.get_object('step4_entry_cem')
        alert_step4 = self.wTree.get_object('alert_step4')
        next4 = self.wTree.get_object('next4')
        if combo_choose.get_active_text() == '0':
            vbox_step4.set_property("visible", False)
            alert_step4.set_property("visible", False)
            next4.set_property("visible", False)
            step4_entry_cem.set_property("text", "")
        elif combo_choose.get_active_text() == '1':
            vbox_step4.set_property("visible", False)
            alert_step4.set_property("visible", False)
            next4.set_property("visible", True)
        elif combo_choose.get_active_text() == '2':
            vbox_step4.set_property("visible", False)
            alert_step4.set_property("visible", False)
            next4.set_property("visible", True)
        elif combo_choose.get_active_text() == '3':
            vbox_step4.set_property("visible", False)
            alert_step4.set_property("visible", False)
            next4.set_property("visible", True)
        elif combo_choose.get_active_text() == '4':
            vbox_step4.set_property("visible", True)
            next4.set_property("visible", True)
        elif combo_choose.get_active_text() == '5':
            vbox_step4.set_property("visible", False)
            next4.set_property("visible", True)
            alert_step4.set_property("visible", False)

    def on_previous4_clicked(self, widget):
        step_view4 = self.wTree.get_object('vbox_step4')
        step_view4.set_property("visible", False)
        step_view3 = self.wTree.get_object('vbox_step3')
        step_view3.set_property("visible", True)
        alert_step4 = self.wTree.get_object('alert_step4')
        alert_step4.set_property("visible", False)
        combo_choose = self.wTree.get_object('combobox_step4')
        step4_entry_cem = self.wTree.get_object('step4_entry_cem')
        step4_entry_cem.set_property("text", "")
        self.combo_step4_choose = ""
        self.cem_option = ""

    def on_next4_clicked(self, widget):
        step_view4 = self.wTree.get_object('vbox_step4')
        step_view5 = self.wTree.get_object('vbox_step5')
        combo_choose = self.wTree.get_object('combobox_step4')
        step4_entry_cem = self.wTree.get_object('step4_entry_cem')
        alert_step4 = self.wTree.get_object('alert_step4')
        if step4_entry_cem.get_text() == '' and combo_choose.get_active_text() == '4':
            alert_step4.set_property("visible", True)
            step_view4.set_property("visible", True)
            step_view5.set_property("visible", False)
        else:
            alert_step4.set_property("visible", False)
            step_view4.set_property("visible", False)
            step_view5.set_property("visible", True)

        self.combo_step4_choose = combo_choose.get_active_text()
        self.cem_option = step4_entry_cem.get_text()

    def on_combobox_step5_changed(self, widget):
        combo_choose = self.wTree.get_object('combobox_step5')
        vbox_step5 = self.wTree.get_object('vboxstep5')
        step5_entry_scripts = self.wTree.get_object('step5_entry_scripts')
        alert_step5 = self.wTree.get_object('alert_step5')
        next5 = self.wTree.get_object('next5')
        if combo_choose.get_active_text() == '0':
            vbox_step5.set_property("visible", False)
            alert_step5.set_property("visible", False)
            next5.set_property("visible", False)
            step5_entry_scripts.set_property("text", "")
        elif combo_choose.get_active_text() == '1':
            vbox_step5.set_property("visible", False)
            alert_step5.set_property("visible", False)
            next5.set_property("visible", True)
        elif combo_choose.get_active_text() == '2':
            vbox_step5.set_property("visible", True)
            alert_step5.set_property("visible", False)
            next5.set_property("visible", True)
        elif combo_choose.get_active_text() == '3':
            vbox_step5.set_property("visible", False)
            alert_step5.set_property("visible", False)
            next5.set_property("visible", True)

    def on_previous5_clicked(self, widget):
        step_view5 = self.wTree.get_object('vbox_step5')
        step_view5.set_property("visible", False)
        step_view4 = self.wTree.get_object('vbox_step4')
        step_view4.set_property("visible", True)
        alert_step5 = self.wTree.get_object('alert_step5')
        alert_step5.set_property("visible", False)
        combo_choose = self.wTree.get_object('combobox_step5')
        step5_entry_scripts = self.wTree.get_object('step5_entry_scripts')
        step5_entry_scripts.set_property("text", "")
        self.combo_step5_choose = ""
        self.scripts_option = ""

    def on_next5_clicked(self, widget):
        step_view5 = self.wTree.get_object('vbox_step5')
        step_view5.set_property("visible", False)
        step_view_end = self.wTree.get_object('vbox_end')
        step_view_end.set_property("visible", True)
        combo_choose = self.wTree.get_object('combobox_step5')
        step5_entry_scripts = self.wTree.get_object('step5_entry_scripts')
        alert_step5 = self.wTree.get_object('alert_step5')
        if step5_entry_scripts.get_text() == '' and combo_choose.get_active_text() == '2':
            alert_step5.set_property("visible", True)
            step_view5.set_property("visible", True)
            step_view_end.set_property("visible", False)
        else:
            alert_step5.set_property("visible", False)
            step_view5.set_property("visible", False)
            step_view_end.set_property("visible", True)

        self.combo_step5_choose = combo_choose.get_active_text()
        self.scripts_option = step5_entry_scripts.get_text()

        # building end form
        end_entry_target = self.wTree.get_object('end_entry_target')
        end_entry_shadow = self.wTree.get_object('end_entry_shadow')
        end_entry_connection = self.wTree.get_object('end_entry_connection')
        end_entry_bypasser = self.wTree.get_object('end_entry_bypasser')
        end_entry_exploit = self.wTree.get_object('end_entry_exploit')
        # step 1
        if self.combo_step1_choose == "1":
            end_entry_target.set_property("text", "URL: " + self.target_option)
        
        if self.combo_step1_choose == "2":
            end_entry_target.set_property("text", ("Dork: " + self.dork_option + "  //  Engine: " + self.dorkengine_option))
        # step 2
        if self.combo_step2_choose == "1":
            end_entry_connection.set_property("text", ("Type: GET " + "  //  Payload: " + self.payload_option))

        if self.combo_step2_choose == "2":
            end_entry_connection.set_property("text", ("Type: POST " + "  //  Payload: " + self.payload_option))

        if self.combo_step2_choose == "3":
            end_entry_connection.set_property("text", "Type: Crawler")

        if self.combo_step2_choose == "4":
            end_entry_connection.set_property("text", "Type: AUTO")

        # step 3
        if self.combo_step3_choose == "1":
            shadow_proxy = end_entry_shadow.set_property("text", self.proxy_option)
            shadow_useragent = end_entry_shadow.set_property("text", self.useragent_option)
            shadow_referer = end_entry_shadow.set_property("text", self.referer_option)
            proxy = "PROXY listening on: " + self.proxy_option
            end_entry_shadow.set_property("text", proxy)
            if self.useragent_option != "":
                end_entry_shadow.set_property("text", proxy + " + UA spoofing")
                if self.referer_option != "":
                    end_entry_shadow.set_property("text", proxy + " + UA spoofing + RF spoofing")
            else:
                end_entry_shadow.set_property("text", proxy + " + UA spoofing(by default)")
                if self.referer_option != "":
                    end_entry_shadow.set_property("text", proxy + " + UA spoofing(by default)+ RF spoofing")

            if self.referer_option != "":
                end_entry_shadow.set_property("text", proxy + " + RF spoofing")

        if self.combo_step3_choose == "2":
            proxy = "PROXY listening on: " + self.proxy_option
            end_entry_shadow.set_property("text", proxy)

        if self.combo_step3_choose == "3":
            end_entry_shadow.set_property("text", "NO PROXY + UA spoofing(by default)")

        if self.combo_step3_choose == "4":
            end_entry_shadow.set_property("text", "DIRECT + UA spoofing(by default)")
    
        # step 4
        if self.combo_step4_choose == "1":
            end_entry_bypasser.set_property("text", "Encode: Nothing")

        if self.combo_step4_choose == "2":
            end_entry_bypasser.set_property("text", "Encode: Hexadecimal")

        if self.combo_step4_choose == "3":
            end_entry_bypasser.set_property("text", "Encode: mix 'String.FromCharCode()' and 'Unescape()'")

        if self.combo_step4_choose == "4":
            end_entry_bypasser.set_property("text", self.cem_option)

        if self.combo_step4_choose == "5":
            end_entry_bypasser.set_property("text", "Encode: Nothing")

        # step 5
        if self.combo_step5_choose == "1":
            end_entry_exploit.set_property("text", "Code: Classic 'XSS' alert box")

        if self.combo_step5_choose == "2":
            end_entry_exploit.set_property("text", self.scripts_option)

        if self.combo_step5_choose == "3":
            end_entry_exploit.set_property("text", "Code: Classic 'XSS' alert box")

    def on_previous6_clicked(self, widget):
        step_view_end = self.wTree.get_object('vbox_end')
        step_view_end.set_property("visible", False)
        step_view5 = self.wTree.get_object('vbox_step5')
        step_view5.set_property("visible", True)
        alert_step5 = self.wTree.get_object('alert_step5')
        alert_step5.set_property("visible", False)
        combo_choose = self.wTree.get_object('combobox_step5')
        step5_entry_scripts = self.wTree.get_object('step5_entry_scripts')
        step5_entry_scripts.set_property("text", "")
        self.combo_step5_choose = ""
        self.scripts_option = ""

    def on_cancel_template_clicked(self, widget):
        step_view_end = self.wTree.get_object('vbox_end')
        step_view_end.set_property("visible", False)
        step_view_start = self.wTree.get_object('vbox_start')
        step1_entry_url = self.wTree.get_object('step1_entry_url')
        step1_entry_dork = self.wTree.get_object('step1_entry_dork')
        step2_entry_payload = self.wTree.get_object('step2_entry_payload')
        step3_entry_proxy = self.wTree.get_object('step3_entry_proxy')
        step4_entry_cem = self.wTree.get_object('step4_entry_cem')
        step5_entry_scripts = self.wTree.get_object('step5_entry_scripts')
        step_view_start.set_property("visible", True)
        # reseting wizard options 
        # step 1
        self.target_option = ""
        self.dork_option = ""
        self.dorkengine_option = ""
        self.combo_step1_choose = ""
        step1_entry_url.set_property("text", "")
        step1_entry_dork.set_property("text", "")
        # step 2
        self.payload_option = ""
        self.combo_step2_choose = ""
        step2_entry_payload.set_property("text", "")
        # step 3
        self.combo_step3_choose = ""
        self.proxy_option = ""
        self.useragent_option = ""
        self.referer_option = ""
        step3_entry_proxy.set_property("text", "")
        # step 4
        self.combo_step4_choose = ""
        self.cem_option = ""
        step4_entry_cem.set_property("text", "")
        # step 5
        self.combo_step5_choose = ""
        self.scripts_option = ""
        step5_entry_scripts.set_property("text", "")

        # remove parameters on autocompleter
        commandsenter = self.wTree.get_object('commandsenter')
        commandsenter.set_property("text", "xsser")

        # clean all buffers
        self.output_wizard.set_buffer(self._wizard_buffer)
     
    def on_accept_template_clicked(self, widget):
        """ 
        Fly your mosquito(s) from wizard
        """
        # clean startup wizard buffer

        step_view_end = self.wTree.get_object('vbox_end')
        step_view_end.set_property("visible", False)
        step_view_start = self.wTree.get_object('vbox_start')
        step_view_start.set_property("visible", True)

        fly_button = self.wTree.get_object('fly')
        if self._flying:
            self.on_stop_attack()
            fly_button.set_label('LANDING!!!')
            fly_button.set_sensitive(False)
            return

        self._report_errors.set_text('')
        self._report_vulnerables.set_text('')
        self._report_success.set_text('')
        self._report_failed.set_text('')
        self._report_crawling.set_text('')
        self.output_wizard.set_buffer(self.output.get_buffer())

        commandsenter = self.wTree.get_object('commandsenter')
        cmd = self.generate_command()
        commandsenter.set_property("text"," ".join(cmd))        

        t = XSSerThread(cmd, self.mothership)
        t.add_reporter(self)
        t.set_webbrowser(self.moz)
        if self.map:
            t.add_reporter(self.map)
            self.mothership.add_reporter(self.map)

        t.start()
        self._flying = t
        fly_button.set_label('LAND!!!')

        step1_entry_url = self.wTree.get_object('step1_entry_url')
        step1_entry_dork = self.wTree.get_object('step1_entry_dork')
        step2_entry_payload = self.wTree.get_object('step2_entry_payload')
        step3_entry_proxy = self.wTree.get_object('step3_entry_proxy')
        step4_entry_cem = self.wTree.get_object('step4_entry_cem')
        step5_entry_scripts = self.wTree.get_object('step5_entry_scripts')
        step_view_start.set_property("visible", True)
        # reseting wizard options 
        # step 1
        self.target_option = ""
        self.dork_option = ""
        self.dorkengine_option = ""
        self.combo_step1_choose = ""
        step1_entry_url.set_property("text", "")
        step1_entry_dork.set_property("text", "")
        # step 2
        self.payload_option = ""
        self.combo_step2_choose = ""
        step2_entry_payload.set_property("text", "")
        # step 3
        self.combo_step3_choose = ""
        self.proxy_option = ""
        self.useragent_option = ""
        self.referer_option = ""
        # step 4
        self.combo_step4_choose = ""
        self.cem_option = ""
        step4_entry_cem.set_property("text", "")
        # step 5
        self.combo_step5_choose = ""
        self.scripts_option = ""
        step5_entry_scripts.set_property("text", "")

        # remove parameters on autocompleter
        commandsenter = self.wTree.get_object('commandsenter')
        commandsenter.set_property("text", "xsser")

    def on_combobox7_changed(self, widget):
        """
        Generate Geoip
        """
        combo_choose = self.wTree.get_object('combobox7')
        image_geomap = self.wTree.get_object('image_geomap')
        vbox9 = self.wTree.get_object('vbox9')

        if combo_choose.get_active_text() == 'OFF':
            self.map.set_property("visible", False)
            vbox9.set_property("visible", False)
            if self._flying:
                self._flying.remove_reporter(self.map)
                self.mothership.remove_reporter(self.map)

        elif combo_choose.get_active_text() == 'ON':
            vbox9.set_property("visible", True)
            if not self.map:
                image_geomap.realize()
                drawarea = GlobalMap(self, image_geomap.get_pixbuf(), self._flying)
                vbox = image_geomap.parent
                vbox.remove(image_geomap)
                eventbox = gtk.EventBox()
                eventbox.add(drawarea)
                vbox.pack_end(eventbox)
                eventbox.show()
                drawarea.show()
                self.map = drawarea
            if self._flying:
                self.mothership.add_reporter(self.map)
                self._flying.add_reporter(self.map)
            self.map.set_property("visible", True)

    def on_update_clicked(self, widget):
        """
        Search for latest XSSer version
        """
        webbrowser.open("https://github.com/epsylon/xsser")

    def on_reportbug_clicked(self, widget):
        """
        Report bugs, ideas...
        """
        webbrowser.open("https://lists.sourceforge.net/lists/listinfo/xsser-users")

    def on_donate_clicked(self, widget):
        """
        Donate something
        """
        webbrowser.open("http://03c8.net")

    def generate_command(self):
        command = ["xsser"]
        # set automatic audit a entire target
        # get target from url
        target_all = self.wTree.get_object('targetall')
        target_entry = self.wTree.get_object('targetenter')
        if target_all.get_active() == False:
            pass
        else:
            if target_entry.get_text() == "":
                pass
            else:
                command.append("--all")
                command.append(target_entry.get_text())

        # get target from url
        target_entry = self.wTree.get_object('targetenter')
        if target_all.get_active() == True:
            pass
        else:
            if target_entry.get_text() == "":
                pass
            else:
                command.append("-u")
                command.append(target_entry.get_text())
        # get explorer test mode
        explorer = self.wTree.get_object('explorer')
        if explorer.get_active() == False:
            pass
        else:
            explorer_enter = self.wTree.get_object('explorer_enter')
            dork_engine = self.wTree.get_object('combobox4')
            if explorer_enter.get_text() == "":
                pass
            else:
                command.append("-d")
                command.append(explorer_enter.get_text())
                command.append("--De")
                command.append(dork_engine.get_active_text())

        # get crawler test mode (common crawling c=50 Cw=3)
        crawler = self.wTree.get_object('crawler')
        combobox5 = self.wTree.get_object('combobox5')
        combobox_deep1 = self.wTree.get_object('combobox_deep1')
        localonly1 = self.wTree.get_object('localonly1')
        if crawler.get_active() == False:
            pass
        else:
            command.append("-c")
            command.append(str(int(combobox5.get_value())))
            command.append("--Cw")
            iter = combobox_deep1.get_active_iter()
            command.append(combobox_deep1.get_model().get_value(iter, 0))
            if localonly1.get_active() == True:
                command.append("--Cl")        

        # get statistics
        target_entry = self.wTree.get_object('statistics')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("-s")
        # get verbose
        target_entry = self.wTree.get_object('verbose')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("-v")
        # use GET connections
        target_entry = self.wTree.get_object('get')
        if target_entry.get_active() == False:
            pass
        else:
            target_entry = self.wTree.get_object('connection_parameters')
            if target_entry.get_text() == "":
                pass
            else:
                command.append("-g")
                command.append(target_entry.get_text())
        # use POST connections
        target_entry = self.wTree.get_object('post')
        if target_entry.get_active() == False:
            pass
        else:
            target_entry = self.wTree.get_object('connection_parameters')
            if target_entry.get_text() == "":
                pass
            else:
                command.append("-p")
                command.append(target_entry.get_text())
        # use checker system No-HEAD
        target_entry = self.wTree.get_object('no-head')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--no-head")
        # use checker system HASH
        target_entry = self.wTree.get_object('hashing')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--hash")
        # use checker system HEURISTIC
        target_entry = self.wTree.get_object('heuristic')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--heuristic")
        # get USER-AGENT
        target_entry = self.wTree.get_object('useragent')
        command.append("--user-agent")
        command.append(target_entry.get_text())
        # get REFERER
        target_entry = self.wTree.get_object('referer')
        if target_entry.get_text() == "":
            pass
        else:
            command.append("--referer")
            command.append(target_entry.get_text())
        # get COOKIE
        target_entry = self.wTree.get_object('cookie')
        if target_entry.get_text() == "":
            pass
        else:
            command.append("--cookie")
            command.append(target_entry.get_text())
        # get Authentication BASIC
        target_entry = self.wTree.get_object('auth_basic')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--auth-type")
            command.append("basic")
        # get Authentication DIGEST
        target_entry = self.wTree.get_object('auth_digest')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--auth-type")
            command.append("digest")
        # get Authentication GSS
        target_entry = self.wTree.get_object('auth_gss')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--auth-type")
            command.append("gss")
        # get Authentication NTLM
        target_entry = self.wTree.get_object('auth_ntlm')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--auth-type")
            command.append("ntlm")
        # get Authentication Credentials
        target_entry = self.wTree.get_object('auth_cred')
        if target_entry.get_text() == "":
            pass
        else:
            command.append("--auth-cred")
            command.append(target_entry.get_text())
        # get PROXY
        proxy = self.wTree.get_object('proxy')
        if proxy.get_text() == "":
            pass
        else:
            command.append("--proxy")
            command.append(proxy.get_text())
            if proxy.get_text() == "http://127.0.0.1:8118":
                torproxy = self.wTree.get_object('torproxy')
                torproxy.set_property('active', True)
            else:
                torproxy.set_property('active', False)
        # get IGNORE-PROXY
        target_entry = self.wTree.get_object('ignore-proxy')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--ignore-proxy")
        # get DROP-COOKIE
        target_entry = self.wTree.get_object('drop-cookie')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--drop-cookie")
        # get XFORW
        target_entry = self.wTree.get_object('xforw')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--xforw")
        # get XCLIENT
        target_entry = self.wTree.get_object('xclient')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--xclient")
        # get TCP-NODELAY
        target_entry = self.wTree.get_object('tcp-nodelay')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--tcp-nodelay")
        # get REVERSE-CHECK
        target_entry = self.wTree.get_object('reverse-check')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--reverse-check")
        # get DISCARD CODE
        target_entry = self.wTree.get_object('discode')
        if target_entry.get_text() == "":
            pass
        else:
            command.append("--discode")
            command.append(target_entry.get_text())
       # get FOLLOWREDIRECTS
        target_entry = self.wTree.get_object('followredirects')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--follow-redirects")
       # get FOLLOW-LIMIT
        target_entry = self.wTree.get_object('follow-limit')
        if target_entry.get_value() == 0:
            pass
        else:
            command.append("--follow-limit")
            command.append(str(int(target_entry.get_value())))
       # get ISALIVE
        target_entry = self.wTree.get_object('alive-limit')
        if target_entry.get_value() == 0:
            pass
        else:
            command.append("--alive")
            command.append(str(int(target_entry.get_value())))
        # get CHECK-AT-URL
        target_entry = self.wTree.get_object('checkaturl')
        check_method = self.wTree.get_object('combobox1')
        check_data = self.wTree.get_object('checkatdata')
        if target_entry.get_text() == "":
            pass
        else:
            command.append("--checkaturl")
            command.append(target_entry.get_text())
            command.append("--checkmethod")
            command.append(check_method.get_active_text())
            if check_data.get_text() == "":
                pass
            else: 
                command.append("--checkatdata")
                command.append(check_data.get_text())        
        # get THREADS
        target_entry = self.wTree.get_object('threads')
        if target_entry.get_value() == 0:
            pass
        else:
            command.append("--threads")
            command.append(str(int(target_entry.get_value())))
        # get TIMEOUT
        target_entry = self.wTree.get_object('timeout')
        command.append("--timeout")
        command.append(str(int(target_entry.get_value())))
        # get RETRIES
        target_entry = self.wTree.get_object('retries')
        command.append("--retries")
        command.append(str(int(target_entry.get_value())))
        # get DELAY
        target_entry = self.wTree.get_object('delay')
        command.append("--delay")
        command.append(str(int(target_entry.get_value()))) 
        # get Extra Headers
        target_entry = self.wTree.get_object('extra_headers')
        if target_entry.get_text() == "":
            pass
        else:
            command.append("--headers")
            command.append(target_entry.get_text())
        # get Payload
        target_entry = self.wTree.get_object('enterpayload')
        if target_entry.get_text() == "":
            pass
        else:
            command.append("--payload")
            command.append(target_entry.get_text())
        # get Automatic Payload test
        target_entry = self.wTree.get_object('automatic_payload')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--auto")
        # get Bypasser: StringFromCharCode()
        target_entry = self.wTree.get_object('by_sfcc')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Str")
        # get Bypasser: Unescape()
        target_entry = self.wTree.get_object('by_unescape')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Une")
        # get Bypasser: Hexadecimal
        target_entry = self.wTree.get_object('by_hex')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Hex")
        # get Bypasser: Hexadecimal with semicolons
        target_entry = self.wTree.get_object('by_hes')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Hes")
        # get Bypasser: Dword
        target_entry = self.wTree.get_object('by_dword')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Dwo")
        # get Bypasser: Octal
        target_entry = self.wTree.get_object('by_octal')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Doo")
        # get Bypasser: Decimal
        target_entry = self.wTree.get_object('by_decimal')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Dec")
        # get Bypasser: CEM
        target_entry = self.wTree.get_object('enter_cem')
        if target_entry.get_text() == "":
            pass
        else:
            command.append("--Cem") 
            command.append(target_entry.get_text())
        # get Technique: Cookie Injection
        target_entry = self.wTree.get_object('cookie_injection')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Coo")
        # get Technique: Cross Site Agent Scripting
        target_entry = self.wTree.get_object('xas')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Xsa")
        # get Technique: Cross Site Referer Scripting
        target_entry = self.wTree.get_object('xsr')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Xsr")
        # get Technique: Document Object Model injections
        target_entry = self.wTree.get_object('dom')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Dom")
        # get Technique: Data Control Protocol injections
        target_entry = self.wTree.get_object('dcp')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Dcp")
        # get Technique: HTTP Response Splitting Induced code
        target_entry = self.wTree.get_object('induced')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Ind")
        # get Technique: Use Anchor Stealth
        target_entry = self.wTree.get_object('anchor')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Anchor")
        # get Technique: PHP IDS bug (0.6.5)
        target_entry = self.wTree.get_object('phpids')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Phpids0.6.5")
        # get Technique: PHP IDS bug (0.7.0)
        target_entry = self.wTree.get_object('phpids070')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Phpids0.7")
        # get Technique: Imperva 
        target_entry = self.wTree.get_object('imperva')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Imperva")
        # get Technique: WebKnight (4.1)
        target_entry = self.wTree.get_object('webknight')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Webknight")
        # get Technique: F5 Big Ip
        target_entry = self.wTree.get_object('f5bigip')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--F5bigip")
        # get Technique: Barracuda
        target_entry = self.wTree.get_object('barracuda')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Barracuda")
        # get Technique: Apache modsec
        target_entry = self.wTree.get_object('modsec')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Modsec")
        # get Technique: QuickDefense
        target_entry = self.wTree.get_object('quickdefense')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Quickdefense")
        # get Final code: Normal Payload
        target_entry = self.wTree.get_object('normalfinal')
        if target_entry.get_active() == False:
            pass
        else:
            target_entry = self.wTree.get_object('payload_entry')
            if target_entry.get_text() == "":
                pass
            else:
                command.append("--Fp")
                command.append(target_entry.get_text())
        # get Final code: Remote Payload
        target_entry = self.wTree.get_object('remotefinal')
        if target_entry.get_active() == False:
            pass
        else:
            target_entry = self.wTree.get_object('payload_entry')
            if target_entry.get_text() == "":
                pass
            else:
                command.append("--Fr")
                command.append(target_entry.get_text())
        # get Final code: DOS client side
        target_entry = self.wTree.get_object('dosclient')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Dos")
        # get Final code: DOS Server side
        target_entry = self.wTree.get_object('dosserver')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Doss")
        # get Final code: Base 64 POC
        target_entry = self.wTree.get_object('b64')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--B64")
        # get Final code: OnMouseMove event ()
        target_entry = self.wTree.get_object('onmouse')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Onm")
        # get Final code: Iframe tag
        target_entry = self.wTree.get_object('iframe')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--Ifr")
        # get SAVE results option
        target_entry = self.wTree.get_object('save')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--save")
        # get Export xml option
        target_entry = self.wTree.get_object('exportxml')
        if target_entry.get_active() == False:
            pass
        else:
            command.append("--xml") 
            command.append("xsser-test:" + str(datetime.datetime.now()) + ".xml")
        # generate wizard commands
        # step 1
        if self.target_option != "":
            command.append("-u")
            command.append(self.target_option)
        elif self.dork_option != "":
            command.append("-d")
            command.append(self.dork_option)
            command.append("--De")
            command.append(self.dorkengine_option)
        # step 2 
        if self.combo_step2_choose == "1":
            if self.payload_option != "":
                command.append("-g")
                command.append(self.payload_option)
        elif self.combo_step2_choose == "2":
            if self.payload_option != "":
                command.append("-p")
                command.append(self.payload_option)
        elif self.combo_step2_choose == "3":
            command.append("-c")
            command.append("50") 
            command.append("--Cw") 
            command.append("3") 
        elif self.combo_step2_choose == "4":
            command.append("-c")
            command.append("20")
            command.append("--Cw")
            command.append("2")
            command.append("--auto")
            command.append("--Cl")
        # step 3
        step3_entry_proxy = self.wTree.get_object('step3_entry_proxy')
        useragent = self.wTree.get_object('useragent')
        if self.combo_step3_choose == "1":
            command.append("--proxy")
            command.append(step3_entry_proxy.get_text())
            if useragent.get_text() == "Googlebot/2.1 (+http://www.google.com/bot.html)":
                pass
            else:
                command.append("--user-agent")
                command.append("Googlebot/2.1 (+http://www.google.com/bot.html)")
            command.append("--referer")
            command.append("http://127.0.0.1")
        if self.combo_step3_choose == "2":
            command.append("--proxy")
            command.append("http://127.0.0.1:8118")
        if self.combo_step3_choose == "3":
            if useragent.get_text() == "Googlebot/2.1 (+http://www.google.com/bot.html)":
                pass
            else:
                command.append("--user-agent")
                command.append("Googlebot/2.1 (+http://www.google.com/bot.html)")
            command.append("--referer")
            command.append("http://127.0.0.1")
        if self.combo_step3_choose == "4":
            pass
        # step 4
        if self.combo_step4_choose == "1":
            pass
        if self.combo_step4_choose == "2":
            command.append("--Hex")
        if self.combo_step4_choose == "3":
            command.append("--Mix")
        if self.combo_step4_choose == "4":
            command.append("--Cem")
            command.append(self.cem_option)
        if self.combo_step4_choose == "5":
            command.append("--Str")
        # step 5
        if self.combo_step5_choose == "1":
            pass	
        if self.combo_step5_choose == "2":
            command.append("--payload")
            command.append(self.scripts_option)
        if self.combo_step5_choose == "3":
            pass
        # propagate the silent flag
        if '--silent' in sys.argv:
            command.append('--silent')

        return command

    def post(self, msg):
        """
        Callback called by xsser when it has output for the user
        """
        gtk.gdk.threads_enter()
        self.post_ui(msg)
        gtk.gdk.threads_leave()

    def post_ui(self, msg):
        """
        Post a message to the interface in the interface thread
        """
        buffer = self.output.get_buffer()
        iter = buffer.get_end_iter()
        buffer.insert(iter, msg+'\n')

class XSSerThread(Thread):
    def __init__ (self, cmd, mothership):
        Thread.__init__(self)
        self.app = xsser(mothership)
        self._cmd = cmd
        options = self.app.create_options(cmd)
        self.app.set_options(options)

    def set_webbrowser(self, browser):
        self.app.set_webbrowser(browser)

    def remove_reporter(self, reporter):
        self.app.remove_reporter(reporter)

    def add_reporter(self, reporter):
        self.app.add_reporter(reporter)

    def run(self):
        self.app.run(self._cmd[1:])

if __name__ == "__main__":
    uifile = "xsser.ui"
    controller = Controller(uifile)
    reactor.run()
