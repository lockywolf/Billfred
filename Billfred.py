#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
    SleekXMPP: The Sleek XMPP Library
    Copyright (C) 2010  Nathanael C. Fritz
    This file is part of SleekXMPP.
    See the file LICENSE for copying permission.
"""

import sys
import os

import logging
import getpass
from optparse import OptionParser
from sleekxmpp.exceptions import IqError, IqTimeout

import sqlite3
import time
import datetime

#only for encode HTML entities
import HTMLParser

import re
import urllib2
import chardet
import feedparser

import sleekxmpp

#attaching Eliza. Lockywolf 28.02.2017
import eliza as elz

# Forcing UTF8
if sys.version_info < (3, 0):
    from sleekxmpp.util.misc_ops import setdefaultencoding
    setdefaultencoding('utf8')
else:
    raw_input = input

class MUCBot(sleekxmpp.ClientXMPP):

    regex_url = re.compile(r"(https?://\S+)\.(\S+)")
    regex_title = re.compile(r"<title>([^<]+)</title>")

    url_ext_blacklist = [
        'png', 'jpg', 'jpeg', 'gif', 'png', 'pdf', 'doc', 'xls',
        'docx', 'djvu', 'ppt', 'pptx', 'avi', 'mp4', 'mp3', 'flac', 'pps',
        'mp3', 'ogg', 'webm'
    ]

    h_parser = HTMLParser.HTMLParser()

    def __init__(self, jid, password, room, nick):
        sleekxmpp.ClientXMPP.__init__(self, jid, password)

        self.room = room
        self.nick = nick

        self.add_event_handler("session_start",     self.start)
        self.add_event_handler("groupchat_message", self.muc_message)

        self.schedule('RSS update',      # Unique name for the timer
                        600,             # Seconds to delay before firing
                        self.rss_update, # Callback to execute
                        args=(),         # A tuple of positional argument values
                        kwargs={},       # A dictionary of keyword argument values
                        repeat=True)     # Make the event happen every X seconds

    def rss_update(self):
        url_rss = 'http://rulinux.net/rss'
        rss_depth_time = 600
        current_time = datetime.datetime.utcnow()

        try:
            rss = feedparser.parse(url_rss)
            for r in rss.entries:
                time_rss = datetime.datetime.fromtimestamp(time.mktime(r.published_parsed))
                #print current_time
                t = current_time - time_rss
                #TODO: normal time pars not like {-(3600*3)} for remove 3 hour
                time_delta = t.total_seconds()-(3600*3)
                if (0 < time_delta)  and (time_delta < rss_depth_time):
                    news_title = unicode(r.title)
                    news_link  = unicode(r.link)
                    self.send_message(mto="rulinux@conference.jabber.ru",
                            mbody="RULIN: %s %s" % (news_title, news_link),
                            mtype='groupchat')
                else:
                    break
        except:
            logging.info("DEBUG: RSS Feed problem, %s" , sys.exc_info()[0])


    def write_log(self,query):
        '''This function is disabled for Billfred-Liza. Lockywolf'''
        #TODO: Сделать раоту базы в тредах иначе приходится на каждый тред открывать и закрывать
        #SQLite objects created in a thread can only be used in that same thread
        connect_db = sqlite3.connect('./rulinux_xmpp_chat_logs.db')
        connect_db = sqlite3.connect(os.path.join(os.path.dirname(__file__), 'rulinux_xmpp_chat_logs.db'))
        cursor_db = connect_db.cursor()
        cursor_db.execute("""INSERT INTO chat_log (id, time, jit, name, message)
                            VALUES (NULL,?,?,?,?)""", query)
        connect_db.commit()
        connect_db.close()
        pass

    def start(self, event):
        self.get_roster()
        self.send_presence()
        self.plugin['xep_0045'].joinMUC(self.room,
                                        self.nick,
                                        # If a room password is needed, use:
                                        # password=the_room_password,
                                        wait=True)

    def muc_message(self, msg):
        # Cmopose data and write message to  SQLite DB
        nick_name = unicode(msg['mucnick']) # User nick sowed in chat room
        full_jit  = unicode(msg['from'])    # Like user@jabb.en/UserName
        message   = unicode(msg['body'])    # Message body

        query = (time.time(), full_jit, nick_name, message,)
        self.write_log(query)

        # Disable self-interaction
        if msg['mucnick'] == self.nick:
            return

        # Try to run command
        if msg['body'].startswith(self.nick):

            tokens = msg['body'].split()
            if len(tokens) > 1:
                command = tokens[1]

                if command == 'ping':
                    self.try_ping(msg['from'], msg['mucnick'])
                    return
            to_strip = msg['body']
            stripped = to_strip[len(tokens[0]):]
            elz_answer = elz.analyze(to_strip)
            self.send_message(mto="rulinux@conference.jabber.ru",
                          mbody="%s: %s " % (msg['mucnick'], elz_answer),
                          mtype='groupchat')

        elif "http" in msg['body']:
            self.try_say_url_info(msg['body'], msg['from'])

    def try_say_url_info(self, text, mucjid):
        try:
            parse_result = re.search(self.regex_url, text)
            if not parse_result:
                logging.info("DEBUG: cant find  URL")
                raise

            url_ext = parse_result.group(2).lower()
            if  url_ext in self.url_ext_blacklist:
                logging.info("DEBUG: url extension blocked")
                raise

            url = parse_result.group(1) + "." + parse_result.group(2)
            req = urllib2.Request(url)

            #TODO: добавить ограничение на очередь запросов
            response = urllib2.urlopen(req, timeout = 2)

            #6000 MAGIC number  for header in bytes, working on youtube
            data  = response.read(6000)
            enc   = chardet.detect(data)

            data  = data.decode(enc['encoding'], errors='ignore')
            title = re.search(self.regex_title, data).group(1)
            title_clean = self.h_parser.unescape(title)

            self.send_message(mto=mucjid.bare,
                            mbody="TITLE: %s" % (title_clean),
                            mtype='groupchat')

        except:  #IOError:  IndexError, urllib2.URLError
            logging.info("DEBUG URL Rarsing error: %s", sys.exc_info()[0])

    def try_ping(self, pingjid, nick):
        try:
            rtt = self['xep_0199'].ping(pingjid,
                                        timeout=10)
            self.send_message(mto=pingjid.bare,
                            mbody="%s, pong is: %s" % (nick, rtt),
                            mtype='groupchat')
            #logging.info("Success! RTT: %s", rtt)
        except IqError as e:
            logging.info("Error pinging %s: %s",
                    pingjid,
                    e.iq['error']['condition'])
        except IqTimeout:
            logging.info("No response from %s", pingjid)

if __name__ == '__main__':
    optp = OptionParser()

    # Output verbosity options.
    optp.add_option('-q', '--quiet', help='set logging to ERROR',
                    action='store_const', dest='loglevel',
                    const=logging.ERROR, default=logging.INFO)
    optp.add_option('-d', '--debug', help='set logging to DEBUG',
                    action='store_const', dest='loglevel',
                    const=logging.DEBUG, default=logging.INFO)
    optp.add_option('-v', '--verbose', help='set logging to COMM',
                    action='store_const', dest='loglevel',
                    const=5, default=logging.INFO)

    # JID and password options.
    optp.add_option("-c", "--config", dest="config",
                    help="import config with connection params")
    optp.add_option("-j", "--jid", dest="jid",
                    help="JID to use")
    optp.add_option("-p", "--password", dest="password",
                    help="password to use")
    optp.add_option("-r", "--room", dest="room",
                    help="MUC room to join")
    optp.add_option("-n", "--nick", dest="nick",
                    help="MUC nickname")

    opts, args = optp.parse_args()

    # Setup logging.
    logging.basicConfig(level=opts.loglevel,
                        format='%(levelname)-8s %(message)s')
   
    if opts.config is None:    
        if opts.jid is None:
            opts.jid = raw_input("Username: ")
        if opts.password is None:
            opts.password = getpass.getpass("Password: ")
        if opts.room is None:
            opts.room = raw_input("MUC room: ")
        if opts.nick is None:
            opts.nick = raw_input("MUC nickname: ")
    else:
        try:
            import config
            opts.jid = config.jid
            opts.password = config.password
            opts.room = config.room
            opts.nick = config.nick
        except ImportError:
            print "error to import config file"
    #opts.password = getpass.getpass("Password: ")

    # Setup the MUCBot and register plugins.
    xmpp = MUCBot(opts.jid, opts.password, opts.room, opts.nick)

    xmpp.register_plugin('xep_0030') # Service Discovery
    xmpp.register_plugin('xep_0045') # Multi-User Chat
    xmpp.register_plugin('xep_0199') # XMPP Ping
    xmpp.register_plugin('xep_0004') # Data Forms
    xmpp.register_plugin('xep_0060') # PubSub

    # Connect to the XMPP server and start processing XMPP stanzas.
    if xmpp.connect():
        xmpp.process(block=True)
        print("Done")
    else:
        print("Unable to connect.")
