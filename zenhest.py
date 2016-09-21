#!/usr/bin/env python
# -*- coding: utf-8 -*-

import urwid
import urllib2
import json
import base64
import keyring
import os
import sys
import re
import clipboard

# FIXME: log file should be done right
import logging
logger = logging.getLogger('myapp')
hdlr = logging.FileHandler('/tmp/myapp.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.WARNING)


# ---- ZENOSS CLASSES ----


class ZenEvents:

    """
    Interface with the Zenoss API
    """

    severities = {
        5: 'crit',
        4: 'error',
        3: 'warn',
        2: 'info',
        1: 'debug',
        0: 'clear',
        }

    event_states = {
        'new': 0,
        'acknowledged': 1,
        'suppressed': 2,
        'closed': 3,
        'cleared': 4,
        'aged': 5,
        }

    class Unauthorized(Exception):
        pass

    def __init__(self, url, username, password):
        self.url = '{}/zport/dmd/evconsole_router'.format(url)
        self.username = username
        self.password = password

        # Holds the JSON result from Zenoss
        self.raw_events = {}

        # Our own representation of the events part of the JSON result
        self.events = []

        # Filter passed to API event query
        self.params = {
            'severity': [3, 4, 5],
            'eventState': [0],
            'prodState': [1000],
        }

    def update(self):
        """ Updates and sorts self.events """
        self.fetch_events()
        self.events = sorted(self.raw_events['result']['events'],
                             key=lambda k: (k['eventState'],
                                            k['severity'], k['count'],
                                            k['details']['device_title'][0]),
                             reverse=True)
        return self.events

    def _req(self, method='query', evids=None, params=None,
             limit=None):
        """ Perform API request to Zenoss """
        headers = {'Content-Type': 'application/json'}

        data = {
            'action': 'EventsRouter',
            'method': method,
            'data': [{
            }],
            'type': 'rpc',
            'tid': 1
        }

        if params:
            data['data'][0]['params'] = params

        if evids:
            data['data'][0]['evids'] = evids

        if limit:
            data['data'][0]['limit'] = limit

        req = urllib2.Request(self.url, json.dumps(data), headers)

        authstr = base64.b64encode('{}:{}'.format(self.username, self.password))
        req.add_header('Authorization', 'Basic {}'.format(authstr))

        res = urllib2.urlopen(req)
        return res

    def get_event(self, evid):
        params = {'evid': evid}
        res = self._req(method='query', params=params, limit=1)
        data = json.loads(res.read())
        res.close()
        try:
            return data['result']['events'][0]
        except IndexError:
            return {}

    def ack_events(self, evids):
        res = self._req(method='acknowledge', evids=evids, limit=1)
        data = json.loads(res.read())
        res.close()
        return data['result']['data']

    def close_events(self, evids):
        res = self._req(method='close', evids=evids, limit=1)
        data = json.loads(res.read())
        res.close()
        return data['result']['data']

    def reopen_events(self, evids):
        res = self._req(method='reopen', evids=evids, limit=1)
        data = json.loads(res.read())
        res.close()
        return data['result']['data']

    def login(self):
        """
        Performs an API request and tries to catch authentication failure
        """
        params = {'severity': [1], 'eventState': [0], 'prodState': [1000]}
        res = self._req(params=params, limit=1)
        content = res.read()
        if re.search('__ac_name', content.decode('utf-8')):
            raise self.Unauthorized
        res.close()

    def fetch_events(self, limit=1000):
        """ Fetches the raw events from Zenoss """
        res = self._req(params=self.params, limit=limit)
        content = res.read()
        self.raw_events = json.loads(content)
        res.close()


# ---- WIDGET CLASSES ----

class EventInfoBox(urwid.ListBox):

    """
    A urwid.ListBox holding information about a selected event.
    """

    def __init__(self, body):
        super(EventInfoBox, self).__init__(body)

        self._command_map['j'] = 'cursor down'
        self._command_map['k'] = 'cursor up'

    def keypress(self, size, key):
        if key == 'home':
            self.set_focus(0)
            self._invalidate()
        elif key == 'end':
            self.set_focus(len(self.body)-1)
            self._invalidate()
        elif key == 'y':
            clipboard.copy(self.get_focus()[0].original_widget.text)
        elif key == 'Y':
            text = ''
            for w in self.body:
                if (isinstance(w, urwid.AttrMap) and
                        hasattr(w.original_widget, 'text')):
                    text += w.original_widget.text
                    text += '\n'
            if text:
                clipboard.copy(text)
        elif key in ('up', 'down', 'right', 'left',
                     'page up', 'page down', 'j', 'k'):
            super(EventInfoBox, self).keypress(size, key)

        return key


class EventListBox(urwid.ListBox):

    """
    A urwid.ListBox holding a list of Zenoss events.
    """

    def __init__(self, body):
        super(EventListBox, self).__init__(body)

        urwid.register_signal(EventListBox, ['update_event_info'])

        self._command_map['j'] = 'cursor down'
        self._command_map['k'] = 'cursor up'

    def render(self, size, focus=False):
        # These values are used to calculate EventText widths
        (self.maxcol, self.maxrow) = size
        return super(EventListBox, self).render(size, focus)

    def keypress(self, size, key):
        if key == 'home':
            self.set_focus(0)
            self._invalidate()
        elif key == 'end':
            self.set_focus(len(self.body)-1)
            self._invalidate()
        elif key in ('up', 'down', 'right', 'left',
                     'page up', 'page down', 'j', 'k'):
            super(EventListBox, self).keypress(size, key)

        # A new event has been selected. Update info about it.
        urwid.emit_signal(self, 'update_event_info')

        return key


class NoKeyNavPile(urwid.Pile):

    """
    A urwid.Pile that disables arrow navigation as this is handled by the
    EventListBox.
    """

    def keypress(self, size, key):
        if key not in ['up', 'down', 'left', 'right', 'j', 'k']:
            return super(NoKeyNavPile, self).keypress(size, key)
        else:
            return self.get_focus().keypress(size, key)


class SelectableText(urwid.Text):

    """
    A urwid.Text that can be selected.
    """

    def keypress(self, size, key):
        return key

    def selectable(self):
        return True


class EventText(SelectableText):

    """
    A Zenoss event represented as a formatted line.
    """

    def __init__(self, event, parent_width):
        """
        event: an event at represented in the ZenEvent.events list
        parent_width: width of the parent widget of the event text
        """
        sep = u' │ '
        severity_len = 5
        event_state_len = 1
        count_len = 4
        title_len = 30
        comp_len = 15
        sep_len = len(sep) * 5  # 5 because there are 5 separators
        fixed_len = (severity_len + event_state_len + count_len + title_len +
                     comp_len + sep_len)
        summary_len = parent_width-fixed_len
        severity = self.short(severity_len,
                              ZenEvents.severities[event['severity']]).upper()
        event_state = self.short(event_state_len, event['eventState']).upper()
        count = self.short(count_len, event['count'])
        title = self.short(title_len, event['details']['device_title'][0], True)
        comp = self.short(comp_len, event['component']['text'] or '', True)
        summary = self.short(summary_len, event['summary'], True)
        msg = (u"{:{severity_len}}{sep}{:{event_state_len}}{sep}{:{count_len}}"
               u"{sep}{:{title_len}}{sep}{:{comp_len}}{sep}{}").format(
            severity, event_state, count, title, comp, summary,
            sep=sep, severity_len=severity_len, event_state_len=event_state_len,
            count_len=count_len, title_len=title_len,
            comp_len=comp_len)
        super(EventText, self).__init__(msg)

    def short(self, length, text, dots=False):
        """
        Shortens a string and optionally replaces the last two characters
        with dots.
        """
        text = str(text).replace('\n', '').replace('\t', '')
        if len(text) > length and dots:
            return text[:length-2] + '..'
        return text[:length]


class EventFilterWindow(urwid.Overlay):

    """
    A widget for setting event filters.
    """

    def __init__(self, top_w):
        urwid.register_signal(EventFilterWindow, ['event_filter_close',
                                                  'change_filter',
                                                  'update_event_list'])

        filters = urwid.SimpleListWalker([])

        sections = [
            {
                'title': 'Event states',
                'field': 'eventState',
                'items': [
                    ['New', True, 0],
                    ['Acknowledged', False, 1],
                    ['Closed', False, 3],
                    ['Cleared', False, 4],
                ]
            },
            {
                'title': 'Production states',
                'field': 'prodState',
                'items': [
                    ['Production', True, 1000],
                    ['Maintenance', False, 300],
                ]
            },
            {
                'title': 'Severities',
                'field': 'severity',
                'items': [
                    ['Critical', True, 5],
                    ['Error', True, 4],
                    ['Warning', True, 3],
                    ['Clear', False, 0],
                ]
            }]

        columns = []

        # Create checkbox piles and put them in columns
        for s in sections:
            items = [urwid.Text(('standout', s['title']))]
            items.extend([
                urwid.CheckBox(i[0], on_state_change=self._state_change,
                               state=i[1], user_data=(s['field'], i[2]))
                for i in s['items']])
            columns.append(urwid.Padding(urwid.Pile(items), left=1, right=1))

        # Construct window content
        filters.append(urwid.Text('EVENT FILTERS', 'center'))
        filters.append(urwid.Divider())
        filters.append(urwid.AttrMap(urwid.Columns(columns), 'panel'))
        filters.append(urwid.Divider())
        filters.append(urwid.Text("Settings are applied on next update.",
                                  'center'))
        filters.append(urwid.Text(
            "Press ESC or 'q' to close window. 'R' to refresh.", 'center'))

        wrap = urwid.LineBox(urwid.ListBox(filters))
        super(EventFilterWindow, self).__init__(wrap, top_w, 'center', 80,
                                                'middle', 24)

    def _state_change(self, checkbox, state, data):
        """ Forwards checkbox changes to the signal handler. """
        urwid.emit_signal(self, 'change_filter', state, data[0], data[1])

    def keypress(self, size, key):
        if key in('q', 'Q', 'esc'):
            urwid.emit_signal(self, 'event_filter_close')
        elif key == 'R':
            urwid.emit_signal(self, 'update_event_list')

        return super(EventFilterWindow, self).keypress(size, key)


class LoginWindow(urwid.Overlay):

    """
    A widget for handling the login window.
    """

    def __init__(self, username='', password=''):
        urwid.register_signal(LoginWindow, ['authenticate', 'quit'])

        self.username_w = urwid.Edit(('body', 'Username : '),
                                     edit_text=username)
        self.password_w = urwid.Edit(('body', 'Password : '), mask='*',
                                     edit_text=password)
        username_wrap = urwid.AttrMap(urwid.Padding(self.username_w), 'input',
                                      'input.focus')
        password_wrap = urwid.AttrMap(urwid.Padding(self.password_w), 'input',
                                      'input.focus')

        login_btn = urwid.Button('Login')
        urwid.connect_signal(login_btn, 'click', self._authenticate)

        quit_btn = urwid.Button('Quit')
        urwid.connect_signal(quit_btn, 'click', self._quit)

        self.buttons = urwid.GridFlow([
            urwid.AttrMap(login_btn, 'btn', 'btn.focus'),
            urwid.AttrMap(quit_btn, 'btn', 'btn.focus')], 12, 2, 0, 'center')

        self.title = ('login.title', 'ZENHEST LOGIN')
        self.title_w = urwid.Text(self.title, 'center')
        self.items = urwid.Pile([self.title_w,
                                 urwid.Divider(),
                                 username_wrap, password_wrap,
                                 urwid.Divider(), self.buttons])
        self.box = urwid.LineBox(urwid.Padding(self.items, left=2, right=2))

        wrap = urwid.Filler(urwid.AttrMap(self.box, 'body'))
        bg = urwid.SolidFill(' ')

        super(LoginWindow, self).__init__(wrap, bg, 'center', 80, 'middle', 24)

    def _authenticate(self, data=None):
        urwid.emit_signal(self, 'authenticate',
                          self.username_w.edit_text,
                          self.password_w.edit_text)

    def _quit(self, data=None):
        urwid.emit_signal(self, 'quit')

    def set_message(self, message):
        self.title_w.set_text([self.title, ('login.message', ' - ' + message)])

    def keypress(self, size, key):
        pos = self.items.focus_position
        if key == 'enter':
            # Pressing 'enter' on the login field focuses the password field
            if pos == 2:
                key = 'down'
            # Presing 'enter' on the password field starts authentication
            elif pos == 3:
                self._authenticate()
                return
        elif key == 'tab':
            # Switch from login field to password field
            if pos == 2:
                key = 'down'
            # Switch from password field to login button
            elif pos == 3:
                self.items.set_focus(5)
                self.buttons.set_focus(0)
            # Switch from login button to quit button
            elif pos == 5 and self.buttons.focus_position == 0:
                self.buttons.set_focus(1)
            # Switch from quit button to login field
            elif pos == 5 and self.buttons.focus_position == 1:
                self.buttons.set_focus(1)
                self.items.set_focus(2)
        elif key == 'esc':
            self._quit()

        return super(LoginWindow, self).keypress(size, key)


class MainFrame(urwid.Frame):

    """
    This is the main window widget.
    """

    def __init__(self, *args, **kwargs):
        urwid.register_signal(MainFrame, ['update_event_list', 'quit',
                                          'ack_event', 'close_event',
                                          'reopen_event', 'create_jira',
                                          'show_event_filter'])

        super(MainFrame, self).__init__(*args, **kwargs)

    def keypress(self, size, key):  # noqa: C901
        if key in ('q', 'Q', 'esc'):
            urwid.emit_signal(self, 'quit')
        elif key == 'R':
            urwid.emit_signal(self, 'update_event_list')
        elif key == 'A':
            urwid.emit_signal(self, 'ack_event')
        elif key == 'C':
            urwid.emit_signal(self, 'close_event')
        elif key == 'O':
            urwid.emit_signal(self, 'reopen_event')
        # TODO: implement it
        elif key == 'J':
            urwid.emit_signal(self, 'create_jira')
        elif key == 'f':
            urwid.emit_signal(self, 'show_event_filter')
        elif key == 'tab':
            columns = self.body.contents[1][0]
            # switch from event list to event info
            if self.body.focus_position == 0:
                columns.set_focus(0)
                self.body.set_focus(1)
            # switch from event info to event filter
            elif (columns.focus_position == 0 and
                  self.focus_position == 'body'):
                columns.set_focus(1)
            # switch from event filter to event list
            elif (columns.focus_position == 1 and
                  self.focus_position == 'body'):
                self.body.set_focus(0)
        return super(MainFrame, self).keypress(size, key)


class UI(object):

    """
    The main UI class for setting up the interface bits.
    """

    def __init__(self):
        self.event_list = urwid.SimpleFocusListWalker([])
        self.list_box = EventListBox(self.event_list)

        self.event_info = urwid.SimpleFocusListWalker([])
        bottom_left_frame = EventInfoBox(self.event_info)

        # TODO: not used yet - graph maybe? or log window?
        bottom_right_frame = urwid.ListBox([urwid.Text('')])

        self.body_columns = urwid.Columns([
            urwid.AttrMap(
                urwid.LineBox(
                    urwid.Padding(bottom_left_frame, left=1, right=1)
                ), 'infobox', 'reversed'),
            urwid.AttrMap(
                urwid.LineBox(bottom_right_frame), 'infobox', 'reversed'),
        ])

        self.body = NoKeyNavPile([
            urwid.AttrMap(
                urwid.LineBox(
                    urwid.Padding(self.list_box, left=1, right=1)
                ), 'eventlist', 'reversed'),
            self.body_columns
        ])

        self.main_frame = MainFrame(self.body, footer=self._get_footer(),
                                    focus_part='body')

        self.event_filter_window = EventFilterWindow(self.main_frame)

    def _get_header(self):
        self.header = urwid.Text('ZenHest')
        return self.header

    def _get_footer(self):
        self.footer = urwid.Text(
            (u"Welcome to ZenHest! "
             u" Refresh(r) Quit(q) Ack(a) Filter(f)"))

        return urwid.AttrMap(
            urwid.Padding(self.footer, left=1, right=1), 'footer')

    def init_login_window(self, username, password):
        self.login_window = LoginWindow(username, password)


# ---- MAIN CLASS ----


class ZenHest(object):

    """
    Main class - instantiates the UI and handles logic.
    """

    smiley = """
                          ooo$$$$$$$$$$$$oooo
                      oo$$$$$$$$$$$$$$$$$$$$$$$$o
                   oo$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$o         o$   $$ o$
   o $ oo        o$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$o       $$ $$ $$o$
oo $ $ \"$      o$$$$$$$$$    $$$$$$$$$$$$$    $$$$$$$$$o       $$$o$$o$
\"$$$$$$o$     o$$$$$$$$$      $$$$$$$$$$$      $$$$$$$$$$o    $$$$$$$$
  $$$$$$$    $$$$$$$$$$$      $$$$$$$$$$$      $$$$$$$$$$$$$$$$$$$$$$$
  $$$$$$$$$$$$$$$$$$$$$$$    $$$$$$$$$$$$$    $$$$$$$$$$$$$$  \"\"\"$$$
   \"$$$\"\"\""$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$     \"$$$
    $$$   o$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$     \"$$$o
   o$$\"   $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$       $$$o
   $$$    $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$\" \"$$$$$$ooooo$$$$o
  o$$$oooo$$$$$  $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$   o$$$$$$$$$$$$$$$$$
  $$$$$$$$"$$$$   $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$     $$$$\"\"\"\"\"\"\"\"
 \"\"\""       $$$$    \"$$$$$$$$$$$$$$$$$$$$$$$$$$$$\"      o$$$
            \"$$$o     \"\"\"$$$$$$$$$$$$$$$$$$\"$$\"         $$$
              $$$o          \"$$\"\"$$$$$$\"\"\"\"           o$$$
               $$$$o                                o$$$\"
                \"$$$$o      o$$$$$$o\"$$$$o        o$$$$
                  \"$$$$$oo     \"\"$$$$o$$$$$o   o$$$$\"\"
                     \"\"$$$$$oooo  \"$$$o$$$$$$$$$\"\"\"
                        \"\"$$$$$$$oo $$$$$$$$$$
                                \"\"\"\"$$$$$$$$$$$
                                    $$$$$$$$$$$$
                                     $$$$$$$$$$"
                                      \"$$$\"\"\"\"
"""

    def __init__(self):
        # Holds currently loaded zenoss events
        self.z_events = []

        self._setup_env()
        self._setup_auth()
        self._setup_ui()
        self._setup_signals()

    def _setup_env(self):
        self.zen_url = os.getenv('ZENHEST_URL', None)
        if self.zen_url is None:
            print("ZENHEST_URL not set. Exiting.")
            sys.exit(1)

        self.keyring_name = os.getenv('ZENHEST_KEYRING', 'zenhest')
        self.update_interval = int(os.getenv('ZENHEST_UPDATE_INTERVAL', 30))

    def _setup_auth(self):
        # True if password was retrieved from keychain
        self.auto_login = False

        self.zen_username = os.getenv('ZENHEST_USER', '')

        # Try getting password from system keyring
        if self.zen_username:
            try:
                self.zen_password = keyring.get_password(self.keyring_name,
                                                         self.zen_username)
                self.auto_login = True
            # Currently if keyring fails we just move on.
            except Exception:
                pass

        if getattr(self, 'zen_password', None) is None:
            self.zen_password = ''

    def _setup_ui(self):
        palette = [
            ('body', 'light gray', 'default'),
            ('eventlist', 'light gray', 'default'),
            ('login.title', 'white', 'default'),
            ('login.message', 'light red', 'default'),
            ('infobox', 'light gray', 'default'),
            ('infobox.focus', 'white', 'dark blue'),
            ('input', 'light gray', 'black'),
            ('input.focus', 'white', 'dark gray'),
            ('panel', 'light gray', 'default'),
            ('btn', 'white', 'dark cyan'),
            ('btn.focus', 'white', 'dark blue'),
            ('footer', 'yellow', 'dark red'),
            ('event.focus', 'white', 'dark blue'),
            # critical
            ('severity_5', 'black', 'dark red'),
            # error
            ('severity_4', 'black', 'brown'),
            # warning
            ('severity_3', 'light gray', 'default'),
            # info
            ('severity_2', 'light gray', 'default'),
            # debug
            ('severity_1', 'light gray', 'default'),
            # clear
            ('severity_0', 'light gray', 'default'),
            ]

        self.ui = UI()

        self.ui.init_login_window(self.zen_username, self.zen_password)

        self.main_loop = urwid.MainLoop(self.ui.main_frame, palette,
                                        handle_mouse=False)
        self.main_loop.screen.set_terminal_properties(256)

    def _setup_signals(self):
        # Event list
        urwid.connect_signal(self.ui.list_box, 'update_event_info',
                             self._update_event_info)

        # Login window
        urwid.connect_signal(self.ui.login_window, 'authenticate', self.login)
        urwid.connect_signal(self.ui.login_window, 'quit', self.quit)

        # Main window
        urwid.connect_signal(self.ui.main_frame, 'update_event_list',
                             self._update_event_list)
        urwid.connect_signal(self.ui.main_frame, 'quit', self.quit)
        urwid.connect_signal(self.ui.main_frame, 'show_event_filter',
                             self.show_event_filter_window)
        urwid.connect_signal(self.ui.main_frame, 'ack_event', self.ack_event)
        urwid.connect_signal(self.ui.main_frame, 'close_event',
                             self.close_event)
        urwid.connect_signal(self.ui.main_frame, 'reopen_event',
                             self.reopen_event)

        # Event filter window
        urwid.connect_signal(self.ui.event_filter_window,
                             'update_event_list', self._update_event_list)
        urwid.connect_signal(self.ui.event_filter_window,
                             'event_filter_close',
                             self.show_main_window)
        urwid.connect_signal(self.ui.event_filter_window, 'change_filter',
                             self._change_zenoss_parameter)

    def _change_zenoss_parameter(self, state, param, value):
        if state:
            self.zenoss.params[param].append(value)
        else:
            self.zenoss.params[param].remove(value)

    def _update_event_info(self):
        """ Updates event info with data from selected event. """

        # Only update info if an event is in focus
        try:
            idx = self.ui.list_box.focus_position
            event = self.z_events[idx]
        except IndexError:
            self.ui.event_info[:] = [urwid.Text('')]
            return

        info_map = [
            SelectableText(event['message']),
            urwid.Divider('-'),
            ('Device', event['details']['device_title'][0]),
            ('Severity', ZenEvents.severities[event['severity']]),
            ('Count', event['count']),
            ('Component', event['component']['text']),
            ('Event state', event['eventState']),
            ('Prod state', event['prodState']),
            ('Owner', event.get('ownerid', 'N/A')),
            ('First seen', event['firstTime']),
            ('Last seen', event['lastTime']),
            ('State change', event['stateChange']),
            ('DeviceClass', event['DeviceClass'][0]['name']),
            ('Location', ', '.join(l['name'] for l in event['Location']
                                   if l['name'])),
            ('Groups', ', '.join(l['name'] for l in event['DeviceGroups']
                                 if l['name'])),
            ('Systems', ', '.join(l['name'] for l in event['Systems']
                                  if l['name'])),
            ('EVID', event['evid']),
        ]

        # Replace previous event info with new
        del self.ui.event_info[:]
        for i in info_map:
            if isinstance(i, tuple):
                i = SelectableText("{:20} : {!s}".format(i[0], i[1]))

            self.ui.event_info.append(
                    urwid.AttrMap(i, 'infobox', 'infobox.focus'))

    def _update_event_list(self, caller=None, use_zenoss=True):
        """ Updates the event list. """

        logger.error(caller)
        logger.error(use_zenoss)
        # Save current focus position for later use
        try:
            saved_focus_idx = self.ui.list_box.focus_position
            saved_evid = self.z_events[saved_focus_idx]['evid']
        except IndexError:
            saved_focus_idx = None
            saved_evid = None

        if self.main_loop:
            self.ui.event_list[:] = [urwid.Text('Updating...')]
            self.main_loop.draw_screen()

        # Get new data from zenoss
        if use_zenoss:
            self.z_events[:] = self.zenoss.update()

        # Populate event list with new data
        self.ui.list_box.body[:] = [
            urwid.AttrMap(EventText(event, self.ui.list_box.maxcol),
                          'severity_'+str(event['severity']), 'event.focus')
            for event in self.z_events]

        # Try to restore focus
        if saved_focus_idx:
            try:
                new_idx = next(i for (i, e) in enumerate(self.z_events) if
                               e['evid'] == saved_evid)
                self.ui.event_list.set_focus(new_idx)
            except StopIteration:
                pass

        # Update event info on currently selected event
        urwid.emit_signal(self.ui.list_box, 'update_event_info')

        # Show HHGTTG smiley if there are no events
        if not len(self.z_events):
            self.ui.list_box.body[:] = [urwid.Padding(urwid.Text(self.smiley),
                                                      'center', 75)]
            del self.ui.event_info[:]

        # Make sure the counter is only reset every N seconds. This prevents
        # setting a timer on manual refresh.
        if isinstance(caller, urwid.MainLoop):
            self.main_loop.set_alarm_in(self.update_interval,
                                        self._update_event_list,
                                        user_data=True)

    # TODO: DRY the _event methods
    def ack_event(self):
        """ Ack an event. """

        # Must have a focused event
        try:
            idx = self.ui.list_box.focus_position
            event = self.z_events[idx]
        except IndexError:
            return

        # Ack in zenoss
        self.zenoss.ack_events([event['evid']])

        # Delete from event list
        if (ZenEvents.event_states['acknowledged'] not in
                self.zenoss.params['eventState']):
            del self.z_events[idx]
        else:
            self.z_events[idx] = self.zenoss.get_event(event['evid'])
        urwid.emit_signal(self.ui.main_frame, 'update_event_list', None, False)

    def close_event(self):
        """ Close an event. """

        # Must have a focused event
        try:
            idx = self.ui.list_box.focus_position
            event = self.z_events[idx]
        except IndexError:
            return

        # Close in zenoss
        self.zenoss.close_events([event['evid']])

        # Delete from event list
        if (ZenEvents.event_states['closed'] not in
                self.zenoss.params['eventState']):
            del self.z_events[idx]
        else:
            self.z_events[idx] = self.zenoss.get_event(event['evid'])
        urwid.emit_signal(self.ui.main_frame, 'update_event_list', None, False)

    def reopen_event(self):
        """ Reopen an event. """

        # Must have a focused event
        try:
            idx = self.ui.list_box.focus_position
            event = self.z_events[idx]
        except IndexError:
            return

        # Reopen in zenoss
        self.zenoss.reopen_events([event['evid']])

        # Delete from event list
        if (ZenEvents.event_states['new'] not in
                self.zenoss.params['eventState']):
            del self.z_events[idx]
        else:
            self.z_events[idx] = self.zenoss.get_event(event['evid'])
        urwid.emit_signal(self.ui.main_frame, 'update_event_list', None, False)

    def login(self, username, password):
        """ Handle authentication. Initiates main window upon success. """
        self.zen_username = username
        self.zen_password = password
        try:
            self.zenoss = ZenEvents(url=self.zen_url,
                                    username=self.zen_username,
                                    password=self.zen_password)
            self.zenoss.login()
            self.ui.login_window.set_message('')
            self.main_loop.widget = self.ui.main_frame

            # Start refreshing the event list periodially
            self.main_loop.set_alarm_in(0, self._update_event_list,
                                        user_data=True)
        except self.zenoss.Unauthorized:
            self.ui.login_window.password_w.set_edit_text('')
            self.ui.login_window.set_message('LOGIN FAILED')

    def quit(self, originator=None):
        raise urwid.ExitMainLoop()

    def show_event_filter_window(self):
        self.main_loop.widget = self.ui.event_filter_window

    def show_main_window(self):
        self.main_loop.widget = self.ui.main_frame

    def start(self):
        # Set login window as the top most widget
        self.main_loop.widget = self.ui.login_window
        if self.auto_login:
            # fill in the password
            self.ui.login_window.password_w.set_edit_text(self.zen_password)
            # focus the login button
            self.ui.login_window.items.set_focus(5)
        self.main_loop.run()


def main():
    zh = ZenHest()
    zh.start()

if __name__ == '__main__':
    main()
