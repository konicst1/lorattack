from __future__ import annotations
from src.player import Player
from src.sniffer import Sniffer
from src.session_manager import SessionManager
from src.analyzer import Analyzer
import urwid

loop = None
top = None


class MenuButton(urwid.Button):
    def __init__(self, caption, callback):
        super().__init__("")
        urwid.connect_signal(self, 'click', callback)
        self._w = urwid.AttrMap(urwid.SelectableIcon(
            ['  \N{BULLET} ', caption], 2), None, 'selected')


class SubMenu(urwid.WidgetWrap):
    def __init__(self, caption, choices):
        super().__init__(MenuButton(
            [caption, "\N{HORIZONTAL ELLIPSIS}"], self.open_menu))
        line = urwid.Divider('\N{LOWER ONE QUARTER BLOCK}')
        listbox = urwid.ListBox(urwid.SimpleFocusListWalker([
                                                                urwid.AttrMap(urwid.Text(["\n  ", caption]), 'heading'),
                                                                urwid.AttrMap(line, 'line'),
                                                                urwid.Divider()] + choices + [urwid.Divider()]))
        self.menu = urwid.AttrMap(listbox, 'options')

    def open_menu(self, button):
        top.open_box(self.menu)


class Choice(urwid.WidgetWrap):
    def __init__(self, caption, action=None, *args, **kwargs):
        super().__init__(
            MenuButton(caption, self.item_chosen))
        self.caption = caption
        self.action = action
        self.args = args
        self.kwargs = kwargs

    def item_chosen(self, button):
        if self.action:
            self.action(*self.args, **self.kwargs)
        else:
            response = urwid.Text(['  You chose ', self.caption, '\n'])
            done = MenuButton('Ok', exit_program)
            response_box = urwid.Filler(urwid.Pile([response, done]))
            top.open_box(urwid.AttrMap(response_box, 'options'))


def exit_program(key):
    raise urwid.ExitMainLoop()


def start_scanning(ifc, button=None):
    global loop

    loop.screen.stop()
    # airmon_scan.run_airodump(ifc)
    loop.screen.start()


palette = [
    (None, 'light gray', 'black'),
    ('heading', 'black', 'light gray'),
    ('line', 'black', 'light gray'),
    ('options', 'dark gray', 'black'),
    ('focus heading', 'white', 'dark red'),
    ('focus line', 'black', 'dark red'),
    ('focus options', 'black', 'light gray'),
    ('selected', 'white', 'dark blue')]
focus_map = {
    'heading': 'focus heading',
    'options': 'focus options',
    'line': 'focus line'}


class HorizontalBoxes(urwid.Columns):
    def __init__(self):
        super().__init__([], dividechars=1)

    def open_box(self, box):
        if self.contents:
            del self.contents[self.focus_position + 1:]
        self.contents.append((urwid.AttrMap(box, 'options', focus_map),
                              self.options('given', 32)))
        self.focus_position = len(self.contents) - 1


class EnterReactEdit(urwid.Edit):
    def __init__(self, *args, **kwargs):
        self.on_enter = kwargs.pop('on_enter', None)  # Extract the on_enter callback if provided
        super().__init__(*args, **kwargs)

    def keypress(self, size, key):
        if key == 'enter':
            if self.on_enter:  # Check if the on_enter callback is provided and callable
                self.on_enter(self.get_edit_text())
            else:
                # Default behavior for 'enter' can be customized here if needed
                pass
        else:
            return super().keypress(size, key)


class GUIManager:
    def __init__(self):
        self.sniffer = Sniffer()
        self.session_manager = SessionManager()
        self.analyzer = Analyzer()
        self.player = Player()
        self.edit = EnterReactEdit("Enter name: ", on_enter=self.on_change)

        menu_top = SubMenu('LoRaWAN Tester', [
            SubMenu('Session', [
                SubMenu('New Session', [
                    self.edit
                ]),
                SubMenu('Choose Session', [
                    Choice(name, action=self.activate_session, text=name) for name in
                    self.session_manager.list_sessions()
                ]),

            ]),
            SubMenu('Sniffer', [
                SubMenu('Sniff', [
                    Choice('Sniff Up/Down link', action=self.sniff, path=self.sniffer.bisniff),
                    Choice('Sniff Uplink', action=self.sniff, path=self.sniffer.upsniff),
                    Choice('Sniff Downlink', action=self.sniff, path=self.sniffer.downsniff)
                ]),
                SubMenu('Configure', [
                    Choice('Edit config/sniffer.config', action=self.sniffer.configure_sniffer)
                ]),

            ]),
            SubMenu('Analyzer', [
                Choice(name, action=self.analyze_pcap, pcap=name) for name in
                self.session_manager.list_pcap_files()
            ]),
            SubMenu('Attack', [
                SubMenu('Replay', [
                    Choice('Join Request', action=self.player.spoof_JoinRequest),
                    Choice('Join Accept'),
                    SubMenu('From pcap', [
                        Choice(name, action=self.replay_sequence_from_pcap, pcap=name) for name in self.session_manager.list_pcap_files()
                    ]),
                    Choice('Edit replay sequence', action=self.edit_replay_sequence),
                    Choice('Configure transmitter', action=self.player.configure_transmitter),
                ]),
            ]),
            Choice('Exit'),
        ])
        global loop
        global top
        top = HorizontalBoxes()
        top.open_box(menu_top.menu)
        loop = urwid.MainLoop(urwid.Filler(top, 'middle', 20), palette)

    def run(self):
        loop.run()

    def sniff(self, path):
        global loop

        loop.screen.stop()
        self.sniffer.run_sniffer_thread(path)
        loop.screen.start()

    def on_change(self, text):
        self.session_manager.create_session(text)
        self.edit.set_edit_text("Session created")

    def activate_session(self, text):
        self.session_manager.activate_session(text)

    def edit_replay_sequence(self):
        global loop

        loop.screen.stop()
        self.session_manager.manage_sequence_file()
        loop.screen.start()

    def analyze_pcap(self, pcap):
        path = self.session_manager.sessions_dir + '/' + self.session_manager.get_current_session_name() + '/' + pcap
        self.analyzer.analyze_pcap(path)

    def replay_sequence_from_pcap(self, pcap):
        global loop

        loop.screen.stop()
        path = self.session_manager.sessions_dir + '/' + self.session_manager.get_current_session_name() + '/' + pcap
        self.player.replay_sequence_from_pcap(path)
        loop.screen.start()
