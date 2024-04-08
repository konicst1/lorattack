from __future__ import annotations
import threading

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
    #airmon_scan.run_airodump(ifc)
    loop.screen.start()


def run_kr00k(tool, target, ifc, button=None):
    global loop
    print(f"Running {tool} in {target} mode on interface {ifc}")

    loop.screen.stop()

    loop.screen.start()


def run_wifi_security_attacks(button=None):
    global loop

    loop.screen.stop()
    loop.screen.start()


def run_frag(button=None):
    global loop

    loop.screen.stop()
    #frag_attack.run_frag()
    loop.screen.start()

def store_frag_cfg(ifc, param, button=None):
    global loop

    loop.screen.stop()
    #frag_attack.store_cfg(param, ifc)
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

class GUIManager:
    def __init__(self):
        menu_top = SubMenu('LoRaWAN Tester', [
            SubMenu('Session', [
                SubMenu('New Session', [

                ]),
                SubMenu('Choose Session', [
                ]),
            ]),
            SubMenu('Sniffer', [
                SubMenu('Live sniffing', [

                ]),
                SubMenu('Session Sniffing', [
                    SubMenu('kr00ker', [
                    ]),
                    SubMenu('r00kie-kr00kie', [
                    ]),
                ]),

            ]),
            SubMenu('Transmit', [
                Choice('wifite2', action=run_wifi_security_attacks),
            ]),
            Choice('Exit'),
        ])
        global loop
        global top
        top = HorizontalBoxes()
        top.open_box(menu_top.menu)
        loop = urwid.MainLoop(urwid.Filler(top, 'middle', 20
                                           ), palette)

    def run(self):

        loop.run()

