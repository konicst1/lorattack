#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: LoRaTransmitter
# Author: konicst1
# GNU Radio version: 3.10.1.1

from packaging.version import Version as StrictVersion

if __name__ == '__main__':
    import ctypes
    import sys
    if sys.platform.startswith('linux'):
        try:
            x11 = ctypes.cdll.LoadLibrary('libX11.so')
            x11.XInitThreads()
        except:
            print("Warning: failed to XInitThreads()")

from gnuradio import blocks
import pmt
from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import sys
import signal
from PyQt5 import Qt
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import uhd
import time
import gnuradio.lora_sdr as lora_sdr



from gnuradio import qtgui

class LoRaTransmitter(gr.top_block, Qt.QWidget):

    def __init__(self, bandwidth=125000, frequency=868.1e6, gain_db=10, message='48656c6cffff776f726c64', samp_rate=1000000, spreading_factor=7):
        gr.top_block.__init__(self, "LoRaTransmitter", catch_exceptions=True)
        Qt.QWidget.__init__(self)
        self.setWindowTitle("LoRaTransmitter")
        qtgui.util.check_set_qss()
        try:
            self.setWindowIcon(Qt.QIcon.fromTheme('gnuradio-grc'))
        except:
            pass
        self.top_scroll_layout = Qt.QVBoxLayout()
        self.setLayout(self.top_scroll_layout)
        self.top_scroll = Qt.QScrollArea()
        self.top_scroll.setFrameStyle(Qt.QFrame.NoFrame)
        self.top_scroll_layout.addWidget(self.top_scroll)
        self.top_scroll.setWidgetResizable(True)
        self.top_widget = Qt.QWidget()
        self.top_scroll.setWidget(self.top_widget)
        self.top_layout = Qt.QVBoxLayout(self.top_widget)
        self.top_grid_layout = Qt.QGridLayout()
        self.top_layout.addLayout(self.top_grid_layout)

        self.settings = Qt.QSettings("GNU Radio", "LoRaTransmitter")

        try:
            if StrictVersion(Qt.qVersion()) < StrictVersion("5.0.0"):
                self.restoreGeometry(self.settings.value("geometry").toByteArray())
            else:
                self.restoreGeometry(self.settings.value("geometry"))
        except:
            pass

        ##################################################
        # Parameters
        ##################################################
        self.bandwidth = bandwidth
        self.frequency = frequency
        self.gain_db = gain_db
        self.message = message
        self.samp_rate = samp_rate
        self.spreading_factor = spreading_factor

        ##################################################
        # Variables
        ##################################################
        self.byte_data = byte_data = bytes.fromhex(message)

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_sink_0 = uhd.usrp_sink(
            ",".join(("", '')),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
            "",
        )
        self.uhd_usrp_sink_0.set_samp_rate(samp_rate)
        self.uhd_usrp_sink_0.set_time_unknown_pps(uhd.time_spec(0))

        self.uhd_usrp_sink_0.set_center_freq(frequency, 0)
        self.uhd_usrp_sink_0.set_antenna("TX/RX", 0)
        self.uhd_usrp_sink_0.set_gain(gain_db, 0)
        self.lora_tx_0 = lora_sdr.lora_sdr_lora_tx(
            bw=bandwidth,
            cr=1,
            has_crc=False,
            impl_head=False,
            samp_rate=samp_rate,
            sf=spreading_factor,
         ldro_mode=2,frame_zero_padd=1280 )
        self.blocks_message_strobe_1 = blocks.message_strobe(pmt.intern(byte_data), 100)
        self.blocks_message_debug_0 = blocks.message_debug(True)


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.blocks_message_strobe_1, 'strobe'), (self.lora_tx_0, 'in'))
        self.connect((self.lora_tx_0, 0), (self.uhd_usrp_sink_0, 0))


    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "LoRaTransmitter")
        self.settings.setValue("geometry", self.saveGeometry())
        self.stop()
        self.wait()

        event.accept()

    def get_bandwidth(self):
        return self.bandwidth

    def set_bandwidth(self, bandwidth):
        self.bandwidth = bandwidth

    def get_frequency(self):
        return self.frequency

    def set_frequency(self, frequency):
        self.frequency = frequency
        self.uhd_usrp_sink_0.set_center_freq(self.frequency, 0)

    def get_gain_db(self):
        return self.gain_db

    def set_gain_db(self, gain_db):
        self.gain_db = gain_db
        self.uhd_usrp_sink_0.set_gain(self.gain_db, 0)

    def get_message(self):
        return self.message

    def set_message(self, message):
        self.message = message
        self.set_byte_data(bytes.fromhex(self.message))

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.uhd_usrp_sink_0.set_samp_rate(self.samp_rate)

    def get_spreading_factor(self):
        return self.spreading_factor

    def set_spreading_factor(self, spreading_factor):
        self.spreading_factor = spreading_factor
        self.lora_tx_0.set_sf(self.spreading_factor)

    def get_byte_data(self):
        return self.byte_data

    def set_byte_data(self, byte_data):
        self.byte_data = byte_data
        self.blocks_message_strobe_1.set_msg(pmt.intern(self.byte_data))



def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--bandwidth", dest="bandwidth", type=intx, default=125000,
        help="Set bandwidth [default=%(default)r]")
    parser.add_argument(
        "--frequency", dest="frequency", type=eng_float, default=eng_notation.num_to_str(float(868.1e6)),
        help="Set frequency [default=%(default)r]")
    parser.add_argument(
        "--gain-db", dest="gain_db", type=intx, default=10,
        help="Set gain_db [default=%(default)r]")
    parser.add_argument(
        "--message", dest="message", type=str, default='48656c6cffff776f726c64',
        help="Set message [default=%(default)r]")
    parser.add_argument(
        "--samp-rate", dest="samp_rate", type=intx, default=1000000,
        help="Set samp_rate [default=%(default)r]")
    parser.add_argument(
        "--spreading-factor", dest="spreading_factor", type=intx, default=7,
        help="Set spreading_factor [default=%(default)r]")
    return parser


def main(top_block_cls=LoRaTransmitter, options=None):
    if options is None:
        options = argument_parser().parse_args()

    if StrictVersion("4.5.0") <= StrictVersion(Qt.qVersion()) < StrictVersion("5.0.0"):
        style = gr.prefs().get_string('qtgui', 'style', 'raster')
        Qt.QApplication.setGraphicsSystem(style)
    qapp = Qt.QApplication(sys.argv)

    tb = top_block_cls(bandwidth=options.bandwidth, frequency=options.frequency, gain_db=options.gain_db, message=options.message, samp_rate=options.samp_rate, spreading_factor=options.spreading_factor)

    tb.start()

    tb.show()

    def sig_handler(sig=None, frame=None):
        tb.stop()
        tb.wait()

        Qt.QApplication.quit()

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    timer = Qt.QTimer()
    timer.start(500)
    timer.timeout.connect(lambda: None)

    qapp.exec_()

if __name__ == '__main__':
    main()
