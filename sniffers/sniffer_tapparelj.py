#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Not titled yet
# Author: pentester
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

from PyQt5 import Qt
from gnuradio import qtgui
from gnuradio.filter import firdes
import sip
from gnuradio import gr
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import uhd
import time
import gnuradio.lora_sdr as lora_sdr
import lora



from gnuradio import qtgui

class sniffer_11_12(gr.top_block, Qt.QWidget):

    def __init__(self, bandwidth=125000, frequency=868.3e6, gain_db=10, samp_rate=2000000, spreading_factor=7):
        gr.top_block.__init__(self, "Not titled yet", catch_exceptions=True)
        Qt.QWidget.__init__(self)
        self.setWindowTitle("Not titled yet")
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

        self.settings = Qt.QSettings("GNU Radio", "sniffer_11_12")

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
        self.samp_rate = samp_rate
        self.spreading_factor = spreading_factor

        ##################################################
        # Variables
        ##################################################
        self.decode_downlink = decode_downlink = False
        self.channels = channels = [frequency]

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_source_0 = uhd.usrp_source(
            ",".join(("", '')),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
        )
        self.uhd_usrp_source_0.set_samp_rate(samp_rate)
        self.uhd_usrp_source_0.set_time_unknown_pps(uhd.time_spec(0))

        self.uhd_usrp_source_0.set_center_freq(frequency, 0)
        self.uhd_usrp_source_0.set_antenna("RX2", 0)
        self.uhd_usrp_source_0.set_gain(gain_db, 0)
        self.uhd_usrp_source_0.set_min_output_buffer(100000)
        self.qtgui_sink_x_0_0_0 = qtgui.sink_c(
            1024, #fftsize
            window.WIN_BLACKMAN_hARRIS, #wintype
            frequency, #fc
            samp_rate, #bw
            "", #name
            True, #plotfreq
            True, #plotwaterfall
            True, #plottime
            True, #plotconst
            None # parent
        )
        self.qtgui_sink_x_0_0_0.set_update_time(1.0/10)
        self._qtgui_sink_x_0_0_0_win = sip.wrapinstance(self.qtgui_sink_x_0_0_0.qwidget(), Qt.QWidget)

        self.qtgui_sink_x_0_0_0.enable_rf_freq(False)

        self.top_layout.addWidget(self._qtgui_sink_x_0_0_0_win)
        self.lora_rx_1_1_1_0_0_0 = lora_sdr.lora_sdr_lora_rx( bw=bandwidth, cr=1, has_crc=True, impl_head=False, pay_len=255, samp_rate=samp_rate, sf=spreading_factor, soft_decoding=True, ldro_mode=2, print_rx=[True,True])
        self.lora_message_socket_sink_0 = lora.message_socket_sink('127.0.0.1', 40868, 0)


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.lora_rx_1_1_1_0_0_0, 'out'), (self.lora_message_socket_sink_0, 'in'))
        self.connect((self.uhd_usrp_source_0, 0), (self.lora_rx_1_1_1_0_0_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.qtgui_sink_x_0_0_0, 0))


    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "sniffer_11_12")
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
        self.set_channels([self.frequency])
        self.qtgui_sink_x_0_0_0.set_frequency_range(self.frequency, self.samp_rate)
        self.uhd_usrp_source_0.set_center_freq(self.frequency, 0)

    def get_gain_db(self):
        return self.gain_db

    def set_gain_db(self, gain_db):
        self.gain_db = gain_db
        self.uhd_usrp_source_0.set_gain(self.gain_db, 0)

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.qtgui_sink_x_0_0_0.set_frequency_range(self.frequency, self.samp_rate)
        self.uhd_usrp_source_0.set_samp_rate(self.samp_rate)

    def get_spreading_factor(self):
        return self.spreading_factor

    def set_spreading_factor(self, spreading_factor):
        self.spreading_factor = spreading_factor

    def get_decode_downlink(self):
        return self.decode_downlink

    def set_decode_downlink(self, decode_downlink):
        self.decode_downlink = decode_downlink

    def get_channels(self):
        return self.channels

    def set_channels(self, channels):
        self.channels = channels



def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--bandwidth", dest="bandwidth", type=intx, default=125000,
        help="Set bandwidth [default=%(default)r]")
    parser.add_argument(
        "--frequency", dest="frequency", type=eng_float, default=eng_notation.num_to_str(float(868.3e6)),
        help="Set frequency [default=%(default)r]")
    parser.add_argument(
        "--gain-db", dest="gain_db", type=intx, default=10,
        help="Set gain_db [default=%(default)r]")
    parser.add_argument(
        "--samp-rate", dest="samp_rate", type=intx, default=2000000,
        help="Set samp_rate [default=%(default)r]")
    parser.add_argument(
        "--spreading-factor", dest="spreading_factor", type=intx, default=7,
        help="Set spreading_factor [default=%(default)r]")
    return parser


def main(top_block_cls=sniffer_11_12, options=None):
    if options is None:
        options = argument_parser().parse_args()

    if StrictVersion("4.5.0") <= StrictVersion(Qt.qVersion()) < StrictVersion("5.0.0"):
        style = gr.prefs().get_string('qtgui', 'style', 'raster')
        Qt.QApplication.setGraphicsSystem(style)
    qapp = Qt.QApplication(sys.argv)

    tb = top_block_cls(bandwidth=options.bandwidth, frequency=options.frequency, gain_db=options.gain_db, samp_rate=options.samp_rate, spreading_factor=options.spreading_factor)

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
