#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: LoRaWAN Sniffer
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
from gnuradio import blocks
import math
from gnuradio import gr
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import uhd
import time
import lora



from gnuradio import qtgui

class test(gr.top_block, Qt.QWidget):

    def __init__(self, bandwidth=125000, frequency=867.6e6, samp_rate=1000000, spreading_factor=7):
        gr.top_block.__init__(self, "LoRaWAN Sniffer", catch_exceptions=True)
        Qt.QWidget.__init__(self)
        self.setWindowTitle("LoRaWAN Sniffer")
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

        self.settings = Qt.QSettings("GNU Radio", "test")

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
        self.samp_rate = samp_rate
        self.spreading_factor = spreading_factor

        ##################################################
        # Variables
        ##################################################
        self.squelch_treshold = squelch_treshold = -60
        self.rpp0_channelization_disable = rpp0_channelization_disable = False
        self.low_pass_trans_width = low_pass_trans_width = bandwidth*0.5
        self.low_pass_cutoff = low_pass_cutoff = bandwidth*0.9
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
        self.uhd_usrp_source_0.set_gain(10, 0)
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
        self.lora_message_socket_sink_1 = lora.message_socket_sink('127.0.0.1', 40868, 1)
        self.lora_lora_receiver_0_0_4_1_9 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, True, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_8 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, True, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_7 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, True, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_6 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, True, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_5 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, True, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_4 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, True, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_3 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, True, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_2 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, True, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_1_9 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, False, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_1_8 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, False, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_1_7 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, False, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_1_6 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, False, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_1_5 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, False, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_1_4 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, False, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_1_3 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, False, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_1_2 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, False, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_1_1 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, False, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_1_0 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, False, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_11 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, True, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_10 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, True, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1_1 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, False, 1, rpp0_channelization_disable, False)
        self.lora_lora_receiver_0_0_4_1 = lora.lora_receiver(samp_rate, frequency, channels, bandwidth, spreading_factor, False, 4, True, False, True, 1, rpp0_channelization_disable, False)
        self.blocks_freqshift_cc_0_1 = blocks.rotator_cc(2.0*math.pi*-900e3/samp_rate)
        self.blocks_freqshift_cc_0_0_1 = blocks.rotator_cc(2.0*math.pi*-700e3/samp_rate)
        self.blocks_freqshift_cc_0_0_0_1 = blocks.rotator_cc(2.0*math.pi*-500e3/samp_rate)
        self.blocks_freqshift_cc_0_0_0_0_2 = blocks.rotator_cc(2.0*math.pi*-300e3/samp_rate)
        self.blocks_freqshift_cc_0_0_0_0_1_0 = blocks.rotator_cc(2.0*math.pi*-100e3/samp_rate)
        self.blocks_freqshift_cc_0_0_0_0_1 = blocks.rotator_cc(2.0*math.pi*+100e3/samp_rate)
        self.blocks_freqshift_cc_0_0_0_0_0 = blocks.rotator_cc(2.0*math.pi*0/samp_rate)
        self.blocks_freqshift_cc_0_0_0_0 = blocks.rotator_cc(2.0*math.pi*+300e3/samp_rate)
        self.blocks_freqshift_cc_0_0_0 = blocks.rotator_cc(2.0*math.pi*+500e3/samp_rate)
        self.blocks_freqshift_cc_0_0 = blocks.rotator_cc(2.0*math.pi*+700e3/samp_rate)
        self.blocks_freqshift_cc_0 = blocks.rotator_cc(2.0*math.pi*+900e3/samp_rate)


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.lora_lora_receiver_0_0_4_1, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_1, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_10, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_11, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_1_0, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_1_1, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_1_2, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_1_3, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_1_4, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_1_5, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_1_6, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_1_7, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_1_8, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_1_9, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_2, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_3, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_4, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_5, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_6, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_7, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_8, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.msg_connect((self.lora_lora_receiver_0_0_4_1_9, 'frames'), (self.lora_message_socket_sink_1, 'in'))
        self.connect((self.blocks_freqshift_cc_0, 0), (self.lora_lora_receiver_0_0_4_1, 0))
        self.connect((self.blocks_freqshift_cc_0, 0), (self.lora_lora_receiver_0_0_4_1_1, 0))
        self.connect((self.blocks_freqshift_cc_0_0, 0), (self.lora_lora_receiver_0_0_4_1_1_0, 0))
        self.connect((self.blocks_freqshift_cc_0_0, 0), (self.lora_lora_receiver_0_0_4_1_2, 0))
        self.connect((self.blocks_freqshift_cc_0_0_0, 0), (self.lora_lora_receiver_0_0_4_1_1_1, 0))
        self.connect((self.blocks_freqshift_cc_0_0_0, 0), (self.lora_lora_receiver_0_0_4_1_3, 0))
        self.connect((self.blocks_freqshift_cc_0_0_0_0, 0), (self.lora_lora_receiver_0_0_4_1_1_2, 0))
        self.connect((self.blocks_freqshift_cc_0_0_0_0, 0), (self.lora_lora_receiver_0_0_4_1_4, 0))
        self.connect((self.blocks_freqshift_cc_0_0_0_0_0, 0), (self.lora_lora_receiver_0_0_4_1_1_4, 0))
        self.connect((self.blocks_freqshift_cc_0_0_0_0_0, 0), (self.lora_lora_receiver_0_0_4_1_6, 0))
        self.connect((self.blocks_freqshift_cc_0_0_0_0_1, 0), (self.lora_lora_receiver_0_0_4_1_1_3, 0))
        self.connect((self.blocks_freqshift_cc_0_0_0_0_1, 0), (self.lora_lora_receiver_0_0_4_1_5, 0))
        self.connect((self.blocks_freqshift_cc_0_0_0_0_1_0, 0), (self.lora_lora_receiver_0_0_4_1_1_5, 0))
        self.connect((self.blocks_freqshift_cc_0_0_0_0_1_0, 0), (self.lora_lora_receiver_0_0_4_1_7, 0))
        self.connect((self.blocks_freqshift_cc_0_0_0_0_2, 0), (self.lora_lora_receiver_0_0_4_1_1_6, 0))
        self.connect((self.blocks_freqshift_cc_0_0_0_0_2, 0), (self.lora_lora_receiver_0_0_4_1_8, 0))
        self.connect((self.blocks_freqshift_cc_0_0_0_1, 0), (self.lora_lora_receiver_0_0_4_1_1_7, 0))
        self.connect((self.blocks_freqshift_cc_0_0_0_1, 0), (self.lora_lora_receiver_0_0_4_1_9, 0))
        self.connect((self.blocks_freqshift_cc_0_0_1, 0), (self.lora_lora_receiver_0_0_4_1_10, 0))
        self.connect((self.blocks_freqshift_cc_0_0_1, 0), (self.lora_lora_receiver_0_0_4_1_1_8, 0))
        self.connect((self.blocks_freqshift_cc_0_1, 0), (self.lora_lora_receiver_0_0_4_1_11, 0))
        self.connect((self.blocks_freqshift_cc_0_1, 0), (self.lora_lora_receiver_0_0_4_1_1_9, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_freqshift_cc_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_freqshift_cc_0_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_freqshift_cc_0_0_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_freqshift_cc_0_0_0_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_freqshift_cc_0_0_0_0_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_freqshift_cc_0_0_0_0_1, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_freqshift_cc_0_0_0_0_1_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_freqshift_cc_0_0_0_0_2, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_freqshift_cc_0_0_0_1, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_freqshift_cc_0_0_1, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_freqshift_cc_0_1, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.qtgui_sink_x_0_0_0, 0))


    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "test")
        self.settings.setValue("geometry", self.saveGeometry())
        self.stop()
        self.wait()

        event.accept()

    def get_bandwidth(self):
        return self.bandwidth

    def set_bandwidth(self, bandwidth):
        self.bandwidth = bandwidth
        self.set_low_pass_cutoff(self.bandwidth*0.9)
        self.set_low_pass_trans_width(self.bandwidth*0.5)

    def get_frequency(self):
        return self.frequency

    def set_frequency(self, frequency):
        self.frequency = frequency
        self.set_channels([self.frequency])
        self.lora_lora_receiver_0_0_4_1.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_1.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_10.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_11.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_1_0.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_1_1.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_1_2.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_1_3.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_1_4.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_1_5.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_1_6.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_1_7.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_1_8.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_1_9.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_2.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_3.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_4.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_5.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_6.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_7.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_8.set_center_freq(self.frequency)
        self.lora_lora_receiver_0_0_4_1_9.set_center_freq(self.frequency)
        self.qtgui_sink_x_0_0_0.set_frequency_range(self.frequency, self.samp_rate)
        self.uhd_usrp_source_0.set_center_freq(self.frequency, 0)

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.blocks_freqshift_cc_0.set_phase_inc(2.0*math.pi*+900e3/self.samp_rate)
        self.blocks_freqshift_cc_0_0.set_phase_inc(2.0*math.pi*+700e3/self.samp_rate)
        self.blocks_freqshift_cc_0_0_0.set_phase_inc(2.0*math.pi*+500e3/self.samp_rate)
        self.blocks_freqshift_cc_0_0_0_0.set_phase_inc(2.0*math.pi*+300e3/self.samp_rate)
        self.blocks_freqshift_cc_0_0_0_0_0.set_phase_inc(2.0*math.pi*0/self.samp_rate)
        self.blocks_freqshift_cc_0_0_0_0_1.set_phase_inc(2.0*math.pi*+100e3/self.samp_rate)
        self.blocks_freqshift_cc_0_0_0_0_1_0.set_phase_inc(2.0*math.pi*-100e3/self.samp_rate)
        self.blocks_freqshift_cc_0_0_0_0_2.set_phase_inc(2.0*math.pi*-300e3/self.samp_rate)
        self.blocks_freqshift_cc_0_0_0_1.set_phase_inc(2.0*math.pi*-500e3/self.samp_rate)
        self.blocks_freqshift_cc_0_0_1.set_phase_inc(2.0*math.pi*-700e3/self.samp_rate)
        self.blocks_freqshift_cc_0_1.set_phase_inc(2.0*math.pi*-900e3/self.samp_rate)
        self.qtgui_sink_x_0_0_0.set_frequency_range(self.frequency, self.samp_rate)
        self.uhd_usrp_source_0.set_samp_rate(self.samp_rate)

    def get_spreading_factor(self):
        return self.spreading_factor

    def set_spreading_factor(self, spreading_factor):
        self.spreading_factor = spreading_factor
        self.lora_lora_receiver_0_0_4_1.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_1.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_10.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_11.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_1_0.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_1_1.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_1_2.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_1_3.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_1_4.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_1_5.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_1_6.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_1_7.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_1_8.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_1_9.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_2.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_3.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_4.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_5.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_6.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_7.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_8.set_sf(self.spreading_factor)
        self.lora_lora_receiver_0_0_4_1_9.set_sf(self.spreading_factor)

    def get_squelch_treshold(self):
        return self.squelch_treshold

    def set_squelch_treshold(self, squelch_treshold):
        self.squelch_treshold = squelch_treshold

    def get_rpp0_channelization_disable(self):
        return self.rpp0_channelization_disable

    def set_rpp0_channelization_disable(self, rpp0_channelization_disable):
        self.rpp0_channelization_disable = rpp0_channelization_disable

    def get_low_pass_trans_width(self):
        return self.low_pass_trans_width

    def set_low_pass_trans_width(self, low_pass_trans_width):
        self.low_pass_trans_width = low_pass_trans_width

    def get_low_pass_cutoff(self):
        return self.low_pass_cutoff

    def set_low_pass_cutoff(self, low_pass_cutoff):
        self.low_pass_cutoff = low_pass_cutoff

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
        "--frequency", dest="frequency", type=eng_float, default=eng_notation.num_to_str(float(867.6e6)),
        help="Set frequency [default=%(default)r]")
    parser.add_argument(
        "--samp-rate", dest="samp_rate", type=intx, default=1000000,
        help="Set samp_rate [default=%(default)r]")
    parser.add_argument(
        "--spreading-factor", dest="spreading_factor", type=intx, default=7,
        help="Set spreading_factor [default=%(default)r]")
    return parser


def main(top_block_cls=test, options=None):
    if options is None:
        options = argument_parser().parse_args()

    if StrictVersion("4.5.0") <= StrictVersion(Qt.qVersion()) < StrictVersion("5.0.0"):
        style = gr.prefs().get_string('qtgui', 'style', 'raster')
        Qt.QApplication.setGraphicsSystem(style)
    qapp = Qt.QApplication(sys.argv)

    tb = top_block_cls(bandwidth=options.bandwidth, frequency=options.frequency, samp_rate=options.samp_rate, spreading_factor=options.spreading_factor)

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
