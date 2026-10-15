#!/usr/bin/env python3

"""
Bridge from a HiSilicon log stream to DiagNG's GSMTAP/PCAP output.

Mirrors :class:`diagng.protocol.qualcomm.modules.ota_decoder.OTADecoder`
but for HiSilicon/Kirin basebands: it owns a :class:`HisiLogParser`, is fed
raw frames (whole pseudo-HDLC frames, 0x7e-terminated), and writes the
resulting GSMTAP v2 packets to a :class:`PcapOutput`.

The HiSilicon DIAG stream is passive (see
:mod:`diagng.protocol.hisilicon.hisi_log_parser`), so this class only reads
and decodes — it never sends QCDM-style log-enable commands.
"""

from logging import error
from traceback import format_exc
from typing import TYPE_CHECKING, Optional

from gi.repository import GObject

from diagng.protocol.hisilicon.hisi_log_parser import (
    HisiLogParser,
    GsmtapRecord,
)
from diagng.protocol.hisilicon.acquisition.base_input import BaseHisiInput

if TYPE_CHECKING:
    from diagng.system.pcap_output import PcapOutput


class HisiOTADecoder(GObject.Object):
    pcap_stream: 'PcapOutput'
    input_obj: Optional[BaseHisiInput] = None

    emit_debug_msgs = GObject.Property(type=bool, default=False)

    def __init__(
        self,
        pcap_stream: 'PcapOutput',
        input_obj: Optional[BaseHisiInput] = None,
        emit_debug_msgs: bool = False,
    ):
        super().__init__()

        self.pcap_stream = pcap_stream
        self.emit_debug_msgs = emit_debug_msgs
        self.parser = HisiLogParser(emit_debug_msgs=emit_debug_msgs)

        self.input_obj = input_obj
        self.input_signal = None
        if input_obj is not None:
            self.input_signal = input_obj.frame_received.connect(
                self._on_frame
            )

    def _on_frame(
        self,
        input_obj: BaseHisiInput,
        frame: bytes,
        num_frame: int,
        total_frames: int,
    ):
        self.feed_frame(frame)

    def disconnect(self):
        if self.input_obj is not None and self.input_signal is not None:
            self.input_obj.frame_received.disconnect(self.input_signal)
            self.input_signal = None

    def feed_frame(self, frame: bytes):
        """Decode one 0x7e-terminated HiSilicon frame and emit GSMTAP."""
        for record in self.parser.parse_frame(frame):
            self._emit(record)

    def feed_stream(self, data: bytes):
        """Decode every complete frame in a byte stream and emit GSMTAP."""
        for record in self.parser.parse_stream(data):
            self._emit(record)

    def _emit(self, record: GsmtapRecord):
        try:
            self.pcap_stream.write_gsmtap_v2_packet(
                record.packet_type,
                record.sub_type,
                record.data,
                record.is_uplink,
                record.arfcn,
            )
        except Exception:
            error('HiSilicon: failed to write GSMTAP packet: ' + format_exc())
