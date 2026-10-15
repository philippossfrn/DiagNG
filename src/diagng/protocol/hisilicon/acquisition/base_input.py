#!/usr/bin/env python3

"""
Base class for HiSilicon / Kirin diagnostic stream acquisition.

The counterpart of
:class:`diagng.protocol.qualcomm.acquisition.base_input.BaseQCDMInput`, but
much thinner: HiSilicon records are not Kaitai structs, so this layer only
does transport framing. It accumulates the raw byte stream from a concrete
transport (USB, file, ...), splits it into pseudo-HDLC frames on the 0x7e
trailer, and emits each complete frame through the ``frame_received`` signal.
Decoding into GSMTAP is the job of
:class:`diagng.protocol.hisilicon.hisi_decoder.HisiOTADecoder`, which
connects to that signal.

The HiSilicon DIAG stream is passive (the modem emits logs; we never send
QCDM-style enable commands), so ``send_raw`` is optional — a subclass over a
one-way transport may leave it unimplemented.
"""

from abc import abstractmethod
from enum import IntEnum

from gi.repository import GObject

from diagng.protocol.qualcomm.utils.hdlc import TRAILER_CHAR


class InputState(IntEnum):
    Initializing = 1
    Processing = 2
    Closed = 3


class BaseHisiInput(GObject.Object):
    short_name = GObject.Property(type=str)
    full_name = GObject.Property(type=str)
    state = GObject.Property(type=int, default=InputState.Initializing)

    buffered_data: bytes = b''

    @GObject.Signal(arg_types=(object, int, int))
    def frame_received(self, frame: bytes, num_frame: int, total_frames: int):
        """One complete 0x7e-terminated pseudo-HDLC frame was received."""

    @GObject.Signal
    def initialized(self):
        if self.state == InputState.Initializing:
            self.state = InputState.Processing

    @GObject.Signal
    def closed(self):
        self.state = InputState.Closed

    @abstractmethod
    def send_raw(self, data: bytes):
        """Optional: write to the DIAG port (passive streams may no-op)."""

    @abstractmethod
    def close(self):
        pass

    def process_input(self, data: bytes):
        """Buffer a chunk of the stream and emit each complete frame.

        A frame is the bytes up to and including the next 0x7e trailer. The
        0x7e boundary is unambiguous because real 0x7e/0x7d bytes in the
        payload are byte-stuffed. A trailing partial frame stays buffered
        until the rest of it arrives on a later call.

        Returns the number of complete frames emitted.
        """

        self.buffered_data += data

        total_frames = self.buffered_data.count(TRAILER_CHAR)
        num_frame = 0

        while TRAILER_CHAR in self.buffered_data:
            payload, sep, self.buffered_data = self.buffered_data.partition(
                TRAILER_CHAR
            )
            num_frame += 1
            if not payload:
                # Empty frame (consecutive 0x7e); nothing to decode.
                continue
            self.frame_received.emit(payload + sep, num_frame, total_frames)

        return num_frame
