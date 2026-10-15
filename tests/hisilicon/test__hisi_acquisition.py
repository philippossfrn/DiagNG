#!/usr/bin/env python3

"""Tests for HiSilicon stream framing and input -> decoder wiring."""

from struct import pack

from diagng.protocol.hisilicon.acquisition.base_input import (
    BaseHisiInput,
    InputState,
)
from diagng.protocol.hisilicon.hisi_decoder import HisiOTADecoder
from diagng.protocol.hisilicon.hisi_log_parser import HisiCmd
from diagng.protocol.network.gsmtap_v2 import GsmtapV2
from diagng.protocol.qualcomm.utils.hdlc import hdlc_encode

PacketType = GsmtapV2.PacketType


class _FakeInput(BaseHisiInput):
    """Concrete BaseHisiInput with no transport, driven by hand."""

    def send_raw(self, data: bytes):
        pass

    def close(self):
        self.closed.emit()


class _FakePcap:
    """Records write_gsmtap_v2_packet calls instead of writing a file."""

    def __init__(self):
        self.calls = []

    def write_gsmtap_v2_packet(
        self, packet_type, sub_type, data, is_uplink=False, arfcn=0
    ):
        self.calls.append((packet_type, sub_type, data, is_uplink, arfcn))


def _lte_rrc_frame(chan: int = 0x01, rrc: bytes = b'\xde\xad') -> bytes:
    ota_hdr = pack('<LLLL', 0xAB, 1, 0, 0)
    body = ota_hdr + bytes([chan]) + rrc
    header = pack('<LQLLL', 0, 0, 0, HisiCmd.LTE_OTA_MSG, len(body))
    return hdlc_encode(b'\x00' + header + body)


# -- framing --------------------------------------------------------------


def test__process_input_emits_one_frame_per_trailer():
    inp = _FakeInput()
    frames = []
    inp.frame_received.connect(lambda o, f, n, t: frames.append((f, n, t)))

    f1 = _lte_rrc_frame()
    f2 = _lte_rrc_frame(chan=0x03)
    emitted = inp.process_input(f1 + f2)

    assert emitted == 2
    assert frames[0][0] == f1
    assert frames[1][0] == f2
    assert frames[0][2] == 2  # total_frames
    assert inp.buffered_data == b''


def test__process_input_reassembles_across_chunks():
    inp = _FakeInput()
    frames = []
    inp.frame_received.connect(lambda o, f, n, t: frames.append(f))

    frame = _lte_rrc_frame()
    split = len(frame) // 2

    assert inp.process_input(frame[:split]) == 0  # no trailer yet
    assert frames == []
    assert inp.process_input(frame[split:]) == 1
    assert frames == [frame]
    assert inp.buffered_data == b''


def test__empty_frames_are_skipped():
    inp = _FakeInput()
    frames = []
    inp.frame_received.connect(lambda o, f, n, t: frames.append(f))
    # Leading/trailing stray trailers around one real frame.
    frame = _lte_rrc_frame()
    inp.process_input(b'\x7e\x7e' + frame)
    assert frames == [frame]


# -- input -> decoder -> pcap wiring --------------------------------------


def test__decoder_consumes_frames_from_input():
    inp = _FakeInput()
    pcap = _FakePcap()
    decoder = HisiOTADecoder(pcap, input_obj=inp)

    # Deliver one LTE RRC frame in two chunks to also exercise reassembly.
    frame = _lte_rrc_frame(chan=0x01, rrc=b'\xca\xfe')
    mid = len(frame) // 2
    inp.process_input(frame[:mid])
    inp.process_input(frame[mid:])

    assert len(pcap.calls) == 1
    packet_type, sub_type, data, is_uplink, _arfcn = pcap.calls[0]
    assert packet_type == PacketType.lte_rrc
    assert sub_type.lte_rrc_subtype == GsmtapV2.LteRrcSubtype.dl_dcch
    assert data == b'\xca\xfe'
    assert is_uplink is False

    # After disconnect, further frames must not reach the decoder.
    decoder.disconnect()
    inp.process_input(_lte_rrc_frame())
    assert len(pcap.calls) == 1


def test__decoder_without_input_still_feeds_manually():
    pcap = _FakePcap()
    decoder = HisiOTADecoder(pcap)
    decoder.feed_frame(_lte_rrc_frame(chan=0x02, rrc=b'\x01\x02'))
    assert len(pcap.calls) == 1
    assert pcap.calls[0][0] == PacketType.lte_rrc
    assert pcap.calls[0][1].lte_rrc_subtype == GsmtapV2.LteRrcSubtype.ul_dcch


def test__close_sets_state_closed():
    inp = _FakeInput()
    assert inp.state == InputState.Initializing
    closed = []
    inp.closed.connect(lambda o: closed.append(True))
    inp.close()
    assert closed == [True]
    assert inp.state == InputState.Closed
