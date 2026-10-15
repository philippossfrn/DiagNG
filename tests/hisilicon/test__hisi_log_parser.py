#!/usr/bin/env python3

"""Unit tests for the HiSilicon / Kirin diagnostic log parser."""

from struct import pack

from diagng.protocol.hisilicon.hisi_log_parser import (
    HisiLogParser,
    HisiCmd,
)
from diagng.protocol.network.gsmtap_v2 import GsmtapV2
from diagng.protocol.qualcomm.utils.hdlc import hdlc_encode

PacketType = GsmtapV2.PacketType
LteRrcSubtype = GsmtapV2.LteRrcSubtype
UmtsRrcSubtype = GsmtapV2.UmtsRrcSubtype

_NESTED_MAGIC_1 = 0xAAAA5555
_NESTED_MAGIC_2 = 0x5555AAAA


def _flat_frame(cmd: int, body: bytes, ts: int = 0x1122334455667788) -> bytes:
    """Build a type-0x00 HiSilicon frame (HDLC-encoded)."""
    header = pack('<LQLLL', 0, ts, 0, cmd, len(body))
    return hdlc_encode(b'\x00' + header + body)


def _nested_frame(cmd: int, inner: bytes, ts: int = 0x42) -> bytes:
    """Build a type-0x01 nested HiSilicon frame (HDLC-encoded)."""
    nested_len2 = len(inner)
    nested_len1 = nested_len2 + 8
    header = pack(
        '<LLLHLHQ', 0, 0, _NESTED_MAGIC_1, nested_len1, cmd, nested_len2, ts
    )
    payload = b'\x01' + header + inner + pack('<L', _NESTED_MAGIC_2)
    return hdlc_encode(payload)


# -- LTE RRC --------------------------------------------------------------


def test__lte_rrc_dl_dcch():
    rrc_bytes = b'\xde\xad\xbe\xef\x01\x02'
    ota_hdr = pack('<LLLL', 0xAB, 1, 0, 0)  # chan_type=0xab (LTE RRC), DL
    content = b'\x01' + rrc_bytes  # channel 0x01 -> DL_DCCH
    frame = _flat_frame(HisiCmd.LTE_OTA_MSG, ota_hdr + content)

    parser = HisiLogParser()
    records = parser.parse_frame(frame)

    assert len(records) == 1
    rec = records[0]
    assert rec.packet_type == PacketType.lte_rrc
    assert rec.sub_type.lte_rrc_subtype == LteRrcSubtype.dl_dcch
    assert rec.data == rrc_bytes
    assert rec.is_uplink is False


def test__lte_rrc_channel_map():
    cases = {
        0x02: LteRrcSubtype.ul_dcch,
        0x03: LteRrcSubtype.dl_ccch,
        0x04: LteRrcSubtype.ul_ccch,
        0x05: LteRrcSubtype.pcch,
        0x06: LteRrcSubtype.bcch_dl_sch,
        0x07: LteRrcSubtype.bcch_bch,
    }
    parser = HisiLogParser()
    for chan, expected in cases.items():
        ota = pack('<LLLL', 0xAB, 1, 0, 0) + bytes([chan]) + b'\xaa\xbb'
        records = parser.parse_frame(_flat_frame(HisiCmd.LTE_OTA_MSG, ota))
        assert len(records) == 1, chan
        assert records[0].sub_type.lte_rrc_subtype == expected


def test__lte_rrc_uecapability_is_dropped():
    ota = pack('<LLLL', 0xAB, 1, 0, 0) + b'\x08' + b'\x00\x01'
    parser = HisiLogParser()
    assert parser.parse_frame(_flat_frame(HisiCmd.LTE_OTA_MSG, ota)) == []


# -- LTE NAS --------------------------------------------------------------


def test__lte_nas():
    nas_bytes = b'\x07\x41\x71\x08'
    ota = pack('<LLLL', 0xAD, 1, 0, 0) + nas_bytes
    parser = HisiLogParser()
    records = parser.parse_frame(_flat_frame(HisiCmd.LTE_OTA_MSG, ota))
    assert len(records) == 1
    assert records[0].packet_type == PacketType.lte_nas
    assert records[0].data == nas_bytes


# -- LTE cell info updates ARFCN state ------------------------------------


def test__lte_cell_info_sets_earfcn_for_following_rrc():
    # 32-byte cell-info tail: ul_earfcn, dl_earfcn, ul_freq, dl_freq,
    # ul_bw, dl_bw, band at [-32:-18]; pad the rest.
    cell_tail = pack('<HHHHHHH', 18100, 100, 0, 0, 50, 50, 1) + b'\x00' * 18
    body = b'\x00' * 8 + cell_tail
    parser = HisiLogParser()
    assert (
        parser.parse_frame(_flat_frame(HisiCmd.LTE_CURRENT_CELL_INFO, body))
        == []
    )
    assert parser.state.lte_earfcn_dl == 100
    assert parser.state.lte_earfcn_ul == 18100
    assert parser.state.lte_bw_dl == 10

    # A subsequent RRC record should carry the DL EARFCN as the ARFCN.
    ota = pack('<LLLL', 0xAB, 1, 0, 0) + b'\x03' + b'\x11\x22'
    rec = parser.parse_frame(_flat_frame(HisiCmd.LTE_OTA_MSG, ota))[0]
    assert rec.arfcn == 100


# -- WCDMA RRC (nested) ---------------------------------------------------


def test__wcdma_rrc_dl_dcch():
    rrc = b'\x00\x11\x22\x33'
    # inner: 0x22, then <L B B B L B> header, chan at offset 12
    inner = b'\x22' + pack('<LBBBLB', 0, 0, 0, 0, len(rrc), 0x03) + rrc
    parser = HisiLogParser()
    records = parser.parse_frame(_nested_frame(HisiCmd.NESTED_L3_OTA, inner))
    assert len(records) == 1
    assert records[0].packet_type == PacketType.umts_rrc
    assert (
        records[0].sub_type.umts_rrc_subtype == UmtsRrcSubtype.dl_dcch_message
    )
    assert records[0].data == rrc


def test__wcdma_rrc_mib():
    inner = b'\x22' + pack('<LBBBLB', 0, 0, 0, 0, 2, 0x0D) + b'\xca\xfe'
    parser = HisiLogParser()
    rec = parser.parse_frame(_nested_frame(HisiCmd.NESTED_L3_OTA, inner))[0]
    assert rec.sub_type.umts_rrc_subtype == (
        UmtsRrcSubtype.master_information_block
    )


# -- GSM / Abis (nested) --------------------------------------------------


def test__gsm_abis_l3():
    l3 = b'\x06\x1b\x00'  # RR, pd 0b0110
    # type 0x25: <H B B B B B L>, msg at offset 12
    inner = b'\x25' + pack('<HBBBBBL', 0, 0, 0, 0, 0, 0, len(l3)) + l3
    parser = HisiLogParser()
    records = parser.parse_frame(_nested_frame(HisiCmd.NESTED_L3_OTA, inner))
    assert len(records) == 1
    assert records[0].packet_type == PacketType.abis
    assert records[0].data == l3


# -- framing / robustness -------------------------------------------------


def test__bad_crc_is_ignored():
    frame = bytearray(
        _flat_frame(
            HisiCmd.LTE_OTA_MSG, pack('<LLLL', 0xAB, 1, 0, 0) + b'\x03x'
        )
    )
    frame[1] ^= 0xFF  # corrupt a payload byte -> CRC mismatch
    parser = HisiLogParser()
    assert parser.parse_frame(bytes(frame)) == []


def test__unknown_cmd_returns_empty():
    parser = HisiLogParser()
    assert parser.parse_frame(_flat_frame(0xDEADBEEF, b'\x00' * 4)) == []


def test__truncated_frame_does_not_raise():
    parser = HisiLogParser()
    assert parser.parse_frame(hdlc_encode(b'\x00\x01\x02')) == []
    assert parser.parse_frame(hdlc_encode(b'\x01\x02')) == []
    assert parser.parse_frame(b'') == []


def test__parse_stream_handles_multiple_and_partial_frames():
    ota = pack('<LLLL', 0xAB, 1, 0, 0) + b'\x03' + b'\x11\x22'
    f1 = _flat_frame(HisiCmd.LTE_OTA_MSG, ota)
    f2 = _flat_frame(HisiCmd.LTE_OTA_MSG, ota)
    parser = HisiLogParser()
    # Two whole frames plus a trailing partial (no 0x7e) which is dropped.
    stream = f1 + f2 + b'\x00\x01\x02'
    records = parser.parse_stream(stream)
    assert len(records) == 2
    assert all(r.packet_type == PacketType.lte_rrc for r in records)


def test__debug_msgs_off_by_default():
    body = b'\x00' * 8
    parser = HisiLogParser()
    assert parser.parse_frame(_flat_frame(HisiCmd.NORM_DEBUG_MSG, body)) == []

    parser_on = HisiLogParser(emit_debug_msgs=True)
    records = parser_on.parse_frame(_flat_frame(HisiCmd.NORM_DEBUG_MSG, body))
    assert len(records) == 1
    assert records[0].packet_type == PacketType.osmocore_log


# -- the subtype field objects must serialize through GSMTAP v2 -----------


def test__records_serialize_as_valid_gsmtap_v2():
    """Each record's sub_type must be writable by GsmtapV2 (the real path
    PcapOutput.write_gsmtap_v2_packet takes)."""
    from io import BytesIO
    from kaitaistruct import KaitaiStream

    KaitaiStream._ensure_bytes_left_to_write = lambda *args: True

    ota = pack('<LLLL', 0xAB, 1, 0, 0) + b'\x01' + b'\xde\xad'
    rec = HisiLogParser().parse_frame(_flat_frame(HisiCmd.LTE_OTA_MSG, ota))[0]

    content = GsmtapV2()
    content.header_len = 4
    content.type = rec.packet_type
    content.timeslot = 0
    content.pcs_band = False
    content.is_uplink = rec.is_uplink
    content.arfcn = rec.arfcn
    content.signal_dbm = 0
    content.snr_db = 0
    content.frame_number = 0
    rec.sub_type._parent = content
    rec.sub_type._root = content._root
    rec.sub_type._check()
    content.sub_type = rec.sub_type
    content.antenna_nr = 0
    content.sub_slot = 0
    content.res = 0
    content.data = rec.data
    content._check()

    buf = BytesIO()
    content._write(KaitaiStream(buf))
    out = buf.getvalue()
    # header_len, type byte, and the RRC bytes must be present
    assert out[0] == 4
    assert out[1] == int(PacketType.lte_rrc)
    assert out.endswith(b'\xde\xad')
