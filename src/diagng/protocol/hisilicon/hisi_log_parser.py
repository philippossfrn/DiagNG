#!/usr/bin/env python3

"""
HiSilicon / Kirin (Balong modem) diagnostic log parser.

Ported and adapted from SCAT's HiSilicon parser
(https://github.com/fgsect/scat, handymenny/scat `dev` branch) to fit
DiagNG's GObject/Kaitai structure and GSMTAP output path.

Unlike the Qualcomm QCDM flow, the HiSilicon DIAG port does not use the
Qualcomm command set and SCAT does not send any "enable logging" commands:
its HiSilicon support is purely *passive*. The modem emits pseudo-HDLC
framed log records (same 0x7e trailer, same byte-stuffing and CCITT CRC-16
as Qualcomm, so :mod:`diagng.protocol.qualcomm.utils.hdlc` is reused) and
this parser turns the records we understand into GSMTAP packets.

Two outer record layouts are seen on the wire, keyed by the first byte of
the decoded payload:

- ``0x00`` — a flat log record::

      u8  type (== 0x00)
      u32 unk2
      u64 timestamp
      u32 unk3
      u32 cmd           <- dispatch key
      u32 length        <- length of the trailing payload
      ...payload...

- ``0x01`` — a nested record wrapped in magic markers
  ``0xaaaa5555`` ... ``0x5555aaaa``::

      u8  type (== 0x01)
      u32 unk1
      u32 unk2
      u32 magic (== 0xaaaa5555)
      u16 nested_len1
      u32 cmd           <- dispatch key
      u16 nested_len2   (== nested_len1 - 8)
      u64 timestamp
      ...payload...
      u32 magic2 (== 0x5555aaaa)

The ``cmd`` field selects a handler. Each handler returns zero or more
:class:`GsmtapRecord` describing a GSMTAP v2 packet to emit; the caller
(:class:`~diagng.protocol.hisilicon.hisi_decoder.HisiOTADecoder`) feeds
these to :class:`~diagng.system.pcap_output.PcapOutput`.
"""

from collections import namedtuple
from dataclasses import dataclass
from logging import warning, debug
from struct import unpack, error as StructError

from diagng.protocol.network.gsmtap_v2 import GsmtapV2
from diagng.protocol.qualcomm.utils.hdlc import hdlc_decode, TRAILER_CHAR

PacketType = GsmtapV2.PacketType
LteRrcSubtype = GsmtapV2.LteRrcSubtype
UmtsRrcSubtype = GsmtapV2.UmtsRrcSubtype
GsmRrSubtype = GsmtapV2.GsmRrSubtype


# A decoded unit of work, ready to hand to PcapOutput.write_gsmtap_v2_packet.
# `sub_type` is either a built GsmtapV2 *SubtypeField or a plain int, matching
# the Union that write_gsmtap_v2_packet accepts.
GsmtapRecord = namedtuple(
    'GsmtapRecord',
    ['packet_type', 'sub_type', 'data', 'is_uplink', 'arfcn'],
)


# HiSilicon command codes (dispatch keys) understood by the parser.
class HisiCmd:
    # Flat (type 0x00) records
    LTE_CURRENT_CELL_INFO = 0x10051082
    LTE_OTA_MSG = 0x20010000
    LTE_MEAS = 0x20020000
    SSRC_DEBUG_MSG = 0x20030000
    NORM_DEBUG_MSG = 0x30940001
    # Nested (type 0x01) records
    NESTED_L3_OTA = 0x00020101
    NESTED_DEBUG_MSG = 0xFD010101


_NESTED_MAGIC_1 = 0xAAAA5555
_NESTED_MAGIC_2 = 0x5555AAAA

# HiSilicon LTE RRC channel byte -> DiagNG GSMTAP LTE RRC subtype.
_LTE_RRC_CHAN_MAP = {
    0x01: LteRrcSubtype.dl_dcch,
    0x02: LteRrcSubtype.ul_dcch,
    0x03: LteRrcSubtype.dl_ccch,
    0x04: LteRrcSubtype.ul_ccch,
    0x05: LteRrcSubtype.pcch,
    0x06: LteRrcSubtype.bcch_dl_sch,
    0x07: LteRrcSubtype.bcch_bch,
}

# HiSilicon WCDMA RRC channel byte -> DiagNG GSMTAP UMTS RRC subtype.
_WCDMA_RRC_CHAN_MAP = {
    0x02: UmtsRrcSubtype.dl_ccch_message,
    0x03: UmtsRrcSubtype.dl_dcch_message,
    0x08: UmtsRrcSubtype.ul_ccch_message,
    0x09: UmtsRrcSubtype.ul_dcch_message,
    0x0D: UmtsRrcSubtype.master_information_block,
    0x0E: UmtsRrcSubtype.sys_info_type_sb1,
    0x10: UmtsRrcSubtype.sys_info_type1,
    0x11: UmtsRrcSubtype.sys_info_type2,
    0x12: UmtsRrcSubtype.sys_info_type3,
    0x14: UmtsRrcSubtype.sys_info_type5,
    0x16: UmtsRrcSubtype.sys_info_type7,
    0x1A: UmtsRrcSubtype.sys_info_type11,
    0x1C: UmtsRrcSubtype.sys_info_type12,
    0x2D: UmtsRrcSubtype.sys_info_type19,
}

_NRB_TO_BW_MHZ = {0: 0, 6: 1.4, 15: 3, 25: 5, 50: 10, 75: 15, 100: 20}


def _lte_rrc_field(subtype: 'GsmtapV2.LteRrcSubtype'):
    field_obj = GsmtapV2.LteRrcSubtypeField()
    field_obj.lte_rrc_subtype = subtype
    return field_obj


def _umts_rrc_field(subtype: 'GsmtapV2.UmtsRrcSubtype'):
    field_obj = GsmtapV2.UmtsRrcSubtypeField()
    field_obj.umts_rrc_subtype = subtype
    return field_obj


def _gsm_rr_field(subtype: 'GsmtapV2.GsmRrSubtype'):
    field_obj = GsmtapV2.GsmRrSubtypeField()
    field_obj.gsm_rr_subtype = subtype
    return field_obj


@dataclass
class HisiRadioState:
    """Running per-radio context the OTA handlers need (e.g. ARFCN)."""

    lte_earfcn_dl: int = 0
    lte_earfcn_ul: int = 0
    lte_bw_dl: float = 0
    lte_bw_ul: float = 0
    lte_band: int = 0


# Flat log header: everything after the 0x00 type byte, 24 bytes.
_LogHeader = namedtuple('HisiLogHeader', 'unk2 ts unk3 cmd length')
# Nested log header: everything after the 0x01 type byte, 28 bytes.
_NestedHeader = namedtuple(
    'HisiNestedHeader', 'unk1 unk2 magic nested_len1 cmd nested_len2 ts'
)


class HisiLogParser:
    """Stateful decoder from raw HiSilicon frames to GSMTAP records."""

    def __init__(self, emit_debug_msgs: bool = False):
        self.state = HisiRadioState()
        self.emit_debug_msgs = emit_debug_msgs

        self._flat_handlers = {
            HisiCmd.LTE_OTA_MSG: self._lte_ota_msg,
            HisiCmd.LTE_CURRENT_CELL_INFO: self._lte_current_cell_info,
            HisiCmd.NORM_DEBUG_MSG: self._debug_msg,
            HisiCmd.SSRC_DEBUG_MSG: self._debug_msg,
        }
        self._nested_handlers = {
            HisiCmd.NESTED_L3_OTA: self._l3_ota,
        }

    # -- framing -----------------------------------------------------------

    def parse_frame(
        self, frame: bytes, hdlc_encoded: bool = True
    ) -> list[GsmtapRecord]:
        """Decode a single HiSilicon frame into GSMTAP records.

        `frame` is one pseudo-HDLC frame (payload + CRC + 0x7e trailer)
        when `hdlc_encoded` is True, or an already-decoded payload
        otherwise. Returns an empty list for records we do not handle or
        cannot parse; parsing never raises on malformed input.
        """

        if hdlc_encoded:
            try:
                payload = hdlc_decode(frame)
            except AssertionError:
                warning('HiSilicon: bad HDLC frame or CRC: %r' % frame)
                return []
        else:
            payload = frame

        if len(payload) < 1:
            return []

        try:
            return self._dispatch(payload)
        except (StructError, IndexError, KeyError, ValueError):
            from traceback import format_exc

            warning('HiSilicon: failed to parse record: ' + format_exc())
            return []

    def parse_stream(self, data: bytes) -> list[GsmtapRecord]:
        """Split a byte stream on 0x7e and parse each complete frame.

        Returns the records for every complete frame found. A trailing
        partial frame (no terminating 0x7e) is dropped; callers that need
        to keep it across reads should buffer at the transport layer.
        """

        records: list[GsmtapRecord] = []
        for atom in data.split(TRAILER_CHAR):
            if not atom:
                continue
            records += self.parse_frame(atom + TRAILER_CHAR)
        return records

    def _dispatch(self, payload: bytes) -> list[GsmtapRecord]:
        kind = payload[0]

        if kind == 0x00:
            if len(payload) < 25:
                return []
            header = _LogHeader._make(unpack('<LQLLL', payload[1:25]))
            body = payload[25:]
            if header.length != len(body):
                debug(
                    'HiSilicon: flat length mismatch cmd=%#010x '
                    'expected=%d got=%d'
                    % (header.cmd, header.length, len(body))
                )
            handler = self._flat_handlers.get(header.cmd)
            return handler(header, body) if handler else []

        if kind == 0x01:
            if len(payload) < 29:
                return []
            header = _NestedHeader._make(unpack('<LLLHLHQ', payload[1:29]))
            body = payload[29:-4]
            magic_2 = unpack('<L', payload[-4:])[0]
            if header.magic != _NESTED_MAGIC_1 or magic_2 != _NESTED_MAGIC_2:
                debug('HiSilicon: nested magic mismatch, skipping')
                return []
            handler = self._nested_handlers.get(header.cmd)
            return handler(header, body) if handler else []

        debug('HiSilicon: unknown record type %#04x' % kind)
        return []

    # -- flat (0x00) handlers ---------------------------------------------

    def _lte_ota_msg(self, header, body: bytes) -> list[GsmtapRecord]:
        if len(body) < 16:
            return []
        # chan_type, direction, unk2, unk3
        chan_type = unpack('<L', body[0:4])[0]
        content = body[16:]

        if chan_type == 0xAB:
            # LTE RRC: first content byte is the HiSilicon channel id
            if len(content) < 1:
                return []
            rrc_chan = content[0]
            rrc_body = content[1:]
            if rrc_chan == 0x08:
                warning(
                    'HiSilicon: ignoring EUTRA UECapability '
                    '(GSMTAP cannot encapsulate it)'
                )
                return []
            subtype = _LTE_RRC_CHAN_MAP.get(rrc_chan)
            if subtype is None:
                warning('HiSilicon: unknown LTE RRC channel %#x' % rrc_chan)
                return []
            return [
                GsmtapRecord(
                    PacketType.lte_rrc,
                    _lte_rrc_field(subtype),
                    rrc_body,
                    False,
                    self.state.lte_earfcn_dl,
                )
            ]

        if chan_type in (0xAD, 0xAE):
            # NAS-EPS (EMM/ESM); GSMTAP LTE_NAS carries it verbatim
            return [GsmtapRecord(PacketType.lte_nas, 0, content, False, 0)]

        warning('HiSilicon: unknown LTE OTA channel type %#x' % chan_type)
        return []

    def _lte_current_cell_info(
        self, header, body: bytes
    ) -> list[GsmtapRecord]:
        # Trailing cell-info block: ul/dl EARFCN, ul/dl freq, ul/dl bw, band
        if len(body) < 32:
            return []
        (
            ul_earfcn,
            dl_earfcn,
            _ul_freq,
            _dl_freq,
            ul_bw,
            dl_bw,
            band,
        ) = unpack('<HHHHHHH', body[-32:-18])

        self.state.lte_earfcn_ul = ul_earfcn
        self.state.lte_earfcn_dl = dl_earfcn
        self.state.lte_bw_ul = _NRB_TO_BW_MHZ.get(ul_bw, 0)
        self.state.lte_bw_dl = _NRB_TO_BW_MHZ.get(dl_bw, 0)
        self.state.lte_band = band

        debug(
            'HiSilicon: LTE cell EARFCN %d/%d, BW %s/%s MHz, Band %d'
            % (
                dl_earfcn,
                ul_earfcn,
                self.state.lte_bw_dl,
                self.state.lte_bw_ul,
                band,
            )
        )
        # State-only update; no GSMTAP packet to emit.
        return []

    def _debug_msg(self, header, body: bytes) -> list[GsmtapRecord]:
        if not self.emit_debug_msgs:
            return []
        if header.cmd == HisiCmd.SSRC_DEBUG_MSG:
            body = body[12:]
        return [GsmtapRecord(PacketType.osmocore_log, 0, body, False, 0)]

    # -- nested (0x01) handlers -------------------------------------------

    def _l3_ota(self, header, body: bytes) -> list[GsmtapRecord]:
        if len(body) < 1:
            return []
        l3_type = body[0]

        if l3_type == 0x22:
            # WCDMA RRC: header <L B B B L B>, content follows at offset 13
            if len(body) < 13:
                return []
            chan = body[12]
            content = body[13:]
            subtype = _WCDMA_RRC_CHAN_MAP.get(chan)
            if subtype is None:
                warning('HiSilicon: unknown WCDMA RRC channel %#04x' % chan)
                return []
            return [
                GsmtapRecord(
                    PacketType.umts_rrc,
                    _umts_rrc_field(subtype),
                    content,
                    False,
                    0,
                )
            ]

        if l3_type == 0x03:
            # GSM/Abis L3: header <H B B B B B L L>, len2 bytes of payload
            if len(body) < 16:
                return []
            len1, len2 = unpack('<LL', body[8:16])
            data = body[16:]
            if len2 + 4 != len1:
                debug(
                    'HiSilicon: Abis length mismatch len1=%d len2=%d'
                    % (len1, len2)
                )
            return [
                GsmtapRecord(
                    PacketType.abis,
                    _gsm_rr_field(GsmRrSubtype.unknown),
                    data[:len2],
                    False,
                    0,
                )
            ]

        if l3_type == 0x25:
            # GSM L3 over Um/Abis: header <H B B B B B L>
            if len(body) < 12:
                return []
            msg_len = unpack('<L', body[8:12])[0]
            ota = body[12:]
            if len(ota) < 1:
                return []
            # 0b0110 == GSM RR protocol discriminator -> treat as Abis
            if (ota[0] & 0x0F) == 0b0110:
                return [
                    GsmtapRecord(
                        PacketType.abis,
                        _gsm_rr_field(GsmRrSubtype.unknown),
                        ota[:msg_len],
                        False,
                        0,
                    )
                ]
            warning(
                'HiSilicon: GSM L3 with non-RR/short-PD discriminator, '
                'skipping'
            )
            return []

        warning('HiSilicon: unknown L3 OTA type %#04x' % l3_type)
        return []
