#!/usr/bin/env python3

"""
Recognise a HiSilicon / Kirin DIAG USB interface.

DiagNG's USB scan (``diagng.utils.usb_port_detecter.detect_diag_usb_ports``)
keeps only interfaces whose class/subclass/protocol match a known DIAG
signature. Qualcomm DIAG ports are ``255/255/48`` or ``255/255/255``;
HiSilicon/Kirin ports do not use those, so without the checks here a Kirin
DIAG port never appears in the UI.

Observed on a Huawei Mate 20 Lite (Kirin 710) after
``adb shell svc usb setFunctions manufacture``: the device re-enumerates as
``12d1:107e`` with three vendor ACM interfaces, ``255/19/33`` (modem/AT),
``255/19/34`` and ``255/19/35``. The ``255/19/35`` interface is the one that
answers pseudo-HDLC framing — the DIAG port — and each carries two bulk
endpoints.

These helpers are pure so they can be unit-tested and reused by the scanner
and the connect handler.
"""

HUAWEI_VID = 0x12D1

# text_interface strings ("class/subclass/protocol") of Kirin DIAG ports.
HISI_DIAG_INTERFACES = frozenset({'255/19/35'})

# Baseband tags stored on USBInterface.baseband.
BASEBAND_QUALCOMM = 'qualcomm'
BASEBAND_HISILICON = 'hisilicon'

# Qualcomm DIAG signatures, kept here so the scanner has one source of truth.
QUALCOMM_DIAG_INTERFACES = frozenset({'255/255/48', '255/255/255'})


def _vid_of(vid_pid: str) -> int:
    """Parse the vendor id from a 'vvvv:pppp' hex string, -1 on failure."""
    try:
        return int(vid_pid.split(':')[0], 16)
    except (ValueError, AttributeError, IndexError):
        return -1


def is_hisi_diag_interface(
    vid_pid: str, text_interface: str, num_endpoints: int
) -> bool:
    """True if this interface is a HiSilicon/Kirin DIAG port."""
    return (
        _vid_of(vid_pid) == HUAWEI_VID
        and text_interface in HISI_DIAG_INTERFACES
        and num_endpoints == 2
    )


def classify_diag_interface(
    vid_pid: str, text_interface: str, num_endpoints: int
):
    """Return the baseband tag for a DIAG interface, or None to skip it.

    This is the single decision the scanner makes per interface: whether to
    surface it and, if so, which connect path it belongs to.
    """
    if num_endpoints != 2:
        return None
    if text_interface in QUALCOMM_DIAG_INTERFACES:
        return BASEBAND_QUALCOMM
    if is_hisi_diag_interface(vid_pid, text_interface, num_endpoints):
        return BASEBAND_HISILICON
    return None
