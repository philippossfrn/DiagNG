#!/usr/bin/env python3

"""Tests for HiSilicon/Kirin DIAG USB interface detection."""

from diagng.protocol.hisilicon.hisi_usb_detect import (
    is_hisi_diag_interface,
    classify_diag_interface,
    BASEBAND_QUALCOMM,
    BASEBAND_HISILICON,
)


def test__kirin_diag_interface_is_detected():
    # Mate 20 Lite DIAG port in manufacture mode.
    assert is_hisi_diag_interface('12d1:107e', '255/19/35', 2) is True


def test__kirin_modem_and_other_vendor_interfaces_are_not_diag():
    # 255/19/33 is the modem/AT port, 255/19/34 the middle ACM channel.
    assert is_hisi_diag_interface('12d1:107e', '255/19/33', 2) is False
    assert is_hisi_diag_interface('12d1:107e', '255/19/34', 2) is False


def test__non_huawei_vendor_is_not_kirin_diag():
    assert is_hisi_diag_interface('05c6:9091', '255/19/35', 2) is False


def test__wrong_endpoint_count_rejected():
    assert is_hisi_diag_interface('12d1:107e', '255/19/35', 1) is False
    assert is_hisi_diag_interface('12d1:107e', '255/19/35', 3) is False


def test__classify_tags_qualcomm_and_hisilicon():
    assert (
        classify_diag_interface('05c6:9091', '255/255/48', 2)
        == BASEBAND_QUALCOMM
    )
    assert (
        classify_diag_interface('05c6:9091', '255/255/255', 2)
        == BASEBAND_QUALCOMM
    )
    assert (
        classify_diag_interface('12d1:107e', '255/19/35', 2)
        == BASEBAND_HISILICON
    )


def test__classify_skips_unknown_interfaces():
    assert classify_diag_interface('12d1:107e', '255/19/33', 2) is None
    assert classify_diag_interface('1234:5678', '14/2/0', 2) is None
    # Right signature, wrong endpoint count -> skipped.
    assert classify_diag_interface('05c6:9091', '255/255/48', 1) is None


def test__malformed_vid_pid_is_safe():
    assert is_hisi_diag_interface('', '255/19/35', 2) is False
    assert classify_diag_interface('nothex', '255/19/35', 2) is None
