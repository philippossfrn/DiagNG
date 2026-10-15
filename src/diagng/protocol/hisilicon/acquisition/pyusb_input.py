#!/usr/bin/env python3

"""
USB acquisition for a HiSilicon / Kirin DIAG port.

Mirrors the Qualcomm ``PyUSBQCDMInput``
but for HiSilicon basebands and read-only: a background thread drains the
bulk IN endpoint and hands each chunk to ``process_input`` on the GLib main
loop, which splits it into frames (see
:class:`diagng.protocol.hisilicon.acquisition.base_input.BaseHisiInput`).

On a Kirin phone the port is reached without root by switching USB mode
(``adb shell svc usb setFunctions manufacture``), which re-enumerates the
device (``12d1:107e``) with vendor ACM interfaces; the DIAG interface is the
one that answers pseudo-HDLC framing. The modem's log stream still has to be
turned on by some other means — this class only reads whatever flows.
"""

from logging import error, debug
from traceback import format_exc
from threading import Thread

from usb.util import dispose_resources
from usb.core import Endpoint, Device

from gi.repository import GLib, Adw

from diagng.protocol.hisilicon.acquisition.base_input import BaseHisiInput
from diagng.gobject.usb_interface import USBInterface
from diagng.gobject.usb_device import USBDevice

_connected_ports: dict[str, 'PyUSBHisiInput'] = {}


class PyUSBHisiInput(BaseHisiInput):
    pyusb_device: Device
    in_endpoint: Endpoint
    out_endpoint: Endpoint

    usb_dev: USBDevice
    usb_intf: USBInterface
    main_window: Adw.ApplicationWindow

    def __init__(
        self,
        pyusb_device: Device,
        in_endpoint: Endpoint,
        out_endpoint: Endpoint,
        usb_dev: USBDevice,
        usb_intf: USBInterface,
        main_window: Adw.ApplicationWindow,
    ):
        super().__init__()

        self.pyusb_device = pyusb_device
        self.in_endpoint = in_endpoint
        self.out_endpoint = out_endpoint

        self.usb_dev = usb_dev
        self.usb_intf = usb_intf
        self.main_window = main_window

        self.usb_intf.connected = True
        _connected_ports[usb_intf.full_intf_id] = self
        self.main_window.update_usb_devices()

        self.short_name = usb_intf.full_intf_id

        self._update_conn_state()
        self.usb_intf.connect('notify::connected', self._update_conn_state)

        def read_thread():
            while True:
                try:
                    data = bytes(
                        in_endpoint.read(
                            in_endpoint.wMaxPacketSize or 0x200,
                            timeout=0x7FFFFFFF,
                        )
                    )
                except Exception:
                    error('Could not read from USB endpoint: ' + format_exc())
                    GLib.idle_add(self.close)
                    return
                debug('Received data from HiSilicon USB interface: %r' % data)
                GLib.idle_add(self.process_input, data)

        thread = Thread(target=read_thread)
        thread.daemon = True
        thread.start()

    def _update_conn_state(self, *args):
        full_name = ''

        if not self.usb_intf.connected:
            full_name += '(DISCONNECTED) - '

        full_name += '%s - ' % self.usb_intf.full_intf_id

        if self.usb_dev.alt_vendor_name:
            full_name += '%s %s - ' % (
                self.usb_dev.alt_vendor_name or '',
                self.usb_dev.alt_model_name or '',
            )

        full_name += '%s %s (%s)' % (
            self.usb_dev.vendor_name or '',
            self.usb_dev.model_name or '',
            self.usb_dev.vid_pid or '',
        )

        self.full_name = full_name

    def send_raw(self, data: bytes):
        """Write to the DIAG port.

        Not needed for passive capture, but the DIAG interface is
        bidirectional, so this is kept available for a future log-enable
        step. Failures are logged, not fatal to the read path.
        """

        def write_task():
            try:
                self.out_endpoint.write(data)
            except Exception:
                error(
                    'Failed to write to HiSilicon USB interface: '
                    + format_exc()
                )

        task = Thread(target=write_task)
        task.daemon = True
        task.start()

    def close(self):
        try:
            dispose_resources(self.pyusb_device)
        except Exception:
            error('Failed to close USB interface: ' + format_exc())

        self.closed.emit()
        if self.usb_intf.full_intf_id in _connected_ports:
            del _connected_ports[self.usb_intf.full_intf_id]
        self.usb_intf.connected = False
        self.main_window.update_usb_devices()
