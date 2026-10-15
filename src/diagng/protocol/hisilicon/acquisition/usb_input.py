#!/usr/bin/env python3

"""
diagmond-backed USB acquisition for a HiSilicon / Kirin DIAG port.

The counterpart of
:class:`diagng.protocol.qualcomm.acquisition.usb_input.USBQCDMInput`: the
privileged ``diagmond`` daemon opens the USB interface and exposes it as a
D-Bus ``SerialDevice``; this input subscribes to its ``Read``/``Closed``
signals and feeds the bytes to ``process_input`` (framing lives in
:class:`~diagng.protocol.hisilicon.acquisition.base_input.BaseHisiInput`).

This is the path taken when diagmond is connected (the usual case). The
read-only, bus-less path is
:class:`~diagng.protocol.hisilicon.acquisition.pyusb_input.PyUSBHisiInput`.
"""

from logging import error, warning, debug

import gi

gi.require_version('Adw', '1')

from gi.repository import Gio, GLib, Adw

from diagng.protocol.hisilicon.acquisition.base_input import BaseHisiInput
from diagng.gobject.usb_interface import USBInterface
from diagng.gobject.usb_device import USBDevice

_connected_ports: dict[str, 'USBHisiInput'] = {}


class USBHisiInput(BaseHisiInput):
    dbus_serial_device: Gio.DBusProxy
    usb_dev: USBDevice
    usb_intf: USBInterface
    main_window: Adw.ApplicationWindow

    def __init__(
        self,
        dbus_serial_device: Gio.DBusProxy,
        usb_dev: USBDevice,
        usb_intf: USBInterface,
        main_window: Adw.ApplicationWindow,
    ):
        super().__init__()

        self.dbus_serial_device = dbus_serial_device
        self.usb_dev = usb_dev
        self.usb_intf = usb_intf
        self.main_window = main_window

        self.usb_intf.connected = True
        _connected_ports[usb_intf.full_intf_id] = self
        self.main_window.update_usb_devices()

        self.short_name = usb_intf.full_intf_id

        self._update_conn_state()

        self.usb_intf.connect('notify::connected', self._update_conn_state)
        self.dbus_serial_device.connect('g-signal::Read', self._on_read)
        self.dbus_serial_device.connect('g-signal::Closed', self._on_closed)

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

    def _on_read(
        self,
        dbus_proxy: Gio.DBusProxy,
        sender_name: str,
        signal_name: str,
        parameters: GLib.Variant,
    ):
        data = bytes(parameters[0])
        debug('Received data from HiSilicon USB interface: %r' % data)
        self.process_input(data)

    def _on_closed(
        self,
        dbus_proxy: Gio.DBusProxy,
        sender_name: str,
        signal_name: str,
        parameters: GLib.Variant,
    ):
        self.closed.emit()
        if self.usb_intf.full_intf_id in _connected_ports:
            del _connected_ports[self.usb_intf.full_intf_id]
        self.usb_intf.connected = False
        self.main_window.update_usb_devices()

        reason = str(parameters[0])
        warning('HiSilicon USB interface closed, reason: ' + reason)

    def send_raw(self, data: bytes):
        def write_cb(proxy, result, obj_path):
            if isinstance(result, Exception):
                error(
                    'Failed to write to HiSilicon USB interface: %r' % result
                )

        self.dbus_serial_device.Write('(ay)', data, result_handler=write_cb)

    def close(self):
        def close_cb(proxy, result, obj_path):
            self.closed.emit()
            if self.usb_intf.full_intf_id in _connected_ports:
                del _connected_ports[self.usb_intf.full_intf_id]
            self.usb_intf.connected = False
            self.main_window.update_usb_devices()

            if isinstance(result, Exception):
                error('Failed to close USB interface: %r' % result)

        self.dbus_serial_device.Close('()', result_handler=close_cb)
