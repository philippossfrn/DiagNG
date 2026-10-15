#!/usr/bin/env python3

"""
Capture window for a HiSilicon / Kirin DIAG stream.

The HiSilicon counterpart of :class:`diagng.ui.qcdm_window.imp.QCDMWindow`,
but much smaller: HiSilicon capture is passive (the modem emits logs; DiagNG
sends no QCDM-style log-config commands), so there is no log-selection UI,
no device-info query and no "raw diag" toggle — just the two capture sinks
(a live Wireshark instance and a PCAP file), each driven by a
:class:`~diagng.protocol.hisilicon.hisi_decoder.HisiOTADecoder` connected to
the input's ``frame_received`` signal.

The window is built in code rather than from a Blueprint template so it
needs no gresource regeneration.
"""

from logging import error
from typing import Optional

import gi

gi.require_version('Gtk', '4.0')
gi.require_version('Adw', '1')

from gi.repository import Adw, Gtk, Gio, GLib

from diagng.protocol.hisilicon.acquisition.base_input import BaseHisiInput
from diagng.protocol.hisilicon.hisi_decoder import HisiOTADecoder
from diagng.system.pcap_output import PcapOutput
from diagng.ui.qcdm_window.imp import InteractiveGUIFileOutModeSelector


class HisiWindow(Adw.Window):
    __gtype_name__ = 'HisiWindow'

    input_obj: BaseHisiInput
    parent: Adw.ApplicationWindow

    wireshark_instance: Optional[PcapOutput] = None
    output_pcap: Optional[PcapOutput] = None

    ws_decoder: Optional[HisiOTADecoder] = None
    pcap_decoder: Optional[HisiOTADecoder] = None

    def __init__(
        self,
        parent: Adw.ApplicationWindow,
        input_obj: BaseHisiInput,
    ):
        super().__init__()

        self.input_obj = input_obj
        self.parent = parent

        self.set_transient_for(parent)
        self.set_default_size(620, 360)
        self.set_title(self.input_obj.full_name or 'HiSilicon capture')

        self._build_ui()

        self.input_obj.connect('notify::full-name', self._on_title_change)
        self.connect('close-request', self._on_quit)

        self.present()

    # -- UI ---------------------------------------------------------------

    def _build_ui(self):
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())

        page = Adw.PreferencesPage()

        intro = Adw.PreferencesGroup()
        intro.set_description(
            'HiSilicon / Kirin capture is passive: DiagNG decodes the '
            'log stream the modem emits and converts it to GSMTAP. It does '
            'not enable logging on the modem, so frames only appear once '
            'the modem is already logging.'
        )
        page.add(intro)

        capture_group = Adw.PreferencesGroup()
        capture_group.set_title('Air logs capture')

        # --- Wireshark row ---
        self.ws_row = Adw.ActionRow()
        self.ws_row.set_title('View in a new Wireshark instance')

        self.start_ws_button = Gtk.Button(label='Start capture')
        self.start_ws_button.add_css_class('pill')
        self.start_ws_button.add_css_class('suggested-action')
        self.start_ws_button.set_valign(Gtk.Align.CENTER)
        self.start_ws_button.connect('clicked', self._start_ws_clicked)

        self.stop_ws_button = Gtk.Button(label='Stop capture')
        self.stop_ws_button.add_css_class('pill')
        self.stop_ws_button.add_css_class('destructive-action')
        self.stop_ws_button.set_valign(Gtk.Align.CENTER)
        self.stop_ws_button.set_visible(False)
        self.stop_ws_button.connect('clicked', self._stop_ws_clicked)

        self.ws_row.add_suffix(self.start_ws_button)
        self.ws_row.add_suffix(self.stop_ws_button)
        self.ws_row.set_activatable_widget(self.start_ws_button)
        capture_group.add(self.ws_row)

        # --- PCAP file row ---
        self.pcap_row = Adw.ActionRow()
        self.pcap_row.set_title('Save to a PCAP file')

        self.pick_pcap_button = Gtk.Button(label='Choose file…')
        self.pick_pcap_button.add_css_class('pill')
        self.pick_pcap_button.set_valign(Gtk.Align.CENTER)
        self.pick_pcap_button.connect('clicked', self._pick_pcap_clicked)

        self.stop_pcap_button = Gtk.Button(label='Stop capture')
        self.stop_pcap_button.add_css_class('pill')
        self.stop_pcap_button.add_css_class('destructive-action')
        self.stop_pcap_button.set_valign(Gtk.Align.CENTER)
        self.stop_pcap_button.set_visible(False)
        self.stop_pcap_button.connect('clicked', self._stop_pcap_clicked)

        self.pcap_row.add_suffix(self.pick_pcap_button)
        self.pcap_row.add_suffix(self.stop_pcap_button)
        self.pcap_row.set_activatable_widget(self.pick_pcap_button)
        capture_group.add(self.pcap_row)

        page.add(capture_group)
        toolbar.set_content(page)
        self.set_content(toolbar)

        if not self.parent.app.can_spawn_commands:
            # Wireshark needs to spawn an external process.
            self.ws_row.set_sensitive(False)
            self.ws_row.set_subtitle(
                'Unavailable: launching external programs is not allowed'
            )

    def _on_title_change(self, *args):
        self.set_title(self.input_obj.full_name or 'HiSilicon capture')

    # -- Wireshark capture ------------------------------------------------

    def _start_ws_clicked(self, target: Gtk.Button, *args):
        self.create_wireshark_pipe()
        self.start_ws_button.set_visible(False)
        self.stop_ws_button.set_visible(True)
        self.ws_row.set_activatable_widget(self.stop_ws_button)

    def _stop_ws_clicked(self, target: Gtk.Button, *args):
        if self.wireshark_instance:
            self.wireshark_instance.close()
            self.wireshark_instance = None

    def create_wireshark_pipe(self):
        assert not self.wireshark_instance

        self.wireshark_instance = PcapOutput(
            use_wireshark=True,
            window=self,
            can_spawn_commands=self.parent.app.can_spawn_commands,
        )

        def on_stream_closed(*args):
            self.start_ws_button.set_visible(True)
            self.stop_ws_button.set_visible(False)
            self.ws_row.set_activatable_widget(self.start_ws_button)
            self.wireshark_instance = None
            if self.ws_decoder:
                self.ws_decoder.disconnect()
                self.ws_decoder = None

        def on_stream_available(*args):
            self.ws_decoder = HisiOTADecoder(
                self.wireshark_instance, self.input_obj
            )

            def close_ws(*args):
                if self.wireshark_instance:
                    self.wireshark_instance.close()
                    self.wireshark_instance = None

            self.input_obj.closed.connect(close_ws)

        self.wireshark_instance.stream_closed.connect(on_stream_closed)
        self.wireshark_instance.stream_active.connect(on_stream_available)
        self.wireshark_instance.open_stream()

    # -- PCAP file capture ------------------------------------------------

    def _pick_pcap_clicked(self, target: Gtk.Button, *args):
        def file_picked(file_dialog: Gtk.FileDialog, task: Gio.Task):
            try:
                open_result: Gio.File = file_dialog.save_finish(task)
            except GLib.GError as err:
                if err.message != 'Dismissed by user':
                    dialog = Adw.AlertDialog.new(
                        'Could not open file', err.message
                    )
                    dialog.add_response('ok', 'Ok')
                    dialog.set_default_response('ok')
                    dialog.set_close_response('ok')
                    dialog.choose(self, None, None)
                return

            file_path = open_result.get_path()
            visible_file_path = file_path
            if visible_file_path.startswith('/run/user'):
                visible_file_path = visible_file_path.split('/').pop()
            self.pcap_row.set_subtitle('Writing to: ' + visible_file_path)

            self.pick_pcap_button.set_visible(False)
            self.stop_pcap_button.set_visible(True)
            self.pcap_row.set_activatable_widget(self.stop_pcap_button)

            self.create_pcap_pipe(open_result)

        file_picker = Gtk.FileDialog()
        file_picker.set_initial_name('output_file.pcap')
        file_picker.save(self, callback=file_picked)

    def _stop_pcap_clicked(self, target: Gtk.Button, *args):
        if self.output_pcap:
            self.output_pcap.close()
            self.output_pcap = None

    def create_pcap_pipe(self, output_file: Gio.File):
        assert not self.output_pcap

        self.output_pcap = PcapOutput(
            mode_selector=InteractiveGUIFileOutModeSelector(output_file, self),
            output_file=output_file,
            can_spawn_commands=self.parent.app.can_spawn_commands,
        )

        def on_stream_closed(*args):
            self.pick_pcap_button.set_visible(True)
            self.stop_pcap_button.set_visible(False)
            self.pcap_row.set_activatable_widget(self.pick_pcap_button)
            self.pcap_row.set_subtitle('')
            self.output_pcap = None
            if self.pcap_decoder:
                self.pcap_decoder.disconnect()
                self.pcap_decoder = None

        def on_stream_available(*args):
            self.pcap_decoder = HisiOTADecoder(
                self.output_pcap, self.input_obj
            )

            def close_pcap(*args):
                if self.output_pcap:
                    self.output_pcap.close()
                    self.output_pcap = None

            self.input_obj.closed.connect(close_pcap)

        self.output_pcap.stream_closed.connect(on_stream_closed)
        self.output_pcap.stream_active.connect(on_stream_available)
        self.output_pcap.open_stream()

    # -- lifecycle --------------------------------------------------------

    def _on_quit(self, *args):
        try:
            if self.wireshark_instance:
                self.wireshark_instance.close()
            if self.output_pcap:
                self.output_pcap.close()
            self.input_obj.close()
        except Exception:
            from traceback import format_exc

            error('HiSilicon: error while closing window: ' + format_exc())
