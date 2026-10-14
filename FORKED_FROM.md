# Source provenance and license notices

Derived from [aw-watcher-window](https://github.com/ActivityWatch/aw-watcher-window) at commit
`624823a7cb00dc2c2e090bdae793bc97ba752d2c`.

Reconciled with upstream `master` at
`6d58cef32808ccf9b53d3e3294e94bcb1fbfcb3c`, retaining the serial macOS retry queue,
lazy bucket creation, accessibility lifetime fixes, and research/config updates.

The original authors retain their copyright and attribution. The upstream
[Mozilla Public License 2.0](LICENSE.txt) and existing file notices are
preserved; modifications to covered files remain under MPL-2.0. Provide the
corresponding covered source and notices when distributing these modifications,
as required by that license.

PeakActivity application identity in the macOS accessibility prompt, renewable local capture credentials, and source-specific capture consent before window events are sent.

Use the matching PeakActivity aw-client source selected by the source graph. An independently installed client version is not an equivalent build input.

The read-only source checks use public [aw-client](https://github.com/ahmetcemkaraca/aw-client)
at `e4b947cc03d886d18318d670e4756f449aaa270c`. Release publishing and security-event
writes are outside this collector workflow.

PeakActivity is an independent project and is not affiliated with or endorsed by
the upstream authors. Release-specific source locations, revisions, notices and
publisher information must be recorded before distribution.
