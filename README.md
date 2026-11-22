# Nexus Manager

## SMB direct mount fork · 0.2.28-smb.3

Saved network locations can open a specific directory inside a share. Highlight a saved location, press X, choose **Edit connection**, change **Starting folder** and save. Existing locations open at the root by default.

To check an installed resident provider after HOME starts, open **SMB / NFS → Mounted SMB image**. When prompted, Manager asks Horizon to launch the provider and waits for its IPC response. The diagnostic log in `switch/nexusmanager/nexus.log` records the launch result separately from the service handshake. Opening an XCI also requests the provider when necessary. A working firmware bridge is still required to register or play a mounted title.

In File manager, open an SMB share, select an uncompressed XCI and choose **Mount XCI from SMB**. The resident service opens the selected file read-only and keeps its connection when Manager exits. Manager compares ranges from both connections, checks game metadata, and offers HOME registration for eligible titles. Registration uses the existing Nexus content, ownership and ticket checks. If a restart is requested, mount the same XCI again before opening the game from HOME.

Direct mount requires the **mt:store v1** persistent image service and the matching **ams:usb SMB bridge** in the running firmware. The application packages contain Manager only. The v1 service supports one uncompressed XCI, a share-local account or guest access, and one external medium at a time. To change images or return to USB, close the game and choose **SMB / NFS → Mounted SMB image → Unmount**. Use the ordinary network installation workflow for NSP, NSZ, XCZ, NFS or SMB domain accounts.

The application builds with the existing NRO location and native NSP title ID. Installing either build in place replaces that copy of Manager. The upstream updater still serves upstream releases. The combined application archive contains the NRO and the standalone NSP. Hekate, boot assets and firmware are installed independently.

Nexus Manager is the Switch app for managing games across SD and USB storage. It provides game installation and moves, USB library import and repair, a file manager, network installation over SMB/NFS, and app updates.

The upstream 0.2.28 application and original release binaries are available from [Nexus Manager releases](https://github.com/TechRepairs4U/Nexus-Manager/releases/tag/v0.2.28).

## What's new since 0.2.24

- Switch system-language detection and a language selector, with translations throughout the interface.
- Guided USB repair with a read-only preview, explicit confirmation and results grouped by game, update and DLC.
- Checked USB map backup to console storage. Backup results are reported separately from repair results.
- Durable checkpoints and revalidation when recovering an interrupted move.
- Signed repair guidance, a checked local cache and an offline fallback. Guidance cannot run code, change arbitrary paths or bypass content validation.
- Report a problem and optional automatic failure reports. Reporting asks for consent, filters diagnostic fields and waits until Manager is idle to upload.

Reports exclude raw logs, credentials, tickets, saves and game files. A matching server receipt is saved before a queued report is removed. Users can disable reporting or discard queued reports. The public build leaves server uploads disabled; deployment configuration belongs outside this repository.

Existing features include port management, icon caching, mod folders and ZIPs, File manager copy/move/delete, FTP and NAS stream installs, cleanup and app updates. Repairs cannot replace missing game files or tickets. Saved progress remains separate from game-content deletion.

The application build and automated checks passed. Version 0.2.28 still needs wider testing on consoles, drives and network servers. Please report the steps to reproduce a problem and a diagnostic report when available, without including private files.

## Getting started

- [Build instructions](BUILDING.md)
- [Contributing](CONTRIBUTING.md) - help building the app, testing it and improving the interface is welcome.
- [App downloads](https://github.com/TechRepairs4U/Nexus-Manager/releases)
- [Nexus Atmosphere source](https://github.com/TR4UNEXUS/Nexus-Atmosphere)
- [USB firmware integration](https://github.com/TR4UNEXUS/Nexus-USB-Firmware)

The application is in `app/`. Most Nexus features are under `app/sphaira/source/nexus`; the interface is under `app/sphaira/source/ui`. Host tests are in `app/tests`. SDK source is under `dependencies/`; compiled SDK libraries are generated locally. Generic catalogue-signing and report-receiver tools are in `app/tools/repair-catalog` and `app/tools/report-server`.

USB features require matching Nexus firmware. Manager uses the shared firmware service so two raw USB drivers do not try to own the same drive. The updater uses the existing Manager release repository; this repository is for development.

## Credits and licence

Nexus Manager is based on Sphaira and retains its GPL licence and dependency notices. Read [the source attribution](app/ATTRIBUTION.md), [LICENSE](LICENSE) and [dependency revisions](app/DEPENDENCIES.json). Source names inherited from upstream are kept where they are part of the implementation.
