# Building Nexus Manager

Use Linux or WSL, devkitPro devkitA64, CMake, Ninja, Make, Python 3 and Git. Install the Switch portlibs used by curl, zlib, minizip and mbedTLS, plus deko3d, uam and the usual Switch build tools. The SDK must support `NacpStruct.lang_data`; a pinned libnx source tree is included for that reason.

```sh
git clone --branch feature/smb-direct-mount https://github.com/nemerpus/Nexus-Manager-Source.git
cd Nexus-Manager-Source/app
export DEVKITPRO=/opt/devkitpro
sh tools/setup-libnx.sh
sh build-nexus-wsl.sh
```

`setup-libnx.sh` verifies and builds the pinned libnx source into `dependencies/sdk/libnx`. It also stages the installed deko3d headers and libraries separately. `build-nexus-wsl.sh` enables SMB and NFS, uses the vendored dependency revisions and builds version 0.2.28-smb.2 by default. Set `NEXUS_BUILD_JOBS` to control parallelism. The fork restores the upstream v1.5.7 zstd CMake files needed by the offline build.

The NRO is written to `app/build/NexusPorts/switch/nexusmanager/NexusManager.nro`. No console key is embedded in the default build. Keep raw USB mounting disabled: Nexus firmware owns the drive.

## NSP packaging

`app/tools/build-native-nsp.py --help` lists the packaging arguments. It requires the completed application build, a separately supplied packer and build tools, and an explicit local key-file path. Those external binaries and private inputs are not included. Do not commit keys or generated packages. The NRO build does not require NSP packaging.

## Tests

Use a host C++20 compiler and Python 3. The library import tests also link OpenSSL (`libssl-dev` on Debian/Ubuntu). Catalogue tests also need mbedTLS (`libmbedtls-dev`). Progress-layout tests also require FreeType and pkg-config (`libfreetype6-dev` and `pkg-config`):

```sh
python3 tests/run_ticket_snapshot_tests.py
python3 tests/run_progress_layout_tests.py
python3 tests/run_port_icon_cache_tests.py
python3 tests/run_port_library_tests.py
python3 tests/run_port_manager_tests.py
python3 tests/run_port_mod_import_tests.py
python3 tests/run_port_progress_ui_tests.py
python3 tests/run_file_manager_tests.py
python3 tests/run_file_manager_action_tests.py
python3 tests/run_pc_transfer_tests.py
python3 tests/run_transfer_cleanup_flow_tests.py
python3 tests/run_transfer_cache_guard_tests.py
python3 tests/run_library_details_tests.py
python3 tests/run_game_cleanup_tests.py
python3 tests/run_usb_import_repair_tests.py
python3 tests/run_usb_import_orchestration_tests.py
python3 tests/run_network_persistence_tests.py
python3 tests/run_network_shortcut_tests.py
```

Run these from `app/`. They exercise production logic with host fixtures; installing, moving, updating and sleep/wake behaviour still need Switch testing. Older PowerShell wrappers remain in the source for reference, but the Linux/WSL shell path above is the portable entry point.

## Repair catalogue and optional reporting

The bundled signed catalogue is included in RomFS. The public verification key is part of the source; the private signing key is not. The catalogue tools accept an explicitly supplied external signing key. See [catalogue tooling](app/tools/repair-catalog/README.md).

The default source build has empty report-server endpoints. It can use the public GitHub catalogue fallback and export diagnostics without a private deployment. To enable your own receiver, keep `nexus_report_endpoint.hpp` outside the checkout and set `NEXUS_REPORT_CONFIG_DIR` to that external directory. Define the HTTPS upload and catalogue URLs there; never put administrator credentials in the header or app. A URL compiled into an app is public, not an authentication secret. See [receiver setup and privacy](app/tools/report-server/README.md).

Additional checks for 0.2.28, run from `app/`:

```sh
python3 tools/verify-vendored-libnx.py
python3 tests/run_language_tests.py
python3 tests/run_language_catalog_tests.py
python3 tests/run_recovery_service_tests.py
python3 tests/run_move_resume_tests.py
python3 tests/run_repair_catalog_tests.py
python3 tests/run_catalog_cache_tests.py
python3 tests/run_repair_assistant_tests.py
python3 tests/run_report_service_tests.py
python3 tools/report-server/test_receiver.py
```

Tests cover catalogue signatures and rollback rejection, report consent and receipt handling, failed storage/network operations, recovery and translation packaging. They do not replace console testing.
