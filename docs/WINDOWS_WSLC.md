# Windows Hidden and WSLC — operator boundary

The MCP host is Windows-native. Generic UIA and the separately pinned official
Makepad71 App Remote adapter are distinct backends. WidgetId, AutomationId,
SessionId, guest PID/WindowId and Windows PID/HWND are separate namespaces.

Build the host with experimental-makepad-remote. Start with the five-tool
read-only example and exact executable SHA. A trusted operator owns profiles,
source/build receipts, actual target identities and the two routing env values.
Templates with zero hashes cannot launch an application or attach a container.
Use the existing dispatcher/owner/Arbiter; do not introduce another MCP or runner.

WindowsHidden is the experimental Makepad default; visible requires explicit
operator opt-in. The approved runtime must be independently built against
71c9ddcbb9c01dd208f99621fdd71024a5d35c65. The host does not link or bundle it.
The105158e Studio/WebSocket generation is not this old HTTP Remote protocol.

WSLC prerequisites are an operator-supported existing Windows WSLC/wslc.exe,
WSLg, Python3 and PowerShell7 at its existing approved executable path. No
automatic VM, SDK, driver, Docker or global WSL configuration installation.
Normal WSL2 distro/Docker Level0 and WSLC GUI qualification are different claims.

One exact owned single-app container uses1GiB RAM/1CPU. Host/build/runtime
admission is2GiB and heavy jobs are serialized. Existing fixed relay/protocol
does not accept arbitrary shell commands from MCP arguments. Unknown/foreign
container identity is refused; never reuse another incarnation's receipts.

Before claiming an application accepted, independently join approved host ELF
bytes, exact transfer CID/image/owner/incarnation/nonce, guest hash/inode,
actual /proc/PID/exe/birth/namespaces, listener and session/window identity.
Then observe actual widget KeyFocus, input postcondition, Makepad renderer,
fresh native/g PNG, runtime health, normal quit, actual App/root exit and
Job/guest/listener/RAIL/container/lease cleanup. Acknowledgement alone is not PASS.

This repository ships source helpers, not an approved ELF/image or private
provisioning contract. Adaptation to other payloads needs explicit review.
Current permanent mutable permissions and production acceptance remain closed.

The public provisioning helpers neutralize personal guest paths to
/opt/makepad-operator. That directory is not a provisioned or approved runtime
by itself. The operator must supply a consistent reviewed source/resource
layout and exact hashes; prior private-profile smoke evidence does not certify
this helper variant. No automatic deployment or profile bypass is provided.
