# Direct Internet Method v1.3.2

Router Gateway table-visibility hotfix on top of the accepted v1.3.1 startup-layout release.

## Windows Router Gateway
- Fixed the DataGrid theme defect that made unselected profiles render white text on the default white row background.
- Explicit dark row, alternating-row, cell and column-header styles keep all loaded profiles readable.
- Selected row remains high-contrast blue.
- Runtime UI automation verifies 9 rows, 7 columns and 9 data items with the current provider catalog.

## Preserved from v1.3.1
- 1289 × 632 preferred Windows startup size.
- Responsive wrapping footer with no overlap at reduced width.
- Provider catalog revision 2: 9 ready profiles from VPN Gate, VPNBook and Pilovali.
- Direct DNS/DPI privileged networking logic is unchanged.
- Linux protected backend compatibility remains 1.2.1; Linux user-space package advances only for release parity.

## Validation boundary
Physical-router authenticated tunnel success remains model/firmware-dependent. Windows installer remains unsigned by Authenticode.
