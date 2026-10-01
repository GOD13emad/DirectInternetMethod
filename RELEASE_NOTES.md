# Direct Internet Method v1.3.1

Windows UI layout hotfix. The networking architecture and privileged backend behavior are unchanged from the accepted v1.3.0 release.

## Windows UI
- Main window now opens at 1289 × 632 device-independent pixels; on the current 96-DPI host this is exactly 1289 × 632 physical pixels.
- Footer actions use a wrapping layout instead of a horizontal StackPanel that could overflow into the explanatory text.
- Footer explanatory text wraps in a bounded column.
- Layout rounding and device-pixel snapping are enabled.
- Host UI automation verifies the preferred startup size, visibility of all six actions, and zero overlap at both 1289 × 632 and a reduced 1000 × 632 window.

## Regression scope
- Direct DNS/DPI logic: unchanged.
- Windows privileged service/update logic: unchanged except assembly version metadata.
- Router Gateway behavior: unchanged.
- Linux networking backend: unchanged; Linux package version is advanced for cross-platform release parity.

## Validation boundary
Physical-router authenticated tunnel success remains model/firmware-dependent. The Windows installer remains unsigned by Authenticode.
