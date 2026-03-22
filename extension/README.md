# Отворен вот — Browser Extension

Verification extension for the otvoren-vot e-voting system.

## Development

1. Open `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked" and select this directory

## Architecture

- `background.js` — Service worker communicating with the Verification Service
- `content.js` — Content script detecting the voting page
- `popup.html/js` — Extension popup showing verification status and return codes

## Note

Icon files (`icons/`) need to be created before publishing. Use 16x16, 48x48, and 128x128 PNG files.
