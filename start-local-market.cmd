@echo off
cd /d "%~dp0"
echo ==== Local connector market (port 8899) ====
echo Keep this window open while WorkBuddy runs.
echo.
"C:\Users\114976\.workbuddy\binaries\node\versions\22.22.2-6\node.exe" scripts\local-connector-market.mjs serve
echo.
echo Server stopped. Press any key to close.
pause >nul
