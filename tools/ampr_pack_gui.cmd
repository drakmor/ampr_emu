@echo off
setlocal
where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
  py -3 "%~dp0ampr_pack_gui.py" %*
) else (
  python "%~dp0ampr_pack_gui.py" %*
)
if %ERRORLEVEL% NEQ 0 pause
endlocal
