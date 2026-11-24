@echo off
cd /d "%~dp0"
title CST8808 Quiz 2 report

where py >nul 2>&1
if %errorlevel%==0 goto runpy
where python >nul 2>&1
if %errorlevel%==0 goto runpython

echo Python was not found.
echo.
echo 1. Open https://www.python.org/downloads/windows/
echo 2. Install Python 3.
echo 3. On the first screen, check the box Add python.exe to PATH.
echo 4. Double-click report.bat again.
echo.
pause
exit /b 1

:runpy
py parse_iptables.py iptables.log
goto done

:runpython
python parse_iptables.py iptables.log

:done
echo.
pause
exit /b 0
