@echo off
setlocal EnableExtensions
cd /d "%~dp0"

REM Allow connections from other computers
set "BIND_HOST=0.0.0.0"
set "PORT=8080"

REM Enable private network certificate monitoring
set "ALLOW_PRIVATE_TARGETS=true"

echo =======================================
echo   TLS Watch - HTTPS Certificate Monitor
echo =======================================
echo.

rem Use labels instead of parenthesized command blocks to avoid cmd.exe parsing errors.
if exist ".venv\Scripts\python.exe" goto dependencies

echo Creating Python virtual environment...
where py >nul 2>nul
if errorlevel 1 goto create_with_python
py -3 -m venv .venv
goto verify_venv

:create_with_python
python -m venv .venv

:verify_venv
if not exist ".venv\Scripts\python.exe" goto venv_error

:dependencies
if exist ".venv\tls_watch_ready.txt" goto run_app

echo Installing Flask and TLS libraries for first launch...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto install_error
>".venv\tls_watch_ready.txt" echo installed

:run_app
echo.
echo Open http://127.0.0.1:8080 in your browser.
echo Keep this window open for automatic daily checks.
echo Stop the service by pressing Ctrl+C.
echo.
".venv\Scripts\python.exe" app.py
set "EXIT_CODE=%ERRORLEVEL%"
if "%EXIT_CODE%"=="0" goto finish

echo.
echo ERROR: TLS Watch exited with code %EXIT_CODE%.
echo Check the error details shown above.
echo If port 8080 is occupied, close the other application first.
pause
exit /b %EXIT_CODE%

:venv_error
echo.
echo ERROR: Python could not create the virtual environment.
echo Install Python 3.11 or newer, then try again.
pause
exit /b 1

:install_error
echo.
echo ERROR: Dependency installation failed.
echo Check the error above and your internet connection.
pause
exit /b 1

:finish
endlocal
