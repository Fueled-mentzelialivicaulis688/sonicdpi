@echo off
:: SonicDPI — diagnostic harness (cmd обёртка над diag.ps1)
::
:: Запускать в Admin cmd:
::   scripts\diag.bat
::
:: Прокидывает все аргументы дальше в diag.ps1 и обходит execution-policy.

setlocal
pushd "%~dp0\.."
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0diag.ps1" %*
set EXITCODE=%ERRORLEVEL%
popd
exit /b %EXITCODE%
