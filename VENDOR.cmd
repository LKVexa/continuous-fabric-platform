@echo off
setlocal
cd /d "%~dp0"
if not exist ledger mkdir ledger
call "%~dp0_find_python.cmd" || goto :fail
"%PY%" %PY_ARGS% -m cfp vendor %* 2> ledger\vendor.log || (type ledger\vendor.log & goto :fail)
"%PY%" %PY_ARGS% -m cfp vendor-verify || goto :fail
echo [CFP] vendor complete.
pause
goto :eof
:fail
echo [CFP] Vendor failed. Details are in ledger\vendor.log
pause
exit /b 1
