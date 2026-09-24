@echo off
setlocal
cd /d "%~dp0"
if not exist ledger mkdir ledger
call "%~dp0_find_python.cmd" || goto :fail
echo [CFP] using %PY%
"%PY%" %PY_ARGS% -m cfp atlas > ledger\start.log 2>&1 || (type ledger\start.log & goto :fail)
echo [CFP] atlas written to ledger\ATLAS.json
"%PY%" %PY_ARGS% -m cfp up %* 2>> ledger\start.log || (type ledger\start.log & goto :fail)
goto :eof
:fail
echo.
echo [CFP] Start failed. Details are in ledger\start.log
pause
exit /b 1
