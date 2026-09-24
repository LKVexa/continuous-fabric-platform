@echo off
rem Sets PY to a working Python 3.10+ (bundled _model runtime first, then py launcher, then PATH).
set "PY="
set "PY_ARGS="
if exist "%~dp0..\_model\runtime\python\python.exe" set "PY=%~dp0..\_model\runtime\python\python.exe"
if defined PY goto :check
py -3 -c "import sys" >nul 2>&1 && set "PY=py" && set "PY_ARGS=-3" && goto :check
python -c "import sys" >nul 2>&1 && set "PY=python" && goto :check
echo [CFP] No Python found. Install Python 3.10+ from python.org or keep ..\_model\runtime\python in place.
exit /b 9009
:check
"%PY%" %PY_ARGS% -c "import sys; sys.exit(0 if sys.version_info>=(3,10) else 1)" || (echo [CFP] Python 3.10+ required & exit /b 1)
exit /b 0
