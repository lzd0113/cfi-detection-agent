@echo off
cd /d "%~dp0"
python -c "import httpx,typer,rich,elftools,openpyxl,flask,cxxfilt,yaml,dotenv,prompt_toolkit" 2>nul
if not errorlevel 1 goto run
echo.
echo ================================================
echo   First run: auto-installing dependencies (one time)...
echo ================================================
echo.
python -m pip install -e . -i https://pypi.tuna.tsinghua.edu.cn/simple --disable-pip-version-check
if errorlevel 1 echo [ERROR] Install failed. Run: pip install -e .
if errorlevel 1 pause
if errorlevel 1 exit /b 1
echo.
echo [DONE] Dependencies installed.
echo.
:run
python -m cfi_agent %*
echo.
echo [Agent exited. errorlevel=%errorlevel%]
echo.
pause
