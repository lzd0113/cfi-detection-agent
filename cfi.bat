@echo off
cd /d "%~dp0"
set PYTHONPATH=%~dp0src
python -c "import cfi_agent; import httpx,typer,rich,elftools,openpyxl,flask,cxxfilt,yaml,dotenv,prompt_toolkit" 2>nul
if not errorlevel 1 goto run
echo.
echo ================================================
echo   First run: auto-installing dependencies (one time)...
echo ================================================
echo.
python -m pip install httpx typer rich pyelftools openpyxl flask cxxfilt pyyaml python-dotenv prompt_toolkit -i https://pypi.tuna.tsinghua.edu.cn/simple --disable-pip-version-check
echo.
echo [DONE] Dependencies installed.
echo.
:run
python -m cfi_agent %*
echo.
echo [Agent exited. errorlevel=%errorlevel%]
echo.
pause
