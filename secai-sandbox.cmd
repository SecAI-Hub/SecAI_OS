@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "REPO_ROOT=%~dp0"
set "START_SCRIPT=%REPO_ROOT%scripts\sandbox\start.ps1"
set "STOP_SCRIPT=%REPO_ROOT%scripts\sandbox\stop.ps1"
set "COMPOSE_FILE=%REPO_ROOT%deploy\sandbox\compose.yaml"
set "ENV_FILE=%REPO_ROOT%deploy\sandbox\.env"

set "ACTION=%~1"
if "%ACTION%"=="" set "ACTION=start"
if /I "%ACTION%"=="help" goto help
if "%ACTION%"=="-h" goto help
if "%ACTION%"=="--help" goto help

if /I "%ACTION%"=="start" (
    shift
    goto start_stack
)
if /I "%ACTION%"=="up" (
    shift
    goto start_stack
)
if /I "%ACTION%"=="stop" goto stop_stack
if /I "%ACTION%"=="down" goto stop_stack
if /I "%ACTION%"=="restart" (
    shift
    set "RESTART_FIRST=1"
    goto start_stack
)
if /I "%ACTION%"=="status" goto status_stack
if /I "%ACTION%"=="ps" goto status_stack
if /I "%ACTION%"=="logs" goto logs_stack
if /I "%ACTION%"=="open" goto open_ui

echo Unknown command: %ACTION%
echo.
goto help_error

:start_stack
set "PS_ARGS="
:parse_start_args
if "%~1"=="" goto run_start
if /I "%~1"=="--with-inference" (
    set "PS_ARGS=!PS_ARGS! -WithInference"
    shift
    goto parse_start_args
)
if /I "%~1"=="-WithInference" (
    set "PS_ARGS=!PS_ARGS! -WithInference"
    shift
    goto parse_start_args
)
if /I "%~1"=="--with-diffusion" (
    set "PS_ARGS=!PS_ARGS! -WithDiffusion"
    shift
    goto parse_start_args
)
if /I "%~1"=="-WithDiffusion" (
    set "PS_ARGS=!PS_ARGS! -WithDiffusion"
    shift
    goto parse_start_args
)
if /I "%~1"=="--with-search" (
    set "PS_ARGS=!PS_ARGS! -WithSearch"
    shift
    goto parse_start_args
)
if /I "%~1"=="-WithSearch" (
    set "PS_ARGS=!PS_ARGS! -WithSearch"
    shift
    goto parse_start_args
)
if /I "%~1"=="--with-airlock" (
    set "PS_ARGS=!PS_ARGS! -WithAirlock"
    shift
    goto parse_start_args
)
if /I "%~1"=="-WithAirlock" (
    set "PS_ARGS=!PS_ARGS! -WithAirlock"
    shift
    goto parse_start_args
)
echo Unknown start option: %~1
exit /b 2

:run_start
if defined RESTART_FIRST (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%STOP_SCRIPT%"
    if errorlevel 1 exit /b !ERRORLEVEL!
)
powershell -NoProfile -ExecutionPolicy Bypass -File "%START_SCRIPT%" !PS_ARGS!
exit /b %ERRORLEVEL%

:stop_stack
powershell -NoProfile -ExecutionPolicy Bypass -File "%STOP_SCRIPT%"
exit /b %ERRORLEVEL%

:status_stack
where docker >nul 2>nul
if errorlevel 1 (
    echo Docker was not found in PATH.
    exit /b 1
)
docker compose -f "%COMPOSE_FILE%" --profile search --profile llm --profile diffusion ps
exit /b %ERRORLEVEL%

:logs_stack
where docker >nul 2>nul
if errorlevel 1 (
    echo Docker was not found in PATH.
    exit /b 1
)
docker compose -f "%COMPOSE_FILE%" --profile search --profile llm --profile diffusion logs -f --tail=100
exit /b %ERRORLEVEL%

:open_ui
set "UI_PORT=8480"
if exist "%ENV_FILE%" (
    for /f "tokens=1,* delims==" %%A in ('findstr /R "^SECAI_UI_PORT=" "%ENV_FILE%"') do set "UI_PORT=%%B"
)
start "" "http://127.0.0.1:%UI_PORT%"
exit /b 0

:help
echo SecAI OS Docker sandbox launcher
echo.
echo Usage:
echo   secai-sandbox.cmd [command] [options]
echo.
echo Commands:
echo   start       Build and start the sandbox stack ^(default^)
echo   stop        Stop the sandbox stack
echo   restart     Stop, then start the sandbox stack
echo   status      Show container status
echo   logs        Follow sandbox logs
echo   open        Open the UI in your default browser
echo   help        Show this help
echo.
echo Start options:
echo   --with-search       Enable Tor and SearXNG search sidecars
echo   --with-airlock      Enable airlock policy in sandbox mode
echo   --with-inference    Enable local LLM inference profile
echo   --with-diffusion    Enable diffusion worker profile
echo.
echo UI:
echo   http://127.0.0.1:8480
exit /b 0

:help_error
call "%~f0" help
exit /b 2
