@echo off
REM Scheduled entry point. Uses an absolute interpreter path because Task
REM Scheduler does not always inherit the PATH an interactive shell has.
cd /d "%~dp0"
"C:\Users\defne\AppData\Local\Programs\Python\Python312\python.exe" -m nobetci --sites sites.json --email >> "logs\nobetci.log" 2>&1
