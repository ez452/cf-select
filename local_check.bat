@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ========================================
echo   CF 优选 - 本地实测精选
echo   需要几分钟，期间请不要关闭窗口
echo ========================================
echo.
python scripts\local_check.py
echo.
echo ========================================
pause
