@echo off

echo 1. �Ϲ� �α� �м�
echo.
echo 2. ���� �м�(Ư�� �����)
echo.
echo 3. ����
echo.

:set
set _ok=
set /p _ok= ������ �м� ����� ���� ���ּ���:
if "%_ok%" == "1" goto 1
if "%_ok%" == "2" goto 2
if "%_ok%" == "3" goto end

:1
cls
python ./csv_analyze_jybaek_Normal_v1.3.1.py

echo �α� ������ �����Ǿ����ϴ�.
pause
goto end

:2
cls
python ./csv_analyze_jybaek_Detail_v1.3.1.py

echo �α� ������ �����Ǿ����ϴ�.
pause
goto end

:end
exit