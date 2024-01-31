@echo off

echo 1. 일반 로그 분석
echo.
echo 2. 복합 분석(특정 고객사용)
echo.
echo 3. 종료
echo.

:set
set _ok=
set /p _ok= 실행할 분석 방식을 선택 해주세요:
if "%_ok%" == "1" goto 1
if "%_ok%" == "2" goto 2
if "%_ok%" == "3" goto end

:1
cls
python ./csv_analyze_jybaek_Normal_v1.3.1.py

echo 로그 파일이 생성되었습니다.
pause
goto end

:2
cls
python ./csv_analyze_jybaek_Detail_v1.3.1.py

echo 로그 파일이 생성되었습니다.
pause
goto end

:end
exit