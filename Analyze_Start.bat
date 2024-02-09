@echo off
echo ===========================================================================================
echo 분석 실행 전, 로그 파일 다운시 해당 항목을 포함하였는지 꼭 확인해주세요.
echo.
echo 일반 로그 분석: [출발지 ip] [목적지 ip] [공격명] [출발지 국가명] [위험도]
echo 복합 로그 분석: [출발지 ip] [목적지 ip] [공격명] [출발지 국가명] [위험도] [url] [Action]
echo.
echo ※미포함 시 해당 프로그램이 원활하게 동작하지 않을 수 있습니다. (★★★★★)
echo ※[decode] 항목 포함 시 해당 프로그램이 원활하게 동작하지 않을 수 있습니다. (★★★★★)
echo.
echo ===========================================================================================
echo.
echo [분석 메뉴 선택 후 파일 선택 창이 뜨면 해당 로그파일(.csv)를 선택해서 열기 해주시면 됩니다.]
echo.
echo 1. 일반 로그 분석 
echo.
echo 2. 복합 로그 분석(특정 고객사용)
echo.
echo 3. 파이썬 설치(미설치 컴퓨터에서 사용)
echo.
echo 4. 필수 패키지 설치(패키지 미설치 시 선택)
echo.
echo 5. 필수 패키지 제거(더이상 사용하지 않을 시 선택)
echo.
echo 6. 종료
echo.

:set
set _ok=
set /p _ok= 실행할 분석 방식을 선택 해주세요:
if "%_ok%" == "1" goto 1
if "%_ok%" == "2" goto 2
if "%_ok%" == "3" goto 3
if "%_ok%" == "4" goto 4
if "%_ok%" == "5" goto 5
if "%_ok%" == "6" goto end

:1
cls
cd Python
python ./csv_analyze_jybaek_Normal.py

echo 로그 파일이 생성되었습니다.
pause
goto end

:2
cls
cd Python
python ./csv_analyze_jybaek_Detail.py

echo 로그 파일이 생성되었습니다.
pause
goto end

:3
cls
cd Packages
start python-3.11.6-amd64.exe
cls
cd ..
Analyze_Start.bat
goto end

:4
cls
cd Packages
install_package.bat

pause
goto end

:5
cls
cd Packages
uninstall_package.bat

pause
goto end

:end
exit