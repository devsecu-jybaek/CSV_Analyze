@echo off
echo ===========================================================================================
echo �м� ���� ��, �α� ���� �ٿ�� �ش� �׸��� �����Ͽ����� �� Ȯ�����ּ���.
echo.
echo �Ϲ� �α� �м�: [����� ip] [������ ip] [���ݸ�] [����� ������] [���赵]
echo ���� �α� �м�: [����� ip] [������ ip] [���ݸ�] [����� ������] [���赵] [url] [Action]
echo.
echo �ع����� �� �ش� ���α׷��� ��Ȱ�ϰ� �������� ���� �� �ֽ��ϴ�. (�ڡڡڡڡ�)
echo ��[decode] �׸� ���� �� �ش� ���α׷��� ��Ȱ�ϰ� �������� ���� �� �ֽ��ϴ�. (�ڡڡڡڡ�)
echo.
echo ===========================================================================================
echo.
echo [�м� �޴� ���� �� ���� ���� â�� �߸� �ش� �α�����(.csv)�� �����ؼ� ���� ���ֽø� �˴ϴ�.]
echo.
echo 1. �Ϲ� �α� �м� 
echo.
echo 2. ���� �α� �м�(Ư�� �����)
echo.
echo 3. ���̽� ��ġ(�̼�ġ ��ǻ�Ϳ��� ���)
echo.
echo 4. �ʼ� ��Ű�� ��ġ(��Ű�� �̼�ġ �� ����)
echo.
echo 5. �ʼ� ��Ű�� ����(���̻� ������� ���� �� ����)
echo.
echo 6. ����
echo.

:set
set _ok=
set /p _ok= ������ �м� ����� ���� ���ּ���:
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

echo �α� ������ �����Ǿ����ϴ�.
pause
goto end

:2
cls
cd Python
python ./csv_analyze_jybaek_Detail.py

echo �α� ������ �����Ǿ����ϴ�.
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