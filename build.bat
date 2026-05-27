@echo off
chcp 65001 >nul
set SRC_DIR=src
set OUT_DIR=out

if not exist %OUT_DIR% mkdir %OUT_DIR%

echo ================================================================
echo   Compiling HE System...
echo ================================================================
javac -encoding UTF-8 -d %OUT_DIR% ^
    %SRC_DIR%/crypto/util/KeyUtils.java ^
    %SRC_DIR%/crypto/he/HEInterface.java ^
    %SRC_DIR%/crypto/he/RSAHomomorphic.java ^
    %SRC_DIR%/crypto/he/Paillier.java ^
    %SRC_DIR%/scenario/PrivacyDemo.java ^
    %SRC_DIR%/Main.java

if %ERRORLEVEL% neq 0 (
    echo Compilation failed!
    pause
    exit /b 1
)

echo.
echo ================================================================
echo   Running HE System Demo...
echo ================================================================
echo.
java -Dfile.encoding=UTF-8 -cp %OUT_DIR% Main
pause
