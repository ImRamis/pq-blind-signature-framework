@ECHO OFF
SETLOCAL ENABLEDELAYEDEXPANSION

ECHO --- Quick Start Script for Blind Signature Project (Windows) ---
ECHO.

:: =================================================================
:: --- 1. Check Prerequisites ---
:: =================================================================
ECHO 1. Checking for required tools...

:: Define a list of required commands to check
SET "COMMANDS=python pip node npm git cargo"

:: Loop through the commands and check if they exist in the system's PATH
FOR %%c IN (%COMMANDS%) DO (
    WHERE %%c >nul 2>nul
    IF !ERRORLEVEL! NEQ 0 (
        ECHO [X] %%c not found. Please install it and ensure it's in your PATH.
        EXIT /B 1
    ) ELSE (
        ECHO [V] %%c is installed.
    )
)

:: Check for Circom separately due to the custom build step
WHERE circom >nul 2>nul
IF !ERRORLEVEL! EQU 0 (
    ECHO [V] Circom compiler is already installed.
) ELSE (
    ECHO.
    ECHO [-] Circom not found. Cloning and building from source...
    IF EXIST "circom" (
        ECHO [-] 'circom' directory already exists. Skipping clone.
    ) ELSE (
        git clone https://github.com/iden3/circom.git
        IF !ERRORLEVEL! NEQ 0 (ECHO [X] Failed to clone circom repository. & EXIT /B 1)
    )
    
    PUSHD circom
    cargo build --release
    IF !ERRORLEVEL! NEQ 0 (ECHO [X] Failed to build circom. Please check your Rust environment. & POPD & EXIT /B 1)
    POPD

    SET "CIRCOM_PATH=%CD%\circom\target\release"
    SET "PATH=!PATH!;!CIRCOM_PATH!"

    WHERE circom >nul 2>nul
    IF !ERRORLEVEL! EQU 0 (
        ECHO [V] Circom successfully built.
        ECHO NOTE: You may need to add the circom binary to your system's PATH permanently.
        ECHO   Path: !CIRCOM_PATH!
    ) ELSE (
        ECHO [X] Failed to find circom after compilation.
        EXIT /B 1
    )
)
ECHO.

:: =================================================================
:: --- 2. Install Dependencies ---
:: =================================================================
ECHO 2. Installing project dependencies...

:: Install Python packages. Note: Use `python` instead of `python3` for Windows standard.
python -m pip install -e .[examples,benchmarks]
IF !ERRORLEVEL! NEQ 0 (ECHO [X] Failed to install Python dependencies. & EXIT /B 1)

:: Install Node.js packages for the SNARK engine
PUSHD snarkjs_engine
npm install
IF !ERRORLEVEL! NEQ 0 (ECHO [X] Failed to install Node.js dependencies. & POPD & EXIT /B 1)
POPD
ECHO.

:: =================================================================
:: --- 3. Download Powers of Tau ---
:: =================================================================
SET "PTAU_FILE=circuits\powersOfTau28_hez_final_15.ptau"
ECHO 3. Checking for Powers of Tau file...

IF EXIST "%PTAU_FILE%" (
    ECHO [V] Powers of Tau file already exists.
) ELSE (
    ECHO [-] Powers of Tau file not found. Downloading (28MB)...
    IF NOT EXIST "circuits" MKDIR "circuits"
    
    :: Use curl, which we checked for earlier. --output is the standard long-form argument.
    curl -L "https://raw.githubusercontent.com/scaffold-eth/scaffold-eth-examples/refs/heads/zk-prove-membership/packages/hardhat/circuits/powersOfTau28_hez_final_15.ptau" --output "%PTAU_FILE%"
    IF !ERRORLEVEL! NEQ 0 (ECHO [X] Download failed. Please check your internet connection. & EXIT /B 1)
    ECHO [V] Powers of Tau file downloaded.
)
ECHO.

:: =================================================================
:: --- 4. Generate SNARK Keys ---
:: =================================================================
ECHO 4. Generating ZK-SNARK keys...
:: Execute the Python script from the scripts directory.
python scripts/setup_keys.py
IF !ERRORLEVEL! NEQ 0 (ECHO [X] SNARK key setup failed. Please check the Python script output. & EXIT /B 1)
ECHO.


ECHO.
ECHO --- SETUP COMPLETE ---
ECHO The environment is ready.
ECHO You can now run the examples, for example:
ECHO python examples/bank_demo.py
ECHO.

ENDLOCAL
EXIT /B 0