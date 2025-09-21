@echo off
REM Log Risk Detection and Auto-Remediation System - Setup Script
REM This script creates a virtual environment and installs dependencies

echo ========================================
echo Log Risk Detection System Setup
echo ========================================

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from https://python.org
    pause
    exit /b 1
)

echo Python found:
python --version

REM Create virtual environment if it doesn't exist
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
    if errorlevel 1 (
        echo Error: Failed to create virtual environment
        pause
        exit /b 1
    )
    echo Virtual environment created successfully
) else (
    echo Virtual environment already exists
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install requirements
echo Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo Error: Failed to install dependencies
    pause
    exit /b 1
)

echo Dependencies installed successfully

REM Create necessary directories
echo Creating output directories...
if not exist "out" mkdir out
if not exist "samples" mkdir samples
if not exist "models" mkdir models

REM Generate sample data for testing
echo Generating sample test data...
python samples\generator.py --seed 42 --count 1000 --attack-ratio 0.1 --output samples\mixed.log
if errorlevel 1 (
    echo Warning: Failed to generate sample data
) else (
    echo Sample data generated: samples\mixed.log
)

REM Generate compressed sample data
echo Generating compressed sample data...
python samples\generator.py --seed 123 --count 500 --attack-ratio 0.15 --output samples\mixed.log.gz --compress
if errorlevel 1 (
    echo Warning: Failed to generate compressed sample data
) else (
    echo Compressed sample data generated: samples\mixed.log.gz
)

REM Generate session attack scenarios
echo Generating session attack scenarios...
python samples\generator.py --seed 456 --session-attack --output samples\session_attacks.log
if errorlevel 1 (
    echo Warning: Failed to generate session attack data
) else (
    echo Session attack data generated: samples\session_attacks.log
)

echo ========================================
echo Setup completed successfully!
echo ========================================
echo.
echo Environment is ready. You can now:
echo.
echo 1. Run the CLI analyzer:
echo    python src\main.py analyze --file samples\mixed.log
echo.
echo 2. Start the API server:
echo    python src\api.py
echo.
echo 3. Run evaluation:
echo    python grader.py --file samples\mixed.log.gz
echo.
echo 4. Train ML model:
echo    python src\main.py train
echo.
echo ========================================

pause