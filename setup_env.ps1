# Log Risk Detection and Auto-Remediation System - PowerShell Setup Script
# This script creates a virtual environment and installs dependencies

Write-Host "========================================" -ForegroundColor Green
Write-Host "Log Risk Detection System Setup" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

# Check if Python is installed
try {
    $pythonVersion = python --version 2>&1
    Write-Host "Python found: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "Error: Python is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Python 3.8 or higher from https://python.org" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# Create virtual environment if it doesn't exist
if (-not (Test-Path "venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Cyan
    python -m venv venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Error: Failed to create virtual environment" -ForegroundColor Red
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-Host "Virtual environment created successfully" -ForegroundColor Green
} else {
    Write-Host "Virtual environment already exists" -ForegroundColor Yellow
}

# Activate virtual environment
Write-Host "Activating virtual environment..." -ForegroundColor Cyan
& "venv\Scripts\Activate.ps1"

# Upgrade pip
Write-Host "Upgrading pip..." -ForegroundColor Cyan
python -m pip install --upgrade pip

# Install requirements
Write-Host "Installing dependencies..." -ForegroundColor Cyan
pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Failed to install dependencies" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}
Write-Host "Dependencies installed successfully" -ForegroundColor Green

# Create necessary directories
Write-Host "Creating output directories..." -ForegroundColor Cyan
if (-not (Test-Path "out")) { New-Item -ItemType Directory -Path "out" | Out-Null }
if (-not (Test-Path "samples")) { New-Item -ItemType Directory -Path "samples" | Out-Null }
if (-not (Test-Path "models")) { New-Item -ItemType Directory -Path "models" | Out-Null }

# Generate sample data for testing
Write-Host "Generating sample test data..." -ForegroundColor Cyan
python samples\generator.py --seed 42 --count 1000 --attack-ratio 0.1 --output samples\mixed.log
if ($LASTEXITCODE -ne 0) {
    Write-Host "Warning: Failed to generate sample data" -ForegroundColor Yellow
} else {
    Write-Host "Sample data generated: samples\mixed.log" -ForegroundColor Green
}

# Generate compressed sample data
Write-Host "Generating compressed sample data..." -ForegroundColor Cyan
python samples\generator.py --seed 123 --count 500 --attack-ratio 0.15 --output samples\mixed.log.gz --compress
if ($LASTEXITCODE -ne 0) {
    Write-Host "Warning: Failed to generate compressed sample data" -ForegroundColor Yellow
} else {
    Write-Host "Compressed sample data generated: samples\mixed.log.gz" -ForegroundColor Green
}

# Generate session attack scenarios
Write-Host "Generating session attack scenarios..." -ForegroundColor Cyan
python samples\generator.py --seed 456 --session-attack --output samples\session_attacks.log
if ($LASTEXITCODE -ne 0) {
    Write-Host "Warning: Failed to generate session attack data" -ForegroundColor Yellow
} else {
    Write-Host "Session attack data generated: samples\session_attacks.log" -ForegroundColor Green
}

Write-Host "========================================" -ForegroundColor Green
Write-Host "Setup completed successfully!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Environment is ready. You can now:" -ForegroundColor White
Write-Host ""
Write-Host "1. Run the CLI analyzer:" -ForegroundColor Cyan
Write-Host "   python src\main.py analyze --file samples\mixed.log" -ForegroundColor White
Write-Host ""
Write-Host "2. Start the API server:" -ForegroundColor Cyan
Write-Host "   python src\api.py" -ForegroundColor White
Write-Host ""
Write-Host "3. Run evaluation:" -ForegroundColor Cyan
Write-Host "   python grader.py --file samples\mixed.log.gz" -ForegroundColor White
Write-Host ""
Write-Host "4. Train ML model:" -ForegroundColor Cyan
Write-Host "   python src\main.py train" -ForegroundColor White
Write-Host ""
Write-Host "========================================" -ForegroundColor Green

Read-Host "Press Enter to exit"