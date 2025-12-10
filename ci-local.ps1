# ci-local.ps1 - Local CI Test Runner for proc-canonicalize (Windows)
# Run all CI checks locally before pushing

$ErrorActionPreference = "Stop"

Write-Host "=== proc-canonicalize Local CI ===" -ForegroundColor Cyan
Write-Host ""

# Find cargo
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $cargoPaths = @(
        "$env:USERPROFILE\.cargo\bin\cargo.exe",
        "C:\Users\$env:USERNAME\.cargo\bin\cargo.exe"
    )
    
    foreach ($cargoPath in $cargoPaths) {
        if (Test-Path $cargoPath) {
            $env:PATH = "$(Split-Path $cargoPath);$env:PATH"
            Write-Host "* Found cargo at: $cargoPath" -ForegroundColor Green
            break
        }
    }
    
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        Write-Host "ERROR: cargo not found. Install Rust from https://rustup.rs/" -ForegroundColor Red
        exit 1
    }
}

Write-Host "* Using cargo: $(Get-Command cargo | Select-Object -ExpandProperty Source)" -ForegroundColor Green
$rustVersion = & rustc --version
Write-Host "Rust version: $rustVersion" -ForegroundColor Magenta
Write-Host ""

function Run-Check {
    param(
        [string]$Name,
        [string]$Command
    )
    
    Write-Host "Running: $Name" -ForegroundColor Blue
    Write-Host "Command: $Command" -ForegroundColor Gray
    
    try {
        Invoke-Expression $Command
        if ($LASTEXITCODE -ne 0) {
            throw "Command failed with exit code $LASTEXITCODE"
        }
        Write-Host "SUCCESS: $Name" -ForegroundColor Green
        Write-Host ""
        return $true
    } catch {
        Write-Host "FAILED: $Name" -ForegroundColor Red
        exit 1
    }
}

# Check we're in project root
if (-not (Test-Path "Cargo.toml")) {
    Write-Host "ERROR: Cargo.toml not found. Are you in the project root?" -ForegroundColor Red
    exit 1
}

# Validate UTF-8 encoding
Write-Host "Validating UTF-8 encoding..." -ForegroundColor Cyan
$files = @("README.md", "Cargo.toml", "src\lib.rs")
foreach ($file in $files) {
    if (Test-Path $file) {
        try {
            $content = Get-Content $file -Encoding UTF8 -ErrorAction Stop
            # Check for UTF-8 BOM (EF BB BF) - only the first 3 bytes
            $stream = [System.IO.File]::OpenRead($file)
            $bom = New-Object byte[] 3
            $bytesRead = $stream.Read($bom, 0, 3)
            $stream.Close()
            
            if ($bytesRead -ge 3 -and $bom[0] -eq 0xEF -and $bom[1] -eq 0xBB -and $bom[2] -eq 0xBF) {
                Write-Host "WARNING: $file has UTF-8 BOM (may cause issues with cargo publish)" -ForegroundColor Yellow
            } else {
                Write-Host "OK: $file - UTF-8 encoding verified, no BOM" -ForegroundColor Green
            }
        } catch {
            Write-Host "ERROR: $file encoding issue" -ForegroundColor Red
            exit 1
        }
    }
}
Write-Host ""

# Auto-fix formatting
Write-Host "Auto-fixing formatting..." -ForegroundColor Cyan
cargo fmt --all
Write-Host "Formatting fixed" -ForegroundColor Green
Write-Host ""

# Run checks
Run-Check "Format check" "cargo fmt --all -- --check"
Run-Check "Clippy" "cargo clippy --all-targets --all-features -- -D warnings"
Run-Check "Tests" "cargo test --verbose"
Run-Check "Tests with dunce" "cargo test --features dunce --verbose"

# Documentation
$env:RUSTDOCFLAGS = "-D warnings"
Run-Check "Documentation" "cargo doc --no-deps --all-features"

Write-Host ""
Write-Host "All CI checks passed!" -ForegroundColor Green
