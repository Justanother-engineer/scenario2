param()

# -- CONFIG: set this to your GitHub raw base URL --
$scriptBase = "https://raw.githubusercontent.com/Justanother-engineer/scenario2/main"

# ── Elevation Gate ──────────────────────────────────────────────
$isAdmin = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[!] Not admin. Requesting elevation via UAC..."
    $scriptUrl = "$scriptBase/cleanup.ps1"
    $b64 = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes(
        "iex((New-Object Net.WebClient).DownloadString('$scriptUrl'))"
    ))
    Start-Process powershell -Verb RunAs -ArgumentList "-NoP -Exec Bypass -Enc $b64"
    exit
}

Write-Host "[*] Running with admin privileges. Proceeding..."

$ErrorActionPreference = "SilentlyContinue"
$VerbosePreference = "Continue"

Write-Host "[*] Cleaning up scenario-02 artifacts..."

# 1. Delete scattered artifact files
$files = @(
    "C:\ProgramData\Package Cache\{7B8E9F12-4A3C-4D5E-9F1A-2B3C4D5E6F7A}\package.dll",
    "C:\ProgramData\Package Cache\{7B8E9F12-4A3C-4D5E-9F1A-2B3C4D5E6F7A}\stage2.dll",
    "C:\Users\Public\Libraries\msimtf.dll",
    "C:\Users\Public\Libraries\tcmsetup.exe",
    "C:\Users\Public\Libraries\colorcpl.exe",
    "C:\ProgramData\Microsoft\Search\Data\EDS\stage.sct",
    "C:\ProgramData\Microsoft\Windows\WER\ReportQueue\stage.js",
    "C:\ProgramData\Microsoft\Windows\WER\Temp\report.hta",
    "C:\Users\Public\Libraries\Telemetry.dll",
    "C:\ProgramData\USOShared\Logs\cache.dat",
    "C:\ProgramData\USOShared\Logs\Telemetry.bin",
    "C:\ProgramData\USOShared\Logs\BITS.bin",
    "C:\ProgramData\USOShared\Logs\Wifi.bin",
    "C:\ProgramData\Microsoft\Search\Data\EDS\index.tmp",
    "C:\ProgramData\Microsoft\Windows\WER\ReportArchive\state.tmp",
    "C:\ProgramData\Microsoft\Search\Data\EDS\spcache.bin",
    "C:\ProgramData\Microsoft\Windows\WER\ReportQueue\queue.tmp",
    "C:\Windows\Temp\~wdg.inf"
)

foreach ($file in $files) {
    if (Test-Path $file) {
        Remove-Item -Path $file -Force
        Write-Host "  [-] Deleted: $file"
    }
}

# 2. Remove COM hijack registry key
$clsidPath = "HKCU:\Software\Classes\CLSID"
if (Test-Path $clsidPath) {
    Get-ChildItem -Path $clsidPath -ErrorAction SilentlyContinue | ForEach-Object {
        $inprocPath = Join-Path $_.PSPath "InprocServer32"
        if (Test-Path $inprocPath) {
            $value = (Get-ItemProperty -Path $inprocPath -Name "(default)" -ErrorAction SilentlyContinue)."(default)"
            if ($value -like "*Telemetry.dll*") {
                Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "  [-] Removed COM hijack key: $($_.PSPath)"
            }
        }
    }
}

# 3. Remove LNK from Startup folder
$startupPath = [Environment]::GetFolderPath("Startup")
if (Test-Path $startupPath) {
    Get-ChildItem -Path $startupPath -Filter "*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
        $shell = New-Object -ComObject WScript.Shell
        $target = $shell.CreateShortcut($_.FullName).TargetPath
        if ($target -match "rundll32.exe" -and $shell.CreateShortcut($_.FullName).Arguments -match "Telemetry.dll") {
            Remove-Item -Path $_.FullName -Force
            Write-Host "  [-] Deleted startup LNK: $($_.FullName)"
        }
    }
}

# 4. Revert WDigest
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f | Out-Null
Write-Host "  [-] WDigest UseLogonCredential reverted to 0"

# 5. Delete self
$selfPath = $MyInvocation.MyCommand.Path
if ($selfPath -and (Test-Path $selfPath)) {
    Remove-Item -Path $selfPath -Force
}

Write-Host "[+] Cleanup complete."
