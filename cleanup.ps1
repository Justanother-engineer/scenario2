param(
    [switch]$WhatIf
)

# -- CONFIG: set this to your GitHub raw base URL --
$scriptBase = "https://raw.githubusercontent.com/Justanother-engineer/scenario2/main"

# ── Elevation Gate ──────────────────────────────────────────────
$isAdmin = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[!] Not admin. Requesting elevation..."
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

# Separate log so residuals report survives cache.dat deletion
$cleanupLog = "C:\ProgramData\USOShared\Logs\cleanup.dat"
function Write-CleanupLog($msg) {
    $parent = Split-Path $cleanupLog -Parent
    if (-not (Test-Path $parent)) { New-Item -Path $parent -ItemType Directory -Force | Out-Null }
    "$(Get-Date -Format '[yyyy-MM-dd HH:mm:ss]') $msg" | Out-File $cleanupLog -Append
}

Write-Host "[*] Cleaning up scenario-02 artifacts..."
Write-CleanupLog "[*] cleanup.ps1 started - scriptBase=$scriptBase logFile=$cleanupLog"

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

Write-CleanupLog "[*] Deleting $($files.Count) scattered files"
foreach ($file in $files) {
    if ($WhatIf) {
        Write-CleanupLog "[WHATIF] would delete $file"
    } elseif (Test-Path $file) {
        Remove-Item -Path $file -Force
        Write-CleanupLog "[-] Deleted: $file"
    } else {
        Write-CleanupLog "[i] Already gone: $file"
    }
}

# 2. Remove COM hijack registry key
$clsidPath = "HKCU:\Software\Classes\CLSID"
Write-CleanupLog "[*] Scanning CLSID for COM hijack (Telemetry.dll)"
if (Test-Path $clsidPath) {
    Get-ChildItem -Path $clsidPath -ErrorAction SilentlyContinue | ForEach-Object {
        $inprocPath = Join-Path $_.PSPath "InprocServer32"
        if (Test-Path $inprocPath) {
            $value = (Get-ItemProperty -Path $inprocPath -Name "(default)" -ErrorAction SilentlyContinue)."(default)"
            if ($value -like "*Telemetry.dll*") {
                if ($WhatIf) {
                    Write-CleanupLog "[WHATIF] would remove COM hijack key: $($_.PSPath)"
                } else {
                    Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    Write-CleanupLog "[-] Removed COM hijack key: $($_.PSPath)"
                }
            }
        }
    }
}

# 3. Remove LNK from Startup folder
$startupPath = [Environment]::GetFolderPath("Startup")
Write-CleanupLog "[*] Scanning Startup LNKs for rundll32 + Telemetry.dll"
if (Test-Path $startupPath) {
    Get-ChildItem -Path $startupPath -Filter "*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
        $shell = New-Object -ComObject WScript.Shell
        $target = $shell.CreateShortcut($_.FullName).TargetPath
        if ($target -match "rundll32.exe" -and $shell.CreateShortcut($_.FullName).Arguments -match "Telemetry.dll") {
            if ($WhatIf) {
                Write-CleanupLog "[WHATIF] would delete startup LNK: $($_.FullName)"
            } else {
                Remove-Item -Path $_.FullName -Force
                Write-CleanupLog "[-] Deleted startup LNK: $($_.FullName)"
            }
        }
    }
}

# 4. Remove service persistence (WinUpdHlth)
$serviceName = "WinUpdHlth"
Write-CleanupLog "[*] Removing service persistence: $serviceName"
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($svc) {
    if ($WhatIf) {
        Write-CleanupLog "[WHATIF] would sc.exe stop + delete $serviceName"
    } else {
        sc.exe stop $serviceName 2>&1 | Out-Null
        sc.exe delete $serviceName 2>&1 | Out-Null
        Write-CleanupLog "[-] Stopped and deleted service: $serviceName"
    }
} else {
    Write-CleanupLog "[i] Service not present: $serviceName"
}

# 5. Revert WDigest
$wdigestKey = "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
Write-CleanupLog "[*] Reverting WDigest at $wdigestKey"
if ($WhatIf) {
    Write-CleanupLog "[WHATIF] would reg add $wdigestKey /v UseLogonCredential /d 0"
} else {
    reg.exe add $wdigestKey /v UseLogonCredential /t REG_DWORD /d 0 /f 2>&1 | Out-Null
    Write-CleanupLog "[-] WDigest UseLogonCredential reverted to 0 at $wdigestKey"
}

# 6. Residual verification (mirrors scenario-01-rmm/src/cleanup.ps1:109-145)
# Probe everything the loader should have produced; report any leftovers.
Write-CleanupLog ""
Write-CleanupLog "[*] Residual verification"
$residFiles = @()
foreach ($f in $files) { if (Test-Path -LiteralPath $f) { $residFiles += $f } }
$residTelemetry = Get-ChildItem -Path "HKCU:\Software\Classes\CLSID" -ErrorAction SilentlyContinue | Where-Object {
    $ip = Join-Path $_.PSPath "InprocServer32"
    if (Test-Path $ip) {
        $v = (Get-ItemProperty -Path $ip -Name "(default)" -ErrorAction SilentlyContinue)."(default)"
        $v -like "*Telemetry.dll*"
    } else { $false }
}
$residLnk = @()
if (Test-Path $startupPath) {
    Get-ChildItem -Path $startupPath -Filter "*.lnk" -ErrorAction SilentlyContinue | ForEach-Object {
        $shell = New-Object -ComObject WScript.Shell
        $t = $shell.CreateShortcut($_.FullName).TargetPath
        $a = $shell.CreateShortcut($_.FullName).Arguments
        if ($t -match "rundll32.exe" -and $a -match "Telemetry.dll") { $residLnk += $_.FullName }
    }
}
$residSvc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
$residWdigest = (Get-ItemProperty -Path $wdigestKey -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential
$residWdigest = if ($residWdigest -eq 1) { "UseLogonCredential=1 (NOT REVERTED)" } else { $null }

$residCount = $residFiles.Count +
    $(if ($residTelemetry) { 1 } else { 0 }) +
    $(if ($residLnk.Count -gt 0) { 1 } else { 0 }) +
    $(if ($residSvc) { 1 } else { 0 }) +
    $(if ($residWdigest) { 1 } else { 0 })

if ($residCount -eq 0) {
    Write-CleanupLog "[+] Clean: no residuals detected"
    Write-Host "[+] Clean: no residuals detected"
} else {
    Write-CleanupLog "[-] $residCount residual(s) remain:"
    $residFiles | ForEach-Object { Write-CleanupLog "    file: $_" }
    if ($residTelemetry) { Write-CleanupLog "    reg:  COM hijack CLSID -> Telemetry.dll" }
    if ($residLnk.Count -gt 0) { Write-CleanupLog "    lnk:  $($residLnk -join ', ')" }
    if ($residSvc) { Write-CleanupLog "    svc:  $serviceName" }
    if ($residWdigest) { Write-CleanupLog "    reg:  $residWdigest" }
}

# 7. Delete self (after residual summary so the report survives)
$selfPath = $MyInvocation.MyCommand.Path
Write-CleanupLog "[*] Self-delete target: $selfPath"
if (-not $WhatIf -and $selfPath -and (Test-Path $selfPath)) {
    Remove-Item -Path $selfPath -Force
    Write-CleanupLog "[-] Self-deleted: $selfPath"
}

Write-CleanupLog "[+] Cleanup complete - log at $cleanupLog"
Write-Host "[+] Cleanup complete. Report at $cleanupLog"
