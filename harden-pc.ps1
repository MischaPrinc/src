<#
.SYNOPSIS
    Interaktivni skript pro zabezpeceni domaciho PC s Windows 10/11.
.DESCRIPTION
    Nabizi hierarchicke menu s moznosti zapinat/vypinat:
      - ASR pravidla, PUA, Defender RT+Cloud, CFA, Tamper Protection
      - SmartScreen pro Windows / Microsoft Edge
      - Windows Firewall, RDP, SMBv1, LLMNR
      - AutoRun, PowerShell Script Block Logging
      - Sysmon64 instalace s pokrocilou konfiguraci
.AUTHOR
    Hack3r.cz
.NOTES
    Spoustejte jako Administrator.
#>

# ==============================================================================
#                     K O N T R O L A   A D M I N A
# ==============================================================================
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host ""
    Write-Host "  +============================================================+" -ForegroundColor Red
    Write-Host "  |   CHYBA: Tento skript musi byt spusten jako ADMINISTRATOR!  |" -ForegroundColor Red
    Write-Host "  +============================================================+" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Kliknete pravym tlacitkem na PowerShell -> Spustit jako spravce" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "  Stisknete Enter pro ukonceni"
    exit 1
}

# ==============================================================================
#                   P O M O C N E   F U N K C E
# ==============================================================================
function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 70) -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host ("=" * 70) -ForegroundColor Cyan
}

function Write-SubHeader {
    param([string]$Title, [string]$Description)
    Write-Host ""
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "  |  $($Title.PadRight(58))|" -ForegroundColor Cyan
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor Cyan
    if ($Description) {
        foreach ($line in $Description -split "`n") {
            Write-Host "  $line" -ForegroundColor DarkGray
        }
    }
    Write-Host ""
}

function Write-Status {
    param([string]$Label, [string]$Value, [ConsoleColor]$Color = 'Yellow')
    $padded = $Label.PadRight(30)
    Write-Host "  $padded : " -NoNewline
    Write-Host $Value -ForegroundColor $Color
}

function Write-MenuItem {
    param([string]$Key, [string]$Text, [ConsoleColor]$Color = 'White')
    $padKey = $Key.PadLeft(4)
    Write-Host "    ${padKey})  $Text" -ForegroundColor $Color
}

function Pause-Menu {
    Write-Host ""
    Write-Host "  Stisknete libovolnou klavesu pro navrat..." -ForegroundColor DarkGray
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Show-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  +============================================================+" -ForegroundColor Cyan
    Write-Host "  |       ZABEZPECENI DOMACIHO PC - Interaktivni nastroj        |" -ForegroundColor Cyan
    Write-Host "  |                     vytvoril: Hack3r.cz                     |" -ForegroundColor DarkCyan
    Write-Host "  +============================================================+" -ForegroundColor Cyan
}

# ==============================================================================
#          D E F I N I C E   A S R   P R A V I D E L
# ==============================================================================
$ASR_RULES = [ordered]@{
    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Blokovat zneuziti zranitelnych podepsanych ovladacu"
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Blokovat Adobe Reader - vytvareni podprocesy"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Blokovat Office - vytvareni podprocesy"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Blokovat kradez prihlasovacich udaju z LSASS"
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Blokovat spustitelny obsah z e-mailu a webmailu"
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Blokovat exe pokud nesplnuji kriteria (prevalence/vek)"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Blokovat spousteni potencialne obfuskovanych skriptu"
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "Blokovat JS/VBS spousteni stazeneho obsahu"
    "3b576869-a4ec-4529-8536-b80a7769e899" = "Blokovat Office - vytvareni spustitelneho obsahu"
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Blokovat Office - injektovani kodu do jinych procesu"
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Blokovat Office komunikacni app - podprocesy"
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Blokovat persistenci pres WMI event subscription"
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Blokovat vytvareni procesu z PSExec a WMI prikazu"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Blokovat neduveryhodne/nepodepsane procesy z USB"
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Blokovat Win32 API volani z Office maker"
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Blokovat predstirani systemovych nastroju"
    "a8f5898e-1dc8-49a9-9878-85004b8a61e6" = "Blokovat Webshell vytvareni pro servery"
    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" = "Blokovat zneuziti zranitelnych ovladacu (rozsirene)"
}

# ==============================================================================
#      G E T / S H O W / S E T   -   D E F E N D E R
# ==============================================================================

# -- ASR ----------------------------------------------------------------------
function Get-ASRStatus {
    try {
        $pref = Get-MpPreference
        $ids     = $pref.AttackSurfaceReductionRules_Ids
        $actions = $pref.AttackSurfaceReductionRules_Actions
        $result = @{}
        if ($ids) {
            for ($i = 0; $i -lt $ids.Count; $i++) {
                $result[$ids[$i].ToLower()] = $actions[$i]
            }
        }
        return $result
    } catch {
        Write-Host "  CHYBA: Nelze ziskat stav ASR pravidel." -ForegroundColor Red
        return @{}
    }
}

function Get-ASRSummary {
    $current = Get-ASRStatus
    $total   = $ASR_RULES.Count
    $blocked = ($current.Values | Where-Object { $_ -eq 1 }).Count
    $audit   = ($current.Values | Where-Object { $_ -eq 2 }).Count
    $off     = $total - $blocked - $audit
    return "Blok: $blocked | Audit: $audit | Vyp: $off ($total celkem)"
}

function Show-ASRDetail {
    Write-Header "Stav ASR pravidel"
    $current = Get-ASRStatus
    $modeMap = @{ 0 = "Vypnuto"; 1 = "Blokovat"; 2 = "Audit"; 6 = "Varovani" }
    foreach ($guid in $ASR_RULES.Keys) {
        $action = if ($current.ContainsKey($guid)) { $current[$guid] } else { 0 }
        $modeText = if ($modeMap.ContainsKey([int]$action)) { $modeMap[[int]$action] } else { "Neznamy ($action)" }
        $color = switch ([int]$action) {
            0 { 'Red' }
            1 { 'Green' }
            2 { 'Yellow' }
            6 { 'DarkYellow' }
            default { 'Gray' }
        }
        Write-Host "  [$modeText]" -ForegroundColor $color -NoNewline
        Write-Host " $($ASR_RULES[$guid])" -ForegroundColor White
    }
}

function Set-AllASR {
    param([int]$Mode)
    $modeMap = @{ 0 = "Vypnuto"; 1 = "Blokovat"; 2 = "Audit" }
    Write-Host ""
    Write-Host "  Nastavuji vsechna ASR pravidla na: $($modeMap[$Mode]) ..." -ForegroundColor Yellow
    foreach ($guid in $ASR_RULES.Keys) {
        try {
            Set-MpPreference -AttackSurfaceReductionRules_Ids $guid -AttackSurfaceReductionRules_Actions $Mode -ErrorAction Stop
            Write-Host "    [OK] $($ASR_RULES[$guid])" -ForegroundColor Green
        } catch {
            Write-Host "    [CHYBA] $($ASR_RULES[$guid]): $_" -ForegroundColor Red
        }
    }
    Write-Host "  Hotovo." -ForegroundColor Green
}

# -- PUA ----------------------------------------------------------------------
function Get-PUAStatus {
    try {
        $pua = (Get-MpPreference).PUAProtection
        switch ($pua) { 0 { "Vypnuto" } 1 { "Blokovat" } 2 { "Audit" } default { "Neznamy ($pua)" } }
    } catch { "Chyba" }
}

function Set-PUA {
    param([int]$Mode)
    $modeMap = @{ 0 = "Vypnuto"; 1 = "Blokovat"; 2 = "Audit" }
    try {
        Set-MpPreference -PUAProtection $Mode -ErrorAction Stop
        Write-Host "  PUA ochrana nastavena na: $($modeMap[$Mode])" -ForegroundColor Green
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

# -- Defender Real-Time + Cloud ------------------------------------------------
function Get-DefenderRTStatus {
    try {
        $pref  = Get-MpPreference
        $rt    = -not $pref.DisableRealtimeMonitoring
        $cloud = -not ($pref.MAPSReporting -eq 0)
        $auto  = -not ($pref.SubmitSamplesConsent -eq 0)
        $parts = @()
        if ($rt)    { $parts += "RealTime" }
        if ($cloud) { $parts += "Cloud" }
        if ($auto)  { $parts += "Samples" }
        if ($parts.Count -eq 3) { "Vse zapnuto" }
        elseif ($parts.Count -eq 0) { "Vse vypnuto" }
        else { $parts -join " + " }
    } catch { "Neznamy" }
}

function Set-DefenderRT {
    param([bool]$Enabled)
    try {
        if ($Enabled) {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction Stop
            Set-MpPreference -MAPSReporting Advanced -ErrorAction Stop
            Set-MpPreference -SubmitSamplesConsent SendAllSamples -ErrorAction Stop
            Write-Host "  Defender Real-Time + Cloud + Samples: Zapnuto" -ForegroundColor Green
        } else {
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
            Write-Host "  Defender Real-Time: Vypnuto (POZOR!)" -ForegroundColor Red
        }
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

# -- Controlled Folder Access -------------------------------------------------
function Get-CFAStatus {
    try {
        $cfa = (Get-MpPreference).EnableControlledFolderAccess
        switch ($cfa) { 0 { "Vypnuto" } 1 { "Zapnuto" } 2 { "Audit" } default { "Neznamy ($cfa)" } }
    } catch { "Neznamy" }
}

function Set-CFA {
    param([int]$Mode)
    $modeMap = @{ 0 = "Vypnuto"; 1 = "Zapnuto"; 2 = "Audit" }
    try {
        Set-MpPreference -EnableControlledFolderAccess $Mode -ErrorAction Stop
        Write-Host "  Controlled Folder Access: $($modeMap[$Mode])" -ForegroundColor Green
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

# -- Tamper Protection ---------------------------------------------------------
function Get-TamperProtectionStatus {
    try {
        $tp = (Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected
        if ($tp) { "Zapnuto" } else { "Vypnuto" }
    } catch {
        try {
            $val = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -ErrorAction Stop).TamperProtection
            switch ($val) { 5 { "Zapnuto" } 4 { "Vypnuto" } 0 { "Vypnuto" } default { "Neznamy ($val)" } }
        } catch { "Neznamy" }
    }
}

function Set-TamperProtection {
    param([bool]$Enabled)
    try {
        $val = if ($Enabled) { 5 } else { 4 }
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" -Name "TamperProtection" -Value $val -Type DWord -ErrorAction Stop
        $state = if ($Enabled) { "Zapnuto" } else { "Vypnuto" }
        Write-Host "  Tamper Protection: $state" -ForegroundColor Green
        if ($Enabled) {
            Write-Host "  POZOR: Muze vyzadovat restart nebo zapnuti pres Windows Security." -ForegroundColor Yellow
        } else {
            Write-Host "  VAROVANI: Malware muze manipulovat s Defenderem!" -ForegroundColor Red
        }
    } catch {
        Write-Host "  CHYBA: $_" -ForegroundColor Red
        Write-Host "  TIP: Nastavte pres Windows Zabezpeceni > Ochrana pred viry > Nastaveni." -ForegroundColor Yellow
    }
}

# ==============================================================================
#         G E T / S E T   -   S M A R T S C R E E N
# ==============================================================================
function Get-SmartScreenStatus {
    try {
        $val = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -ErrorAction Stop).SmartScreenEnabled
        switch ($val) { "RequireAdmin" { "Zapnuto (RequireAdmin)" } "Prompt" { "Zapnuto (Prompt)" } "Off" { "Vypnuto" } default { $val } }
    } catch { "Neznamy" }
}

function Set-SmartScreen {
    param([string]$Mode)
    try {
        Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Value $Mode -ErrorAction Stop
        Write-Host "  SmartScreen (Windows): $Mode" -ForegroundColor Green
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

function Get-EdgeSmartScreenStatus {
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
        if (-not (Test-Path $regPath)) { return "Nenastaveno (politika)" }
        $val = Get-ItemProperty -Path $regPath -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue
        if ($null -eq $val -or $null -eq $val.SmartScreenEnabled) { return "Nenastaveno (politika)" }
        if ($val.SmartScreenEnabled -eq 1) { "Zapnuto" } else { "Vypnuto" }
    } catch { "Neznamy" }
}

function Set-EdgeSmartScreen {
    param([bool]$Enabled)
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    try {
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        $val = if ($Enabled) { 1 } else { 0 }
        Set-ItemProperty -Path $regPath -Name "SmartScreenEnabled" -Value $val -Type DWord -ErrorAction Stop
        $state = if ($Enabled) { "Zapnuto" } else { "Vypnuto" }
        Write-Host "  SmartScreen (Edge): $state" -ForegroundColor Green
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

# ==============================================================================
#         G E T / S E T   -   S I T   a   P R O T O K O L Y
# ==============================================================================
function Get-FirewallStatus {
    try {
        $profiles = Get-NetFirewallProfile -ErrorAction Stop
        $allOn = ($profiles | Where-Object { $_.Enabled -eq $true }).Count -eq $profiles.Count
        if ($allOn) { "Zapnuto (vsechny profily)" }
        else {
            $on = ($profiles | Where-Object { $_.Enabled }).Name -join ", "
            if ($on) { "Castecne ($on)" } else { "Vypnuto" }
        }
    } catch { "Neznamy" }
}

function Set-FirewallState {
    param([bool]$Enabled)
    try {
        $gpoVal = if ($Enabled) { [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean]::True } else { [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.GpoBoolean]::False }
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled $gpoVal -ErrorAction Stop
        $state = if ($Enabled) { "Zapnuto" } else { "Vypnuto" }
        Write-Host "  Windows Firewall: $state (vsechny profily)" -ForegroundColor Green
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

function Get-RDPStatus {
    try {
        $val = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction Stop).fDenyTSConnections
        if ($val -eq 1) { "Zakazano (bezpecne)" } else { "Povoleno (riziko!)" }
    } catch { "Neznamy" }
}

function Set-RDPState {
    param([bool]$Disabled)
    try {
        $val = if ($Disabled) { 1 } else { 0 }
        Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value $val -Type DWord -ErrorAction Stop
        $state = if ($Disabled) { "Zakazano" } else { "Povoleno" }
        Write-Host "  Vzdalena plocha (RDP): $state" -ForegroundColor Green
        if ($Disabled) { Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue }
        else { Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue }
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

function Get-SMBv1Status {
    try {
        $smb = Get-SmbServerConfiguration -ErrorAction Stop
        if ($smb.EnableSMB1Protocol) { "Povoleno (riziko!)" } else { "Zakazano (bezpecne)" }
    } catch { "Neznamy" }
}

function Set-SMBv1State {
    param([bool]$Enabled)
    try {
        Set-SmbServerConfiguration -EnableSMB1Protocol $Enabled -Force -ErrorAction Stop
        $state = if ($Enabled) { "Povoleno" } else { "Zakazano" }
        Write-Host "  SMBv1: $state" -ForegroundColor Green
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

function Get-LLMNRStatus {
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        if (-not (Test-Path $regPath)) { return "Povoleno (vychozi)" }
        $val = Get-ItemProperty -Path $regPath -Name "EnableMulticast" -ErrorAction SilentlyContinue
        if ($null -eq $val -or $val.EnableMulticast -ne 0) { "Povoleno" } else { "Zakazano (bezpecne)" }
    } catch { "Neznamy" }
}

function Set-LLMNRState {
    param([bool]$Disabled)
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    try {
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        $val = if ($Disabled) { 0 } else { 1 }
        Set-ItemProperty -Path $regPath -Name "EnableMulticast" -Value $val -Type DWord -ErrorAction Stop
        $state = if ($Disabled) { "Zakazano" } else { "Povoleno" }
        Write-Host "  LLMNR: $state" -ForegroundColor Green
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

# ==============================================================================
#         G E T / S E T   -   S Y S T E M
# ==============================================================================
function Get-AutoRunStatus {
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (-not (Test-Path $regPath)) { return "Povoleno (vychozi)" }
        $val = Get-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
        if ($null -eq $val) { "Povoleno (vychozi)" }
        elseif ($val.NoDriveTypeAutoRun -eq 255) { "Zakazano (bezpecne)" }
        else { "Castecne ($($val.NoDriveTypeAutoRun))" }
    } catch { "Neznamy" }
}

function Set-AutoRunState {
    param([bool]$Disabled)
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    try {
        if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
        if ($Disabled) {
            Set-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -Value 255 -Type DWord -ErrorAction Stop
            Write-Host "  AutoRun/AutoPlay: Zakazano (vsechny disky)" -ForegroundColor Green
        } else {
            Remove-ItemProperty -Path $regPath -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue
            Write-Host "  AutoRun/AutoPlay: Obnoveno na vychozi" -ForegroundColor Yellow
        }
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

function Get-PSLoggingStatus {
    try {
        $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        if (-not (Test-Path $regPath)) { return "Vypnuto" }
        $val = Get-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue
        if ($null -eq $val -or $val.EnableScriptBlockLogging -ne 1) { "Vypnuto" } else { "Zapnuto" }
    } catch { "Neznamy" }
}

function Set-PSLogging {
    param([bool]$Enabled)
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    try {
        if ($Enabled) {
            if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
            Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -ErrorAction Stop
            Write-Host "  PS Script Block Logging: Zapnuto" -ForegroundColor Green
        } else {
            if (Test-Path $regPath) {
                Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 0 -Type DWord -ErrorAction Stop
            }
            Write-Host "  PS Script Block Logging: Vypnuto" -ForegroundColor Yellow
        }
    } catch { Write-Host "  CHYBA: $_" -ForegroundColor Red }
}

# ==============================================================================
#                          S Y S M O N
# ==============================================================================
$SysmonExeUrl     = "https://live.sysinternals.com/Sysmon64.exe"
$SysmonConfigUrl  = "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig-mde-augment.xml"
$SysmonDir        = "$env:ProgramData\Sysmon"
$SysmonExePath    = "$SysmonDir\Sysmon64.exe"
$SysmonConfigPath = "$SysmonDir\sysmonconfig.xml"

function Get-SysmonStatus {
    $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if (-not $svc) { $svc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }
    if ($svc) {
        if ($svc.Status -eq "Running") { "Bezi ($($svc.Name))" }
        else { "Zastaveny ($($svc.Status))" }
    } else { "Nenainstalovan" }
}

function Install-Sysmon {
    Write-Host ""
    Write-Host "  -- Instalace Sysmon64 --" -ForegroundColor Cyan

    if (-not (Test-Path $SysmonDir)) {
        New-Item -Path $SysmonDir -ItemType Directory -Force | Out-Null
        Write-Host "  Vytvoren adresar: $SysmonDir" -ForegroundColor Green
    }

    Write-Host "  Stahuji Sysmon64.exe z live.sysinternals.com ..." -ForegroundColor Yellow
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $SysmonExeUrl -OutFile $SysmonExePath -UseBasicParsing -ErrorAction Stop
        Write-Host "  [OK] Sysmon64.exe stazen" -ForegroundColor Green
    } catch {
        Write-Host "  [CHYBA] Nelze stahnout Sysmon64.exe: $_" -ForegroundColor Red
        return
    }

    Write-Host "  Stahuji konfiguraci (sysmon-modular by Olaf Hartong) ..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri $SysmonConfigUrl -OutFile $SysmonConfigPath -UseBasicParsing -ErrorAction Stop
        Write-Host "  [OK] Konfigurace stazena" -ForegroundColor Green
    } catch {
        Write-Host "  [CHYBA] Nelze stahnout konfiguraci: $_" -ForegroundColor Red
        return
    }

    $existingSvc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if (-not $existingSvc) { $existingSvc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }
    if ($existingSvc) {
        Write-Host "  Odinstalovavam starsi verzi Sysmon ..." -ForegroundColor Yellow
        & $SysmonExePath -u force 2>$null
        Start-Sleep -Seconds 2
    }

    Write-Host "  Instaluji Sysmon64 s konfiguraci ..." -ForegroundColor Yellow
    try {
        $proc = Start-Process -FilePath $SysmonExePath -ArgumentList "-accepteula -i `"$SysmonConfigPath`"" -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -eq 0) {
            Write-Host "  [OK] Sysmon64 nainstalovan a bezi!" -ForegroundColor Green
            Write-Host "  Logy: Event Viewer -> Microsoft-Windows-Sysmon/Operational" -ForegroundColor DarkGray
        } else {
            Write-Host "  [VAROVANI] Sysmon se vratil s kodem: $($proc.ExitCode)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [CHYBA] Instalace selhala: $_" -ForegroundColor Red
    }
}

function Update-SysmonConfig {
    Write-Host ""
    Write-Host "  -- Aktualizace konfigurace Sysmon --" -ForegroundColor Cyan

    $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
    if (-not $svc) { $svc = Get-Service -Name "Sysmon" -ErrorAction SilentlyContinue }
    if (-not $svc) {
        Write-Host "  Sysmon neni nainstalovan. Nejprve ho nainstalujte." -ForegroundColor Red
        return
    }

    if (-not (Test-Path $SysmonDir)) { New-Item -Path $SysmonDir -ItemType Directory -Force | Out-Null }

    Write-Host "  Stahuji nejnovejsi konfiguraci ..." -ForegroundColor Yellow
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $SysmonConfigUrl -OutFile $SysmonConfigPath -UseBasicParsing -ErrorAction Stop
        Write-Host "  [OK] Konfigurace stazena" -ForegroundColor Green
    } catch {
        Write-Host "  [CHYBA] Nelze stahnout konfiguraci: $_" -ForegroundColor Red
        return
    }

    $sysmonPath = $SysmonExePath
    if (-not (Test-Path $sysmonPath)) {
        $sysmonPath = (Get-Command Sysmon64.exe -ErrorAction SilentlyContinue).Source
        if (-not $sysmonPath) { $sysmonPath = (Get-Command Sysmon.exe -ErrorAction SilentlyContinue).Source }
    }
    if (-not $sysmonPath) {
        Write-Host "  [CHYBA] Nelze najit Sysmon64.exe" -ForegroundColor Red
        return
    }

    Write-Host "  Aplikuji konfiguraci ..." -ForegroundColor Yellow
    try {
        $proc = Start-Process -FilePath $sysmonPath -ArgumentList "-c `"$SysmonConfigPath`"" -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -eq 0) {
            Write-Host "  [OK] Konfigurace aktualizovana!" -ForegroundColor Green
        } else {
            Write-Host "  [VAROVANI] Kod: $($proc.ExitCode)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [CHYBA]: $_" -ForegroundColor Red
    }
}

function Uninstall-Sysmon {
    Write-Host ""
    Write-Host "  -- Odinstalace Sysmon --" -ForegroundColor Cyan

    $sysmonPath = $SysmonExePath
    if (-not (Test-Path $sysmonPath)) {
        $sysmonPath = (Get-Command Sysmon64.exe -ErrorAction SilentlyContinue).Source
        if (-not $sysmonPath) { $sysmonPath = (Get-Command Sysmon.exe -ErrorAction SilentlyContinue).Source }
    }
    if (-not $sysmonPath) {
        Write-Host "  Sysmon nebyl nalezen." -ForegroundColor Yellow
        return
    }

    try {
        $proc = Start-Process -FilePath $sysmonPath -ArgumentList "-u force" -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -eq 0) {
            Write-Host "  [OK] Sysmon odinstalovany." -ForegroundColor Green
        } else {
            Write-Host "  [VAROVANI] Kod: $($proc.ExitCode)" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  [CHYBA]: $_" -ForegroundColor Red
    }
}

# ==============================================================================
#              G E T / S E T   -   B E Z P E C N E   D N S
# ==============================================================================
# Cloudflare DNS varianty:
#   1.1.1.1 / 1.0.0.1          = Standardni (rychle, soukrome)
#   1.1.1.2 / 1.0.0.2          = Malware Blocking (blokuje skodlive domeny)
#   1.1.1.3 / 1.0.0.3          = Malware + Adult Content (blokuje skodlive + obsah pro dospele)

$DNS_PROFILES = [ordered]@{
    "cloudflare_malware" = @{
        Name     = "Cloudflare - Blokace malware"
        Primary  = "1.1.1.2"
        Secondary = "1.0.0.2"
        Info     = "Blokuje pristup ke znamym skodlivym domenam (phishing, malware C2)."
    }
    "cloudflare_family" = @{
        Name     = "Cloudflare - Blokace malware + obsah pro dospele"
        Primary  = "1.1.1.3"
        Secondary = "1.0.0.3"
        Info     = "Blokuje malware domeny + obsah pro dospele (family filter)."
    }
    "cloudflare_standard" = @{
        Name     = "Cloudflare - Standardni (bez filtrace)"
        Primary  = "1.1.1.1"
        Secondary = "1.0.0.1"
        Info     = "Rychle a soukrome DNS bez filtrace obsahu."
    }
}

function Get-ActiveNetAdapters {
    Get-NetAdapter -Physical -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq "Up" }
}

function Get-DNSStatus {
    try {
        $adapters = Get-ActiveNetAdapters
        if (-not $adapters) { return "Zadny aktivni adapter" }
        $results = @()
        foreach ($adapter in $adapters) {
            $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
            $servers = $dns.ServerAddresses
            if ($servers) {
                $label = "$($adapter.Name): $($servers -join ', ')"
                # Rozpoznej profil
                foreach ($key in $DNS_PROFILES.Keys) {
                    $prof = $DNS_PROFILES[$key]
                    if ($servers -contains $prof.Primary) {
                        $label = "$($adapter.Name): $($prof.Name) ($($servers -join ', '))"
                        break
                    }
                }
                $results += $label
            } else {
                $results += "$($adapter.Name): DHCP (automaticky)"
            }
        }
        return ($results -join " | ")
    } catch { "Neznamy" }
}

function Get-DNSStatusShort {
    try {
        $adapters = Get-ActiveNetAdapters
        if (-not $adapters) { return "Zadny adapter" }
        $adapter = $adapters | Select-Object -First 1
        $dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $servers = $dns.ServerAddresses
        if (-not $servers -or $servers.Count -eq 0) { return "DHCP (auto)" }
        foreach ($key in $DNS_PROFILES.Keys) {
            $prof = $DNS_PROFILES[$key]
            if ($servers -contains $prof.Primary) {
                return "$($prof.Primary)/$($prof.Secondary)"
            }
        }
        return ($servers -join ", ")
    } catch { "Neznamy" }
}

function Show-DNSDetail {
    Write-Header "Aktualni DNS na vsech adapterech"
    $adapters = Get-ActiveNetAdapters
    if (-not $adapters) {
        Write-Host "  Zadny aktivni sitovy adapter." -ForegroundColor Red
        return
    }
    foreach ($adapter in $adapters) {
        $dns4 = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $dns6 = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue
        Write-Host ""
        Write-Host "  Adapter: $($adapter.Name) ($($adapter.InterfaceDescription))" -ForegroundColor White
        if ($dns4.ServerAddresses) {
            Write-Host "    IPv4 DNS: $($dns4.ServerAddresses -join ', ')" -ForegroundColor Cyan
        } else {
            Write-Host "    IPv4 DNS: DHCP (automaticky)" -ForegroundColor Yellow
        }
        if ($dns6.ServerAddresses) {
            Write-Host "    IPv6 DNS: $($dns6.ServerAddresses -join ', ')" -ForegroundColor Cyan
        }
    }
}

function Set-SecureDNS {
    param([string]$ProfileKey)
    $prof = $DNS_PROFILES[$ProfileKey]
    if (-not $prof) {
        Write-Host "  CHYBA: Neznamy DNS profil." -ForegroundColor Red
        return
    }
    $adapters = Get-ActiveNetAdapters
    if (-not $adapters) {
        Write-Host "  CHYBA: Zadny aktivni sitovy adapter." -ForegroundColor Red
        return
    }
    Write-Host ""
    Write-Host "  Nastavuji DNS: $($prof.Name)" -ForegroundColor Yellow
    Write-Host "  Servery: $($prof.Primary), $($prof.Secondary)" -ForegroundColor DarkGray
    foreach ($adapter in $adapters) {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @($prof.Primary, $prof.Secondary) -ErrorAction Stop
            Write-Host "    [OK] $($adapter.Name)" -ForegroundColor Green
        } catch {
            Write-Host "    [CHYBA] $($adapter.Name): $_" -ForegroundColor Red
        }
    }
    Write-Host "  Hotovo." -ForegroundColor Green
}

function Reset-DNS {
    $adapters = Get-ActiveNetAdapters
    if (-not $adapters) {
        Write-Host "  CHYBA: Zadny aktivni sitovy adapter." -ForegroundColor Red
        return
    }
    Write-Host ""
    Write-Host "  Resetuji DNS na automaticke (DHCP) ..." -ForegroundColor Yellow
    foreach ($adapter in $adapters) {
        try {
            Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses -ErrorAction Stop
            Write-Host "    [OK] $($adapter.Name) - DHCP" -ForegroundColor Green
        } catch {
            Write-Host "    [CHYBA] $($adapter.Name): $_" -ForegroundColor Red
        }
    }
    Write-Host "  Hotovo." -ForegroundColor Green
}

# ==============================================================================
#    V O L B A   9 9   -   K O M P L E T N I   P R E H L E D
# ==============================================================================
function Show-FullStatus {
    Show-Banner
    Write-Header "KOMPLETNI PREHLED ZABEZPECENI"

    function Get-StatusColor([string]$Value) {
        if ($Value -match "Zapnuto|Blokovat|Zakazano \(bezpecne\)|Bezi|Vse zapnuto") { 'Green' }
        elseif ($Value -match "Vypnuto|Povoleno \(riziko|Vse vypnuto|Nenainstalovan") { 'Red' }
        else { 'Yellow' }
    }

    Write-Host ""
    Write-Host "  -- DEFENDER a ASR -------------------------------------------------" -ForegroundColor Magenta
    $v = Get-DefenderRTStatus;        Write-Status "Defender (RT+Cloud+Samples)" $v (Get-StatusColor $v)
    $v = Get-TamperProtectionStatus;  Write-Status "Tamper Protection"           $v (Get-StatusColor $v)
    $v = Get-PUAStatus;               Write-Status "PUA ochrana"                 $v (Get-StatusColor $v)
    $v = Get-CFAStatus;               Write-Status "Controlled Folder Access"    $v (Get-StatusColor $v)

    Write-Host ""
    Write-Host "  ASR pravidla:" -ForegroundColor White
    $current = Get-ASRStatus
    $modeMap = @{ 0 = "Vypnuto"; 1 = "Blokovat"; 2 = "Audit"; 6 = "Varovani" }
    foreach ($guid in $ASR_RULES.Keys) {
        $action = if ($current.ContainsKey($guid)) { $current[$guid] } else { 0 }
        $modeText = if ($modeMap.ContainsKey([int]$action)) { $modeMap[[int]$action] } else { "?" }
        $color = switch ([int]$action) { 0 { 'Red' } 1 { 'Green' } 2 { 'Yellow' } default { 'Gray' } }
        $desc = $ASR_RULES[$guid]
        if ($desc.Length -gt 58) { $desc = $desc.Substring(0,55) + "..." }
        Write-Host "    [$modeText]" -ForegroundColor $color -NoNewline
        Write-Host " $desc" -ForegroundColor White
    }

    Write-Host ""
    Write-Host "  -- SMARTSCREEN ----------------------------------------------------" -ForegroundColor Magenta
    $v = Get-SmartScreenStatus;       Write-Status "SmartScreen (Windows)"       $v (Get-StatusColor $v)
    $v = Get-EdgeSmartScreenStatus;   Write-Status "SmartScreen (Edge)"          $v (Get-StatusColor $v)

    Write-Host ""
    Write-Host "  -- SIT a PROTOKOLY ------------------------------------------------" -ForegroundColor Magenta
    $v = Get-FirewallStatus;          Write-Status "Windows Firewall"            $v (Get-StatusColor $v)
    $v = Get-RDPStatus;               Write-Status "Vzdalena plocha (RDP)"       $v (Get-StatusColor $v)
    $v = Get-SMBv1Status;             Write-Status "SMBv1 protokol"              $v (Get-StatusColor $v)
    $v = Get-LLMNRStatus;             Write-Status "LLMNR"                       $v (Get-StatusColor $v)

    Write-Host ""
    Write-Host "  -- SYSTEM a LOGGING -----------------------------------------------" -ForegroundColor Magenta
    $v = Get-AutoRunStatus;           Write-Status "AutoRun / AutoPlay"          $v (Get-StatusColor $v)
    $v = Get-PSLoggingStatus;         Write-Status "PS Script Block Logging"     $v (Get-StatusColor $v)

    Write-Host ""
    Write-Host "  -- DNS ----------------------------------------------------------------" -ForegroundColor Magenta
    $dnsInfo = Get-DNSStatus
    Write-Status "DNS servery" $dnsInfo 'Cyan'

    Write-Host ""
    Write-Host "  -- MONITORING -----------------------------------------------------" -ForegroundColor Magenta
    $v = Get-SysmonStatus;            Write-Status "Sysmon"                      $v (Get-StatusColor $v)

    Write-Host ""
}

# ==============================================================================
#           Z A P N O U T   V S E   N A   M A X I M U M
# ==============================================================================
function Enable-MaxSecurity {
    Write-Header "Zapinam MAXIMUM zabezpeceni"
    Write-Host ""
    Set-AllASR -Mode 1
    Set-PUA -Mode 1
    Set-DefenderRT -Enabled $true
    Set-CFA -Mode 1
    # Tamper Protection - casto nelze menit pres registr, jen informujeme
    $tpSt = Get-TamperProtectionStatus
    if ($tpSt -eq "Zapnuto") {
        Write-Host "  Tamper Protection: jiz Zapnuto" -ForegroundColor Green
    } else {
        Write-Host "  Tamper Protection: Nelze nastavit skriptem - Windows ho chrani." -ForegroundColor Yellow
        Write-Host "  -> Zapnete rucne: Windows Zabezpeceni > Ochrana pred viry > Nastaveni" -ForegroundColor Yellow
    }
    Set-SmartScreen -Mode "RequireAdmin"
    Set-EdgeSmartScreen -Enabled $true
    Set-FirewallState -Enabled $true
    Set-RDPState -Disabled $true
    Set-SMBv1State -Enabled $false
    Set-LLMNRState -Disabled $true
    Set-AutoRunState -Disabled $true
    Set-PSLogging -Enabled $true
    Set-SecureDNS -ProfileKey "cloudflare_malware"
    Write-Host ""
    Write-Host "  *** Vse nastaveno na maximalni ochranu! ***" -ForegroundColor Green
}

# ==============================================================================
#                      S U B - M E N U
# ==============================================================================

# -- 1) Defender a ASR ---------------------------------------------------------
function Show-Menu-DefenderASR {
    do {
        Show-Banner
        Write-SubHeader "DEFENDER a ASR" @"
  Windows Defender je vestaveny antivir ve Windows. ASR (Attack Surface
  Reduction) pravidla blokuji bezne techniky utoku - makra, skripty,
  kradeze credentials, exploit ovladacu apod. PUA blokuje nezadouci
  aplikace. CFA chrani slozky pred ransomware. Tamper Protection brani
  malwaru vypnout ochranu Defenderu.
"@

        $asrSum = Get-ASRSummary
        $puaSt  = Get-PUAStatus
        $rtSt   = Get-DefenderRTStatus
        $cfaSt  = Get-CFAStatus
        $tpSt   = Get-TamperProtectionStatus

        Write-Host "  Aktualni stav:" -ForegroundColor DarkGray
        Write-Host "    ASR: $asrSum" -ForegroundColor DarkGray
        Write-Host "    PUA: $puaSt | RT+Cloud: $rtSt | CFA: $cfaSt | Tamper: $tpSt" -ForegroundColor DarkGray
        Write-Host ""

        Write-MenuItem "1"  "ASR pravidla -> Zobrazit detail vsech pravidel"
        Write-MenuItem "2"  "ASR pravidla -> Nastavit VSECHNA na BLOKOVAT"
        Write-MenuItem "3"  "ASR pravidla -> Nastavit VSECHNA na AUDIT"
        Write-MenuItem "4"  "ASR pravidla -> VYPNOUT VSECHNA"
        Write-Host ""
        Write-MenuItem "5"  "PUA ochrana -> BLOKOVAT"
        Write-MenuItem "6"  "PUA ochrana -> AUDIT"
        Write-MenuItem "7"  "PUA ochrana -> VYPNOUT"
        Write-Host ""
        Write-MenuItem "8"  "Defender Real-Time + Cloud -> ZAPNOUT"
        Write-MenuItem "9"  "Defender Real-Time -> VYPNOUT"
        Write-Host ""
        Write-MenuItem "10" "Controlled Folder Access -> ZAPNOUT"
        Write-MenuItem "11" "Controlled Folder Access -> AUDIT"
        Write-MenuItem "12" "Controlled Folder Access -> VYPNOUT"
        Write-Host ""
        Write-MenuItem "13" "Tamper Protection -> ZAPNOUT"
        Write-MenuItem "14" "Tamper Protection -> VYPNOUT"
        Write-Host ""
        Write-MenuItem "0"  "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-Host "  Vyberte volbu"
        switch ($c) {
            "1"  { Show-ASRDetail; Pause-Menu }
            "2"  { Set-AllASR -Mode 1; Pause-Menu }
            "3"  { Set-AllASR -Mode 2; Pause-Menu }
            "4"  { Set-AllASR -Mode 0; Pause-Menu }
            "5"  { Set-PUA -Mode 1; Pause-Menu }
            "6"  { Set-PUA -Mode 2; Pause-Menu }
            "7"  { Set-PUA -Mode 0; Pause-Menu }
            "8"  { Set-DefenderRT -Enabled $true; Pause-Menu }
            "9"  { Set-DefenderRT -Enabled $false; Pause-Menu }
            "10" { Set-CFA -Mode 1; Pause-Menu }
            "11" { Set-CFA -Mode 2; Pause-Menu }
            "12" { Set-CFA -Mode 0; Pause-Menu }
            "13" { Set-TamperProtection -Enabled $true; Pause-Menu }
            "14" { Set-TamperProtection -Enabled $false; Pause-Menu }
            "0"  { return }
            default { Write-Host "  Neplatna volba." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# -- 2) SmartScreen ------------------------------------------------------------
function Show-Menu-SmartScreen {
    do {
        Show-Banner
        Write-SubHeader "SMARTSCREEN" @"
  SmartScreen chrani pred stahovanim a spoustenim skodlivych souboru,
  phishingem a nebezpecnymi webovymi strankami. Funguje na urovni
  systemu Windows (Explorer) i v prohlizeci Microsoft Edge.
"@

        $ssSt = Get-SmartScreenStatus
        $esSt = Get-EdgeSmartScreenStatus
        Write-Host "  Aktualni stav:" -ForegroundColor DarkGray
        Write-Host "    Windows: $ssSt | Edge: $esSt" -ForegroundColor DarkGray
        Write-Host ""

        Write-MenuItem "1" "SmartScreen (Windows) -> ZAPNOUT"
        Write-MenuItem "2" "SmartScreen (Windows) -> VYPNOUT"
        Write-Host ""
        Write-MenuItem "3" "SmartScreen (Edge) -> ZAPNOUT"
        Write-MenuItem "4" "SmartScreen (Edge) -> VYPNOUT"
        Write-Host ""
        Write-MenuItem "0" "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-Host "  Vyberte volbu"
        switch ($c) {
            "1" { Set-SmartScreen -Mode "RequireAdmin"; Pause-Menu }
            "2" { Set-SmartScreen -Mode "Off"; Pause-Menu }
            "3" { Set-EdgeSmartScreen -Enabled $true; Pause-Menu }
            "4" { Set-EdgeSmartScreen -Enabled $false; Pause-Menu }
            "0" { return }
            default { Write-Host "  Neplatna volba." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# -- 3) Sit a Protokoly -------------------------------------------------------
function Show-Menu-Network {
    do {
        Show-Banner
        Write-SubHeader "SIT a PROTOKOLY" @"
  Firewall filtruje sitovy provoz a blokuje neopravnene pripojeni.
  RDP (vzdalena plocha) je casty cil brute-force utoku - doma zbytecny.
  SMBv1 je zastaraly protokol (WannaCry, EternalBlue) - zakazte ho.
  LLMNR umoznuje poisoning utoky v lokalni siti (Responder apod.).
"@

        $fwSt    = Get-FirewallStatus
        $rdpSt   = Get-RDPStatus
        $smbSt   = Get-SMBv1Status
        $llmnrSt = Get-LLMNRStatus
        Write-Host "  Aktualni stav:" -ForegroundColor DarkGray
        Write-Host "    Firewall: $fwSt" -ForegroundColor DarkGray
        Write-Host "    RDP: $rdpSt | SMBv1: $smbSt | LLMNR: $llmnrSt" -ForegroundColor DarkGray
        Write-Host ""

        Write-MenuItem "1" "Windows Firewall -> ZAPNOUT"
        Write-MenuItem "2" "Windows Firewall -> VYPNOUT"
        Write-Host ""
        Write-MenuItem "3" "Vzdalena plocha (RDP) -> ZAKAZAT"
        Write-MenuItem "4" "Vzdalena plocha (RDP) -> POVOLIT"
        Write-Host ""
        Write-MenuItem "5" "SMBv1 -> ZAKAZAT"
        Write-MenuItem "6" "SMBv1 -> POVOLIT"
        Write-Host ""
        Write-MenuItem "7" "LLMNR -> ZAKAZAT"
        Write-MenuItem "8" "LLMNR -> POVOLIT"
        Write-Host ""
        Write-MenuItem "0" "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-Host "  Vyberte volbu"
        switch ($c) {
            "1" { Set-FirewallState -Enabled $true; Pause-Menu }
            "2" { Set-FirewallState -Enabled $false; Pause-Menu }
            "3" { Set-RDPState -Disabled $true; Pause-Menu }
            "4" { Set-RDPState -Disabled $false; Pause-Menu }
            "5" { Set-SMBv1State -Enabled $false; Pause-Menu }
            "6" { Set-SMBv1State -Enabled $true; Pause-Menu }
            "7" { Set-LLMNRState -Disabled $true; Pause-Menu }
            "8" { Set-LLMNRState -Disabled $false; Pause-Menu }
            "0" { return }
            default { Write-Host "  Neplatna volba." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# -- 4) System a Logging ------------------------------------------------------
function Show-Menu-System {
    do {
        Show-Banner
        Write-SubHeader "SYSTEM a LOGGING" @"
  AutoRun/AutoPlay automaticky spousti obsah z USB/CD - oblibeny vektor
  sireni malwaru. Zakazanim zabranite automatickemu spusteni.
  PowerShell Script Block Logging zaznamenava vsechny spustene PS skripty
  do Event Logu - klicove pro forenzni analyzu a detekci utoku.
"@

        $arSt = Get-AutoRunStatus
        $psSt = Get-PSLoggingStatus
        Write-Host "  Aktualni stav:" -ForegroundColor DarkGray
        Write-Host "    AutoRun: $arSt | PS Logging: $psSt" -ForegroundColor DarkGray
        Write-Host ""

        Write-MenuItem "1" "AutoRun/AutoPlay -> ZAKAZAT"
        Write-MenuItem "2" "AutoRun/AutoPlay -> POVOLIT"
        Write-Host ""
        Write-MenuItem "3" "PS Script Block Logging -> ZAPNOUT"
        Write-MenuItem "4" "PS Script Block Logging -> VYPNOUT"
        Write-Host ""
        Write-MenuItem "0" "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-Host "  Vyberte volbu"
        switch ($c) {
            "1" { Set-AutoRunState -Disabled $true; Pause-Menu }
            "2" { Set-AutoRunState -Disabled $false; Pause-Menu }
            "3" { Set-PSLogging -Enabled $true; Pause-Menu }
            "4" { Set-PSLogging -Enabled $false; Pause-Menu }
            "0" { return }
            default { Write-Host "  Neplatna volba." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# -- 5) Sysmon ----------------------------------------------------------------
function Show-Menu-Sysmon {
    do {
        Show-Banner
        Write-SubHeader "SYSMON - System Monitor" @"
  Sysmon (Sysinternals) je pokrocily monitoring systemovych udalosti -
  sleduje vytvareni procesu, sitova pripojeni, zmeny souboru, registry
  a dalsi. Konfigurace 'sysmon-modular' od Olafa Hartonga je komunitne
  udrzovana sada pravidel optimalizovana pro detekci hrozeb.
  Logy: Event Viewer -> Microsoft-Windows-Sysmon/Operational
"@

        $sysSt = Get-SysmonStatus
        Write-Host "  Aktualni stav:" -ForegroundColor DarkGray
        Write-Host "    Sysmon: $sysSt" -ForegroundColor DarkGray
        Write-Host ""

        Write-MenuItem "1" "Instalovat Sysmon64 + konfigurace (stahne z internetu)"
        Write-MenuItem "2" "Aktualizovat konfiguraci (stahne nejnovejsi pravidla)"
        Write-MenuItem "3" "Odinstalovat Sysmon"
        Write-Host ""
        Write-MenuItem "0" "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-Host "  Vyberte volbu"
        switch ($c) {
            "1" { Install-Sysmon; Pause-Menu }
            "2" { Update-SysmonConfig; Pause-Menu }
            "3" { Uninstall-Sysmon; Pause-Menu }
            "0" { return }
            default { Write-Host "  Neplatna volba." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# -- 6) Bezpecne DNS ----------------------------------------------------------
function Show-Menu-DNS {
    do {
        Show-Banner
        Write-SubHeader "BEZPECNE DNS" @"
  DNS (Domain Name System) preklada jmena webovych stranek na IP adresy.
  Bezpecne DNS servery mohou blokovat pristup ke skodlivym domenam
  (phishing, malware, C2 servery) nebo i obsah pro dospele.
  Cloudflare 1.1.1.2/1.0.0.2 blokuje malware domeny.
  Cloudflare 1.1.1.3/1.0.0.3 blokuje malware + obsah pro dospele.
"@

        Write-Host "  Aktualni DNS:" -ForegroundColor DarkGray
        Show-DNSDetail
        Write-Host ""

        Write-MenuItem "1" "Zobrazit detail DNS na vsech adapterech"
        Write-Host ""
        Write-Host "    Nastavit DNS profil:" -ForegroundColor Cyan
        Write-MenuItem "2" "Cloudflare 1.1.1.2 / 1.0.0.2 - Blokace malware" Green
        Write-MenuItem "3" "Cloudflare 1.1.1.3 / 1.0.0.3 - Blokace malware + dospely obsah" Green
        Write-MenuItem "4" "Cloudflare 1.1.1.1 / 1.0.0.1 - Standardni (bez filtrace)"
        Write-Host ""
        Write-MenuItem "5" "Resetovat DNS na automaticke (DHCP)" Yellow
        Write-Host ""
        Write-MenuItem "0" "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-Host "  Vyberte volbu"
        switch ($c) {
            "1" { Show-DNSDetail; Pause-Menu }
            "2" { Set-SecureDNS -ProfileKey "cloudflare_malware"; Pause-Menu }
            "3" { Set-SecureDNS -ProfileKey "cloudflare_family"; Pause-Menu }
            "4" { Set-SecureDNS -ProfileKey "cloudflare_standard"; Pause-Menu }
            "5" { Reset-DNS; Pause-Menu }
            "0" { return }
            default { Write-Host "  Neplatna volba." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# ==============================================================================
#                       H L A V N I   M E N U
# ==============================================================================
do {
    Show-Banner
    Write-Host ""
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "  |                      HLAVNI MENU                           |" -ForegroundColor Cyan
    Write-Host "  +------------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host ""

    # Quick-status
    $rtQ  = Get-DefenderRTStatus
    $asrQ = Get-ASRSummary
    $ssQ  = Get-SmartScreenStatus
    $fwQ  = Get-FirewallStatus
    $syQ  = Get-SysmonStatus
    $arQ  = Get-AutoRunStatus
    $psQ  = Get-PSLoggingStatus
    $dnsQ = Get-DNSStatusShort

    $rtC  = if ($rtQ -eq "Vse zapnuto") { 'Green' } elseif ($rtQ -eq "Vse vypnuto") { 'Red' } else { 'Yellow' }
    $ssC  = if ($ssQ -match "Zapnuto") { 'Green' } elseif ($ssQ -eq "Vypnuto") { 'Red' } else { 'Yellow' }
    $fwC  = if ($fwQ -match "Zapnuto") { 'Green' } elseif ($fwQ -eq "Vypnuto") { 'Red' } else { 'Yellow' }
    $syC  = if ($syQ -match "Bezi") { 'Green' } elseif ($syQ -match "Nenainstalovan") { 'Red' } else { 'Yellow' }
    $arC  = if ($arQ -match "Zakazano") { 'Green' } elseif ($arQ -match "Povoleno") { 'Red' } else { 'Yellow' }
    $psC  = if ($psQ -eq "Zapnuto") { 'Green' } else { 'Red' }

    Write-Host "    1)  Defender a ASR" -ForegroundColor White -NoNewline
    Write-Host "           [RT: " -NoNewline -ForegroundColor DarkGray
    Write-Host "$rtQ" -NoNewline -ForegroundColor $rtC
    Write-Host "]" -ForegroundColor DarkGray
    Write-Host "        ASR: $asrQ" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "    2)  SmartScreen" -ForegroundColor White -NoNewline
    Write-Host "              [" -NoNewline -ForegroundColor DarkGray
    Write-Host "$ssQ" -NoNewline -ForegroundColor $ssC
    Write-Host "]" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "    3)  Sit a Protokoly" -ForegroundColor White -NoNewline
    Write-Host "          [FW: " -NoNewline -ForegroundColor DarkGray
    Write-Host "$fwQ" -NoNewline -ForegroundColor $fwC
    Write-Host "]" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "    4)  System a Logging" -ForegroundColor White -NoNewline
    Write-Host "         [AutoRun: " -NoNewline -ForegroundColor DarkGray
    Write-Host "$arQ" -NoNewline -ForegroundColor $arC
    Write-Host " | PS: " -NoNewline -ForegroundColor DarkGray
    Write-Host "$psQ" -NoNewline -ForegroundColor $psC
    Write-Host "]" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "    5)  Sysmon" -ForegroundColor White -NoNewline
    Write-Host "                    [" -NoNewline -ForegroundColor DarkGray
    Write-Host "$syQ" -NoNewline -ForegroundColor $syC
    Write-Host "]" -ForegroundColor DarkGray
    Write-Host ""

    $dnsC = if ($dnsQ -match "1\.1\.1\.[23]") { 'Green' } elseif ($dnsQ -match "DHCP|auto") { 'Yellow' } else { 'Cyan' }
    Write-Host "    6)  Bezpecne DNS" -ForegroundColor White -NoNewline
    Write-Host "               [" -NoNewline -ForegroundColor DarkGray
    Write-Host "$dnsQ" -NoNewline -ForegroundColor $dnsC
    Write-Host "]" -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "   10)  ZAPNOUT VSE (maximum zabezpeceni)" -ForegroundColor Green
    Write-Host "   99)  Aktualni stav - kompletni prehled" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    0)  Konec" -ForegroundColor Yellow
    Write-Host ""

    $mainChoice = Read-Host "  Vyberte volbu"

    switch ($mainChoice) {
        "1"  { Show-Menu-DefenderASR }
        "2"  { Show-Menu-SmartScreen }
        "3"  { Show-Menu-Network }
        "4"  { Show-Menu-System }
        "5"  { Show-Menu-Sysmon }
        "6"  { Show-Menu-DNS }
        "10" { Enable-MaxSecurity; Pause-Menu }
        "99" { Show-FullStatus; Pause-Menu }
        "0"  {
            Write-Host ""
            Write-Host "  Ukoncuji. Zustan v bezpeci! - Hack3r.cz" -ForegroundColor Cyan
            Write-Host ""
        }
        default {
            Write-Host "  Neplatna volba, zkuste znovu." -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($mainChoice -ne "0")
