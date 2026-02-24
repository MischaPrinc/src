<#
.SYNOPSIS
    Interaktivni nastroj pro Application Whitelisting (WDAC) a Macro Whitelisting.
.DESCRIPTION
    Spravuje:
      - WDAC (Windows Defender Application Control) politiky
        - DefaultWindows politika (povoluje jen to co je soucasti Windows)
        - Audit / Enforce mod
        - Vlastni pravidla (cesta, publisher, hash)
        - Merge politik
      - Office Macro Whitelisting
        - Blokovani vsech maker krome podepsanych
        - Sprava Trusted Locations
        - Sprava Trusted Publishers
        - Zobrazeni stavu
.AUTHOR
    Hack3r.cz
.NOTES
    Spoustejte jako Administrator.
    WDAC vyzaduje Windows 10/11 Pro nebo vyssi.
    Office makro nastaveni vyzaduje nainstalovany Microsoft Office.
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
    $padded = $Label.PadRight(35)
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
    Write-Host "  |   APPLICATION + MACRO WHITELISTING - Interaktivni nastroj   |" -ForegroundColor Cyan
    Write-Host "  |                     vytvoril: Hack3r.cz                     |" -ForegroundColor DarkCyan
    Write-Host "  +============================================================+" -ForegroundColor Cyan
}

# ==============================================================================
#                          W D A C   K O N S T A N T Y
# ==============================================================================
$WDACPolicyDir      = "$env:ProgramData\WDACPolicies"
$WDACDefaultXml     = "$WDACPolicyDir\DefaultPolicy.xml"
$WDACCustomXml      = "$WDACPolicyDir\CustomRules.xml"
$WDACMergedXml      = "$WDACPolicyDir\MergedPolicy.xml"
$WDACCompiledBin    = "$WDACPolicyDir\MergedPolicy.bin"
$WDACDeployedPath   = "$env:windir\System32\CodeIntegrity\SIPolicy.p7b"

# ==============================================================================
#        W D A C   -   S T A V   a   I N F O R M A C E
# ==============================================================================
function Get-WDACStatus {
    try {
        $ci = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard" -ErrorAction Stop
        $status = $ci.CodeIntegrityPolicyEnforcementStatus
        # 0 = Off, 1 = Audit, 2 = Enforced
        switch ($status) {
            0 { "Vypnuto" }
            1 { "Audit mod" }
            2 { "Enforce mod (aktivni!)" }
            default { "Neznamy ($status)" }
        }
    } catch {
        # Alternativni detekce - existuje soubor politiky?
        if (Test-Path $WDACDeployedPath) {
            "Nasazeno (nelze zjistit mod)"
        } else {
            "Vypnuto"
        }
    }
}

function Get-WDACStatusShort {
    try {
        $ci = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace "root\Microsoft\Windows\DeviceGuard" -ErrorAction SilentlyContinue
        if ($ci) {
            switch ($ci.CodeIntegrityPolicyEnforcementStatus) {
                0 { "Vypnuto" }
                1 { "Audit" }
                2 { "Enforce" }
                default { "?" }
            }
        } else {
            if (Test-Path $WDACDeployedPath) { "Nasazeno" } else { "Vypnuto" }
        }
    } catch { "Neznamy" }
}

function Show-WDACDetail {
    Write-Header "WDAC - Detailni stav"

    $st = Get-WDACStatus
    $color = if ($st -match "Enforce") { 'Green' } elseif ($st -match "Audit") { 'Yellow' } else { 'Red' }
    Write-Status "WDAC stav" $st $color

    # Policy soubory
    Write-Host ""
    Write-Host "  Soubory politik:" -ForegroundColor White
    $files = @(
        @{ Path = $WDACDefaultXml;   Label = "Vychozi politika (XML)" }
        @{ Path = $WDACCustomXml;    Label = "Vlastni pravidla (XML)" }
        @{ Path = $WDACMergedXml;    Label = "Sloupcena politika (XML)" }
        @{ Path = $WDACCompiledBin;  Label = "Kompilovan politika (BIN)" }
        @{ Path = $WDACDeployedPath; Label = "Nasazena politika (system)" }
    )
    foreach ($f in $files) {
        $exists = Test-Path $f.Path
        $eColor = if ($exists) { 'Green' } else { 'DarkGray' }
        $eText  = if ($exists) { "ANO" } else { "NE" }
        Write-Status $f.Label $eText $eColor
    }

    # WDAC eventy z Event Logu
    Write-Host ""
    Write-Host "  Posledni WDAC udalosti (CodeIntegrity log):" -ForegroundColor White
    try {
        $events = Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 10 -ErrorAction Stop |
            Select-Object TimeCreated, Id, LevelDisplayName, Message
        if ($events) {
            foreach ($ev in $events) {
                $msgShort = if ($ev.Message.Length -gt 70) { $ev.Message.Substring(0,67) + "..." } else { $ev.Message }
                $lvlColor = switch ($ev.LevelDisplayName) {
                    "Error"       { 'Red' }
                    "Warning"     { 'Yellow' }
                    "Information" { 'Gray' }
                    default       { 'White' }
                }
                Write-Host "    [$($ev.TimeCreated.ToString('dd.MM HH:mm'))] " -NoNewline -ForegroundColor DarkGray
                Write-Host "ID:$($ev.Id)" -NoNewline -ForegroundColor $lvlColor
                Write-Host " $msgShort" -ForegroundColor White
            }
        } else {
            Write-Host "    Zadne udalosti." -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "    Nelze cist Event Log: $_" -ForegroundColor DarkGray
    }
}

# ==============================================================================
#        W D A C   -   V Y T V O R E N I   P O L I T I K Y
# ==============================================================================
function Initialize-WDACDirectory {
    if (-not (Test-Path $WDACPolicyDir)) {
        New-Item -Path $WDACPolicyDir -ItemType Directory -Force | Out-Null
        Write-Host "  Vytvoren adresar: $WDACPolicyDir" -ForegroundColor Green
    }
}

function New-WDACDefaultPolicy {
    param([switch]$AuditMode)
    Initialize-WDACDirectory

    Write-Host ""
    $modeName = if ($AuditMode) { "AUDIT" } else { "ENFORCE" }
    Write-Host "  Vytvarim vychozi WDAC politiku ($modeName mod) ..." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Tato politika povoli:" -ForegroundColor DarkGray
    Write-Host "    - Vsechny komponenty Windows" -ForegroundColor DarkGray
    Write-Host "    - Windows Store aplikace" -ForegroundColor DarkGray
    Write-Host "    - WHQL podepsane ovladace" -ForegroundColor DarkGray
    Write-Host "    - Aplikace z Intelligent Security Graph (Microsoft cloud reputace)" -ForegroundColor DarkGray
    Write-Host ""

    try {
        # Nejprve zkontrolujme zda modul ConfigCI existuje
        if (-not (Get-Command New-CIPolicy -ErrorAction SilentlyContinue)) {
            Write-Host "  [CHYBA] Cmdlet New-CIPolicy neni dostupny." -ForegroundColor Red
            Write-Host "  WDAC vyzaduje Windows 10/11 Pro nebo vyssi s ConfigCI modulem." -ForegroundColor Yellow
            Write-Host "  Zkuste: Import-Module ConfigCI" -ForegroundColor Yellow
            return
        }

        # Vytvorit DefaultWindows politiku
        # Pouzijeme predpripravenou politiku z Windows
        $defaultPolicyPath = "$env:windir\schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml"
        if (-not (Test-Path $defaultPolicyPath)) {
            # Fallback - vytvorit sken-based
            Write-Host "  Predpripravena politika nenalezena, vytvarim scan-based ..." -ForegroundColor Yellow
            New-CIPolicy -Level Publisher -Fallback Hash -FilePath $WDACDefaultXml -UserPEs -ErrorAction Stop
        } else {
            Copy-Item $defaultPolicyPath $WDACDefaultXml -Force
            Write-Host "  [OK] Pouzita DefaultWindows sablona" -ForegroundColor Green
        }

        # Pridat ISG (Intelligent Security Graph) - Microsoft cloud reputace
        try {
            Set-RuleOption -FilePath $WDACDefaultXml -Option 14 -ErrorAction SilentlyContinue  # ISG
            Write-Host "  [OK] Pridano: Intelligent Security Graph (cloud reputace)" -ForegroundColor Green
        } catch {
            Write-Host "  [INFO] ISG nelze nastavit: $_" -ForegroundColor DarkGray
        }

        if ($AuditMode) {
            # Option 3 = Audit Mode
            Set-RuleOption -FilePath $WDACDefaultXml -Option 3
            Write-Host "  [OK] Nastaven AUDIT mod (jen loguje, neblokuje)" -ForegroundColor Yellow
        } else {
            # Odebrat audit mode
            Set-RuleOption -FilePath $WDACDefaultXml -Option 3 -Delete -ErrorAction SilentlyContinue
            Write-Host "  [OK] Nastaven ENFORCE mod (blokuje neschvalene aplikace!)" -ForegroundColor Green
        }

        Write-Host ""
        Write-Host "  Politika ulozena: $WDACDefaultXml" -ForegroundColor Green
        Write-Host ""
        Write-Host "  DALSI KROK: Pouzijte 'Kompilovat a nasadit' z menu." -ForegroundColor Cyan

    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# ==============================================================================
#        W D A C   -   V L A S T N I   P R A V I D L A
# ==============================================================================
function Add-WDACPathRule {
    Write-Host ""
    Write-Host "  -- Pridani pravidla podle cesty --" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Priklad cest:" -ForegroundColor DarkGray
    Write-Host "    C:\Program Files\MojeApp\*" -ForegroundColor DarkGray
    Write-Host "    C:\Tools\*.exe" -ForegroundColor DarkGray
    Write-Host ""

    $path = Read-Host "  Zadejte cestu (prazdne = zrusit)"
    if ([string]::IsNullOrWhiteSpace($path)) { return }

    if (-not (Test-Path (Split-Path $path -Parent -ErrorAction SilentlyContinue) -ErrorAction SilentlyContinue)) {
        Write-Host "  VAROVANI: Nadrazeny adresar neexistuje. Pokracuji pres to." -ForegroundColor Yellow
    }

    Initialize-WDACDirectory

    try {
        if (-not (Test-Path $WDACCustomXml)) {
            # Vytvorit prazdnou politiku
            Write-Host "  Vytvarim novou politiku pro vlastni pravidla ..." -ForegroundColor Yellow
            New-CIPolicy -Level Hash -FilePath $WDACCustomXml -UserPEs -ScanPath $env:windir\Temp -ErrorAction Stop
            # Smazat vsechna defaultni pravidla a nechat jen nas path rule
        }

        $rules = New-CIPolicyRule -FilePathRule $path -ErrorAction Stop
        Merge-CIPolicy -PolicyPaths $WDACCustomXml -Rules $rules -OutputFilePath $WDACCustomXml -ErrorAction Stop

        Write-Host "  [OK] Pravidlo pridano: $path" -ForegroundColor Green
        Write-Host "  Nezapomente znovu kompilovat a nasadit politiku!" -ForegroundColor Yellow
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

function Add-WDACPublisherRule {
    Write-Host ""
    Write-Host "  -- Pridani pravidla podle vydavatele (Publisher) --" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Zadejte cestu k podepsanemu EXE/DLL souboru." -ForegroundColor DarkGray
    Write-Host "  Skript extrahuje certifikat vydavatele a povoli vsechny jeho aplikace." -ForegroundColor DarkGray
    Write-Host ""

    $file = Read-Host "  Cesta k souboru (prazdne = zrusit)"
    if ([string]::IsNullOrWhiteSpace($file)) { return }
    if (-not (Test-Path $file)) {
        Write-Host "  [CHYBA] Soubor nenalezen: $file" -ForegroundColor Red
        return
    }

    Initialize-WDACDirectory

    try {
        if (-not (Test-Path $WDACCustomXml)) {
            New-CIPolicy -Level Hash -FilePath $WDACCustomXml -UserPEs -ScanPath $env:windir\Temp -ErrorAction Stop
        }

        $rules = New-CIPolicyRule -Level Publisher -DriverFilePath $file -Fallback Hash -ErrorAction Stop
        Merge-CIPolicy -PolicyPaths $WDACCustomXml -Rules $rules -OutputFilePath $WDACCustomXml -ErrorAction Stop

        Write-Host "  [OK] Publisher pravidlo pridano ze souboru: $file" -ForegroundColor Green
        Write-Host "  Nezapomente znovu kompilovat a nasadit politiku!" -ForegroundColor Yellow
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

function Add-WDACHashRule {
    Write-Host ""
    Write-Host "  -- Pridani pravidla podle hashe souboru --" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Konkretni soubor bude povolen na zaklade jeho hashe." -ForegroundColor DarkGray
    Write-Host "  POZOR: Po aktualizaci aplikace se hash zmeni!" -ForegroundColor DarkGray
    Write-Host ""

    $file = Read-Host "  Cesta k souboru (prazdne = zrusit)"
    if ([string]::IsNullOrWhiteSpace($file)) { return }
    if (-not (Test-Path $file)) {
        Write-Host "  [CHYBA] Soubor nenalezen: $file" -ForegroundColor Red
        return
    }

    Initialize-WDACDirectory

    try {
        if (-not (Test-Path $WDACCustomXml)) {
            New-CIPolicy -Level Hash -FilePath $WDACCustomXml -UserPEs -ScanPath $env:windir\Temp -ErrorAction Stop
        }

        $rules = New-CIPolicyRule -Level Hash -DriverFilePath $file -ErrorAction Stop
        Merge-CIPolicy -PolicyPaths $WDACCustomXml -Rules $rules -OutputFilePath $WDACCustomXml -ErrorAction Stop

        $hash = (Get-FileHash $file -Algorithm SHA256).Hash
        Write-Host "  [OK] Hash pravidlo pridano: $file" -ForegroundColor Green
        Write-Host "       SHA256: $hash" -ForegroundColor DarkGray
        Write-Host "  Nezapomente znovu kompilovat a nasadit politiku!" -ForegroundColor Yellow
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

function Add-WDACFolderScan {
    Write-Host ""
    Write-Host "  -- Sken slozky a povoleni vsech nalezenych aplikaci --" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Proskenuje zadanou slozku a povoli vsechny EXE/DLL nalezene v ni." -ForegroundColor DarkGray
    Write-Host "  Idealni pro C:\Program Files\* po ciste instalaci." -ForegroundColor DarkGray
    Write-Host ""

    $folder = Read-Host "  Cesta ke slozce (prazdne = zrusit)"
    if ([string]::IsNullOrWhiteSpace($folder)) { return }
    if (-not (Test-Path $folder -PathType Container)) {
        Write-Host "  [CHYBA] Slozka nenalezena: $folder" -ForegroundColor Red
        return
    }

    Initialize-WDACDirectory

    Write-Host "  Skenuji slozku (muze trvat dele) ..." -ForegroundColor Yellow

    try {
        $scanPolicyFile = "$WDACPolicyDir\ScanResult_$(Get-Date -Format 'yyyyMMdd_HHmmss').xml"
        New-CIPolicy -Level Publisher -Fallback Hash -FilePath $scanPolicyFile -ScanPath $folder -UserPEs -ErrorAction Stop

        if (Test-Path $WDACCustomXml) {
            Merge-CIPolicy -PolicyPaths $WDACCustomXml, $scanPolicyFile -OutputFilePath $WDACCustomXml -ErrorAction Stop
            Remove-Item $scanPolicyFile -Force -ErrorAction SilentlyContinue
        } else {
            Move-Item $scanPolicyFile $WDACCustomXml -Force
        }

        Write-Host "  [OK] Slozka proskenovana a pravidla pridana: $folder" -ForegroundColor Green
        Write-Host "  Nezapomente znovu kompilovat a nasadit politiku!" -ForegroundColor Yellow
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# ==============================================================================
#     W D A C   -   K O M P I L A C E   a   N A S A Z E N I
# ==============================================================================
function Deploy-WDACPolicy {
    Write-Host ""
    Write-Host "  -- Kompilace a nasazeni WDAC politiky --" -ForegroundColor Cyan

    # Overit existenci zdrojove politiky
    $sourceXml = $null
    if ((Test-Path $WDACCustomXml) -and (Test-Path $WDACDefaultXml)) {
        Write-Host "  Slucuji vychozi + vlastni pravidla ..." -ForegroundColor Yellow
        try {
            Merge-CIPolicy -PolicyPaths $WDACDefaultXml, $WDACCustomXml -OutputFilePath $WDACMergedXml -ErrorAction Stop
            $sourceXml = $WDACMergedXml
            Write-Host "  [OK] Politiky slouceny" -ForegroundColor Green
        } catch {
            Write-Host "  [CHYBA] Merge selhal: $_" -ForegroundColor Red
            return
        }
    } elseif (Test-Path $WDACDefaultXml) {
        $sourceXml = $WDACDefaultXml
        Write-Host "  Pouzivam pouze vychozi politiku (zadna vlastni pravidla)." -ForegroundColor Yellow
    } else {
        Write-Host "  [CHYBA] Zadna politika nenalezena!" -ForegroundColor Red
        Write-Host "  Nejprve vytvorte vychozi politiku z menu." -ForegroundColor Yellow
        return
    }

    # Kompilace XML -> BIN
    Write-Host "  Kompiluji politiku ..." -ForegroundColor Yellow
    try {
        ConvertFrom-CIPolicy $sourceXml $WDACCompiledBin -ErrorAction Stop
        Write-Host "  [OK] Kompilace dokoncena: $WDACCompiledBin" -ForegroundColor Green
    } catch {
        Write-Host "  [CHYBA] Kompilace selhala: $_" -ForegroundColor Red
        return
    }

    # Nasazeni
    Write-Host "  Nasazuji politiku do systemu ..." -ForegroundColor Yellow
    try {
        Copy-Item $WDACCompiledBin $WDACDeployedPath -Force -ErrorAction Stop
        Write-Host "  [OK] Politika nasazena: $WDACDeployedPath" -ForegroundColor Green
        Write-Host ""
        Write-Host "  DULEZITE: Restartujte pocitac pro aktivaci politiky!" -ForegroundColor Yellow
        Write-Host "  DOPORUCENI: Nejprve pouzijte AUDIT mod a zkontrolujte Event Log." -ForegroundColor Yellow
    } catch {
        Write-Host "  [CHYBA] Nasazeni selhalo: $_" -ForegroundColor Red
    }
}

function Remove-WDACPolicy {
    Write-Host ""
    Write-Host "  -- Odebrani WDAC politiky --" -ForegroundColor Cyan

    if (Test-Path $WDACDeployedPath) {
        try {
            # Nejprve prepnout na audit
            if (Test-Path $WDACDefaultXml) {
                Set-RuleOption -FilePath $WDACDefaultXml -Option 3 -ErrorAction SilentlyContinue
                Write-Host "  Prepnuto na audit pred odebranim ..." -ForegroundColor Yellow
            }

            Remove-Item $WDACDeployedPath -Force -ErrorAction Stop
            Write-Host "  [OK] Politika odebrana ze systemu." -ForegroundColor Green
            Write-Host "  Restartujte pocitac pro uplne deaktivovani." -ForegroundColor Yellow
        } catch {
            Write-Host "  [CHYBA] $_" -ForegroundColor Red
            Write-Host "  TIP: Mozna budete muset spustit z recovery konzole." -ForegroundColor Yellow
        }
    } else {
        Write-Host "  Zadna nasazena politika nenalezena." -ForegroundColor Yellow
    }
}

function Switch-WDACAuditEnforce {
    param([switch]$Audit)
    if (-not (Test-Path $WDACDefaultXml)) {
        Write-Host "  [CHYBA] Vychozi politika neexistuje. Vytvorte ji z menu." -ForegroundColor Red
        return
    }
    try {
        if ($Audit) {
            Set-RuleOption -FilePath $WDACDefaultXml -Option 3 -ErrorAction Stop
            Write-Host "  [OK] Politika prepnuta na AUDIT mod" -ForegroundColor Yellow
        } else {
            Set-RuleOption -FilePath $WDACDefaultXml -Option 3 -Delete -ErrorAction Stop
            Write-Host "  [OK] Politika prepnuta na ENFORCE mod" -ForegroundColor Green
        }
        Write-Host "  Znovu kompilujte a nasadte pro uplatneni zmeny." -ForegroundColor Yellow
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# ==============================================================================
#      M A C R O   W H I T E L I S T I N G   -   K O N S T A N T Y
# ==============================================================================
# Office VBA security registry paths
# VBAWarnings values: 1=AllEnabled, 2=DisableWithNotification, 3=DisableExceptSigned, 4=DisableAll
$OfficeApps = [ordered]@{
    "Word"       = @{ RegPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Word\Security";       Name = "Word" }
    "Excel"      = @{ RegPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Excel\Security";      Name = "Excel" }
    "PowerPoint" = @{ RegPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\PowerPoint\Security"; Name = "PowerPoint" }
    "Access"     = @{ RegPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Access\Security";     Name = "Access" }
    "Outlook"    = @{ RegPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Outlook\Security";    Name = "Outlook" }
    "Visio"      = @{ RegPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Visio\Security";      Name = "Visio" }
    "Publisher"  = @{ RegPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\16.0\Publisher\Security";   Name = "Publisher" }
}

$VBAWarningLabels = @{
    1 = "Vse povoleno (nebezpecne!)"
    2 = "Zakazano s notifikaci (vychozi)"
    3 = "Zakazano krome podepsanych"
    4 = "Vse zakazano"
}

# ==============================================================================
#    M A C R O   -   S T A V   a   N A S T A V E N I
# ==============================================================================
function Get-MacroStatus {
    param([string]$AppKey)
    $app = $OfficeApps[$AppKey]
    if (-not $app) { return "Neznama app" }

    try {
        $regPath = $app.RegPath
        if (-not (Test-Path $regPath)) { return "Nenastaveno (vychozi Office)" }
        $val = Get-ItemProperty -Path $regPath -Name "VBAWarnings" -ErrorAction SilentlyContinue
        if ($null -eq $val -or $null -eq $val.VBAWarnings) { return "Nenastaveno" }
        $code = $val.VBAWarnings
        if ($VBAWarningLabels.ContainsKey($code)) { $VBAWarningLabels[$code] }
        else { "Neznamy ($code)" }
    } catch { "Chyba" }
}

function Get-MacroStatusShort {
    $statuses = @()
    foreach ($key in $OfficeApps.Keys) {
        $st = Get-MacroStatus -AppKey $key
        if ($st -match "podepsanych") { $statuses += "P" }
        elseif ($st -match "Vse zakazano") { $statuses += "X" }
        elseif ($st -match "Vse povoleno") { $statuses += "!" }
        elseif ($st -match "notifikaci") { $statuses += "N" }
        else { $statuses += "-" }
    }
    # Zjistit prevladajici stav
    $signed = ($statuses | Where-Object { $_ -eq "P" }).Count
    $total  = $statuses.Count
    if ($signed -eq $total) { return "Jen podepsane (vse)" }
    $blocked = ($statuses | Where-Object { $_ -eq "X" }).Count
    if ($blocked -eq $total) { return "Vse zakazano" }
    $danger = ($statuses | Where-Object { $_ -eq "!" }).Count
    if ($danger -gt 0) { return "POZOR: Neco povoleno!" }
    $unset = ($statuses | Where-Object { $_ -eq "-" }).Count
    if ($unset -eq $total) { return "Nenastaveno" }
    return "Smisene nastaveni"
}

function Show-MacroStatusAll {
    Write-Header "Stav Office maker - vsechny aplikace"
    Write-Host ""
    foreach ($key in $OfficeApps.Keys) {
        $st = Get-MacroStatus -AppKey $key
        $color = if ($st -match "podepsanych") { 'Green' }
                 elseif ($st -match "Vse zakazano") { 'Cyan' }
                 elseif ($st -match "Vse povoleno") { 'Red' }
                 elseif ($st -match "notifikaci") { 'Yellow' }
                 else { 'DarkGray' }
        Write-Status $OfficeApps[$key].Name $st $color
    }
}

function Set-MacroPolicy {
    param([int]$Level)
    # Level: 1=AllEnabled, 2=DisableNotif, 3=DisableExceptSigned, 4=DisableAll
    $label = $VBAWarningLabels[$Level]
    Write-Host ""
    Write-Host "  Nastavuji makra na: $label ..." -ForegroundColor Yellow

    foreach ($key in $OfficeApps.Keys) {
        $regPath = $OfficeApps[$key].RegPath
        try {
            if (-not (Test-Path $regPath)) {
                New-Item -Path $regPath -Force | Out-Null
            }
            Set-ItemProperty -Path $regPath -Name "VBAWarnings" -Value $Level -Type DWord -ErrorAction Stop
            Write-Host "    [OK] $($OfficeApps[$key].Name)" -ForegroundColor Green
        } catch {
            Write-Host "    [CHYBA] $($OfficeApps[$key].Name): $_" -ForegroundColor Red
        }
    }
    Write-Host "  Hotovo." -ForegroundColor Green
}

# ==============================================================================
#     M A C R O   -   T R U S T E D   L O C A T I O N S
# ==============================================================================
function Get-TrustedLocations {
    param([string]$AppKey = "Word")
    $app = $OfficeApps[$AppKey]
    if (-not $app) { return @() }

    $basePath = $app.RegPath -replace "\\Security$", "\Security\Trusted Locations"
    $locations = @()

    if (-not (Test-Path $basePath)) { return $locations }

    $subKeys = Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue
    foreach ($sub in $subKeys) {
        $props = Get-ItemProperty -Path $sub.PSPath -ErrorAction SilentlyContinue
        if ($props.Path) {
            $locations += [PSCustomObject]@{
                Key         = $sub.PSChildName
                Path        = $props.Path
                AllowSub    = [bool]$props.AllowSubFolders
                Description = if ($props.Description) { $props.Description } else { "-" }
            }
        }
    }
    return $locations
}

function Show-TrustedLocations {
    Write-Header "Trusted Locations - duveryhodna umisteni maker"
    Write-Host ""

    foreach ($appKey in $OfficeApps.Keys) {
        $locs = Get-TrustedLocations -AppKey $appKey
        Write-Host "  $($OfficeApps[$appKey].Name):" -ForegroundColor White
        if ($locs.Count -eq 0) {
            Write-Host "    Zadne vlastni trusted locations." -ForegroundColor DarkGray
        } else {
            foreach ($loc in $locs) {
                $subText = if ($loc.AllowSub) { " (+podslozky)" } else { "" }
                Write-Host "    [$($loc.Key)] $($loc.Path)$subText" -ForegroundColor Cyan
                if ($loc.Description -ne "-") {
                    Write-Host "         Popis: $($loc.Description)" -ForegroundColor DarkGray
                }
            }
        }
        Write-Host ""
    }
}

function Add-TrustedLocation {
    Write-Host ""
    Write-Host "  -- Pridani Trusted Location --" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Makra ze souboru v teto slozce budou povolena bez upozorneni." -ForegroundColor DarkGray
    Write-Host ""

    $folder = Read-Host "  Cesta ke slozce (prazdne = zrusit)"
    if ([string]::IsNullOrWhiteSpace($folder)) { return }

    $desc = Read-Host "  Popis (volitelne, Enter = preskocit)"

    Write-Host ""
    Write-Host "  Aplikace pro pridani:" -ForegroundColor Yellow
    Write-MenuItem "1" "Vsechny Office aplikace" Green
    Write-MenuItem "2" "Jen Word"
    Write-MenuItem "3" "Jen Excel"
    Write-MenuItem "4" "Jen PowerPoint"
    Write-Host ""
    $appChoice = Read-Host "  Vyberte"

    $targetApps = switch ($appChoice) {
        "1" { $OfficeApps.Keys }
        "2" { @("Word") }
        "3" { @("Excel") }
        "4" { @("PowerPoint") }
        default { $OfficeApps.Keys }
    }

    Write-Host ""
    $allowSub = Read-Host "  Povolit i podslozky? (a/n, vychozi: a)"
    $allowSubVal = if ($allowSub -eq "n") { 0 } else { 1 }

    foreach ($appKey in $targetApps) {
        $basePath = $OfficeApps[$appKey].RegPath -replace "\\Security$", "\Security\Trusted Locations"
        try {
            if (-not (Test-Path $basePath)) {
                New-Item -Path $basePath -Force | Out-Null
            }
            # Najit dalsi volny Location klic
            $existing = Get-ChildItem -Path $basePath -ErrorAction SilentlyContinue
            $nextNum = 100  # Zaciname od 100 aby neklidovaly s defaultnimi
            if ($existing) {
                $nums = $existing.PSChildName | Where-Object { $_ -match "^Location(\d+)$" } |
                    ForEach-Object { [int]($_ -replace "Location", "") }
                if ($nums) { $nextNum = ($nums | Measure-Object -Maximum).Maximum + 1 }
            }

            $locPath = "$basePath\Location$nextNum"
            New-Item -Path $locPath -Force | Out-Null
            Set-ItemProperty -Path $locPath -Name "Path" -Value $folder -Type String
            Set-ItemProperty -Path $locPath -Name "AllowSubFolders" -Value $allowSubVal -Type DWord
            if (-not [string]::IsNullOrWhiteSpace($desc)) {
                Set-ItemProperty -Path $locPath -Name "Description" -Value $desc -Type String
            }

            Write-Host "    [OK] $($OfficeApps[$appKey].Name): $folder" -ForegroundColor Green
        } catch {
            Write-Host "    [CHYBA] $($OfficeApps[$appKey].Name): $_" -ForegroundColor Red
        }
    }
    Write-Host "  Hotovo." -ForegroundColor Green
}

function Remove-TrustedLocation {
    Write-Host ""
    Write-Host "  -- Odebrani Trusted Location --" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Vyberte aplikaci:" -ForegroundColor Yellow

    $appKeys = @($OfficeApps.Keys)
    for ($i = 0; $i -lt $appKeys.Count; $i++) {
        Write-MenuItem "$($i+1)" $OfficeApps[$appKeys[$i]].Name
    }
    Write-Host ""
    $appIdx = Read-Host "  Cislo aplikace (prazdne = zrusit)"
    if ([string]::IsNullOrWhiteSpace($appIdx)) { return }
    $idx = [int]$appIdx - 1
    if ($idx -lt 0 -or $idx -ge $appKeys.Count) {
        Write-Host "  Neplatna volba." -ForegroundColor Red
        return
    }

    $appKey = $appKeys[$idx]
    $locs = Get-TrustedLocations -AppKey $appKey
    if ($locs.Count -eq 0) {
        Write-Host "  Zadne trusted locations k odebrani." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "  Existing locations pro $($OfficeApps[$appKey].Name):" -ForegroundColor White
    for ($i = 0; $i -lt $locs.Count; $i++) {
        Write-MenuItem "$($i+1)" "[$($locs[$i].Key)] $($locs[$i].Path)"
    }
    Write-Host ""
    $locIdx = Read-Host "  Cislo k odebrani (prazdne = zrusit)"
    if ([string]::IsNullOrWhiteSpace($locIdx)) { return }
    $li = [int]$locIdx - 1
    if ($li -lt 0 -or $li -ge $locs.Count) {
        Write-Host "  Neplatna volba." -ForegroundColor Red
        return
    }

    $basePath = $OfficeApps[$appKey].RegPath -replace "\\Security$", "\Security\Trusted Locations"
    $targetKey = "$basePath\$($locs[$li].Key)"
    try {
        Remove-Item -Path $targetKey -Recurse -Force -ErrorAction Stop
        Write-Host "  [OK] Odebrano: $($locs[$li].Path)" -ForegroundColor Green
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# ==============================================================================
#    M A C R O   -   T R U S T E D   P U B L I S H E R S
# ==============================================================================
function Show-TrustedPublishers {
    Write-Header "Trusted Publishers - duveryhodne vydavatele"
    Write-Host ""
    try {
        $certs = Get-ChildItem Cert:\CurrentUser\TrustedPublisher -ErrorAction Stop
        if ($certs.Count -eq 0) {
            Write-Host "  Zadne duveryhodne vydavatele." -ForegroundColor DarkGray
        } else {
            foreach ($cert in $certs) {
                $subj = if ($cert.Subject.Length -gt 60) { $cert.Subject.Substring(0,57) + "..." } else { $cert.Subject }
                Write-Host "  [" -NoNewline
                Write-Host "$($cert.Thumbprint.Substring(0,12))..." -ForegroundColor Cyan -NoNewline
                Write-Host "] " -NoNewline
                Write-Host "$subj" -ForegroundColor White
                Write-Host "       Platnost: $($cert.NotBefore.ToString('dd.MM.yyyy')) - $($cert.NotAfter.ToString('dd.MM.yyyy'))" -ForegroundColor DarkGray
            }
        }
        Write-Host ""

        # Machine level
        Write-Host "  Machine-level publishers:" -ForegroundColor White
        $mcerts = Get-ChildItem Cert:\LocalMachine\TrustedPublisher -ErrorAction SilentlyContinue
        if ($mcerts -and $mcerts.Count -gt 0) {
            foreach ($cert in $mcerts) {
                $subj = if ($cert.Subject.Length -gt 60) { $cert.Subject.Substring(0,57) + "..." } else { $cert.Subject }
                Write-Host "  [$($cert.Thumbprint.Substring(0,12))...] $subj" -ForegroundColor DarkGray
            }
        } else {
            Write-Host "  Zadne." -ForegroundColor DarkGray
        }
    } catch {
        Write-Host "  CHYBA: $_" -ForegroundColor Red
    }
}

function Add-TrustedPublisher {
    Write-Host ""
    Write-Host "  -- Pridani Trusted Publisher z certifikatu --" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Muzete zadat cestu k:" -ForegroundColor DarkGray
    Write-Host "    - .cer / .crt souboru (certifikat)" -ForegroundColor DarkGray
    Write-Host "    - podepsanemu .exe / .dll (extrahuje certifikat)" -ForegroundColor DarkGray
    Write-Host ""

    $file = Read-Host "  Cesta k souboru (prazdne = zrusit)"
    if ([string]::IsNullOrWhiteSpace($file)) { return }
    if (-not (Test-Path $file)) {
        Write-Host "  [CHYBA] Soubor nenalezen: $file" -ForegroundColor Red
        return
    }

    try {
        $ext = [IO.Path]::GetExtension($file).ToLower()
        if ($ext -in ".cer", ".crt") {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($file)
        } else {
            # Extrahovat certifikat z podepsaneho souboru
            $sig = Get-AuthenticodeSignature $file -ErrorAction Stop
            if ($sig.Status -eq "Valid" -or $sig.Status -eq "UnknownError") {
                $cert = $sig.SignerCertificate
            } else {
                Write-Host "  [CHYBA] Soubor neni validne podepsany (status: $($sig.Status))" -ForegroundColor Red
                return
            }
        }

        if (-not $cert) {
            Write-Host "  [CHYBA] Nelze ziskat certifikat." -ForegroundColor Red
            return
        }

        Write-Host "  Certifikat: $($cert.Subject)" -ForegroundColor White
        Write-Host "  Platnost:   $($cert.NotBefore.ToString('dd.MM.yyyy')) - $($cert.NotAfter.ToString('dd.MM.yyyy'))" -ForegroundColor DarkGray
        Write-Host ""

        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher", "CurrentUser")
        $store.Open("MaxAllowed")
        $store.Add($cert)
        $store.Close()

        Write-Host "  [OK] Publisher pridan do TrustedPublisher (CurrentUser)" -ForegroundColor Green
    } catch {
        Write-Host "  [CHYBA] $_" -ForegroundColor Red
    }
}

# ==============================================================================
#       V O L B A   9 9   -   K O M P L E T N I   P R E H L E D
# ==============================================================================
function Show-FullStatus {
    Show-Banner
    Write-Header "KOMPLETNI PREHLED"

    function Get-StatusColor([string]$Value) {
        if ($Value -match "Enforce|podepsanych|Vse zakazano") { 'Green' }
        elseif ($Value -match "Vypnuto|Nenastaveno|povoleno") { 'Red' }
        else { 'Yellow' }
    }

    Write-Host ""
    Write-Host "  -- WDAC (Application Whitelisting) --------------------------------" -ForegroundColor Magenta
    $v = Get-WDACStatus; Write-Status "WDAC stav" $v (Get-StatusColor $v)

    $pFiles = @($WDACDefaultXml, $WDACCustomXml, $WDACMergedXml, $WDACCompiledBin) |
        Where-Object { Test-Path $_ }
    Write-Status "Pripravene politiky" "$($pFiles.Count) souboru" 'Cyan'

    Write-Host ""
    Write-Host "  -- OFFICE MAKRA ---------------------------------------------------" -ForegroundColor Magenta
    foreach ($key in $OfficeApps.Keys) {
        $st = Get-MacroStatus -AppKey $key
        $color = if ($st -match "podepsanych") { 'Green' }
                 elseif ($st -match "Vse zakazano") { 'Cyan' }
                 elseif ($st -match "Vse povoleno") { 'Red' }
                 elseif ($st -match "notifikaci") { 'Yellow' }
                 else { 'DarkGray' }
        Write-Status "  $($OfficeApps[$key].Name)" $st $color
    }

    Write-Host ""
    Write-Host "  -- TRUSTED LOCATIONS ---------------------------------------------" -ForegroundColor Magenta
    foreach ($appKey in @("Word", "Excel", "PowerPoint")) {
        $locs = Get-TrustedLocations -AppKey $appKey
        if ($locs.Count -gt 0) {
            foreach ($loc in $locs) {
                Write-Host "    $($OfficeApps[$appKey].Name): $($loc.Path)" -ForegroundColor Cyan
            }
        }
    }

    Write-Host ""
    Write-Host "  -- TRUSTED PUBLISHERS --------------------------------------------" -ForegroundColor Magenta
    $certs = Get-ChildItem Cert:\CurrentUser\TrustedPublisher -ErrorAction SilentlyContinue
    if ($certs -and $certs.Count -gt 0) {
        foreach ($c in $certs) {
            $subj = if ($c.Subject.Length -gt 55) { $c.Subject.Substring(0,52) + "..." } else { $c.Subject }
            Write-Host "    $subj" -ForegroundColor Cyan
        }
    } else {
        Write-Host "    Zadne." -ForegroundColor DarkGray
    }

    Write-Host ""
}

# ==============================================================================
#                      S U B - M E N U
# ==============================================================================

# -- 1) WDAC ------------------------------------------------------------------
function Show-Menu-WDAC {
    do {
        Show-Banner
        Write-SubHeader "WDAC - Application Whitelisting" @"
  WDAC (Windows Defender Application Control) umoznuje definovat
  ktere aplikace smi bezet na vasem PC. Vse ostatni je blokovano.
  DOPORUCENY POSTUP:
  1. Vytvorte politiku v AUDIT modu
  2. Pridejte vlastni pravidla pro vase aplikace
  3. Kompilujte a nasadte
  4. Zkontrolujte Event Log, az vse funguje, prepnete na ENFORCE
"@

        $wdacSt = Get-WDACStatus
        $wColor = if ($wdacSt -match "Enforce") { 'Green' } elseif ($wdacSt -match "Audit") { 'Yellow' } else { 'Red' }
        Write-Host "  Aktualni stav:" -ForegroundColor DarkGray
        Write-Host "    WDAC: " -NoNewline -ForegroundColor DarkGray
        Write-Host $wdacSt -ForegroundColor $wColor
        Write-Host ""

        Write-Host "    Vytvoreni politiky:" -ForegroundColor Cyan
        Write-MenuItem "1"  "Vytvorit vychozi politiku (AUDIT mod) - DOPORUCENO" Green
        Write-MenuItem "2"  "Vytvorit vychozi politiku (ENFORCE mod) - POZOR!"
        Write-Host ""
        Write-Host "    Vlastni pravidla (whitelist):" -ForegroundColor Cyan
        Write-MenuItem "3"  "Pridat pravidlo podle CESTY (FilePath)"
        Write-MenuItem "4"  "Pridat pravidlo podle VYDAVATELE (Publisher)"
        Write-MenuItem "5"  "Pridat pravidlo podle HASHE souboru"
        Write-MenuItem "6"  "Proskenovad slozku a povolit vsechny nalezene app"
        Write-Host ""
        Write-Host "    Nasazeni:" -ForegroundColor Cyan
        Write-MenuItem "7"  "Kompilovat a nasadit politiku"
        Write-MenuItem "8"  "Prepnout na AUDIT mod"
        Write-MenuItem "9"  "Prepnout na ENFORCE mod"
        Write-MenuItem "10" "Odebrat nasazenou politiku"
        Write-Host ""
        Write-Host "    Informace:" -ForegroundColor Cyan
        Write-MenuItem "11" "Zobrazit detailni stav + Event Log"
        Write-Host ""
        Write-MenuItem "0"  "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-Host "  Vyberte volbu"
        switch ($c) {
            "1"  { New-WDACDefaultPolicy -AuditMode; Pause-Menu }
            "2"  {
                Write-Host ""
                Write-Host "  VAROVANI: ENFORCE mod okamzite blokuje neschvalene aplikace!" -ForegroundColor Red
                Write-Host "  Doporucujeme nejprve pouzit AUDIT mod." -ForegroundColor Yellow
                $confirm = Read-Host "  Opravdu pokracovat? (ano/ne)"
                if ($confirm -eq "ano") { New-WDACDefaultPolicy }
                else { Write-Host "  Zruseno." -ForegroundColor Yellow }
                Pause-Menu
            }
            "3"  { Add-WDACPathRule; Pause-Menu }
            "4"  { Add-WDACPublisherRule; Pause-Menu }
            "5"  { Add-WDACHashRule; Pause-Menu }
            "6"  { Add-WDACFolderScan; Pause-Menu }
            "7"  { Deploy-WDACPolicy; Pause-Menu }
            "8"  { Switch-WDACAuditEnforce -Audit; Pause-Menu }
            "9"  {
                Write-Host ""
                Write-Host "  VAROVANI: ENFORCE zacne blokovat neschvalene aplikace!" -ForegroundColor Red
                $confirm = Read-Host "  Opravdu pokracovat? (ano/ne)"
                if ($confirm -eq "ano") { Switch-WDACAuditEnforce }
                else { Write-Host "  Zruseno." -ForegroundColor Yellow }
                Pause-Menu
            }
            "10" { Remove-WDACPolicy; Pause-Menu }
            "11" { Show-WDACDetail; Pause-Menu }
            "0"  { return }
            default { Write-Host "  Neplatna volba." -ForegroundColor Red; Start-Sleep 1 }
        }
    } while ($true)
}

# -- 2) Macro Whitelisting ----------------------------------------------------
function Show-Menu-Macros {
    do {
        Show-Banner
        Write-SubHeader "OFFICE MACRO WHITELISTING" @"
  Makra v Office souborech jsou casty vektor utoku (phishing, malware).
  Doporuceni: Zakazat vsechna makra KROM podepsanych duveryhodnymi
  vydavateli. Pro vlastni makra pouzijte Trusted Locations (duveryhodne
  slozky) nebo podepiste makra vlastnim certifikatem.
  Podepsana makra = bezpecnejsi. Trusted Locations = pohodlnejsi.
"@

        $macSt = Get-MacroStatusShort
        $mColor = if ($macSt -match "podepsane") { 'Green' } elseif ($macSt -match "POZOR") { 'Red' } else { 'Yellow' }
        Write-Host "  Aktualni stav:" -ForegroundColor DarkGray
        Write-Host "    Makra: " -NoNewline -ForegroundColor DarkGray
        Write-Host $macSt -ForegroundColor $mColor
        Write-Host ""

        Write-Host "    Uroven ochrany maker:" -ForegroundColor Cyan
        Write-MenuItem "1"  "Zobrazit stav vsech Office aplikaci"
        Write-MenuItem "2"  "Zakazat vse KROME PODEPSANYCH (doporuceno)" Green
        Write-MenuItem "3"  "Zakazat vse s notifikaci (vychozi Office)"
        Write-MenuItem "4"  "Zakazat UPLNE VSE (zadna makra)"
        Write-MenuItem "5"  "Povolit vse (NEBEZPECNE!)" Red
        Write-Host ""
        Write-Host "    Trusted Locations (duveryhodne slozky):" -ForegroundColor Cyan
        Write-MenuItem "6"  "Zobrazit vsechny Trusted Locations"
        Write-MenuItem "7"  "Pridat Trusted Location"
        Write-MenuItem "8"  "Odebrat Trusted Location"
        Write-Host ""
        Write-Host "    Trusted Publishers (duveryhodne vydavatele):" -ForegroundColor Cyan
        Write-MenuItem "9"  "Zobrazit Trusted Publishers"
        Write-MenuItem "10" "Pridat Trusted Publisher (ze souboru/certifikatu)"
        Write-Host ""
        Write-MenuItem "0"  "<- Zpet do hlavniho menu" Yellow
        Write-Host ""

        $c = Read-Host "  Vyberte volbu"
        switch ($c) {
            "1"  { Show-MacroStatusAll; Pause-Menu }
            "2"  { Set-MacroPolicy -Level 3; Pause-Menu }
            "3"  { Set-MacroPolicy -Level 2; Pause-Menu }
            "4"  { Set-MacroPolicy -Level 4; Pause-Menu }
            "5"  {
                Write-Host ""
                Write-Host "  VAROVANI: Povoleni vsech maker je NEBEZPECNE!" -ForegroundColor Red
                $confirm = Read-Host "  Opravdu pokracovat? (ano/ne)"
                if ($confirm -eq "ano") { Set-MacroPolicy -Level 1 }
                else { Write-Host "  Zruseno." -ForegroundColor Yellow }
                Pause-Menu
            }
            "6"  { Show-TrustedLocations; Pause-Menu }
            "7"  { Add-TrustedLocation; Pause-Menu }
            "8"  { Remove-TrustedLocation; Pause-Menu }
            "9"  { Show-TrustedPublishers; Pause-Menu }
            "10" { Add-TrustedPublisher; Pause-Menu }
            "0"  { return }
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
    $wdacQ  = Get-WDACStatusShort
    $macroQ = Get-MacroStatusShort

    $wdacC  = if ($wdacQ -match "Enforce") { 'Green' } elseif ($wdacQ -match "Audit") { 'Yellow' } else { 'Red' }
    $macroC = if ($macroQ -match "podepsane") { 'Green' } elseif ($macroQ -match "POZOR") { 'Red' } else { 'Yellow' }

    Write-Host "    1)  WDAC (Application Whitelisting)" -ForegroundColor White -NoNewline
    Write-Host "  [" -NoNewline -ForegroundColor DarkGray
    Write-Host "$wdacQ" -NoNewline -ForegroundColor $wdacC
    Write-Host "]" -ForegroundColor DarkGray
    Write-Host "        Povolte jen duveryhodne aplikace." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "    2)  Office Macro Whitelisting" -ForegroundColor White -NoNewline
    Write-Host "       [" -NoNewline -ForegroundColor DarkGray
    Write-Host "$macroQ" -NoNewline -ForegroundColor $macroC
    Write-Host "]" -ForegroundColor DarkGray
    Write-Host "        Kontrola maker, trusted locations, publishers." -ForegroundColor DarkGray
    Write-Host ""

    Write-Host "   99)  Kompletni prehled stavu" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "    0)  Konec" -ForegroundColor Yellow
    Write-Host ""

    $mainChoice = Read-Host "  Vyberte volbu"

    switch ($mainChoice) {
        "1"  { Show-Menu-WDAC }
        "2"  { Show-Menu-Macros }
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
