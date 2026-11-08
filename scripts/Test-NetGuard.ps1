<#
.SYNOPSIS
    Auto-test de netguard-gaming dans un BAC À SABLE : HKCU:\Software\NetGuardTest + %TEMP%.
.DESCRIPTION
    Prouve, sans toucher aux vrais réglages :
      1. l'audit n'écrit QUE dans reports\ et baseline\ (ici redirigés vers %TEMP%), et rien
         sous -WhatIf ; aucun fichier du projet n'est modifié ;
      2. -WhatIf ne change rien (Apply) ;
      3. export + Undo restaurent les valeurs à l'identique (valeur, type, clé créée) ;
      4. un service protégé, une règle de pare-feu Windows, une écriture hors HKCU, une clé
         Defender et un processus système sont REFUSÉS ;
      5. Mode Jeu -> Normal restaure l'état exact, même après une interruption simulée ;
      6. le rapport partageable ne contient ni IP, ni MAC, ni SSID, ni e-mail, ni nom.
    Le plan d'alimentation réel n'est jamais changé (désactivé dans la config de test).
    Durée : 1 à 2 minutes (l'audit de test fait 1 passe de 5 pings par cible). -SansAudit : ~15 s.
.EXAMPLE
    .\Test-NetGuard.ps1
    .\Test-NetGuard.ps1 -SansAudit
#>
[CmdletBinding()]
param([switch]$SansAudit)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
$S = $PSScriptRoot
$Root = Get-NgPath '.'
$K = 'HKCU:\Software\NetGuardTest'
$T = Join-Path $env:TEMP ('NetGuardTest_' + (Get-Date -Format 'yyyyMMdd_HHmmss'))
$res = New-Object Collections.Generic.List[object]
$enc = New-Object Text.UTF8Encoding($true)
function Check { param([string]$Name, [bool]$Ok, [string]$Detail = '') $res.Add([pscustomobject]@{ Test = $Name; Resultat = $(if ($Ok) { 'OK' } else { 'ÉCHEC' }); Detail = $Detail }); Write-Host ("  [{0}] {1}" -f $(if ($Ok) { 'OK' } else { 'ÉCHEC' }), $Name) -ForegroundColor $(if ($Ok) { 'Green' } else { 'Red' }) }
function Get-RegDump { ((& reg.exe query 'HKCU\Software\NetGuardTest' /s 2>$null) -join "`n") }
function Get-ProjectState {
    # Empreinte des fichiers du projet (hors dossiers de sortie ignorés par Git)
    Get-ChildItem -LiteralPath $Root -Recurse -File | Where-Object { $_.FullName -notmatch '\\(reports|baseline|logs|\.git)\\' } |
        ForEach-Object { '{0}|{1}|{2}' -f $_.FullName.Substring($Root.Length), $_.Length, $_.LastWriteTimeUtc.Ticks }
}
function Quiet { param([scriptblock]$B) & $B *>&1 | Out-String }   # sorties des scripts testés, gardées pour l'analyse

Write-Host "netguard-gaming : auto-test en bac à sable ($T)" -ForegroundColor Cyan
if (Test-Path $K) { throw "$K existe déjà (test précédent interrompu ?). Supprime-la puis relance : Remove-Item '$K' -Recurse" }
New-Item -ItemType Directory $T | Out-Null
$proc = $null
$projectBefore = Get-ProjectState
$planBefore = Get-NgActivePowerScheme
try {
    New-Item $K | Out-Null
    New-ItemProperty $K -Name Val1 -PropertyType DWord -Value 5 | Out-Null
    New-ItemProperty $K -Name Val3 -PropertyType ExpandString -Value '%TEMP%\x' | Out-Null
    $snap0 = Get-RegDump

    # ---------------------------------------------------------------- 1. Audit en lecture seule
    $tr = Join-Path $T 'reports'; $tb = Join-Path $T 'baseline'
    if (-not $SansAudit) {
        Write-Host '1. Audit (1 passe, 5 requêtes par cible, sans winget)...' -ForegroundColor Cyan
        $null = Quiet { & "$S\Audit.ps1" -Passes 1 -PingCount 5 -PassIntervalSec 0 -SkipWinget -ReportsDir $tr -BaselineDir $tb -WhatIf }
        Check 'Audit -WhatIf : aucun fichier écrit' (-not (Test-Path $tr) -and -not (Test-Path $tb))
        $null = Quiet { & "$S\Audit.ps1" -Passes 1 -PingCount 5 -PassIntervalSec 0 -SkipWinget -ReportsDir $tr -BaselineDir $tb }
        $written = @(Get-ChildItem $T -Recurse -File | ForEach-Object { $_.FullName.Substring($T.Length + 1) })
        $outside = @($written | Where-Object { $_ -notmatch '^(reports|baseline)\\' })
        Check 'Audit : fichiers écrits seulement dans reports\ et baseline\' (($written.Count -ge 3) -and -not $outside) ($written -join ', ')
        Check 'Audit : aucun fichier du projet modifié' (-not (Compare-Object $projectBefore (Get-ProjectState)))
        Check 'Audit : registre du bac à sable intact' ((Get-RegDump) -eq $snap0)

        # ------------------------------------------------------------ 6a. Rapport partageable réel
        $auditJson = (Get-ChildItem $tr -Recurse -Filter audit.json | Select-Object -First 1).FullName
        $null = Quiet { & "$S\New-AuditReport.ps1" -AuditPath $auditJson -ReportsDir $tr }
        $sharePath = Join-Path $tr 'rapport_audit_partageable.html'
        if (Test-Path $sharePath) {
            $share = [IO.File]::ReadAllText($sharePath)
            $au = Get-Content $auditJson -Raw -Encoding UTF8 | ConvertFrom-Json
            $secrets = @($env:COMPUTERNAME, $env:USERNAME, $au.Contexte.NomPc, $au.Contexte.Utilisateur) + @($au.Contexte.Gere.Mdm | ForEach-Object { $_.Compte })
            $leaks = Find-NgShareableLeak -Text $share -Secrets $secrets
            $ipLocal = $au.Contexte.IPv4; $mac = $au.Contexte.Carte.Mac
            Check 'Rapport partageable : ni IP, ni MAC, ni e-mail, ni nom' ((@($leaks).Count -eq 0) -and -not ($ipLocal -and $share.Contains($ipLocal)) -and -not ($mac -and $share.Contains($mac))) ((@($leaks) | Select-Object -First 3) -join ' ; ')
        } else { Check 'Rapport partageable généré' $false 'fichier absent' }
    } else { Write-Host '1. Audit : ignoré (-SansAudit)' -ForegroundColor DarkGray }

    # ---------------------------------------------------------------- 6b. Masquage (données factices, dont un SSID)
    $fake = 'PC MONPCTEST, user jdupont, IP 192.168.1.42, box 10.0.0.1, IPv6 fe80::1c2b:3d4e:5f60:7a8b%12, MAC 3C-7C-3F-11-22-33 / aa:bb:cc:dd:ee:ff, Wi-Fi « Livebox-AB12 », compte jean.dupont@exemple.fr, SID S-1-5-21-111-222-333-1001, C:\Users\jdupont\AppData, DNS 1.1.1.1, heure 12:07:48'
    $sec = @('MONPCTEST', 'jdupont', 'Livebox-AB12')
    $masked = ConvertTo-NgShareable -Text $fake -Secrets $sec
    # Piège : Find-NgShareableLeak renvoie « , tableau » ; l'affecter d'abord, sinon @(...) compte 1 même vide
    $leak2 = Find-NgShareableLeak -Text $masked -Secrets $sec
    Check 'Masquage : IP, MAC, SSID, e-mail, SID, nom masqués ; 1.1.1.1 et l''heure conservés' ((@($leak2).Count -eq 0) -and $masked.Contains('1.1.1.1') -and $masked.Contains('12:07:48') -and -not $masked.Contains('fe80')) $masked

    # ---------------------------------------------------------------- 2-3. Apply / Undo
    Write-Host '2-3. Apply / Undo (catalogue de test)...' -ForegroundColor Cyan
    $cat = @{ actions = @(
        @{ id = 'T-1'; titre = 'DWord existant'; profils = @('Prudent'); methode = 'registre'; sourceVerifiee = $true; application = @{ type = 'registre'; chemin = $K; nom = 'Val1'; typeValeur = 'DWord'; valeur = 1 } },
        @{ id = 'T-2'; titre = 'Valeur absente'; profils = @('Prudent'); methode = 'registre'; sourceVerifiee = $true; application = @{ type = 'registre'; chemin = $K; nom = 'Val2'; typeValeur = 'String'; valeur = 'netguard' } },
        @{ id = 'T-3'; titre = 'Clé absente'; profils = @('Prudent'); methode = 'registre'; sourceVerifiee = $true; application = @{ type = 'registre'; chemin = "$K\Sub"; nom = 'Val4'; typeValeur = 'QWord'; valeur = 7 } },
        @{ id = 'T-4'; titre = 'Type changé'; profils = @('Prudent'); methode = 'registre'; sourceVerifiee = $true; application = @{ type = 'registre'; chemin = $K; nom = 'Val3'; typeValeur = 'String'; valeur = 'plat' } },
        @{ id = 'T-X1'; titre = 'Interdit HKLM'; profils = @('Prudent'); methode = 'registre'; sourceVerifiee = $true; application = @{ type = 'registre'; chemin = 'HKLM:\SOFTWARE\NetGuardTest'; nom = 'X'; typeValeur = 'DWord'; valeur = 1 } },
        @{ id = 'T-X2'; titre = 'Interdit Defender'; profils = @('Prudent'); methode = 'registre'; sourceVerifiee = $true; application = @{ type = 'registre'; chemin = 'HKCU:\Software\Policies\Microsoft\Windows Defender'; nom = 'X'; typeValeur = 'DWord'; valeur = 1 } },
        @{ id = 'T-X3'; titre = 'Placebo'; profils = @('Prudent'); methode = 'registre'; nonRecommande = $true; sourceVerifiee = $true; application = @{ type = 'registre'; chemin = $K; nom = 'Placebo'; typeValeur = 'DWord'; valeur = 1 } },
        @{ id = 'T-X4'; titre = 'Non vérifié'; profils = @('Prudent'); methode = 'registre'; sourceVerifiee = $false; application = @{ type = 'registre'; chemin = $K; nom = 'NonVerifie'; typeValeur = 'DWord'; valeur = 1 } }
    ) }
    $catPath = Join-Path $T 'actions_test.json'
    [IO.File]::WriteAllText($catPath, ($cat | ConvertTo-Json -Depth 6), $enc)
    $logs = Join-Path $T 'logs'
    $o1 = Quiet { & "$S\Apply.ps1" -Profil Prudent -CatalogPath $catPath -LogsDir $logs -WhatIf }
    Check 'Apply -WhatIf : rien de modifié, aucun journal' (((Get-RegDump) -eq $snap0) -and -not (Test-Path $logs))
    Check 'Écriture hors HKCU et clé Defender refusées' (($o1 -match 'T-X1.*REFUS') -and ($o1 -match 'T-X2.*REFUS'))
    Check 'Placebo et non vérifié jamais appliqués par défaut' (($o1 -match 'T-X3.*jamais') -and ($o1 -match 'T-X4.*non vérifiée'))
    $null = Quiet { & "$S\Apply.ps1" -Profil Prudent -CatalogPath $catPath -LogsDir $logs -Oui }
    $sess = Get-ChildItem $logs -Directory | Select-Object -First 1
    $j = Get-Content (Join-Path $sess.FullName 'journal.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $item = Get-Item $K
    Check 'Apply réel : valeurs écrites' (($item.GetValue('Val1') -eq 1) -and ($item.GetValue('Val2') -eq 'netguard') -and ((Get-Item "$K\Sub").GetValue('Val4') -eq 7) -and ([string]$item.GetValueKind('Val3') -eq 'String'))
    Check 'Journal : origine et type de chaque valeur' ((@($j.Entrees | Where-Object Etat -eq 'fait').Count -eq 4) -and (($j.Entrees | Where-Object Nom -eq 'Val1').ValeurOrigine -eq 5) -and (($j.Entrees | Where-Object Nom -eq 'Val3').TypeOrigine -eq 'ExpandString') -and (($j.Entrees | Where-Object Nom -eq 'Val2').Existait -eq $false))
    Check 'Export .reg écrit avant chaque changement de clé existante' (@(Get-ChildItem $sess.FullName -Filter *.reg).Count -ge 3)
    Check 'Rien créé dans HKLM' (-not (Test-Path 'HKLM:\SOFTWARE\NetGuardTest'))
    $null = Quiet { & "$S\Undo.ps1" -Session $sess.Name -LogsDir $logs -WhatIf }
    Check 'Undo -WhatIf : rien de restauré' ((Get-Item $K).GetValue('Val1') -eq 1)
    $null = Quiet { & "$S\Undo.ps1" -Session $sess.Name -LogsDir $logs -Oui }
    Check 'Undo : état d''origine exact (valeurs, types, clé créée retirée)' ((Get-RegDump) -eq $snap0)

    # ---------------------------------------------------------------- 4. Garde-fous
    Write-Host '4. Garde-fous...' -ForegroundColor Cyan
    $refused = 0
    foreach ($svc in 'WinDefend', 'mpssvc', 'wuauserv', 'BFE') { try { Assert-NgServiceAllowed $svc } catch { $refused++ } }
    Check 'Services protégés refusés (WinDefend, mpssvc, wuauserv, BFE)' ($refused -eq 4)
    $wr = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { ([string]$_.Group).StartsWith('@') } | Select-Object -First 1
    $e3 = $null; try { Assert-NgFirewallRuleAllowed $wr } catch { $e3 = $_ }
    Check 'Règle de pare-feu Windows refusée' ([bool]$e3) "$($wr.DisplayName)"
    $e4 = $null; try { Assert-NgRegistryAllowed 'HKCU:\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate' } catch { $e4 = $_ }
    Check 'Clé Windows Update refusée même dans HKCU' ([bool]$e4)

    # ---------------------------------------------------------------- 5. Mode Jeu
    Write-Host '5. Mode Jeu (interruption simulée, puis cycle complet)...' -ForegroundColor Cyan
    $exe = Join-Path $T 'ngtestproc.exe'; Copy-Item "$env:windir\System32\PING.EXE" $exe
    $proc = Start-Process $exe -ArgumentList '-n 300 127.0.0.1' -WindowStyle Hidden -PassThru
    Start-Sleep -Milliseconds 500
    $prio0 = [string]$proc.PriorityClass
    $gm = @{
        planAlimentation = @{ actif = $false }
        registre = @(
            @{ id = 'G-1'; actif = $true; titre = 'existante'; chemin = $K; nom = 'Val1'; type = 'DWord'; valeur = 0; sourceVerifiee = $true },
            @{ id = 'G-2'; actif = $true; titre = 'absente'; chemin = $K; nom = 'GmAbsente'; type = 'DWord'; valeur = 1; sourceVerifiee = $true },
            @{ id = 'G-3'; actif = $true; titre = 'interdite'; chemin = 'HKLM:\SOFTWARE\NetGuardTest'; nom = 'X'; type = 'DWord'; valeur = 1; sourceVerifiee = $true }
        )
        processus = @(@{ nom = 'ngtestproc'; actif = $true; priorite = 'BelowNormal' }, @{ nom = 'svchost'; actif = $true; priorite = 'Idle' }, @{ nom = 'explorer'; actif = $true; priorite = 'Idle' })
    }
    $gmPath = Join-Path $T 'game_mode_test.json'
    [IO.File]::WriteAllText($gmPath, ($gm | ConvertTo-Json -Depth 6), $enc)
    $stDir = Join-Path $T 'gamemode'
    $null = Quiet { & "$S\GameMode.ps1" -Mode Jeu -ConfigPath $gmPath -StateDir $stDir -WhatIf }
    Check 'Mode Jeu -WhatIf : rien de modifié' (((Get-RegDump) -eq $snap0) -and -not (Test-Path $stDir))
    $int = $null; try { $null = Quiet { & "$S\GameMode.ps1" -Mode Jeu -ConfigPath $gmPath -StateDir $stDir -Oui -StopAfterStep 2 } } catch { $int = $_ }
    $st = Get-Content (Join-Path $stDir 'etat.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Check 'Interruption : état « jeu » déjà sur le disque' ([bool]$int -and $st.Mode -eq 'jeu' -and ((Get-RegDump) -ne $snap0))
    Check 'Processus système refusés (svchost, explorer)' ((@(Get-Process svchost -ErrorAction SilentlyContinue | Where-Object { [string]$_.PriorityClass -eq 'Idle' }).Count -eq 0) -and ([string](Get-Process explorer -ErrorAction SilentlyContinue | Select-Object -First 1).PriorityClass -ne 'Idle'))
    $null = Quiet { & "$S\GameMode.ps1" -Mode Reprise -ConfigPath $gmPath -StateDir $stDir -Oui }
    $proc.Refresh(); $st = Get-Content (Join-Path $stDir 'etat.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Check 'Reprise après interruption : état exact' (((Get-RegDump) -eq $snap0) -and $st.Mode -eq 'normal' -and ([string]$proc.PriorityClass -eq $prio0))
    $null = Quiet { & "$S\GameMode.ps1" -Mode Jeu -ConfigPath $gmPath -StateDir $stDir -Oui }
    $proc.Refresh(); $midP = [string]$proc.PriorityClass; $midV = (Get-Item $K).GetValue('Val1')
    $null = Quiet { & "$S\GameMode.ps1" -Mode Normal -ConfigPath $gmPath -StateDir $stDir -Oui }
    $proc.Refresh()
    Check 'Mode Jeu appliqué (registre + priorité)' (($midP -eq 'BelowNormal') -and ($midV -eq 0))
    Check 'Mode Normal : état exact' (((Get-RegDump) -eq $snap0) -and ([string]$proc.PriorityClass -eq $prio0))
} catch {
    Check "Erreur inattendue : $($_.Exception.Message)" $false ($_.ScriptStackTrace)
} finally {
    if ($proc) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }   # notre propre processus de test
    Remove-Item $K -Recurse -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300
    Remove-Item $T -Recurse -Force -ErrorAction SilentlyContinue
}
Check 'Plan d''alimentation réel inchangé' ((Get-NgActivePowerScheme) -eq $planBefore)
Check 'Bac à sable nettoyé (registre + %TEMP%)' (-not (Test-Path $K) -and -not (Test-Path $T))
$ko = @($res | Where-Object Resultat -ne 'OK')
Write-Host ''
Write-Host ("{0} test(s), {1} OK, {2} échec(s)" -f $res.Count, ($res.Count - $ko.Count), $ko.Count) -ForegroundColor $(if ($ko) { 'Red' } else { 'Green' })
foreach ($k2 in $ko) { Write-Host "  ÉCHEC : $($k2.Test) $($k2.Detail)" -ForegroundColor Red }
