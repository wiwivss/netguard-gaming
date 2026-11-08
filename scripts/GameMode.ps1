<#
.SYNOPSIS
    Bascule Mode Jeu <-> Mode Normal, avec restauration EXACTE de l'état d'origine.
.DESCRIPTION
    Mode Jeu (config\game_mode.json + game_mode.local.json validé par toi) :
      - plan d'alimentation « Performances élevées » (powercfg, sans admin) ;
      - valeurs HKCU que tu as activées (ex. bannières de notification, opt-in) ;
      - priorité « inférieure à la normale » pour les programmes de fond que tu as listés.
      Rien n'est tué, suspendu ou arrêté ; aucun processus système / sécurité / anti-triche.
    Ordre de sécurité : 1) journal de session créé, 2) logs\gamemode\etat.json passe à « jeu »,
    3) chaque changement est journalisé AVANT d'être fait. Si le script, la session ou le PC
    s'arrête en route, le prochain lancement (option 6 ou démarrage du menu) le détecte
    (-Mode Reprise) et propose de tout remettre.
    Mode Normal : rejoue le journal à l'envers, puis VÉRIFIE que chaque valeur est revenue à
    l'identique.
.EXAMPLE
    .\GameMode.ps1 -Mode Jeu -WhatIf
    .\GameMode.ps1 -Mode Jeu
    .\GameMode.ps1 -Mode Normal
    .\GameMode.ps1 -Mode Etat
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Jeu', 'Normal', 'Etat', 'Reprise')][string]$Mode = 'Etat',
    [switch]$Oui,
    [string]$ConfigPath,
    [string]$StateDir,
    # Test uniquement (Test-NetGuard.ps1) : simule un arrêt brutal après N changements.
    [int]$StopAfterStep = 0
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
if (-not $StateDir) { $StateDir = Get-NgPath 'logs\gamemode' }
$statePath = Join-Path $StateDir 'etat.json'
$isWhatIf = [bool]$WhatIfPreference

# ---- Configuration (la dernière occurrence d'un id / nom l'emporte : local.json > public) ----
$cfg = if ($ConfigPath) { Get-Content -LiteralPath $ConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json } else { Get-NgConfig 'game_mode' }
function Get-LastWins { param($List, [string]$Key) $h = [ordered]@{}; foreach ($x in @($List)) { if ($x) { $h[[string]$x.$Key] = $x } }; @($h.Values) }
$regItems = @(Get-LastWins $cfg.registre 'id' | Where-Object { $_.actif })
$procItems = @(Get-LastWins $cfg.processus 'nom' | Where-Object { $_.actif })

# ---- État persistant ---------------------------------------------------------------------
function Get-GmState {
    if (-not (Test-Path -LiteralPath $statePath)) { return $null }
    Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
}
function Save-GmState {
    param([hashtable]$Data)
    if (-not (Test-Path -LiteralPath $StateDir)) { New-Item -ItemType Directory -Path $StateDir -Force -WhatIf:$false | Out-Null }
    $tmp = "$statePath.tmp"
    [IO.File]::WriteAllText($tmp, ([pscustomobject]$Data | ConvertTo-Json), (New-Object Text.UTF8Encoding($true)))
    Move-Item -LiteralPath $tmp -Destination $statePath -Force -WhatIf:$false
}
function Confirm-Oui {
    param([string]$Question)
    if ($Oui) { Write-Host "$Question  -> OUI (paramètre -Oui)"; return $true }
    (Read-Host "$Question  Tape OUI pour continuer") -ceq 'OUI'
}
function Test-GmEntryRestored {
    # Vrai si la valeur actuelle est identique à l'origine enregistrée
    param($e)
    switch ($e.Type) {
        'registre' {
            $n = Get-NgRegSnapshot $e.Cible $e.Nom
            if ($e.Existait) { return ($n.Existait -and $n.Type -eq $e.TypeOrigine -and "$($n.Valeur)" -eq "$($e.ValeurOrigine)") }
            return (-not $n.Existait)
        }
        'powercfg' { return ((Get-NgActivePowerScheme) -eq $e.ValeurOrigine) }
        'priorite' {
            $p = Get-Process -Id $e.Pid -ErrorAction SilentlyContinue
            if (-not $p -or $p.StartTime.ToString('s') -ne $e.Demarrage) { return $true }   # processus fermé : rien à restaurer
            return ([string]$p.PriorityClass -eq $e.ValeurOrigine)
        }
        default { return $true }
    }
}

# =====================================================================================
function Invoke-GmNormal {
    param([switch]$AfterInterruption)
    $st = Get-GmState
    if (-not $st -or $st.Mode -ne 'jeu') { Write-Host 'Déjà en Mode Normal : rien à restaurer.'; return }
    if ($AfterInterruption) {
        Write-Host "ATTENTION : le Mode Jeu est resté actif (activé le $($st.Debut)). Le script, la session ou le PC a été interrompu avant le retour au Mode Normal." -ForegroundColor Yellow
    }
    $j = Read-NgJournal $st.Session
    $entries = @($j.Data.Entrees | Where-Object { $_.Etat -in @('fait', 'prevu', 'echec') } | Sort-Object { [int]$_.N } -Descending)
    Write-Host "SIMULATION du retour au Mode Normal ($($entries.Count) changement(s) journalisé(s)) :" -ForegroundColor Cyan
    foreach ($e in $entries) {
        $r = Restore-NgJournalEntry -Entry $e -WhatIf:$true
        Write-Host ("  #{0} {1} {2} : {3}" -f $e.N, $e.Type, $(if ($e.Nom) { $e.Nom } else { $e.Cible }), $(switch ($r) { 'simule' { "remis à $($e.ValeurOrigine)" } 'deja' { 'déjà à l''origine' } default { 'processus fermé, rien à faire' } }))
    }
    if ($isWhatIf) { Write-Host 'Simulation (-WhatIf) : rien n''a été modifié.'; return }
    if (-not (Confirm-Oui 'Retour au Mode Normal.')) { Write-Host 'Annulé : le Mode Jeu reste actif.'; return }
    foreach ($e in $entries) {
        try {
            [void](Restore-NgJournalEntry -Entry $e -WhatIf:$false)
            $e | Add-Member -NotePropertyName Etat -NotePropertyValue 'annule' -Force
            Save-NgJournal $j
        } catch { Write-Host ("  #{0} ÉCHEC : {1}" -f $e.N, $_.Exception.Message) -ForegroundColor Red; Write-NgLog $j "Normal #$($e.N) ÉCHEC : $($_.Exception.Message)" }
    }
    $bad = @($entries | Where-Object { -not (Test-GmEntryRestored $_) })
    if ($bad.Count) {
        $j.Data.Etat = 'annulation_partielle'; Save-NgJournal $j
        Write-Host "État d'origine PAS entièrement restauré : $(($bad | ForEach-Object { "#$($_.N) $($_.Nom)$($_.Cible)" }) -join ', '). Le Mode Jeu reste marqué actif ; journal : $($j.Path)" -ForegroundColor Red
        return
    }
    $j.Data.Etat = 'annulee'; Save-NgJournal $j
    Write-NgLog $j 'Retour au Mode Normal : état d''origine vérifié identique'
    Save-GmState @{ Mode = 'normal'; Session = $st.Session; Debut = $st.Debut; Fin = (Get-Date).ToString('s') }
    Write-Host 'Mode Normal : état d''origine restauré et vérifié à l''identique.' -ForegroundColor Green
}

function Invoke-GmJeu {
    $st = Get-GmState
    if ($st -and $st.Mode -eq 'jeu') {
        Write-Host "Le Mode Jeu est déjà actif (depuis le $($st.Debut)), ou a été interrompu. Repasse d'abord en Mode Normal : .\GameMode.ps1 -Mode Normal" -ForegroundColor Yellow
        return
    }
    Write-Host 'SIMULATION du Mode Jeu (rien n''est modifié) :' -ForegroundColor Cyan
    $plan = New-Object Collections.Generic.List[object]
    if ($cfg.planAlimentation -and $cfg.planAlimentation.actif) {
        $g = $cfg.planAlimentation.guid
        if (-not (Test-NgPowerSchemeExists $g)) { Write-Host "  Plan $g absent de cette machine : ignoré." -ForegroundColor DarkGray }
        else {
            $r = Set-NgPowerSchemeLogged -Session $null -ActionId 'GM-PLAN' -Guid $g -WhatIf:$true
            Write-Host "  Plan d'alimentation : $(if ($r -eq 'deja') { "déjà « $(Get-NgPowerSchemeName $g) »" } else { "« $(Get-NgPowerSchemeName (Get-NgActivePowerScheme)) » -> « $(Get-NgPowerSchemeName $g) »" })"
            if ($r -eq 'simule') { $plan.Add(@{ Kind = 'plan'; Guid = $g }) }
        }
    }
    foreach ($i in $regItems) {
        try {
            $r = Set-NgRegistryValueLogged -Session $null -ActionId $i.id -Path $i.chemin -Name $i.nom -Type $i.type -Value $i.valeur -WhatIf:$true
            Write-Host "  [$($i.id)] $($i.titre) : $(if ($r -eq 'deja') { 'déjà en place' } else { 'serait appliqué' })$(if (-not $i.sourceVerifiee) { ' (non vérifié, activé par toi)' })"
            if ($r -eq 'simule') { $plan.Add(@{ Kind = 'reg'; Item = $i }) }
        } catch { Write-Host "  [$($i.id)] REFUSÉ : $($_.Exception.Message)" -ForegroundColor Red }
    }
    foreach ($pi in $procItems) {
        foreach ($p in @(Get-Process -Name $pi.nom -ErrorAction SilentlyContinue)) {
            if (Test-NgProtectedProcess $p) { Write-Host "  $($p.ProcessName) (PID $($p.Id)) : REFUSÉ (processus protégé)" -ForegroundColor Red; continue }
            $r = Set-NgProcessPriorityLogged -Session $null -ActionId "GM-PRIO-$($pi.nom)" -Process $p -Priority $pi.priorite -WhatIf:$true
            Write-Host "  $($p.ProcessName) (PID $($p.Id)) : priorité $($p.PriorityClass) -> $($pi.priorite)$(if ($r -eq 'deja') { ' (déjà)' })"
            if ($r -eq 'simule') { $plan.Add(@{ Kind = 'prio'; Proc = $p; Prio = $pi.priorite; Nom = $pi.nom }) }
        }
    }
    if (-not $procItems.Count) { Write-Host '  Aucun programme de fond validé (config\game_mode.local.json, "actif": true).' -ForegroundColor DarkGray }
    Write-Host "  Rappel : Windows 11 coupe déjà les notifications pendant un jeu si « Ne pas déranger automatiquement > quand je joue » est coché (Paramètres > Système > Notifications)." -ForegroundColor DarkGray
    if ($isWhatIf) { Write-Host 'Simulation (-WhatIf) : rien n''a été modifié.'; return }
    if (-not $plan.Count) { Write-Host 'Rien à changer : le Mode Jeu n''est pas activé.'; return }
    if (-not (Confirm-Oui "$($plan.Count) changement(s) pour le Mode Jeu.")) { Write-Host 'Annulé : rien n''a été modifié.'; return }

    # 1) journal, 2) état « jeu » sur le disque, 3) seulement ensuite les changements
    $s = New-NgSession -Outil 'GameMode' -Profil 'Jeu' -LogsDir $StateDir
    Save-GmState @{ Mode = 'jeu'; Session = $s.Dir; Debut = (Get-Date).ToString('s') }
    $done = 0
    foreach ($step in $plan) {
        try {
            switch ($step.Kind) {
                'plan' { [void](Set-NgPowerSchemeLogged -Session $s -ActionId 'GM-PLAN' -Guid $step.Guid -WhatIf:$false) }
                'reg' { $i = $step.Item; [void](Set-NgRegistryValueLogged -Session $s -ActionId $i.id -Path $i.chemin -Name $i.nom -Type $i.type -Value $i.valeur -WhatIf:$false) }
                'prio' { [void](Set-NgProcessPriorityLogged -Session $s -ActionId "GM-PRIO-$($step.Nom)" -Process $step.Proc -Priority $step.Prio -WhatIf:$false) }
            }
            $done++
        } catch { Write-Host "  ÉCHEC : $($_.Exception.Message)" -ForegroundColor Red }
        if ($StopAfterStep -gt 0 -and $done -ge $StopAfterStep) { throw "Interruption simulée après $done changement(s) (test)." }
    }
    $s.Data.Etat = 'jeu_actif'; Save-NgJournal $s
    Write-Host "Mode Jeu actif : $done changement(s). Retour : option 6 du menu ou .\GameMode.ps1 -Mode Normal" -ForegroundColor Green
}

switch ($Mode) {
    'Jeu' { Invoke-GmJeu }
    'Normal' { Invoke-GmNormal }
    'Reprise' {
        $st = Get-GmState
        if ($st -and $st.Mode -eq 'jeu') { Invoke-GmNormal -AfterInterruption } else { Write-Host 'Aucun Mode Jeu en suspens.' }
    }
    'Etat' {
        $st = Get-GmState
        $m = if ($st -and $st.Mode -eq 'jeu') { "JEU (depuis le $($st.Debut))" } else { 'normal' }
        Write-Host "Mode actuel : $m ; plan d'alimentation : $(Get-NgPowerSchemeName (Get-NgActivePowerScheme))"
    }
}
