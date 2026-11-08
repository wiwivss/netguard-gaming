<#
.SYNOPSIS
    Annule une session : rejoue logs\session_<date>\journal.json à l'envers.
.DESCRIPTION
    Pour chaque entrée (de la dernière à la première) : remet la valeur et le type d'origine,
    supprime une valeur qui n'existait pas, remet le plan d'alimentation d'origine.
    Les entrées 'prevu' (arrêt entre le journal et le changement) sont aussi restaurées.
    Simulation d'abord, puis réel après « OUI ». Les exports .reg du dossier de session
    restent disponibles en secours (double-clic = réimport).
    Pare-feu : netguard n'a modifié aucune règle ; les commandes Enable-NetFirewallRule de
    la session sont réaffichées.
.EXAMPLE
    .\Undo.ps1 -Liste
    .\Undo.ps1                         # dernière session non annulée
    .\Undo.ps1 -Session session_2026-11-08_170000 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Session,
    [switch]$Liste,
    [switch]$Oui,
    [string]$LogsDir
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
if (-not $LogsDir) { $LogsDir = Get-NgPath 'logs' }

$all = @(Get-ChildItem -LiteralPath $LogsDir -Directory -Filter 'session_*' -ErrorAction SilentlyContinue |
        Where-Object { Test-Path (Join-Path $_.FullName 'journal.json') } | Sort-Object Name -Descending)

if ($Liste) {
    if (-not $all) { Write-Host "Aucune session dans $LogsDir."; return }
    $all | ForEach-Object {
        $j = Read-NgJournal $_.FullName
        [pscustomobject]@{ Session = $_.Name; Outil = $j.Data.Outil; Profil = $j.Data.Profil; Etat = $j.Data.Etat; Entrees = @($j.Data.Entrees).Count }
    } | Format-Table -AutoSize | Out-String | Write-Host
    return
}

if ($Session) {
    $dir = if (Test-Path -LiteralPath $Session) { (Resolve-Path -LiteralPath $Session).Path } else { Join-Path $LogsDir $Session }
    if (-not (Test-Path -LiteralPath (Join-Path $dir 'journal.json'))) { throw "Session introuvable : $Session" }
} else {
    $pick = $all | Where-Object { (Read-NgJournal $_.FullName).Data.Etat -ne 'annulee' } | Select-Object -First 1
    if (-not $pick) { Write-Host 'Aucune session à annuler.'; return }
    $dir = $pick.FullName
}
$j = Read-NgJournal $dir
$entries = @($j.Data.Entrees | Where-Object { $_.Etat -in @('fait', 'prevu', 'echec') } | Sort-Object { [int]$_.N } -Descending)
Write-Host "Session $(Split-Path $dir -Leaf) ($($j.Data.Outil), profil '$($j.Data.Profil)', état $($j.Data.Etat)) : $($entries.Count) entrée(s) à rejouer." -ForegroundColor Cyan

# Simulation
$need = New-Object Collections.Generic.List[object]
foreach ($e in $entries) {
    $r = Restore-NgJournalEntry -Entry $e -WhatIf:$true
    $msg = switch ($r) { 'deja' { 'déjà à la valeur d''origine' } 'simule' { 'serait restauré' } default { 'rien à faire' } }
    Write-Host ("  #{0} [{1}] {2} {3} : {4}" -f $e.N, $e.Action, $e.Type, "$($e.Cible)$(if ($e.Nom) { '\' + $e.Nom })", $msg)
    if ($r -eq 'simule') { $need.Add($e) }
}
$fwe = @($j.Data.Entrees | Where-Object { $_.Type -eq 'pare-feu-export' })
foreach ($f in $fwe) {
    Write-Host '  Pare-feu : netguard n''a modifié aucune règle. Si tu as lancé les commandes de désactivation, annulation (PowerShell admin) :' -ForegroundColor Yellow
    @($f.Regles) | ForEach-Object { Write-Host "    Enable-NetFirewallRule -Name '$_'" }
}
if ($WhatIfPreference) { Write-Host 'Simulation (-WhatIf) : rien n''a été modifié.'; return }
if (-not $need.Count) {
    Write-Host 'Tout est déjà à l''état d''origine.'
    if ($j.Data.Etat -ne 'annulee') { $j.Data.Etat = 'annulee'; Save-NgJournal $j; Write-NgLog $j 'Undo : rien à restaurer, session marquée annulée' }
    return
}
$go = if ($Oui) { $true } else { (Read-Host "$($need.Count) restauration(s). Tape OUI pour continuer") -ceq 'OUI' }
if (-not $go) { Write-Host 'Annulé : rien n''a été modifié.'; return }

$ok = 0; $ko = 0
foreach ($e in $entries) {
    try {
        $r = Restore-NgJournalEntry -Entry $e -WhatIf:$false
        $e | Add-Member -NotePropertyName Etat -NotePropertyValue 'annule' -Force
        Save-NgJournal $j
        Write-NgLog $j "Undo #$($e.N) [$($e.Action)] : $r"
        if ($r -eq 'restaure') { Write-Host ("  #{0} restauré" -f $e.N) -ForegroundColor Green; $ok++ }
    } catch { Write-Host ("  #{0} ÉCHEC : {1}" -f $e.N, $_.Exception.Message) -ForegroundColor Red; Write-NgLog $j "Undo #$($e.N) ÉCHEC : $($_.Exception.Message)"; $ko++ }
}
if (-not $ko) { $j.Data.Etat = 'annulee' } else { $j.Data.Etat = 'annulation_partielle' }
Save-NgJournal $j
Write-Host "$ok restauré(s), $ko échec(s). En secours : exports .reg dans $dir"
