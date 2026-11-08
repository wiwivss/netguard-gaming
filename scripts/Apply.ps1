<#
.SYNOPSIS
    Applique un profil du catalogue (config\actions.json) : simulation d'abord, puis réel après « OUI ».
.DESCRIPTION
    Profils : Prudent | Équilibré | Avancé (voir config\actions.json).
    - Réglages « auto » (powercfg, registre HKCU) : appliqués par ce script, SANS admin, avec
      journal logs\session_<date>\journal.json écrit AVANT chaque changement (+ export .reg).
    - Réglages « admin » : commandes AFFICHÉES, jamais lancées.
    - Pare-feu (-PareFeu) : revue règle par règle ; export JSON de la règle avant ; seules les
      règles hors Windows sont proposées ; la commande de DÉSACTIVATION est affichée (jamais
      de suppression).
    - Réglages « non vérifiés » (sans source officielle) : ignorés sauf -Inclure NG-xxx.
    - Placebos et interdits : jamais appliqués, quel que soit le profil.
    Annulation : Undo.ps1 (option 5 du menu).
.EXAMPLE
    .\Apply.ps1 -Profil Prudent -WhatIf     # simulation seule
    .\Apply.ps1 -Profil Équilibré           # simulation, puis « OUI » pour appliquer
    .\Apply.ps1 -Manuel -Profil Avancé      # fiches manuelles et commandes admin (lecture seule)
    .\Apply.ps1 -PareFeu                    # revue des règles larges / orphelines, une par une
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Profil = 'Prudent',
    [string[]]$Inclure = @(),
    [string[]]$Exclure = @(),
    [switch]$Manuel,
    [switch]$PareFeu,
    # Saute la question « OUI » (tests automatisés, Test-NetGuard.ps1). La simulation est quand même affichée.
    [switch]$Oui,
    [string]$CatalogPath,
    [string]$LogsDir,
    [string]$AuditPath
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
if (-not $LogsDir) { $LogsDir = Get-NgPath 'logs' }

# Profil : accepte « Equilibre », « équilibré », etc.
$norm = ($Profil.ToLower() -replace '[éè]', 'e')
$Profil = switch -Wildcard ($norm) { 'prud*' { 'Prudent' } 'equi*' { 'Équilibré' } 'avan*' { 'Avancé' } default { throw "Profil inconnu : $Profil (Prudent, Équilibré ou Avancé)." } }

$catalog = if ($CatalogPath) { @((Get-Content -LiteralPath $CatalogPath -Raw -Encoding UTF8 | ConvertFrom-Json).actions) } else { @((Get-NgConfig 'actions').actions) }
$isWhatIf = [bool]$WhatIfPreference

function Show-Title { param([string]$t) Write-Host ''; Write-Host "== $t ==" -ForegroundColor Cyan }
function Confirm-Oui {
    param([string]$Question)
    if ($Oui) { Write-Host "$Question  -> OUI (paramètre -Oui)"; return $true }
    (Read-Host "$Question  Tape OUI pour continuer, autre chose pour annuler") -ceq 'OUI'
}

# =====================================================================================
# SÉLECTION
# =====================================================================================
$sel = New-Object Collections.Generic.List[object]; $skipped = New-Object Collections.Generic.List[string]
foreach ($a in $catalog) {
    $inProfile = @($a.profils) -contains $Profil
    $forced = $Inclure -contains $a.id
    if ($Exclure -contains $a.id) { continue }
    if (-not ($inProfile -or $forced)) { continue }
    if ($a.interdit -or $a.nonRecommande) { $skipped.Add("$($a.id) $($a.titre) : jamais appliqué ($($a.classement))"); continue }
    # Sans source officielle : jamais appliqué/affiché comme commande sans opt-in.
    # Une fiche MANUELLE reste affichée (marquée « non vérifié ») : la lire ne change rien.
    if (-not $a.sourceVerifiee -and -not $forced -and $a.methode -ne 'manuel') { $skipped.Add("$($a.id) $($a.titre) : source non vérifiée, opt-in avec -Inclure $($a.id)"); continue }
    $sel.Add($a)
}
# Deux plans d'alimentation demandés : le dernier du catalogue l'emporte
$pw = @($sel | Where-Object { $_.methode -eq 'powercfg' })
if ($pw.Count -gt 1) { foreach ($x in $pw[0..($pw.Count - 2)]) { [void]$sel.Remove($x); $skipped.Add("$($x.id) remplacé par $($pw[-1].id) (un seul plan d'alimentation à la fois)") } }

$auto = @($sel | Where-Object { $_.methode -in @('powercfg', 'registre') })
$admin = @($sel | Where-Object { $_.methode -eq 'admin' })
$fw = @($sel | Where-Object { $_.methode -eq 'pare-feu' })
$manual = @($sel | Where-Object { $_.methode -eq 'manuel' })

# =====================================================================================
# MODE -Manuel : fiches et commandes admin (aucune écriture)
# =====================================================================================
function Show-Cards {
    param($List, [string]$Title)
    if (-not @($List).Count) { return }
    Show-Title $Title
    foreach ($a in $List) {
        Write-Host ("[{0}] {1}  (risque {2}, {3}{4})" -f $a.id, $a.titre, $a.risque, $a.classement, $(if (-not $a.sourceVerifiee) { ', NON VÉRIFIÉ' })) -ForegroundColor Yellow
        Write-Host "    $($a.quoi)"
        if ($a.risqueDetail) { Write-Host "    Attention : $($a.risqueDetail)" -ForegroundColor DarkYellow }
        if ($a.commande) { Write-Host "    Commande : $($a.commande)" -ForegroundColor Gray }
        if ($a.annulation) { Write-Host "    Annulation : $($a.annulation)" -ForegroundColor DarkGray }
        Write-Host "    Source : $(if ($a.source) { $a.source } else { 'aucune source officielle (non vérifié)' })" -ForegroundColor DarkGray
    }
}
if ($Manuel) {
    Write-Host "Profil $Profil : fiches à suivre toi-même. Rien n'est lancé." -ForegroundColor Cyan
    Show-Cards $admin 'Commandes ADMINISTRATEUR (à copier dans un PowerShell admin, après lecture)'
    Show-Cards $fw 'Pare-feu (revue règle par règle : .\Apply.ps1 -PareFeu)'
    Show-Cards $manual 'Fiches manuelles'
    if ($skipped.Count) { Show-Title 'Non proposés'; $skipped | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkGray } }
    return
}

# =====================================================================================
# MODE -PareFeu : revue règle par règle (affiche les commandes, ne modifie rien)
# =====================================================================================
if ($PareFeu) {
    if (-not $AuditPath) {
        $last = Get-ChildItem -LiteralPath (Get-NgPath 'reports') -Directory -Filter 'audit_*' -ErrorAction SilentlyContinue | Sort-Object Name -Descending |
            Where-Object { Test-Path (Join-Path $_.FullName 'audit.json') } | Select-Object -First 1
        if (-not $last) { throw "Aucun audit : lance d'abord l'option 1." }
        $AuditPath = Join-Path $last.FullName 'audit.json'
    }
    $au = Get-Content -LiteralPath $AuditPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $cands = @(@($au.Securite.PareFeu.ReglesLarges) + @($au.Securite.PareFeu.ReglesProgrammeAbsent) | Where-Object { $_ -and -not $_.Systeme } | Sort-Object Id -Unique)
    Show-Title "Revue du pare-feu : $($cands.Count) règle(s) hors Windows (audit $(Split-Path (Split-Path $AuditPath) -Leaf))"
    Write-Host 'Pour chaque règle : o = proposer la désactivation, n (ou Entrée) = garder, q = arrêter. Rien n''est modifié par ce script.'
    $chosen = New-Object Collections.Generic.List[object]
    foreach ($c in $cands) {
        $r = Get-NetFirewallRule -Name $c.Id -ErrorAction SilentlyContinue
        if (-not $r) { Write-Host "  [absente] $($c.Nom) : la règle n'existe plus." -ForegroundColor DarkGray; continue }
        if (Test-NgSystemFirewallRule $r) { Write-Host "  [REFUSÉ] $($r.DisplayName) : règle Windows." -ForegroundColor DarkGray; continue }
        if ($r.Enabled -ne 'True') { Write-Host "  [déjà désactivée] $($r.DisplayName)" -ForegroundColor DarkGray; continue }
        Write-Host ''
        Write-Host ("  {0}  [{1}] profils {2}, {3}, public : {4}" -f $r.DisplayName, $c.Protocole, $c.Profils, $(if ($c.ProgrammeAbsent) { 'PROGRAMME ABSENT' } else { 'programme présent' }), $(if ($c.Public) { 'oui' } else { 'non' })) -ForegroundColor Yellow
        Write-Host "    $($c.Programme)" -ForegroundColor DarkGray
        if ($isWhatIf) { continue }
        $ans = if ($Oui) { 'n' } else { Read-Host '    Désactiver ? (o/N/q)' }
        if ($ans -eq 'q') { break }
        if ($ans -eq 'o') { Assert-NgFirewallRuleAllowed $r; $chosen.Add($r) }
    }
    if ($isWhatIf) { Write-Host "`nSimulation : aucune question posée, aucun fichier écrit."; return }
    if (-not $chosen.Count) { Write-Host "`nAucune règle retenue. Rien n'est écrit."; return }
    # Export JSON complet AVANT d'afficher la moindre commande (règle 6)
    $s = New-NgSession -Outil 'Apply -PareFeu' -LogsDir $LogsDir
    $export = foreach ($r in $chosen) {
        [pscustomobject]@{
            Name = $r.Name; DisplayName = $r.DisplayName; Group = $r.Group; Enabled = [string]$r.Enabled; Direction = [string]$r.Direction
            Action = [string]$r.Action; Profile = [string]$r.Profile
            Program = ($r | Get-NetFirewallApplicationFilter).Program
            Protocol = ($r | Get-NetFirewallPortFilter).Protocol; LocalPort = ($r | Get-NetFirewallPortFilter).LocalPort
            RemoteAddress = ($r | Get-NetFirewallAddressFilter).RemoteAddress
        }
    }
    $exp = Join-Path $s.Dir 'pare-feu_export.json'
    [IO.File]::WriteAllText($exp, (@($export) | ConvertTo-Json -Depth 4), (New-Object Text.UTF8Encoding($true)))
    $e = Add-NgJournalEntry $s @{ Action = 'NG-008/NG-009'; Type = 'pare-feu-export'; Cible = $exp; Regles = @($chosen | ForEach-Object { $_.Name }) }
    Set-NgJournalEntryState $s $e 'fait' 'export seulement : aucune règle modifiée par netguard'
    $cmd = ($chosen | ForEach-Object { "Disable-NetFirewallRule -Name '$($_.Name)'   # $($_.DisplayName)" }) -join "`r`n"
    $undo = ($chosen | ForEach-Object { "Enable-NetFirewallRule -Name '$($_.Name)'" }) -join "`r`n"
    [IO.File]::WriteAllText((Join-Path $s.Dir 'commandes_admin.txt'), "# À lancer dans un PowerShell ADMINISTRATEUR, après lecture.`r`n$cmd`r`n`r`n# Annulation :`r`n$undo`r`n", (New-Object Text.UTF8Encoding($true)))
    $s.Data.Etat = 'terminee'; Save-NgJournal $s
    Show-Title "Export : $exp"
    Write-Host 'Commandes à lancer TOI-MÊME dans un PowerShell administrateur :' -ForegroundColor Yellow
    Write-Host $cmd
    Write-Host "`nAnnulation :" -ForegroundColor DarkGray; Write-Host $undo -ForegroundColor DarkGray
    return
}

# =====================================================================================
# APPLICATION : simulation, puis réel
# =====================================================================================
function Invoke-NgAction {
    param($a, $Session, [bool]$Simulate)
    switch ($a.application.type) {
        'powercfg' { Set-NgPowerSchemeLogged -Session $Session -ActionId $a.id -Guid $a.application.guid -WhatIf:$Simulate }
        'registre' { Set-NgRegistryValueLogged -Session $Session -ActionId $a.id -Path $a.application.chemin -Name $a.application.nom -Type $a.application.typeValeur -Value $a.application.valeur -WhatIf:$Simulate }
        default { throw "Type d'application inconnu pour $($a.id)." }
    }
}
$label = @{ deja = 'déjà conforme'; simule = 'serait appliqué'; fait = 'APPLIQUÉ' }

Show-Title "SIMULATION, profil $Profil (rien n'est modifié)"
$todo = New-Object Collections.Generic.List[object]
foreach ($a in $auto) {
    try {
        $r = Invoke-NgAction $a $null $true
        Write-Host ("  [{0}] {1} : {2}" -f $a.id, $a.titre, $label[$r])
        if ($r -eq 'simule') { $todo.Add($a) }
    } catch { Write-Host ("  [{0}] {1} : IGNORÉ ({2})" -f $a.id, $a.titre, $_.Exception.Message) -ForegroundColor Red }
}
if (-not $auto.Count) { Write-Host '  Aucun réglage automatique dans ce profil.' }
if ($admin.Count + $fw.Count + $manual.Count) {
    Write-Host ("  + {0} commande(s) admin, {1} revue(s) pare-feu, {2} fiche(s) manuelle(s) : affichées par l'option 4 (Apply.ps1 -Manuel), jamais lancées." -f $admin.Count, $fw.Count, $manual.Count) -ForegroundColor DarkGray
}
if ($skipped.Count) { $skipped | ForEach-Object { Write-Host "  - $_" -ForegroundColor DarkGray } }

if ($isWhatIf) { Write-Host "`nSimulation terminée (-WhatIf) : aucun fichier écrit."; return }
if (-not $todo.Count) { Write-Host "`nRien à appliquer : aucune session créée."; return }
if (-not (Confirm-Oui "`n$($todo.Count) réglage(s) à appliquer.")) { Write-Host 'Annulé : rien n''a été modifié.'; return }

$s = New-NgSession -Outil 'Apply' -Profil $Profil -LogsDir $LogsDir
Show-Title "APPLICATION (journal : $($s.Path))"
$ok = 0; $ko = 0
foreach ($a in $todo) {
    try {
        $r = Invoke-NgAction $a $s $false
        Write-Host ("  [{0}] {1} : {2}" -f $a.id, $a.titre, $label[$r]) -ForegroundColor Green; $ok++
    } catch { Write-Host ("  [{0}] {1} : ÉCHEC ({2})" -f $a.id, $a.titre, $_.Exception.Message) -ForegroundColor Red; $ko++ }
}
$s.Data.Etat = 'terminee'; Save-NgJournal $s
Write-NgLog $s "Session terminée : $ok appliqué(s), $ko échec(s)"
Write-Host "`n$ok appliqué(s), $ko échec(s). Annulation : .\Undo.ps1 -Session '$(Split-Path $s.Dir -Leaf)' (option 5 du menu)."
Write-Host 'Mesure de l''effet : option 7 (Verify.ps1).' -ForegroundColor DarkGray
