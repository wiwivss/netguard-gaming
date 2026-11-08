<#
.SYNOPSIS
    Génère le rapport HTML de l'audit (privé + version partageable masquée).
.DESCRIPTION
    Lit reports\audit_<date>\audit.json (le plus récent par défaut) et config\actions.json,
    puis écrit :
      reports\rapport_audit.html              : rapport complet (reste sur ta machine, ignoré par Git)
      reports\rapport_audit_partageable.html  : IP, MAC, SSID, e-mails, SID, nom du PC et
                                                 d'utilisateur masqués ; écriture REFUSÉE si
                                                 un contrôle trouve encore une fuite.
    Lecture seule pour le système : n'écrit QUE dans reports\.
.EXAMPLE
    .\New-AuditReport.ps1            # dernier audit
    .\New-AuditReport.ps1 -Open      # et ouvre le rapport
    .\New-AuditReport.ps1 -WhatIf    # n'écrit rien
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$AuditPath,
    [string]$ReportsDir,
    [switch]$Open
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')

if (-not $ReportsDir) { $ReportsDir = Get-NgPath 'reports' }
if (-not $AuditPath) {
    $last = Get-ChildItem -LiteralPath $ReportsDir -Directory -Filter 'audit_*' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Where-Object { Test-Path (Join-Path $_.FullName 'audit.json') } | Select-Object -First 1
    if (-not $last) { throw "Aucun audit trouvé dans $ReportsDir : lance d'abord Audit.ps1 (option 1 du menu)." }
    $AuditPath = Join-Path $last.FullName 'audit.json'
}
$Aud = Get-Content -LiteralPath $AuditPath -Raw -Encoding UTF8 | ConvertFrom-Json
$catalog = @((Get-NgConfig 'actions').actions)
$fr = [Globalization.CultureInfo]'fr-FR'

# NB : pas de fonction nommée 'H' (alias intégré de Get-History, prioritaire sur les fonctions).
# NB : $A et $a sont la MÊME variable en PowerShell : l'audit s'appelle $Aud.
# ---- Seuils (les mêmes que Verify.ps1) ------------------------------------------------
$script:SeuilDnsMs = $script:NgSeuilDnsMs      # seuils communs (Common.ps1)
$script:SeuilLatMs = $script:NgSeuilLatenceMs
$script:SeuilPerte = $script:NgSeuilPertePts

# =====================================================================================
# OUTILS
# =====================================================================================
function Esc { param($s) if ($null -eq $s) { return '' } [System.Net.WebUtility]::HtmlEncode([string]$s) }
function N {
    # Piège PS : « 0 -eq '' » vaut VRAI (la chaîne est convertie en nombre) : tester le type d'abord
    param($v, [string]$f = '0.#')
    if ($null -eq $v -or ($v -is [string] -and $v -eq '')) { return '—' }
    ([double]$v).ToString($f, $fr)
}
function Badge { param([string]$Text, [string]$Kind) "<span class=""b b-$Kind"">$(Esc $Text)</span>" }
function RiskBadge { param([string]$r) switch ($r) { 'vert' { Badge 'vert' 'ok' } 'orange' { Badge 'orange' 'warn' } 'rouge' { Badge 'rouge' 'bad' } default { Badge $r 'mut' } } }
function LevelBadge { param([string]$l) switch ($l) { 'critique' { Badge 'CRITIQUE' 'bad' } 'attention' { Badge 'attention' 'warn' } default { Badge 'info' 'mut' } } }
function Table {
    # $rows = tableau de tableaux de cellules DÉJÀ encodées en HTML
    param([string[]]$Head, $Rows, [string]$Class = '')
    $sb = New-Object Text.StringBuilder
    [void]$sb.Append("<div class=""tw""><table class=""$Class""><thead><tr>")
    foreach ($h in $Head) { [void]$sb.Append("<th>$(Esc $h)</th>") }
    [void]$sb.Append('</tr></thead><tbody>')
    foreach ($r in $Rows) {
        [void]$sb.Append('<tr>')
        foreach ($c in $r) { [void]$sb.Append("<td>$c</td>") }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div>')
    $sb.ToString()
}
function SrcLink {
    param($a)
    if ($a.sourceVerifiee -and $a.source) { return "<a href=""$(Esc $a.source)"" rel=""noopener"">source</a>" }
    if ($a.source) { return "<a href=""$(Esc $a.source)"" rel=""noopener"">source</a> " + (Badge 'non vérifié' 'warn') }
    Badge 'non vérifié' 'warn'
}
function Find-Constat { param([string]$Pattern) @($Aud.Constats | Where-Object { $_.Texte -match $Pattern }) }

$sec = $Aud.Securite; $sys = $sec.Systeme; $jeu = $Aud.Jeu; $reg = $jeu.Reglages; $net = $Aud.Reseau
$knownPlans = @('381b4222-f694-41f0-9685-ff5bb260df2e', '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c', 'a1841308-3541-4fab-bc81-f71556f20b4a', 'e9a42b02-d5df-448d-aa00-03f14749eb61')

# =====================================================================================
# ÉTAT DE CHAQUE ACTION DU CATALOGUE (d'après l'audit)
#   a_faire        : le réglage s'applique à ta machine
#   conforme       : déjà dans le bon état
#   optionnel      : possible, mais aucun problème constaté
#   non_recommande : mesuré inutile ici, placebo, ou interdit par le projet
#   inconnu        : l'audit n'a pas pu le mesurer
# =====================================================================================
function Get-ActionState {
    param($a)
    $s = 'inconnu'; $e = 'non mesuré'
    switch ($a.detection) {
        'winrar' {
            $c = Find-Constat 'WinRAR'
            if ($c) { $s = 'a_faire'; $e = ($c[0].Texte -split ' : ')[0] } else { $s = 'conforme'; $e = 'pas de WinRAR vulnérable détecté' }
        }
        'hosts' {
            $hr = $sec.Reseau.HostsRedirections
            if ($hr -and $hr.Lignes -gt 0) { $s = 'a_faire'; $e = "$($hr.Lignes) ligne(s) vers une IP externe ($(@($hr.IpCibles) -join ', ')), modifié le $(([datetime]$hr.ModifieLe).ToString('dd/MM/yyyy'))" }
            else { $s = 'conforme'; $e = 'aucune redirection vers une IP externe' }
        }
        'sshd' {
            $p = @($sec.PortsEcoute | Where-Object { $_.Processus -eq 'sshd.exe' })
            if ($p) { $s = 'a_faire'; $e = "en écoute sur TCP $($p[0].Port), pare-feu : " + $(if ($p[0].PareFeuAutorise) { "autorisé ($($p[0].ProfilsAutorises))" } else { 'bloqué' }) }
            else { $s = 'conforme'; $e = 'sshd absent ou arrêté' }
        }
        'tamper' {
            if ($null -eq $sys.Defender.ProtectionFalsification) { $s = 'inconnu' }
            elseif ($sys.Defender.ProtectionFalsification) { $s = 'conforme'; $e = 'activée' } else { $s = 'a_faire'; $e = 'désactivée' }
        }
        'bufferbloat' {
            $v = $net.Bufferbloat.Verdict
            if (-not $v) { $s = 'inconnu'; $e = 'non mesuré (audit avec -LoadTest, après ton accord)' }
            else {
                $e = "note $v (envoi +$(N $net.Bufferbloat.Envoi.AjoutMs) ms, téléchargement +$(N $net.Bufferbloat.Telechargement.AjoutMs) ms)"
                if ($v -in @('C', 'D', 'F')) { $s = 'a_faire' } elseif ($v -eq 'B') { $s = 'optionnel' } else { $s = 'conforme' }
            }
        }
        'powerplan_tiers' {
            $g = $reg.PlanAlimentation.Guid
            $e = $reg.PlanAlimentation.Nom
            if ($g -and $knownPlans -notcontains $g) { $s = 'a_faire' } elseif ($g) { $s = 'conforme' }
        }
        'powerplan_perf' {
            $e = $reg.PlanAlimentation.Nom
            if ($reg.PlanAlimentation.Guid -in @('8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c', 'e9a42b02-d5df-448d-aa00-03f14749eb61')) { $s = 'conforme' } else { $s = 'optionnel' }
        }
        'fw_larges' {
            $n = @($sec.PareFeu.ReglesLarges | Where-Object { -not $_.Systeme }).Count
            $pub = @($sec.PareFeu.ReglesLarges | Where-Object { -not $_.Systeme -and $_.Public }).Count
            if ($n) { $s = 'a_faire'; $e = "$n règle(s) tous ports / toute adresse, dont $pub sur le profil Public" } else { $s = 'conforme'; $e = 'aucune' }
        }
        'fw_absents' {
            $n = @($sec.PareFeu.ReglesProgrammeAbsent | Where-Object { -not $_.Systeme }).Count
            if ($n) { $s = 'a_faire'; $e = "$n règle(s) vers un programme absent" } else { $s = 'conforme'; $e = 'aucune' }
        }
        'llmnr' { $e = $sys.Llmnr; if ($e -match 'désactiv') { $s = 'conforme' } else { $s = 'optionnel' } }
        'netbios' {
            $e = (@($sys.NetBios | ForEach-Object { $_.NetBios }) -join ', ')
            if ($e -match 'désactiv') { $s = 'conforme' } else { $s = 'optionnel' }
        }
        'nic_eee' {
            $p = @($net.ProprietesCarte | Where-Object { $_.Cle -eq '*EEE' })
            if (-not $p) { $s = 'conforme'; $e = 'non proposé par la carte' }
            elseif ($p[0].ValeurBrute -eq '0') { $s = 'conforme'; $e = 'désactivé' } else { $s = 'optionnel'; $e = "activé ($($p[0].Valeur))" }
        }
        'nic_realtek' {
            $on = @($net.ProprietesCarte | Where-Object { $_.Cle -in @('EnableGreenEthernet', 'GigaLite', 'PowerSavingMode') -and $_.ValeurBrute -eq '1' } | ForEach-Object { $_.Nom })
            if ($on) { $s = 'optionnel'; $e = 'activés : ' + ($on -join ', ') } else { $s = 'conforme'; $e = 'désactivés ou absents' }
        }
        'nic_pnp' {
            if ($net.AlimentationCarte.WindowsPeutEteindre) { $s = 'optionnel'; $e = 'Windows peut éteindre la carte (valeur par défaut)' } else { $s = 'conforme'; $e = 'Windows ne peut pas éteindre la carte' }
        }
        'delivery_opt' {
            $d = $net.DeliveryOptimization
            $e = "$($d.ModeEffectif) ; ce mois : $($d.MoisTelechargeMo) Mo reçus, $($d.MoisEnvoyeInternetMo + $d.MoisEnvoyeLanMo) Mo envoyés"
            $s = 'optionnel'
        }
        'nic_driver' {
            $c = Find-Constat 'Pilote de la carte réseau'
            $e = "$($Aud.Contexte.Carte.Pilote) du $($Aud.Contexte.Carte.DatePilote)"
            if ($c) { $s = 'a_faire' } else { $s = 'conforme' }
        }
        'scanner' {
            $c = Find-Constat 'découverte / inventaire'
            if ($c) { $s = 'a_faire'; $e = 'outil actif : ' + (($c[0].Texte -replace '^.*actif \(', '') -replace '\).*$', '') } else { $s = 'conforme'; $e = 'aucun outil de balayage détecté' }
        }
        'winget' {
            $n = @($sec.Winget.Lignes).Count
            if ($null -eq $sec.Winget) { $s = 'inconnu'; $e = 'non vérifié (-SkipWinget)' }
            elseif ($n) { $s = 'a_faire'; $e = "$n mise(s) à jour en attente" } else { $s = 'conforme'; $e = 'tout est à jour' }
        }
        'hags' { $e = $reg.Hags; $s = 'optionnel' }
        'gamemode' { $e = $reg.ModeJeu; if ($e -match '^activé') { $s = 'conforme' } else { $s = 'a_faire' } }
        'gamedvr' {
            $e = "capture : $($reg.GameDvr.CaptureAutorisee) ; enregistrement en arrière-plan : $($reg.GameDvr.EnregistrementArrierePlan)"
            if ($reg.GameDvr.EnregistrementArrierePlan -match '^oui') { $s = 'a_faire' } else { $s = 'conforme' }
        }
        'souris' {
            if ($reg.AccelerationSouris.Active) { $s = 'optionnel'; $e = 'activée' } else { $s = 'conforme'; $e = 'désactivée' }
        }
        'smb1' {
            if ($sys.Smb.Smb1Serveur -or $sys.Smb.Smb1ClientInstalle) { $s = 'a_faire'; $e = 'SMBv1 actif' } else { $s = 'conforme'; $e = 'désactivé' }
        }
        'dns' {
            $cur = @($net.Dns | Where-Object { $_.Nom -like 'Actuel*' })[0]
            $best = @($net.Dns | Where-Object { $_.Nom -notlike 'Actuel*' -and $_.Echecs -lt $_.Requetes } | Sort-Object MedianeMs)[0]
            if ($cur -and $best) {
                $gain = [double]$cur.MedianeMs - [double]$best.MedianeMs
                if ($gain -ge $script:SeuilDnsMs) { $s = 'a_faire'; $e = "$($best.Nom) plus rapide de $(N $gain) ms (médiane)" }
                else { $s = 'non_recommande'; $e = "actuel $(N $cur.MedianeMs) ms, meilleur public $($best.Nom) $(N $best.MedianeMs) ms : écart < $script:SeuilDnsMs ms" }
            }
        }
        'ram_mix' {
            $c = Find-Constat 'kits mélangés'
            $r = $jeu.Materiel.Ram
            $e = "$($r.TotalGo) Go $($r.Type) à $($r.FrequenceReelle) MT/s, XMP/EXPO : $($r.ProfilXmpExpo)"
            if ($c) { $s = 'optionnel'; $e += ', kits différents' } else { $s = 'conforme' }
        }
        'nvidia' {
            $nv = $jeu.Materiel.Nvidia
            if (-not $nv) { $s = 'inconnu' }
            elseif ($null -eq $nv.AJour) { $s = 'inconnu'; $e = "installé $($nv.Version) (référence nvidia.com non fournie)" }
            elseif ($nv.AJour) { $s = 'conforme'; $e = "$($nv.Version) = dernière version publiée" } else { $s = 'a_faire'; $e = "$($nv.Version), dernière : $($nv.DerniereOfficielle)" }
        }
        'vbs' { $s = 'non_recommande'; $e = "VBS : $($jeu.Vbs.Etat) ; $($jeu.Vbs.ServicesEnCours) ; liste de blocage : $($jeu.Vbs.ListeBlocagePilotes)" }
        'mtu' { $s = 'non_recommande'; $e = "MTU du chemin mesuré : $($net.Mtu.Chemin.MtuChemin) (interface $($net.Mtu.Interface))" }
        default { $s = 'non_recommande'; $e = 'non appliqué (placebo ou interdit)' }
    }
    if ($a.nonRecommande) { $s = 'non_recommande' }
    [pscustomobject]@{ Statut = $s; Etat = $e }
}

$rows = foreach ($a in $catalog) {
    $st = Get-ActionState $a
    [pscustomobject]@{ Action = $a; Statut = $st.Statut; Etat = $st.Etat }
}

# =====================================================================================
# SCORES (formules volontairement simples et affichées dans le rapport)
# =====================================================================================
$lat = @($net.Latence.PSObject.Properties | ForEach-Object { $o = $_.Value; $o | Add-Member -NotePropertyName Nom -NotePropertyValue $_.Name -Force -PassThru })

function Get-NetScore {
    $pts = 100; $d = New-Object Collections.Generic.List[string]
    $bl = $net.Bufferbloat.Verdict
    $pen = @{ 'A+' = 0; 'A' = 0; 'B' = 10; 'C' = 25; 'D' = 40; 'F' = 50 }
    if ($bl -and $pen.ContainsKey($bl) -and $pen[$bl]) { $pts -= $pen[$bl]; $d.Add("−$($pen[$bl]) : bufferbloat noté $bl") }
    if (-not $bl) { $d.Add('bufferbloat non mesuré : non compté') }
    $prox = @($lat | Where-Object { $_.Type -eq 'proxy' -and $null -ne $_.MedianeMs } | Sort-Object MedianeMs)
    if ($prox) {
        $m = [double]$prox[0].MedianeMs
        if ($m -gt 60) { $pts -= 20; $d.Add("−20 : ville de jeu la plus proche à $(N $m) ms (> 60)") }
        elseif ($m -gt 30) { $pts -= 10; $d.Add("−10 : ville de jeu la plus proche à $(N $m) ms (> 30)") }
    }
    $loss = ($lat | Measure-Object PertePct -Maximum).Maximum
    if ($loss -gt $script:SeuilPerte) { $pts -= 25; $d.Add("−25 : perte jusqu'à $(N $loss) %") } elseif ($loss -gt 0.5) { $pts -= 10; $d.Add("−10 : perte jusqu'à $(N $loss) %") }
    $jit = ($lat | Measure-Object JitterMs -Maximum).Maximum
    if ($jit -gt 5) { $pts -= 10; $d.Add("−10 : gigue jusqu'à $(N $jit) ms (> 5)") }
    $gw = @($lat | Where-Object { $_.Nom -like 'Passerelle*' })
    if ($gw -and [double]$gw[0].MedianeMs -gt 5) { $pts -= 10; $d.Add("−10 : $(N $gw[0].MedianeMs) ms jusqu'à la box (> 5 : Wi-Fi ou réseau local à vérifier)") }
    if ($d.Count -eq 0 -or ($d.Count -eq 1 -and -not $bl)) { $d.Add('aucune pénalité') }
    [pscustomobject]@{ Score = [math]::Max(0, $pts); Detail = $d.ToArray() }
}
function Get-SecScore {
    $pts = 100; $d = New-Object Collections.Generic.List[string]
    $c = @($Aud.Constats | Where-Object { $_.Section -like 'B*' })
    $nc = @($c | Where-Object Niveau -eq 'critique').Count
    $na = @($c | Where-Object Niveau -eq 'attention').Count
    $ni = @($c | Where-Object Niveau -eq 'info').Count
    if ($nc) { $pts -= 20 * $nc; $d.Add("−$(20 * $nc) : $nc constat(s) critique(s) × 20") }
    if ($na) { $pts -= 6 * $na; $d.Add("−$(6 * $na) : $na constat(s) « attention » × 6") }
    if ($ni) { $pts -= $ni; $d.Add("−$ni : $ni constat(s) « info » × 1") }
    if ($d.Count -eq 0) { $d.Add('aucune pénalité') }
    [pscustomobject]@{ Score = [math]::Max(0, $pts); Detail = $d.ToArray() }
}
function Get-GameScore {
    $pts = 100; $d = New-Object Collections.Generic.List[string]
    if ($reg.PlanAlimentation.Guid -and $knownPlans -notcontains $reg.PlanAlimentation.Guid) { $pts -= 10; $d.Add('−10 : plan d''alimentation tiers non documenté') }
    if ($reg.ModeJeu -notmatch '^activé') { $pts -= 10; $d.Add('−10 : Mode Jeu désactivé') }
    if ($reg.GameDvr.EnregistrementArrierePlan -match '^oui') { $pts -= 5; $d.Add('−5 : enregistrement Game Bar en arrière-plan') }
    if ($reg.AccelerationSouris.Active) { $pts -= 3; $d.Add('−3 : accélération de la souris') }
    $nv = $jeu.Materiel.Nvidia
    if ($nv -and $nv.AJour -eq $false) { $pts -= 15; $d.Add('−15 : pilote NVIDIA en retard') }
    $r = $jeu.Materiel.Ram
    if ($r -and $r.FrequenceNominale -and $r.FrequenceReelle -lt $r.FrequenceNominale) { $pts -= 10; $d.Add('−10 : RAM sous sa fréquence nominale (XMP/EXPO inactif)') }
    if (Find-Constat 'kits mélangés') { $pts -= 5; $d.Add('−5 : kits de RAM mélangés (risque de stabilité)') }
    if ($d.Count -eq 0) { $d.Add('aucune pénalité') }
    $d.Add('VBS / HVCI actifs : jamais pénalisés (sécurité)')
    [pscustomobject]@{ Score = [math]::Max(0, $pts); Detail = $d.ToArray() }
}
$scNet = Get-NetScore; $scSec = Get-SecScore; $scGame = Get-GameScore
function ScoreTile {
    param([string]$Title, $Sc)
    $k = if ($Sc.Score -ge 80) { 'ok' } elseif ($Sc.Score -ge 50) { 'warn' } else { 'bad' }
    $li = ($Sc.Detail | ForEach-Object { "<li>$(Esc $_)</li>" }) -join ''
    "<div class=""tile t-$k""><div class=""tt"">$(Esc $Title)</div><div class=""sv"">$($Sc.Score)<small>/100</small></div><ul>$li</ul></div>"
}

# =====================================================================================
# CONSTRUCTION DU HTML
# =====================================================================================
$ctx = $Aud.Contexte
$hasCrit = @($Aud.Constats | Where-Object { $_.Niveau -eq 'critique' }).Count -gt 0
$auditDate = ([datetime]$Aud.Date).ToString('dd/MM/yyyy HH:mm')
$html = New-Object Text.StringBuilder
function Add { param([string]$s) [void]$html.Append($s); [void]$html.Append("`r`n") }

# ---- Baseline ------------------------------------------------------------------------
$latRows = foreach ($t in $lat) {
    $passes = (@($t.Passes) | ForEach-Object { N $_.MedianeMs }) -join ' / '
    , @("$(Esc $t.Nom)<div class=""sub"">$(Esc $t.Type)</div>", (N $t.MedianeMs), (N $t.P95Ms), (N $t.PireMs), (N $t.JitterMs '0.##'), "$(N $t.PertePct) %", (Esc $passes))
}
$dnsRows = foreach ($d in @($net.Dns | Sort-Object MedianeMs)) {
    , @((Esc $d.Nom), (Esc $d.Ip), (N $d.MedianeMs), (N $d.MedianeNomsCourantsMs), (N $d.MedianeSansCacheMs), (N $d.P95Ms), "$($d.Echecs)/$($d.Requetes)")
}
$bb = $net.Bufferbloat
$baseline = New-Object Text.StringBuilder
[void]$baseline.Append("<p class=""note"">$($Aud.Parametres.Passes) passe(s) espacée(s) de $($Aud.Parametres.IntervallePassesS) s, $($Aud.Parametres.RequetesParCible) requêtes par cible et par passe (au plus 20, une toutes les 200 ms). Valeurs en ms. « Passerelle » = ta box. Les villes sont des <b>proxys</b> (régions cloud situées dans les mêmes villes que les serveurs de jeu) : elles mesurent ta ligne jusqu'à la ville, pas le serveur de jeu lui-même.</p>")
[void]$baseline.Append((Table -Head @('Cible', 'Médiane', 'p95', 'Pire', 'Gigue', 'Perte', 'Médiane par passe') -Rows $latRows))
[void]$baseline.Append('<h3>DNS (temps de résolution)</h3>')
[void]$baseline.Append((Table -Head @('Résolveur', 'Adresse', 'Médiane', 'Noms courants', 'Sans cache', 'p95', 'Échecs') -Rows $dnsRows))
if ($bb -and $bb.Verdict) {
    $bbRows = @(
        , @('Repos', (N $bb.Repos.MedianeMs), '—', '—', '—')
        , @('Téléchargement', (N $bb.Telechargement.Latence.MedianeMs), "+$(N $bb.Telechargement.AjoutMs)", (Esc $bb.Telechargement.Note), "$(N $bb.Telechargement.DebitMbps) Mbit/s ($(N $bb.Telechargement.Mo) Mo)")
        , @('Envoi', (N $bb.Envoi.Latence.MedianeMs), "+$(N $bb.Envoi.AjoutMs)", (Esc $bb.Envoi.Note), "$(N $bb.Envoi.DebitMbps) Mbit/s ($(N $bb.Envoi.Mo) Mo)")
    )
    $from = if ($bb.ReprisDe) { " (mesure reprise de l'audit du $(Esc $bb.ReprisDe))" } else { '' }
    [void]$baseline.Append("<h3>Bufferbloat : note $(Esc $bb.Verdict)$from</h3>")
    [void]$baseline.Append((Table -Head @('Ligne', 'Ping médian vers 1.1.1.1', 'Ajout', 'Note', 'Débit moyen pendant le test (PAS un test de débit)') -Rows $bbRows))
} else {
    [void]$baseline.Append('<p class="note">Bufferbloat non mesuré : il demande un test de charge vers speed.cloudflare.com (100 à 300 Mo), lancé seulement après ton accord (Audit.ps1 -LoadTest).</p>')
}
[void]$baseline.Append("<p>MTU du chemin vers $(Esc $net.Mtu.Chemin.Cible) : <b>$(Esc $net.Mtu.Chemin.MtuChemin)</b> (interface $(Esc $net.Mtu.Interface)). Lien : $(Esc $net.Lien.Type) $(Esc $net.Lien.Vitesse)$(if ($net.Lien.DuplexIntegral) { ', duplex intégral' }). Trafic au repos (10 s) : $(N $net.TraficRepos.RxKbpsMediane) kbit/s reçus, $(N $net.TraficRepos.TxKbpsMediane) kbit/s envoyés (médianes).</p>")

# ---- Top 5 ---------------------------------------------------------------------------
$top = @($rows | Where-Object { $_.Statut -eq 'a_faire' -and -not $_.Action.nonRecommande } | Sort-Object { [int]$_.Action.priorite } | Select-Object -First 5)
$topHtml = New-Object Text.StringBuilder
[void]$topHtml.Append('<ol class="top">')
foreach ($r in $top) {
    $a = $r.Action
    $how = switch ($a.methode) { 'powercfg' { 'appliqué par Apply.ps1 (option 3), sans admin' } 'admin' { 'commande admin AFFICHÉE (option 4), à lancer toi-même' } 'pare-feu' { 'règle par règle, après ton accord (option 4)' } default { 'fiche manuelle' } }
    $cmd = if ($a.commande) { "<code>$(Esc $a.commande)</code>" } else { '' }
    [void]$topHtml.Append("<li><div class=""th""><b>$(Esc $a.titre)</b> $(RiskBadge $a.risque) $(Badge $a.classement 'mut')</div><div>$(Esc $r.Etat)</div><div class=""sub"">$(Esc $a.quoi)</div><div class=""sub"">→ $(Esc $how). $(SrcLink $a)</div>$cmd</li>")
}
[void]$topHtml.Append('</ol>')
if (-not $top) { [void]$topHtml.Clear(); [void]$topHtml.Append('<p>Rien à corriger d''après cet audit.</p>') }

# ---- Tableau complet -----------------------------------------------------------------
$stLabel = @{ a_faire = @('à faire', 'warn'); conforme = @('conforme', 'ok'); optionnel = @('optionnel', 'mut'); non_recommande = @('non recommandé', 'mut'); inconnu = @('non mesuré', 'mut') }
$fullRows = foreach ($r in ($rows | Where-Object { -not $_.Action.nonRecommande } | Sort-Object @{ e = { @('a_faire', 'optionnel', 'inconnu', 'non_recommande', 'conforme').IndexOf($_.Statut) } }, @{ e = { [int]$_.Action.priorite } })) {
    $a = $r.Action; $l = $stLabel[$r.Statut]
    $meth = switch ($a.methode) { 'powercfg' { 'auto (sans admin)' } 'admin' { 'admin (affiché)' } 'pare-feu' { 'admin, règle par règle' } 'manuel' { 'manuel' } default { '—' } }
    $prof = if (@($a.profils).Count) { (@($a.profils) -join ', ') } else { 'opt-in' }
    , @("<b>$(Esc $a.id)</b> $(Esc $a.titre)", (Esc $r.Etat), (Badge $l[0] $l[1]), (Esc $a.classement), (RiskBadge $a.risque), (Esc $meth), (Esc $prof), (SrcLink $a))
}

# ---- Sécurité ------------------------------------------------------------------------
$secHtml = New-Object Text.StringBuilder
$def = $sys.Defender
$chk = @(
    @('Pare-feu (3 profils)', ((@($sec.PareFeu.Profils | ForEach-Object { "$($_.Profil) : $($_.Actif), entrant $($_.EntrantParDefaut)" })) -join ' ; '), (@($sec.PareFeu.Profils | Where-Object { $_.Actif -notmatch 'True|activ' }).Count -eq 0)),
    @('Defender temps réel', "$(if ($def.TempsReel) { 'actif' } else { 'INACTIF' }), signatures de $($def.AgeSignaturesJours) jour(s)", [bool]$def.TempsReel),
    @('Protection contre les falsifications', $(if ($def.ProtectionFalsification) { 'activée' } else { 'désactivée' }), [bool]$def.ProtectionFalsification),
    @('Secure Boot', $sys.SecureBoot, ($sys.SecureBoot -match '^activ')),
    @('TPM', $sys.Tpm, ($sys.Tpm -match '2\.0')),
    @('BitLocker C:', $sys.BitLockerC.Etat, ($sys.BitLockerC.Etat -notmatch 'désactiv')),
    @('VBS / HVCI', "$($jeu.Vbs.Etat) ; $($jeu.Vbs.ServicesEnCours)", ($jeu.Vbs.Etat -match 'en cours')),
    @('Liste de blocage des pilotes vulnérables', $jeu.Vbs.ListeBlocagePilotes, ($jeu.Vbs.ListeBlocagePilotes -match '^active')),
    @('SMBv1', $(if ($sys.Smb.Smb1Serveur -or $sys.Smb.Smb1ClientInstalle) { 'actif' } else { 'désactivé' }), -not ($sys.Smb.Smb1Serveur -or $sys.Smb.Smb1ClientInstalle)),
    @('Bureau à distance (RDP)', $(if ($sys.Rdp.Active) { "activé, NLA : $($sys.Rdp.Nla)" } else { 'désactivé' }), -not $sys.Rdp.Active),
    @('WinRM', "$($sys.WinRM.Etat) ($($sys.WinRM.Demarrage))", ($sys.WinRM.Etat -ne 'Running')),
    @('Registre à distance', $sys.RegistreDistant, ($sys.RegistreDistant -ne 'Running')),
    @('UAC', $(if ($sys.Uac.Active) { 'actif' } else { 'DÉSACTIVÉ' }), [bool]$sys.Uac.Active),
    @('LLMNR / NetBIOS / mDNS', "$($sys.Llmnr) / $((@($sys.NetBios | ForEach-Object { $_.NetBios })) -join ', ') / $($sys.Mdns)", $null),
    @('Proxy', $(if ($sec.Reseau.Proxy.Utilisateur -or $sec.Reseau.Proxy.WinHttp) { 'configuré' } else { 'aucun' }), -not ($sec.Reseau.Proxy.Utilisateur -or $sec.Reseau.Proxy.WinHttp)),
    @('Table ARP', "$($sec.Reseau.Arp.Entrees) entrées, $(@($sec.Reseau.Arp.MacEnDouble).Count) MAC en double", (@($sec.Reseau.Arp.MacEnDouble).Count -eq 0))
)
$chkRows = foreach ($c in $chk) {
    $b = if ($null -eq $c[2]) { Badge 'à choisir' 'mut' } elseif ($c[2]) { Badge 'ok' 'ok' } else { Badge 'à revoir' 'warn' }
    , @((Esc $c[0]), (Esc $c[1]), $b)
}
[void]$secHtml.Append((Table -Head @('Point', 'État', '') -Rows $chkRows))

$larges = @($sec.PareFeu.ReglesLarges | Where-Object { -not $_.Systeme } | Sort-Object @{ e = { -[int]$_.Public } }, Nom)
if ($larges) {
    $lr = foreach ($r in $larges) { , @((Esc $r.Nom), (Esc $r.Profils), (Esc $r.Protocole), $(if ($r.Public) { Badge 'oui' 'warn' } else { 'non' }), "<span class=""sub"">$(Esc $r.Programme)</span>") }
    [void]$secHtml.Append("<h3>Règles entrantes larges hors Windows ($($larges.Count))</h3><p class=""note"">Tous ports, toute adresse distante. Aucune n'est modifiée par l'audit. Désactivation possible règle par règle après ton accord (NG-008), jamais de suppression, jamais une règle Windows.</p>")
    [void]$secHtml.Append((Table -Head @('Règle', 'Profils', 'Proto', 'Public', 'Programme') -Rows $lr))
}
$abs = @($sec.PareFeu.ReglesProgrammeAbsent | Where-Object { -not $_.Systeme })
if ($abs) {
    $ar = foreach ($r in $abs) { , @((Esc $r.Nom), (Esc $r.Profils), "<span class=""sub"">$(Esc $r.Programme)</span>") }
    [void]$secHtml.Append("<details><summary>Règles vers un programme absent ($($abs.Count))</summary>$(Table -Head @('Règle', 'Profils', 'Programme') -Rows $ar)</details>")
}
$ports = @($sec.PortsEcoute | Where-Object { $_.ToutesInterfaces } | Sort-Object Proto, Port)
$pr = foreach ($p in $ports) {
    , @("$(Esc $p.Proto) $($p.Port)", (Esc $p.Processus), (Esc $p.Services), $(if ($p.Windows) { 'Windows' } else { Badge 'tiers' 'warn' }), (Esc $p.Signature), $(if ($p.PareFeuAutorise) { Esc "autorisé ($($p.ProfilsAutorises))" } else { 'non autorisé' }))
}
[void]$secHtml.Append("<details><summary>Ports en écoute sur toutes les interfaces ($($ports.Count))</summary>$(Table -Head @('Port', 'Processus', 'Services', 'Origine', 'Signature', 'Pare-feu entrant') -Rows $pr)</details>")
$out = @($sec.Sortantes)
$or = foreach ($o in $out) { , @((Esc $o.Processus), $o.Connexions, (Esc $o.Signature), (Esc $o.CheminInhabituel)) }
[void]$secHtml.Append("<details><summary>Connexions sortantes par programme ($($out.Count))</summary>$(Table -Head @('Processus', 'Connexions', 'Signature', 'Emplacement inhabituel') -Rows $or)</details>")
$usr = @($sec.Comptes.Utilisateurs | Where-Object Active)
$ur = foreach ($u in $usr) { , @((Esc $u.Nom), $(if ($u.Admin) { 'administrateur' } else { 'standard' }), $(if ($u.MotDePasseRequis) { 'requis' } else { Badge 'non requis (indicateur)' 'warn' })) }
[void]$secHtml.Append("<h3>Comptes locaux actifs</h3>$(Table -Head @('Compte', 'Type', 'Mot de passe') -Rows $ur)")
$hr = $sec.Reseau.HostsRedirections
if ($hr -and $hr.Lignes) {
    $hl = (@($sec.Reseau.Hosts) | ForEach-Object { Esc $_ }) -join "`n"
    [void]$secHtml.Append("<h3>Fichier hosts</h3><p>$($hr.Lignes) ligne(s) redirigent vers une IP externe ($(Esc (@($hr.IpCibles) -join ', '))) ; $($hr.LignesAvecJoker) ligne(s) avec joker, ignorées par Windows. Modifié le $(([datetime]$hr.ModifieLe).ToString('dd/MM/yyyy HH:mm')).</p><details><summary>Lignes actives</summary><pre>$hl</pre></details>")
}
if ($sec.Winget -and @($sec.Winget.Lignes).Count) {
    $wl = ((@($sec.Winget.Entete) + @($sec.Winget.Lignes)) | ForEach-Object { Esc $_ }) -join "`n"
    [void]$secHtml.Append("<details><summary>Mises à jour d'applications en attente ($(@($sec.Winget.Lignes).Count), liste winget, rien n'est installé)</summary><pre>$wl</pre></details>")
}
if ($ctx.Gere -and @($ctx.Gere.Mdm).Count) {
    $mr = foreach ($m in @($ctx.Gere.Mdm)) { , @((Esc $m.Fournisseur), (Esc $m.Compte), $m.Type, $m.Etat) }
    [void]$secHtml.Append("<h3>Inscriptions à une organisation</h3><p class=""note"">Une organisation (entreprise, école) peut imposer des stratégies qui priment sur les réglages locaux. Paramètres &gt; Comptes &gt; Accès professionnel ou scolaire.</p>$(Table -Head @('Fournisseur', 'Compte', 'Type', 'État') -Rows $mr)")
}

# ---- Réseau détaillé -----------------------------------------------------------------
$netHtml = New-Object Text.StringBuilder
$npr = foreach ($p in @($net.ProprietesCarte | Where-Object { $_.Categorie -ne 'autre' } | Sort-Object Categorie, Nom)) { , @((Esc $p.Categorie), (Esc $p.Nom), (Esc $p.Valeur), "<code>$(Esc $p.Cle)</code>") }
[void]$netHtml.Append("<p>Carte : $(Esc $ctx.Carte.Modele), pilote $(Esc $ctx.Carte.Pilote) du $(Esc $ctx.Carte.DatePilote).</p><details><summary>Propriétés avancées de la carte ($(@($npr).Count))</summary>$(Table -Head @('Catégorie', 'Propriété', 'Valeur', 'Mot-clé') -Rows $npr)</details>")
$do = $net.DeliveryOptimization
[void]$netHtml.Append("<p>Optimisation de la distribution : $(Esc $do.ModeEffectif) ; ce mois-ci $(N $do.MoisTelechargeMo) Mo reçus, $(N ($do.MoisEnvoyeInternetMo + $do.MoisEnvoyeLanMo)) Mo envoyés à d'autres PC.</p>")
$cons = foreach ($c in @($net.Consommateurs)) { , @((Esc $c.Processus), (Esc $c.Services), $c.Connexions, (N $c.IoKoParSec)) }
[void]$netHtml.Append("<details><summary>Programmes avec des connexions pendant la mesure ($(@($cons).Count))</summary>$(Table -Head @('Processus', 'Services', 'Connexions', 'E/S Ko/s') -Rows $cons)</details>")

# ---- Jeu -----------------------------------------------------------------------------
$nv = $jeu.Materiel.Nvidia; $ram = $jeu.Materiel.Ram; $th = $jeu.Thermique
$gameRows = @(
    , @('Carte graphique', (Esc "$($nv.Carte), pilote $($nv.Version)$(if ($nv.AJour) { ' (dernier publié)' } elseif ($nv.AJour -eq $false) { " (dernier : $($nv.DerniereOfficielle))" })"))
    , @('Mémoire', (Esc "$($ram.TotalGo) Go $($ram.Type), $($ram.Barrettes) barrettes à $($ram.FrequenceReelle) MT/s (nominal $($ram.FrequenceNominale)), XMP/EXPO $($ram.ProfilXmpExpo) ; $(@($ram.References) -join ' / ')"))
    , @('Mode Jeu', (Esc $reg.ModeJeu))
    , @('Plan d''alimentation', (Esc $reg.PlanAlimentation.Nom))
    , @('HAGS', (Esc $reg.Hags))
    , @('Game Bar', (Esc "capture $($reg.GameDvr.CaptureAutorisee), arrière-plan $($reg.GameDvr.EnregistrementArrierePlan)"))
    , @('Optimisations plein écran / fenêtré', (Esc "$($reg.OptimisationsPleinEcran.Note) / $($reg.OptimisationsFenetre)"))
    , @('Accélération souris', $(if ($reg.AccelerationSouris.Active) { 'activée' } else { 'désactivée' }))
    , @('Résolution du minuteur', (Esc "$(N $reg.Timer.ActuelleMs '0.###') ms (de $(N $reg.Timer.PlusFineMs '0.###') à $(N $reg.Timer.PlusGrossiereMs '0.###'))"))
    , @('GPU au moment de l''audit', (Esc "$($th.Gpu.TempC) °C, $($th.Gpu.PuissanceW) W, état $($th.Gpu.Pstate), $($th.Gpu.UtilisationPct) %"))
    , @('Processeur', (Esc "performance $($th.CpuPerfPct) % de la fréquence de base"))
)
$gameHtml = Table -Head @('Point', 'État') -Rows $gameRows

# ---- Constats ------------------------------------------------------------------------
$ord = @{ critique = 0; attention = 1; info = 2 }
$constRows = foreach ($c in @($Aud.Constats | Sort-Object @{ e = { $ord[$_.Niveau] } }, Section)) { , @((LevelBadge $c.Niveau), (Esc $c.Section), (Esc $c.Texte)) }

# ---- Ce que je ne te recommande PAS --------------------------------------------------
$notRows = foreach ($r in @($rows | Where-Object { $_.Statut -eq 'non_recommande' } | Sort-Object { [int]$_.Action.priorite })) {
    $a = $r.Action
    $tag = if ($a.interdit) { Badge 'interdit par le projet' 'bad' } else { Badge $a.classement 'mut' }
    , @("<b>$(Esc $a.titre)</b>", $tag, "$(Esc $a.quoi)<div class=""sub"">Sur ta machine : $(Esc $r.Etat)</div>", (SrcLink $a))
}

# ---- Commandes admin (affichées) -----------------------------------------------------
$adm = New-Object Text.StringBuilder
foreach ($c in @($Aud.CommandesAdmin)) { [void]$adm.Append("<li>$(Esc $c.Pourquoi)<code>$(Esc $c.Commande)</code></li>") }
foreach ($r in @($rows | Where-Object { $_.Statut -eq 'a_faire' -and $_.Action.admin -and $_.Action.commande })) {
    [void]$adm.Append("<li>$(Esc $r.Action.id) : $(Esc $r.Action.titre)<code>$(Esc $r.Action.commande)</code><span class=""sub"">Annulation : $(Esc $r.Action.annulation)</span></li>")
}

# ---- Assemblage ----------------------------------------------------------------------
$css = @'
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2430;--mut:#5d6878;--line:#dde2ea;--ok:#1f7a4a;--okb:#e3f4ea;--warn:#8a5a00;--warnb:#fdf1d8;--bad:#a32020;--badb:#fbe3e3;--acc:#2f5fb3;--code:#eef1f6}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--card:#1b2029;--fg:#e4e8ef;--mut:#9aa5b5;--line:#2c3340;--ok:#6fd39c;--okb:#173326;--warn:#f0c46a;--warnb:#3a2e14;--bad:#ff8f8f;--badb:#3d1c1c;--acc:#8cb4ff;--code:#232a35}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 "Segoe UI",system-ui,sans-serif}
main{max-width:1100px;margin:0 auto;padding:20px 16px 60px}h1{font-size:1.6rem;margin:.2em 0}h2{font-size:1.25rem;margin:1.8em 0 .6em;padding-bottom:.3em;border-bottom:1px solid var(--line)}h3{font-size:1.05rem;margin:1.4em 0 .5em}
.meta,.note,.sub{color:var(--mut)}.sub{font-size:.88em}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:12px 0}
.alert{background:var(--badb);border:1px solid var(--bad);border-radius:10px;padding:12px 16px;margin:14px 0}.alert b{color:var(--bad)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}.tile{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--mut);border-radius:10px;padding:12px 14px}
.t-ok{border-left-color:var(--ok)}.t-warn{border-left-color:var(--warn)}.t-bad{border-left-color:var(--bad)}.tt{font-weight:600}.sv{font-size:2rem;font-weight:700}.sv small{font-size:.9rem;color:var(--mut)}.tile ul{margin:.3em 0 0;padding-left:1.1em;font-size:.88em;color:var(--mut)}
.tw{overflow-x:auto;margin:8px 0}table{border-collapse:collapse;width:100%;background:var(--card);font-size:.92em}th,td{text-align:left;vertical-align:top;padding:6px 8px;border-bottom:1px solid var(--line)}th{background:var(--code);font-weight:600}
.b{display:inline-block;padding:1px 7px;border-radius:9px;font-size:.8em;font-weight:600;white-space:nowrap}.b-ok{background:var(--okb);color:var(--ok)}.b-warn{background:var(--warnb);color:var(--warn)}.b-bad{background:var(--badb);color:var(--bad)}.b-mut{background:var(--code);color:var(--mut)}
code{display:block;background:var(--code);padding:6px 8px;border-radius:6px;margin:6px 0;font:13px/1.4 Consolas,monospace;white-space:pre-wrap;word-break:break-all}pre{background:var(--code);padding:8px;border-radius:6px;overflow-x:auto;font-size:12px}
ol.top{padding-left:1.3em}ol.top li{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 12px;margin:8px 0}.th{margin-bottom:2px}
details{margin:8px 0}summary{cursor:pointer;color:var(--acc)}a{color:var(--acc)}ul.adm li{margin:8px 0}
'@

Add '<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
Add "<title>Rapport netguard</title><style>$css</style></head><body><main>"
Add "<h1>netguard-gaming : rapport d'audit</h1>"
Add "<div class=""meta"">Audit du $auditDate · $(Esc $ctx.Edition) $(Esc $ctx.Version) (build $(Esc $ctx.Build)) · PC $(Esc $ctx.Type) $(Esc $ctx.NomPc) · $(Esc $ctx.Processeur) · $(Esc $ctx.RamGo) Go · $(Esc (@($ctx.Gpu) -join ', ')) · $(Esc $ctx.Connexion) · IPv4 $(Esc $ctx.IPv4) · MAC $(Esc $ctx.Carte.Mac)</div>"
Add '<p class="note">L''audit est en lecture seule : rien n''a été modifié sur la machine. Chaque réglage proposé cite sa source ; « non vérifié » = source officielle introuvable, désactivé par défaut.</p>'
if ($hasCrit) {
    $cl = (@($Aud.Constats | Where-Object Niveau -eq 'critique') | ForEach-Object { "<li>$(Esc $_.Texte)</li>" }) -join ''
    Add "<div class=""alert""><b>Problème de sécurité critique : à traiter avant tout réglage de jeu.</b><ul>$cl</ul></div>"
}
Add '<h2>Scores</h2><div class="tiles">'
Add (ScoreTile 'Réseau' $scNet); Add (ScoreTile 'Sécurité' $scSec); Add (ScoreTile 'Jeu' $scGame)
Add '</div><p class="note">Le score part de 100 et retire des points pour chaque problème mesuré (détail sous chaque score). Ce n''est pas une note de vitesse : une bonne ligne avec un bufferbloat C perd 25 points.</p>'
Add "<h2>Baseline (mesures avant toute modification)</h2>$($baseline.ToString())"
Add "<h2>Top 5 des gains</h2><p class=""note"">Classés par priorité : sécurité d'abord, puis stabilité, puis gains marginaux. Aucun gain en millisecondes n'est promis : il sera mesuré par Verify.ps1 (option 7).</p>$($topHtml.ToString())"
$secBlock = "<h2>Sécurité</h2>$($secHtml.ToString())"
$netBlock = "<h2>Réseau (détails)</h2>$($netHtml.ToString())"
if ($hasCrit) { Add $secBlock; Add $netBlock } else { Add $netBlock; Add $secBlock }
Add "<h2>Jeu</h2>$gameHtml"
Add "<h2>Tous les réglages du catalogue</h2>$(Table -Head @('Réglage', 'État actuel', 'Statut', 'Gain', 'Risque', 'Méthode', 'Profils', 'Source') -Rows $fullRows)"
Add "<h2>Ce que je ne te recommande PAS, et pourquoi</h2>$(Table -Head @('Réglage', 'Classement', 'Pourquoi', 'Source') -Rows $notRows)"
Add "<h2>Tous les constats ($(@($Aud.Constats).Count))</h2>$(Table -Head @('Niveau', 'Section', 'Constat') -Rows $constRows)"
Add "<h2>Commandes administrateur (affichées, jamais lancées)</h2><p class=""note"">À copier dans un PowerShell ouvert en administrateur, après lecture. L'annulation est indiquée sous chaque commande.</p><ul class=""adm"">$($adm.ToString())</ul>"
Add "<h2>Méthode et limites</h2><div class=""card""><ul><li>Latence : ping ICMP (.NET), au plus 20 requêtes par cible et par passe, aucune autre machine du réseau local n'est sondée (seule la box, ta passerelle).</li><li>Les serveurs de Riot, Valve et Epic filtrent le ping : les villes sont mesurées via des points d'entrée cloud. La référence reste le ping affiché en jeu.</li><li>Seuils de conclusion (Verify.ps1) : $script:SeuilLatMs ms de latence médiane, $script:SeuilPerte points de perte ; DNS : $script:SeuilDnsMs ms. En dessous : « aucun gain mesurable ».</li><li>Bufferbloat : ping vers 1.1.1.1 pendant un téléchargement puis un envoi vers speed.cloudflare.com (seule requête externe de charge, après accord). Notes : A+ &lt; 5 ms ajoutées, A &lt; 30, B &lt; 60, C &lt; 200, D &lt; 400, F au-delà.</li><li>Fichier source : $(Esc (Split-Path $AuditPath -Leaf)) du dossier $(Esc (Split-Path (Split-Path $AuditPath -Parent) -Leaf)).</li></ul></div>"
Add '</main></body></html>'
$full = $html.ToString()

# =====================================================================================
# VERSION PARTAGEABLE + CONTRÔLE DES FUITES
# =====================================================================================
$secrets = @($ctx.NomPc, $ctx.Utilisateur, $env:COMPUTERNAME, $env:USERNAME) + @($ctx.Gere.Mdm | ForEach-Object { $_.Compte })
$shareable = ConvertTo-NgShareable -Text $full -Secrets $secrets
$shareable = $shareable.Replace('<h1>netguard-gaming : rapport d''audit</h1>', '<h1>netguard-gaming : rapport d''audit (version partageable)</h1><p class="note">IP, MAC, SSID, e-mails, identifiants de machine, nom du PC et nom d''utilisateur masqués.</p>')
$leaks = Find-NgShareableLeak -Text $shareable -Secrets $secrets

$outFull = Join-Path $ReportsDir 'rapport_audit.html'
$outShare = Join-Path $ReportsDir 'rapport_audit_partageable.html'
$enc = New-Object Text.UTF8Encoding($true)
if ($PSCmdlet.ShouldProcess($outFull, 'Écrire le rapport complet')) {
    [IO.File]::WriteAllText($outFull, $full, $enc)
    Write-Host "Rapport complet      : $outFull"
}
if (@($leaks).Count) {
    Write-Warning ("Version partageable NON écrite : $(@($leaks).Count) fuite(s) détectée(s) -> " + ((@($leaks) | Select-Object -First 5) -join ' ; '))
} elseif ($PSCmdlet.ShouldProcess($outShare, 'Écrire le rapport partageable')) {
    [IO.File]::WriteAllText($outShare, $shareable, $enc)
    Write-Host "Rapport partageable  : $outShare (contrôle : aucune IP, MAC, e-mail, SID ni nom trouvé)"
}
Write-Host ("Scores : réseau {0}/100, sécurité {1}/100, jeu {2}/100 ; {3} action(s) à faire, Top 5 : {4}" -f $scNet.Score, $scSec.Score, $scGame.Score, @($rows | Where-Object Statut -eq 'a_faire').Count, ((@($top) | ForEach-Object { $_.Action.id }) -join ', '))
if ($Open -and -not $WhatIfPreference -and (Test-Path -LiteralPath $outFull)) { Start-Process $outFull }
