<#
.SYNOPSIS
    Mesure APRÈS et compare à la baseline (avant) : conclut « gain mesuré » ou « aucun gain mesurable ».
.DESCRIPTION
    Lecture seule. N'écrit que dans reports\verify_<date>\ (verify.json + verify.log).
    1. Latence : mêmes cibles que la baseline, plusieurs passes espacées, au plus 20 requêtes
       par cible et par passe. Agrégat = médiane de toutes les mesures, comme l'audit.
    2. DNS : le résolveur ACTUEL (18 requêtes, cache évité) comparé au résolveur de la baseline.
    3. Sécurité : relecture des points clés ; toute régression est signalée en premier.
    Seuils (Common.ps1, règle 8) : 5 ms de latence médiane, 2 points de perte, 5 ms de DNS.
    En dessous : « aucun gain mesurable sur cette machine ».
    A/B honnête : une seule comparaison avant/après reste sensible à l'heure (charge du réseau
    du soir, etc.). Pour conclure, refaire Verify à un autre moment de la journée.
.EXAMPLE
    .\Verify.ps1                                 # dernière baseline, 3 passes espacées de 60 s
    .\Verify.ps1 -Passes 5 -Label 'après NG-006'
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$Baseline,
    [ValidateRange(1, 5)][int]$Passes = 3,
    [int]$PassIntervalSec = 60,
    [ValidateRange(5, 20)][int]$PingCount = 20,
    [switch]$SkipDns,
    [string]$Label = '',
    [string]$ReportsDir,
    [string]$BaselineDir
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
if (-not $ReportsDir) { $ReportsDir = Get-NgPath 'reports' }
if (-not $BaselineDir) { $BaselineDir = Get-NgPath 'baseline' }
$log = New-Object Collections.Generic.List[string]
function Say { param([string]$t, [string]$c = 'Gray') Write-Host $t -ForegroundColor $c; $log.Add(('{0:HH:mm:ss} {1}' -f (Get-Date), $t)) }

if (-not $Baseline) {
    $bf = Get-ChildItem -LiteralPath $BaselineDir -Filter 'baseline_*.json' -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
    if (-not $bf) { throw "Aucune baseline dans $BaselineDir : lance d'abord l'audit (option 1)." }
    $Baseline = $bf.FullName
}
$B = Get-Content -LiteralPath $Baseline -Raw -Encoding UTF8 | ConvertFrom-Json
$stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
Say "netguard-gaming : vérification $stamp$(if ($Label) { " ($Label)" }) contre la baseline du $($B.Date)" 'Green'

# =====================================================================================
# 1. LATENCE
# =====================================================================================
$gt = Get-NgConfig 'game_targets'
$targets = foreach ($p in $B.Latence.PSObject.Properties) {
    $port = 443
    $cfgT = @($gt.targets | Where-Object { $_.name -eq $p.Name })[0]
    if ($cfgT -and $cfgT.port) { $port = [int]$cfgT.port }
    [pscustomobject]@{ Nom = $p.Name; Hote = $p.Value.Hote; Methode = $p.Value.Methode; Port = $port; Avant = $p.Value }
}
Say "1. Latence : $Passes passe(s) x $PingCount requêtes par cible ($(@($targets).Count) cibles, mêmes hôtes que la baseline)" 'Cyan'
$passRes = @{}; foreach ($t in $targets) { $passRes[$t.Nom] = New-Object Collections.Generic.List[object] }
for ($p = 1; $p -le $Passes; $p++) {
    Say ("   Passe {0}/{1} à {2:HH:mm:ss}" -f $p, $Passes, (Get-Date))
    foreach ($t in $targets) {
        $s = if ($t.Methode -eq 'tcp') { Measure-NgTcpConnect -Target $t.Hote -Port $t.Port -Count $PingCount } else { Measure-NgPing -Target $t.Hote -Count $PingCount }
        $passRes[$t.Nom].Add($s)
    }
    if ($p -lt $Passes) { Start-Sleep -Seconds $PassIntervalSec }
}
# NB : pas de $S / $L ici : $s et $l (boucles) seraient la MÊME variable en PowerShell.
$SeuilLat = $script:NgSeuilLatenceMs; $SeuilPerte = $script:NgSeuilPertePts
$latRows = foreach ($t in $targets) {
    $all = [double[]]@($passRes[$t.Nom] | ForEach-Object { $_.Mesures } | ForEach-Object { $_ })
    $sent = ($passRes[$t.Nom] | Measure-Object -Property Envoyes -Sum).Sum
    $ap = Get-NgSeriesStats -Rtts $all -Sent $sent
    $dMed = if ($null -ne $ap.MedianeMs -and $null -ne $t.Avant.MedianeMs) { [math]::Round($ap.MedianeMs - [double]$t.Avant.MedianeMs, 1) } else { $null }
    $dLoss = [math]::Round([double]$ap.PertePct - [double]$t.Avant.PertePct, 1)
    $v = if ($null -eq $dMed) { 'non comparable' }
         elseif ($dMed -le (-$SeuilLat) -or $dLoss -le (-$SeuilPerte)) { 'gain mesuré' }
         elseif ($dMed -ge $SeuilLat -or $dLoss -ge $SeuilPerte) { 'dégradation mesurée' }
         else { 'aucun gain mesurable' }
    # Bruit : écart entre passes de la mesure « avant ». S'il dépasse le seuil, une différence de cette taille ne prouve rien.
    $pm = @($t.Avant.Passes | Where-Object { $null -ne $_.MedianeMs } | ForEach-Object { [double]$_.MedianeMs })
    $noise = if ($pm.Count -ge 2) { ($pm | Measure-Object -Maximum).Maximum - ($pm | Measure-Object -Minimum).Minimum } else { $null }
    [pscustomobject]@{
        Cible = $t.Nom; AvantMs = $t.Avant.MedianeMs; ApresMs = $ap.MedianeMs; EcartMs = $dMed
        AvantPerte = $t.Avant.PertePct; ApresPerte = $ap.PertePct; EcartPerte = $dLoss
        AvantGigue = $t.Avant.JitterMs; ApresGigue = (Get-NgMedian ([double[]]@($passRes[$t.Nom] | Where-Object { $null -ne $_.JitterMs } | ForEach-Object { $_.JitterMs })))
        BruitAvantMs = $noise; Verdict = $v; Passes = @($passRes[$t.Nom] | Select-Object Envoyes, Recus, PertePct, MedianeMs, JitterMs, MaxMs)
    }
}
foreach ($r in $latRows) {
    $c = switch ($r.Verdict) { 'gain mesuré' { 'Green' } 'dégradation mesurée' { 'Red' } default { 'Gray' } }
    Say ("   {0,-38} avant {1,5} ms  après {2,5} ms  écart {3,6} ms  perte {4} -> {5} %  : {6}" -f $r.Cible, $r.AvantMs, $r.ApresMs, $r.EcartMs, $r.AvantPerte, $r.ApresPerte, $r.Verdict) $c
}

# =====================================================================================
# 2. DNS (résolveur actuel)
# =====================================================================================
$dnsRes = $null
if (-not $SkipDns) {
    $ad = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | Sort-Object ifIndex | Select-Object -First 1
    $cur = if ($ad) { @((Get-DnsClientServerAddress -InterfaceIndex $ad.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses)[0] } else { $null }
    if ($cur) {
        $cfg = Get-NgConfig 'dns_providers'
        $doms = @($cfg.domains)
        $names = @($doms) + @($doms | Select-Object -First ([int]$cfg.randomSubdomainsPerServer) | ForEach-Object { "$(New-NgRandomLabel).$_" })
        $names = @($names | Select-Object -First $script:NgMaxProbesPerTarget)
        Say "2. DNS : $($names.Count) requêtes vers le résolveur actuel" 'Cyan'
        $ms = foreach ($n in $names) { $q = Measure-NgDnsQuery -Server $cur -Name $n; if ($q.Ok) { $q.Ms } }
        $after = Get-NgMedian ([double[]]@($ms))
        $before = @($B.Dns | Where-Object { $_.Nom -like 'Actuel*' })[0]
        $sameNow = @($B.Dns | Where-Object { $_.Ip -eq $cur })[0]
        $changed = $before -and $before.Ip -ne $cur
        $d = if ($before -and $null -ne $after) { [math]::Round($after - [double]$before.MedianeMs, 1) } else { $null }
        $v = if ($null -eq $d) { 'non comparable' } elseif ($d -le (-$script:NgSeuilDnsMs)) { 'gain mesuré' } elseif ($d -ge $script:NgSeuilDnsMs) { 'dégradation mesurée' } else { 'aucun gain mesurable' }
        $dnsRes = [pscustomobject]@{ ResolveurAvant = $before.Ip; ResolveurApres = $cur; Change = [bool]$changed; AvantMs = $before.MedianeMs; ApresMs = [math]::Round($after, 1); EcartMs = $d; Verdict = $v; Requetes = $names.Count; Echecs = $names.Count - @($ms).Count }
        Say ("   résolveur {0}{1} : avant {2} ms, après {3} ms, écart {4} ms : {5}" -f $(if ($changed) { 'CHANGÉ ' } else { '' }), $(if ($changed) { "$($before.Ip) -> $cur" } else { 'inchangé' }), $before.MedianeMs, $dnsRes.ApresMs, $d, $v) $(if ($v -eq 'dégradation mesurée') { 'Red' } elseif ($v -eq 'gain mesuré') { 'Green' } else { 'Gray' })
    }
}

# =====================================================================================
# 3. SÉCURITÉ : relecture des points clés (lecture seule)
# =====================================================================================
Say '3. Sécurité : relecture des points clés' 'Cyan'
$sec = New-Object Collections.Generic.List[object]
function Add-Sec { param([string]$Point, [string]$Etat, [bool]$Ok, [bool]$Regression = $false) $sec.Add([pscustomobject]@{ Point = $Point; Etat = $Etat; Ok = $Ok; Regression = $Regression }) }
$fwp = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction SilentlyContinue)
$fwOff = @($fwp | Where-Object { -not $_.Enabled })
Add-Sec 'Pare-feu (3 profils)' $(if ($fwOff) { "DÉSACTIVÉ : $(($fwOff | ForEach-Object Name) -join ', ')" } else { 'actif' }) (-not $fwOff) ([bool]$fwOff)
$mp = $null; try { $mp = Get-MpComputerStatus -ErrorAction Stop } catch { }
if ($mp) {
    Add-Sec 'Defender temps réel' $(if ($mp.RealTimeProtectionEnabled) { 'actif' } else { 'INACTIF' }) $mp.RealTimeProtectionEnabled (-not $mp.RealTimeProtectionEnabled)
    Add-Sec 'Protection contre les falsifications' $(if ($mp.IsTamperProtected) { 'activée' } else { 'désactivée' }) $mp.IsTamperProtected $false
}
$smb1 = $null; try { $smb1 = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { }
if ($null -ne $smb1) { Add-Sec 'SMBv1 (serveur)' $(if ($smb1) { 'ACTIF' } else { 'désactivé' }) (-not $smb1) ([bool]$smb1 -and -not $B.Etats.Smb1.Smb1Serveur) }
$dg = $null; try { $dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop } catch { }
if ($dg) { $hv = @($dg.SecurityServicesRunning) -contains 2; Add-Sec 'Intégrité de la mémoire (HVCI)' $(if ($hv) { 'en cours' } else { 'ARRÊTÉE' }) $hv (-not $hv) }
$bl = Get-NgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable'
Add-Sec 'Liste de blocage des pilotes' $(if ($bl -eq 0) { 'DÉSACTIVÉE' } else { 'active' }) ($bl -ne 0) ($bl -eq 0)
$hostsExt = 0
try {
    foreach ($l in (Get-Content -LiteralPath "$env:windir\System32\drivers\etc\hosts" -ErrorAction Stop)) {
        $x = ($l -replace '#.*$', '').Trim(); if (-not $x) { continue }
        $ip = ($x -split '\s+')[0]
        if ($ip -match '^\d{1,3}(\.\d{1,3}){3}$' -and $ip -notmatch '^(0\.0\.0\.0|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)') { $hostsExt++ }
    }
} catch { }
Add-Sec 'hosts : redirections vers une IP externe' "$hostsExt ligne(s)" ($hostsExt -eq 0) $false
$ssh = @(Get-NetTCPConnection -State Listen -LocalPort 22 -ErrorAction SilentlyContinue)
Add-Sec 'Serveur SSH en écoute (port 22)' $(if ($ssh) { 'oui' } else { 'non' }) (-not $ssh) $false
$rl = $null; try { $rl = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction Stop).Count } catch { }
if ($null -ne $rl) { Add-Sec 'Règles entrantes autorisées actives' "$rl" $true $false }
Add-Sec 'Plan d''alimentation' (Get-NgPowerSchemeName (Get-NgActivePowerScheme)) $true $false
foreach ($s in $sec) {
    $c = if ($s.Regression) { 'Red' } elseif ($s.Ok) { 'Gray' } else { 'Yellow' }
    Say ("   {0,-42} {1}{2}" -f $s.Point, $s.Etat, $(if ($s.Regression) { '   <- RÉGRESSION' })) $c
}

# =====================================================================================
# CONCLUSION
# =====================================================================================
$gains = @($latRows | Where-Object Verdict -eq 'gain mesuré')
$worse = @($latRows | Where-Object Verdict -eq 'dégradation mesurée')
$regs = @($sec | Where-Object Regression)
$concl = if ($regs) { "RÉGRESSION DE SÉCURITÉ : $(($regs | ForEach-Object Point) -join ', '). À corriger avant tout." }
         elseif ($gains -and -not $worse) { "Gain mesuré sur : $(($gains | ForEach-Object Cible) -join ', ') (seuil $SeuilLat ms / $SeuilPerte points)." }
         elseif ($worse -and -not $gains) { "Dégradation mesurée sur : $(($worse | ForEach-Object Cible) -join ', '). Refaire la mesure à un autre moment ; si elle se confirme, annuler (option 5)." }
         elseif ($gains -and $worse) { 'Résultats contradictoires (gains et dégradations) : c''est du bruit de mesure. Refaire Verify à un autre moment.' }
         else { "Aucun gain mesurable sur cette machine (écarts sous $SeuilLat ms de latence médiane et $SeuilPerte points de perte)." }
Say ''
Say "CONCLUSION : $concl" $(if ($regs -or ($worse -and -not $gains)) { 'Red' } elseif ($gains -and -not $worse) { 'Green' } else { 'Yellow' })
Say 'Rappel : une seule comparaison dépend de l''heure (charge du réseau). Refaire Verify à un autre moment avant de conclure. Bufferbloat : seul un nouvel audit avec -LoadTest (et ton accord) le remesure.' 'DarkGray'

$out = [ordered]@{
    Outil = 'netguard-gaming Verify'; Date = (Get-Date).ToString('s'); Label = $Label; Baseline = (Split-Path $Baseline -Leaf)
    Seuils = [ordered]@{ LatenceMs = $SeuilLat; PertePts = $SeuilPerte; DnsMs = $script:NgSeuilDnsMs }
    Parametres = [ordered]@{ Passes = $Passes; IntervallePassesS = $PassIntervalSec; RequetesParCible = $PingCount }
    Latence = $latRows; Dns = $dnsRes; Securite = $sec; Conclusion = $concl
}
$dir = Join-Path $ReportsDir "verify_$stamp"
if ($PSCmdlet.ShouldProcess($dir, 'Écrire verify.json et verify.log')) {
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $enc = New-Object Text.UTF8Encoding($true)
    [IO.File]::WriteAllText((Join-Path $dir 'verify.json'), ($out | ConvertTo-Json -Depth 6), $enc)
    [IO.File]::WriteAllText((Join-Path $dir 'verify.log'), ($log -join "`r`n"), $enc)
    Write-Host "Résultat : $dir" -ForegroundColor Green
}
