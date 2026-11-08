<#
.SYNOPSIS
    Audit netguard-gaming : LECTURE SEULE. Mesure le réseau, la sécurité et le jeu avant tout réglage.
.DESCRIPTION
    Phase 0 (contexte) + Phase 1 (A réseau, B sécurité, C jeu). N'écrit QUE dans :
      reports\audit_<date>\audit.json + audit.log
      baseline\baseline_<date>.json
    Aucune commande d'écriture (registre, service, pare-feu, carte réseau) dans ce fichier ; vérifiable avec :
      Select-String -Path .\scripts\Audit.ps1 -Pattern 'Set-ItemProperty|New-ItemProperty|Remove-Item|Set-Service|Stop-Service|Set-Net|Disable-|Enable-|New-NetFirewallRule|reg add|reg delete'
    Mesures réseau : uniquement depuis CETTE machine vers des cibles nommées (passerelle, résolveurs publics,
    config\game_targets.json). Au plus 20 requêtes par cible et par passe. Aucun balayage d'IP ou de ports.
    Le test de charge (bufferbloat) n'est lancé QU'AVEC -LoadTest (il consomme ~300 Mo vers speed.cloudflare.com).
.EXAMPLE
    .\scripts\Audit.ps1 -WhatIf                 # mesure, mais n'écrit aucun fichier
    .\scripts\Audit.ps1                         # audit complet sans test de charge (~4 min)
    .\scripts\Audit.ps1 -LoadTest               # + bufferbloat (après ton accord)
    .\scripts\Audit.ps1 -Passes 1 -SkipWinget   # rapide
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateRange(1, 5)][int]$Passes = 3,           # passes de mesure de latence
    [int]$PassIntervalSec = 60,                      # pause entre deux passes
    [ValidateRange(5, 20)][int]$PingCount = 20,      # requêtes par cible et par passe (plafond : 20)
    [switch]$LoadTest,                               # bufferbloat : seulement avec ton accord
    [int]$LoadMaxDownloadMB = 200,                   # plafond de données téléchargées pendant le test de charge
    [int]$LoadMaxUploadMB = 100,                     # plafond de données envoyées
    [switch]$SkipWinget,
    [string]$LoadTestFrom,                           # réutilise le bufferbloat d'un audit précédent (évite de reconsommer ~300 Mo)
    [string]$NvidiaLatestVersion,                    # dernière version lue sur nvidia.com (ex. '581.80'), pour comparaison
    [string]$ReportsDir,                             # défaut : reports\  (Test-NetGuard.ps1 passe un dossier temporaire)
    [string]$BaselineDir                             # défaut : baseline\
)

. (Join-Path $PSScriptRoot 'Common.ps1')
$ErrorActionPreference = 'Continue'
$stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$constats = New-Object System.Collections.Generic.List[object]   # { Niveau, Section, Texte }
$adminCmds = New-Object System.Collections.Generic.List[object]  # { Pourquoi, Commande }
$logLines = New-Object System.Collections.Generic.List[string]
function Add-Constat([string]$Niveau, [string]$Section, [string]$Texte) {
    # Niveau : critique | attention | info | ok
    $constats.Add([pscustomobject]@{ Niveau = $Niveau; Section = $Section; Texte = $Texte })
}
function Add-AdminCmd([string]$Pourquoi, [string]$Commande) { $adminCmds.Add([pscustomobject]@{ Pourquoi = $Pourquoi; Commande = $Commande }) }
function Write-AuditLog([string]$t) { $logLines.Add(("{0:HH:mm:ss} {1}" -f (Get-Date), $t)) }
function Step([string]$t) { Write-Host "  - $t" -ForegroundColor Cyan; Write-AuditLog $t }
function Show([string]$t) { Write-Host "      $t"; Write-AuditLog "    $t" }
$isAdmin = Test-NgAdmin

Write-Host "`nnetguard-gaming : audit en lecture seule ($stamp)" -ForegroundColor Green
if ($isAdmin) { Write-Host "  (session administrateur : lectures plus complètes, toujours AUCUNE modification)" -ForegroundColor Yellow }

# =====================================================================================
# PHASE 0 - CONTEXTE
# =====================================================================================
Step 'Phase 0 : contexte'
$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$gpus = @(Get-CimInstance Win32_VideoController)
$chassis = @((Get-CimInstance Win32_SystemEnclosure).ChassisTypes)
$isLaptop = [bool](Get-CimInstance Win32_Battery) -or [bool]($chassis | Where-Object { $_ -in 8, 9, 10, 11, 12, 14, 30, 31, 32 })

# Carte réseau active = carte physique « Up » qui porte la route par défaut
$ipcfg = @(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' })
$mainCfg = $ipcfg | Select-Object -First 1
$adapter = if ($mainCfg) { Get-NetAdapter -InterfaceIndex $mainCfg.InterfaceIndex } else { Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | Select-Object -First 1 }
$isWifi = $adapter -and ($adapter.PhysicalMediaType -match '802\.11' -or $adapter.NdisPhysicalMedium -eq 9)
$gateway = if ($mainCfg) { $mainCfg.IPv4DefaultGateway.NextHop } else { $null }
$gwMac = if ($gateway) { (Get-NetNeighbor -IPAddress $gateway -ErrorAction SilentlyContinue | Select-Object -First 1).LinkLayerAddress } else { $null }
$dnsCurrent = @()
if ($adapter) { $dnsCurrent = @((Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses) }
$dnsCfg = Get-NgConfig 'dns_providers'
function Get-NgDnsOwner([string]$ip) {
    foreach ($p in @($dnsCfg.providers)) { if (@($p.ipv4) -contains $ip) { return $p.name } }
    if ($ip -match '^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)') { return 'Box / routeur local (relais vers le DNS de l''opérateur)' }
    'Autre / opérateur'
}

# PC géré ? (MDM Intune, domaine, Entra ID) : des stratégies peuvent primer sur les réglages locaux
$mdm = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction SilentlyContinue | ForEach-Object {
        $pid_ = Get-NgRegValue $_.PSPath 'ProviderID'
        # Windows crée d'office plusieurs clés (Local Authority, Deploy Authority...) : seule une inscription avec un COMPTE (UPN) compte
        $upn = Get-NgRegValue $_.PSPath 'UPN'
        if ($pid_ -and $upn) { [pscustomobject]@{ Fournisseur = $pid_; Type = Get-NgRegValue $_.PSPath 'EnrollmentType'; Etat = Get-NgRegValue $_.PSPath 'EnrollmentState'; Compte = $upn } } })
$aadJoin = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo' -ErrorAction SilentlyContinue).Count -gt 0
$policiesCount = @(Get-ChildItem 'HKLM:\SOFTWARE\Policies\Microsoft' -ErrorAction SilentlyContinue).Count

$contexte = [ordered]@{
    Date            = (Get-Date).ToString('s')
    Edition         = $cv.ProductName -replace 'Windows 10', 'Windows 11'   # ProductName dit encore « Windows 10 » sur Windows 11
    EditionId       = $cv.EditionID
    Version         = $cv.DisplayVersion
    Build           = "$($cv.CurrentBuild).$($cv.UBR)"
    Langue          = (Get-Culture).Name
    Type            = if ($isLaptop) { 'portable' } else { 'fixe' }
    Processeur      = $cpu.Name.Trim()
    RamGo           = [math]::Round($cs.TotalPhysicalMemory / 1GB)
    Gpu             = @($gpus | ForEach-Object { $_.Name })
    Admin           = $isAdmin
    Connexion       = if (-not $adapter) { 'aucune' } elseif ($isWifi) { 'Wi-Fi' } else { 'Ethernet' }
    Carte           = if ($adapter) { [ordered]@{
            Modele = $adapter.InterfaceDescription; Nom = $adapter.Name
            Pilote = $adapter.DriverVersion; DatePilote = $adapter.DriverDate; FournisseurPilote = $adapter.DriverProvider
            Vitesse = $adapter.LinkSpeed; DuplexIntegral = $adapter.FullDuplex; Mac = $adapter.MacAddress } } else { $null }
    IPv4            = if ($mainCfg) { @($mainCfg.IPv4Address.IPAddress) } else { @() }
    IPv6Global      = if ($mainCfg) { @($mainCfg.IPv6Address | Where-Object { $_.PrefixOrigin -ne 'WellKnown' } | ForEach-Object { $_.IPAddress }).Count -gt 0 } else { $false }
    Passerelle      = $gateway
    PasserelleMac   = $gwMac
    Dns             = @($dnsCurrent | ForEach-Object { [ordered]@{ Ip = $_; Fournisseur = Get-NgDnsOwner $_ } })
    Gere            = [ordered]@{ Mdm = $mdm; Domaine = [bool]$cs.PartOfDomain; EntraId = $aadJoin; ClesStrategiesMicrosoft = $policiesCount }
    NomPc           = $env:COMPUTERNAME     # uniquement dans reports\ (ignoré par Git) ; masqué dans la version partageable
    Utilisateur     = $env:USERNAME
}
Show ("{0} {1} (build {2}), {3}, {4}" -f $contexte.Edition, $contexte.Version, $contexte.Build, $contexte.Langue, $contexte.Type)
if ($adapter) { Show ("Connexion : {0} - {1}, pilote {2} du {3:dd/MM/yyyy}, {4}, duplex intégral : {5}" -f $contexte.Connexion, $adapter.InterfaceDescription, $adapter.DriverVersion, $adapter.DriverDate, $adapter.LinkSpeed, $adapter.FullDuplex) }
Show ("DNS actuel : {0}" -f (($contexte.Dns | ForEach-Object { "$($_.Ip) ($($_.Fournisseur))" }) -join ', '))
if ($mdm.Count -or $cs.PartOfDomain -or $aadJoin) {
    Add-Constat 'attention' '0. Contexte' ("Inscription à une organisation détectée (MDM avec compte : {0} [{1}], domaine : {2}, Entra ID : {3}) : des stratégies d'entreprise ou d'école peuvent primer sur les réglages locaux. Vérifier Paramètres > Comptes > Accès professionnel ou scolaire." -f $mdm.Count, (($mdm | ForEach-Object { $_.Fournisseur }) -join ', '), $cs.PartOfDomain, $aadJoin)
} else { Show 'PC non géré (ni MDM, ni domaine, ni Entra ID)' }
if (-not $adapter) { Add-Constat 'critique' '0. Contexte' 'Aucune carte réseau active avec passerelle : mesures réseau impossibles.' }
$drvDate = $null; if ($adapter) { try { $drvDate = [datetime]$adapter.DriverDate } catch { } }   # DriverDate est une CHAÎNE ('2024-03-12')
if ($drvDate -and ((Get-Date) - $drvDate).TotalDays -gt 730) {
    Add-Constat 'info' 'A. Réseau' ("Pilote de la carte réseau daté du {0:dd/MM/yyyy} (plus de 2 ans) : vérifier sur le site du fabricant de la carte mère / de la puce (fiche manuelle)." -f $drvDate)
}

# =====================================================================================
# A. RÉSEAU
# =====================================================================================
Step 'A1. Lien physique'
$lien = [ordered]@{ Type = $contexte.Connexion; Vitesse = if ($adapter) { $adapter.LinkSpeed } else { $null }
    VitesseBps = if ($adapter) { $adapter.ReceiveLinkSpeed } else { $null }; DuplexIntegral = if ($adapter) { $adapter.FullDuplex } else { $null }; WiFi = $null }
$wlan = $null
try { $wlan = Get-NgWlanInfo } catch { Write-AuditLog "Wi-Fi : $($_.Exception.Message)" }
if ($isWifi -and $wlan) {
    $w = @($wlan | Where-Object Connecte | Select-Object -First 1)
    if ($w) {
        $lien.WiFi = [ordered]@{ Bande = $w.Bande; Canal = $w.Canal; Phy = $w.Phy; SignalPct = $w.SignalPct; DebitRxMbps = $w.DebitRxMbps; DebitTxMbps = $w.DebitTxMbps
            Largeur = 'non lisible sans netsh (voir l''interface de la box)' }
        Show ("Wi-Fi {0}, canal {1}, {2}, signal {3} %, débit négocié {4} Mbit/s" -f $w.Bande, $w.Canal, $w.Phy, $w.SignalPct, $w.DebitRxMbps)
        Add-Constat 'attention' 'A. Réseau' 'Connexion en Wi-Fi : pour jouer, un câble Ethernet supprime la gigue et les pertes dues aux interférences (fiche manuelle).'
        if ($w.SignalPct -lt 60) { Add-Constat 'attention' 'A. Réseau' "Signal Wi-Fi faible ($($w.SignalPct) %)." }
        if ($w.Bande -eq '2,4 GHz') { Add-Constat 'attention' 'A. Réseau' 'Wi-Fi en 2,4 GHz : bande encombrée, préférer 5 ou 6 GHz.' }
    }
} elseif ($adapter) {
    Show ("Ethernet {0}, duplex intégral : {1}" -f $adapter.LinkSpeed, $adapter.FullDuplex)
    if ($adapter.ReceiveLinkSpeed -lt 1000000000) { Add-Constat 'attention' 'A. Réseau' "Lien Ethernet négocié à $($adapter.LinkSpeed) (moins de 1 Gbit/s) : câble (catégorie, paires), port de la box ou réglage de vitesse de la carte à vérifier." }
    if (-not $adapter.FullDuplex) { Add-Constat 'attention' 'A. Réseau' 'Lien Ethernet en semi-duplex : collisions possibles, vérifier le câble et le réglage « Speed & Duplex ».' }
}

# --- A2. Latence, gigue, perte : plusieurs passes, médiane et pire cas -----------------
Step "A2. Latence / gigue / perte : $Passes passe(s) x $PingCount requêtes par cible (1 toutes les 200 ms)"
$gt = Get-NgConfig 'game_targets'
$targets = New-Object System.Collections.Generic.List[object]
if ($gateway) { $targets.Add([pscustomobject]@{ name = 'Passerelle (box)'; host = $gateway; method = 'icmp'; kind = 'passerelle'; port = $null }) }
foreach ($t in @($gt.targets)) { $targets.Add($t) }
$latence = [ordered]@{}
foreach ($t in $targets) { $latence[$t.name] = [ordered]@{ Hote = $t.host; Methode = $t.method; Type = $t.kind; Passes = @() } }
for ($p = 1; $p -le $Passes; $p++) {
    Show ("Passe {0}/{1} à {2:HH:mm:ss}" -f $p, $Passes, (Get-Date))
    foreach ($t in $targets) {
        if ($t.method -eq 'tcp') {
            $port = if ($t.port) { [int]$t.port } else { 443 }
            $s = Measure-NgTcpConnect -Target $t.host -Port $port -Count $PingCount
        } else { $s = Measure-NgPing -Target $t.host -Count $PingCount }
        $s | Add-Member -NotePropertyName Heure -NotePropertyValue (Get-Date).ToString('s')
        $latence[$t.name].Passes += $s
        Show ("  {0,-38} médiane {1,5} ms  gigue {2,5} ms  perte {3,5} %  pire {4,5} ms" -f $t.name, $s.MedianeMs, $s.JitterMs, $s.PertePct, $s.MaxMs)
    }
    if ($p -lt $Passes) { Start-Sleep -Seconds $PassIntervalSec }
}
# Agrégat : médiane de TOUTES les mesures, pire passe, perte totale
foreach ($k in @($latence.Keys)) {
    $all = [double[]]@($latence[$k].Passes | ForEach-Object { $_.Mesures } | ForEach-Object { $_ })
    $sent = ($latence[$k].Passes | Measure-Object -Property Envoyes -Sum).Sum
    $agg = Get-NgSeriesStats -Rtts $all -Sent $sent
    $latence[$k].MedianeMs = $agg.MedianeMs
    $latence[$k].P95Ms = $agg.P95Ms
    $latence[$k].PireMs = $agg.MaxMs
    $latence[$k].PertePct = $agg.PertePct
    $latence[$k].JitterMs = Get-NgMedian ([double[]]@($latence[$k].Passes | Where-Object { $null -ne $_.JitterMs } | ForEach-Object { $_.JitterMs }))
    $latence[$k].PirePasseMedianeMs = ($latence[$k].Passes | Where-Object { $null -ne $_.MedianeMs } | Measure-Object -Property MedianeMs -Maximum).Maximum
    if ($agg.PertePct -ge 2) { Add-Constat 'attention' 'A. Réseau' ("Perte de paquets vers {0} : {1} % sur {2} requêtes." -f $k, $agg.PertePct, $sent) }
}
$gwStats = if ($gateway) { $latence['Passerelle (box)'] } else { $null }
if ($gwStats -and $gwStats.MedianeMs -gt 5) { Add-Constat 'attention' 'A. Réseau' "Latence vers la box anormalement haute ($($gwStats.MedianeMs) ms) pour un réseau local : Wi-Fi, CPL ou équipement intermédiaire ?" }
if ($gwStats -and $gwStats.JitterMs -gt 2) { Add-Constat 'attention' 'A. Réseau' "Gigue vers la box de $($gwStats.JitterMs) ms : instabilité du réseau LOCAL (avant même Internet)." }

# --- A3. Benchmark DNS --------------------------------------------------------------------
Step 'A3. Benchmark DNS (actuel vs Cloudflare vs Google vs Quad9, cache évité par sous-domaines aléatoires)'
$servers = New-Object System.Collections.Generic.List[object]
foreach ($d in ($dnsCurrent | Select-Object -First 1)) { $servers.Add([pscustomobject]@{ Nom = "Actuel ($(Get-NgDnsOwner $d))"; Ip = $d }) }
foreach ($pv in @($dnsCfg.providers)) {
    if ($dnsCurrent -notcontains $pv.ipv4[0]) { $servers.Add([pscustomobject]@{ Nom = $pv.name; Ip = $pv.ipv4[0] }) }
}
$domains = @($dnsCfg.domains)
$nRand = [math]::Min([int]$dnsCfg.randomSubdomainsPerServer, $script:NgMaxProbesPerTarget - $domains.Count)
$queries = @($domains | ForEach-Object { [pscustomobject]@{ Name = $_; Cache = $true } })
for ($i = 0; $i -lt $nRand; $i++) { $queries += [pscustomobject]@{ Name = $domains[$i % $domains.Count]; Cache = $false } }
$dnsRes = @{}
foreach ($s in $servers) { $dnsRes[$s.Ip] = New-Object System.Collections.Generic.List[object] }
# Requêtes ENTRELACÉES (même requête vers chaque serveur à la suite) : un pic de charge du réseau pénalise tout le monde pareil
foreach ($q in $queries) {
    foreach ($s in $servers) {
        $name = if ($q.Cache) { $q.Name } else { "$(New-NgRandomLabel).$($q.Name)" }
        $r = Measure-NgDnsQuery -Server $s.Ip -Name $name
        $dnsRes[$s.Ip].Add([pscustomobject]@{ Ok = $r.Ok; Ms = $r.Ms; Cache = $q.Cache })
    }
}
$dnsBench = @(foreach ($s in $servers) {
        $rs = $dnsRes[$s.Ip]
        $okC = [double[]]@($rs | Where-Object { $_.Ok -and $_.Cache } | ForEach-Object { $_.Ms })
        $okN = [double[]]@($rs | Where-Object { $_.Ok -and -not $_.Cache } | ForEach-Object { $_.Ms })
        $okA = [double[]]@($rs | Where-Object Ok | ForEach-Object { $_.Ms })
        [pscustomobject]@{
            Nom = $s.Nom; Ip = $s.Ip; Requetes = $rs.Count; Echecs = @($rs | Where-Object { -not $_.Ok }).Count
            MedianeMs = [math]::Round((Get-NgMedian $okA), 1)
            MedianeNomsCourantsMs = [math]::Round((Get-NgMedian $okC), 1)
            MedianeSansCacheMs = [math]::Round((Get-NgMedian $okN), 1)
            P95Ms = Get-NgPercentile $okA 95
        }
    }) | Sort-Object MedianeMs
foreach ($b in $dnsBench) { Show ("  {0,-55} médiane {1,6} ms (noms courants {2}, sans cache {3}, p95 {4}), échecs {5}/{6}" -f $b.Nom, $b.MedianeMs, $b.MedianeNomsCourantsMs, $b.MedianeSansCacheMs, $b.P95Ms, $b.Echecs, $b.Requetes) }
$dnsActuel = $dnsBench | Where-Object { $_.Nom -like 'Actuel*' } | Select-Object -First 1
$dnsBest = $dnsBench | Where-Object { $_.Echecs -eq 0 } | Select-Object -First 1
if ($dnsActuel -and $dnsBest -and $dnsBest.Nom -ne $dnsActuel.Nom -and ($dnsActuel.MedianeMs - $dnsBest.MedianeMs) -ge 5) {
    Add-Constat 'info' 'A. Réseau' ("{0} répond plus vite que le DNS actuel ({1} ms contre {2} ms). Effet : chargement des pages et connexion aux services, PAS le ping en jeu." -f $dnsBest.Nom, $dnsBest.MedianeMs, $dnsActuel.MedianeMs)
}

# --- A4. MTU, propriétés avancées et alimentation de la carte -----------------------------
Step 'A4. MTU et propriétés de la carte réseau'
$mtu = [ordered]@{ Interface = $null; Chemin = $null }
if ($adapter) { $mtu.Interface = (Get-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).NlMtu }
$mtu.Chemin = Test-NgPathMtu -Target '1.1.1.1'
Show ("MTU de l'interface : {0} ; MTU effectif vers 1.1.1.1 : {1} ({2})" -f $mtu.Interface, $mtu.Chemin.MtuChemin, $mtu.Chemin.Note)
if ($mtu.Chemin.MtuChemin -and $mtu.Interface -and $mtu.Chemin.MtuChemin -lt $mtu.Interface) {
    Add-Constat 'info' 'A. Réseau' "MTU du chemin ($($mtu.Chemin.MtuChemin)) inférieur à celui de l'interface ($($mtu.Interface)) : normal en PPPoE ; Windows le gère seul (PMTUD). Ne pas forcer de MTU « gaming »."
}
$advanced = @()
$pnpCap = $null
if ($adapter) {
    $advanced = @(Get-NetAdapterAdvancedProperty -Name $adapter.Name -ErrorAction SilentlyContinue | ForEach-Object {
            $cat = 'autre'
            if ($_.RegistryKeyword -match '(?i)EEE|Green|PowerSav|PowerDown|GigaLite|SavePower|ULP|SelectiveSuspend|\*PME|EnablePME') { $cat = 'énergie' }
            elseif ($_.RegistryKeyword -match '(?i)Offload|Checksum|Lso|Rsc|IPsec') { $cat = 'déchargement (offload)' }
            elseif ($_.RegistryKeyword -match '(?i)Buffers') { $cat = 'tampons' }
            elseif ($_.RegistryKeyword -match '(?i)InterruptModeration|ITR|RSS|Queues') { $cat = 'interruptions / files' }
            elseif ($_.RegistryKeyword -match '(?i)Wake|WoL') { $cat = 'réveil (WoL)' }
            elseif ($_.RegistryKeyword -match '(?i)FlowControl|SpeedDuplex|Jumbo|Priority|VLAN') { $cat = 'lien' }
            [pscustomobject]@{ Categorie = $cat; Nom = $_.DisplayName; Valeur = $_.DisplayValue; Cle = $_.RegistryKeyword; ValeurBrute = "$($_.RegistryValue)" } })
    foreach ($a in ($advanced | Where-Object { $_.Categorie -eq 'énergie' })) { Show ("  [énergie] {0} = {1}" -f $a.Nom, $a.Valeur) }
    # Gestion d'alimentation de la carte (« Autoriser l'ordinateur à éteindre ce périphérique ») :
    # Get-NetAdapterPowerManagement est refusé à un utilisateur standard ; on lit PnPCapabilities dans la clé de classe.
    # 24 (0x18) = case décochée ; absent ou 0 = autorisé (défaut).
    $classKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}'
    $inst = Get-ChildItem $classKey -ErrorAction SilentlyContinue | Where-Object { (Get-NgRegValue $_.PSPath 'NetCfgInstanceId') -eq $adapter.InterfaceGuid } | Select-Object -First 1
    if ($inst) { $pnpCap = Get-NgRegValue $inst.PSPath 'PnPCapabilities' }
    $eeeOn = @($advanced | Where-Object { $_.Categorie -eq 'énergie' -and $_.Cle -match '(?i)EEE|Green|PowerSav|GigaLite|PowerDown' -and $_.ValeurBrute -notin '0', '' })
    if ($eeeOn.Count) { Add-Constat 'info' 'A. Réseau' ("Économies d'énergie actives sur la carte : {0}. Effet sur le ping : à mesurer en A/B (souvent nul sur PC fixe), mais cause connue de micro-coupures avec certains switchs." -f (($eeeOn | ForEach-Object { $_.Nom }) -join ', ')) }
}
$alimCarte = [ordered]@{ PnPCapabilities = $pnpCap; WindowsPeutEteindre = -not ($pnpCap -band 0x10) }
Show ("Windows peut éteindre la carte pour économiser l'énergie : {0} (PnPCapabilities = {1})" -f $alimCarte.WindowsPeutEteindre, $(if ($null -eq $pnpCap) { 'absent' } else { $pnpCap }))

# --- A5. Consommation réseau en arrière-plan ------------------------------------------------
Step 'A5. Trafic en arrière-plan (10 s), Delivery Optimization, OneDrive'
$perfName = if ($adapter) { $adapter.InterfaceDescription -replace '\(', '[' -replace '\)', ']' -replace '#', '_' -replace '/', '_' } else { '' }
$netSamples = @()
for ($i = 0; $i -lt 5; $i++) {
    $ni = Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkInterface -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq $perfName }
    if ($ni) { $netSamples += [pscustomobject]@{ RxKbps = [math]::Round($ni.BytesReceivedPersec * 8 / 1000, 1); TxKbps = [math]::Round($ni.BytesSentPersec * 8 / 1000, 1) } }
    Start-Sleep -Seconds 2
}
$traficRepos = [ordered]@{
    RxKbpsMediane = Get-NgMedian ([double[]]@($netSamples | ForEach-Object { $_.RxKbps }))
    TxKbpsMediane = Get-NgMedian ([double[]]@($netSamples | ForEach-Object { $_.TxKbps }))
    RxKbpsMax = ($netSamples | Measure-Object -Property RxKbps -Maximum).Maximum
    TxKbpsMax = ($netSamples | Measure-Object -Property TxKbps -Maximum).Maximum
}
Show ("Trafic au repos : réception médiane {0} kbit/s (max {1}), envoi médian {2} kbit/s (max {3})" -f $traficRepos.RxKbpsMediane, $traficRepos.RxKbpsMax, $traficRepos.TxKbpsMediane, $traficRepos.TxKbpsMax)

# Processus <-> connexions (Windows n'expose pas d'octets réseau PAR processus sans admin/ETW :
# on croise le nombre de connexions établies et le débit d'E/S du processus, qui inclut disque ET réseau)
$procs = @{}; foreach ($p in Get-CimInstance Win32_Process) { $procs[[int]$p.ProcessId] = $p }
$svcByPid = @{}
$svcPathByPid = @{}
foreach ($s in Get-CimInstance Win32_Service -Filter 'ProcessId > 0') {
    $k = [int]$s.ProcessId; if (-not $svcByPid[$k]) { $svcByPid[$k] = @() }; $svcByPid[$k] += $s.Name
    # Chemin de l'exécutable du service (PathName, lisible sans admin) : '"C:\x\y.exe" -k ...' -> C:\x\y.exe
    if ($s.PathName -match '^"?([A-Za-z]:\\[^"]+?\.exe)') { $svcPathByPid[$k] = $Matches[1] }
}
function Get-NgProcPath([int]$procId) { $pr = $procs[$procId]; if ($pr -and $pr.ExecutablePath) { $pr.ExecutablePath } elseif ($svcPathByPid[$procId]) { $svcPathByPid[$procId] } else { $null } }
$ioByPid = @{}
foreach ($pp in Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -ErrorAction SilentlyContinue) { $ioByPid[[int]$pp.IDProcess] = $pp }
$estab = @(Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Where-Object { $_.RemoteAddress -notmatch '^(127\.|::1$|0\.0\.0\.0)' })
$consommateurs = @($estab | Group-Object OwningProcess | ForEach-Object {
        $procId = [int]$_.Name; $pr = $procs[$procId]
        [pscustomobject]@{
            Processus = if ($pr) { $pr.Name } else { "PID $procId" }; Pid = $procId
            Services = ($svcByPid[$procId] -join ', ')
            Connexions = $_.Count
            IoKoParSec = if ($ioByPid[$procId]) { [math]::Round($ioByPid[$procId].IODataBytesPersec / 1KB, 1) } else { $null }
        } } | Sort-Object Connexions -Descending)
foreach ($c in ($consommateurs | Select-Object -First 8)) { Show ("  {0,-28} {1,3} connexion(s)  E/S {2} Ko/s {3}" -f $c.Processus, $c.Connexions, $c.IoKoParSec, $(if ($c.Services) { "($($c.Services))" })) }

# Delivery Optimization : partage des mises à jour avec d'autres PC (peut ENVOYER vers Internet)
$doModes = @{ 0 = 'HTTP seul (pas de partage)'; 1 = 'PC du réseau local'; 2 = 'groupe'; 3 = 'réseau local + Internet'; 99 = 'simple'; 100 = 'contournement' }
$doPolicy = Get-NgRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization' 'DODownloadMode'
$doUser = Get-NgRegValue 'Registry::HKEY_USERS\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings' 'DownloadMode'
$doSnap = $null
try { $doSnap = Get-DeliveryOptimizationPerfSnapThisMonth -ErrorAction Stop } catch { }
$doJobs = @()
try { $doJobs = @(Get-DeliveryOptimizationStatus -ErrorAction Stop) } catch { }
$deliveryOpt = [ordered]@{
    ModeStrategie = $doPolicy; ModeParametres = $doUser
    ModeEffectif = if ($null -ne $doPolicy) { $doModes[[int]$doPolicy] } elseif ($null -ne $doUser) { $doModes[[int]$doUser] } else { 'défaut Windows (réseau local)' }
    TachesEnCours = $doJobs.Count
    MoisTelechargeMo = if ($doSnap) { [math]::Round(($doSnap.DownloadHttpBytes + $doSnap.DownloadLanBytes + $doSnap.DownloadInternetBytes) / 1MB) } else { $null }
    MoisEnvoyeInternetMo = if ($doSnap) { [math]::Round($doSnap.UploadInternetBytes / 1MB) } else { $null }
    MoisEnvoyeLanMo = if ($doSnap) { [math]::Round($doSnap.UploadLanBytes / 1MB) } else { $null }
}
Show ("Delivery Optimization : {0} ; ce mois : {1} Mo reçus, {2} Mo envoyés vers Internet, {3} Mo vers le réseau local" -f $deliveryOpt.ModeEffectif, $deliveryOpt.MoisTelechargeMo, $deliveryOpt.MoisEnvoyeInternetMo, $deliveryOpt.MoisEnvoyeLanMo)
if ($deliveryOpt.MoisEnvoyeInternetMo -gt 500) { Add-Constat 'info' 'A. Réseau' "Delivery Optimization a envoyé $($deliveryOpt.MoisEnvoyeInternetMo) Mo vers d'autres PC sur Internet ce mois-ci." }
$oneDrive = [ordered]@{
    EnCours = [bool](Get-Process OneDrive -ErrorAction SilentlyContinue)
    Comptes = @(Get-ChildItem 'HKCU:\Software\Microsoft\OneDrive\Accounts' -ErrorAction SilentlyContinue | Where-Object { Get-NgRegValue $_.PSPath 'UserFolder' }).Count
}
Show ("OneDrive : en cours = {0}, comptes configurés = {1}" -f $oneDrive.EnCours, $oneDrive.Comptes)

# --- A6. Bufferbloat (test de charge, seulement avec -LoadTest) ----------------------------
$bufferbloat = $null
function Get-NgBloatGrade([double]$delta) {
    # Barème de la latence AJOUTÉE sous charge (repris de la méthode des tests de bufferbloat publics)
    if ($delta -lt 5) { 'A+' } elseif ($delta -lt 30) { 'A' } elseif ($delta -lt 60) { 'B' } elseif ($delta -lt 200) { 'C' } elseif ($delta -lt 400) { 'D' } else { 'F' }
}
function Invoke-NgLoadPhase {
    <#
        Charge la ligne avec 4 flux parallèles vers speed.cloudflare.com (__down ou __up) jusqu'à $MaxMB
        ou 15 s, et mesure PENDANT ce temps la latence vers 1.1.1.1 (20 pings max, 1 toutes les 150 ms).
        Seuls les pings envoyés pendant que la charge tourne sont comptés.
    #>
    param([ValidateSet('down', 'up')][string]$Mode, [int]$MaxMB)
    $sync = [hashtable]::Synchronized(@{ Bytes = [int64]0; Stop = $false; Errors = 0 })
    $worker = {
        param($Mode, $Sync, $MaxBytes)
        Add-Type -AssemblyName System.Net.Http
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $client = New-Object System.Net.Http.HttpClient
        $client.Timeout = [TimeSpan]::FromSeconds(20)
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $buf = New-Object byte[] 65536
        $payload = New-Object byte[] (4MB)
        try {
            while (-not $Sync.Stop -and $sw.Elapsed.TotalSeconds -lt 15 -and $Sync.Bytes -lt $MaxBytes) {
                try {
                    if ($Mode -eq 'down') {
                        $resp = $client.GetAsync('https://speed.cloudflare.com/__down?bytes=25000000', [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).Result
                        $st = $resp.Content.ReadAsStreamAsync().Result
                        while (($n = $st.Read($buf, 0, $buf.Length)) -gt 0) {
                            [Threading.Monitor]::Enter($Sync.SyncRoot); try { $Sync.Bytes += $n } finally { [Threading.Monitor]::Exit($Sync.SyncRoot) }
                            if ($Sync.Stop -or $Sync.Bytes -ge $MaxBytes -or $sw.Elapsed.TotalSeconds -ge 15) { break }
                        }
                        $st.Dispose(); $resp.Dispose()
                    } else {
                        $content = New-Object System.Net.Http.ByteArrayContent(, $payload)
                        $resp = $client.PostAsync('https://speed.cloudflare.com/__up', $content).Result
                        [Threading.Monitor]::Enter($Sync.SyncRoot); try { $Sync.Bytes += $payload.Length } finally { [Threading.Monitor]::Exit($Sync.SyncRoot) }
                        $resp.Dispose(); $content.Dispose()
                    }
                } catch { $Sync.Errors++; Start-Sleep -Milliseconds 300 }
            }
        } finally { $client.Dispose() }
    }
    $pool = [runspacefactory]::CreateRunspacePool(1, 4); $pool.Open()
    $jobs = @(1..4 | ForEach-Object {
            $ps = [powershell]::Create(); $ps.RunspacePool = $pool
            [void]$ps.AddScript($worker).AddArgument($Mode).AddArgument($sync).AddArgument([int64]$MaxMB * 1MB)
            [pscustomobject]@{ Ps = $ps; Handle = $ps.BeginInvoke() } })
    $sw = [Diagnostics.Stopwatch]::StartNew()
    Start-Sleep -Milliseconds 1000   # montée en charge
    $ping = New-Object System.Net.NetworkInformation.Ping
    $rtts = New-Object System.Collections.Generic.List[double]; $sent = 0
    while ($sent -lt $script:NgMaxProbesPerTarget -and @($jobs | Where-Object { -not $_.Handle.IsCompleted }).Count -gt 0) {
        $sent++
        try { $r = $ping.Send('1.1.1.1', 2000); if ($r.Status -eq 'Success') { $rtts.Add([double]$r.RoundtripTime) } } catch { }
        Start-Sleep -Milliseconds 150
    }
    $sync.Stop = $true
    foreach ($j in $jobs) { try { [void]$j.Ps.EndInvoke($j.Handle) } catch { }; $j.Ps.Dispose() }
    $elapsed = $sw.Elapsed.TotalSeconds
    $pool.Close(); $ping.Dispose()
    $st = Get-NgSeriesStats -Rtts $rtts.ToArray() -Sent $sent
    [pscustomobject]@{
        Sens = $Mode; Mo = [math]::Round($sync.Bytes / 1MB); DureeS = [math]::Round($elapsed, 1)
        DebitMbps = if ($elapsed -gt 0) { [math]::Round($sync.Bytes * 8 / $elapsed / 1e6) } else { $null }
        ErreursHttp = $sync.Errors; Latence = $st
    }
}
if ($LoadTest) {
    Step "A6. Bufferbloat : repos puis charge (plafonds : $LoadMaxDownloadMB Mo reçus, $LoadMaxUploadMB Mo envoyés, vers speed.cloudflare.com)"
    $idle = Measure-NgPing -Target '1.1.1.1' -Count 20 -IntervalMs 150
    Show ("Repos : médiane {0} ms, gigue {1} ms" -f $idle.MedianeMs, $idle.JitterMs)
    $down = Invoke-NgLoadPhase -Mode down -MaxMB $LoadMaxDownloadMB
    Show ("Pendant le téléchargement : {0} Mo en {1} s ({2} Mbit/s moyens, montée en charge comprise : PAS un test de débit) ; latence médiane {3} ms, p95 {4} ms, {5} mesures" -f $down.Mo, $down.DureeS, $down.DebitMbps, $down.Latence.MedianeMs, $down.Latence.P95Ms, $down.Latence.Recus)
    Start-Sleep -Seconds 3
    $up = Invoke-NgLoadPhase -Mode up -MaxMB $LoadMaxUploadMB
    Show ("Pendant l'envoi : {0} Mo en {1} s ({2} Mbit/s) ; latence médiane {3} ms, p95 {4} ms, {5} mesures" -f $up.Mo, $up.DureeS, $up.DebitMbps, $up.Latence.MedianeMs, $up.Latence.P95Ms, $up.Latence.Recus)
    $bufferbloat = [ordered]@{ Repos = $idle; Telechargement = $down; Envoi = $up; Verdict = $null; Note = $null }
    $grades = @()
    foreach ($ph in @($down, $up)) {
        if ($ph.Latence.Recus -ge 5 -and $null -ne $idle.MedianeMs) {
            $delta = [math]::Round($ph.Latence.MedianeMs - $idle.MedianeMs, 1)
            $ph | Add-Member -NotePropertyName AjoutMs -NotePropertyValue $delta
            $ph | Add-Member -NotePropertyName Note -NotePropertyValue (Get-NgBloatGrade $delta)
            $grades += $ph.Note
        } else { $ph | Add-Member -NotePropertyName Note -NotePropertyValue 'non concluant (charge trop courte ou pas de réponse)' }
    }
    $order = 'A+', 'A', 'B', 'C', 'D', 'F'
    if ($grades.Count) {
        $bufferbloat.Verdict = ($grades | Sort-Object { [array]::IndexOf($order, $_) } | Select-Object -Last 1)
        Show ("Verdict bufferbloat : {0} (téléchargement {1} : +{2} ms ; envoi {3} : +{4} ms)" -f $bufferbloat.Verdict, $down.Note, $down.AjoutMs, $up.Note, $up.AjoutMs)
        if ($bufferbloat.Verdict -in 'C', 'D', 'F') { Add-Constat 'attention' 'A. Réseau' "Bufferbloat noté $($bufferbloat.Verdict) : le ping s'envole quand la ligne est chargée. Correctif réel : QoS / SQM sur la box (fiche manuelle), pas sur le PC." }
    }
    if (($down.Mo -ge $LoadMaxDownloadMB -and $down.DureeS -lt 5) -or ($up.Mo -ge $LoadMaxUploadMB -and $up.DureeS -lt 5)) {
        $bufferbloat.Note = 'Plafond de données atteint en moins de 5 s : ligne très rapide, la saturation a été brève. Verdict à confirmer (relancer avec des plafonds plus hauts si tu es d''accord).'
        Show $bufferbloat.Note
    }
} elseif ($LoadTestFrom -and (Test-Path -LiteralPath $LoadTestFrom)) {
    Step "A6. Bufferbloat : résultat repris de $LoadTestFrom (pas de nouveau test de charge)"
    $prev = Get-Content -LiteralPath $LoadTestFrom -Raw -Encoding UTF8 | ConvertFrom-Json
    $bufferbloat = $prev.Reseau.Bufferbloat
    if ($bufferbloat) { $bufferbloat | Add-Member -NotePropertyName ReprisDe -NotePropertyValue "$($prev.Date)" -Force; Show ("Verdict repris : {0} (mesuré le {1})" -f $bufferbloat.Verdict, $prev.Date)
        if ($bufferbloat.Verdict -in 'C', 'D', 'F') { Add-Constat 'attention' 'A. Réseau' "Bufferbloat noté $($bufferbloat.Verdict) (mesure du $($prev.Date)) : le ping s'envole quand la ligne est chargée. Correctif réel : QoS / SQM sur la box (fiche manuelle), pas sur le PC." } }
} else { Step 'A6. Bufferbloat : non lancé (ajoute -LoadTest après accord : ~300 Mo vers speed.cloudflare.com)' }

# =====================================================================================
# B. SÉCURITÉ
# =====================================================================================
Step 'B1. Pare-feu : profils et règles entrantes autorisées'
$fwProfiles = @()
try { $fwProfiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop) } catch { $fwProfiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue) }
$netProfiles = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Interface = $_.InterfaceAlias; Categorie = "$($_.NetworkCategory)"; Ipv4 = "$($_.IPv4Connectivity)" } })
$pareFeu = [ordered]@{
    Profils = @($fwProfiles | ForEach-Object { [pscustomobject]@{ Profil = "$($_.Name)"; Actif = "$($_.Enabled)"; EntrantParDefaut = "$($_.DefaultInboundAction)"; SortantParDefaut = "$($_.DefaultOutboundAction)" } })
    ReseauActuel = $netProfiles
    ReglesLarges = @(); ReglesProgrammeAbsent = @(); TotalEntrantesAutorisees = 0
}
foreach ($fp in $pareFeu.Profils) {
    Show ("  Profil {0,-8} actif : {1,-5} entrant par défaut : {2}" -f $fp.Profil, $fp.Actif, $fp.EntrantParDefaut)
    if ($fp.Actif -in 'False', '0') { Add-Constat 'critique' 'B. Sécurité' "Pare-feu DÉSACTIVÉ sur le profil $($fp.Profil)." }
    if ($fp.EntrantParDefaut -eq 'Allow') { Add-Constat 'critique' 'B. Sécurité' "Profil $($fp.Profil) : connexions entrantes AUTORISÉES par défaut." }
}
foreach ($np in $netProfiles) { Show ("  Réseau actuel : {0} -> profil {1}" -f $np.Interface, $np.Categorie) }

$inRules = @(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue)
$pareFeu.TotalEntrantesAutorisees = $inRules.Count
$portF = @{}; foreach ($f in @(Get-NetFirewallPortFilter -All -ErrorAction SilentlyContinue)) { $portF[$f.InstanceID] = $f }
$appF = @{}; foreach ($f in @(Get-NetFirewallApplicationFilter -All -ErrorAction SilentlyContinue)) { $appF[$f.InstanceID] = $f }
$addrF = @{}; foreach ($f in @(Get-NetFirewallAddressFilter -All -ErrorAction SilentlyContinue)) { $addrF[$f.InstanceID] = $f }
$ruleInfo = @(foreach ($r in $inRules) {
        $pf = $portF[$r.InstanceID]; $af = $appF[$r.InstanceID]; $ad = $addrF[$r.InstanceID]
        $prog = if ($af) { "$($af.Program)" } else { 'Any' }
        $progX = [Environment]::ExpandEnvironmentVariables($prog)
        $isSystem = ("$($r.Group)" -like '@*') -or [bool]$r.Owner   # groupe intégré Windows (@FirewallAPI.dll...) ou règle d'appli du Store
        [pscustomobject]@{
            Nom = $r.DisplayName; Id = $r.Name; Groupe = "$($r.DisplayGroup)"; Systeme = $isSystem
            Profils = "$($r.Profile)"; Protocole = if ($pf) { "$($pf.Protocol)" } else { 'Any' }
            PortsLocaux = if ($pf) { (@($pf.LocalPort) -join ',') } else { 'Any' }
            Distant = if ($ad) { (@($ad.RemoteAddress) -join ',') } else { 'Any' }
            Programme = $prog
            ProgrammeAbsent = ($prog -notin 'Any', 'System', '') -and -not (Test-Path -LiteralPath $progX)
            Public = ("$($r.Profile)" -eq 'Any' -or "$($r.Profile)" -match 'Public')
        } })
$pareFeu.ReglesLarges = @($ruleInfo | Where-Object { -not $_.Systeme -and $_.PortsLocaux -eq 'Any' -and $_.Distant -eq 'Any' -and $_.Public })
$pareFeu.ReglesProgrammeAbsent = @($ruleInfo | Where-Object { $_.ProgrammeAbsent })
Show ("  {0} règles entrantes autorisées actives ; {1} hors Windows ouvertes à tous ports / toutes adresses y compris en Public ; {2} pointent vers un programme absent" -f $ruleInfo.Count, $pareFeu.ReglesLarges.Count, $pareFeu.ReglesProgrammeAbsent.Count)
if ($pareFeu.ReglesLarges.Count) { Add-Constat 'attention' 'B. Sécurité' ("{0} règle(s) entrante(s) hors Windows autorisent tous les ports depuis toute adresse, y compris sur un réseau Public (souvent créées par la fenêtre « Autoriser l'accès » d'un jeu). À examiner une par une." -f $pareFeu.ReglesLarges.Count) }
if ($pareFeu.ReglesProgrammeAbsent.Count) { Add-Constat 'info' 'B. Sécurité' ("{0} règle(s) entrante(s) visent un programme désinstallé : inutiles (désactivation possible après ton accord, jamais de suppression)." -f $pareFeu.ReglesProgrammeAbsent.Count) }

Step 'B2. Ports en écoute (TCP/UDP) avec processus et chemin'
$sigCache = @{}
function Get-NgSignature([string]$path) {
    if (-not $path) { return 'inconnu (processus protégé : chemin illisible sans admin)' }
    if (-not $sigCache.ContainsKey($path)) {
        try { $s = Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop
            $who = if ($s.SignerCertificate) { ($s.SignerCertificate.Subject -replace '^CN="?([^",]+).*$', '$1') } else { '' }
            $sigCache[$path] = if ("$($s.Status)" -eq 'Valid') { "valide ($who)" } else { "$($s.Status) $who".Trim() }
        } catch { $sigCache[$path] = 'illisible' }
    }
    $sigCache[$path]
}
function Get-NgScope([string]$addr) {
    if ($addr -in '0.0.0.0', '::') { 'toutes les interfaces' } elseif ($addr -match '^(127\.|::1$)') { 'local uniquement' } else { "adresse précise ($addr)" }
}
$listen = @()
$listen += @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Proto = 'TCP'; Adresse = $_.LocalAddress; Port = $_.LocalPort; Pid = [int]$_.OwningProcess } })
$listen += @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Proto = 'UDP'; Adresse = $_.LocalAddress; Port = $_.LocalPort; Pid = [int]$_.OwningProcess } })
$ports = @($listen | Group-Object Proto, Port, Pid | ForEach-Object {
        $f = $_.Group[0]; $pr = $procs[$f.Pid]
        $path = Get-NgProcPath $f.Pid
        $scopes = @($_.Group | ForEach-Object { Get-NgScope $_.Adresse } | Select-Object -Unique)
        $isWin = ($f.Pid -eq 4) -or ($path -and $path -like "$env:windir\*")
        # Le pare-feu laisse-t-il entrer ? (règle entrante autorisée pour ce programme, ou pour ce port sans programme)
        $allowed = @($ruleInfo | Where-Object {
                ($path -and $_.Programme -ne 'Any' -and ([Environment]::ExpandEnvironmentVariables($_.Programme) -ieq $path) -and ($_.PortsLocaux -eq 'Any' -or ($_.PortsLocaux -split ',') -contains "$($f.Port)")) -or
                ($_.Programme -eq 'Any' -and $_.Protocole -in $f.Proto, 'Any' -and ($_.PortsLocaux -split ',') -contains "$($f.Port)") })
        [pscustomobject]@{
            Proto = $f.Proto; Port = $f.Port; Portee = ($scopes -join ' + '); ToutesInterfaces = [bool]($scopes -contains 'toutes les interfaces')
            Processus = if ($f.Pid -eq 4) { 'System' } elseif ($pr) { $pr.Name } else { "PID $($f.Pid)" }; Pid = $f.Pid
            Services = ($svcByPid[$f.Pid] -join ', '); Chemin = $path; Windows = [bool]$isWin
            Signature = if ($f.Pid -eq 4) { 'noyau Windows' } else { Get-NgSignature $path }
            PareFeuAutorise = [bool]$allowed.Count
            ProfilsAutorises = (@($allowed | ForEach-Object { $_.Profils }) | Select-Object -Unique) -join ','
        } } | Sort-Object Proto, Port)
$exposed = @($ports | Where-Object { $_.ToutesInterfaces -and -not $_.Windows })
$exposedFw = @($exposed | Where-Object PareFeuAutorise)
Show ("  {0} ports en écoute ({1} TCP, {2} UDP) ; {3} hors Windows sur toutes les interfaces, dont {4} autorisés par une règle entrante" -f $ports.Count, @($ports | Where-Object Proto -eq 'TCP').Count, @($ports | Where-Object Proto -eq 'UDP').Count, $exposed.Count, $exposedFw.Count)
foreach ($e in ($exposedFw | Sort-Object Processus -Unique)) {
    Show ("    {0} {1} {2} - signature : {3} - profils : {4}" -f $e.Proto, $e.Port, $e.Processus, $e.Signature, $e.ProfilsAutorises)
}
foreach ($e in ($ports | Where-Object { $_.Proto -eq 'TCP' -and $_.ToutesInterfaces -and $_.Port -in 445, 139, 3389, 5985, 5986, 22, 21, 23, 5900 })) {
    Add-Constat 'info' 'B. Sécurité' ("Port sensible en écoute sur toutes les interfaces : TCP {0} ({1}). Le pare-feu doit le bloquer depuis Internet ; vérifié en section pare-feu." -f $e.Port, $(if ($e.Services) { $e.Services } else { $e.Processus }))
}
foreach ($e in ($exposedFw | Where-Object { $_.Signature -notlike 'valide*' })) {
    Add-Constat 'attention' 'B. Sécurité' ("{0} écoute sur {1} {2}, autorisé par le pare-feu, signature : {3}." -f $e.Processus, $e.Proto, $e.Port, $e.Signature)
}

# Accès à distance en écoute (même s'ils viennent de Windows) : joignables depuis le réseau si le pare-feu les autorise
foreach ($e in ($ports | Where-Object { $_.Proto -eq 'TCP' -and $_.ToutesInterfaces -and ($_.Processus -match '(?i)^(sshd|vncserver|tvnserver|winvnc|AnyDesk|TeamViewer)' -or $_.Port -in 22, 3389, 5900, 5985, 5986) })) {
    $prof = if ($e.PareFeuAutorise) { "autorisé par le pare-feu (profil $($e.ProfilsAutorises))" } else { 'sans règle entrante autorisée trouvée' }
    Add-Constat 'attention' 'B. Sécurité' ("Serveur d'accès à distance en écoute : {0} sur TCP {1}, {2}. Si tu ne t'en sers pas, l'arrêter ; sinon, authentification par clé uniquement." -f $e.Processus, $e.Port, $prof)
}
$scanners = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Running' -and $_.DisplayName -match '(?i)Lansweeper|Network Discovery Hub|Advanced IP Scanner|Angry IP|PRTG|Nessus|Spiceworks|Fing' })
if ($scanners.Count) { Add-Constat 'attention' 'B. Sécurité' ("Logiciel de découverte / inventaire réseau actif ({0}) : il BALAIE le réseau local en permanence. Normal sur un PC d'entreprise ; sur un PC perso, à désinstaller si tu ne l'as pas installé volontairement." -f (($scanners | ForEach-Object { $_.DisplayName }) -join ', ')) }

Step 'B3. Connexions sortantes établies : signature et chemin'
$userPathRx = '(?i)\\AppData\\|\\Temp\\|\\Downloads\\|\\T[ée]l[ée]chargements\\'
$sortantes = @($estab | Group-Object OwningProcess | ForEach-Object {
        $procId = [int]$_.Name; $pr = $procs[$procId]; $path = Get-NgProcPath $procId
        $sig = Get-NgSignature $path
        $unusual = if ($path -match '(?i)\\Temp\\|\\Downloads\\|\\T[ée]l[ée]chargements\\') { 'Temp / Téléchargements' } elseif ($path -match '(?i)\\AppData\\') { 'AppData (courant : Discord, Spotify, Teams...)' } else { '' }
        [pscustomobject]@{
            Processus = if ($pr) { $pr.Name } else { "PID $procId" }; Pid = $procId; Connexions = $_.Count
            Distants = (@($_.Group | ForEach-Object { "$($_.RemoteAddress):$($_.RemotePort)" } | Select-Object -Unique -First 5) -join ' ')
            Chemin = $path; Signature = $sig; CheminInhabituel = $unusual
        } } | Sort-Object Connexions -Descending)
$suspects = @($sortantes | Where-Object { $_.Chemin -match $userPathRx -and $_.Signature -notlike 'valide*' })
Show ("  {0} processus avec connexions établies ; {1} depuis un dossier utilisateur ; {2} depuis un dossier utilisateur ET non signés" -f $sortantes.Count, @($sortantes | Where-Object CheminInhabituel).Count, $suspects.Count)
foreach ($s in $suspects) { Show ("    ! {0} ({1}) - {2}" -f $s.Processus, $s.Signature, $s.CheminInhabituel); Add-Constat 'attention' 'B. Sécurité' ("Connexion sortante d'un exécutable non signé dans {0} : {1}. Vérifier ce programme (VirusTotal à la main, analyse Defender)." -f $s.CheminInhabituel, $s.Processus) }

Step 'B4. Defender, BitLocker, Secure Boot, TPM, SMB, RDP, WinRM, partages, découverte, NetBIOS/LLMNR'
$def = $null
try { $def = Get-MpComputerStatus -ErrorAction Stop } catch { }
$avs = @(Get-CimInstance -Namespace root\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | ForEach-Object { $_.displayName })
$smbS = $null; $smbC = $null
try { $smbS = Get-SmbServerConfiguration -ErrorAction Stop } catch { }
try { $smbC = Get-SmbClientConfiguration -ErrorAction Stop } catch { }
$tpmDev = @(Get-CimInstance Win32_PnPEntity -Filter "PNPClass='SecurityDevices'" -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'TPM|plateforme' })
$nbt = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Carte = $_.Description; NetBios = @{ 0 = 'défaut (via DHCP)'; 1 = 'activé'; 2 = 'désactivé' }[[int]$_.TcpipNetbiosOptions] } })
$shares = @(Get-CimInstance Win32_Share -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Nom = $_.Name; Chemin = $_.Path; Administratif = ($_.Type -ge 2147483648); Description = $_.Description } })
$curCat = ($netProfiles | Select-Object -First 1).Categorie
$discRules = @($ruleInfo | Where-Object { $_.Groupe -match 'Découverte du réseau|Network Discovery' })
$fileRules = @($ruleInfo | Where-Object { $_.Groupe -match 'Partage de fichiers et d.imprimantes|File and Printer Sharing' })
$fdRes = Get-Service FDResPub -ErrorAction SilentlyContinue
$winrm = Get-Service WinRM -ErrorAction SilentlyContinue
$rdpDeny = Get-NgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections'
$rdpNla = Get-NgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication'
$securite = [ordered]@{
    Defender = if ($def) { [ordered]@{ Service = $def.AMServiceEnabled; Antivirus = $def.AntivirusEnabled; TempsReel = $def.RealTimeProtectionEnabled
            Mode = "$($def.AMRunningMode)"; Signatures = $def.AntivirusSignatureLastUpdated; AgeSignaturesJours = $def.AntivirusSignatureAge
            ProtectionFalsification = $def.IsTamperProtected; DerniereAnalyseRapide = $def.QuickScanEndTime } } else { 'illisible' }
    AntivirusDeclares = $avs
    BitLockerC = Get-NgBitLockerStatus 'C:'
    SecureBoot = switch (Get-NgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' 'UEFISecureBootEnabled') { 1 { 'activé' } 0 { 'désactivé' } default { 'inconnu (BIOS hérité ?)' } }
    Tpm = if ($tpmDev) { ($tpmDev | Select-Object -First 1).Name } else { 'non détecté' }
    Smb = [ordered]@{
        Smb1Serveur = if ($smbS) { $smbS.EnableSMB1Protocol } else { $null }
        Smb1ClientInstalle = [bool](Get-Service mrxsmb10 -ErrorAction SilentlyContinue)
        SignatureServeurExigee = if ($smbS) { $smbS.RequireSecuritySignature } else { $null }
        SignatureClientExigee = if ($smbC) { $smbC.RequireSecuritySignature } else { $null }
        ServeurEnCours = "$((Get-Service LanmanServer -ErrorAction SilentlyContinue).Status)"
    }
    Rdp = [ordered]@{ Active = ($rdpDeny -eq 0); Nla = ($rdpNla -eq 1); Service = "$((Get-Service TermService -ErrorAction SilentlyContinue).Status)" }
    WinRM = [ordered]@{ Etat = "$($winrm.Status)"; Demarrage = "$($winrm.StartType)" }
    Partages = $shares
    Decouverte = [ordered]@{ ProfilActuel = $curCat; ReglesActives = $discRules.Count; ReglesPartageFichiers = $fileRules.Count; PublicationService = "$($fdRes.Status)" }
    NetBios = $nbt
    Llmnr = if ((Get-NgRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' 'EnableMulticast') -eq 0) { 'désactivé (stratégie)' } else { 'activé (défaut)' }
    Mdns = if ((Get-NgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' 'EnableMDNS') -eq 0) { 'désactivé' } else { 'activé (défaut)' }
    Uac = [ordered]@{ Active = ((Get-NgRegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA') -ne 0)
        InviteAdmin = Get-NgRegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' }
    RegistreDistant = "$((Get-Service RemoteRegistry -ErrorAction SilentlyContinue).Status)"
}
if ($def) {
    Show ("  Defender : temps réel {0}, signatures du {1:dd/MM/yyyy HH:mm} ({2} j), protection contre la falsification {3}, mode {4}" -f $def.RealTimeProtectionEnabled, $def.AntivirusSignatureLastUpdated, $def.AntivirusSignatureAge, $def.IsTamperProtected, $def.AMRunningMode)
    if (-not $def.RealTimeProtectionEnabled -and $avs.Count -le 1) { Add-Constat 'critique' 'B. Sécurité' 'Protection en temps réel de Defender désactivée, sans autre antivirus déclaré.' }
    if ($def.AntivirusSignatureAge -gt 3) { Add-Constat 'attention' 'B. Sécurité' "Signatures Defender vieilles de $($def.AntivirusSignatureAge) jours." }
    if (-not $def.IsTamperProtected) { Add-Constat 'attention' 'B. Sécurité' 'Protection contre les falsifications de Defender désactivée (Sécurité Windows > Protection contre virus > Gérer les paramètres).' }
} else { Add-Constat 'attention' 'B. Sécurité' 'État de Defender illisible.' }
Show ("  BitLocker C: {0} ; Secure Boot {1} ; TPM : {2}" -f $securite.BitLockerC.Etat, $securite.SecureBoot, $securite.Tpm)
Show ("  SMB : SMBv1 serveur {0}, client SMBv1 installé {1}, signature exigée serveur {2} / client {3}" -f $securite.Smb.Smb1Serveur, $securite.Smb.Smb1ClientInstalle, $securite.Smb.SignatureServeurExigee, $securite.Smb.SignatureClientExigee)
Show ("  RDP actif {0} (NLA {1}) ; WinRM {2} ({3}) ; Registre à distance {4}" -f $securite.Rdp.Active, $securite.Rdp.Nla, $securite.WinRM.Etat, $securite.WinRM.Demarrage, $securite.RegistreDistant)
Show ("  Partages : {0} (dont {1} non administratifs) ; découverte réseau : {2} règle(s) active(s), profil {3}" -f $shares.Count, @($shares | Where-Object { -not $_.Administratif }).Count, $discRules.Count, $curCat)
Show ("  NetBIOS : {0} ; LLMNR : {1} ; mDNS : {2}" -f (($nbt | ForEach-Object { $_.NetBios }) -join ', '), $securite.Llmnr, $securite.Mdns)
if ($securite.Smb.Smb1Serveur -or $securite.Smb.Smb1ClientInstalle) { Add-Constat 'critique' 'B. Sécurité' 'SMBv1 présent : protocole obsolète (WannaCry). Désactivation recommandée par Microsoft.' }
if ($securite.Rdp.Active -and -not $securite.Rdp.Nla) { Add-Constat 'critique' 'B. Sécurité' 'Bureau à distance actif SANS authentification au niveau du réseau (NLA).' }
elseif ($securite.Rdp.Active) { Add-Constat 'attention' 'B. Sécurité' 'Bureau à distance actif : à couper si tu ne t''en sers pas.' }
if ($securite.BitLockerC.Code -eq 2) { Add-Constat 'info' 'B. Sécurité' 'BitLocker désactivé sur C: : en cas de vol du PC, les données sont lisibles. Utile surtout pour un portable.' }
if ($securite.SecureBoot -ne 'activé') { Add-Constat 'attention' 'B. Sécurité' "Secure Boot : $($securite.SecureBoot). Certains anti-triche (Vanguard pour Valorant, FACEIT) l'exigent sous Windows 11." }
if ($curCat -eq 'Private' -and $discRules.Count) { Add-Constat 'info' 'B. Sécurité' 'Réseau en profil Privé avec découverte du réseau active : normal à la maison, à passer en Public sur un réseau partagé (résidence, école).' }
if ($curCat -eq 'Public') { Show '  Profil réseau Public : découverte et partage bloqués par défaut (le plus sûr)' }
foreach ($sh in ($shares | Where-Object { -not $_.Administratif })) { Add-Constat 'info' 'B. Sécurité' "Dossier partagé sur le réseau : $($sh.Nom)." }

Step 'B5. Comptes locaux'
$users = @()
try { $users = @(Get-LocalUser -ErrorAction Stop) } catch { }
$admins = @()
try { $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Nom = $_.Name; Type = "$($_.ObjectClass)"; Source = "$($_.PrincipalSource)"; Sid = "$($_.SID)" } }) }
catch { Write-AuditLog "Get-LocalGroupMember : $($_.Exception.Message)" }
$comptes = [ordered]@{
    Utilisateurs = @($users | ForEach-Object { [pscustomobject]@{
                Nom = $_.Name; Active = $_.Enabled; MotDePasseRequis = $_.PasswordRequired; Expiration = if ($_.PasswordExpires) { $_.PasswordExpires.ToString('s') } else { 'jamais' }
                DernierChangement = if ($_.PasswordLastSet) { $_.PasswordLastSet.ToString('s') } else { $null }; Source = "$($_.PrincipalSource)"
                Sid = "$($_.SID)"; Rid = ("$($_.SID)" -split '-')[-1]; Admin = $false } })
    Administrateurs = $admins
}
# Membre du groupe Administrateurs (S-1-5-32-544) : comparaison par SID exact, indépendante de la langue
foreach ($u in $comptes.Utilisateurs) { $u.Admin = [bool](@($admins | Where-Object { $_.Sid -eq $u.Sid }).Count) }
$enabled = @($comptes.Utilisateurs | Where-Object Active)
Show ("  {0} comptes locaux ({1} actifs) ; {2} membre(s) du groupe Administrateurs" -f $comptes.Utilisateurs.Count, $enabled.Count, $admins.Count)
$guest = $comptes.Utilisateurs | Where-Object { $_.Rid -eq '501' }
if ($guest -and $guest.Active) { Add-Constat 'critique' 'B. Sécurité' 'Compte Invité ACTIVÉ.' }
$builtinAdmin = $comptes.Utilisateurs | Where-Object { $_.Rid -eq '500' }
if ($builtinAdmin -and $builtinAdmin.Active) { Add-Constat 'attention' 'B. Sécurité' 'Compte Administrateur intégré activé (désactivé par défaut).' }
foreach ($u in ($enabled | Where-Object { -not $_.MotDePasseRequis })) {
    Add-Constat 'attention' 'B. Sécurité' ("Compte local actif « {0} »{1} avec l'indicateur « mot de passe non requis » : il PEUT avoir un mot de passe vide. Indicateur fréquent sur les comptes créés à l'installation, impossible à confirmer sans tenter une connexion (ce que l'audit ne fait pas) : si tu ouvres ta session avec un mot de passe, c'est sans objet ; sinon c'est CRITIQUE." -f $u.Nom, $(if ($u.Admin) { ' ADMINISTRATEUR' }))
}
foreach ($u in ($enabled | Where-Object { $_.Expiration -eq 'jamais' -and $_.Source -eq 'Local' })) { Write-AuditLog "Mot de passe sans expiration : $($u.Nom) (normal pour un PC perso, recommandation actuelle du NIST)" }
if (-not $securite.Uac.Active) { Add-Constat 'critique' 'B. Sécurité' 'Contrôle de compte d''utilisateur (UAC) désactivé.' }

Step 'B6. Fichier hosts, proxy, DNS configurés, table ARP'
$hostsPath = "$env:windir\System32\drivers\etc\hosts"
$hostsEntries = @(Get-Content -LiteralPath $hostsPath -ErrorAction SilentlyContinue | ForEach-Object { $_.Trim() } | Where-Object { $_ -and $_ -notmatch '^#' })
$ie = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$winHttp = Get-NgRegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' 'WinHttpSettings'
# WinHttpSettings (binaire) : octets 8-11 = indicateurs, 12-15 = longueur du nom du proxy. Longueur 0 = accès direct.
$winHttpProxy = if ($winHttp -and $winHttp.Length -ge 16) { [BitConverter]::ToInt32($winHttp, 12) -gt 0 } else { $false }
$neigh = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
        $_.State -in 'Reachable', 'Stale', 'Delay', 'Probe', 'Permanent' -and $_.LinkLayerAddress -and
        $_.LinkLayerAddress -notmatch '^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF|01-00-5E)' -and $_.IPAddress -notmatch '^(22[4-9]|23\d|255)\.' })
$dupMacs = @($neigh | Group-Object LinkLayerAddress | Where-Object { @($_.Group.IPAddress | Select-Object -Unique).Count -gt 1 } | ForEach-Object {
        [pscustomobject]@{ Mac = $_.Name; Ips = @($_.Group.IPAddress | Select-Object -Unique); ContientPasserelle = (@($_.Group.IPAddress) -contains $gateway) } })
$doh = @()
try { $doh = @(Get-DnsClientDohServerAddress -ErrorAction Stop | Where-Object { $dnsCurrent -contains $_.ServerAddress } | ForEach-Object { $_.ServerAddress }) } catch { }
$reseauSecu = [ordered]@{
    Hosts = $hostsEntries
    Proxy = [ordered]@{ Utilisateur = ((Get-NgRegValue $ie 'ProxyEnable') -eq 1); Serveur = Get-NgRegValue $ie 'ProxyServer'; ScriptAuto = Get-NgRegValue $ie 'AutoConfigURL'; WinHttp = $winHttpProxy }
    DnsParCarte = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } | ForEach-Object { [pscustomobject]@{ Carte = $_.InterfaceAlias; Serveurs = @($_.ServerAddresses) } })
    DnsChiffre = $doh
    Arp = [ordered]@{ Entrees = $neigh.Count; MacEnDouble = $dupMacs }
}
Show ("  hosts : {0} entrée(s) active(s) ; proxy utilisateur {1}, script auto {2}, proxy WinHTTP {3}" -f $hostsEntries.Count, $reseauSecu.Proxy.Utilisateur, [bool]$reseauSecu.Proxy.ScriptAuto, $winHttpProxy)
Show ("  ARP : {0} voisin(s) en cache, {1} adresse(s) MAC en double" -f $neigh.Count, $dupMacs.Count)
$oddHosts = @($hostsEntries | Where-Object { $_ -notmatch '^(127\.0\.0\.1|::1|0\.0\.0\.0)\s' })
$wildHosts = @($hostsEntries | Where-Object { ($_ -split '\s+')[1] -match '^\*' })
$reseauSecu.HostsRedirections = [ordered]@{ Lignes = $oddHosts.Count; IpCibles = @($oddHosts | ForEach-Object { ($_ -split '\s+')[0] } | Select-Object -Unique); LignesAvecJoker = $wildHosts.Count; ModifieLe = (Get-Item -LiteralPath $hostsPath).LastWriteTime.ToString('s') }
if ($oddHosts.Count) { Add-Constat 'attention' 'B. Sécurité' ("Fichier hosts (modifié le {0:dd/MM/yyyy}) : {1} ligne(s) redirigent des noms vers une IP EXTERNE ({2}) au lieu de les bloquer (0.0.0.0). Toute visite de ces noms va vers ce serveur. {3} ligne(s) avec joker (*.) sont ignorées par Windows. Vérifier d'où vient cette liste ; correctif manuel (admin)." -f (Get-Item -LiteralPath $hostsPath).LastWriteTime, $oddHosts.Count, ($reseauSecu.HostsRedirections.IpCibles -join ', '), $wildHosts.Count) }
if ($reseauSecu.Proxy.Utilisateur -or $reseauSecu.Proxy.ScriptAuto -or $winHttpProxy) { Add-Constat 'attention' 'B. Sécurité' 'Un proxy système est configuré : vérifier que tu l''as mis toi-même (un logiciel malveillant peut détourner le trafic ainsi).' }
foreach ($d in ($dupMacs | Where-Object ContientPasserelle)) { Add-Constat 'critique' 'B. Sécurité' "La MAC de la passerelle répond aussi pour d'autres IP ($($d.Ips -join ', ')) : signe possible d'usurpation ARP. Vérifier (peut aussi être un répéteur / un mode bridge)." }

Step 'B7. Profils Wi-Fi enregistrés'
$wifiProfils = $null
if ($wlan) {
    $wifiProfils = [ordered]@{ Total = ($wlan | Measure-Object ProfilsTotal -Sum).Sum; Ouverts = ($wlan | Measure-Object ProfilsOuverts -Sum).Sum; Wep = ($wlan | Measure-Object ProfilsWep -Sum).Sum }
    Show ("  {0} profil(s) : {1} ouvert(s), {2} en WEP (SSID non affichés)" -f $wifiProfils.Total, $wifiProfils.Ouverts, $wifiProfils.Wep)
    if ($wifiProfils.Ouverts -or $wifiProfils.Wep) { Add-Constat 'attention' 'B. Sécurité' ("{0} profil(s) Wi-Fi ouvert(s) et {1} en WEP enregistrés : le PC peut s'y reconnecter seul (risque de faux point d'accès)." -f $wifiProfils.Ouverts, $wifiProfils.Wep) }
} else { Show '  Pas de carte Wi-Fi (ou service WLAN arrêté) : sans objet' }

$wingetList = $null
if (-not $SkipWinget -and (Get-Command winget -ErrorAction SilentlyContinue)) {
    Step 'B8. Applications à mettre à jour (winget upgrade : LISTE seulement, rien n''est installé)'
    # Lancé dans un job avec délai maximal : winget peut attendre le réseau. --source winget évite l'accord du Store.
    $job = Start-Job { [Console]::OutputEncoding = [Text.Encoding]::UTF8; winget upgrade --source winget --disable-interactivity 2>$null }
    if (Wait-Job $job -Timeout 120) {
        $raw = @(Receive-Job $job | ForEach-Object { "$_" } | Where-Object { $_.Trim() -and -not ($_.Trim().Length -lt 5 -and $_ -match '^[\s\-\\|/]+$') })   # retire l'animation de winget, PAS la ligne de tirets
        # Le tableau commence après la ligne de tirets ; on garde les lignes brutes (pas d'analyse de colonnes)
        $hdr = -1; for ($i = 0; $i -lt $raw.Count; $i++) { if ($raw[$i] -match '^-{10,}') { $hdr = $i; break } }
        $rows = if ($hdr -ge 0) { @($raw[($hdr + 1)..($raw.Count - 1)] | Where-Object { $_ -notmatch '(?i)mise.*niveau.*disponible|upgrades? available|explicit|package.*version' }) } else { @() }
        $wingetList = [ordered]@{ Entete = if ($hdr -gt 0) { $raw[$hdr - 1] } else { $null }; Lignes = $rows }
        Show ("  {0} application(s) avec une mise à jour disponible (liste brute de winget dans le rapport)" -f $rows.Count)
        # Applis connues pour des failles exploitées dans les anciennes versions (liste courte, sources dans le README)
        foreach ($row in $rows) {
            if ($row -match 'RARLab\.WinRAR\s+(\d+\.\d+)' -and [version]$Matches[1] -lt [version]'7.13') { Add-Constat 'critique' 'B. Sécurité' "WinRAR $($Matches[1]) installé : failles exploitées par ouverture d'archive piégée (CVE-2023-38831 corrigée en 6.23, CVE-2025-8088 corrigée en 7.13). Mettre à jour : winget upgrade RARLab.WinRAR" }
        }
        if ($rows.Count -ge 10) { Add-Constat 'info' 'B. Sécurité' "$($rows.Count) applications ont une mise à jour en attente (winget) : les navigateurs, lanceurs de jeux et Discord en priorité." }
    } else { Show '  winget n''a pas répondu en 2 min : ignoré'; Stop-Job $job }
    Remove-Job $job -Force
} else { Step 'B8. winget : ignoré' }

# =====================================================================================
# C. JEU
# =====================================================================================
Step 'C1. Pilote NVIDIA et mémoire vive'
$nv = $gpus | Where-Object { $_.Name -match 'NVIDIA' } | Select-Object -First 1
$nvVer = $null
if ($nv) {
    # 32.0.16.2114 -> on garde les 5 derniers chiffres : 62114 -> 621.14 (numérotation NVIDIA)
    $digits = ($nv.DriverVersion -replace '\.', '')
    $nvVer = $digits.Substring($digits.Length - 5, 3) + '.' + $digits.Substring($digits.Length - 2)
}
$smi = "$env:windir\System32\nvidia-smi.exe"
$gpuLive = $null
if (Test-Path -LiteralPath $smi) {
    # Sortie CSV documentée de nvidia-smi (format machine, pas un texte à « deviner »)
    $q = & $smi --query-gpu=temperature.gpu,clocks.sm,clocks.max.sm,power.draw,pstate,utilization.gpu --format=csv,noheader,nounits 2>$null
    if ($q) { $gpuLive = $q | Select-Object -First 1 | ConvertFrom-Csv -Header TempC, FreqMHz, FreqMaxMHz, PuissanceW, Pstate, UtilisationPct }
}
$ram = @(Get-CimInstance Win32_PhysicalMemory)
$ramRated = @($ram | ForEach-Object { if ("$($_.PartNumber)" -match '(2133|2400|2666|2800|2933|3000|3200|3333|3466|3600|3733|3800|4000|4133|4266|4400|4800|5200|5600|6000|6200|6400|6800|7200|8000)') { [int]$Matches[1] } })
$ramType = @{ 26 = 'DDR4'; 34 = 'DDR5'; 24 = 'DDR3' }[[int]($ram | Select-Object -First 1).SMBIOSMemoryType]
$ramCfg = ($ram | Measure-Object -Property ConfiguredClockSpeed -Minimum).Minimum
$ramNominal = if ($ramRated) { ($ramRated | Measure-Object -Minimum).Minimum } else { ($ram | Measure-Object -Property Speed -Maximum).Maximum }
$jedecMax = if ($ramType -eq 'DDR5') { 4800 } else { 2666 }
$jeu = [ordered]@{
    Nvidia = if ($nv) { [ordered]@{ Carte = $nv.Name; VersionWindows = $nv.DriverVersion; Version = $nvVer; Date = $nv.DriverDate
            DerniereOfficielle = $NvidiaLatestVersion; AJour = if ($NvidiaLatestVersion) { [version]$nvVer -ge [version]$NvidiaLatestVersion } else { $null }
            Direct = $gpuLive } } else { $null }
    Ram = [ordered]@{
        Type = $ramType; Barrettes = $ram.Count; TotalGo = [math]::Round(($ram | Measure-Object Capacity -Sum).Sum / 1GB)
        FrequenceReelle = $ramCfg; FrequenceNominale = $ramNominal
        ProfilXmpExpo = if ($ramCfg -ge $ramNominal -and $ramCfg -gt $jedecMax) { 'actif' } elseif ($ramCfg -le $jedecMax -and $ramNominal -gt $jedecMax) { 'INACTIF (fréquence JEDEC)' } else { 'indéterminé' }
        References = @($ram | ForEach-Object { "$($_.Manufacturer) $($_.PartNumber.Trim())" } | Select-Object -Unique)
    }
}
if ($nv) { Show ("  {0} : pilote {1} du {2:dd/MM/yyyy}{3}" -f $nv.Name, $nvVer, $nv.DriverDate, $(if ($NvidiaLatestVersion) { " (dernier sur nvidia.com : $NvidiaLatestVersion)" } else { ' (comparer avec nvidia.com/fr-fr/drivers, sans rien télécharger)' })) }
if ($gpuLive) { Show ("  GPU maintenant : {0} °C, {1}/{2} MHz, {3} W, {4}, utilisation {5} %" -f $gpuLive.TempC, $gpuLive.FreqMHz, $gpuLive.FreqMaxMHz, $gpuLive.PuissanceW, $gpuLive.Pstate, $gpuLive.UtilisationPct) }
Show ("  RAM : {0} x {1}, {2} Go, {3} MT/s réels pour {4} nominaux -> XMP/EXPO {5}" -f $ram.Count, $ramType, $jeu.Ram.TotalGo, $ramCfg, $ramNominal, $jeu.Ram.ProfilXmpExpo)
if ($jeu.Ram.ProfilXmpExpo -like 'INACTIF*') { Add-Constat 'attention' 'C. Jeu' "RAM à $ramCfg MT/s au lieu de $ramNominal : profil XMP/EXPO à activer dans le BIOS (fiche manuelle). Gain réel en jeu sur Ryzen (la fréquence de l'Infinity Fabric suit la RAM)." }
if ($jeu.Ram.References.Count -gt 1) { Add-Constat 'info' 'C. Jeu' ("Barrettes de références différentes ({0}) : kits mélangés. Si le PC plante en jeu, tester la stabilité (MemTest86 / diagnostic mémoire Windows) avant d'accuser le réseau." -f ($jeu.Ram.References -join ' / ')) }
if ($NvidiaLatestVersion -and $jeu.Nvidia -and -not $jeu.Nvidia.AJour) { Add-Constat 'info' 'C. Jeu' "Pilote NVIDIA $nvVer, $NvidiaLatestVersion disponible sur nvidia.com (fiche manuelle)." }

Step 'C2. Réglages Windows liés au jeu'
$gb = 'HKCU:\Software\Microsoft\GameBar'
$dvr = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR'
$gcs = 'HKCU:\System\GameConfigStore'
$activeScheme = Get-NgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes' 'ActivePowerScheme'
$hags = Get-NgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers' 'HwSchMode'
$dxUser = "$(Get-NgRegValue 'HKCU:\Software\Microsoft\DirectX\UserGpuPreferences' 'DirectXUserGlobalSettings')"
$timer = Get-NgTimerResolution
$mouse = 'HKCU:\Control Panel\Mouse'
$reglagesJeu = [ordered]@{
    ModeJeu = if ((Get-NgRegValue $gb 'AutoGameModeEnabled') -eq 0) { 'désactivé' } else { 'activé (défaut)' }
    PlanAlimentation = [ordered]@{ Guid = $activeScheme; Nom = Get-NgPowerSchemeName $activeScheme; NomRegistre = Get-NgRegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\$activeScheme" 'FriendlyName' }
    Hags = switch ($hags) { 2 { 'activé' } 1 { 'désactivé' } default { 'valeur absente : choix par défaut du pilote' } }
    GameDvr = [ordered]@{
        CaptureAutorisee = if ((Get-NgRegValue $dvr 'AppCaptureEnabled') -eq 0) { 'non' } else { 'oui (défaut)' }
        EnregistrementArrierePlan = if ((Get-NgRegValue $dvr 'HistoricalCaptureEnabled') -eq 1) { 'oui' } else { 'non (défaut)' }
        GameDVR_Enabled = Get-NgRegValue $gcs 'GameDVR_Enabled'
        StrategieAllowGameDVR = Get-NgRegValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' 'AllowGameDVR'
    }
    OptimisationsPleinEcran = [ordered]@{ FSEBehaviorMode = Get-NgRegValue $gcs 'GameDVR_FSEBehaviorMode'; Note = 'valeur absente = optimisations plein écran actives (défaut Windows)' }
    OptimisationsFenetre = if ($dxUser -match 'SwapEffectUpgradeEnable=1') { 'activées' } elseif ($dxUser -match 'SwapEffectUpgradeEnable=0') { 'désactivées' } else { 'défaut Windows' }
    AccelerationSouris = [ordered]@{ Active = ((Get-NgRegValue $mouse 'MouseSpeed') -ne '0'); MouseSpeed = Get-NgRegValue $mouse 'MouseSpeed'; Seuil1 = Get-NgRegValue $mouse 'MouseThreshold1'; Seuil2 = Get-NgRegValue $mouse 'MouseThreshold2' }
    Timer = $timer
}
if ($reglagesJeu.PlanAlimentation.NomRegistre -and $reglagesJeu.PlanAlimentation.Nom -like 'Mode personnalisé*') { $reglagesJeu.PlanAlimentation.Nom = "$($reglagesJeu.PlanAlimentation.NomRegistre) (personnalisé)" }
if ($reglagesJeu.PlanAlimentation.Nom -match '(?i)booster|optimi[sz]er|gaming|turbo') { Add-Constat 'info' 'C. Jeu' "Plan d'alimentation créé par un logiciel tiers ($($reglagesJeu.PlanAlimentation.Nom)) : réglages inconnus, non documentés. Revenir à un plan Windows (Utilisation normale, ou Performances élevées en jeu)." }
Show ("  Mode Jeu {0} ; plan : {1} ; HAGS {2} ; optimisations fenêtrées {3}" -f $reglagesJeu.ModeJeu, $reglagesJeu.PlanAlimentation.Nom, $reglagesJeu.Hags, $reglagesJeu.OptimisationsFenetre)
Show ("  Capture Game Bar autorisée {0}, enregistrement en arrière-plan {1} ; accélération souris (« précision du pointeur ») {2}" -f $reglagesJeu.GameDvr.CaptureAutorisee, $reglagesJeu.GameDvr.EnregistrementArrierePlan, $reglagesJeu.AccelerationSouris.Active)
Show ("  Timer : actuel {0} ms (plus fin possible {1} ms, défaut {2} ms)" -f $timer.ActuelleMs, $timer.PlusFineMs, $timer.PlusGrossiereMs)
if ($reglagesJeu.GameDvr.EnregistrementArrierePlan -eq 'oui') { Add-Constat 'info' 'C. Jeu' 'Enregistrement en arrière-plan de la Game Bar actif : il encode la vidéo en continu pendant le jeu (coût GPU/disque réel, faible sur RTX grâce à NVENC).' }
if ($reglagesJeu.AccelerationSouris.Active) { Add-Constat 'info' 'C. Jeu' 'Accélération de la souris active : la distance parcourue dépend de la vitesse du geste, ce qui gêne la visée dans les FPS (confort, pas de FPS en plus).' }
if ($reglagesJeu.ModeJeu -eq 'désactivé') { Add-Constat 'info' 'C. Jeu' 'Mode Jeu désactivé.' }

Step 'C3. Sécurité basée sur la virtualisation (VBS / intégrité de la mémoire)'
$dg = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction SilentlyContinue
$svcNames = @{ 1 = 'Credential Guard'; 2 = 'Intégrité de la mémoire (HVCI)'; 3 = 'System Guard Secure Launch'; 4 = 'Mesure du firmware SMM'; 5 = 'Protection de la pile en mode noyau'; 7 = 'Hypervisor-Enforced Paging Translation' }
$vbs = [ordered]@{
    Etat = if ($dg) { @{ 0 = 'désactivée'; 1 = 'configurée mais pas en cours'; 2 = 'en cours' }[[int]$dg.VirtualizationBasedSecurityStatus] } else { 'illisible' }
    ServicesEnCours = if ($dg) { @($dg.SecurityServicesRunning | Where-Object { $_ } | ForEach-Object { $svcNames[[int]$_] }) } else { @() }
    HvciRegistre = Get-NgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' 'Enabled'
    ListeBlocagePilotes = if ((Get-NgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable') -eq 0) { 'DÉSACTIVÉE' } else { 'active (défaut)' }
}
Show ("  VBS {0} ; services : {1} ; liste de blocage des pilotes vulnérables : {2}" -f $vbs.Etat, ($vbs.ServicesEnCours -join ', '), $vbs.ListeBlocagePilotes)
if ($vbs.ListeBlocagePilotes -eq 'DÉSACTIVÉE') { Add-Constat 'critique' 'B. Sécurité' 'Liste de blocage des pilotes vulnérables DÉSACTIVÉE : à réactiver (Sécurité Windows > Sécurité de l''appareil > Isolation du noyau).' }

Step 'C4. Températures, fréquence CPU et processus actifs (au repos)'
$tz = @(Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Zone = $_.Name; TempC = [math]::Round($_.Temperature - 273.15, 1); Bridage = $_.PercentPassiveLimit } })
[void](Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -ErrorAction SilentlyContinue)
Start-Sleep -Seconds 2
$cores = [int]$cs.NumberOfLogicalProcessors
$cpuInfo = Get-CimInstance Win32_PerfFormattedData_Counters_ProcessorInformation -Filter "Name='_Total'" -ErrorAction SilentlyContinue
$top = @(Get-CimInstance Win32_PerfFormattedData_PerfProc_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin '_Total', 'Idle' } |
        Sort-Object PercentProcessorTime -Descending | Select-Object -First 10 | ForEach-Object {
            [pscustomobject]@{ Processus = $_.Name; CpuPct = [math]::Round($_.PercentProcessorTime / $cores, 1); RamMo = [math]::Round($_.WorkingSetPrivate / 1MB) } })
$thermique = [ordered]@{
    ZonesAcpi = $tz
    NoteZones = 'Zones ACPI de la carte mère : sur beaucoup de PC fixes, valeur figée et sans rapport avec le CPU. Pour la température réelle du CPU, utiliser le logiciel du fabricant.'
    Gpu = $gpuLive
    CpuPerfPct = if ($cpuInfo) { $cpuInfo.PercentProcessorPerformance } else { $null }
    CpuFreqMHz = if ($cpuInfo) { $cpuInfo.ProcessorFrequency } else { $null }
    CpuBridageLimitePct = if ($cpuInfo) { $cpuInfo.PercentPerformanceLimit } else { $null }
    TopProcessus = $top
}
foreach ($z in $tz) { Show ("  Zone ACPI {0} : {1} °C (bridage passif {2} %)" -f $z.Zone, $z.TempC, $z.Bridage) }
Show ("  CPU : {0} % de la performance nominale, limite {1} %" -f $thermique.CpuPerfPct, $thermique.CpuBridageLimitePct)
foreach ($t in ($top | Select-Object -First 5)) { Show ("    {0,-28} {1,5} % CPU  {2,6} Mo" -f $t.Processus, $t.CpuPct, $t.RamMo) }
if ($thermique.CpuBridageLimitePct -and $thermique.CpuBridageLimitePct -lt 100) { Add-Constat 'attention' 'C. Jeu' "Le CPU est bridé à $($thermique.CpuBridageLimitePct) % de sa performance (température ou alimentation)." }

# Commandes admin utiles (affichées, jamais lancées)
Add-AdminCmd 'État TPM détaillé' 'Get-Tpm'
Add-AdminCmd 'État BitLocker détaillé' 'Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod'
Add-AdminCmd 'Exclusions Defender (vérifier qu''il n''y en a pas d''inconnues)' 'Get-MpPreference | Select-Object ExclusionPath, ExclusionProcess, ExclusionExtension'
Add-AdminCmd 'Composant SMBv1 (installé ou non)' 'Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object FeatureName, State'
Add-AdminCmd 'Gestion d''alimentation de la carte réseau' "Get-NetAdapterPowerManagement -Name '$($adapter.Name)'"

# =====================================================================================
# ÉCRITURE (reports\ et baseline\ UNIQUEMENT)
# =====================================================================================
$audit = [ordered]@{
    Outil = 'netguard-gaming'; Version = 1; Date = (Get-Date).ToString('s'); Parametres = [ordered]@{ Passes = $Passes; IntervallePassesS = $PassIntervalSec; RequetesParCible = $PingCount; TestCharge = [bool]$LoadTest }
    Contexte = $contexte
    Reseau = [ordered]@{ Lien = $lien; Latence = $latence; Dns = $dnsBench; Mtu = $mtu; ProprietesCarte = $advanced; AlimentationCarte = $alimCarte
        TraficRepos = $traficRepos; Consommateurs = $consommateurs; DeliveryOptimization = $deliveryOpt; OneDrive = $oneDrive; Bufferbloat = $bufferbloat }
    Securite = [ordered]@{ PareFeu = $pareFeu; ReglesEntrantes = $ruleInfo; PortsEcoute = $ports; Sortantes = $sortantes; Systeme = $securite; Comptes = $comptes; Reseau = $reseauSecu; WiFi = $wifiProfils; Winget = $wingetList }
    Jeu = [ordered]@{ Materiel = $jeu; Reglages = $reglagesJeu; Vbs = $vbs; Thermique = $thermique }
    Constats = $constats; CommandesAdmin = $adminCmds
}
# Baseline : ce que Verify.ps1 recompare (mesures réseau + états clés)
$baseline = [ordered]@{
    Date = $audit.Date; Build = $contexte.Build; Connexion = $contexte.Connexion; Vitesse = $lien.Vitesse; Parametres = $audit.Parametres
    Latence = $latence; Dns = $dnsBench; MtuChemin = $mtu.Chemin.MtuChemin; Bufferbloat = $bufferbloat; TraficRepos = $traficRepos
    Etats = [ordered]@{ DnsActuel = @($dnsCurrent); ModeJeu = $reglagesJeu.ModeJeu; Plan = $reglagesJeu.PlanAlimentation.Nom; Dvr = $reglagesJeu.GameDvr; Souris = $reglagesJeu.AccelerationSouris.Active
        Smb1 = $securite.Smb; Llmnr = $securite.Llmnr; NetBios = @($nbt | ForEach-Object { $_.NetBios }); DeliveryOptimization = $deliveryOpt.ModeEffectif
        PortsExposesAutorises = $exposedFw.Count; ReglesLarges = $pareFeu.ReglesLarges.Count; Critiques = @($constats | Where-Object Niveau -eq 'critique').Count }
}

$rDir = if ($ReportsDir) { $ReportsDir } else { Get-NgPath 'reports' }
$bDir = if ($BaselineDir) { $BaselineDir } else { Get-NgPath 'baseline' }
$outDir = Join-Path $rDir "audit_$stamp"
$auditFile = Join-Path $outDir 'audit.json'
$baseFile = Join-Path $bDir "baseline_$stamp.json"
if ($PSCmdlet.ShouldProcess($outDir, 'Écrire audit.json et audit.log')) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    $audit | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $auditFile -Encoding UTF8
    $logLines | Set-Content -LiteralPath (Join-Path $outDir 'audit.log') -Encoding UTF8
}
if ($PSCmdlet.ShouldProcess($baseFile, 'Écrire la baseline')) {
    New-Item -ItemType Directory -Force -Path $bDir | Out-Null
    $baseline | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $baseFile -Encoding UTF8
}

Write-Host "`nConstats ($($constats.Count)) :" -ForegroundColor Green
foreach ($n in 'critique', 'attention', 'info') {
    foreach ($c in ($constats | Where-Object Niveau -eq $n)) {
        $col = @{ critique = 'Red'; attention = 'Yellow'; info = 'Gray' }[$n]
        Write-Host ("  [{0}] {1} - {2}" -f $n.ToUpper(), $c.Section, $c.Texte) -ForegroundColor $col
    }
}
Write-Host "`nAudit : $auditFile`nBaseline : $baseFile" -ForegroundColor Green
