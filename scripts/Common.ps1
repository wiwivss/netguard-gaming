<#
.SYNOPSIS
    Fonctions partagées par les scripts netguard-gaming.
.DESCRIPTION
    À charger avec : . (Join-Path $PSScriptRoot 'Common.ps1')
    Sections 1 à 3 : lecture seule (registre, CIM, cmdlets réseau) et mesures (ping, DNS,
    connexion TCP) limitées à 20 requêtes par cible.
    Section 4 (JOURNAL ET GARDE-FOUS) : les SEULES fonctions qui modifient le système.
    Chacune écrit le journal AVANT le changement, respecte -WhatIf, et refuse les cibles
    interdites (HKLM, Defender, pare-feu Windows, mises à jour, VBS/HVCI, services protégés).
#>

# Sous -WhatIf, le chargement automatique de CimCmdlets affiche des lignes « Définir l'alias »
# (Set-Alias hérite de -WhatIf). On le charge une fois, sans -WhatIf (piège déjà vu dans win-tune).
& { $WhatIfPreference = $false; Import-Module CimCmdlets -ErrorAction SilentlyContinue }

$script:NgRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$script:NgMaxProbesPerTarget = 20   # RÈGLE 2 : jamais plus de 20 requêtes par cible et par série
# RÈGLE 8 : seuils de conclusion (Verify.ps1 et rapport). En dessous : « aucun gain mesurable ».
$script:NgSeuilLatenceMs = 5     # écart de latence médiane
$script:NgSeuilPertePts = 2      # écart de perte, en points de pourcentage
$script:NgSeuilDnsMs = 5         # écart de médiane DNS

function Get-NgPath { param([Parameter(Mandatory)][string]$Child) Join-Path $script:NgRoot $Child }

function Get-NgMedian {
    # Médiane d'une liste de nombres ($null si vide)
    param([double[]]$Values)
    if (-not $Values -or $Values.Count -eq 0) { return $null }
    $s = $Values | Sort-Object
    $n = $s.Count
    if ($n % 2) { return [double]$s[($n - 1) / 2] }
    return ([double]$s[$n / 2 - 1] + [double]$s[$n / 2]) / 2
}

function Get-NgPercentile {
    # Percentile par rang (p95 = valeur sous laquelle sont 95 % des mesures)
    param([double[]]$Values, [double]$P = 95)
    if (-not $Values -or $Values.Count -eq 0) { return $null }
    $s = @($Values | Sort-Object)
    $i = [math]::Ceiling($P / 100 * $s.Count) - 1
    [double]$s[[math]::Max(0, [math]::Min($i, $s.Count - 1))]
}

function Get-NgJitter {
    <#
        Gigue (jitter) : moyenne des écarts ABSOLUS entre mesures successives (méthode RFC 3550, simplifiée).
        Windows PowerShell 5.1 n'a pas de mesure de gigue native : on la calcule.
    #>
    param([double[]]$Values)
    if (-not $Values -or $Values.Count -lt 2) { return $null }
    $sum = 0.0
    for ($i = 1; $i -lt $Values.Count; $i++) { $sum += [math]::Abs($Values[$i] - $Values[$i - 1]) }
    [math]::Round($sum / ($Values.Count - 1), 2)
}

function Test-NgAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-NgConfig {
    <#
        Lit config\<Name>.json. Si config\<Name>.local.json existe (ignoré par Git),
        ses listes sont AJOUTÉES à celles de la config publique (ex. tes vrais serveurs de jeu).
    #>
    param([Parameter(Mandatory)][string]$Name)
    $path = Join-Path (Get-NgPath 'config') "$Name.json"
    $cfg = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
    $local = Join-Path (Get-NgPath 'config') "$Name.local.json"
    if (Test-Path -LiteralPath $local) {
        $l = Get-Content -LiteralPath $local -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($p in $l.PSObject.Properties) {
            if ($cfg.PSObject.Properties[$p.Name] -and $cfg.($p.Name) -is [array]) {
                $cfg.($p.Name) = @($cfg.($p.Name)) + @($p.Value)
            } else {
                $cfg | Add-Member -NotePropertyName $p.Name -NotePropertyValue $p.Value -Force
            }
        }
    }
    $cfg
}

function Get-NgRegValue {
    <#
        Lit une valeur de registre ; $null si la clé ou la valeur n'existe pas.
        Ne PAS nommer une fonction 'R' : c'est un alias intégré d'Invoke-History.
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    try { (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name } catch { $null }
}

function Read-NgJsonArray {
    <#
        Lit un fichier JSON contenant un tableau et renvoie VRAIMENT un tableau.
        Piège PS 5.1 : « Get-Content | ConvertFrom-Json » émet le tableau comme UN SEUL objet.
        ForEach-Object le déroule.
    #>
    param([Parameter(Mandatory)][string]$Path)
    @(Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json | ForEach-Object { $_ })
}

function Test-NgProtectedService {
    # Vrai si le service est dans config\protected_services.json (nom exact ou motif *)
    param([Parameter(Mandatory)][string]$Name)
    $cfg = Get-NgConfig 'protected_services'
    foreach ($s in @($cfg.services)) { if ($Name -ieq $s.name) { return $true } }
    foreach ($p in @($cfg.patterns)) { if ($Name -ilike $p) { return $true } }
    return $false
}

# =====================================================================================
# MESURES RÉSEAU (lecture seule, bornées à 20 requêtes par cible)
# =====================================================================================

function Get-NgSeriesStats {
    # Statistiques d'une série de mesures (ms) : médiane, p95, pire cas, gigue, perte
    param([double[]]$Rtts, [int]$Sent)
    $ok = @($Rtts).Count
    $o = [ordered]@{
        Envoyes   = $Sent
        Recus     = $ok
        PertePct  = if ($Sent) { [math]::Round(100 * ($Sent - $ok) / $Sent, 1) } else { $null }
        MedianeMs = $null; MoyenneMs = $null; MinMs = $null; P95Ms = $null; MaxMs = $null; JitterMs = $null
        Mesures   = @($Rtts)
    }
    if ($ok) {
        $m = $Rtts | Measure-Object -Average -Minimum -Maximum
        $o.MedianeMs = [math]::Round((Get-NgMedian $Rtts), 1)
        $o.MoyenneMs = [math]::Round($m.Average, 1)
        $o.MinMs = $m.Minimum; $o.MaxMs = $m.Maximum
        $o.P95Ms = Get-NgPercentile $Rtts 95
        $o.JitterMs = Get-NgJitter $Rtts
    }
    [pscustomobject]$o
}

function Measure-NgPing {
    <#
        Série de pings ICMP (classe .NET System.Net.NetworkInformation.Ping : objets, pas de texte à analyser).
        Count est plafonné à 20 (règle 2) ; une requête toutes les IntervalMs : pas de flood.
        Note : RoundtripTime est un entier en ms (une passerelle à 0,3 ms apparaît « 0 »).
    #>
    param([Parameter(Mandatory)][string]$Target, [int]$Count = 20, [int]$IntervalMs = 200, [int]$TimeoutMs = 1000)
    $Count = [math]::Min($Count, $script:NgMaxProbesPerTarget)
    $p = New-Object System.Net.NetworkInformation.Ping
    $rtts = New-Object System.Collections.Generic.List[double]
    try {
        for ($i = 0; $i -lt $Count; $i++) {
            try {
                $r = $p.Send($Target, $TimeoutMs)
                if ($r.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) { $rtts.Add([double]$r.RoundtripTime) }
            } catch { }   # hôte introuvable / réseau absent : compté comme perdu
            if ($i -lt $Count - 1) { Start-Sleep -Milliseconds $IntervalMs }
        }
    } finally { $p.Dispose() }
    Get-NgSeriesStats -Rtts $rtts.ToArray() -Sent $Count
}

function Measure-NgTcpConnect {
    <#
        Durée d'ouverture d'une connexion TCP (poignée de main SYN / SYN-ACK) vers UN port d'UN hôte.
        Sert pour les hôtes qui filtrent le ping. Ce n'est pas un balayage : un seul port, au plus 20 fois.
        Le nom est résolu UNE fois avant la série (le temps DNS n'est pas compté).
    #>
    param([Parameter(Mandatory)][string]$Target, [int]$Port = 443, [int]$Count = 10, [int]$IntervalMs = 300, [int]$TimeoutMs = 1500)
    $Count = [math]::Min($Count, $script:NgMaxProbesPerTarget)
    $ip = $null
    try { $ip = ([System.Net.Dns]::GetHostAddresses($Target) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1) } catch { }
    $rtts = New-Object System.Collections.Generic.List[double]
    for ($i = 0; $i -lt $Count; $i++) {
        if ($ip) {
            $c = New-Object System.Net.Sockets.TcpClient
            try {
                $sw = [Diagnostics.Stopwatch]::StartNew()
                $ar = $c.BeginConnect($ip, $Port, $null, $null)
                if ($ar.AsyncWaitHandle.WaitOne($TimeoutMs) -and $c.Connected) {
                    $sw.Stop(); $c.EndConnect($ar)
                    $rtts.Add([math]::Round($sw.Elapsed.TotalMilliseconds, 1))
                }
            } catch { } finally { $c.Close() }
        }
        if ($i -lt $Count - 1) { Start-Sleep -Milliseconds $IntervalMs }
    }
    Get-NgSeriesStats -Rtts $rtts.ToArray() -Sent $Count
}

function Measure-NgDnsQuery {
    <#
        Temps de réponse d'UN serveur DNS à UNE requête de type A.
        -DnsOnly -NoHostsFile + -Server : la requête part directement au serveur, sans le fichier hosts
        ni le cache du client DNS de Windows. Une réponse « nom inexistant » (NXDOMAIN, attendue pour les
        sous-domaines aléatoires) est une VRAIE réponse : elle est chronométrée comme un succès.
    #>
    param([Parameter(Mandatory)][string]$Server, [Parameter(Mandatory)][string]$Name)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $ok = $true
    try { [void](Resolve-DnsName -Name $Name -Server $Server -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop) }
    catch { if ($_.FullyQualifiedErrorId -notmatch 'RCODE_NAME_ERROR') { $ok = $false } }
    $sw.Stop()
    [pscustomobject]@{ Ok = $ok; Ms = [math]::Round($sw.Elapsed.TotalMilliseconds, 1) }
}

function New-NgRandomLabel {
    # Étiquette aléatoire (sous-domaine inexistant, donc jamais en cache)
    $chars = 'abcdefghijklmnopqrstuvwxyz0123456789'.ToCharArray()
    'ng' + (-join (1..10 | ForEach-Object { $chars[(Get-Random -Maximum $chars.Count)] }))
}

function Test-NgPathMtu {
    <#
        MTU effectif vers une cible, SANS rien changer : pings avec le bit « ne pas fragmenter » (DF),
        recherche dichotomique de la plus grande charge utile qui passe. MTU = charge + 28 (en-têtes IPv4 20 + ICMP 8).
        Environ 9 pings au total. Si la cible ne répond pas du tout au ping, résultat $null.
    #>
    param([string]$Target = '1.1.1.1', [int]$Low = 1200, [int]$High = 1472)
    $p = New-Object System.Net.NetworkInformation.Ping
    $opt = New-Object System.Net.NetworkInformation.PingOptions(64, $true)   # TTL 64, DontFragment
    $send = {
        param($size)
        try { ($p.Send($Target, 1000, (New-Object byte[] $size), $opt)).Status -eq 'Success' } catch { $false }
    }
    try {
        if (-not (& $send $Low)) { return [pscustomobject]@{ Cible = $Target; ChargeMax = $null; MtuChemin = $null; Note = "Aucune réponse avec DF à $Low octets (cible filtrée ou MTU très bas)" } }
        if (& $send $High) { return [pscustomobject]@{ Cible = $Target; ChargeMax = $High; MtuChemin = $High + 28; Note = 'MTU Ethernet standard (1500) sans fragmentation' } }
        $lo = $Low; $hi = $High
        while ($hi - $lo -gt 1) {
            $mid = [int](($lo + $hi) / 2)
            if (& $send $mid) { $lo = $mid } else { $hi = $mid }
        }
        [pscustomobject]@{ Cible = $Target; ChargeMax = $lo; MtuChemin = $lo + 28; Note = 'Chemin avec MTU réduit (PPPoE, tunnel, VPN...)' }
    } finally { $p.Dispose() }
}

# =====================================================================================
# API WINDOWS EN LECTURE SEULE (résolution du timer, Wi-Fi)
# =====================================================================================
if (-not ('NetGuard.Native' -as [type])) {
    Add-Type -Namespace NetGuard -Name Native -MemberDefinition @'
[DllImport("ntdll.dll")] public static extern int NtQueryTimerResolution(out uint MinimumResolution, out uint MaximumResolution, out uint CurrentResolution);
[DllImport("wlanapi.dll")] public static extern uint WlanOpenHandle(uint dwClientVersion, IntPtr pReserved, out uint pdwNegotiatedVersion, out IntPtr phClientHandle);
[DllImport("wlanapi.dll")] public static extern uint WlanCloseHandle(IntPtr hClientHandle, IntPtr pReserved);
[DllImport("wlanapi.dll")] public static extern uint WlanEnumInterfaces(IntPtr hClientHandle, IntPtr pReserved, out IntPtr ppInterfaceList);
[DllImport("wlanapi.dll")] public static extern uint WlanGetProfileList(IntPtr hClientHandle, ref Guid pInterfaceGuid, IntPtr pReserved, out IntPtr ppProfileList);
[DllImport("wlanapi.dll", CharSet = CharSet.Unicode)] public static extern uint WlanGetProfile(IntPtr hClientHandle, ref Guid pInterfaceGuid, string strProfileName, IntPtr pReserved, out IntPtr pstrProfileXml, IntPtr pdwFlags, IntPtr pdwGrantedAccess);
[DllImport("wlanapi.dll")] public static extern uint WlanQueryInterface(IntPtr hClientHandle, ref Guid pInterfaceGuid, int OpCode, IntPtr pReserved, out uint pdwDataSize, out IntPtr ppData, IntPtr pWlanOpcodeValueType);
[DllImport("wlanapi.dll")] public static extern void WlanFreeMemory(IntPtr pMemory);
'@
}

function Get-NgTimerResolution {
    <#
        Résolution du timer système (NtQueryTimerResolution, ntdll), en ms. Lecture seule.
        « Plus grossière » = 15,625 ms par défaut ; « actuelle » = ce que demande l'appli la plus exigeante
        (jeu, navigateur, Discord...). Depuis Windows 11, la demande d'un processus ne s'applique plus
        globalement par défaut : la valeur « actuelle » ne dit pas ce que voit TON jeu.
    #>
    $min = 0; $max = 0; $cur = 0
    [void][NetGuard.Native]::NtQueryTimerResolution([ref]$min, [ref]$max, [ref]$cur)
    [pscustomobject]@{ PlusGrossiereMs = $min / 10000; PlusFineMs = $max / 10000; ActuelleMs = $cur / 10000 }
}

function Get-NgWlanInfo {
    <#
        Wi-Fi via wlanapi.dll (objets, pas de texte netsh) :
          - connexion actuelle : signal (%), débit négocié, type PHY, canal -> bande ;
          - profils enregistrés : COMPTE par type d'authentification (ouvert / WEP / WPA...).
        Les SSID ne sont jamais renvoyés (vie privée, règle du rapport partageable).
        Pas de carte Wi-Fi -> $null.
    #>
    $h = [IntPtr]::Zero; $ver = 0
    if ([NetGuard.Native]::WlanOpenHandle(2, [IntPtr]::Zero, [ref]$ver, [ref]$h) -ne 0) { return $null }
    try {
        $list = [IntPtr]::Zero
        if ([NetGuard.Native]::WlanEnumInterfaces($h, [IntPtr]::Zero, [ref]$list) -ne 0) { return $null }
        $n = [Runtime.InteropServices.Marshal]::ReadInt32($list, 0)
        $result = @()
        for ($i = 0; $i -lt $n; $i++) {
            # WLAN_INTERFACE_INFO : GUID (16) + description WCHAR[256] (512) + état (4) = 532 octets ; liste après 8 octets
            $base = [IntPtr]($list.ToInt64() + 8 + $i * 532)
            $guid = [Runtime.InteropServices.Marshal]::PtrToStructure($base, [type][Guid])
            $state = [Runtime.InteropServices.Marshal]::ReadInt32($base, 528)
            $info = [ordered]@{ Connecte = ($state -eq 1); SignalPct = $null; DebitRxMbps = $null; DebitTxMbps = $null; Phy = $null; Canal = $null; Bande = $null
                ProfilsTotal = 0; ProfilsOuverts = 0; ProfilsWep = 0; ProfilsWpaPerso = 0; ProfilsWpa3 = 0 }
            if ($state -eq 1) {
                $sz = 0; $data = [IntPtr]::Zero
                # opcode 7 = wlan_intf_opcode_current_connection (WLAN_CONNECTION_ATTRIBUTES)
                if ([NetGuard.Native]::WlanQueryInterface($h, [ref]$guid, 7, [IntPtr]::Zero, [ref]$sz, [ref]$data, [IntPtr]::Zero) -eq 0) {
                    $phy = [Runtime.InteropServices.Marshal]::ReadInt32($data, 568)
                    $info.Phy = @{ 4 = '802.11a'; 5 = '802.11b'; 6 = '802.11g'; 7 = '802.11n'; 8 = '802.11ac'; 10 = '802.11ax'; 11 = '802.11be' }[$phy]
                    $info.SignalPct = [Runtime.InteropServices.Marshal]::ReadInt32($data, 576)
                    $info.DebitRxMbps = [Runtime.InteropServices.Marshal]::ReadInt32($data, 580) / 1000
                    $info.DebitTxMbps = [Runtime.InteropServices.Marshal]::ReadInt32($data, 584) / 1000
                    [NetGuard.Native]::WlanFreeMemory($data)
                }
                # opcode 8 = wlan_intf_opcode_channel_number
                if ([NetGuard.Native]::WlanQueryInterface($h, [ref]$guid, 8, [IntPtr]::Zero, [ref]$sz, [ref]$data, [IntPtr]::Zero) -eq 0) {
                    $ch = [Runtime.InteropServices.Marshal]::ReadInt32($data, 0)
                    $info.Canal = $ch
                    $info.Bande = if ($ch -le 14) { '2,4 GHz' } elseif ($ch -ge 32 -and $ch -le 177) { '5 GHz (ou 6 GHz)' } else { '6 GHz' }
                    [NetGuard.Native]::WlanFreeMemory($data)
                }
            }
            # Profils enregistrés : WLAN_PROFILE_INFO_LIST (2 x DWORD puis 516 octets par profil : nom WCHAR[256] + flags)
            $pl = [IntPtr]::Zero
            if ([NetGuard.Native]::WlanGetProfileList($h, [ref]$guid, [IntPtr]::Zero, [ref]$pl) -eq 0) {
                $pn = [Runtime.InteropServices.Marshal]::ReadInt32($pl, 0)
                for ($j = 0; $j -lt $pn; $j++) {
                    $name = [Runtime.InteropServices.Marshal]::PtrToStringUni([IntPtr]($pl.ToInt64() + 8 + $j * 516))
                    $xmlPtr = [IntPtr]::Zero
                    if ([NetGuard.Native]::WlanGetProfile($h, [ref]$guid, $name, [IntPtr]::Zero, [ref]$xmlPtr, [IntPtr]::Zero, [IntPtr]::Zero) -eq 0) {
                        $xml = [xml][Runtime.InteropServices.Marshal]::PtrToStringUni($xmlPtr)
                        [NetGuard.Native]::WlanFreeMemory($xmlPtr)
                        $auth = "$($xml.WLANProfile.MSM.security.authEncryption.authentication)"
                        $enc = "$($xml.WLANProfile.MSM.security.authEncryption.encryption)"
                        $info.ProfilsTotal++
                        if ($auth -eq 'open' -and $enc -eq 'none') { $info.ProfilsOuverts++ }
                        elseif ($enc -eq 'WEP') { $info.ProfilsWep++ }
                        elseif ($auth -match 'WPA3') { $info.ProfilsWpa3++ }
                        elseif ($auth -match 'PSK') { $info.ProfilsWpaPerso++ }
                    }
                }
                [NetGuard.Native]::WlanFreeMemory($pl)
            }
            $result += [pscustomobject]$info
        }
        [NetGuard.Native]::WlanFreeMemory($list)
        $result
    } finally { [void][NetGuard.Native]::WlanCloseHandle($h, [IntPtr]::Zero) }
}

function Get-NgBitLockerStatus {
    <#
        État BitLocker SANS admin : propriété Shell « System.Volume.BitLockerProtection »
        (Get-BitLockerVolume et Win32_EncryptableVolume exigent l'admin).
        Valeurs : 1 = activé, 2 = désactivé, 3 = chiffrement en cours, 4 = déchiffrement, 5 = suspendu,
        6 = activé (verrouillé), vide = non pris en charge.
    #>
    param([string]$Drive = 'C:')
    try {
        $v = (New-Object -ComObject Shell.Application).NameSpace("$Drive\").Self.ExtendedProperty('System.Volume.BitLockerProtection')
        $txt = @{ 1 = 'activé'; 2 = 'désactivé'; 3 = 'chiffrement en cours'; 4 = 'déchiffrement en cours'; 5 = 'suspendu'; 6 = 'activé (verrouillé)' }[[int]$v]
        if (-not $txt) { $txt = 'non pris en charge / inconnu' }
        [pscustomobject]@{ Lecteur = $Drive; Code = $v; Etat = $txt }
    } catch { [pscustomobject]@{ Lecteur = $Drive; Code = $null; Etat = 'illisible' } }
}

function Get-NgPowerSchemeName {
    # Nom des modes d'alimentation Windows connus (GUID documentés par powercfg)
    param([string]$Guid)
    $known = @{
        '381b4222-f694-41f0-9685-ff5bb260df2e' = 'Utilisation normale (Balanced)'
        '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' = 'Performances élevées'
        'a1841308-3541-4fab-bc81-f71556f20b4a' = 'Économie d''énergie'
        'e9a42b02-d5df-448d-aa00-03f14749eb61' = 'Performances optimales (Ultimate)'
    }
    if ($known.ContainsKey($Guid)) { return $known[$Guid] }
    # Plan tiers : nom lisible depuis le registre (« @fichier.dll,-123,Nom » -> « Nom »)
    $fn = Get-NgRegValue "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\$Guid" 'FriendlyName'
    if ($fn) { return ("{0} (personnalisé)" -f ($fn -replace '^@[^,]+,-?\d+,', '')) }
    "Mode personnalisé ($Guid)"
}

# =====================================================================================
# VERSION PARTAGEABLE : masquage des données identifiantes
# =====================================================================================
$script:NgPublicIps = @('1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112', '0.0.0.0', '127.0.0.1')

function ConvertTo-NgShareable {
    <#
        Masque dans un texte : adresses IPv4 / IPv6 (sauf résolveurs publics connus et 0.0.0.0 / 127.0.0.1),
        adresses MAC, et les chaînes passées dans -Secrets (nom du PC, nom d'utilisateur, SSID...).
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [string[]]$Secrets = @())
    $t = $Text
    foreach ($s in ($Secrets | Where-Object { $_ -and $_.Length -ge 3 } | Sort-Object Length -Descending)) {
        $t = [regex]::Replace($t, [regex]::Escape($s), '[masqué]', 'IgnoreCase')
    }
    # Adresses e-mail (comptes MDM / professionnels)
    $t = [regex]::Replace($t, '[\w.+-]+@[\w-]+(?:\.[\w-]+)+', '[e-mail masqué]')
    # SID de machine (identifiant unique du PC) et dossiers de profil d'autres comptes
    $t = [regex]::Replace($t, 'S-1-5-21-\d+-\d+-\d+', 'S-1-5-21-[masqué]')
    $t = [regex]::Replace($t, '(?i)([A-Z]:\\{1,2}Users\\{1,2})(?!Public\b|Default\b)[^\\"<>]+', '$1[masqué]')
    $t = [regex]::Replace($t, '\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b', 'xx-xx-xx-xx-xx-xx')
    $t = [regex]::Replace($t, '\b(?:\d{1,3}\.){3}\d{1,3}\b', {
            param($m) if ($script:NgPublicIps -contains $m.Value) { $m.Value } else { 'x.x.x.x' } })
    # IPv6, y compris la forme courte « fe80::1c2b:… » (bug trouvé par Test-NetGuard : l'ancien motif
    # exigeait deux groupes avant « :: »). Résolveurs publics conservés.
    $t = [regex]::Replace($t, $script:NgIPv6Regex, {
            param($m) if (Test-NgIPv6Candidate $m.Value) { 'x:x::x' } else { $m.Value } })
    $t
}

# Candidat IPv6 : groupes hexadécimaux (0 à 4 chiffres) séparés par « : », suffixe %zone facultatif
$script:NgIPv6Regex = '(?i)(?<![\w:.])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:%\d+)?(?![\w:])'
function Test-NgIPv6Candidate {
    # Vrai si la chaîne est une IPv6 à masquer. « 12:07:48 » (une heure) n'en est pas une :
    # on exige « :: » ou au moins 5 groupes. Résolveurs publics et ::1 conservés.
    param([string]$Value)
    $v = $Value -replace '%\d+$', ''
    if ($v -notmatch '::' -and $v.Split(':').Count -lt 5) { return $false }
    if ($v -notmatch '[0-9a-fA-F]') { return $false }
    if ($v -eq '::1' -or $v -match '^(?i)(2606:4700:4700|2001:4860:4860|2620:fe:)') { return $false }
    $true
}

function Find-NgShareableLeak {
    <#
        Contrôle d'un texte « partageable » : renvoie la liste des fuites trouvées
        (IPv4 non publique, MAC, e-mail, SID de machine, chaînes secrètes). Liste vide = propre.
        Utilisé par New-AuditReport.ps1 (refus d'écrire si fuite) et par Test-NetGuard.ps1.
    #>
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [string[]]$Secrets = @())
    $leaks = New-Object System.Collections.Generic.List[string]
    foreach ($m in [regex]::Matches($Text, '\b(?:\d{1,3}\.){3}\d{1,3}\b')) {
        if ($script:NgPublicIps -notcontains $m.Value) { $leaks.Add("IPv4 $($m.Value)") }
    }
    foreach ($m in [regex]::Matches($Text, '\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b')) { $leaks.Add("MAC $($m.Value)") }
    foreach ($m in [regex]::Matches($Text, $script:NgIPv6Regex)) { if (Test-NgIPv6Candidate $m.Value) { $leaks.Add("IPv6 $($m.Value)") } }
    foreach ($m in [regex]::Matches($Text, '[\w.+-]+@[\w-]+(?:\.[\w-]+)+')) { $leaks.Add("e-mail $($m.Value)") }
    foreach ($m in [regex]::Matches($Text, 'S-1-5-21-\d+-\d+-\d+')) { $leaks.Add("SID $($m.Value)") }
    foreach ($s in ($Secrets | Where-Object { $_ -and $_.Length -ge 3 })) {
        if ($Text.IndexOf($s, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $leaks.Add("secret ($($s.Length) caractères)") }
    }
    , $leaks.ToArray()
}

# =====================================================================================
# 4. JOURNAL ET GARDE-FOUS (seules fonctions qui modifient le système)
# =====================================================================================
# Règle 7 : la valeur d'origine (et son type) est écrite dans journal.json AVANT le changement.
# Règle 5 : cibles interdites, refusées même si un catalogue (ou un test) les demande.

$script:NgForbiddenRegPatterns = @(
    '*Windows Defender*', '*Microsoft Antimalware*', '*WindowsFirewall*', '*SharedAccess*',
    '*WindowsUpdate*', '*DeviceGuard*', '*\CI\Config*', '*\CI\Policy*', '*HVCI*',
    '*Hyper-V*', '*VMware*', '*VirtualBox*',
    '*KeePass*', '*Bitwarden*', '*1Password*', '*Dashlane*', '*LastPass*'
)
$script:NgProtectedProcesses = @(
    'System', 'Idle', 'Registry', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'lsaiso',
    'svchost', 'dwm', 'explorer', 'fontdrvhost', 'sihost', 'ctfmon', 'audiodg', 'MsMpEng', 'NisSrv',
    'SecurityHealthService', 'SecurityHealthSystray', 'MpDefenderCoreService', 'vgc', 'vgtray',
    'EasyAntiCheat', 'EasyAntiCheat_EOS', 'BEService', 'FACEIT', 'nvcontainer', 'NVDisplay.Container',
    'vmware-vmx', 'vmware', 'VirtualBox', 'VBoxSVC', 'vmmem', 'vmmemWSL', 'wsl', 'wslservice',
    'KeePass', 'KeePassXC', 'Bitwarden', '1Password'
)

function Test-NgForbiddenRegistryPath {
    # Vrai si netguard ne doit JAMAIS écrire à cet endroit (tout ce qui n'est pas HKCU, ou cible sensible)
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -notmatch '^(HKCU:|Registry::HKEY_CURRENT_USER|HKEY_CURRENT_USER)') { return $true }
    foreach ($p in $script:NgForbiddenRegPatterns) { if ($Path -like $p) { return $true } }
    return $false
}
function Assert-NgRegistryAllowed {
    param([Parameter(Mandatory)][string]$Path)
    if (Test-NgForbiddenRegistryPath $Path) { throw "REFUSÉ : écriture interdite dans $Path (hors HKCU ou cible protégée)." }
}
function Assert-NgServiceAllowed {
    param([Parameter(Mandatory)][string]$Name)
    if (Test-NgProtectedService $Name) { throw "REFUSÉ : le service '$Name' est protégé (config\protected_services.json)." }
}
function Test-NgSystemFirewallRule {
    <#
        Vrai si la règle appartient à Windows : groupe en chaîne de ressource (« @FirewallAPI.dll,… »),
        propriétaire d'application système, ou règle venant d'une stratégie (GPO / MDM).
    #>
    param([Parameter(Mandatory)]$Rule)
    if ($Rule.Group -and ([string]$Rule.Group).StartsWith('@')) { return $true }
    if ($Rule.PSObject.Properties['Owner'] -and $Rule.Owner) { return $true }
    if ($Rule.PSObject.Properties['PolicyStoreSourceType'] -and $Rule.PolicyStoreSourceType -and [string]$Rule.PolicyStoreSourceType -ne 'Local') { return $true }
    return $false
}
function Assert-NgFirewallRuleAllowed {
    param([Parameter(Mandatory)]$Rule)
    if (Test-NgSystemFirewallRule $Rule) { throw "REFUSÉ : la règle de pare-feu '$($Rule.DisplayName)' appartient à Windows (groupe système ou stratégie)." }
}
function Test-NgProtectedProcess {
    # Vrai pour un processus système, de sécurité, d'anti-triche, de VM ou de coffre de mots de passe
    param([Parameter(Mandatory)][Diagnostics.Process]$Process)
    if ($script:NgProtectedProcesses -contains $Process.ProcessName) { return $true }
    if ($Process.SessionId -eq 0) { return $true }
    $path = $null; try { $path = $Process.MainModule.FileName } catch { }
    if (-not $path) { return $true }   # chemin illisible = processus d'un autre compte ou système
    if ($path -like "$env:windir\*") { return $true }
    return $false
}

function Get-NgActivePowerScheme {
    Get-NgRegValue 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes' 'ActivePowerScheme'
}
function Test-NgPowerSchemeExists {
    param([Parameter(Mandatory)][string]$Guid)
    Test-Path -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\$Guid"
}

function New-NgSession {
    # Crée logs\session_<date>\ et un journal vide (appelé seulement en mode réel)
    param([Parameter(Mandatory)][string]$Outil, [string]$Profil = '', [string]$LogsDir = (Get-NgPath 'logs'))
    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
    $dir = Join-Path $LogsDir "session_$stamp"
    $i = 1; while (Test-Path -LiteralPath $dir) { $dir = Join-Path $LogsDir "session_$stamp-$i"; $i++ }
    New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false | Out-Null
    $s = [pscustomobject]@{
        Dir  = $dir
        Path = Join-Path $dir 'journal.json'
        Data = [pscustomobject]@{ Outil = $Outil; Profil = $Profil; Debut = (Get-Date).ToString('s'); Etat = 'en_cours'; Entrees = @() }
    }
    Save-NgJournal $s
    Write-NgLog $s "Session ouverte ($Outil, profil '$Profil')"
    $s
}
function Save-NgJournal {
    # Écriture atomique : fichier temporaire puis remplacement (un arrêt brutal ne laisse pas un JSON coupé)
    param([Parameter(Mandatory)]$Session)
    $tmp = "$($Session.Path).tmp"
    [IO.File]::WriteAllText($tmp, ($Session.Data | ConvertTo-Json -Depth 8), (New-Object Text.UTF8Encoding($true)))
    Move-Item -LiteralPath $tmp -Destination $Session.Path -Force -WhatIf:$false
}
function Read-NgJournal {
    param([Parameter(Mandatory)][string]$Dir)
    $p = Join-Path $Dir 'journal.json'
    $d = Get-Content -LiteralPath $p -Raw -Encoding UTF8 | ConvertFrom-Json
    $d.Entrees = @($d.Entrees | ForEach-Object { $_ })
    [pscustomobject]@{ Dir = $Dir; Path = $p; Data = $d }
}
function Write-NgLog {
    # Journal texte horodaté (session.log) à côté de journal.json
    param([Parameter(Mandatory)]$Session, [Parameter(Mandatory)][string]$Message)
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    [IO.File]::AppendAllText((Join-Path $Session.Dir 'session.log'), $line + "`r`n", (New-Object Text.UTF8Encoding($true)))
}
function Add-NgJournalEntry {
    param([Parameter(Mandatory)]$Session, [Parameter(Mandatory)][hashtable]$Entry)
    $Entry.N = @($Session.Data.Entrees).Count + 1
    $Entry.Heure = (Get-Date).ToString('s')
    $Entry.Etat = 'prevu'
    $o = [pscustomobject]$Entry
    $Session.Data.Entrees = @($Session.Data.Entrees) + $o
    Save-NgJournal $Session
    $o
}
function Set-NgJournalEntryState {
    param([Parameter(Mandatory)]$Session, [Parameter(Mandatory)]$Entry, [Parameter(Mandatory)][string]$Etat, [string]$Note)
    $Entry | Add-Member -NotePropertyName Etat -NotePropertyValue $Etat -Force
    if ($Note) { $Entry | Add-Member -NotePropertyName Note -NotePropertyValue $Note -Force }
    Save-NgJournal $Session
}

function Get-NgRegSnapshot {
    # Valeur d'origine ET type (DWord, String, ...) ; Existait = $false si absente
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name)
    $keyExists = Test-Path -LiteralPath $Path
    if ($keyExists) {
        $k = Get-Item -LiteralPath $Path
        if ($k.GetValueNames() -contains $Name) {
            return [pscustomobject]@{ CleExistait = $true; Existait = $true; Valeur = $k.GetValue($Name, $null, 'DoNotExpandEnvironmentNames'); Type = [string]$k.GetValueKind($Name) }
        }
    }
    [pscustomobject]@{ CleExistait = $keyExists; Existait = $false; Valeur = $null; Type = $null }
}
function Export-NgRegKey {
    # Export .reg de la clé (si elle existe) avec reg.exe, outil Windows documenté
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$File)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $native = $Path -replace '^HKCU:\\?', 'HKCU\' -replace '^Registry::HKEY_CURRENT_USER\\?', 'HKCU\'
    & reg.exe export $native $File /y 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) { return $File }
    return $null
}

function Set-NgRegistryValueLogged {
    <#
        Écrit une valeur HKCU après : contrôle de la cible, lecture de l'origine, export .reg,
        entrée de journal 'prevu' ENREGISTRÉE. Marque 'fait' ou 'echec' ensuite.
        Renvoie 'deja' si la valeur est déjà la bonne, 'simule' sous -WhatIf.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param($Session, [string]$ActionId, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Type, [Parameter(Mandatory)]$Value)
    Assert-NgRegistryAllowed $Path
    $snap = Get-NgRegSnapshot $Path $Name
    if ($snap.Existait -and $snap.Type -eq $Type -and "$($snap.Valeur)" -eq "$Value") { return 'deja' }
    $orig = if ($snap.Existait) { "$($snap.Type) = $($snap.Valeur)" } else { 'absente' }
    if (-not $PSCmdlet.ShouldProcess("$Path\$Name", "Écrire $Type = $Value (origine : $orig)")) { return 'simule' }
    $exportFile = Join-Path $Session.Dir ('{0:D3}_{1}.reg' -f (@($Session.Data.Entrees).Count + 1), ($Name -replace '[^\w-]', '_'))
    $export = Export-NgRegKey $Path $exportFile
    $e = Add-NgJournalEntry $Session @{
        Action = $ActionId; Type = 'registre'; Cible = $Path; Nom = $Name
        CleExistait = $snap.CleExistait; Existait = $snap.Existait; ValeurOrigine = $snap.Valeur; TypeOrigine = $snap.Type
        ValeurNouvelle = $Value; TypeNouveau = $Type; Export = $export
    }
    Write-NgLog $Session "[$ActionId] registre $Path\$Name : $orig -> $Type $Value"
    try {
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -Path $Path -Force -WhatIf:$false | Out-Null }
        New-ItemProperty -LiteralPath $Path -Name $Name -PropertyType $Type -Value $Value -Force -WhatIf:$false | Out-Null
        Set-NgJournalEntryState $Session $e 'fait'
        return 'fait'
    } catch {
        Set-NgJournalEntryState $Session $e 'echec' $_.Exception.Message
        Write-NgLog $Session "[$ActionId] ÉCHEC : $($_.Exception.Message)"
        throw
    }
}

function Set-NgPowerSchemeLogged {
    # Active un plan d'alimentation (powercfg, sans admin) après journalisation du plan d'origine
    [CmdletBinding(SupportsShouldProcess)]
    param($Session, [string]$ActionId, [Parameter(Mandatory)][string]$Guid)
    if (-not (Test-NgPowerSchemeExists $Guid)) { throw "Plan $Guid absent de cette machine (powercfg /list)." }
    $cur = Get-NgActivePowerScheme
    if ($cur -eq $Guid) { return 'deja' }
    if (-not $PSCmdlet.ShouldProcess("plan d'alimentation", "Passer de « $(Get-NgPowerSchemeName $cur) » à « $(Get-NgPowerSchemeName $Guid) »")) { return 'simule' }
    $e = Add-NgJournalEntry $Session @{ Action = $ActionId; Type = 'powercfg'; Cible = 'ActivePowerScheme'; ValeurOrigine = $cur; ValeurNouvelle = $Guid }
    Write-NgLog $Session "[$ActionId] powercfg /setactive $Guid (origine $cur)"
    & powercfg.exe /setactive $Guid
    if ($LASTEXITCODE -ne 0 -or (Get-NgActivePowerScheme) -ne $Guid) {
        Set-NgJournalEntryState $Session $e 'echec' "powercfg code $LASTEXITCODE"
        throw "powercfg /setactive a échoué (code $LASTEXITCODE)."
    }
    Set-NgJournalEntryState $Session $e 'fait'
    'fait'
}

function Restore-NgJournalEntry {
    <#
        Rejoue UNE entrée à l'envers (Undo.ps1 et GameMode.ps1). Les entrées 'prevu' et 'echec'
        sont aussi restaurées : un arrêt a pu survenir entre le journal et le changement.
        Renvoie : 'restaure', 'deja' (déjà à l'origine), 'simule' ou 'ignore'.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)]$Entry)
    switch ($Entry.Type) {
        'registre' {
            Assert-NgRegistryAllowed $Entry.Cible
            $now = Get-NgRegSnapshot $Entry.Cible $Entry.Nom
            if ($Entry.Existait) {
                if ($now.Existait -and $now.Type -eq $Entry.TypeOrigine -and "$($now.Valeur)" -eq "$($Entry.ValeurOrigine)") { return 'deja' }
                if (-not $PSCmdlet.ShouldProcess("$($Entry.Cible)\$($Entry.Nom)", "Remettre $($Entry.TypeOrigine) = $($Entry.ValeurOrigine)")) { return 'simule' }
                $v = $Entry.ValeurOrigine
                if ($Entry.TypeOrigine -eq 'MultiString') { $v = [string[]]@($v) }
                elseif ($Entry.TypeOrigine -eq 'Binary') { $v = [byte[]]@($v) }
                if (-not (Test-Path -LiteralPath $Entry.Cible)) { New-Item -Path $Entry.Cible -Force -WhatIf:$false | Out-Null }
                New-ItemProperty -LiteralPath $Entry.Cible -Name $Entry.Nom -PropertyType $Entry.TypeOrigine -Value $v -Force -WhatIf:$false | Out-Null
            } else {
                $keyLeft = Test-Path -LiteralPath $Entry.Cible
                if (-not $now.Existait -and ($Entry.CleExistait -or -not $keyLeft)) { return 'deja' }
                if (-not $PSCmdlet.ShouldProcess("$($Entry.Cible)\$($Entry.Nom)", "Supprimer la valeur (absente à l'origine)")) { return 'simule' }
                if ($now.Existait) { Remove-ItemProperty -LiteralPath $Entry.Cible -Name $Entry.Nom -WhatIf:$false }
                # Clé créée par netguard et restée vide : on la retire aussi
                if (-not $Entry.CleExistait -and (Test-Path -LiteralPath $Entry.Cible)) {
                    $k = Get-Item -LiteralPath $Entry.Cible
                    if ($k.ValueCount -eq 0 -and $k.SubKeyCount -eq 0) { Remove-Item -LiteralPath $Entry.Cible -WhatIf:$false }
                }
            }
            return 'restaure'
        }
        'powercfg' {
            if ((Get-NgActivePowerScheme) -eq $Entry.ValeurOrigine) { return 'deja' }
            if (-not $PSCmdlet.ShouldProcess("plan d'alimentation", "Remettre « $(Get-NgPowerSchemeName $Entry.ValeurOrigine) »")) { return 'simule' }
            & powercfg.exe /setactive $Entry.ValeurOrigine
            if ($LASTEXITCODE -ne 0) { throw "powercfg /setactive $($Entry.ValeurOrigine) a échoué (code $LASTEXITCODE)." }
            return 'restaure'
        }
        'priorite' {
            $p = Get-Process -Id $Entry.Pid -ErrorAction SilentlyContinue
            if (-not $p -or $p.StartTime.ToString('s') -ne $Entry.Demarrage) { return 'ignore' }   # processus fermé ou PID réutilisé
            if ([string]$p.PriorityClass -eq $Entry.ValeurOrigine) { return 'deja' }
            if (-not $PSCmdlet.ShouldProcess("$($p.ProcessName) (PID $($p.Id))", "Remettre la priorité $($Entry.ValeurOrigine)")) { return 'simule' }
            $p.PriorityClass = [Diagnostics.ProcessPriorityClass]$Entry.ValeurOrigine
            return 'restaure'
        }
        default { return 'ignore' }   # ex. 'pare-feu-export' : aucune règle n'est modifiée par netguard
    }
}

function Set-NgProcessPriorityLogged {
    <#
        Baisse la priorité d'un processus de l'utilisateur (Mode Jeu). Ne tue rien, ne suspend rien.
        Refuse les processus protégés (système, sécurité, anti-triche, VM, coffres de mots de passe).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param($Session, [string]$ActionId, [Parameter(Mandatory)][Diagnostics.Process]$Process, [Parameter(Mandatory)][string]$Priority)
    if (Test-NgProtectedProcess $Process) { throw "REFUSÉ : $($Process.ProcessName) (PID $($Process.Id)) est un processus protégé." }
    $cur = [string]$Process.PriorityClass
    if ($cur -eq $Priority) { return 'deja' }
    if (-not $PSCmdlet.ShouldProcess("$($Process.ProcessName) (PID $($Process.Id))", "Priorité $cur -> $Priority")) { return 'simule' }
    $e = Add-NgJournalEntry $Session @{ Action = $ActionId; Type = 'priorite'; Cible = $Process.ProcessName; Pid = $Process.Id; Demarrage = $Process.StartTime.ToString('s'); ValeurOrigine = $cur; ValeurNouvelle = $Priority }
    Write-NgLog $Session "[$ActionId] priorité $($Process.ProcessName) PID $($Process.Id) : $cur -> $Priority"
    try {
        $Process.PriorityClass = [Diagnostics.ProcessPriorityClass]$Priority
        Set-NgJournalEntryState $Session $e 'fait'
        'fait'
    } catch {
        Set-NgJournalEntryState $Session $e 'echec' $_.Exception.Message
        throw
    }
}
