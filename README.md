# netguard-gaming

Boîte à outils PowerShell pour **mesurer puis améliorer le réseau, la sécurité réseau / système et la fluidité en jeu** sous Windows 10/11, sans placebo :

1. on **mesure avant** (baseline : latence vers la box et vers les villes des serveurs de jeu, gigue, perte, DNS, bufferbloat) ;
2. on ne règle **que ce qui a un effet prouvé**, avec une **source officielle** ;
3. on **vérifie après** en A/B et on conclut honnêtement : « gain mesuré » ou « aucun gain mesurable sur cette machine ».

> 3ᵉ projet d'une suite : [pc-cleanup](https://github.com/wiwivss/pc-cleanup) (nettoyage disque) et [win-tune](https://github.com/wiwivss/win-tune) (Windows lui-même). Projet personnel d'étudiant ingénieur Réseaux & Sécurité : le but est autant de comprendre son réseau que de le régler.

## Démarrage rapide

1. Télécharge le dépôt (**Code > Download ZIP**) et extrais-le où tu veux.
2. Double-clique sur **`netguard.cmd`**. Aucune installation, aucun droit administrateur.
3. Suis le menu :

```
  1  Audit (lecture seule) + rapport HTML
  2  Ouvrir le rapport
  3  Appliquer un profil (simulation, puis OUI)
  4  Commandes manuelles / admin, revue du pare-feu
  5  Annuler une session
  6  Mode Jeu <-> Mode Normal
  7  Vérifier avant / après (mesures A/B)
  8  Auto-test (bac à sable)
  0  Quitter
```

Le cycle conseillé : **1** (audit) → lire le rapport, **sécurité d'abord** → **3** (profil, simulation, `OUI`) ou **4** (fiches) → **7** (avant/après), à refaire à un autre moment de la journée avant de conclure.

> `netguard.cmd` lance PowerShell avec `-ExecutionPolicy Bypass` **pour ce seul processus** : la stratégie d'exécution de Windows n'est pas modifiée. Lis les scripts avant : tout est en clair et commenté.

## Principes de sécurité

| Règle | Mise en œuvre |
|---|---|
| L'audit ne modifie rien | `Audit.ps1` n'écrit que dans `reports\` et `baseline\`. `Test-NetGuard.ps1` le prouve (empreinte des fichiers du projet avant/après, sorties redirigées vers `%TEMP%`, rien sous `-WhatIf`). |
| Ma machine seulement | Aucun scan du réseau local ni d'autres machines (pas de nmap, pas de balayage de ports ou d'IP). Seule la box (passerelle) est pingée. **Au plus 20 requêtes par cible et par passe**, une toutes les 200 ms. |
| Une seule requête de charge | Le test de bufferbloat utilise l'endpoint de test de Cloudflare (`speed.cloudflare.com`), **seulement avec `-LoadTest`** après ton accord, avec un plafond de volume. |
| Simulation d'abord | Tous les scripts gèrent `-WhatIf` ; `Apply`, `Undo` et `GameMode` montrent toujours la simulation avant de demander `OUI`. |
| Sauvegarde avant modification | Export `.reg` + valeur **et type** d'origine dans `logs\session_<date>\journal.json`, écrit **avant** chaque changement (écriture atomique). `Undo.ps1` rejoue le journal à l'envers. |
| Pas d'admin implicite | Utilisateur standard. Ce qui demande l'administrateur est **affiché, jamais lancé**. Les écritures automatiques sont limitées à **HKCU** et à `powercfg`. |
| Zones interdites | Defender (ni désactivation, ni exclusion), pare-feu, mises à jour de sécurité, liste de blocage des pilotes vulnérables, VBS/HVCI : jamais. Services de `config\protected_services.json`, VM, coffres de mots de passe, anti-triche : refusés par le code, même si un catalogue le demande. |
| Pare-feu | Aucune règle n'est **supprimée**. Désactivation proposée **règle par règle**, après export JSON, jamais pour une règle Windows (groupe système ou stratégie). |
| Sources | Chaque réglage cite learn.microsoft.com / support.microsoft.com ou le fabricant, vérifié par recherche web. Sans source officielle : **« non vérifié »**, désactivé par défaut, opt-in explicite (`-Inclure NG-xxx`). |
| Pas d'outil tiers | Aucun « tweak pack », aucun script trouvé sur Internet, rien n'est téléchargé ni installé (winget : liste seulement ; NVIDIA : comparaison de version seulement). |
| Données personnelles | IP, MAC, SSID, nom du PC et d'utilisateur ne quittent pas `reports\` (ignoré par Git). Le **rapport partageable** les masque et son écriture est **refusée** si un contrôle trouve encore une fuite. |

### Niveaux de risque et profils

| Niveau | Signification | Profil minimal |
|---|---|---|
| 🟢 Vert | Réversible, sans effet de bord connu | Prudent |
| 🟠 Orange | Peut casser un usage précis (indiqué dans la fiche) | Équilibré ou Avancé, validé **une par une** |
| 🔴 Rouge | Peut dégrader le PC ou la sécurité | Jamais appliqué (placebos et interdits) |

### Classement honnête de chaque réglage

| Classement | Signification |
|---|---|
| gain réel mesuré | Seulement après `Verify.ps1` en A/B, au-delà des seuils |
| stabilité | Pas plus rapide, mais plus fiable (pilote, plan d'alimentation documenté…) |
| gain marginal | Effet réel mais en général sous le bruit de mesure |
| placebo | Aucun effet mesurable : les « tweaks TCP » des vidéos, MTU « gaming »… |
| sécurité | Hors classement de performance : corrige un risque, ne promet aucune milliseconde |

## Contenu

```
netguard.cmd               double-clic : lance le menu
scripts\
  Start-NetGuard.ps1       menu ; au démarrage, détecte un Mode Jeu resté actif et propose de tout remettre
  Audit.ps1                Phase 0 (contexte) + Phase 1 (réseau, sécurité, jeu ; lecture seule)
                           -> reports\audit_<date>\audit.json, baseline\baseline_<date>.json
  New-AuditReport.ps1      rapport HTML : scores, baseline, Top 5, tableau complet, « ce que je ne recommande PAS »
                           -> reports\rapport_audit.html + rapport_audit_partageable.html (masqué)
  Apply.ps1                profils Prudent / Équilibré / Avancé ; -Manuel (fiches) ; -PareFeu (revue règle par règle)
  Undo.ps1                 annule une session à partir de son journal
  Verify.ps1               nouvelles mesures, comparaison à la baseline avec seuils, relecture de sécurité
  GameMode.ps1             Mode Jeu <-> Mode Normal, état écrit sur disque AVANT le basculement
  Test-NetGuard.ps1        auto-test dans un bac à sable (HKCU:\Software\NetGuardTest + %TEMP%)
  Common.ps1               mesures (ping, TCP, DNS, MTU), masquage, journal et garde-fous
config\
  actions.json             catalogue numéroté : classement, risque, méthode, commande, source, annulation
  dns_providers.json       résolveurs comparés (adresses recopiées des pages officielles)
  game_targets.json        cibles de latence (proxys des villes de serveurs de jeu)
  game_mode.json           ce que fait le Mode Jeu (tout désactivé sauf le plan d'alimentation)
  protected_services.json  services jamais modifiés
  *.local.json             tes surcharges (vrais serveurs, programmes validés…) : ignorées par Git
reports\ baseline\ logs\   résultats, mesures et journaux (ignorés par Git : données perso)
```

## Ce que mesure l'audit

| Section | Contenu |
|---|---|
| 0. Contexte | Édition, build, langue, fixe/portable, CPU, RAM, GPU, carte réseau et pilote, DNS utilisé, PC géré (domaine, Entra ID, inscription MDM) |
| A. Réseau | Lien (Ethernet / Wi-Fi : bande, canal, signal) ; **latence, gigue, perte** vers la box, 1.1.1.1, 8.8.8.8 et Paris / Francfort / Londres, en plusieurs passes espacées (médiane, p95, pire cas) ; **benchmark DNS** (résolveur actuel vs Cloudflare / Google / Quad9, cache évité par sous-domaines aléatoires) ; **MTU du chemin** (bit DF, dichotomie) ; propriétés avancées de la carte (énergie, délestage, tampons) ; trafic au repos et programmes qui l'utilisent ; Optimisation de la distribution ; **bufferbloat** (optionnel, après accord) |
| B. Sécurité | Profils de pare-feu, règles entrantes larges ou orphelines ; ports en écoute (signature, règle qui les autorise) ; connexions sortantes par programme ; Defender, protection contre les falsifications, BitLocker, Secure Boot, TPM, SMBv1, RDP, WinRM, partages, LLMNR / NetBIOS / mDNS, UAC ; comptes locaux ; **fichier hosts**, proxy, DNS chiffré, doublons ARP ; profils Wi-Fi (compte seulement) ; mises à jour en attente (winget, liste seulement) |
| C. Jeu | Pilote NVIDIA comparé à nvidia.com, RAM (XMP/EXPO, kits mélangés), Mode Jeu, plan d'alimentation, HAGS, Game Bar, optimisations plein écran, accélération souris, résolution du minuteur, VBS / HVCI et liste de blocage des pilotes, températures et processus |

Les serveurs de Riot, Valve et Epic **filtrent le ping** : les villes sont mesurées via des points d'entrée cloud situés dans les mêmes villes. Cela mesure ta ligne jusqu'à la ville, pas le serveur de jeu ; la référence reste le ping affiché en jeu. Tes vrais serveurs (méthode `tcp`) vont dans `config\game_targets.local.json`.

## Catalogue des actions

| N° | Réglage | Classement | Risque | Méthode | Source |
|---|---|---|---|---|---|
| NG-001 | Mettre à jour WinRAR (≥ 7.13) | sécurité | 🟢 | fiche | [NVD CVE-2025-8088](https://nvd.nist.gov/vuln/detail/cve-2025-8088) |
| NG-002 | hosts : retirer les redirections vers une IP externe | sécurité | 🟠 | fiche (admin) | [Microsoft](https://support.microsoft.com/en-us/windows/experience/how-to-reset-the-hosts-file-back-to-the-default) |
| NG-003 | Serveur OpenSSH : arrêter s'il ne sert pas | sécurité | 🟠 | admin, affiché | [Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse) |
| NG-004 | Protection contre les falsifications de Defender | sécurité | 🟢 | fiche | [Microsoft Learn](https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection) |
| NG-005 | Bufferbloat : QoS / SQM sur la box | gain marginal | 🟢 | fiche | [Bouygues Telecom](https://www.bouyguestelecom.fr/guide-pratique/internet/QOS) |
| NG-006 | Plan d'alimentation : revenir à un mode Windows | stabilité | 🟢 | **auto** (powercfg) | [Microsoft Learn](https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options) |
| NG-007 | Plan « Performances élevées » (PC fixe) | gain marginal | 🟢 | **auto** (powercfg) | idem |
| NG-008 / 009 | Pare-feu : règles larges / programmes désinstallés | sécurité | 🟠 / 🟢 | règle par règle | [Disable-NetFirewallRule](https://learn.microsoft.com/en-us/powershell/module/netsecurity/disable-netfirewallrule) |
| NG-010 | LLMNR désactivé (si inutilisé) | sécurité | 🟠 | admin, affiché | [Policy CSP ADMX_DnsClient](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-dnsclient) |
| NG-011 | NetBIOS sur TCP/IP désactivé (si inutilisé) | sécurité | 🟠 | admin, affiché | [SetTcpipNetbios](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/settcpipnetbios-method-in-class-win32-networkadapterconfiguration) |
| NG-012 | Carte réseau : EEE (`*EEE`) désactivé | gain marginal | 🟢 | admin, affiché | [mots-clés INF standard](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/standardized-inf-keywords-for-power-management) |
| NG-013 | Realtek : Green Ethernet, Gigabit Lite, Power Saving | gain marginal | 🟢 | admin, opt-in | ❌ non vérifié |
| NG-014 | Windows ne peut plus éteindre la carte (PnPCapabilities) | stabilité | 🟢 | opt-in | ❌ non vérifié (article Microsoft retiré) |
| NG-015 | Optimisation de la distribution : limiter le débit | gain marginal | 🟢 | fiche | [Microsoft Learn](https://learn.microsoft.com/en-us/windows/deployment/do/waas-delivery-optimization-reference) |
| NG-016 à 018 | Pilote réseau, outil d'inventaire réseau, mises à jour winget | stabilité / sécurité | 🟢 | fiches | ❌ non vérifié / éditeur |
| NG-019 | HAGS | gain marginal | 🟢 | fiche | [DirectX Blog](https://devblogs.microsoft.com/directx/hardware-accelerated-gpu-scheduling/) |
| NG-020 | Mode Jeu Windows | gain marginal | 🟢 | fiche | [Microsoft](https://support.microsoft.com/en-us/windows/using-game-mode-on-your-pc-5c94107e-a537-206e-e9e9-20600523bc43) |
| NG-021 / 022 | Capture Game Bar, accélération souris | gain marginal | 🟢 | fiches | ❌ non vérifié |
| NG-023 | SMBv1 désactivé (s'il est actif) | sécurité | 🟢 | admin, affiché | [Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3) |
| NG-024 | DNS le plus rapide (si écart ≥ 5 ms) | gain marginal | 🟢 | admin, affiché | [Set-DnsClientServerAddress](https://learn.microsoft.com/en-us/powershell/module/dnsclient/set-dnsclientserveraddress) |
| NG-025 / 026 | RAM (kits mélangés), pilote NVIDIA | stabilité | 🟢 | fiches | — |

**Ce que je ne recommande PAS, et pourquoi** (détail dans le rapport) :

| Réglage | Pourquoi |
|---|---|
| Désactiver l'autotuning TCP | Les jeux temps réel sont en **UDP** ; désactivé, il bride les téléchargements. Microsoft recommande `normal` ([source](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/tcpip-performance-known-issues)). |
| `TcpAckFrequency`, `TCPNoDelay`, « désactiver Nagle » | TCP seulement ; Nagle se règle par l'application (socket), pas par le registre ([source](https://learn.microsoft.com/en-us/archive/blogs/nettracer/tcp-delayed-ack-combined-with-nagle-algorithm-can-badly-impact-communication-performance), [KB 328890](https://support.microsoft.com/kb/328890)). |
| Forcer un MTU « gaming » | Windows découvre le MTU du chemin ; l'audit le mesure. Plus bas = fragmentation inutile, plus haut = pertes. |
| `NetworkThrottlingIndex`, `SystemResponsiveness` | Aucune documentation officielle les reliant au ping. |
| Couper la modération d'interruptions | Quelques microsecondes, face à des millisecondes de ligne. |
| Changer de DNS « pour le ping » | Le DNS ne joue qu'à la résolution d'un nom, pas pendant la partie. Proposé seulement si la mesure montre ≥ 5 ms. |
| Désactiver VBS / HVCI, Defender, pare-feu, mises à jour | Interdit par le projet. La liste de blocage des pilotes vulnérables est appliquée quand l'intégrité de la mémoire est active ([source](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules)). |

Les tweaks TCP ne sont **jamais appliqués par défaut**. Ils peuvent être testés en A/B **sur demande** : applique-les toi-même, puis `Verify.ps1` à plusieurs moments ; netguard conclura ce que la mesure dit.

## Mode Jeu

| Mode Jeu | Détail |
|---|---|
| Plan « Performances élevées » | `powercfg /setactive`, sans admin |
| Notifications | Windows 11 active déjà « Ne pas déranger » pendant un jeu ([source](https://support.microsoft.com/en-us/windows/experience/notifications-and-do-not-disturb-in-windows)) : rappel seulement. Couper toutes les bannières (`ToastEnabled`) est possible en opt-in, **non vérifié**. |
| Programmes de fond | Seulement ceux que tu valides dans `game_mode.local.json` (`"actif": true`) : **priorité abaissée** ([`Process.PriorityClass`](https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.priorityclass)). Rien n'est tué, suspendu ou arrêté (arrêter un service demande l'admin). Système, sécurité, anti-triche, VM et coffres de mots de passe : refusés. |

Ordre de sécurité : journal créé → `logs\gamemode\etat.json` passe à « jeu » → changements. Si le script, la session ou le PC s'arrête, le prochain lancement du menu le détecte et propose la restauration. Le Mode Normal **vérifie** ensuite que chaque valeur est revenue à l'identique.

## Usage des scripts sans le menu

```powershell
.\scripts\Audit.ps1 -WhatIf                         # ce qui serait écrit, sans rien écrire
.\scripts\Audit.ps1                                 # 3 passes espacées de 60 s, 20 requêtes par cible
.\scripts\Audit.ps1 -LoadTest                       # + bufferbloat (100 à 300 Mo vers speed.cloudflare.com)
.\scripts\Audit.ps1 -LoadTestFrom reports\audit_<date>\audit.json   # réutilise un bufferbloat déjà mesuré
.\scripts\Audit.ps1 -NvidiaLatestVersion 621.14     # compare au dernier pilote lu sur nvidia.com
.\scripts\New-AuditReport.ps1 -Open

.\scripts\Apply.ps1 -Profil Prudent -WhatIf
.\scripts\Apply.ps1 -Profil Equilibre
.\scripts\Apply.ps1 -Profil Avance -Inclure NG-013  # réglage non vérifié : opt-in explicite
.\scripts\Apply.ps1 -Manuel -Profil Avance          # fiches et commandes admin, rien n'est lancé
.\scripts\Apply.ps1 -PareFeu                        # revue des règles, une par une

.\scripts\Undo.ps1 -Liste
.\scripts\Undo.ps1 -WhatIf                          # dernière session non annulée
.\scripts\GameMode.ps1 -Mode Jeu -WhatIf
.\scripts\GameMode.ps1 -Mode Normal

.\scripts\Verify.ps1 -Label 'après NG-006'
.\scripts\Test-NetGuard.ps1                         # ~1 min 30 ; -SansAudit : ~15 s
```

## Pièges rencontrés (Windows PowerShell 5.1)

- **Les variables ne sont pas sensibles à la casse** : `$A` (l'audit) et `$a` (variable de boucle) sont la même variable. Bug trouvé deux fois (rapport, Verify) : la boucle écrasait l'objet principal.
- Une fonction nommée `H` est masquée par l'alias intégré `H` = `Get-History` (les alias passent avant les fonctions).
- `0 -eq ''` vaut **vrai** (la chaîne est convertie en nombre) : les pertes à 0 % s'affichaient « — ».
- Une fonction qui renvoie `, $tableau` (pour garder un tableau vide) donne un résultat de **1 élément** si on l'entoure de `@(...)` : l'affecter d'abord.
- `Get-NetAdapter.DriverDate` est une **chaîne**, pas une date : la soustraction échoue (« op_Subtraction ambigu »).
- Sans admin, `Get-NetAdapterPowerManagement` et `Win32_PowerPlan` sont refusés : l'audit lit `PnPCapabilities` et `ActivePowerScheme` dans le registre.
- Le chemin d'un processus SYSTEM (ex. `sshd`) est illisible sans admin : `Win32_Service.PathName` le donne.
- Les clés `HKLM\SOFTWARE\Microsoft\Enrollments` existent sur **tout** Windows : seules celles avec un compte (UPN) indiquent une vraie inscription MDM.
- `winget upgrade` affiche une ligne de tirets entre l'en-tête et la liste : un filtre trop large la supprimait, et la liste semblait vide.
- Dans une chaîne `"..."`, `` `* `` devient `*` : un motif `-like '***'` correspondait à tout.
- Le masquage IPv6 ratait la forme courte `fe80::…` (un seul groupe avant `::`) : bug trouvé par l'auto-test.
- Les lignes « WhatIf : … » vont directement à la console : `*>&1` ne les capture pas.

## Risques et limites

- **Mesures bruitées** : la latence varie avec l'heure et la charge du réseau de l'opérateur. Verify applique des seuils (**5 ms** de latence médiane, **2 points** de perte, **5 ms** de DNS) en dessous desquels il conclut « aucun gain mesurable » ; refaire la mesure à un autre moment avant de conclure.
- **Proxys de villes** : ils mesurent la ligne jusqu'à Paris / Francfort / Londres, pas le serveur de jeu. Le ping en jeu reste la référence.
- **Bufferbloat** : il se corrige sur la box ou un routeur (QoS / SQM), **pas depuis le PC**. Certaines box n'ont pas de réglage de QoS par appareil.
- **Réglages « non vérifiés »** : valeurs non documentées par l'éditeur, qu'une mise à jour peut ignorer ou réinitialiser.
- **PC géré (MDM, école, entreprise)** : des stratégies peuvent primer sur les réglages locaux ; une règle de pare-feu venant d'une stratégie est traitée comme une règle Windows (refusée).
- **Mode Jeu** : la priorité abaissée ne survit pas à la fermeture du programme ; après un redémarrage, seul le plan d'alimentation est à remettre (le menu le fait).
- **Masquage** : il repose sur des motifs (IP, MAC, e-mail, SID) et sur les noms connus (PC, utilisateur, SSID) ; relis le rapport partageable avant de le publier.
- Le rapport, l'audit et les journaux contiennent des données de la machine : ils sont exclus du dépôt par `.gitignore`.

## Résultat sur ma machine

Ryzen 7 3700X, 32 Go, RTX 4070 SUPER, Windows 11 Pro 25H2, **Ethernet 1 Gbit/s**, box FAI, serveurs Europe de l'Ouest.

**Baseline** (3 passes × 20 requêtes par cible, espacées de 60 s) :

| Cible | Médiane | p95 | Pire | Gigue | Perte |
|---|---|---|---|---|---|
| Box | 3 ms | 5 | 8 | 0,79 | 0 % |
| Cloudflare 1.1.1.1 | 8 ms | 12 | 23 | 1,63 | 0 % |
| Google 8.8.8.8 | 7 ms | 12 | 18 | 1,84 | 0 % |
| Paris (proxy) | 7 ms | 10 | 11 | 1,84 | 0 % |
| Francfort (proxy) | 15 ms | 17 | 20 | 1,63 | 0 % |
| Londres (proxy) | 15 ms | 18 | 21 | 1,53 | 0 % |

- **DNS** : le résolveur de la box est le plus rapide (9,9 ms de médiane, contre 14,5 Quad9, 14,6 Cloudflare, 21,3 Google) → **changer de DNS : aucun gain**.
- **Bufferbloat : C**. +18 ms en téléchargement (A), **+94 ms en envoi** (C) : un envoi de fichiers pendant une partie fait passer le ping d'environ 8 à environ 100 ms. Correctif : côté box (fiche NG-005).
- **MTU du chemin** : 1472, géré par Windows : rien à régler.
- **Test A/A** (Verify sans aucun changement, 4 h 40 après la baseline, 3 × 20 requêtes) : écart de **0 à 1 ms** sur toutes les cibles, 0 % de perte, DNS 9,9 → 10 ms → « aucun gain mesurable », comme attendu. Le bruit de ma ligne est donc bien sous le seuil de 5 ms : un écart de 5 ms ou plus après un réglage ne serait pas du hasard.
- **Auto-test** : `Test-NetGuard.ps1` → 26 tests, 26 OK (dont l'audit en bac à sable).

Ce que l'audit a trouvé **avant tout réglage de ping** (plus important que n'importe quel tweak) :
- **WinRAR 5.91**, vulnérable à deux failles exploitées par archive piégée ;
- un **fichier hosts** modifié qui redirigeait des dizaines de noms vers une **IP externe** au lieu de les bloquer ;
- un **serveur SSH** et un **outil d'inventaire réseau** actifs, et 30 règles de pare-feu entrantes « tous ports » (dont 17 pour un seul logiciel de récupération de données) ;
- la **protection contre les falsifications** de Defender désactivée ;
- un plan d'alimentation créé par un logiciel tiers.

Déjà en ordre : pare-feu actif (entrées bloquées), Secure Boot, TPM 2.0, VBS + HVCI, liste de blocage des pilotes, SMBv1 et RDP coupés, pilote NVIDIA à jour, XMP actif, Mode Jeu activé.

| | Latence Paris | Bufferbloat (envoi) | Score sécurité |
|---|---|---|---|
| Baseline | 7 ms | +94 ms (C) | 39 / 100 |
| Après corrections | *à mesurer* | *à mesurer* | *à mesurer* |

Conclusion à ce stade : la ligne est déjà bonne (Paris à 7 ms, 0 % de perte) ; **aucun réglage du PC ne peut faire mieux sur la latence**. Les vrais gains sont la **sécurité** et le **bufferbloat** (côté box).

## Licence

MIT
