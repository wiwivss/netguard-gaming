<#
.SYNOPSIS
    Menu de netguard-gaming (lancé par netguard.cmd). Utilisateur standard, aucun droit admin.
.DESCRIPTION
    Au démarrage : si un Mode Jeu est resté actif (script ou PC interrompu), propose de tout
    remettre à l'état d'origine avant d'afficher le menu.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Common.ps1')
$S = $PSScriptRoot

function Pause-Ng { [void](Read-Host "`nEntrée pour revenir au menu") }
function Invoke-Safe {
    # Une erreur d'un script n'arrête pas le menu
    param([scriptblock]$Block)
    try { & $Block } catch { Write-Host "ERREUR : $($_.Exception.Message)" -ForegroundColor Red }
}
function Select-Profil {
    $p = Read-Host 'Profil : 1 = Prudent, 2 = Équilibré, 3 = Avancé (Entrée = Prudent)'
    switch ($p) { '2' { 'Équilibré' } '3' { 'Avancé' } default { 'Prudent' } }
}

# ---- Reprise après interruption du Mode Jeu --------------------------------------------
$st = Join-Path (Get-NgPath 'logs\gamemode') 'etat.json'
if (Test-Path -LiteralPath $st) {
    $e = Get-Content -LiteralPath $st -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($e.Mode -eq 'jeu') { Invoke-Safe { & "$S\GameMode.ps1" -Mode Reprise } ; Pause-Ng }
}

while ($true) {
    Clear-Host
    Write-Host 'netguard-gaming : réseau, sécurité, fluidité en jeu' -ForegroundColor Cyan
    Write-Host "Utilisateur standard$(if (Test-NgAdmin) { ' (ATTENTION : console administrateur, inutile ici)' }). Ce qui demande l'admin est affiché, jamais lancé.`n"
    Write-Host '  1  Audit (lecture seule) + rapport HTML'
    Write-Host '  2  Ouvrir le rapport'
    Write-Host '  3  Appliquer un profil (simulation, puis OUI)'
    Write-Host '  4  Commandes manuelles / admin, revue du pare-feu'
    Write-Host '  5  Annuler une session'
    Write-Host '  6  Mode Jeu <-> Mode Normal'
    Write-Host '  7  Vérifier avant / après (mesures A/B)'
    Write-Host '  8  Auto-test (bac à sable)'
    Write-Host '  0  Quitter'
    $c = Read-Host "`nChoix"
    switch ($c) {
        '1' {
            Invoke-Safe {
                $lt = (Read-Host 'Test de charge vers speed.cloudflare.com (bufferbloat, 100 à 300 Mo) ? o/N') -eq 'o'
                if ($lt) { & "$S\Audit.ps1" -LoadTest } else { & "$S\Audit.ps1" }
                & "$S\New-AuditReport.ps1" -Open
            }
            Pause-Ng
        }
        '2' {
            $r = Get-NgPath 'reports\rapport_audit.html'
            if (Test-Path -LiteralPath $r) { Start-Process $r } else { Write-Host 'Pas encore de rapport : option 1.'; Pause-Ng }
        }
        '3' { Invoke-Safe { & "$S\Apply.ps1" -Profil (Select-Profil) }; Pause-Ng }
        '4' {
            Invoke-Safe {
                & "$S\Apply.ps1" -Manuel -Profil Avancé
                if ((Read-Host "`nRevoir les règles de pare-feu une par une ? o/N") -eq 'o') { & "$S\Apply.ps1" -PareFeu }
            }
            Pause-Ng
        }
        '5' {
            Invoke-Safe {
                & "$S\Undo.ps1" -Liste
                $n = Read-Host 'Nom de la session à annuler (Entrée = la plus récente non annulée)'
                if ($n) { & "$S\Undo.ps1" -Session $n } else { & "$S\Undo.ps1" }
            }
            Pause-Ng
        }
        '6' {
            Invoke-Safe {
                $e = $null; if (Test-Path -LiteralPath $st) { $e = Get-Content -LiteralPath $st -Raw -Encoding UTF8 | ConvertFrom-Json }
                if ($e -and $e.Mode -eq 'jeu') { & "$S\GameMode.ps1" -Mode Normal } else { & "$S\GameMode.ps1" -Mode Jeu }
            }
            Pause-Ng
        }
        '7' { if (Test-Path "$S\Verify.ps1") { Invoke-Safe { & "$S\Verify.ps1" } } else { Write-Host 'Verify.ps1 arrive en Phase 4.' }; Pause-Ng }
        '8' { if (Test-Path "$S\Test-NetGuard.ps1") { Invoke-Safe { & "$S\Test-NetGuard.ps1" } } else { Write-Host 'Test-NetGuard.ps1 arrive en Phase 4.' }; Pause-Ng }
        '0' { return }
        default { }
    }
}
