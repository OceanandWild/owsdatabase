# =============================================================================
# OWS Work Sessions - cliente PowerShell
#
# La skill `skills/ows-work-sessions.txt` esta escrita para bash y referencia
# scripts/ows-session.sh + ows-auto-login.sh, que NO existen en esta maquina.
# Este es el equivalente para Windows.
#
# Usa el flujo de DISPOSITIVO DE CONFIANZA (trust_token, ~30 dias) en vez del
# login de 3 pasos: no hay desafio numerico ni refresh cada 2h. El JWT se pide
# en cada invocacion y vive solo en memoria del proceso.
#
#   .\scripts\ows-session.ps1 projects
#   .\scripts\ows-session.ps1 list
#   .\scripts\ows-session.ps1 start "Titulo" "Detalles" 133
#   .\scripts\ows-session.ps1 group <sid> "Hub de 4 cards" rework "Nota"
#   .\scripts\ows-session.ps1 change <sid> "Texto" grande 0 "hub-de-4-cards"
#   .\scripts\ows-session.ps1 stop <sid> 0 complete
#
# Credenciales: secrets/ows-admin-auth.json (device_id + trust_token).
# NUNCA se imprimen ni se pasan por argumentos.
# =============================================================================

param(
    [Parameter(Mandatory = $true, Position = 0)][string]$Command,
    [Parameter(Position = 1)][string]$Arg1,
    [Parameter(Position = 2)][string]$Arg2,
    [Parameter(Position = 3)][string]$Arg3,
    [Parameter(Position = 4)][string]$Arg4,
    [Parameter(Position = 5)][string]$Arg5
)

$ErrorActionPreference = 'Stop'

# Render en free tier: el cold start puede pasar de 30s. Nada de timeouts cortos.
$Base = 'https://owsdatabase.onrender.com'
$AdminName = 'OceanandWild'
$TzOffset = -180          # Uruguay (UTC-3)
$Timeout = 120
$Secrets = Join-Path (Split-Path $PSScriptRoot -Parent) 'secrets'

function Get-Headers {
    param([string]$Jwt = $null)
    $h = @{ accept = 'application/json'; 'x-ows-admin-name' = $AdminName }
    if ($Jwt) { $h['x-ows-admin-token'] = $Jwt }
    return $h
}

function Invoke-Api {
    param([string]$Path, [string]$Method = 'GET', $Payload = $null, [string]$Jwt = $null)
    $p = @{ Uri = "$Base$Path"; Method = $Method; TimeoutSec = $Timeout; Headers = (Get-Headers $Jwt) }
    if ($null -ne $Payload) {
        $p.Body = ($Payload | ConvertTo-Json -Depth 6)
        $p.ContentType = 'application/json'
    }
    Invoke-RestMethod @p
}

function Get-Jwt {
    # Dispositivo de confianza: sin contrasena, sin desafio numerico.
    $authPath = Join-Path $Secrets 'ows-admin-auth.json'
    if (-not (Test-Path $authPath)) { throw "Falta $authPath" }
    $auth = Get-Content $authPath -Raw | ConvertFrom-Json
    $r = Invoke-Api -Path '/ows-admin-panel/login-with-device' -Method POST `
        -Payload @{ device_id = $auth.device_id; trust_token = $auth.trust_token }
    $jwt = $r.token
    if (-not $jwt) { $jwt = $r.jwt }
    if (-not $jwt) { throw "login-with-device no devolvio token" }
    return $jwt
}

switch ($Command) {

    'projects' {
        $r = Invoke-Api -Path '/ows-launch-projects?include_hidden=1'
        $list = if ($r -is [array]) { $r } else { $r.projects }
        $list | Select-Object id, slug, name, admin_only | Format-Table -AutoSize
    }

    'list' {
        $jwt = Get-Jwt
        $r = Invoke-Api -Path "/ows-work-sessions?limit=20&tz_offset=$TzOffset" -Jwt $jwt
        $list = if ($r -is [array]) { $r } else { $r.sessions }
        $list | Select-Object id, project_id, title, status, created_at |
            Format-Table -AutoSize -Wrap
    }

    'start' {
        if (-not $Arg1 -or -not $Arg3) { throw 'uso: start "Titulo" "Detalles" <projectId>' }
        $jwt = Get-Jwt
        $r = Invoke-Api -Path '/ows-work-sessions' -Method POST -Jwt $jwt -Payload @{
            project_id = [int]$Arg3
            title      = $Arg1
            details    = $Arg2
            realtime   = $true
            tz_offset  = $TzOffset
            created_by = $AdminName
        }
        $id = $r.id
        if (-not $id -and $r.session) { $id = $r.session.id }
        "SESSION_ID=$id"
    }

    'group' {
        if (-not $Arg1 -or -not $Arg2 -or -not $Arg3) { throw 'uso: group <sid> "Nombre" rework|major "Nota"' }
        $jwt = Get-Jwt
        $r = Invoke-Api -Path "/ows-work-sessions/$Arg1/reworks" -Method POST -Jwt $jwt -Payload @{
            name = $Arg2
            kind = $Arg3      # rework | major
            note = $Arg4
        }
        $key = $r.key
        if (-not $key -and $r.rework) { $key = $r.rework.key }
        "GROUP_KEY=$key"
    }

    'change' {
        # uso: change <sid> "Texto" chico|mediano|grande|critico <delta> [reworkName]
        if (-not $Arg1 -or -not $Arg2) { throw 'uso: change <sid> "Texto" <kind> <delta> [reworkName]' }
        $jwt = Get-Jwt
        $payload = @{
            text           = $Arg2
            kind           = $Arg3
            progress_delta = if ($Arg4) { [int]$Arg4 } else { 0 }
        }
        if ($Arg5) { $payload.rework_name = $Arg5 }
        $r = Invoke-Api -Path "/ows-work-sessions/$Arg1/changes" -Method POST -Jwt $jwt -Payload $payload
        "OK change"
    }

    'stop' {
        # uso: stop <sid> <delta> complete|paused|incomplete ["motivo"]
        $jwt = Get-Jwt
        $p = @{
            progress_delta = if ($Arg2) { [int]$Arg2 } else { 0 }
            completion     = if ($Arg3) { $Arg3 } else { 'complete' }
        }
        if ($p.completion -ne 'complete') { $p.incomplete_reason = $Arg4 }
        $r = Invoke-Api -Path "/ows-work-sessions/$Arg1/stop" -Method POST -Jwt $jwt -Payload $p
        $pct = 'n/d'
        if ($r.development) { $pct = $r.development.percent }
        "STOPPED  development.percent=$pct"
    }

    'daily' {
        # uso: daily <projectId> [YYYY-MM-DD]
        # Publica el devlog del dia. El servidor calcula local = UTC + tz_offset,
        # asi que la fecha va en hora Uruguaya, no en la local de la maquina.
        if (-not $Arg1) { throw 'uso: daily <projectId> [YYYY-MM-DD]' }
        $jwt = Get-Jwt
        $date = $Arg2
        if (-not $date) {
            $date = [DateTime]::UtcNow.AddMinutes($TzOffset).ToString('yyyy-MM-dd')
        }
        $r = Invoke-Api -Path '/ows-work-sessions/daily' -Method POST -Jwt $jwt -Payload @{
            date       = $date
            project_id = [int]$Arg1
            tz_offset  = $TzOffset
            created_by = $AdminName
        }
        "DEVLOG publicado para $date"
    }

    default { throw "Comando desconocido: $Command" }
}
