param(
  [string]$Remote = "origin",
  [string]$Branch = "",
  [string]$MonitorUrl = "https://owsdatabase.onrender.com/status",
  [int]$HealthTimeoutSec = 600,
  [int]$PollSec = 10,
  [switch]$SkipPush,
  [string]$RenderServiceId = "",
  [string]$RenderApiKey = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step([string]$Message) {
  Write-Host "[push-monitor] $Message" -ForegroundColor Cyan
}

function Write-WarnMsg([string]$Message) {
  Write-Host "[push-monitor] $Message" -ForegroundColor Yellow
}

function Write-ErrMsg([string]$Message) {
  Write-Host "[push-monitor] $Message" -ForegroundColor Red
}

function Invoke-Git([string]$GitArgs) {
  $tmpOut = [System.IO.Path]::GetTempFileName()
  $tmpErr = [System.IO.Path]::GetTempFileName()
  try {
    $p = Start-Process -FilePath "cmd.exe" -ArgumentList "/c git $GitArgs" -NoNewWindow -Wait -PassThru -RedirectStandardOutput $tmpOut -RedirectStandardError $tmpErr
    $stdout = if (Test-Path $tmpOut) { Get-Content -Path $tmpOut -Raw } else { "" }
    $stderr = if (Test-Path $tmpErr) { Get-Content -Path $tmpErr -Raw } else { "" }
    $combined = @($stdout, $stderr) -join ""
    $code = $p.ExitCode
  } finally {
    if (Test-Path $tmpOut) { Remove-Item $tmpOut -Force -ErrorAction SilentlyContinue }
    if (Test-Path $tmpErr) { Remove-Item $tmpErr -Force -ErrorAction SilentlyContinue }
  }
  return @{
    Output = $combined.Trim()
    ExitCode = $code
  }
}

function Try-GetJson([string]$Url, [hashtable]$Headers = @{}) {
  try {
    $res = Invoke-RestMethod -Uri $Url -Headers $Headers -Method Get -TimeoutSec 25
    return @{ Ok = $true; Data = $res; Raw = ($res | ConvertTo-Json -Depth 10) }
  } catch {
    $raw = ""
    try {
      if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream()) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $raw = $reader.ReadToEnd()
      } else {
        $raw = $_.Exception.Message
      }
    } catch {
      $raw = $_.Exception.Message
    }
    return @{ Ok = $false; Data = $null; Raw = $raw; Error = $_.Exception.Message }
  }
}

function Resolve-Branch() {
  if ($Branch -and $Branch.Trim()) {
    return $Branch.Trim()
  }
  $r = Invoke-Git "rev-parse --abbrev-ref HEAD"
  if ($r.ExitCode -ne 0) {
    throw "No se pudo detectar la rama actual: $($r.Output)"
  }
  return $r.Output.Trim()
}

function Get-RenderDeployInfo([string]$ServiceId, [string]$ApiKey) {
  if (-not $ServiceId -or -not $ApiKey) {
    return $null
  }
  $url = "https://api.render.com/v1/services/$ServiceId/deploys?limit=1"
  $headers = @{ Authorization = "Bearer $ApiKey" }
  $res = Try-GetJson -Url $url -Headers $headers
  if (-not $res.Ok) {
    return @{ Ok = $false; Error = $res.Error; Raw = $res.Raw }
  }
  $item = $null
  if ($res.Data -is [System.Array]) {
    if ($res.Data.Count -gt 0) { $item = $res.Data[0] }
  } elseif ($res.Data.deploy) {
    $item = $res.Data.deploy
  } elseif ($res.Data.deploys -and $res.Data.deploys.Count -gt 0) {
    $item = $res.Data.deploys[0]
  } else {
    $item = $res.Data
  }
  return @{ Ok = $true; Data = $item }
}

function Test-StatusHealthy($statusData) {
  if (-not $statusData) { return $false }
  if ($statusData.status -ne "ok") { return $false }
  if ($statusData.services -and $statusData.services.database) {
    return ($statusData.services.database.status -eq "up")
  }
  return $true
}

try {
  Write-Step "Validando repositorio git..."
  $inside = Invoke-Git "rev-parse --is-inside-work-tree"
  if ($inside.ExitCode -ne 0) {
    throw "No estas dentro de un repositorio git valido. Detalle: $($inside.Output)"
  }

  $targetBranch = Resolve-Branch
  Write-Step "Rama detectada: $targetBranch"

  if (-not $SkipPush) {
    Write-Step "Ejecutando git push ($Remote $targetBranch)..."
    $push = Invoke-Git "push $Remote $targetBranch"
    if ($push.ExitCode -ne 0) {
      Write-ErrMsg "git push fallo."
      Write-Host $push.Output
      exit 1
    }
    Write-Step "git push completado."
  } else {
    Write-WarnMsg "SkipPush activo: se omite git push."
  }

  $svcId = if ($RenderServiceId) { $RenderServiceId } else { $env:RENDER_SERVICE_ID }
  $apiKey = if ($RenderApiKey) { $RenderApiKey } else { $env:RENDER_API_KEY }
  if ($svcId -and $apiKey) {
    Write-Step "Monitoreo Render API habilitado (servicio: $svcId)."
  } else {
    Write-WarnMsg "Monitoreo Render API no configurado (faltan RENDER_SERVICE_ID/RENDER_API_KEY). Se usa solo health endpoint."
  }

  Write-Step "Monitoreando disponibilidad en: $MonitorUrl"
  $deadline = (Get-Date).AddSeconds($HealthTimeoutSec)
  $stableHits = 0
  $lastRaw = ""
  $lastRenderState = ""

  while ((Get-Date) -lt $deadline) {
    $statusRes = Try-GetJson -Url $MonitorUrl
    $renderInfo = Get-RenderDeployInfo -ServiceId $svcId -ApiKey $apiKey

    if ($renderInfo -and $renderInfo.Ok -and $renderInfo.Data) {
      $r = $renderInfo.Data
      $lastRenderState = "status=$($r.status) commit=$($r.commit.id) createdAt=$($r.createdAt)"
      Write-Step ("Render deploy: " + $lastRenderState)
      if ($r.status -match "failed|canceled|cancelled") {
        Write-ErrMsg "Render reporta un deploy fallido/cancelado."
        if ($statusRes.Raw) {
          Write-Host "`n--- Status endpoint response ---"
          Write-Host $statusRes.Raw
        }
        exit 1
      }
    } elseif ($renderInfo -and -not $renderInfo.Ok) {
      Write-WarnMsg "No se pudo leer Render API: $($renderInfo.Error)"
    }

    if ($statusRes.Ok -and (Test-StatusHealthy $statusRes.Data)) {
      $stableHits++
      Write-Step "Health check OK ($stableHits/2)..."
      if ($stableHits -ge 2) {
        Write-Host ""
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "Push + monitoreo completados correctamente." -ForegroundColor Green
        if ($lastRenderState) { Write-Host "Render: $lastRenderState" -ForegroundColor Green }
        Write-Host "========================================" -ForegroundColor Green
        exit 0
      }
    } else {
      $stableHits = 0
      $lastRaw = if ($statusRes.Raw) { $statusRes.Raw } else { $statusRes.Error }
      Write-WarnMsg "Health check aun no estable. Reintentando en $PollSec s..."
    }

    Start-Sleep -Seconds $PollSec
  }

  Write-ErrMsg "Timeout de monitoreo ($HealthTimeoutSec s)."
  if ($lastRenderState) {
    Write-Host "`nUltimo estado Render: $lastRenderState"
  }
  if ($lastRaw) {
    Write-Host "`n--- Ultima respuesta de estado ---"
    Write-Host $lastRaw
  }
  exit 1
}
catch {
  Write-ErrMsg $_.Exception.Message
  exit 1
}
