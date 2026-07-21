[CmdletBinding()]
param(
    [string]$TokenPath = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\cloudflare-deploy.token',
    [string]$WorkerSource = 'C:\Users\aedyn\Downloads\io-uring-ai-control\relay\cloudflare\src\index.js'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$accountId = 'b6cab373d3dec5d96e3e47f521a83f70'
$databaseId = '89b508d4-9771-4b06-b009-f1df0aae4890'
$scriptName = 'iou-ai-notify-relay'
# Bumped to the current reviewed index.js (11/11 relay tests pass; callback-ack
# and v2 execution-approval paths reviewed). The prior pin (0f9e9988...) predated
# GPT's edits, so every redeploy silently refused and the live Worker went stale.
$expectedWorkerSha256 = '4a58a70dc0d7e41a27c0e1dd6d9961ed78d31b5598daad65ef3f93251962f7d3'
$workerUrl = 'https://iou-ai-notify-relay.aedyn11107.workers.dev'

function Read-CloudflareToken([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw 'Cloudflare deployment token file is unavailable.'
    }
    $value = [System.IO.File]::ReadAllText($Path)
    if ($value -cnotmatch '^[A-Za-z0-9_-]{32,4096}$') {
        throw 'Cloudflare deployment token is not one valid opaque line.'
    }
    return $value
}

function Read-CloudflareJsonResponse(
    [System.Net.Http.HttpResponseMessage]$Response,
    [string]$Operation
) {
    $body = $Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    try {
        $document = $body | ConvertFrom-Json
    }
    catch {
        throw "$Operation returned an invalid JSON response (HTTP $([int]$Response.StatusCode))."
    }
    if (-not $Response.IsSuccessStatusCode -or $document.success -ne $true) {
        $codes = @($document.errors | ForEach-Object { [string]$_.code }) -join ','
        if (-not $codes) { $codes = 'none' }
        throw "$Operation failed (HTTP $([int]$Response.StatusCode), Cloudflare codes: $codes)."
    }
    return $document
}

$workerHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $WorkerSource).Hash.ToLowerInvariant()
if ($workerHash -cne $expectedWorkerSha256) {
    throw 'Reviewed Worker source digest changed; refusing deployment.'
}

$token = Read-CloudflareToken $TokenPath
$authenticatedClient = [System.Net.Http.HttpClient]::new()
$publicClient = [System.Net.Http.HttpClient]::new()
try {
    $authenticatedClient.Timeout = [TimeSpan]::FromSeconds(30)
    $authenticatedClient.DefaultRequestHeaders.Authorization =
        [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token)

    # Add only the one missing pairing table. CREATE IF NOT EXISTS is
    # intentionally idempotent and does not alter existing event or decision data.
    $migrationSql = @'
CREATE TABLE IF NOT EXISTS telegram_recipient (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    chat_id TEXT NOT NULL UNIQUE,
    paired_at TEXT NOT NULL
)
'@
    $migrationBody = @{ sql = $migrationSql; params = @() } | ConvertTo-Json -Compress
    $migrationContent = [System.Net.Http.StringContent]::new(
        $migrationBody,
        [System.Text.Encoding]::UTF8,
        'application/json'
    )
    try {
        $migrationResponse = $authenticatedClient.PostAsync(
            "https://api.cloudflare.com/client/v4/accounts/$accountId/d1/database/$databaseId/query",
            $migrationContent
        ).GetAwaiter().GetResult()
        try {
            $migrationResult = Read-CloudflareJsonResponse $migrationResponse 'D1 recipient-table migration'
        }
        finally {
            $migrationResponse.Dispose()
        }
    }
    finally {
        $migrationContent.Dispose()
    }

    $verificationBody = @{
        sql = "SELECT COUNT(*) AS table_count FROM sqlite_master WHERE type = 'table' AND name = 'telegram_recipient'"
        params = @()
    } | ConvertTo-Json -Compress
    $verificationContent = [System.Net.Http.StringContent]::new(
        $verificationBody,
        [System.Text.Encoding]::UTF8,
        'application/json'
    )
    try {
        $verificationResponse = $authenticatedClient.PostAsync(
            "https://api.cloudflare.com/client/v4/accounts/$accountId/d1/database/$databaseId/query",
            $verificationContent
        ).GetAwaiter().GetResult()
        try {
            $verificationResult = Read-CloudflareJsonResponse $verificationResponse 'D1 recipient-table verification'
        }
        finally {
            $verificationResponse.Dispose()
        }
    }
    finally {
        $verificationContent.Dispose()
    }
    if (
        @($verificationResult.result).Count -ne 1 -or
        @($verificationResult.result[0].results).Count -ne 1 -or
        [int]$verificationResult.result[0].results[0].table_count -ne 1
    ) {
        throw 'D1 recipient-table verification returned an unexpected result.'
    }

    $recipientBody = @{
        sql = 'SELECT COUNT(*) AS recipient_count FROM telegram_recipient'
        params = @()
    } | ConvertTo-Json -Compress
    $recipientContent = [System.Net.Http.StringContent]::new(
        $recipientBody,
        [System.Text.Encoding]::UTF8,
        'application/json'
    )
    try {
        $recipientResponse = $authenticatedClient.PostAsync(
            "https://api.cloudflare.com/client/v4/accounts/$accountId/d1/database/$databaseId/query",
            $recipientContent
        ).GetAwaiter().GetResult()
        try {
            $recipientResult = Read-CloudflareJsonResponse $recipientResponse 'D1 recipient verification'
        }
        finally {
            $recipientResponse.Dispose()
        }
    }
    finally {
        $recipientContent.Dispose()
    }
    if (
        @($recipientResult.result).Count -ne 1 -or
        @($recipientResult.result[0].results).Count -ne 1 -or
        [int]$recipientResult.result[0].results[0].recipient_count -notin @(0, 1)
    ) {
        throw 'D1 recipient verification returned an unexpected result.'
    }
    $recipientCount = [int]$recipientResult.result[0].results[0].recipient_count

    # Upload one ES module and explicitly preserve the sole D1 binding.
    $metadata = @{
        main_module = 'worker.js'
        compatibility_date = '2026-07-16'
        bindings = @(
            @{
                type = 'd1'
                name = 'DB'
                database_id = $databaseId
            }
        )
        annotations = @{
            'workers/message' = 'Deploy reviewed Telegram callback acknowledgement 0.1.16'
            'workers/tag' = 'iou-ai-relay-0.1.16'
        }
    } | ConvertTo-Json -Depth 8 -Compress

    $multipart = [System.Net.Http.MultipartFormDataContent]::new()
    try {
        $metadataPart = [System.Net.Http.StringContent]::new(
            $metadata,
            [System.Text.Encoding]::UTF8,
            'application/json'
        )
        $multipart.Add($metadataPart, 'metadata')

        $moduleBytes = [System.IO.File]::ReadAllBytes($WorkerSource)
        $modulePart = [System.Net.Http.ByteArrayContent]::new($moduleBytes)
        $modulePart.Headers.ContentType =
            [System.Net.Http.Headers.MediaTypeHeaderValue]::new('application/javascript+module')
        $multipart.Add($modulePart, 'worker.js', 'worker.js')

        $uploadResponse = $authenticatedClient.PutAsync(
            "https://api.cloudflare.com/client/v4/accounts/$accountId/workers/scripts/$scriptName`?bindings_inherit=strict",
            $multipart
        ).GetAwaiter().GetResult()
        try {
            $uploadResult = Read-CloudflareJsonResponse $uploadResponse 'Worker deployment'
        }
        finally {
            $uploadResponse.Dispose()
        }
    }
    finally {
        $multipart.Dispose()
    }

    # Strict binding inheritance preserves existing secrets. A paired relay
    # must stay ready across a reviewed code deployment; an unpaired relay must
    # remain in the canonical fail-closed state.
    $expectedHealthCode = if ($recipientCount -eq 1) { 200 } else { 503 }
    $expectedHealthBody = if ($recipientCount -eq 1) { '{"status":"ready"}' } else { '{"status":"not_ready"}' }
    $expectedHealthLabel = if ($recipientCount -eq 1) { '200 ready' } else { '503 not_ready' }
    $healthVerified = $false
    for ($attempt = 0; $attempt -lt 6; $attempt++) {
        $healthResponse = $publicClient.GetAsync("$workerUrl/healthz").GetAwaiter().GetResult()
        try {
            $healthBody = $healthResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ([int]$healthResponse.StatusCode -eq $expectedHealthCode -and $healthBody -ceq $expectedHealthBody) {
                $healthVerified = $true
                break
            }
        }
        finally {
            $healthResponse.Dispose()
        }
        Start-Sleep -Milliseconds 750
    }
    if (-not $healthVerified) {
        throw 'Deployed Worker did not reach the expected recipient-bound health state.'
    }

    [pscustomobject]@{
        worker = $scriptName
        worker_sha256 = $workerHash
        d1_recipient_table = 'present'
        public_health = $expectedHealthLabel
        relay_timers_changed = $false
    } | ConvertTo-Json -Compress
}
finally {
    $token = $null
    $authenticatedClient.Dispose()
    $publicClient.Dispose()
}
