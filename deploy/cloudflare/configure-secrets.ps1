[CmdletBinding()]
param(
    [string]$CloudflareTokenPath = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\cloudflare-deploy.token',
    [string]$RelayTokenPath = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\relay.token',
    [string]$DecisionKeyPath = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\decision.key',
    [string]$TelegramWebhookSecretPath = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\telegram-webhook.secret',
    [string]$TelegramBotTokenPath = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\telegram-bot.token'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Windows PowerShell 5.1 does not load System.Net.Http by default; PowerShell 7
# already has it. Load it best-effort so this runs under either.
try { Add-Type -AssemblyName System.Net.Http -ErrorAction Stop } catch { }

$accountId = 'b6cab373d3dec5d96e3e47f521a83f70'
$scriptName = 'iou-ai-notify-relay'
$workerUrl = 'https://iou-ai-notify-relay.aedyn11107.workers.dev'

function Read-ExactSecret(
    [string]$Path,
    [string]$Pattern,
    [string]$Label
) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Label file is unavailable."
    }
    $value = [System.IO.File]::ReadAllText($Path)
    if ($value -cnotmatch $Pattern) {
        throw "$Label file failed strict validation."
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
        throw "$Operation returned invalid JSON (HTTP $([int]$Response.StatusCode))."
    }
    if (-not $Response.IsSuccessStatusCode -or $document.success -ne $true) {
        $codes = @($document.errors | ForEach-Object { [string]$_.code }) -join ','
        if (-not $codes) { $codes = 'none' }
        throw "$Operation failed (HTTP $([int]$Response.StatusCode), Cloudflare codes: $codes)."
    }
    return $document
}

$cloudflareToken = Read-ExactSecret $CloudflareTokenPath '^[A-Za-z0-9_-]{32,4096}$' 'Cloudflare deployment token'
$relayToken = Read-ExactSecret $RelayTokenPath '^[A-Za-z0-9_-]{64}$' 'Relay bearer token'
$decisionKey = Read-ExactSecret $DecisionKeyPath '^[A-Za-z0-9_-]{64}$' 'Decision HMAC key'
$telegramWebhookSecret = Read-ExactSecret $TelegramWebhookSecretPath '^[A-Za-z0-9_-]{64}$' 'Telegram webhook secret'
$telegramBotToken = Read-ExactSecret $TelegramBotTokenPath '^[0-9]{6,20}:[A-Za-z0-9_-]{30,}$' 'Telegram bot token'

$secretBindings = [ordered]@{
    'RELAY_PROVIDER' = 'telegram'
    'TELEGRAM_DELIVERY_MODE' = 'host'
    'FUZZ_RELAY_TOKEN' = $relayToken
    'DECISION_HMAC_KEY' = $decisionKey
    'TELEGRAM_WEBHOOK_SECRET' = $telegramWebhookSecret
    'TELEGRAM_BOT_TOKEN' = $telegramBotToken
}
$requiredNames = @($secretBindings.Keys)

$authenticatedClient = [System.Net.Http.HttpClient]::new()
$publicClient = [System.Net.Http.HttpClient]::new()
try {
    $authenticatedClient.Timeout = [TimeSpan]::FromSeconds(30)
    $authenticatedClient.DefaultRequestHeaders.Authorization =
        [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $cloudflareToken)

    foreach ($bindingName in $requiredNames) {
        $requestBody = @{
            name = $bindingName
            text = $secretBindings[$bindingName]
            type = 'secret_text'
        } | ConvertTo-Json -Compress
        $content = [System.Net.Http.StringContent]::new(
            $requestBody,
            [System.Text.Encoding]::UTF8,
            'application/json'
        )
        try {
            $response = $authenticatedClient.PutAsync(
                "https://api.cloudflare.com/client/v4/accounts/$accountId/workers/scripts/$scriptName/secrets",
                $content
            ).GetAwaiter().GetResult()
            try {
                [void](Read-CloudflareJsonResponse $response "Worker secret $bindingName")
            }
            finally {
                $response.Dispose()
            }
        }
        finally {
            $content.Dispose()
            $requestBody = $null
        }
    }

    $listResponse = $authenticatedClient.GetAsync(
        "https://api.cloudflare.com/client/v4/accounts/$accountId/workers/scripts/$scriptName/secrets"
    ).GetAwaiter().GetResult()
    try {
        $listResult = Read-CloudflareJsonResponse $listResponse 'Worker secret verification'
    }
    finally {
        $listResponse.Dispose()
    }

    $installedNames = @($listResult.result | ForEach-Object { [string]$_.name })
    $missingNames = @($requiredNames | Where-Object { $_ -cnotin $installedNames })
    if ($missingNames.Count -ne 0) {
        throw ('Worker secret verification is missing required binding names: {0}.' -f ($missingNames -join ','))
    }

    # A new relay remains fail-closed until paired; an existing singular
    # pairing must remain ready across idempotent secret refreshes.
    $healthVerified = $false
    $healthLabel = $null
    for ($attempt = 0; $attempt -lt 6; $attempt++) {
        $healthResponse = $publicClient.GetAsync("$workerUrl/healthz").GetAwaiter().GetResult()
        try {
            $healthBody = $healthResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            if ([int]$healthResponse.StatusCode -eq 503 -and $healthBody -ceq '{"status":"not_ready"}') {
                $healthVerified = $true
                $healthLabel = '503 not_ready'
                break
            }
            if ([int]$healthResponse.StatusCode -eq 200 -and $healthBody -ceq '{"status":"ready"}') {
                $healthVerified = $true
                $healthLabel = '200 ready'
                break
            }
        }
        finally {
            $healthResponse.Dispose()
        }
        Start-Sleep -Milliseconds 750
    }
    if (-not $healthVerified) {
        throw 'Worker did not return a canonical paired or fail-closed health state after secret installation.'
    }

    [pscustomobject]@{
        worker = $scriptName
        required_secret_bindings = $requiredNames
        secret_values_disclosed = $false
        public_health = $healthLabel
        telegram_pairing_required = ($healthLabel -eq '503 not_ready')
        relay_timers_changed = $false
    } | ConvertTo-Json -Compress
}
finally {
    $cloudflareToken = $null
    $relayToken = $null
    $decisionKey = $null
    $telegramWebhookSecret = $null
    $telegramBotToken = $null
    $secretBindings = $null
    $authenticatedClient.Dispose()
    $publicClient.Dispose()
}
