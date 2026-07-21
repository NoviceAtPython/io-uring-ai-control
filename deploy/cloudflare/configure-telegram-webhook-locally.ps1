[CmdletBinding()]
param(
    [string]$TelegramBotTokenPath = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\telegram-bot.token',
    [string]$TelegramWebhookSecretPath = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\telegram-webhook.secret'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

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
    if (-not [regex]::IsMatch($value, "\A(?:$Pattern)\z")) {
        throw "$Label file failed strict validation."
    }
    return $value
}

function Read-TelegramResponse(
    [System.Net.Http.HttpResponseMessage]$Response,
    [string]$Operation
) {
    $body = $Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
    try {
        $document = $body | ConvertFrom-Json
    }
    catch {
        throw "$Operation returned an invalid response."
    }
    if (-not $Response.IsSuccessStatusCode -or $document.ok -ne $true) {
        throw "$Operation failed (HTTP $([int]$Response.StatusCode))."
    }
    return $document
}

$telegramBotToken = Read-ExactSecret `
    $TelegramBotTokenPath '[0-9]{6,20}:[A-Za-z0-9_-]{30,}' 'Telegram bot token'
$telegramWebhookSecret = Read-ExactSecret `
    $TelegramWebhookSecretPath '[A-Za-z0-9_-]{64}' 'Telegram webhook secret'

$telegram = [System.Net.Http.HttpClient]::new()
try {
    $telegram.Timeout = [TimeSpan]::FromSeconds(30)
    $telegram.DefaultRequestHeaders.UserAgent.ParseAdd('iou-ai-telegram-webhook/0.1.16')

    $webhookBody = @{
        allowed_updates = @('callback_query')
        drop_pending_updates = $false
        secret_token = $telegramWebhookSecret
        url = "$workerUrl/webhooks/telegram"
    } | ConvertTo-Json -Compress
    $webhookContent = [System.Net.Http.StringContent]::new(
        $webhookBody,
        [System.Text.Encoding]::UTF8,
        'application/json'
    )
    try {
        $webhookResponse = $telegram.PostAsync(
            "https://api.telegram.org/bot$telegramBotToken/setWebhook",
            $webhookContent
        ).GetAwaiter().GetResult()
        try {
            $webhook = Read-TelegramResponse $webhookResponse 'Telegram callback webhook setup'
        }
        finally {
            $webhookResponse.Dispose()
        }
    }
    finally {
        $webhookContent.Dispose()
        $webhookBody = $null
    }
    if ($webhook.result -ne $true) {
        throw 'Telegram callback webhook setup was not acknowledged.'
    }

    $statusResponse = $telegram.GetAsync(
        "https://api.telegram.org/bot$telegramBotToken/getWebhookInfo"
    ).GetAwaiter().GetResult()
    try {
        $status = Read-TelegramResponse $statusResponse 'Telegram callback webhook verification'
    }
    finally {
        $statusResponse.Dispose()
    }
    if (
        [string]$status.result.url -cne "$workerUrl/webhooks/telegram" -or
        @($status.result.allowed_updates).Count -ne 1 -or
        [string](@($status.result.allowed_updates)[0]) -cne 'callback_query'
    ) {
        throw 'Telegram callback webhook verification failed.'
    }

    [pscustomobject]@{
        callback_webhook = 'configured'
        pending_updates = [int]$status.result.pending_update_count
        public_endpoint = 'verified'
        secret_values_disclosed = $false
        pending_updates_dropped = $false
    } | ConvertTo-Json -Compress
}
finally {
    $telegramBotToken = $null
    $telegramWebhookSecret = $null
    $telegram.Dispose()
}
