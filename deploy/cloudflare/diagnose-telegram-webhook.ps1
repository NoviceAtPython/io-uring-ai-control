[CmdletBinding()]
param(
    [string]$TelegramBotTokenPath = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\telegram-bot.token',
    [string]$WorkerUrl = 'https://iou-ai-notify-relay.aedyn11107.workers.dev'
)
# READ-ONLY diagnostic. Calls Telegram getWebhookInfo + the Worker health/ready
# endpoints and prints only non-secret status fields. Never prints the token.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if (-not (Test-Path -LiteralPath $TelegramBotTokenPath -PathType Leaf)) {
    throw "Telegram bot token file not found: $TelegramBotTokenPath"
}
$tok = ([System.IO.File]::ReadAllText($TelegramBotTokenPath)).Trim()
try {
    Write-Output '=== Telegram getWebhookInfo ==='
    $resp = Invoke-RestMethod -Method Get -Uri "https://api.telegram.org/bot$tok/getWebhookInfo" -TimeoutSec 30
    $i = $resp.result
    [pscustomobject]@{
        url                    = $i.url
        ip_address             = $i.ip_address
        pending_update_count   = $i.pending_update_count
        max_connections        = $i.max_connections
        allowed_updates        = (@($i.allowed_updates) -join ',')
        has_custom_certificate = $i.has_custom_certificate
        last_error_date        = if ($i.last_error_date)                { [datetimeoffset]::FromUnixTimeSeconds([int64]$i.last_error_date).ToString('u') } else { '(none)' }
        last_error_message     = if ($i.last_error_message)             { $i.last_error_message } else { '(none)' }
        last_sync_error_date   = if ($i.last_synchronization_error_date){ [datetimeoffset]::FromUnixTimeSeconds([int64]$i.last_synchronization_error_date).ToString('u') } else { '(none)' }
    } | Format-List
}
finally { $tok = $null }

Write-Output '=== Worker /healthz (public) ==='
try { Invoke-RestMethod -Method Get -Uri "$WorkerUrl/healthz" -TimeoutSec 20 | ConvertTo-Json -Compress | Write-Output }
catch { Write-Output "healthz error: $($_.Exception.Message)" }
