[CmdletBinding()]
param(
    [string]$CloudflareTokenPath = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\cloudflare-deploy.token',
    [string]$TelegramBotTokenPath = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\telegram-bot.token',
    [string]$TelegramWebhookSecretPath = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\telegram-webhook.secret'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$accountId = 'b6cab373d3dec5d96e3e47f521a83f70'
$databaseId = '89b508d4-9771-4b06-b009-f1df0aae4890'
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

function Read-CloudflareResponse(
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

function Invoke-D1Query(
    [System.Net.Http.HttpClient]$Client,
    [string]$Sql,
    [object[]]$Parameters,
    [string]$Operation
) {
    $body = @{ sql = $Sql; params = $Parameters } | ConvertTo-Json -Depth 4 -Compress
    $content = [System.Net.Http.StringContent]::new(
        $body,
        [System.Text.Encoding]::UTF8,
        'application/json'
    )
    try {
        $response = $Client.PostAsync(
            "https://api.cloudflare.com/client/v4/accounts/$accountId/d1/database/$databaseId/query",
            $content
        ).GetAwaiter().GetResult()
        try {
            return Read-CloudflareResponse $response $Operation
        }
        finally {
            $response.Dispose()
        }
    }
    finally {
        $content.Dispose()
        $body = $null
    }
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

$cloudflareToken = Read-ExactSecret $CloudflareTokenPath '[A-Za-z0-9_-]{32,4096}' 'Cloudflare deployment token'
$telegramBotToken = Read-ExactSecret $TelegramBotTokenPath '[0-9]{6,20}:[A-Za-z0-9_-]{30,}' 'Telegram bot token'
$telegramWebhookSecret = Read-ExactSecret $TelegramWebhookSecretPath '[A-Za-z0-9_-]{64}' 'Telegram webhook secret'

$cloudflare = [System.Net.Http.HttpClient]::new()
$telegram = [System.Net.Http.HttpClient]::new()
$public = [System.Net.Http.HttpClient]::new()
try {
    $cloudflare.Timeout = [TimeSpan]::FromSeconds(30)
    $telegram.Timeout = [TimeSpan]::FromSeconds(30)
    $public.Timeout = [TimeSpan]::FromSeconds(30)
    $cloudflare.DefaultRequestHeaders.Authorization =
        [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $cloudflareToken)
    $telegram.DefaultRequestHeaders.UserAgent.ParseAdd('iou-ai-telegram-bootstrap/0.1.16')

    $updatesBody = @{
        allowed_updates = @('message')
        limit = 10
        timeout = 0
    } | ConvertTo-Json -Compress
    $updatesContent = [System.Net.Http.StringContent]::new(
        $updatesBody,
        [System.Text.Encoding]::UTF8,
        'application/json'
    )
    try {
        try {
            $updatesResponse = $telegram.PostAsync(
                "https://api.telegram.org/bot$telegramBotToken/getUpdates",
                $updatesContent
            ).GetAwaiter().GetResult()
        }
        catch {
            throw 'Telegram private-chat discovery connection failed.'
        }
        try {
            $updates = Read-TelegramResponse $updatesResponse 'Telegram private-chat discovery'
        }
        finally {
            $updatesResponse.Dispose()
        }
    }
    finally {
        $updatesContent.Dispose()
        $updatesBody = $null
    }

    $candidates = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    foreach ($update in @($updates.result)) {
        $message = $update.message
        if ($null -eq $message) { continue }
        $chatText = [string]$message.chat.id
        $fromText = [string]$message.from.id
        $chatId = 0L
        $fromId = 0L
        $updateId = 0L
        if (
            -not [long]::TryParse([string]$update.update_id, [ref]$updateId) -or $updateId -lt 0 -or
            [string]$message.chat.type -cne 'private' -or
            -not [long]::TryParse($chatText, [ref]$chatId) -or $chatId -le 0 -or
            -not [long]::TryParse($fromText, [ref]$fromId) -or $fromId -ne $chatId -or
            $message.from.is_bot -eq $true -or
            -not [regex]::IsMatch([string]$message.text, '\A/start(?:@[A-Za-z0-9_]{5,32})?\z')
        ) {
            continue
        }
        [void]$candidates.Add($chatText)
    }
    if ($candidates.Count -ne 1) {
        throw 'Telegram pairing requires exactly one valid private /start sender.'
    }
    $candidateChatId = @($candidates)[0]

    $existing = Invoke-D1Query -Client $cloudflare `
        -Sql 'SELECT chat_id FROM telegram_recipient WHERE singleton = 1' `
        -Parameters @() -Operation 'D1 recipient lookup'
    $existingRows = @($existing.result[0].results)
    if ($existingRows.Count -gt 1) {
        throw 'D1 recipient binding is not singular.'
    }
    $bindingStatus = 'already_matched'
    if ($existingRows.Count -eq 1) {
        if ([string]$existingRows[0].chat_id -cne $candidateChatId) {
            throw 'D1 is already bound to a different Telegram recipient.'
        }
    }
    else {
        $pairedAt = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        $insert = Invoke-D1Query -Client $cloudflare `
            -Sql 'INSERT INTO telegram_recipient(singleton,chat_id,paired_at) VALUES(1,?,?)' `
            -Parameters @($candidateChatId, $pairedAt) `
            -Operation 'D1 recipient binding'
        if ([int]$insert.result[0].meta.changes -ne 1) {
            throw 'D1 recipient binding did not commit exactly once.'
        }
        $bindingStatus = 'created'
    }

    $verify = Invoke-D1Query -Client $cloudflare `
        -Sql 'SELECT chat_id FROM telegram_recipient WHERE singleton = 1' `
        -Parameters @() -Operation 'D1 recipient verification'
    $verifiedRows = @($verify.result[0].results)
    if ($verifiedRows.Count -ne 1 -or [string]$verifiedRows[0].chat_id -cne $candidateChatId) {
        throw 'D1 recipient verification failed.'
    }

    $webhookBody = @{
        allowed_updates = @('callback_query')
        secret_token = $telegramWebhookSecret
        url = "$workerUrl/webhooks/telegram"
    } | ConvertTo-Json -Compress
    $webhookContent = [System.Net.Http.StringContent]::new(
        $webhookBody,
        [System.Text.Encoding]::UTF8,
        'application/json'
    )
    try {
        try {
            $webhookResponse = $telegram.PostAsync(
                "https://api.telegram.org/bot$telegramBotToken/setWebhook",
                $webhookContent
            ).GetAwaiter().GetResult()
        }
        catch {
            throw 'Telegram callback webhook connection failed.'
        }
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

    $health = $public.GetAsync("$workerUrl/healthz").GetAwaiter().GetResult()
    try {
        $healthBody = $health.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if ([int]$health.StatusCode -ne 200 -or $healthBody -cne '{"status":"ready"}') {
            throw 'Relay did not become ready after the recipient binding.'
        }
    }
    finally {
        $health.Dispose()
    }

    [pscustomobject]@{
        telegram_update_candidates = 1
        recipient_binding = $bindingStatus
        callback_webhook = 'configured'
        public_health = '200 ready'
        secret_values_disclosed = $false
        relay_timers_changed = $false
    } | ConvertTo-Json -Compress
}
finally {
    $candidateChatId = $null
    $cloudflareToken = $null
    $telegramBotToken = $null
    $telegramWebhookSecret = $null
    $cloudflare.Dispose()
    $telegram.Dispose()
    $public.Dispose()
}
