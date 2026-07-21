[CmdletBinding()]
param(
    [string]$TelegramBotTokenPath = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\telegram-bot.token',
    [string]$WebhookSecretPath   = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\telegram-webhook.secret',
    [string]$ChatIdPath          = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\telegram-chat.id',
    [string]$WorkerUrl           = 'https://iou-ai-notify-relay.aedyn11107.workers.dev'
)
# DEFINITIVE isolation test. Temporarily removes the webhook, sends a button,
# waits for you to tap, then answers the callback DIRECTLY with the token file
# (bypassing the Worker). Prints Telegram's exact response. ALWAYS re-registers
# the webhook at the end. Never prints the token.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$base = "https://api.telegram.org/bot"

$tok    = ([System.IO.File]::ReadAllText($TelegramBotTokenPath)).Trim()
$secret = ([System.IO.File]::ReadAllText($WebhookSecretPath)).Trim()
$chat   = ([System.IO.File]::ReadAllText($ChatIdPath)).Trim()

function Post($method, $obj) {
    return Invoke-RestMethod -Method Post -Uri "$base$tok/$method" `
        -ContentType 'application/json; charset=utf-8' `
        -Body ($obj | ConvertTo-Json -Depth 6 -Compress) -TimeoutSec 30
}

try {
    Write-Output '=== 1. Removing webhook so getUpdates can read the tap ==='
    Post 'deleteWebhook' @{ drop_pending_updates = $false } | Out-Null

    # Drain any backlog to establish a clean offset.
    $drain = Post 'getUpdates' @{ timeout = 0 }
    $offset = 0
    if ($drain.result.Count -gt 0) { $offset = [int]$drain.result[-1].update_id + 1 }

    Write-Output '=== 2. Sending a fresh button. TAP "Approve (direct test)" in Telegram now. ==='
    Post 'sendMessage' @{
        chat_id = $chat
        text = 'DIRECT TOKEN TEST: tap the Approve button. This answer comes straight from your token file, bypassing the Worker.'
        reply_markup = @{ inline_keyboard = @(,@(@{ text = 'Approve (direct test)'; callback_data = 'iou-ai:approve:AAAAAAAA' })) }
    } | Out-Null

    Write-Output '=== 3. Waiting up to 60s for your tap... ==='
    $cbId = $null; $cbData = $null
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline -and -not $cbId) {
        $r = Post 'getUpdates' @{ timeout = 15; offset = $offset }
        foreach ($upd in $r.result) {
            $offset = [int]$upd.update_id + 1
            if ($upd.callback_query) { $cbId = $upd.callback_query.id; $cbData = $upd.callback_query.data }
        }
    }

    if (-not $cbId) {
        Write-Output 'RESULT: no callback received (did you tap in time?).'
    }
    else {
        Write-Output ("=== 4. Got callback (data=$cbData). Answering DIRECTLY with the token file... ===")
        try {
            $ans = Post 'answerCallbackQuery' @{ callback_query_id = $cbId; text = 'Direct token test OK'; show_alert = $true }
            Write-Output ('answerCallbackQuery RESPONSE: ' + ($ans | ConvertTo-Json -Compress))
            Write-Output 'If a popup "Direct token test OK" appeared -> the TOKEN is fine, the WORKER is the problem.'
        }
        catch {
            Write-Output ('answerCallbackQuery FAILED: ' + $_.Exception.Message)
            if ($_.ErrorDetails.Message) { Write-Output ('Telegram says: ' + $_.ErrorDetails.Message) }
            Write-Output 'A failure here means the token/callback itself is the problem, not the Worker.'
        }
    }
}
finally {
    Write-Output '=== 5. Re-registering the real webhook (always) ==='
    try {
        $re = Post 'setWebhook' @{
            url = "$WorkerUrl/webhooks/telegram"
            secret_token = $secret
            allowed_updates = @('callback_query')
            drop_pending_updates = $false
        }
        Write-Output ('webhook re-set ok=' + $re.ok)
    }
    catch {
        Write-Output ('WEBHOOK RE-SET FAILED: ' + $_.Exception.Message)
        Write-Output 'RESTORE MANUALLY: run configure-telegram-webhook-locally.ps1'
    }
    $tok = $null; $secret = $null
}
