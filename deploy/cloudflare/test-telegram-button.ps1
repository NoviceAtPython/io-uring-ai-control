[CmdletBinding()]
param(
    [string]$TelegramBotTokenPath = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\telegram-bot.token',
    [string]$ChatIdPath = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\telegram-chat.id'
)
# Sends ONE diagnostic message with an Approve button whose code is fake
# (AAAAAAAA). Tapping it exercises the relay's answerCallbackQuery path without
# recording any real decision: a working relay resolves the button to a popup
# alert ("Approval window expired."); a broken one leaves it glowing.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$tok  = ([System.IO.File]::ReadAllText($TelegramBotTokenPath)).Trim()
$chat = ([System.IO.File]::ReadAllText($ChatIdPath)).Trim()
try {
    $text = 'Approval-loop diagnostic. Tap the Approve button below. If it resolves to a small popup alert, the acknowledgment path works. If it keeps glowing, answerCallbackQuery is failing on the relay.'
    $body = "{""chat_id"":""$chat"",""text"":""$text"",""reply_markup"":{""inline_keyboard"":[[{""text"":""Approve (diagnostic)"",""callback_data"":""iou-ai:approve:AAAAAAAA""}]]}}"
    $r = Invoke-RestMethod -Method Post -Uri "https://api.telegram.org/bot$tok/sendMessage" -ContentType 'application/json; charset=utf-8' -Body $body -TimeoutSec 30
    "SENT ok=$($r.ok) message_id=$($r.result.message_id) chat=$chat"
}
catch { "SEND FAILED: " + $_.Exception.Message }
finally { $tok = $null }
