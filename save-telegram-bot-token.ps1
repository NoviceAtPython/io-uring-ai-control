[CmdletBinding()]
param(
    [switch]$ReplaceExisting,
    [switch]$FromClipboard
)

$ErrorActionPreference = 'Stop'

$destination = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\telegram-bot.token'

if (-not $FromClipboard) {
    Write-Host '1. Leave this window open.'
    Write-Host '2. In the private BotFather chat, copy the bot API token.'
    Write-Host '3. Return here and press Enter.'
    [void](Read-Host)
}

$clipboardValue = Get-Clipboard
if ($clipboardValue -is [array]) {
    $clipboardValue = $clipboardValue -join "`n"
}
$token = ([string]$clipboardValue).Trim()

if ($token -cnotmatch '^[0-9]{6,20}:[A-Za-z0-9_-]{30,}$') {
    throw 'Clipboard does not contain one valid Telegram bot token. Nothing was saved.'
}

if ((Test-Path -LiteralPath $destination -PathType Leaf) -and -not $ReplaceExisting) {
    throw 'A Telegram bot token file already exists. Re-run with -ReplaceExisting only after rotating the token in BotFather.'
}

$temporary = "$destination.$PID.new"
try {
    Set-Content -LiteralPath $temporary -Value $token -NoNewline -Encoding ascii
    Move-Item -LiteralPath $temporary -Destination $destination -Force
    Set-Clipboard -Value ' '
    Write-Host ('Saved a rotated Telegram bot token ({0} characters) and cleared the clipboard.' -f $token.Length)
}
finally {
    if (Test-Path -LiteralPath $temporary -PathType Leaf) {
        Remove-Item -LiteralPath $temporary -Force
    }
    $token = $null
}
