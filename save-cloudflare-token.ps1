$ErrorActionPreference = 'Stop'

$destination = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\cloudflare-deploy.token'

Write-Host '1. Leave this window open.'
Write-Host '2. In the Cloudflare token tab, click Copy beside the raw one-time token.'
Write-Host '3. Return here and press Enter.'
[void](Read-Host)

$clipboardValue = Get-Clipboard
if ($clipboardValue -is [array]) {
    $clipboardValue = $clipboardValue -join "`n"
}
$token = ([string]$clipboardValue).Trim()

if ($token -cnotmatch '^[A-Za-z0-9_-]{32,4096}$') {
    throw 'Clipboard does not contain one valid opaque Cloudflare token. Nothing was saved.'
}

Set-Content -LiteralPath $destination -Value $token -NoNewline
Set-Clipboard -Value ' '
Write-Host ('Saved a valid token ({0} characters) and cleared the clipboard.' -f $token.Length)
