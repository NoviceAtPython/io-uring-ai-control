[CmdletBinding()]
param(
    [string]$CloudflareTokenPath = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\cloudflare-deploy.token',
    [string]$OutputPath = 'C:\Users\aedyn\Downloads\io-uring-ai-control\secrets\telegram-chat.id'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$accountId = 'b6cab373d3dec5d96e3e47f521a83f70'
$databaseId = '89b508d4-9771-4b06-b009-f1df0aae4890'

$token = [System.IO.File]::ReadAllText($CloudflareTokenPath)
if (-not [regex]::IsMatch($token, '\A[A-Za-z0-9_-]{32,4096}\z')) {
    throw 'Cloudflare deployment token failed strict validation.'
}

$client = [System.Net.Http.HttpClient]::new()
$temporary = $null
try {
    $client.Timeout = [TimeSpan]::FromSeconds(30)
    $client.DefaultRequestHeaders.Authorization =
        [System.Net.Http.Headers.AuthenticationHeaderValue]::new('Bearer', $token)
    $requestBody = @{
        sql = 'SELECT chat_id FROM telegram_recipient WHERE singleton = 1'
        params = @()
    } | ConvertTo-Json -Compress
    $content = [System.Net.Http.StringContent]::new(
        $requestBody,
        [System.Text.Encoding]::UTF8,
        'application/json'
    )
    try {
        $response = $client.PostAsync(
            "https://api.cloudflare.com/client/v4/accounts/$accountId/d1/database/$databaseId/query",
            $content
        ).GetAwaiter().GetResult()
        try {
            $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
            try { $document = $body | ConvertFrom-Json }
            catch { throw 'D1 recipient export returned invalid JSON.' }
            if (-not $response.IsSuccessStatusCode -or $document.success -ne $true) {
                throw 'D1 recipient export failed.'
            }
        }
        finally {
            $response.Dispose()
        }
    }
    finally {
        $content.Dispose()
        $requestBody = $null
    }

    $rows = @($document.result[0].results)
    if ($rows.Count -ne 1) {
        throw 'D1 recipient export requires exactly one binding.'
    }
    $chatId = [string]$rows[0].chat_id
    if (-not [regex]::IsMatch($chatId, '\A[1-9][0-9]{0,18}\z')) {
        throw 'D1 recipient binding failed strict validation.'
    }

    $directory = Split-Path -Parent $OutputPath
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        throw 'Telegram handoff output directory is unavailable.'
    }
    $temporary = Join-Path $directory ('.telegram-chat.' + [guid]::NewGuid().ToString('N') + '.tmp')
    [System.IO.File]::WriteAllText(
        $temporary,
        $chatId,
        [System.Text.Encoding]::ASCII
    )
    Move-Item -LiteralPath $temporary -Destination $OutputPath -Force
    $temporary = $null

    [pscustomobject]@{
        recipient_binding_exported = $true
        value_disclosed = $false
        character_count = $chatId.Length
    } | ConvertTo-Json -Compress
}
finally {
    if ($null -ne $temporary -and (Test-Path -LiteralPath $temporary)) {
        Remove-Item -LiteralPath $temporary -Force
    }
    $chatId = $null
    $token = $null
    $client.Dispose()
}
