# Generate TOTP secret for Dynamic SPA (Windows PowerShell)
# Usage: .\scripts\generate-totp-secret.ps1 [output_file]

param(
    [string]$OutputFile = "keys\totp_secret.txt"
)

# Create keys directory if it doesn't exist
$keyDir = Split-Path -Parent $OutputFile
if (-not (Test-Path $keyDir)) {
    New-Item -ItemType Directory -Path $keyDir | Out-Null
}

# Generate 32-byte random secret (base64 encoded)
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$secret = [Convert]::ToBase64String($bytes)

# Write to file
$secret | Out-File -FilePath $OutputFile -Encoding ASCII -NoNewline

# Set file permissions (Windows)
$acl = Get-Acl $OutputFile
$permission = $env:USERNAME,"FullControl","Allow"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.SetAccessRule($accessRule)
Set-Acl $OutputFile $acl

Write-Host "TOTP secret generated: $OutputFile"
Write-Host "Secret length: $($secret.Length) characters"
Write-Host ""
Write-Host "IMPORTANT:"
Write-Host "1. Copy this secret to all clients"
Write-Host "2. Keep it secure"
Write-Host "3. Server and clients must use the SAME secret"

