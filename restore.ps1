<#
  restore.ps1
  Reassembles the encrypted parts downloaded from GitHub back into the original
  "Day NN" folders. Run it from the SAME folder where the .enc.NNN parts live.

  Pipeline per day:  .enc.NNN parts -> join -> AES-256 decrypt -> .zip -> extract folders

  Usage:
    Right-click -> Run with PowerShell, or:
    .\restore.ps1                 # restores into the current folder
    .\restore.ps1 -OutDir "C:\somewhere"
#>
[CmdletBinding()]
param(
  [string]$PartsDir = $PSScriptRoot,
  [string]$OutDir   = $PSScriptRoot,
  [string]$Password
)

$ErrorActionPreference = "Stop"
if (-not $PartsDir) { $PartsDir = (Get-Location).Path }
if (-not $OutDir)   { $OutDir   = (Get-Location).Path }
$MAGIC_EXPECT = "FDEENC01"
$ITER = 200000

function Get-PlainPassword {
  $p = Read-Host "Enter decryption password" -AsSecureString
  $b = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($p)
  try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($b) }
  finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($b) }
}

function Join-Parts {
  param([string[]]$Parts, [string]$OutPath)
  $out = [System.IO.File]::Create($OutPath)
  try {
    foreach ($p in $Parts) {
      $in = [System.IO.File]::OpenRead($p)
      try { $in.CopyTo($out) } finally { $in.Dispose() }
    }
  } finally { $out.Dispose() }
}

function Decrypt-File {
  param([string]$InPath, [string]$OutPath, [string]$Password)
  $in = [System.IO.File]::OpenRead($InPath)
  try {
    $magic = New-Object byte[] 8; [void]$in.Read($magic,0,8)
    if ([System.Text.Encoding]::ASCII.GetString($magic) -ne $MAGIC_EXPECT) { throw "Bad file header (not an FDE encrypted file)." }
    $salt = New-Object byte[] 16; [void]$in.Read($salt,0,16)
    $iv   = New-Object byte[] 16; [void]$in.Read($iv,0,16)
    $kdf  = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password,$salt,$ITER,[System.Security.Cryptography.HashAlgorithmName]::SHA256)
    $key  = $kdf.GetBytes(32)
    $aes  = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize=256; $aes.Mode=[System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding=[System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.Key=$key; $aes.IV=$iv
    $dec = $aes.CreateDecryptor()
    $cs  = New-Object System.Security.Cryptography.CryptoStream($in,$dec,[System.Security.Cryptography.CryptoStreamMode]::Read)
    $out = [System.IO.File]::Create($OutPath)
    try {
      $buf = New-Object byte[] (1MB)
      while (($n = $cs.Read($buf,0,$buf.Length)) -gt 0) { $out.Write($buf,0,$n) }
    } finally { $out.Dispose() }
    $cs.Dispose(); $aes.Dispose()
  } catch {
    throw "Decrypt failed (wrong password or corrupt/missing part?): $($_.Exception.Message)"
  } finally { $in.Dispose() }
}

# --- main ---
$PartsDir = (Resolve-Path $PartsDir).Path
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$OutDir = (Resolve-Path $OutDir).Path

# group parts by base name  "<Day>.enc"  from files named "<Day>.enc.NNN"
$allParts = Get-ChildItem -Path $PartsDir -File | Where-Object { $_.Name -match '\.enc\.\d{3}$' }
if (-not $allParts) { throw "No '*.enc.NNN' parts found in $PartsDir" }
$groups = $allParts | Group-Object { ($_.Name -replace '\.\d{3}$','') } | Sort-Object Name
Write-Host ("Found {0} day set(s) to restore." -f $groups.Count) -ForegroundColor Cyan
if ($Password) { $pw = $Password } else { $pw = Get-PlainPassword }

foreach ($g in $groups) {
  $dayBase = $g.Name -replace '\.enc$',''
  Write-Host ("`n[{0}] joining {1} part(s)..." -f $dayBase, $g.Count) -ForegroundColor Yellow
  $ordered = $g.Group | Sort-Object { [int]($_.Name -replace '.*\.(\d{3})$','$1') } | ForEach-Object { $_.FullName }
  $tmpEnc = Join-Path $env:TEMP ("{0}_{1}.enc" -f ($dayBase -replace '\s','_'), [guid]::NewGuid().ToString('N').Substring(0,8))
  $tmpZip = "$tmpEnc.zip"
  Join-Parts -Parts $ordered -OutPath $tmpEnc
  Write-Host "    decrypting..."
  Decrypt-File -InPath $tmpEnc -OutPath $tmpZip -Password $pw
  Remove-Item $tmpEnc -Force
  Write-Host "    extracting..."
  Expand-Archive -Path $tmpZip -DestinationPath $OutDir -Force
  Remove-Item $tmpZip -Force
  Write-Host ("    -> restored {0}" -f $dayBase) -ForegroundColor Green
}

Write-Host "`n==== RESTORE COMPLETE ====" -ForegroundColor Cyan
Write-Host ("Folders restored under: {0}" -f $OutDir)
