# For educational purposes only. Use responsibly and ethically.
param(
    [Parameter(Position=0, Mandatory=$true)]
    [string]$InputImage,
    [Parameter(Position=1, Mandatory=$true)]
    [string]$OutputImage,
    [Parameter(Position=2, Mandatory=$false)]
    [string]$MessageFile
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

function Embed-MessageInImage($imgPath, $outPath, $plaintext) {
    Add-Type -AssemblyName System.Drawing
    $bmp = [System.Drawing.Bitmap]::FromFile($imgPath)
    $width = $bmp.Width
    $height = $bmp.Height

    $payload = [System.Text.Encoding]::UTF8.GetBytes($plaintext)
    $header = IntToBigEndianBytes $payload.Length
    $bitstr = BytesToBits ($header + $payload)

    $capacity = $width * $height * 3
    if ($bitstr.Length -gt $capacity) {
        throw "Obraz pojme $capacity bitu, potreba $($bitstr.Length)"
    }

    $bitIdx = 0
    for ($y=0; $y -lt $height; $y++) {
        for ($x=0; $x -lt $width; $x++) {
            $pixel = $bmp.GetPixel($x, $y)
            $r = $pixel.R
            $g = $pixel.G
            $b = $pixel.B
            if ($bitIdx -lt $bitstr.Length) {
                $r = ($r -band 0xFE) -bor [int]$bitstr[$bitIdx]; $bitIdx++
            }
            if ($bitIdx -lt $bitstr.Length) {
                $g = ($g -band 0xFE) -bor [int]$bitstr[$bitIdx]; $bitIdx++
            }
            if ($bitIdx -lt $bitstr.Length) {
                $b = ($b -band 0xFE) -bor [int]$bitstr[$bitIdx]; $bitIdx++
            }
            $bmp.SetPixel($x, $y, [System.Drawing.Color]::FromArgb($r, $g, $b))
        }
    }
    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
}


    if (-not $MessageFile) { throw "Pro vkladani je nutne zadat MessageFile." }
    $msgContent = Get-Content $MessageFile -Raw
    # Převod načteného textu na base64
    $base64Content = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($msgContent))
    Embed-MessageInImage $InputImage $OutputImage $base64Content
    Embed-MessageInImage $InputImage $OutputImage $base64Content
