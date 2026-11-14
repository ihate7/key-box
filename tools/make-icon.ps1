# Generates res\app.ico (multi-size) and res\logo.png for KeyBox.
# The result is committed to the repository; run this script only to change the artwork.
#
#   powershell -ExecutionPolicy Bypass -File tools\make-icon.ps1

param(
    [string]$OutDir = (Join-Path $PSScriptRoot "..\res")
)

Add-Type -AssemblyName System.Drawing

function New-Frame([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::Half
    $g.Clear([System.Drawing.Color]::Transparent)

    $s = [single]$size

    # Rounded square with a blue gradient.
    $inset = [single]($s * 0.035)
    $side = [single]($s - 2 * $inset)
    $d = [single]($s * 0.44)
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddArc($inset, $inset, $d, $d, 180, 90)
    $path.AddArc(($inset + $side - $d), $inset, $d, $d, 270, 90)
    $path.AddArc(($inset + $side - $d), ($inset + $side - $d), $d, $d, 0, 90)
    $path.AddArc($inset, ($inset + $side - $d), $d, $d, 90, 90)
    $path.CloseFigure()

    $rect = New-Object System.Drawing.RectangleF(0, 0, $s, $s)
    $top = [System.Drawing.Color]::FromArgb(255, 66, 139, 250)
    $bottom = [System.Drawing.Color]::FromArgb(255, 29, 78, 216)
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rect, $top, $bottom, [single]65)
    $g.FillPath($brush, $path)

    # White keyhole: a circle with a widening stem.
    $white = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
    $cx = [single]($s * 0.5)
    $cy = [single]($s * 0.405)
    $r = [single]($s * 0.165)
    $g.FillEllipse($white, ($cx - $r), ($cy - $r), (2 * $r), (2 * $r))

    $stem = [System.Drawing.PointF[]]@(
        (New-Object System.Drawing.PointF(($cx - $s * 0.07), ($s * 0.44))),
        (New-Object System.Drawing.PointF(($cx + $s * 0.07), ($s * 0.44))),
        (New-Object System.Drawing.PointF(($cx + $s * 0.135), ($s * 0.775))),
        (New-Object System.Drawing.PointF(($cx - $s * 0.135), ($s * 0.775)))
    )
    $g.FillPolygon($white, $stem)

    $white.Dispose(); $brush.Dispose(); $path.Dispose(); $g.Dispose()
    return $bmp
}

function Get-PngBytes([System.Drawing.Bitmap]$bmp) {
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    return ,$ms.ToArray()
}

# Classic DIB frame: BITMAPINFOHEADER + bottom-up BGRA pixels + 1-bit AND mask.
function Get-DibBytes([System.Drawing.Bitmap]$bmp) {
    $w = $bmp.Width
    $h = $bmp.Height
    $rect = New-Object System.Drawing.Rectangle(0, 0, $w, $h)
    $data = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $pixels = New-Object byte[] ($w * $h * 4)
    [System.Runtime.InteropServices.Marshal]::Copy($data.Scan0, $pixels, 0, $pixels.Length)
    $bmp.UnlockBits($data)

    $maskStride = [int]([Math]::Floor(($w + 31) / 32) * 4)
    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ms)
    $bw.Write([int]40)                # biSize
    $bw.Write([int]$w)                # biWidth
    $bw.Write([int]($h * 2))          # biHeight: image + mask
    $bw.Write([int16]1)               # biPlanes
    $bw.Write([int16]32)              # biBitCount
    $bw.Write([int]0)                 # biCompression
    $bw.Write([int]($w * $h * 4 + $maskStride * $h))
    $bw.Write([int]0); $bw.Write([int]0); $bw.Write([int]0); $bw.Write([int]0)

    for ($y = $h - 1; $y -ge 0; $y--) {
        $bw.Write($pixels, $y * $w * 4, $w * 4)
    }
    for ($y = $h - 1; $y -ge 0; $y--) {
        $row = New-Object byte[] $maskStride
        for ($x = 0; $x -lt $w; $x++) {
            if ($pixels[($y * $w + $x) * 4 + 3] -eq 0) {
                $row[[int][Math]::Floor($x / 8)] = $row[[int][Math]::Floor($x / 8)] -bor (0x80 -shr ($x % 8))
            }
        }
        $bw.Write($row)
    }
    $bw.Flush()
    return ,$ms.ToArray()
}

$OutDir = [System.IO.Path]::GetFullPath($OutDir)
New-Item -ItemType Directory -Force $OutDir | Out-Null

$sizes = 16, 20, 24, 32, 40, 48, 64, 256
$frames = @()
foreach ($size in $sizes) {
    $bmp = New-Frame $size
    if ($size -ge 256) { $bytes = Get-PngBytes $bmp } else { $bytes = Get-DibBytes $bmp }
    $frames += ,@{ Size = $size; Bytes = $bytes }
    if ($size -eq 256) { $bmp.Save((Join-Path $OutDir "logo.png"), [System.Drawing.Imaging.ImageFormat]::Png) }
    $bmp.Dispose()
}

$icoPath = Join-Path $OutDir "app.ico"
$fs = [System.IO.File]::Create($icoPath)
$bw = New-Object System.IO.BinaryWriter($fs)
$bw.Write([int16]0)                   # reserved
$bw.Write([int16]1)                   # type: icon
$bw.Write([int16]$frames.Count)
$offset = 6 + 16 * $frames.Count
foreach ($frame in $frames) {
    $dim = $frame.Size
    if ($dim -ge 256) { $dim = 0 }
    $bw.Write([byte]$dim)             # width (0 means 256)
    $bw.Write([byte]$dim)             # height
    $bw.Write([byte]0)                # palette size
    $bw.Write([byte]0)                # reserved
    $bw.Write([int16]1)               # planes
    $bw.Write([int16]32)              # bits per pixel
    $bw.Write([int]$frame.Bytes.Length)
    $bw.Write([int]$offset)
    $offset += $frame.Bytes.Length
}
foreach ($frame in $frames) {
    $bw.Write([byte[]]$frame.Bytes)
}
$bw.Flush()
$fs.Close()

"Written: $icoPath ($((Get-Item $icoPath).Length) bytes), $(Join-Path $OutDir 'logo.png')"
