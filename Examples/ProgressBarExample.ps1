# Example 1: Normal progress bar during a loop
Param(
    [switch]$ShowFinalProgress,
    [char]$BarCharacter = '='
)

$TotalItems = 300
$BarChar = @{}
if ($BarCharacter) {
    $BarChar['BarChar'] = $BarCharacter
} else {
    $BarChar['BarChar'] = '='
}
Start-Transcript -Path "ProgressBarExample.log"
for ($i = 1; $i -le $totalItems; $i++) {
    $percentComplete = [Math]::Floor(($i / [double]$totalItems) * 100)
    Show-ProgressBar -PercentComplete $percentComplete -Activity "SQL Import" -Status "Item $i of $totalItems" @BarChar
    Start-Sleep -Milliseconds 50
}

# Example 2: Show final completion state that stays visible
If ($ShowFinalProgress) {
    Show-ProgressBar -PercentComplete 100 -Activity "SQL Import" -Status "Complete - All $totalItems items processed" -Completed
} else {
    Show-ProgressBar -Completed
}
Stop-Transcript
