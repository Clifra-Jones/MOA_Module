# Example 1: Normal spinner animation in a loop
Param(
    [switch]$ShowFinalProgress
)
for ($i = 1; $i -le 50; $i++) {
    Show-ProgressBar -Activity "Processing Data" -Status "Item $i of 50" -Spinner
    Start-Sleep -Milliseconds 100
}

# Example 2: Show final spinner state with custom message that stays visible
If ($ShowFinalProgress) {
    Show-ProgressBar -Activity "Processing Data" -Status "All items processed successfully" -Spinner -Completed
} else {
    Show-ProgressBar -Spinner -Completed
}

