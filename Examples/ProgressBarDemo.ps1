
# Demo 1: Basic progress bar with no color customization
Write-Host "`nDemo 1: Basic progress bar"
for ($i = 0; $i -le 100; $i += 10) {
    Show-ProgressBar -PercentComplete $i -Activity "Basic Demo" -Status "Processing $i%"
    Start-Sleep -Milliseconds 300
}
Show-ProgressBar -Completed
Start-Sleep -Seconds 1

# Demo 2: Progress bar with custom foreground color
Write-Host "`nDemo 2: Progress bar with custom foreground color (Green)"
for ($i = 0; $i -le 100; $i += 10) {
    Show-ProgressBar -PercentComplete $i -Activity "Green Demo" -Status "Processing $i%" -ForegroundColor Green
    Start-Sleep -Milliseconds 300
}
Show-ProgressBar -Completed
Start-Sleep -Seconds 1

# Demo 3: Progress bar with custom bar character and bar foreground color
Write-Host "`nDemo 3: Progress bar with custom bar character (#) and bar color (Red)"
for ($i = 0; $i -le 100; $i += 10) {
    Show-ProgressBar -PercentComplete $i -Activity "Custom Bar" -Status "Processing $i%" -BarChar "#" -BarForegroundColor Red
    Start-Sleep -Milliseconds 300
}
Show-ProgressBar -Completed
Start-Sleep -Seconds 1

# Demo 4: Progress bar with bar foreground and background colors
Write-Host "`nDemo 4: Progress bar with bar foreground (Yellow) and background (DarkBlue) colors"
for ($i = 0; $i -le 100; $i += 10) {
    Show-ProgressBar -PercentComplete $i -Activity "Colorful Bar" -Status "Processing $i%" -BarForegroundColor Yellow -BarBackgroundColor DarkBlue
    Start-Sleep -Milliseconds 300
}
Show-ProgressBar -Completed
Start-Sleep -Seconds 1

# Demo 5: Progress bar with all custom colors
Write-Host "`nDemo 5: Progress bar with all custom colors (Cyan text, Red bar with White background), Show completed bar & message"
for ($i = 0; $i -le 100; $i += 10) {
    Show-ProgressBar -PercentComplete $i -Activity "All Colors" -Status "Processing $i%" -ForegroundColor Cyan -BarForegroundColor Red -BarBackgroundColor White
    Start-Sleep -Milliseconds 300
}
Show-ProgressBar -Completed -ForegroundColor Cyan
Start-Sleep -Seconds 1

# Demo 6: Custom length progress bar, with green bar
Write-Host "`nDemo 6: Custom length progress bar (30 characters)"
for ($i = 0; $i -le 100; $i += 10) {
    Show-ProgressBar -PercentComplete $i -Activity "Short Bar" -Status "Processing $i%" -BarLength 30 -BarForegroundColor Green
    Start-Sleep -Milliseconds 300
}
Show-ProgressBar -Completed
Start-Sleep -Seconds 1

# Demo 7: Basic spinner
Write-Host "`nDemo 7: Basic spinner"
for ($i = 0; $i -lt 20; $i++) {
    Show-ProgressBar -Spinner -Activity "Loading" -Status "Please wait..."
    Start-Sleep -Milliseconds 150
}
# Complete with just -Completed to clear the spinner
Show-ProgressBar -Completed
Start-Sleep -Seconds 1

# Demo 8: Colored spinner
Write-Host "`nDemo 8: Colored spinner (Magenta), show completed status"
for ($i = 0; $i -lt 20; $i++) {
    Show-ProgressBar -Spinner -Activity "Colored Spinner" -Status "Processing item $i" -ForegroundColor Magenta
    Start-Sleep -Milliseconds 150
}
# Complete with final message
Show-ProgressBar -Spinner -Completed -Activity "Colored Spinner" -Status "Process complete!" -ForegroundColor Magenta
Start-Sleep -Seconds 1

# Demo 9: Spinner with custom colors
Write-Host "`nDemo 9: Spinner with Yellow symbol on Blue background, show completed status"
for ($i = 0; $i -lt 20; $i++) {
    Show-ProgressBar -Spinner -Activity "Fancy Spinner" -Status "Working..." -BarForegroundColor Yellow -BarBackgroundColor Blue
    Start-Sleep -Milliseconds 150
}
Show-ProgressBar -Spinner -Completed -Activity "Fancy Spinner" -Status "Work complete!" -BarForegroundColor Yellow -BarBackgroundColor Blue
Start-Sleep -Seconds 1

# Demo 10: All custom colors for spinner
Write-Host "`nDemo 10: All custom colors for spinner (Green text, Red spinner on Yellow background), show completed status"
for ($i = 0; $i -lt 20; $i++) {
    Show-ProgressBar -Spinner -Activity "Ultimate Spinner" -Status "Almost done ($i/20)" -ForegroundColor Green -BarForegroundColor Red -BarBackgroundColor Yellow
    Start-Sleep -Milliseconds 150
}
Show-ProgressBar -Spinner -Completed -Activity "Ultimate Spinner" -Status "Completed!" -ForegroundColor Green -BarForegroundColor Red -BarBackgroundColor Yellow
#Show-ProgressBar -Spinner -Completed -ForegroundColor Green

# Final message
Write-Host "`nAll demos completed!" -ForegroundColor Cyan