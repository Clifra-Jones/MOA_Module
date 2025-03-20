function Show-ProgressBar {
    param (
        [Parameter(Mandatory = $false)]
        [int]$PercentComplete = 100,
        
        [Parameter(Mandatory = $false)]
        [int]$BarLength = 60,
        
        [Parameter(Mandatory = $false)]
        [char]$BarChar = '=',
        
        [Parameter(Mandatory = $false)]
        [string]$Activity = "Processing",
        
        [Parameter(Mandatory = $false)]
        [string]$Status = "",
        
        [Parameter(Mandatory = $false)]
        [switch]$Completed,
        
        [Parameter(Mandatory = $false)]
        [switch]$Spinner,
        
        [Parameter(Mandatory = $false)]
        [System.ConsoleColor]$ForegroundColor = [System.ConsoleColor]::White,
        
        [Parameter(Mandatory = $false)]
        [System.ConsoleColor]$BarForegroundColor,
        
        [Parameter(Mandatory = $false)]
        [System.ConsoleColor]$BarBackgroundColor = $null
    )
    
    # If BarForegroundColor isn't specified, use the main ForegroundColor
    if (-not $PSBoundParameters.ContainsKey('BarForegroundColor')) {
        $BarForegroundColor = $ForegroundColor
    }
    
    # Static variable to keep track of spinner state
    if (-not [bool]::TryParse($script:spinnerInitialized, [ref]$null)) {
        $script:spinnerInitialized = $true
        $script:spinnerIndex = 0
    }
    
    # Spinner characters in correct rotation order
    $spinnerChars = @('-', '\', '|', '/', '-', '\', '|', '/')
    
    # Check if only the -Completed switch was provided (with default values for other parameters)
    $onlyCompletedProvided = $Completed -and 
                             $PSBoundParameters.Count -eq 1 -and
                             $PercentComplete -eq 100 -and
                             $BarLength -eq 60 -and
                             $BarChar -eq '=' -and
                             $Activity -eq "Processing" -and
                             $Status -eq "" -and
                             (-not $Spinner)
    
    # If only -Completed is specified, clear the progress bar line
    if ($onlyCompletedProvided) {
        # Create a blank line that overwrites the existing progress bar
        Write-Host "`r" -NoNewline
        Write-Host (" " * 200) -NoNewline  # 200 spaces should be enough to clear most lines
        Write-Host "`r" -NoNewline
        Write-Host ""  # Add a newline to move to next line
        return
    }
    
    # Check if only -Completed and -Spinner were provided
    $onlyCompletedAndSpinnerProvided = $Completed -and 
                                      $Spinner -and
                                      $PSBoundParameters.Count -eq 2 -and
                                      $PercentComplete -eq 100 -and
                                      $BarLength -eq 60 -and
                                      $BarChar -eq '=' -and
                                      $Activity -eq "Processing" -and
                                      $Status -eq ""
    
    # If only -Completed and -Spinner are specified, clear the spinner line
    if ($onlyCompletedAndSpinnerProvided) {
        # Create a blank line that overwrites the existing spinner
        Write-Host "`r" -NoNewline
        Write-Host (" " * 200) -NoNewline
        Write-Host "`r" -NoNewline
        Write-Host ""  # Add a newline to move to next line
        return
    }
    
    # Move cursor to beginning of line
    Write-Host "`r" -NoNewline
    
    # Write the activity and opening bracket with specified color
    Write-Host "$Activity [" -NoNewline -ForegroundColor $ForegroundColor
    
    if ($Spinner) {
        # Get the current spinner character
        $currentSpinnerChar = $spinnerChars[$script:spinnerIndex]
        
        # Update spinner index for next call
        $script:spinnerIndex = ($script:spinnerIndex + 1) % $spinnerChars.Length
        
        # Display spinner character with optional background color
        if ($PSBoundParameters.ContainsKey('BarBackgroundColor')) {
            Write-Host $currentSpinnerChar -NoNewline -ForegroundColor $BarForegroundColor -BackgroundColor $BarBackgroundColor
        } else {
            Write-Host $currentSpinnerChar -NoNewline -ForegroundColor $BarForegroundColor
        }
    }
    else {
        # Regular progress bar
        # Ensure percent is within valid range
        $PercentComplete = [Math]::Max(0, [Math]::Min(100, $PercentComplete))
        
        # Calculate how many bar characters to display
        $completedChars = [Math]::Floor(($BarLength * $PercentComplete) / 100)
        $remainingChars = $BarLength - $completedChars
        
        # Build and display the colored progress portion
        if ($completedChars -gt 0) {
            $progressBar = $BarChar.ToString() * $completedChars
            # Use background color only if explicitly provided
            if ($PSBoundParameters.ContainsKey('BarBackgroundColor')) {
                Write-Host $progressBar -NoNewline -ForegroundColor $BarForegroundColor -BackgroundColor $BarBackgroundColor
            } else {
                Write-Host $progressBar -NoNewline -ForegroundColor $BarForegroundColor
            }
        }
        
        # Build and display the remaining portion with just text color
        if ($remainingChars -gt 0) {
            $remainingBar = " " * $remainingChars
            Write-Host $remainingBar -NoNewline -ForegroundColor $ForegroundColor
        }
    }
    
    # Close the bracket and show percentage with text color
    Write-Host "] $PercentComplete%" -NoNewline -ForegroundColor $ForegroundColor
    
    # Add status if provided
    if (-not [string]::IsNullOrWhiteSpace($Status)) {
        Write-Host " - $Status" -NoNewline -ForegroundColor $ForegroundColor
    }
    
    # If -Completed is specified with custom parameters, add a newline
    if ($Completed -and (-not $onlyCompletedProvided) -and (-not $onlyCompletedAndSpinnerProvided)) {
        Write-Host ""
    }
    
    # Add a special case for 100% without -Completed
    if ((-not $Completed) -and $PercentComplete -eq 100 -and (-not $Spinner)) {
        # Pause briefly to show the 100% state
        Start-Sleep -Milliseconds 500
        
        # Clear the line and move to next line
        Write-Host "`r" -NoNewline
        Write-Host (" " * 200) -NoNewline
        Write-Host "`r" -NoNewline
        Write-Host ""
    }
}
#>

# Standard progress bar with custom text color
for ($i = 1; $i -le $totalItems; $i++) {
    $percentComplete = [Math]::Floor(($i / [double]$totalItems) * 100)
    Show-ProgressBar -PercentComplete $percentComplete -Activity "SQL Import" -Status "Item $i of $totalItems" -ForegroundColor Cyan
    Start-Sleep -Milliseconds 10
}

# # Custom colors for both text and bar
# Show-ProgressBar -PercentComplete 100 -Activity "SQL Import" -Status "Complete!" -Completed `
#                 -ForegroundColor Yellow -BarForegroundColor Black -BarBackgroundColor Green

# # Bar inherits the text color (no specific bar color)
# Show-ProgressBar -PercentComplete 50 -Activity "Processing" -Status "Halfway there" `
#                 -ForegroundColor Magenta -BarBackgroundColor DarkBlue