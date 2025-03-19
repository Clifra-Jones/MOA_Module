using namespace System.Collections.Generic
using namespace System.Security.AccessControl
using namespace System.Security.Cryptography.X509Certificates
function ConvertFrom-Html {
    param([System.String] $html)
   
    # remove line breaks, replace with spaces
    $html = $html -replace '(`r|`n|`t)', ' '
    # write-verbose 'removed line breaks: `n`n$html`n'
   
    # remove invisible content
    @('head', 'style', 'script', 'object', 'embed', 'applet', 'noframes', 'noscript', 'noembed') | ForEach-Object {
     $html = $html -replace '<$_[^>]*?>.*?</$_>', ''
    }
    # write-verbose 'removed invisible blocks: `n`n$html`n'
   
    # Condense extra whitespace
    $html = $html -replace '( )+', ' '
    # write-verbose 'condensed whitespace: `n`n$html`n'
   
    # Add line breaks
    @('div','p','blockquote','h[1-9]') | % { $html = $html -replace '</?$_[^>]*?>.*?</$_>', ('`n' + '$0' )} 
    # Add line breaks for self-closing tags
    @('div','p','blockquote','h[1-9]','br') | % { $html = $html -replace '<$_[^>]*?/>', ('$0' + '`n')} 
    # write-verbose 'added line breaks: `n`n$html`n'
   
    #strip tags 
    $html = $html -replace '<[^>]*?>', ''
    # write-verbose 'removed tags: `n`n$html`n'
     
    # replace common entities
    @( 
     @('&amp;bull;', ' * '),
     @('&amp;lsaquo;', '<'),
     @('&amp;rsaquo;', '>'),
     @('&amp;(rsquo|lsquo);', "'"),
     @('&amp;(quot|ldquo|rdquo);', "'"),
     @('&amp;trade;', 'tm'),
     @('&amp;frasl;', '/'),
     @('&amp;(quot|#34|#034|#x22);', "'"),
     @('&amp;(amp|#38|#038|#x26);', '&amp;'),
     @('&amp;(lt|#60|#060|#x3c);', '<'),
     @('&amp;(gt|#62|#062|#x3e);', '>'),
     @('&amp;(copy|#169);', '(c)'),
     @('&amp;(reg|#174);', '(r)'),
     @('&amp;nbsp;', ' '),
     @('&amp;(.{2,6});', '')
    ) | ForEach-Object { $html = $html -replace $_[0], $_[1] }
    # write-verbose 'replaced entities: `n`n$html`n'
   
    return $html
   
}

function Get-IpRange {
<#
.SYNOPSIS
    Given a subnet in CIDR format, get all of the valid IP addresses in that range.
.DESCRIPTION
    Given a subnet in CIDR format, get all of the valid IP addresses in that range.
.PARAMETER Subnets
    The subnet written in CIDR format 'a.b.c.d/#' and an example would be '192.168.1.24/27'. Can be a single value, an
    array of values, or values can be taken from the pipeline.
.EXAMPLE
    Get-IpRange -Subnets '192.168.1.24/30'
    
    192.168.1.25
    192.168.1.26
.EXAMPLE
    (Get-IpRange -Subnets '10.100.10.0/24').count
    
    254
.EXAMPLE
    '192.168.1.128/30' | Get-IpRange
    
    192.168.1.129
    192.168.1.130
.NOTES
    Inspired by https://gallery.technet.microsoft.com/PowerShell-Subnet-db45ec74
    
    * Added comment help
#>

    [CmdletBinding(ConfirmImpact = 'None')]
    Param(
        [Parameter(Mandatory, HelpMessage = 'Please enter a subnet in the form a.b.c.d/#', ValueFromPipeline, Position = 0)]
        [string[]] $Subnets
    )

    begin {
        Write-Verbose -Message "Starting [$($MyInvocation.Mycommand)]"
    }

    process {
        foreach ($subnet in $subnets) {
            if ($subnet -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$') {
                #Split IP and subnet
                $IP = ($Subnet -split '\/')[0]
                [int] $SubnetBits = ($Subnet -split '\/')[1]
                if ($SubnetBits -lt 7 -or $SubnetBits -gt 30) {
                    Write-Error -Message 'The number following the / must be between 7 and 30'
                    break
                }
                #Convert IP into binary
                #Split IP into different octects and for each one, figure out the binary with leading zeros and add to the total
                $Octets = $IP -split '\.'
                $IPInBinary = @()
                foreach ($Octet in $Octets) {
                    #convert to binary
                    $OctetInBinary = [convert]::ToString($Octet, 2)
                    #get length of binary string add leading zeros to make octet
                    $OctetInBinary = ('0' * (8 - ($OctetInBinary).Length) + $OctetInBinary)
                    $IPInBinary = $IPInBinary + $OctetInBinary
                }
                $IPInBinary = $IPInBinary -join ''
                #Get network ID by subtracting subnet mask
                $HostBits = 32 - $SubnetBits
                $NetworkIDInBinary = $IPInBinary.Substring(0, $SubnetBits)
                #Get host ID and get the first host ID by converting all 1s into 0s
                $HostIDInBinary = $IPInBinary.Substring($SubnetBits, $HostBits)
                $HostIDInBinary = $HostIDInBinary -replace '1', '0'
                #Work out all the host IDs in that subnet by cycling through $i from 1 up to max $HostIDInBinary (i.e. 1s stringed up to $HostBits)
                #Work out max $HostIDInBinary
                $imax = [convert]::ToInt32(('1' * $HostBits), 2) - 1
                $IPs = @()
                #Next ID is first network ID converted to decimal plus $i then converted to binary
                For ($i = 1 ; $i -le $imax ; $i++) {
                    #Convert to decimal and add $i
                    $NextHostIDInDecimal = ([convert]::ToInt32($HostIDInBinary, 2) + $i)
                    #Convert back to binary
                    $NextHostIDInBinary = [convert]::ToString($NextHostIDInDecimal, 2)
                    #Add leading zeros
                    #Number of zeros to add
                    $NoOfZerosToAdd = $HostIDInBinary.Length - $NextHostIDInBinary.Length
                    $NextHostIDInBinary = ('0' * $NoOfZerosToAdd) + $NextHostIDInBinary
                    #Work out next IP
                    #Add networkID to hostID
                    $NextIPInBinary = $NetworkIDInBinary + $NextHostIDInBinary
                    #Split into octets and separate by . then join
                    $IP = @()
                    For ($x = 1 ; $x -le 4 ; $x++) {
                        #Work out start character position
                        $StartCharNumber = ($x - 1) * 8
                        #Get octet in binary
                        $IPOctetInBinary = $NextIPInBinary.Substring($StartCharNumber, 8)
                        #Convert octet into decimal
                        $IPOctetInDecimal = [convert]::ToInt32($IPOctetInBinary, 2)
                        #Add octet to IP
                        $IP += $IPOctetInDecimal
                    }
                    #Separate by .
                    $IP = $IP -join '.'
                    $IPs += $IP
                }
                Write-Output -InputObject $IPs
            } else {
                Write-Error -Message "Subnet [$subnet] is not in a valid format"
            }
        }
    }

    end {
        Write-Verbose -Message "Ending [$($MyInvocation.Mycommand)]"
    }
}

function ConvertFrom-INI() {
    [CmdletBinding()]   
    Param(
        [Parameter(
            ValueFromPipeline
        )]
        [string[]]$InputObject,
        [string]$Path,
        [switch]$UseHeadings
    )
        
    $Settings = [List[PsObject]]::New()

    if ($UseHeadings) {
        $InputObject = Get-Content -Path $Path
        foreach ($Line in $InputObject) {
            if ($line.StartsWith('[')) {
                $Header=$Line.Replace("[",'').Replace("]",'')
                if ($PrevHeader) {
                    if ($Header -ne $PrevHeader) {
                        $Section = [PSCustomObject]@{
                           $PrevHeader = $HeaderSettings.ToArray()

                        }
                        $Settings.Add($Section)
                        $HeaderSettings = [List[PsObject]]::New()
                        $PrevHeader = $Header
                    }
                }else {
                    $PrevHeader = $Header
                    $HeaderSettings = [List[PsObject]]::New()
                }
            } else {
                if ($Line.Length -gt 0) {
                    $values = $line | ConvertFrom-StringData
                    $Setting = [PSCustomObject]@{
                        [string]$values.Keys[0] = [string]$values.values[0]
                    }
                    $HeaderSettings.Add($Setting)
                }
            }            
        }
        $Section = [PSCustomObject]@{
            $PrevHeader = $HeaderSettings.ToArray()
        }
        $Settings.Add($Section)
    } else {
        $Settings = Get-Content -Path $Path | Where-Object {$_ -notmatch "^\["} | ConvertFrom-StringData
        foreach ($Setting in $Settings) {
            $Setting = [PSCustomObject]@{
                [string]$Setting.Keys[0] = [string]$Setting.values[0]
            }
            $Settings.Add($setting)
        }
    }

    return $Settings.ToArray()
}

function Add-Ace() {
    [CmdletBinding(DefaultParameterSetName = 'default')]
    Param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Identity,
        [Parameter(Mandatory)]       
        [String[]]$FileSystemRights,        
        [string[]]$InheritanceFlags = 'None',
        [string[]]$PropagationFlags = @('None'),
        [ValidateSet('Allow','Deny')]
        [string]$AccessControlType = 'Allow',
        [switch]$Recurse
    )

    If (Test-Path $Path) {
        try {
            $Acl = Get-Acl -Path $Path
        } catch {
            throw $_
        }

        If ($InheritanceFlags) {
            $FileSystemAccessRule = [FileSystemAccessRule]::New($Identity,$FileSystemRight,$InheritanceFlags,$PropagationFlags,$AccessControlType)
        } else {
            $FileSystemAccessRule = [FileSystemAccessRule]::New($Identity,$FileSystemRight,$AccessControlType)
        }

        $Acl.SetAccessRule($FileSystemAccessRule)

        try {
            Set-Acl -Path $Path -AclObject $Acl -Verbose
            if ($Recurse) {
                $response = Read-Host -Prompt "Replace permissions on on all child objects [y/N]: "
                If ($response = 'y') {
                    $Children = Get-ChildItem -Path -Recurse
                    foreach ($Child in $Children) {
                        set-acl -Path $Child.FullName -AclObject $Acl -verbose
                    }
                }
            }

        } catch {
            throw $_
        }
    }
}
Function Import-X509Certificate () {
    [CmdletBinding()]
    Param(
        [string]$StoreName = "My",
        [ValidateSet('CurrentUser','LocalMachine')]
        [string]$Scope = 'CurrentUser',
        [Parameter(Mandatory)]
        [string]$CertificatePath,
        [securestring]$PassPhrase
    )

    $Store = [X509Store]::new($StoreName, $Scope, 'ReadWrite')
    $Store.Add([X509Certificate2]::New($CertificatePath,$PassPhrase,[X509KeyStorageFlags]::PersistKeySet))
    $Store.Dispose()
}

function ConvertTo-DataTable {
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$InputObject
    )
    begin {
        $dataTable = New-Object System.Data.DataTable
    }
    process {
        foreach ($object in $InputObject) {
            if ($dataTable.Columns.Count -eq 0) {
                $object | Get-Member -MemberType Properties | ForEach-Object {
                    $dataTable.Columns.Add($_.Name, $_.Type)
                }
            }
            $dataRow = $dataTable.NewRow()
            foreach ($column in $dataTable.Columns) {
                $dataRow[$column.ColumnName] = $object."$($column.ColumnName)"
            }
            $dataTable.Rows.Add($dataRow)
        }
    }
    end {
        $dataTable
    }
}

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
        [switch]$Spinner
    )
    
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
        $clearLine = "`r" + " " * 200 + "`r"  # 200 spaces should be enough to clear most lines
        Write-Host $clearLine -NoNewline
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
        $clearLine = "`r" + " " * 200 + "`r"  # 200 spaces should be enough to clear most lines
        Write-Host $clearLine -NoNewline
        return
    }
    
    # Build the display string
    if ($Spinner) {
        # Get the current spinner character
        $currentSpinnerChar = $spinnerChars[$script:spinnerIndex]
        
        # Update spinner index for next call
        $script:spinnerIndex = ($script:spinnerIndex + 1) % $spinnerChars.Length
        
        # Create spinner display
        $displayString = "`r$Activity [$currentSpinnerChar]"
    }
    else {
        # Regular progress bar
        # Ensure percent is within valid range
        $PercentComplete = [Math]::Max(0, [Math]::Min(100, $PercentComplete))
        
        # Calculate how many bar characters to display
        $completedChars = [Math]::Floor(($BarLength * $PercentComplete) / 100)
        
        # Build the progress bar
        $progressBar = ""
        for ($i = 0; $i -lt $completedChars; $i++) {
            $progressBar += $BarChar
        }
        
        $remainingBar = ""
        for ($i = 0; $i -lt ($BarLength - $completedChars); $i++) {
            $remainingBar += " "
        }
        
        # Build the display string for progress bar
        $displayString = "`r$Activity [$progressBar$remainingBar] $PercentComplete%"
    }
    
    # Add status if provided
    if (-not [string]::IsNullOrWhiteSpace($Status)) {
        $displayString += " - $Status"
    }
    
    # Display the progress indicator
    Write-Host $displayString -NoNewline
    
    # If -Completed is specified with custom parameters, add a newline to finalize and keep it visible
    if ($Completed -and (-not $onlyCompletedProvided) -and (-not $onlyCompletedAndSpinnerProvided)) {
        Write-Host ""
    }
    <#
    .SYNOPSIS
        Display a progress bar or spinner in the console.
    .DESCRIPTION
        Display a progress bar or spinner in the console. The progress bar can be customized with different lengths, characters, and activity descriptions.
    .PARAMETER PercentComplete
        The percentage of completion for the progress bar. Must be an integer between 0 and 100. Default is 100.
    .PARAMETER BarLength
        The length of the progress bar in characters. Default is 60.
    .PARAMETER BarChar
        The character to use for the progress bar. Default is '='.
    .PARAMETER Activity
        The description of the activity being displayed. Default is "Processing".
    .PARAMETER Status
        Additional status information to display alongside the progress bar.
    .PARAMETER Completed
        Indicates that the progress bar is complete and should be finalized. 
        If this switch is used, the progress bar will be cleared after displaying the final state.
        If the parameters for the progress bar are customized, the final state will be displayed with those customizations.
    .PARAMETER Spinner
        Indicates that a spinner should be displayed instead of a progress bar. 
        The spinner will cycle through a set of characters to indicate activity.
    .EXAMPLE    
        Show-ProgressBar -PercentComplete 50 -BarLength 40 -BarChar '#' -Activity "Downloading" -Status "File 1 of 10"
        Display a progress bar with 50% completion, a length of 40 characters, using '#' as the bar character, 
        and showing the activity as "Downloading" with the status "File 1 of 10".
    .EXAMPLE
        Show-ProgressBar -Spinner -Activity "Processing"
        Display a spinner with the activity "Processing" to indicate ongoing activity.
    .EXAMPLE
        Show-ProgressBar -Completed
        Clear the progress bar line after completion.
    .EXAMPLE    
        Show-ProgressBar -Completed -Activity "Completed" -Status "All items processed"
        Display a final completion message with the activity "Completed" and status "All items processed".
    .EXAMPLE
        Show-ProgressBar -Completed -Activity "Completed" -Status "All items processed" -PercentComplete 100
        Display a final completion message with the activity "Completed" and status "All items processed and 100% complete".
    .NOTES
        This is a cleaner progress bar than the one provided in the PowerShell, which can be customized with 
        different lengths, characters, and activity descriptions. It also supports displaying a spinner instead of a progress bar.
    #>
}