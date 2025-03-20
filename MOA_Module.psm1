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
    @('div','p','blockquote','h[1-9]') | ForEach-Object { $html = $html -replace '</?$_[^>]*?>.*?</$_>', ('`n' + '$0' )} 
    # Add line breaks for self-closing tags
    @('div','p','blockquote','h[1-9]','br') | ForEach-Object { $html = $html -replace '<$_[^>]*?/>', ('$0' + '`n')} 
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

    # Test Operating system
    If (-Not $IsWindows) {
        Write-Host "This function is only available on Windows"
        return
    }

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
                If ($response -eq 'y') {
                    $Children = Get-ChildItem -Path -Recurse
                    foreach ($Child in $Children) {
                        set-acl -Path $Child.FullName -AclObject $Acl -verbose
                    }
                } else {
                    Write-Host "Permissions not applied to child objects"
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
        Write-ConsoleOnly $clearLine -NoNewline
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
        Write-ConsoleOnly $clearLine -NoNewline
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
    Write-ConsoleOnly $displayString -NoNewline
    
    # If -Completed is specified with custom parameters, add a newline to finalize and keep it visible
    if ($Completed -and (-not $onlyCompletedProvided) -and (-not $onlyCompletedAndSpinnerProvided)) {
        Write-ConsoleOnly ""
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

function Update-ComputerDNSServers () {
	[CmdletBinding()]
	Param (
		[Parameter(Mandatory=$true)]
		$ComputerName,
		[Parameter(Mandatory=$true)]
		$DNSServer1,
		[Parameter(Mandatory=$false)]
		$DNSServer2
	)

    if (-not $IsWindows) {
        Write-Host "This function is only available on Windows"
        return
    }
	
	Write-Host "Checking if computer $ComputerName is accessible"
	If (-not (Test-Connection -ComputerName $ComputerName -Quiet)) { 
		Write-Host "Server $ComputerName not accessible"
		return 
	} else {
		Write-Host "Server $ComputerName is accessible via ping"
	}

	$SessionOptions = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
	$Session = New-PSSession -ComputerName $ComputerName -UseSSL -SessionOption $SessionOptions -ErrorAction SilentlyContinue
	If ($Session) {
		Write-Host "Server $ComputerName is accessible via WinRM over HTTPS"
		Invoke-Command -Session $Session -ScriptBlock {
			$NICs = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
			foreach ($NIC in $NICs) {
				$DNSSearchOrder = $NIC.DNSServerSearchOrder
				for ($i=0; $i -lt $DNSSearchOrder.length; $i++) {
					If ($i -eq 0) {
						$DNSSearchOrder[$i] = $using:DNSServer1		
					} elseIf ($i -eq 1) {
						$DNSSearchOrder[$i] = $using:DNSServer2
					}
				}
				[void]$NIC.SetDNSServerSearchOrder($DNSSearchOrder)
				[void]$NIC.SetDynamicDNSRegistration("TRUE")
			}
		}
		Remove-PSSession -Session $Session
	} else {
		Write-Host "Server $ComputerName is not accessible via WinRM over HTTPS"
		$Session = New-PSSession -ComputerName $ComputerName -ErrorAction SilentlyContinue
		If ($Session) {
			Write-Host "Server $ComputerName is accessible via WinRM over HTTP"
			Invoke-Command -Session $Session -ScriptBlock {
				$NICs = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
				foreach ($NIC in $NICs) {
					$DNSSearchOrder = $NIC.DNSServerSearchOrder
					for ($i=0; $i -lt $DNSSearchOrder.length; $i++) {
						If ($i -eq 0) {
							$DNSSearchOrder[$i] = $using:DNSServer1		
						} elseIf ($i -eq 1) {
							$DNSSearchOrder[$i] = $using:DNSServer2
						}
					}
					[void]$NIC.SetDNSServerSearchOrder($DNSSearchOrder)
					[void]$NIC.SetDynamicDNSRegistration("TRUE")
				}
			}
			Remove-PSSession -Session $Session
		} else {
			Write-Host "Server $ComputerName is not accessible via WinRM over HTTPS or HTTP"
		}
	}
    <#
    .SYNOPSIS
        Update the DNS servers for a remote computer.
    .DESCRIPTION
        Update the DNS servers for a remote computer by setting the primary and secondary DNS server IP addresses.
        The target computer must have a WinRM listening service enabled using wither HTTP or HTTPS and be accessible.
    .PARAMETER ComputerName        
        The name of the remote computer to update the DNS servers for.
    .PARAMETER DNSServer1
        The IP address of the primary DNS server to set.
    .PARAMETER DNSServer2
        The IP address of the secondary DNS server to set.
    .EXAMPLE    
        Update-ComputerDNSServers -ComputerName "Server01" -DNSServer1 "
    .EXAMPLE
        Update-ComputerDNSServers -ComputerName "Server02" -DNSServer1 -DNSServer2 "
    #>
}

function Debug-String() {
    <#
    .SYNOPSIS
    Outputs a string in diagnostic form or as source code.

    .DESCRIPTION
    With -AsSourceCode: prints a string in single-line form as a double-quoted
    PowerShell string literal that is reusable as source code.

    Otherwise: Prints a string with typically control or hidden characters visualized:

    Common control characters are visualized using PowerShell's own escaping
    notation by default, such as
    "`t" for a tab, "`r" for a CR, but a LF is visualized as itself, as an
    actual newline, unless you specify -SingleLine.

    As an alternative, if you want ASCII-range control characters visualized in caret notation
    (see https://en.wikipedia.org/wiki/Caret_notation), similar to cat -A on Linux,
    use -CaretNotation. E.g., ^M then represents a CR; but note that a LF is
    always represented as "$" followed by an actual newline.

    Any other control characters as well as otherwise hidden characters or
    format / punctuation characters in the non-ASCII range are represented in
    `u{hex-code-point} notation.

    To print space characters as themselves, use -NoSpacesAsDots.

    $null inputs are accepted, but a warning is issued.

    .PARAMETER CaretNotation
    Causes LF to be visualized as "$" and all other ASCII-range control characters
    in caret notation, similar to `cat -A` on Linux.

    .PARAMETER Delimiters
    You may optionally specify delimiters that The visualization of each input string is enclosed in "[...]" to demarcate
    its boundaries. Use -Delimiters '' to suppress that, or specify alternate
    delimiters; you may specify a single string or a 2-element array.

    .PARAMETER NoSpacesAsDots
    By default, space chars. are visualized as "·", the MIDDLE DOT char. (U+00B7)
    Use this switch to represent spaces as themselves.

    .PARAMETER AsSourceCode
    Outputs each input string as a double-quoted PowerShell string
    that is reusable in source code, with embedded double quotes, backticks, 
    and "$" signs backtick-escaped.

    Use -SingleLine to get a single-line representation.
    Control characters that have no native PS escape sequence are represented
    using `u{<hex-code-point} notation, which will only work in PowerShell *Core*
    (v6+) source code.

    .PARAMETER SingleLine
    Requests a single-line representation, where LF characters are represented
    as `n instead of actual line breaks.

    .PARAMETER UnicodeEscapes
    Requests that all non-ASCII-range characters - such as foreign letters -  in
    the input string be represented as Unicode escape sequences in the form
    `u{hex-code-point}.

    When combined with -AsSourceCode, the result is a PowerShell string literal
    composed of ASCII-range characters only, but note that only PowerShell *Core*
    (v6+) understands such Unicode escapes.

    By default, only control characters that don't have a native PS escape
    sequence / cannot be represented with caret notation are represented this way.

    .EXAMPLE
    PS> "a`ab`t c`0d`r`n" | Debug-String -Delimiters [, ]
    [a`0b`t·c`0d`r`
    ]

    .EXAMPLE
    PS> "a`ab`t c`0d`r`n" | Debug-String -CaretNotation
    a^Gb^I c^@d^M$

    .EXAMPLE
    PS> "a-ü`u{2028}" | Debug-String -UnicodeEscapes # The dash is an em-dash (U+2014)
    a·`u{2014}·`u{fc}

    .EXAMPLE
    PS> "a`ab`t c`0d`r`n" | Debug-String -AsSourceCode -SingleLine # roundtrip
    "a`ab`t c`0d`r`n"
    #>

    [CmdletBinding(DefaultParameterSetName = 'Standard')]
    param(
      [Parameter(ValueFromPipeline, Mandatory, ParameterSetName = 'Standard', Position = 0)]
      [Parameter(ValueFromPipeline, Mandatory, ParameterSetName = 'Caret', Position = 0)]
      [Parameter(ValueFromPipeline, Mandatory, ParameterSetName = 'AsSourceCode', Position = 0)]
      [AllowNull()]
      [object[]] $InputObject,

      [Parameter(ParameterSetName = 'Caret')]
      [switch] $CaretNotation,

      [Parameter(ParameterSetName = 'Standard')]
      [Parameter(ParameterSetName = 'Caret')]
      [string[]] $Delimiters,

      [Parameter(ParameterSetName = 'Standard')]
      [switch] $NoSpacesAsDots,

      [Parameter(ParameterSetName = 'AsSourceCode')]
      [switch] $AsSourceCode,

      [Parameter(ParameterSetName = 'Standard')]
      [Parameter(ParameterSetName = 'AsSourceCode')]
      [switch] $SingleLine,

      [Parameter(ParameterSetName = 'Standard')]
      [Parameter(ParameterSetName = 'Caret')]
      [Parameter(ParameterSetName = 'AsSourceCode')]
      [switch] $UnicodeEscapes

    )

    begin {
      if ($UnicodeEscapes) {
        $re = [regex] '(?s).' # *all* characters.
      } else {
        # Only control / separator / punctuation chars.
        # * \p{C} matches any Unicode control / format/ invisible characters, both inside and outside
        #   the ASCII range; note that tabs (`t) are control character too, but not spaces; it comprises
        #   the following Unicode categories: Control, Format, Private_Use, Surrogate, Unassigned
        # * \p{P} comprises punctuation characters.
        # * \p{Z} comprises separator chars., including spaces, but not other ASCII whitespace, which is in the Control category.
        # Note: For -AsSourceCode we include ` (backticks) too.
        $re = if ($AsSourceCode) { [regex] '[`\p{C}\p{P}\p{Z}]' } else { [regex] '[\p{C}\p{P}\p{Z}]' }
      }
      $openingDelim = $closingDelim = ''
      if ($Delimiters) {
        $openingDelim = $Delimiters[0]
        $closingDelim = $Delimiters[1]
        if (-not $closingDelim) { $closingDelim = $openingDelim }
      }
    }

    process {
      if ($null -eq $InputObject) { Write-Warning 'Ignoring $null input.'; return }
        foreach ($str in $InputObject) {
            if ($null -eq $str) { Write-Warning 'Ignoring $null input.'; continue }
            if ($str -isnot [string]) { $str = -join ($str | Out-String -Stream) }
            $strViz = $re.Replace($str, {
                param($match)
                $char = [char] $match.Value[0]
                $codePoint = [uint16] $char
                $sbToUnicodeEscape = { '`u{' + '{0:x}' -f [int] $Args[0] + '}' }
                # wv -v ('in [{0}]' -f [char] $match.Value)
                if ($CaretNotation) {
                    if ($codePoint -eq 10) {
                        # LF -> $<newline>
                        '$' + $char
                    } elseif ($codePoint -eq 32) {
                        # space char.
                        if ($NoSpacesAsDots) { ' ' } else { '·' }
                    } elseif ($codePoint -ge 0 -and $codePoint -le 31 -or $codePoint -eq 127) {
                        # If it's a control character in the ASCII range,
                        # use caret notation too (C0 range).
                        # See https://en.wikipedia.org/wiki/Caret_notation
                        '^' + [char] (64 + $codePoint)
                    }
                    elseif ($codePoint -ge 128) {
                    # Non-ASCII (control) character -> `u{<hex-code-point>}
                        & $sbToUnicodeEscape $codePoint
                    } else {
                        $char
                    }
                } else {
                    # -not $CaretNotation
                    # Translate control chars. that have native PS escape sequences
                    # into these escape sequences.
                    switch ($codePoint) {
                        0  { '`0'; break }
                        7  { '`a'; break }
                        8  { '`b'; break }
                        9  { '`t'; break }
                        11 { '`v'; break }
                        12 { '`f'; break }
                        10 { if ($SingleLine) { '`n' } else { "`n" }; break }
                        13 { '`r'; break }
                        27 { '`e'; break }
                        32 { if ($AsSourceCode -or $NoSpacesAsDots) { ' ' } else { '·' }; break } # Spaces are visualized as middle dots by default.
                        default {
                            if ($codePoint -ge 128) {
                                & $sbToUnicodeEscape $codePoint
                            } elseif ($AsSourceCode -and $codePoint -eq 96) { # ` (backtick)
                                '``'
                            } else {
                                $char
                            }
                        }
                    } # switch
                }
                }) # .Replace

                # Output
            if ($AsSourceCode) {
                '"{0}"' -f ($strViz -replace '"', '`"' -replace '\$', '`$')
            }
            else {
                if ($CaretNotation) {
                    # If a string *ended* in a newline, our visualization now has
                    # a trailing LF, which we remove.
                    $strViz = $strViz -replace '(?s)^(.*\$)\n$', '$1'
                }
                $openingDelim + $strViz + $closingDelim
            }
        }
    } # process
}

function Get-FolderStats() {
    Param(
        [Parameter(Mandatory)]
        [string]$Path,
        [switch]$Recurse,
        [switch]$IncludeTypeStats,
        [switch]$ShowProgress,
        [ValidateSet("Standard","Text")]
        [string]$ProgressType = "Standard"
    )

    $params = @{}
    if ($Recurse.IsPresent) {
        $params.Add("Recurse", $true)
    } else {
        $params.Add("Recurse", $false)
    }
    Write-Host "Gathering files... This may take a while if you selected recuse on a large folder!"
    $Items = Get-ChildItem -Path $Path @params -File
    $Stats = $Items | Measure-Object -Property Length -Sum | Select-Object Count, @{Name="Size"; Expression={$_.Sum / 1mb}}
    $Stats | Add-Member -MemberType NoteProperty -Name "Folder" -Value $Path

    $threeYrStats = $Items.Where({$_.LastWriteTime -lt (Get-Date).AddYears(-3)}) | Measure-Object -Property Length -Sum | Select-Object Count, @{Name="Size";Expression={$_.Sum / 1mb}}
    $fourYrStats = $Items.Where({$_.LastWriteTime -lt (Get-Date).AddYears(-4)}) | Measure-Object -Property Length -Sum | Select-Object Count, @{Name="Size";Expression={$_.Sum / 1mb}}
    $fiveYrStats = $Items.Where({$_.LastWriteTime -lt (Get-Date).AddYears(-5)}) | Measure-Object -Property Length -Sum | Select-Object Count, @{Name="Size";Expression={$_.Sum / 1mb}}

    [PSCustomObject]@{
        ThreeYearFiles = $threeYrStats.count
        ThreeYearSize = $threeYrStats.Size
        FourYearFiles = $fourYrStats.Count
        FourYearSize = $fourYrStats.Size
        FiveYearFiles = $fiveYrStats.Count
        FiveYearSize = $fiveYrStats.Size
    }

    # Stats per file type

    if ($IncludeTypeStats.IsPresent) {
        Write-Host "Gathering Type statistics... This may take a while if you selected recuse on a large folder!"
        $TypeStats = [List[PsObject]]::New()

        $Types = $Items | Group-Object -Property Extension | Where-Object {$_.Name -ne ''}

        foreach ($Type in $Types) {

            If ($ShowProgress) {
                $INdex = $Types.IndexOf($Type)
                $PercentComplete = [math]::Round(($Index / $Types.Count) * 100)
                if ($ProgressType -eq "Standard") {
                    Write-Progress -PercentComplete $PercentComplete -Activity "Gathering Type statistics" -Status "Processing $Type"
                } else {
                    Show-ProgressBar -Activity "Gathering Type statistics" -Status "Processing $Type" -PercentComplete $PercentComplete
                }
            }

            $TypeSize = ($Type.Group | Measure-Object -Property Length -Sum).Sum / 1mb

            if ($TypeSize -ge 0.01) {
                $TypeStat = [PSCustomObject]@{
                    Name = ( ('' -eq $Type.Name) ? "Undefined" : $Type.Name )
                    Count = $Type.Count
                    Size = $TypeSize
                }
                $TypeStats.Add($TypeStat)
            }
        }
        if ($ProgressType -eq "Standard") {
            Write-Progress -Completed
        } else {
            Show-ProgressBar -Completed
        }

        if ($TypeStats.Count -gt 0) {
            $Stats | Add-Member -MemberType NoteProperty -Name "TypeStats" -Value ($TypeStats.toArray())
        }
    }
    return $Stats
    <#
    .SYNOPSIS
        Get statistics for a folder.
    .DESCRIPTION
        Get statistics for a folder, including the number of files, total size, and optionally statistics per file type.
    .PARAMETER Path
        The path to the folder for which to get statistics.
    .PARAMETER Recurse
        If present, statistics are gathered recursively, including all subfolders.
    .PARAMETER IncludeTypeStats
        If present, statistics are gathered per file type.  
    .PARAMETER ShowProgress
        If present, a progress bar is displayed while gathering statistics.
    .PARAMETER ProgressType 
        The type of progress bar to display. Options are "Standard" or "Text".
    .EXAMPLE
        Get-FolderStats -Path "C:\Temp" -Recurse -IncludeTypeStats
        Get statistics for the folder "C:\Temp", including subfolders, and per file type.  
    .EXAMPLE
        Get-FolderStats -Path "C:\Temp" -ShowProgress
        Get statistics for the folder "C:\Temp" and display a progress bar while gathering statistics.  
    #>
}

function Get-FunctionNamesInFiles () {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [string]$Path,
        [string[]]$Exclude,
        [string]$Filter,
        [switch]$Recurse

    )

    try {
        $params = @{
            Path = $Path
        }
        if ($Exclude) {
            $params.Add("Exclude", $Exclude)
        }
        if ($Filter) {
            $params.add("Filter", $Filter)
        }
        if ($Recurse) {
            $params.Add("Recurse", $true)
        }

        Get-ChildItem @params | ForEach-Object {
            $Command = Get-Command $_
            $Command.ScriptBlock.Ast.FindAll({$args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst]}, $false).Name
        } | ForEach-Object {
            "'$_',"
        }
    } catch {
        throw $_
    }
    <#
    .SYNOPSIS
        Get the names of functions defined in files.
    .DESCRIPTION
        Get the names of functions defined in files in a specified folder.
    .PARAMETER Path
        The path to the folder containing the files to search.
    .PARAMETER Exclude
        An array of file names or patterns to exclude from the search.
    .PARAMETER Filter
        A wildcard pattern to filter the files to search.
    .PARAMETER Recurse
        If present, the search is performed recursively, including all subfolders.
    .EXAMPLE
        Get-FunctionNamesInFiles -Path "C:\Scripts"
        Get the names of functions defined in files in the "C:\Scripts" folder.
    .EXAMPLE    
        Get-FunctionNamesInFiles -Path "C:\Scripts" -Recurse
        Get the names of functions defined in files in the "C:\Scripts" folder and all subfolders.  
    .EXAMPLE
        Get-FunctionNamesInFiles -Path "C:\Scripts" -Exclude "*.ps1"
        Get the names of functions defined in files in the "C:\Scripts" folder, excluding all .ps1 files.
    .EXAMPLE
        Get-FunctionNamesInFiles -Path "C:\Scripts" -Filter "*.psm1"
        Get the names of functions defined in files in the "C:\Scripts" folder, including only .psm1 files.
    .EXAMPLE
        Get-FunctionNamesInFiles -Path "C:\Scripts" -Recurse -Exclude "*.ps1" -Filter "*.psm1"
        Get the names of functions defined in files in the "C:\Scripts" folder and all subfolders, excluding .ps1 files and including only .psm1 files.
    #>
}

function Get-ProcessStatus () {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [string]$ProcessName,
        [switch]$CPU,
        [switch]$Memory
    )

    $NumberOfLogicalProcessors=(Get-WmiObject -class Win32_processor | Measure-Object -Sum NumberOfLogicalProcessors).Sum -1

    if ($CPU) {
        $Counter = "\Process({0})\% Processor Time" -f $ProcessName
        $cookedValue = ((Get-Counter $Counter).Countersamples).cookedValue
        $value = [math]::Round(($cookedValue) / $NumberOfLogicalProcessors , 1)
        write-host "$Process CPU Utilization: $value"
    }

    If ($Memory) {
        $Counter = "Process({0})\Working Set" -f $ProcessName
        $cookedValue = ((Get-Process $Counter).Countersamples).cookedValue
        $Value = [math]::Round(($CookedValue)/1023/1024 ,1)
        Write-Host "Process memory utilization $value"
    }
    <#
    .SYNOPSIS
        Get the CPU and memory utilization of a process.
    .DESCRIPTION
        Get the CPU and memory utilization of a process by specifying the process name.
    .PARAMETER ProcessName
        The name of the process for which to get the CPU and memory utilization.
    .PARAMETER CPU
        If present, the CPU utilization of the process is returned.
    .PARAMETER Memory
        If present, the memory utilization of the process is returned.
    .EXAMPLE    
        Get-ProcessStatus -ProcessName "notepad" -CPU
        Get the CPU utilization of the "notepad" process.
    .EXAMPLE    
        Get-ProcessStatus -ProcessName "notepad" -Memory
        Get the memory utilization of the "notepad" process.
    .EXAMPLE    
        Get-ProcessStatus -ProcessName "notepad" -CPU -Memory
        Get the CPU and memory utilization of the "notepad" process.
    #>
}

function Update-DataBaseMailCredentials {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory)]
        [string]$SqlServer,
        [Parameter(Mandatory)]
        [Parameter(Mandatory=$false)]
        [string]$MailAccount,
        [Parameter(Mandatory)]
        [string]$MailUser,
        [Parameter(Mandatory)]        
        [string]$MailPassword
    )

    # This SQL script retrieves the current SQL Database Mail configurations
    $sqlGetDbMailAccounts = @"
SELECT [sysmail_server]
    ,[account_id]
    ,[sysmail_account].[name] AS [AccountName]
    ,[servertype]
    ,[servername] AS [SMTPServerAddress]
    ,[Port]
    ,[Username]

FROM [msdb].[dbo].[sysmail_server]
INNER JOIN [msdb].[dbo].[sysmail_account]
ON [sysmail_server].[account_id]=[sysmail_account].[account_id]
"@

If ($MailAccount) {
    $sqlGetDbMailAccounts += " WHERE [sysmail_account].[name] = '$MailAccount'"
}

    # this SQL script updates the Database Mail account for the Account Id.
    $sqlUpdateDbMailAccount = @"
EXEC [dbo].[sysmail_update_account_sp] 
    @account_id='{0}'
    ,@username='{1}'
    ,@password='{2}'
"@

    # Retrieve the Database Mail Accounts
    $dbMailAccounts = Invoke-Sqlcmd -ServerInstance $sqlserver -Database msdb -Query $sqlGetDbMailAccounts

    # Loop through each account and check if the username has changed.
    # if the username has changed update the Database Mail configuration.
    foreach ($dbMailAccount in $dbMailAccounts) {
        If ($dbMailAccount.Username -ne $ses_creds.SmtpUsername) {
            try{
                $Procedure = $sqlUpdateDbMailAccount -f $dbMailAccount.account_Id, $MailUser, $MailPassword
                $result = Invoke-Sqlcmd -ServerInstance $sqlserver -Database 'msdb' -Query $Procedure
            } catch {
                Write-Log $result
                throw $result
            }
            $msg = "Database mail account {0} updated to new credentials." -f $dbMailAccount.AccountName
            Write-Log $msg
        }
    }
    <#
    .SYNOPSIS
        Update the credentials for SQL Database Mail.
    .DESCRIPTION
        Update the credentials for SQL Database Mail by specifying the SQL Server, Database, Mail Server, Mail User, and Mail Password.
    .PARAMETER SqlServer
        The SQL Server to update the Database Mail credentials.
    .PARAMETER MailAccount      
        The name of the Database Mail account to update. If not specified, all accounts are updated.
    .PARAMETER MailUser
        The new username for the Database Mail account.
    .PARAMETER MailPassword
        The new password for the Database Mail account.
    .EXAMPLE
        Update-DataBaseMailCredentials -SqlServer "SQLServer01" -MailAccount "MailAccount01" -MailUser "user01" -MailPassword "password01"
        Update the credentials for the Database Mail account "MailAccount01" on SQL Server "SQLServer01" with the username "user01" and password "password01".
    .EXAMPLE
        Update-DataBaseMailCredentials -SqlServer "SQLServer01" -MailUser "user01" -MailPassword "password01"
        Update the credentials for all Database Mail accounts on SQL Server "SQLServer01" with the username "user01" and password "password01". 
    #>
}

function ConvertTo-LocalTime() {
    param( 
        [parameter(Mandatory=$true)]
        [Datetime]$DateTime 
    )
    $tz = Get-TimeZone
    $result = [System.TimeZoneInfo]::ConvertTimeBySystemTimeZoneId($DateTime, $tz.StandardName)
    return $result
    <#
    .SYNOPSIS
        Convert a UTC time to local time.
    .DESCRIPTION
        Convert a UTC time to local time.
    .PARAMETER DateTime
        The UTC time to convert to local time.
    .EXAMPLE
        ConvertTo-LocalTime -DateTime "2021-01-01 12:00:00"
        Convert the UTC time "2021-01-01 12:00:00" to local time.   
    .EXAMPLE
        ConvertTo-LocalTime -DateTime (Get-Date)
        Convert the current UTC time to local time.
    #>
}

function ConvertFrom-LocalTime() {
    [CmdletBinding(DefaultParameterSetName = 'Name')]
    Param(
        [Parameter(
            Mandatory = $true
        )]
        [DateTime]$DateTime,
        [Parameter(
            Mandatory = $true,
            ParameterSetName = "Name"
        )]
        [String]$StandardName,
        [Parameter(
            Mandatory =$true,
            ParameterSetName = "tz"
        )]
        [TimeZoneInfo]$Tz
    )
    if ($StandardName) {
        $Tz = Get-TimeZone -Name $StandardName
    }

    $result = [System.TimeZoneInfo]::ConvertTime($datetime, $Tz)
    return $result
    <#
    .SYNOPSIS
        Convert a local time to UTC time.
    .DESCRIPTION
        Convert a local time to UTC time.
    .PARAMETER DateTime       
        The local time to convert to UTC time.  
    .PARAMETER StandardName
        The standard name of the time zone to use for the conversion.
    .PARAMETER Tz
        The time zone to use for the conversion.
    .EXAMPLE    
        ConvertFrom-LocalTime -DateTime "2021-01-01 12:00:00" -StandardName "Eastern Standard Time"
        Convert the local time "2021-01-01 12:00:00" to UTC time using the "Eastern Standard Time" time zone.   
    .EXAMPLE
        ConvertFrom-LocalTime -DateTime (Get-Date) -Tz (Get-TimeZone -Name "Eastern Standard Time")
        Convert the current local time to UTC time using the "Eastern Standard Time" time zone.
    #>
}

function ConvertFrom-UTC() {
    Param(
        [Parameter(
            Mandatory = $true
        )]
        [datetime]$DateTime
    )
    $tz = Get-TimeZone
    $result = [System.TimeZoneInfo]::ConvertTimeFromUtc($Datetime, $tz)
    return $result
    <#
    .SYNOPSIS
        Convert a UTC time to local time.
    .DESCRIPTION    
        Convert a UTC time to local time.
    .PARAMETER DateTime      
        The UTC time to convert to local time.
    .EXAMPLE
        ConvertFrom-UTC -DateTime "2021-01-01 12:00:00"
        Convert the UTC time "2021-01-01 12:00:00" to local time.
    .EXAMPLE    
        ConvertFrom-UTC -DateTime (Get-Date)
        Convert the current UTC time to local time.
    #>
}

function ConvertTo-UTC() {
    Param(
        [Parameter(
            Mandatory = $true
        )]
        [DateTime]$time
    )
    $tz = Get-TimeZone
    $result = [System.TimeZoneInfo]::ConvertTimeToUtc($datetime, $tz)
    return $result

    <#
    .SYNOPSIS
        Convert a local time to UTC time.
    .DESCRIPTION
        Convert a local time to UTC time.
    .PARAMETER DateTime
        The local time to convert to UTC time.
    .EXAMPLE
        ConvertTo-UTC -DateTime "2021-01-01 12:00:00"
        Convert the local time "2021-01-01 12:00:00" to UTC time.
    .EXAMPLE
        ConvertTo-UTC -DateTime (Get-Date)
        Convert the current local time to UTC time.
    #>
}

function Write-ConsoleOnly {
    [CmdletBinding()]
    param(
        [Parameter(Position=0, ValueFromPipeline=$true)]
        [string]$Message='',
        
        [Parameter()]
        [ConsoleColor]$ForegroundColor = [Console]::ForegroundColor,
        
        [Parameter()]
        [ConsoleColor]$BackgroundColor = [Console]::BackgroundColor,
        
        [Parameter()]
        [switch]$NoNewline
    )
    
    # Save original colors
    $originalForeground = [Console]::ForegroundColor
    $originalBackground = [Console]::BackgroundColor
    
    # Set new colors
    [Console]::ForegroundColor = $ForegroundColor
    [Console]::BackgroundColor = $BackgroundColor
    
    # Write to console only
    if ($NoNewline) {
        [Console]::Write($Message)
    } else {
        [Console]::WriteLine($Message)
    }
    
    # Restore original colors
    [Console]::ForegroundColor = $originalForeground
    [Console]::BackgroundColor = $originalBackground

    <#
    .SYNOPSIS
        Write a message to the console only.
    .DESCRIPTION
        Write a message to the console only, without sending it to the pipeline.
    .PARAMETER Message
        The message to write to the console.
    .PARAMETER ForegroundColor
        The foreground color of the message.
    .PARAMETER BackgroundColor
        The background color of the message.
    .PARAMETER NoNewline
        If present, the message is written without a newline character.
    .Example
        Write-ConsoleOnly -Message "This is a test message"
        Write the message "This is a test message" to the console.
    .EXAMPLE
        Write-ConsoleOnly -Message "This is a test message" -ForegroundColor Green -BackgroundColor Black
        Write the message "This is a test message" to the console with green foreground and black background colors.
    .EXAMPLE    
        Write-ConsoleOnly -Message "This is a test message" -ForegroundColor Green -BackgroundColor Black -NoNewline
        Write the message "This is a test message" to the console with green foreground and black background colors without a newline character.    
    .EXAMPLE
        "This is a test message" | Write-ConsoleOnly -ForegroundColor Green -BackgroundColor Black
        Write the message "This is a test message" to the console with green foreground and black background colors.
    .EXAMPLE
        "This is a test message" | Write-ConsoleOnly -ForegroundColor Green -BackgroundColor Black -NoNewline
        Write the message "This is a test message" to the console with green foreground and black background colors without a newline character.
    #>
}