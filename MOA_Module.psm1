using namespace System.Collections.Generic

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
