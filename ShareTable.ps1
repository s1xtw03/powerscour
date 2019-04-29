#View shares as current user
#Recommended to use verbose flag and pipe output to file:
# ./ShareTable.ps1 -Verbose -HostListFile ./servers.txt > sharesaccess.txt

[CmdletBinding()]
param(
    [Parameter(Mandatory=$True)]
    [string] $HostListFile
)

try 
{
    if($HostListFile)
    {
      $Hosts = Get-Content -Path $HostListFile -ErrorAction Stop
    }
}
catch [System.Exception]
{
    throw "The HostListFile is unreadable."
}

function Test-SMBPortConnection
{
    Param([string]$srv,$port=445,$timeout=1000,[switch]$verbose)
    # Create TCP Client
    $tcpclient = new-Object system.Net.Sockets.TcpClient
    # Tell TCP Client to connect to machine on Port
    $iar = $tcpclient.BeginConnect($srv,$port,$null,$null)
    # Set the wait time
    $wait = $iar.AsyncWaitHandle.WaitOne($timeout,$false)
    # Check to see if the connection is done
    if(!$wait)
    {
        # Close the connection and report timeout
        $tcpclient.Close()
        if($verbose){Write-Verbose "Connection timeout to $srv"}
        Return $false
    }
    else
    {
        # Close the connection and report the error if there is one
        $error.Clear()
        $tcpclient.EndConnect($iar) | out-Null
        $tcpclient.Close()
    }
    # Return $true if connection Establish else $False
    if($failed){return $false}else{return $true}
}

function Write-Verbose-Timestamp
{
  Param([string]$Message="")
  $Timestamp = Get-Date -UFormat "%m/%d %T"
  Write-Verbose "[$Timestamp] $Message"
}

function Write-Output-Timestamp
{
  Param([string]$Message="")
  $Timestamp = Get-Date -UFormat "%m/%d %T"
  Write-Output "[$Timestamp] $Message"
}

Write-Output-Timestamp("Starting scan!")

foreach ($CurrentHost in $Hosts)
{
    $ScannedFiles = @()
    $NameScanned = @()

    Write-Verbose-Timestamp("************ Connecting to $CurrentHost...")
    #check connection quickly
    if (-Not (Test-SMBPortConnection($CurrentHost)))
    {
        Write-Verbose "Could not connect to port 445 on $CurrentHost. Moving on."
        continue
    }

    #Hashmap where ShareName is key, list of users with access is value.
    $AccessTable = @{}

    #Did did any user successfully map?
    $HostMapped = 0

    $CurrentUser = whoami
    Write-Verbose-Timestamp("Connecting as $CurrentUser@$CurrentHost")
    #This echo pipe thing is to pass the prompt net use gives if the creds fail. 
    echo '' | net use \\$CurrentHost\IPC$ /persistent:no 2>$null | Out-Null

    #Check the AUTOMATIC VARIABLE https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_automatic_variables
    if ($LASTEXITCODE -ne 0) {
        Write-Verbose "Could not map $CurrentHost as $CurrentUser. Moving on."
        continue
    }

    $HostMapped = 1

    #give that a second and parse the shares
    Start-Sleep -Seconds 1
    $Shares = net view \\$CurrentHost /all | where {$_ -match 'disk*'} | foreach {$_ -match '^(.+?)\s+Disk*'| out-null;$matches[1]}

    $PrintableShares = $Shares -join ', '
    Write-Verbose-Timestamp("Found the following shares: $PrintableShares")

    foreach ($CurrentShare in $Shares)
    {
        #if the share isn't in the access table as a key, add that with an empty list val.
        if ( -Not ($AccessTable.ContainsKey($CurrentShare)))
        {
          $AccessTable[$CurrentShare] = @(@(), @())
        }

        if ($CurrentShare -eq "Reception_Scans") { continue }
        if ($CurrentShare -eq "WDE$") { continue }

        Write-Verbose-Timestamp("****** Starting : $CurrentShare")

        #test if I have read access
        try 
        {
            $TopLevelDirectories = Get-Childitem -Force -path \\$CurrentHost\$CurrentShare -ErrorAction Stop 
            $AccessTable[$CurrentShare][0] += $CurrentUser

            if ($AccessTable[$CurrentShare][1].Length -lt $TopLevelDirectories.Length)
            {
              $AccessTable[$CurrentShare][1] = $TopLevelDirectories
            }

            Write-Verbose-Timestamp("Super! $CurrentUser does have read access to $CurrentShare")
        }
        catch
        {
            Write-Verbose-Timestamp("$CurrentUser does not have read access to $CurrentShare")
            continue
        }

        Write-Verbose-Timestamp("****** Finished : $CurrentShare")
        continue 
    }

    #Done! Remove the SMB mapping
    $SmbMapFilter = '$_."Remote Path" "*' + $CurrentHost + '*"'
    Get-SmbMapping | Where-Object {$SmbMapFilter} | Remove-SmbMapping -Force
    Start-Sleep -Seconds 2
    Write-Verbose "Done with $CurrentUser@$CurrentHost"
    Start-Sleep -Seconds 1
 

    if($HostMapped -eq 0)
    {
    continue
    }

    Write-Output-Timestamp "Share access info for $CurrentHost :"

    $AccessTable | Format-Table -AutoSize -Wrap @{Label="Share Name"; Expression={Write-Output $_.Key}}, @{Label="Users With Access"; Expression={$_.Value[0] | Out-String -Width 1000}}, @{Label="Top Level Directory Contents"; Expression={$_.Value[1] | Select -ExpandProperty Name | Out-String -Width 1000}}

}

# Written by John McGuiness, NCC Group