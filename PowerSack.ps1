<#
.SYNOPSIS
    This script attempts to search files on SMB shares for strings of text. It takes a list of hosts, a list of credentials to try authenticating with, and a list of strings to search for.  

.DESCRIPTION
    We want to try every share, with every set of credentials, and we don't want to spend much time looking through large files or binary stuff.

.EXAMPLE
    .\PowerSack.ps1 -HostListFile .\hosts.txt -FileContentsKeywordListFile .\keywords.txt -CredentialListFile .\credentials.txt
    Authenticate to all of the hosts listed in hosts.txt as all of the users in credentials.txt, and search for all of the strings listed in keywords.txt 

.EXAMPLE 
    .\PowerSack.ps1 -HostlistFIle .\hosts.txt -CredentialListFile .\credentials.txt -InfoOnly
    Authenticate to shares as the current shell user and skip scanning - return information about user access and a file list for each share.
    Recommended to run this first if you're in a large, unfamiliar environment.

.EXAMPLE
    .\PowerSack.ps1 -HostListFile .\hosts.txt -FileContentsKeywordListFile .\keywords.txt -CredentialListFile .\credentials.txt -MaxFileSize 200MB -IgnoreFileNamePatterns *.pshh,*Wack*
    Same as above but increase file size filter and exclude files with Wack in the name, or ending with .pshh, in addition to default exclude list. 

.EXAMPLE
    .\PowerSack.ps1 -HostListFile .\hosts.txt -FileContentsKeywordListFile .\keywords.txt -CredentialListFile .\credentials.txt -Verbose 4>&1 | Out-File powersackresults.txt
    Same as example 1 but include verbose details, redirect verbose and stdout to a file. 

.PARAMETER HostListFile
    A file containing a newline-separated list of hosts. Hosts can be described by IP address or a resolvable name. I don't yet support ranges, entries must be explicit. 
    EZ turn range into IP list hint: nmap -sL -n <YOUR-CIDR> | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'

.PARAMETER FileContentsKeywordListFile
    A file containing a newline-separated list of strings to search for in file contents and file names. Seach will be case insensitive.

.PARAMETER FileNameKeywordListFile
    A file containing a newline-separated list of strings to search for in file names, but not within file contents. Seach will be case insensitive.
    This is useful for looking for "password", "shadow", "id_*" files etc without getting all the false positives that may occur for common or short words.
    
.PARAMETER CredentialListFile
    A file containing a newline-separated list of credential pairs, where username and password are separated by a colon. For example:
    
    localusername1:password1
    DOMAIN\username2:password2

.PARAMETER InfoOnly
    Set this switch if you only want to return accessible share names and top-level files without scanning for strings.

.PARAMETER UseWindowsAuth
    Set this switch if you want to use the current windows user instead of a credential list file.

.PARAMETER IgnoreFileNamePatterns
    Comma-separated list of filename patterns to ignore. 
    By default, this script ignores several file extensions, detailed in the AllFileExtensions parameter description.
    This is most commonly to filter additional extensions, like: *.dat,*.jpg,*.psd
    But can be more complex to match on the entire name: *.xlsx,Vid*.mpeg

.PARAMETER SpecificFileNamePatterns
    Comma-separated list of filename patterns to search; anything that does not match will not be searched.
    Example: *.txt,*Financials*,*.bat,*.xml

.PARAMETER UseBuiltinTextFilePatterns
    To save you the hassle, the script includes a list of common text file extensions as a filter.
    If it's missing something important let me know!

.PARAMETER IgnoreShareNames
    Comma-separated list of share names to ignore. 

.PARAMETER MaxFileSize
    Maximum file size to scan. Defaults to 5MB. Probably want to make it smaller if you're on a big network.
    This thing can be an integer representing number of bytes, or human shorthand for larger quantities, like 2MB, 2GB, 2TB, etc. 

.PARAMETER AllFileExtensions
    Search through all files, regardless of extension. By default, this script ignores files with extensions indicating they're not text.

.PARAMETER ShowShareRootContents
    If a share was accessible, print its root directory contents. This is on by default if you do -InfoOnly, but not if you're doing a keyword scan.

.LINK
    https://www.youtube.com/watch?v=nA5WsSyO2BM
.LINK
    https://en.wikipedia.org/wiki/Acabou_Chorare
.LINK
    https://en.wikipedia.org/wiki/A_Tabua_de_Esmeralda
#>
#To see the help page formatted nicely, Run:  Get-Help .\PowerSack.ps1 -Full

##TODO Provide different filters for extensions/names
##TODO Can I scan filenames and contents at the same time
##TODO Use Windows Auth Too ANd UnAuth 
##TODO Better way to handle file read errors (-ErrorAction Silently COntinue?)
##TODO add some default keywords
##TODO Use PSDrive instead of net use /view
##TODO Choose user for TLD 

[CmdletBinding()]
param(
    [Parameter(Mandatory=$True)]
    [string] $HostListFile,
    [string] $FileContentsKeywordListFile,
    [string] $FileNameKeywordListFile,
    [string] $CredentialListFile,
    [string []] $IgnoreFileNamePatterns,
    [string []] $SpecificFileNamePatterns,
    [switch] $UseBuiltinTextFilePatterns,
    [switch] $AllFileExtensions,
    [string []] $IgnoreShareNames,
    [switch] $InfoOnly,
    [switch] $UseWindowsAuth,
    [switch] $ShowShareRootContents,
    $MaxFileSize=5MB
)

$AutoExcludedExtensions = @("*.dll.*", "*.dll", "*.exe.*", "*.exe", "*.msi", "*.dmg", "*.png", "*.pdb", "*.pdb.*", "*.gif", "*.h", "*.mp4", "*.adml", "*.jpg", "*.rar", "*.zip", "*.iso", "*.bin", "*.avi", "*.mkv", "*.git", "*.svn", "*.7z")
$AutoExcludedShares = @("C$", "ADMIN$", "print$", "Users")

$BuiltinTextFilePatterns = @("*.txt", "*.bat", "*.ps1", "*.config", "*.conf", "*.cnf", "*.cfg", "*.settings", "*.xml", "*.doc", "*.csv", "*.ini", "*.yaml", "*.json", "*.log", "*.crt", "*.pem")

$Hosts = @()
$Credentials = @()
$IgnoredShares = @()
$ContentKeywords = @()
$FileNameKeywords = @()
$IncludeNamePatterns = @()

############ Validate Input Parameters #$#####
try 
{
    if($HostListFile)
    {
      $Hosts = Get-Content -Path $HostListFile -ErrorAction Stop
    }
    if($FileContentsKeywordListFile)
    {
      $ContentKeywords = Get-Content -Path $FileContentsKeywordListFile -ErrorAction Stop
    }
    if($FileNameKeywordListFile)
    {
      $FileNameKeywords = Get-Content -Path $FileNameKeywordListFile -ErrorAction Stop
    }
    if($CredentialListFile)
    {
      $Credentials = Get-Content -Path $CredentialListFile -ErrorAction Stop
    }
}
catch [System.Exception]
{
    throw "An error already! The HostListFile, FileContentsKeywordListFile, FileNameKeywordListFile or CredentialListFile is _unreadable_."
}

if ( (-not $InfoOnly) -and (-not $FileContentsKeywordListFile) -and (-not $FileNameKeywordListFile) )
{
  throw "You have to specify either -InfoOnly or -FileContentsKeywordListFile or -FileNameKeywordListFile"
}

#This is like ParameterSets, but uglier. There's gotta be a better way 
if( ($IgnoreFileNamePatterns -and ($SpecificFileNamePatterns -or $AllFileExtensions)) -or ($SpecificFileNamePatterns -and ($IgnoreFileNamePatterns -or $AllFileExtensions)) -or ($AllFileExtensions -and ($IgnoreFileNamePatterns -or $SpecificFileNamePatterns)))
{
  throw "You provided too many file name pattern options. There should only be one of: [IgnoreFileNamePatterns, SpecificFileNamePatterns, AllFileExtensions]"
}

if( (-Not $UseWindowsAuth) -and (-not $CredentialListFile))
{
  throw "You have to specify either -UseWindowsAuth or -CredentialListFile"
}

if($UseWindowsAuth)
{
  $Credentials += "Windows"
}

#########################################

#If additional share names are provided to ignore, add them to our autoexclude list
if($IgnoreShareNames)
{
  $IgnoredShares = $AutoExcludedShares + $IgnoreShareNames
}
else {
  $IgnoredShares = $AutoExcludedShares
}

#if additional name patterns are desired, add them to our list
if($SpecificFileNamePatterns)
{
  $IncludeNamePatterns += $SpecificFileNamePatterns
}
if($UseBuiltinTextFilePatterns)
{
  $IncludeNamePatterns += $BuiltinTextFilePatterns
}

# robbed from https://web.archive.org/web/20150405035615/http://poshcode.org/85
# this is used because `net use` has a long timeout for failed connections
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

Write-Output-Timestamp "Starting scan!" 

foreach ($CurrentHost in $Hosts)
{
    Write-Verbose-Timestamp "Connecting to $CurrentHost..."
    #check connection quickly
    if (-Not (Test-SMBPortConnection($CurrentHost)))
    {
        Write-Verbose "Could not connect to port 445 on $CurrentHost. Moving on."
        continue
    }

    #using these lists to keep track of what we have already scanned for output trimming
    $ScannedFiles = @()
    $NameScanned = @()

    #Hashmap where ShareName is key, list of users with access is value.
    $AccessTable = @{}

    #Did did any user successfully map?
    $HostMapped = 0

    foreach ($CurrentCredential in $Credentials)
    {
        if($CurrentCredential -eq "Windows")
        {
          $CurrentUser = whoami
          Write-Verbose-Timestamp("Connecting as $CurrentUser@$CurrentHost")
          #This echo pipe thing is to pass the prompt net use gives if the creds fail. 
          echo '' | net use \\$CurrentHost\IPC$ /persistent:no 2>$null | Out-Null
        }
        else {
          $CurrentUser = $CurrentCredential.split(":")[0]
          $CurrentPassword = $CurrentCredential.split(":")[1]

          Write-Verbose-Timestamp("Connecting as $CurrentUser@$CurrentHost")

          #establish the smb mapping
          net use \\$CurrentHost\IPC$ /user:$CurrentUser "$CurrentPassword" /persistent:no 2>$null | Out-Null
        }
        
        #Check the AUTOMATIC VARIABLE https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_automatic_variables
        if ($LASTEXITCODE -ne 0) {
            Write-Verbose "Could not map $CurrentHost as $CurrentUser. Moving on."
            continue
        }

        $HostMapped = 1

        #give that a second and parse the shares
        Start-Sleep -Seconds 1
        $Shares = net view \\$CurrentHost /all | where {$_ -match 'disk*'} | foreach {$_ -match '^(.+?)\s+Disk*'| out-null;$matches[1]}
        Write-Verbose-Timestamp $Shares
        $FilteredShares = $Shares | Where-Object {$_ -notin $IgnoredShares } 

        $PrintableShares = $Shares -join ', '
        $PrintableFilteredShares = $FilteredShares -join ', '

        Write-Verbose-Timestamp("Found the following shares: $PrintableShares")
        Write-Verbose-Timestamp("After share filtering, only scanning files in: $PrintableFilteredShares")

        foreach ($CurrentShare in $Shares)
        {
            #if the share isn't in the access table as a key, add that with an empty list val.
            if ( -Not ($AccessTable.ContainsKey($CurrentShare)))
            {
              $AccessTable[$CurrentShare] = @(@(), @())
            }

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
                #$ErrorMessage = $_.Exception.Message
                #Write-Verbose-Timestamp("Error: $ErrorMessage")
                Write-Verbose-Timestamp("$CurrentUser does not have read access to $CurrentShare")
                continue
            }

            if($InfoOnly) { continue }
            if( -Not ($FilteredShares -Contains $CurrentShare)) { 
              Write-Verbose-Timestamp("Not scanning files in $CurrentShare as due to filter")
              continue 
            }
            
            $AllFSObjects = Get-Childitem -path \\$CurrentHost\$CurrentShare -Recurse -Force -ErrorAction SilentlyContinue | Where-Object {$_.FullName -notin $NameScanned }

            #check keyword matches in filenames
            foreach($FSObject in $AllFSObjects)
            {
                foreach ($CurrentKeyword in $ContentKeywords)
                {
                    $WildCardKeyword = "*" + $CurrentKeyword + "*"
                    if ($FSObject.Name -like $WildCardKeyword)
                    {
                        $FSObjectPath = $FSObject.FullName
                        Write-Output "Keyword match in filesystem path: $FSObjectPath" 
                        $NameScanned += $FSObjectPath
                    }
                }
                foreach ($CurrentKeyword in $FileNameKeywords)
                {
                    if ($FSObject.Name -like $CurrentKeyword)
                    {
                        $FSObjectPath = $FSObject.FullName
                        Write-Output "Keyword match in filesystem path: $FSObjectPath" 
                        $NameScanned += $FSObjectPath
                    }
                }
            }

            ########File Filtering Time!!!!!!!!
            if ($AllFileExtensions) #why? whatever man 
            {
                $FilteredFiles = Get-Childitem -path \\$CurrentHost\$CurrentShare -File -Recurse -Force -ErrorAction SilentlyContinue
            }
            else 
            {
                if($SpecificFileNamePatterns)
                {
                    $FilteredFiles = Get-Childitem -path \\$CurrentHost\$CurrentShare -Recurse -File -Force -ErrorAction SilentlyContinue -Include $IncludeNamePatterns 
                }
                elseif($UseBuiltinTextFilePatterns)
                {
                    $FilteredFiles = Get-Childitem -path \\$CurrentHost\$CurrentShare -Recurse -File -Force -ErrorAction SilentlyContinue -Include $IncludeNamePatterns 
                }
                else 
                {
                    $IgnoredPatterns = $IgnoreFileNamePatterns + $AutoExcludedExtensions
                    $FilteredFiles = Get-Childitem -path \\$CurrentHost\$CurrentShare -Recurse -File -Force -ErrorAction SilentlyContinue -Exclude $IgnoredPatterns 
                }
            }

            #no more large files
            $FilteredFiles = $FilteredFiles | Where-Object {$_.Length -lt $MaxFileSize}
            #and no repeats.
            $FilteredFiles = $FilteredFiles | Where-Object {$_.FullName -notin $ScannedFiles}

            #build a regex with all the keywords 
            [regex] $KeywordsRegex = '(?i)(' + (($ContentKeywords | foreach {[regex]::escape($_)}) -join "|") + ")"

            #ok actually search now
            foreach($FFile in $FilteredFiles)
            {
                try {
                  Select-String -ErrorAction 'Stop' -pattern $KeywordsRegex $FFile
                  $ScannedFiles += $FFile.FullName
                }
                catch{
                  continue
                }
            }
        }

        #Done! Remove the SMB mapping
        $SmbMapFilter = '$_."Remote Path" "*' + $CurrentHost + '*"'
        Get-SmbMapping | Where-Object {$SmbMapFilter} | Remove-SmbMapping -Force
        Start-Sleep -Seconds 2
        Write-Verbose "Done with $CurrentUser@$CurrentHost"
        Start-Sleep -Seconds 1
    } 

  if($HostMapped -eq 0)
  {
    continue
  }

  Write-Output-Timestamp "Share access info for $CurrentHost :"
  
  if($ShowShareRootContents -or $InfoOnly)
  {
    $AccessTable | Format-Table -AutoSize -Wrap @{Label="Share Name"; Expression={Write-Output $_.Key}}, @{Label="Users With Access"; Expression={$_.Value[0] | Out-String -Width 1000}}, @{Label="Top Level Directory Contents"; Expression={$_.Value[1] | Select -ExpandProperty Name | Out-String -Width 1000}}
  }
  else {
    $AccessTable | Format-Table -AutoSize -Wrap @{Label="Share Name"; Expression={Write-Output $_.Key}}, @{Label="Users With Access"; Expression={$_.Value[0] | Out-String -Width 1000}}
  }
}