[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type -AssemblyName System.Security

$configtxtdir = 'C:\ProgramData\Parsec\config.txt'

# [hashtable]$config = @{
#     [string]$key = ""
#     [string]$team_id = ""
#     [String]$host_name = $env:COMPUTERNAME
#     [int]$encoder_bitrate = 10
#     [int]$fps = 60
#     [int]$quality = 0
#     [int]$client_enhanced_pen = 1
#     [int]$client_decoder_h265 = 1
#     [bool]$client_decoder_444 = $false
#     [int]$host_virtual_monitors = 1
#     [int]$app_force_relay = 1
#     [String]$app_stun_address = ""
# }
# [int]$override_config = 0
# [int]$clear_config = 0

Class Config {
    [string]$key = $null
    [string]$team_id = $null
    [String]$host_name = $env:COMPUTERNAME
    [int]$encoder_bitrate = 10
    [int]$fps = 60
    [int]$quality = 0
    [int]$client_enhanced_pen = 1
    [int]$client_decoder_h265 = 1
    [bool]$client_decoder_444 = $null
    [int]$host_virtual_monitors = 1
    [int]$app_force_relay = 1
    [String|null]$app_stun_address = $null
}

Class ConfigInstance {
    [Config]$config = [Config]::new()
    [int]$override_config = 0
    [int]$clear_config = 0

    [ConfigInstance]pullFromUserData() {
        $userDataConfig = fetchUserData
        Write-Output $userDataConfig
        foreach ($line in $userDataConfig) {
            $this.config["$($line.split("=")[0])"] = $($line.split("=")[1])
        }
        return $this
    }

    [string]writeToConfigFile($configtxtdir) {
        if (!(Test-Path $configtxtdir)) {
        }
        if ($this.override_config -eq 1) {
            if ($this.clear_config -eq 1) {
                Out-File -FilePath $configtxtdir -Encoding ascii
            }
            $currentConfigFileContents = Get-Content $configtxtdir
            foreach($line in $currentConfigFileContents) {
                Write-Output $line
            }
            return ""
        } else {
            $output = ""
            $currentConfigFileContents = Get-Content $configtxtdir
            foreach($property in $this.config.PSObject.Properties) {
                $output += $property.Value.GetType()
                if ($null -ne $property.Value) {
                    $output += $property.Name + "=" + $property.Value
                    if (($this.override_config) -and ($currentConfigFileContents -match $property.Name)) {
                        $output += ":MATCH"
                    } else {
                        $output += ":NEW"
                    }
                    $output += ";"
                }
            }
            return "$output"
        }
    }
} 


function fetchUserData { 
    $metadata = $(
        try {
            [string]$token = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token-ttl-seconds" = "21600" } -Method PUT -Uri http: / / 169.254.169.254 / latest / api / token
            Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token } -Method GET -Uri http: / / 169.254.169.254 / latest / user-data
            $stream = "bytes"
        }
        catch {
                    
        }
    )
    if ($metadata.StatusCode -eq 200) {
        if (($metadata.Content.Length) -gt 1) { 
            if ($stream -eq "bytes") {
                [System.Text.Encoding]::ASCII.GetString($metadata.content).split(':')
            }
            elseif ($stream -eq "base64") {
                [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($metadata.Content)).split(':')
            }
        }
        else {
            #no userdata found, exiting...
            Exit
        }
    }
    else {
        #no userdata found, exiting...
        Exit
    }
}

Function WriteHostname {
    Param(
        $host_name
    )
    $configfile = Get-Content $configtxtdir
    $File = Foreach ($configline in $configfile) { 
        if ($configline -like 'host_name*') {
        }
        Else { $configline }
    }
    $file += "host_name=$host_name"
    $file | Out-File $configtxtdir -Encoding ascii
}

$RequestDetails = [ConfigInstance]::new()
# $RequestDetails.pullFromUserData()

$RequestDetails.writeToConfigFile($configtxtdir)
#Stop-Process -Name parsecd -Force -Wait
#Start-Process -Name parsecd
