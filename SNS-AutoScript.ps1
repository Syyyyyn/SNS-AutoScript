<#
.SYNOPSIS
Converts CSV export to exploitable Stormshield CLI script.
.DESCRIPTION
This module helps to convert CSV exports from formatted Excel sheets to exploitable Stormshield CLI script.

-**CSVfile**
    The path of the CSV file to read.
-ExportType
    The type of CSV export: MACHINE, NETWORK, PORT, PORT_RANGE.
-OutputFileName [Optional]
    The path of the Stormshield CLI script to be created.
-Overwrite [Optional]
    If provided, the script will overwrite any file at {OutputFileName} location.
.PARAMETER CSVfile
The path of the CSV file to read.
.PARAMETER ExportType
The type of CSV export: MACHINE, NETWORK, PORT, PORT_RANGE.
.PARAMETER OutputFileName
The path of the Stormshield CLI script to be created.
.PARAMETER Overwrite
If provided, the script will overwrite any file at {OutputFileName} location.
.EXAMPLE
SNS-AutoScript -CSVfile export.csv -ExportType NETWORK -Name stormshield_cli.script
.LINK
https://github.com/Syyyyyn/SNS-AutoScript
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory=$true)]
    [string]$CSVfile,

    [Parameter(Mandatory=$true)]
    [ValidateSet("MACHINE", "NETWORK", "PORT", "PORT_RANGE")]
    [string]$ExportType,

    [Parameter()]
    [string]$OutputFileName = "stormshield_cli",

    [Parameter()]
    [string]$Group,

    [Parameter()]
    [string]$TicketID,

    [Parameter()]
    [switch]$Overwrite
)

function CIDR2PointedDecimal ($CIDR) {
    $CIDR_binary = ('1' * $CIDR).PadRight(32, "0")
    $CIDR_decimal = $CIDR_binary -split '(.{8})' -ne ''
    return ($CIDR_decimal | ForEach-Object -Process {[Convert]::ToInt32($_, 2) }) -join '.'
}

function IPAddressVerifyFormat ($string) {
    if (!($string -match "^((\d){1,3}\.){3}(\d){1,3}$")) { return $false }
    foreach ($byte in $string.Split(".")) { if (!([int]$byte -ge 0 -and [int]$byte -le 255)) { return $false } }
    return $true
}

function MACAddressVerifyFormat ($string) {
    if ($string -match "^(([a-f]|[A-F]|\d){2}:){5}([a-f]|[A-F]|\d){2}$") { 
        return $true
    } else { return $false }
}

function DefaultComment ($TicketID) {
    if (!([string]::IsNullOrEmpty($TicketID))) {
        return [string](Get-Date -Format ddMMyyyy) + "-" + $TicketID
    } else { return [string](Get-Date -Format ddMMyyyy) }
}

class Machine {
    [string]$Name
    [string]$Comment
    [string]$IPAddress
    [string]$Resolve
    [string]$MACAddress

    Machine(
        [string]$CSVLine,
        [string]$TicketID
    ){
        # Set attribute {IPAddress}
        # Verify if the provided IP address format is valid (e.g. 192.168.1.1).
        if (IPAddressVerifyFormat($CSVLine.Split(";")[2])) {
            $this.IPAddress = $CSVLine.Split(";")[2]
        } else { Throw 'ERROR: {0} is not a valid IP address.' -f ($CSVLine.Split(";")[2])}
        
        # Set attribute {MACAddress}
        # Verify if the provided MAC address format is valid (e.g. 0A:00:27:00:00:28).
        if (!([string]::IsNullOrEmpty($CSVLine.Split(";")[4]))) {
            if (MACAddressVerifyFormat($CSVLine.Split(";")[4])) {
                $this.MACAddress = $CSVLine.Split(";")[4]
            } else { Throw 'ERROR: {0} is not a valid MAC address.' -f ($CSVLine.Split(";")[4]) }
        } else { $this.MACAddress = "" }
        

        # Set attribute {Resolve}
        # Verify if the provided value matches an acceptable value.
        switch ($CSVLine.Split(";")[3]) {
            "dynamique" { $this.Resolve = "dynamic" } #FIXME: Vérifier la valeur possible pour le champ "resolve" sur la CLI
            "statique" { $this.Resolve = "static" }
            Default { Throw "ERROR: Wrong resolve option." }
        }
        
        # Set attribute {Name}
        # If no name was provided, default name will be set to format IP_{IPAddress} (e.g. IP_192.168.10.5).
        if ([string]::IsNullOrEmpty($CSVLine.Split(";")[0])) {
            $this.Name = "IP_" + $this.IPAddress
        } else { $this.Name = $CSVLine.Split(";")[0] }

        # Set attribute {Comment}
        # If no comment was provided, default comment will be set to date format ddMMyyyy{\-ticketID} (e.g. 17052020).
        if ([string]::IsNullOrEmpty($CSVLine.Split(";")[1])) {
            $this.Comment = DefaultComment($TicketID)
        } else { $this.Comment = $CSVLine.Split(";")[1] }
    }

    [string]GetName(){ return $this.Name }

    # Return the CLI command that describes the object.
    [string]GetCLICommand(){
        $cli = 'CONFIG OBJECT HOST NEW name="{0}" comment="{1}" ip="{2}" resolve={3} mac="{4}"' -f ($this.Name, $this.Comment, $this.IPAddress, $this.Resolve, $this.MACAddress)
        return $cli
    }
}

class Network {
    [string]$Name
    [string]$Comment
    [string]$NetworkID
    [string]$Netmask

    Network(
        [string]$CSVLine,
        [string]$TicketID
    ){
        # Set attribute {NetworkID}
        # Verify if the provided IP address format is valid (e.g. 192.168.1.1).
        if (IPAddressVerifyFormat($CSVLine.Split(";")[2].Split("/")[0])) {
            $this.NetworkID = $CSVLine.Split(";")[2].Split("/")[0]
        } else { Throw 'ERROR: {0} is not a valid network.' -f ($CSVLine.Split(";")[2])}
        
        # Set attribute {Netmask}
        # Verify if CIDR notation is valid and convert CIDR to pointed decimal subnet mask (e.g. /24 -> 255.255.255.0).
        if ([int]$CSVLine.Split(";")[2].Split("/")[1] -ge 1 -and [int]$CSVLine.Split(";")[2].Split("/")[1] -le 32) {
            $this.Netmask = CIDR2PointedDecimal($CSVLine.Split(";")[2].Split("/")[1])
        } else { Throw 'ERROR: {0} is not a valid subnet mask. Must be in range 1-32.' -f ($CSVLine.Split(";")[2].Split("/")[1]) }
        
        # Set attribute {Name}
        # If no name was provided, default name will be set to format NET_{networkID} (e.g. NET_192.168.0.0/24).
        if ([string]::IsNullOrEmpty($CSVLine.Split(";")[0])) {
            $this.Name = "NET_" + $this.NetworkID + "/" + $CSVLine.Split(";")[2].Split("/")[1]
        } else { $this.Name = $CSVLine.Split(";")[0] }
        
        # Set attribute {Comment}
        # If no comment was provided, default comment will be set to date format ddMMyyyy (e.g. 17052020).
        if ([string]::IsNullOrEmpty($CSVLine.Split(";")[1])) {
            $this.Comment = DefaultComment($TicketID)
        } else { $this.Comment = $CSVLine.Split(";")[1] }
    }

    [string]GetName(){ return $this.Name }

    # Return the CLI command that describes the object.
    [string]GetCLICommand(){
        $cli = 'CONFIG OBJECT NETWORK NEW name="{0}" comment="{1}" ip={2} mask={3}' -f ($this.Name, $this.Comment, $this.NetworkID, $this.Netmask)
        return $cli
    }
}

class Port {
    [string]$Name
    [string]$Comment
    [string]$Port
    [string]$Protocol

    Port(
        [string]$CSVLine,
        [string]$TicketID
    ){
        # Set attribute {Port}
        # Verify if provided value is in range 1-65535.
        if ([int]$CSVLine.Split(";")[2] -ge 1 -and [int]$CSVLine.Split(";")[2] -le 65535) {
            $this.Port = $CSVLine.Split(";")[2]
        } else { Throw 'ERROR: {0} is not in range 1-65535.' -f ($CSVLine.Split(";")[2]) }

        # Set attribue {Protocol}
        # Verify if the provided value matches an acceptable value.
        switch ($CSVLine.Split(";")[3]) {
            "TCP" { $this.Protocol = "TCP" }
            "UDP" { $this.Protocol = "UDP" }
            "Any" { $this.Protocol = "Any" }
            Default { Throw 'ERROR: {0} is not a valid protocol.' -f ($CSVLine.Split(";")[2]) }
        }

        # Set attribute {Name}
        # If no name was provided, default name will be set to format {Protocol}_{Port} (e.g. TCP_8443).
        if ([string]::IsNullOrEmpty($CSVLine.Split(";")[0]) -and $this.Protocol -eq "Any") {
            $this.Name = "TCP/UDP_" + $this.Port
        } elseif ([string]::IsNullOrEmpty($CSVLine.Split(";")[0])) {
            $this.Name = $this.Protocol + $this.Port
        } else { $this.Name = $CSVLine.Split(";")[0] }

        # Set attribute {Comment}
        # If no comment was provided, default comment will be set to date format ddMMyyyy (e.g. 17052020).
        if ([string]::IsNullOrEmpty($CSVLine.Split(";")[1])) {
            $this.Comment = DefaultComment($TicketID)
        } else { $this.Comment = $CSVLine.Split(";")[1] }
    }

    [string]GetName(){ return $this.Name }

    [string]GetCLICommand(){
        $cli = 'CONFIG OBJECT SERVICE NEW name="{0}" comment="{1}" port={2} proto={3}' -f ($this.Name, $this.Comment, $this.Port, $this.Protocol)
        return $cli
    }
}

# Ensure a CSV file was provided and thow an exception if not.
if (!($CSVfile -match "^.*\.csv$")) { Throw 'ERROR:  is not a CSV file.' -f ($CSVfile) }

$isFirstline = $true
$script = [System.Collections.ArrayList]@()
$object_list = [System.Collections.ArrayList]@()
$group_list = [System.Collections.ArrayList]@()

# Create the appropriate group or servicegroup if {Group} option was provided.
if (!([string]::IsNullOrEmpty($Group))) {
    if ($ExportType -in "MACHINE", "NETWORK", "IP_RANGE") {
        $cli = 'CONFIG OBJECT GROUP NEW name="{0}" comment="{1}"' -f ($Group, $(DefaultComment($TicketID)))
        [void]$group_list.Add($cli)
    } elseif ($ExportType -in "PORT", "PORT_RANGE") {
        $cli = 'CONFIG OBJECT SERVICEGROUP NEW name="{0}" comment="{1}"' -f ($Group, $(DefaultComment($TicketID)))
        [void]$group_list.Add($cli)
    } else { Throw 'ERROR: {0} is not a valid method.' -f ($ExportType) }
}

# For each line in the CSV export file, generate the CLI command to create the object.
# If {Group} option was provided, generate the CLI command to add the object to the group.
foreach ($line in Get-Content $CSVfile) {
    if ($isFirstLine) { $isFirstline = $false } else {
        switch ($ExportType) {
            "MACHINE" {
                [void]$object_list.Add([Machine]::new($line, $TicketID).GetCLICommand())
                if (!([string]::IsNullOrEmpty($Group))) {
                    $cli = 'CONFIG OBJECT GROUP ADDTO group="{0}" node="{1}"' -f ($Group, [Machine]::new($line, $TicketID).GetName())
                    [void]$group_list.Add($cli)
                }
            }
            "NETWORK" { 
                [void]$object_list.Add([Network]::new($line, $TicketID).GetCLICommand())
                if (!([string]::IsNullOrEmpty($Group))) {
                    $cli = 'CONFIG OBJECT GROUP ADDTO group="{0}" node="{1}"' -f ($Group, [Network]::new($line, $TicketID).GetName())
                    [void]$group_list.Add($cli)
                }
            }
            "IP_RANGE" { 
                Write-Host "IP_RANGE: Unavailable feature."
            }
            "PORT" { 
                [void]$object_list.Add([Port]::new($line, $TicketID).GetCLICommand())
                if (!([string]::IsNullOrEmpty($Group))) {
                    $cli = 'CONFIG OBJECT SERVICEGROUP ADDTO group="{0}" node="{1}"' -f ($Group, [Port]::new($line, $TicketID).GetName())
                    [void]$group_list.Add($cli)
                }
            }
            "PORT_RANGE" {
                Write-Host "PORT_RANGE: Unavailable feature."
            }
            Default { Throw 'ERROR: {0} is not a valid method.' -f ($ExportType) }
        }
    }
}


[void]$script.Add($object_list)
[void]$script.Add($group_list)
[void]$script.Add("CONFIG OBJECT ACTIVATE")

if ($Overwrite) {
    Write-Output $script > $PSScriptRoot\$OutputFileName.script
} else { Write-Output $script >> $PSScriptRoot\$OutputFileName.script }