# SNS-AutoScript

This Powershell module allows to convert CSV exports from formatted Excel sheets to exploitable Stormshield CLI scripts.

## Getting started

### Prerequisites

In order to execute Powershell scripts onto your machine, you need to set Powershell scripts execution policy to `Unrestricted`. Open a new Powershell terminal as Administrator and paste :

```
PS > Set-ExecutionPolicy Unrestricted -Force
```

### Installation

**Install by cloning the repository**

```
PS > git clone git@github.com:Syyyyyn/SNS-AutoScript.git
```

**Install by downloading the .zip archive**

You can download a `.zip` archive of the repository follwing this [link](https://github.com/Syyyyyn/SNS-AutoScript/archive/master.zip).

## Features

### Quick use

1. Open `export.xlsx` and provide all the informations about the objects you want to create on your Stormshield SNS appliance. Delimiter **must be** `;` (semicolon) in order to be parsed.
2. Export the sheets to CSV (using UTF-8 encoding is highly recommended)
3. Execute `SNS-AutoScript.ps1` :

```
PS > .\SNS-AutoScript.ps1 -CSVFile .\export.csv -ExportType MACHINE
```

By default, the script will be named `stormshield_cli.script`. You can **specify a name for the output script** by using the `-OutputFileName` option :

```
PS > .\SNS-AutoScript.ps1 -CSVFile .\export.csv -ExportType MACHINE -OutputFileNale custom_name
```

The `-ExportType` option supports the values `MACHINE`, `NETWORK`, `PORT` in reference to the formatted sheets in the Excel file.

### Advanced features

#### TicketID

By using the `-TicketID` option, you can provide additionnal information such as ticket unique identifier to the comment of the objects created :

```
PS > .\SNS-AutoScript.ps1 -CSVfile .\export.csv -ExportType NETWORK -TicketID 12345678
---
Output:

CONFIG OBJECT NETWORK NEW name="NET_3.7.35.0/25" comment="17052020-12345678" ip=3.7.35.0 mask=255.255.255.128
CONFIG OBJECT NETWORK NEW name="NET_3.21.137.128/25" comment="17052020-12345678" ip=3.21.137.128 mask=255.255.255.128
CONFIG OBJECT NETWORK NEW name="NET_3.22.11.0/24" comment="17052020-12345678" ip=3.22.11.0 mask=255.255.255.0
```

By default, a blank comment section will be filled with date format `ddMMyyy` (e.g. 17052020).

#### Group

By using the `-Group` option, you can specify a group in which all the items will be stored in.

```
PS > .\SNS-AutoScript.ps1 -CSVfile .\export.csv -ExportType MACHINE -Group "LAN machines"
---
Output :

CONFIG OBJECT HOST NEW name="SRV-DC01" comment="Main domain controller" ip="192.168.1.5" resolve=static mac="0A:00:27:00:00:28"
CONFIG OBJECT HOST NEW name="SRV-DC02" comment="Secondary domain controller" ip="192.168.1.6" resolve=static mac="B4:2E:99:96:06:6F"
CONFIG OBJECT HOST NEW name="SRV-EXCHANGE" comment="17052020" ip="192.168.1.7" resolve=static mac=""
CONFIG OBJECT GROUP NEW name="LAN machines" comment="17052020"
CONFIG OBJECT GROUP ADDTO group="LAN machines" node="SRV-DC01"
CONFIG OBJECT GROUP ADDTO group="LAN machines" node="SRV-DC02"
CONFIG OBJECT GROUP ADDTO group="LAN machines" node="SRV-EXCHANGE"
```

#### Overwrite

By using the `-Overwrite` option, the module will overwrite any data in the output file if the path exists.

## Licence

This software is under [GNU General Public License v3.0](https://opensource.org/licenses/GPL-3.0).