$ComputerName=$env:COMPUTERNAME

###определяет тип компьютера
function get-TypePC{
    param($PCname)
	$PCmodel=""
	$WMIinfo=gwmi win32_systemenclosure -ComputerName $PCname
	switch($WMIinfo.chassistypes){
		1 {$PCmodel="Другое";break}
		2 {$PCmodel="Unknown";break}
		3 {$PCmodel="Настольный ПК";break}
		4 {$PCmodel="Low Profile Desktop";break}
		5 {$PCmodel="Pizza Box";break}
		6 {$PCmodel="Mini Tower";break}
		7 {$PCmodel="Tower";break}
		8 {$PCmodel="Portable";break}
		9 {$PCmodel="Laptop";break}
		10 {$PCmodel="Ноутбук";break}
		11 {$PCmodel="Handheld";break}
		12 {$PCmodel="Docking Station";break}
		13 {$PCmodel="All-in-One";break}
		14 {$PCmodel="Sub-Notebook";break}
		15 {$PCmodel="Space Saving";break}
		16 {$PCmodel="Lunch Box";break}
		17 {$PCmodel="Main System Chassis";break}
		18 {$PCmodel="Expansion Chassis";break}
		19 {$PCmodel="Sub-Chassis";break}
		20 {$PCmodel="Bus Expansion Chassis";break}
		21 {$PCmodel="Peripheral Chassis";break}
		22 {$PCmodel="Storage Chassis";break}
		23 {$PCmodel="Rack Mount Chassis";break}
		24 {$PCmodel="Sealed-Case PC";break}
	}
	return $PCmodel
}
	
###Заменяет неверные размерности хардов
function get-HHDRightSize{
    param($size)
	switch($size){
		75 {$size=80;break}
		149 {$size=160;break}
		233 {$size=240;break}
		234 {$size=240;break}
		298 {$size=320;break}
		466 {$size=500;break}
		596 {$size=650;break}
		default {$size=$size;break}
	}
	return $size
}

function New-ComputerInfoApp{
    param($ComputerName)
    $ComputerAppInfo=New-Object System.Object
    $ComputerAppInfo|Add-Member -MemberType NoteProperty -Name "ComputerName" -Value $ComputerName -Force
    $ComputerAppInfo|Add-Member -MemberType NoteProperty -Name "Applications" -Value @()
    $ComputerAppInfo|Add-Member -MemberType NoteProperty -Name "HardWare" -Value @()
    $ComputerAppInfo|Add-Member -MemberType NoteProperty -Name "ChangeApp" -Value @()
    $ComputerAppInfo|Add-Member -MemberType NoteProperty -Name "ChangeHard" -Value @()
    return $ComputerAppInfo
}

function Get-InstalledApp{
    param($ObjectInstalledApp)


    $UninstallKey="Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall"

    $reg=[microsoft.win32.registrykey]::OpenRemoteBaseKey('LocalMachine',$ObjectInstalledApp.ComputerName)

    $regkey=$reg.OpenSubKey($UninstallKey)

    $subkey=$regkey.GetSubKeyNames()

    foreach($key in $subkey)
    {
        $thiskey=$UninstallKey+"\\"+$key
        $thisSubKey=$reg.OpenSubKey($thiskey)
        $DisplayName=$thisSubKey.GetValue("DisplayName")
        $obj = New-Object PSObject
        if($($thisSubKey.GetValue("DisplayName")) -notlike "" -and $($thisSubKey.GetValue("DisplayName")) -notmatch "kb[0-9][0-9][0-9][0-9][0-9][0-9]"`
           -and $($thisSubKey.GetValue("DisplayName")) -notmatch "NVIDIA"){
            $obj | Add-Member -MemberType NoteProperty -Name "DisplayName" -Value $($thisSubKey.GetValue("DisplayName"))
            $obj | Add-Member -MemberType NoteProperty -Name "DisplayVersion" -Value $($thisSubKey.GetValue("DisplayVersion"))
            $obj | Add-Member -MemberType NoteProperty -Name "InstallLocation" -Value $($thisSubKey.GetValue("InstallLocation"))
            $obj | Add-Member -MemberType NoteProperty -Name "Publisher" -Value $($thisSubKey.GetValue("Publisher"))
            $ObjectInstalledApp.Applications += $obj
        }
    }
    return $ObjectInstalledApp
}

function Get-HardWareTable{
    param($Name, $Manufacturer, $Size, $SerialNumber)

    $Object=New-Object psobject
    $Object|Add-Member -MemberType NoteProperty -Name Name -Value $Name -Force
    $Object|Add-Member -MemberType NoteProperty -Name Manufacturer -Value $Manufacturer -Force
    $Object|Add-Member -MemberType NoteProperty -Name Size -Value $Size -Force
    $Object|Add-Member -MemberType NoteProperty -Name SerialNumber -Value $SerialNumber -Force

    return $Object
}

function Get-ChangeTable{
    param([string]$Removed,
    [string]$Installed)

    $Object=New-Object psobject
    $Object|Add-Member -MemberType NoteProperty -Name Removed -Value $Removed -Force
    $Object|Add-Member -MemberType NoteProperty -Name Installed -Value $Installed -Force

    return $Object
}

function Get-InstalledHardWare{
    param($ObjectInstalledApp)

    $ComputerName=$ObjectInstalledApp.ComputerName

    $obj = New-Object PSObject
	$obj|Add-Member -MemberType NoteProperty -Name HDD_model -Value '' -Force
	$obj|Add-Member -MemberType NoteProperty -Name HDD_size -Value '' -Force
	$obj|Add-Member -MemberType NoteProperty -Name HDD_SerialNumber -Value '' -Force
	$obj|Add-Member -MemberType NoteProperty -Name RAM -Value '' -Force
    $obj|Add-Member -MemberType NoteProperty -Name RAM_PartNumber -Value '' -Force
	$obj|Add-Member -MemberType NoteProperty -Name RAM_SerialNumber -Value '' -Force
	$obj|Add-Member -MemberType NoteProperty -Name CPU -Value '' -Force
	$obj|Add-Member -MemberType NoteProperty -Name MB_name -Value '' -Force
	$obj|Add-Member -MemberType NoteProperty -Name MB_Manufacturer -Value '' -Force
	$obj|Add-Member -MemberType NoteProperty -Name MB_SerialNumber -Value '' -Force
	$obj|Add-Member -MemberType NoteProperty -Name PCType -Value '' -Force
	$obj|Add-Member -MemberType NoteProperty -Name printer -Value '' -Force
	$obj|Add-Member -MemberType NoteProperty -Name LANAdapterName -Value '' -Force
	$obj|Add-Member -MemberType NoteProperty -Name IP_Address -Value '' -Force
	$obj|Add-Member -MemberType NoteProperty -Name MAC_Address -Value '' -Force
	$obj|Add-Member -MemberType NoteProperty -Name GPU_Name -Value '' -Force
	$obj|Add-Member -MemberType NoteProperty -Name GPU_Size -Value '' -Force


    $hdd=get-wmiobject -ComputerName $ComputerName -Class win32_diskdrive|where{$_.DeviceID -like "*PHYSICALDRIVE0"}|Select-Object SerialNumber, @{n="size"; e={[int32]($_.size/1048576/1024)}}, Model
	$mb=Get-WmiObject -ComputerName $ComputerName -Class win32_baseboard|Select-Object product, serialnumber, Manufacturer
	$cpu=Get-WmiObject -ComputerName $ComputerName -Class win32_processor|Select-Object name
	$printer=Get-WmiObject -ComputerName $ComputerName -Class Win32_Printer|where{$_.name -notlike "*pdf*" -and $_.name -notlike "fax"-and $_.name -notlike "microsoft xps*" -and $_.name -notlike "*OneNote*"}|Select-Object name
	$ram=Get-WmiObject -ComputerName $ComputerName -Class win32_physicalmemory|Select-Object PartNumber,serialnumber, @{n="size"; e={($_.capacity/1024/1024/1024)}}
	$net=Get-WmiObject -ComputerName $ComputerName -Class Win32_NetworkAdapterConfiguration|where{$_.DNSDomain -like "netgate.kmz" }
	$mac=Get-WmiObject -ComputerName $ComputerName -Class Win32_NetworkAdapter|where{$_.ServiceName -like $net.ServiceName}
    $gpu = Get-WmiObject -ComputerName $ComputerName -Class Win32_VideoController | select Name,@{Expression={$_.AdapterRAM/1024/1024/1024};Label="GraphicsRAM"}


    $obj.PCType=get-TypePC $ComputerName

	$obj.MB_name=$mb.product
	$obj.MB_Manufacturer=$mb.Manufacturer
	$obj.MB_SerialNumber=$mb.serialnumber

	$obj.HDD_model= $hdd.model
	$obj.HDD_size= [string](get-HHDRightSize $hdd.size)+"GB"
	$obj.HDD_SerialNumber=$hdd.SerialNumber
	if($obj.HDD_SerialNumber -notlike $null -and $obj.HDD_SerialNumber.Length -ge 30)
	{
		$hdd_dex=$obj.HDD_SerialNumber -split '(.{2})' |%{ if ($_ -ne ""){[CHAR]([CONVERT]::toint16("$_",16))}}
		$obj.HDD_SerialNumber=''
		$obj.HDD_SerialNumber+=$hdd_dex|foreach{$_}
		$obj.HDD_SerialNumber=$obj.HDD_SerialNumber -replace " "
	}

	$obj.CPU=$cpu.name

	$obj.RAM='';$obj.RAM+=$ram|foreach{[string]$_.size+"GB"}
	$obj.RAM_SerialNumber='';$obj.RAM_SerialNumber+=$ram|foreach{$_.serialnumber+";"}
    $obj.RAM_PartNumber='';$obj.RAM_PartNumber+=$ram|foreach{$_.PartNumber+";"}

	$obj.printer='';$obj.printer+=$printer|foreach{$_.name+";"}

    $obj.LANAdapterName=($mac|where{$_.Speed -eq 100000000}).Name
	$obj.IP_Address=$net.IPAddress[0]
	$obj.MAC_Address=($mac|where{$_.Speed -eq 100000000}).MACAddress

    $obj.GPU_Name=$gpu.Name
    $obj.GPU_Size=[string]([math]::round($($gpu.GraphicsRAM), 2))+"GB"

    $ObjectInstalledApp.HardWare+=Get-HardWareTable "PCType" $obj.PCType "" ""
    $ObjectInstalledApp.HardWare+=Get-HardWareTable "MatherBoard" ($obj.MB_Manufacturer+" "+$obj.MB_name) "" $obj.MB_SerialNumber
    $ObjectInstalledApp.HardWare+=Get-HardWareTable "HardDrive" $obj.HDD_model $obj.HDD_size $obj.HDD_SerialNumber
    $ObjectInstalledApp.HardWare+=Get-HardWareTable "CPU" $obj.CPU "" ""
    $ObjectInstalledApp.HardWare+=Get-HardWareTable "RAM" $obj.RAM_PartNumber $obj.RAM $obj.RAM_SerialNumber
    $ObjectInstalledApp.HardWare+=Get-HardWareTable "GPU" $obj.GPU_Name $obj.GPU_Size ""
    $ObjectInstalledApp.HardWare+=Get-HardWareTable "Printers" $obj.printer "" ""
    $ObjectInstalledApp.HardWare+=Get-HardWareTable "NetworkAdapter" $obj.LANAdapterName $obj.IP_Address $obj.MAC_Address

    return $ObjectInstalledApp
}

function Get-Changes{
    param($OldComputerInfo,
    $ComputerInfo)

    $RemovedApp=$OldComputerInfo.Applications.DisplayName | where {$ComputerInfo.Applications.DisplayName -notcontains $_}
    $InstalledApp=$ComputerInfo.Applications.DisplayName | where {$OldComputerInfo.Applications.DisplayName -notcontains $_}

    if($RemovedApp.Count -ge $InstalledApp.Count){$AppCount=$RemovedApp.Count}else{$AppCount=$InstalledApp.Count}

    $RemovedHard=$OldComputerInfo.HardWare | where {$ComputerInfo.HardWare.Manufacturer -notcontains $_.Manufacturer}
    $InstalledHard=$ComputerInfo.HardWare | where {$OldComputerInfo.HardWare.Manufacturer -notcontains $_.Manufacturer}
    
    $RemoveBuf=@()
    $InstallBuff=@()
    foreach($Rem in $RemovedHard){$RemoveBuf+=$Rem.Manufacturer+","+$Rem.size}
    foreach($Inst in $InstalledHard){$InstallBuff+=$Inst.Manufacturer+","+$Inst.size}

    if($RemoveBuf.Count -ge $InstallBuff.Count){$HardCount=$RemoveBuf.Count}else{$HardCount=$InstallBuff.Count}

    for($i=0;$i -lt $AppCount;$i++){$ComputerInfo.ChangeApp += Get-ChangeTable $RemovedApp[$i] $InstalledApp[$i]}
    for($i=0;$i -lt $HardCount;$i++){$ComputerInfo.ChangeHard += Get-ChangeTable $RemoveBuf[$i] $InstallBuff[$i]}

    return $ComputerInfo
}

function Get-EditStatusInstalled{
    param($ComputerName)
    $OutDir="$env:ProgramData\InventoryReports"
    if((Test-Path $OutDir) -eq $false){new-item $OutDir -Type directory}

    $ComputerInfo=Get-InstalledHardWare (Get-InstalledApp (New-ComputerInfoApp $ComputerName))

    if((Get-ChildItem $OutDir|where{$_.name -like "Report.xml"}) -eq $null){
        $ComputerInfo|Export-Clixml "$OutDir\Report.xml"
        Send-Message "MuromtsevDM@krasm.com" (Set-HtmlForm $ComputerName ($ComputerInfo.Applications) $ComputerInfo.HardWare) "$ComputerName - Полный отчет инвентаризации"
    }else{
        $OldComputerInfo=Import-Clixml "$OutDir\Report.xml"
        if((Compare-Object -ReferenceObject $ComputerInfo.Applications -DifferenceObject $OldComputerInfo.Applications) -ne $null -or (Compare-Object -ReferenceObject $ComputerInfo.HardWare -DifferenceObject $OldComputerInfo.HardWare) -ne $null){
            $ComputerInfo = Get-Changes $OldComputerInfo $ComputerInfo
            $ComputerInfo|Export-Clixml "$OutDir\Report.xml"
            Send-Message "MuromtsevDM@krasm.com" (Set-HtmlForm $ComputerName ($ComputerInfo.Applications) $ComputerInfo.HardWare $ComputerInfo.ChangeApp $ComputerInfo.ChangeHard) "$ComputerName Измененный отчет Инвентаризации"
        }
    }
    
}

function Set-HtmlForm{
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$ComputerName,
        [Parameter(Mandatory=$True)]
        $Application,
        [Parameter(Mandatory=$True)]
        $HardWare,
        $ChangeApp,
        $ChangeHard
    )

    $frag1 = Get-WmiObject -ComputerName $ComputerName -Class win32_operatingsystem|
                Select-Object Caption, OSArchitecture, serialnumber|
                ConvertTo-HTML -Fragment -As List -PreContent "<h2>Operating Sytem</h2>" |
                Out-String

    $frag2 = $Application |
                ConvertTo-HTML -Fragment -As Table -PreContent "<h2>Installed Applications</h2>" |
                Out-String

    $frag3 = $HardWare |
                ConvertTo-HTML -Fragment -As Table -PreContent "<h2>Installed HardWare</h2>" |
                Out-String

    $frag4 = $ChangeApp |
                ConvertTo-HTML -Fragment -As Table -PreContent "<h2>Change Application</h2>" |
                Out-String

    $frag5 = $ChangeHard |
                ConvertTo-HTML -Fragment -As Table -PreContent "<h2>Change HardWare</h2>" |
                Out-String


    $HTMLForm=ConvertTo-HTML -Title "Report from $ComputerName" `
                    -Head "<style>table {border-collapse: collapce; border-radius: 10px;} table,th, td {border: 1px solid black;} tr:nth-child(even) {background-color: #f2f2f2</style>}"`
                    -Body "<h1>Report for $ComputerName</h1>",$frag1,$frag2,$frag3,$frag4,$frag5
    return $HTMLForm
}

function Send-Message($Accout="Recepient@this",$Body,$Subject) 
{
$to=$Accout

#$att=New-Object Net.Mail.Attachment($file)
 

$SmtpClient=New-Object System.Net.Mail.SmtpClient("your.mail.server")
$Message = New-Object System.Net.Mail.MailMessage

$Message.IsBodyHtml=$true
$Message.Subject=$Subject

$Message.From="Sender@this"
$Message.to.Add($to)

$Message.Body=$Body
#$Message.Attachments.add($att)

$SmtpClient.UseDefaultCredentials=$true

$SmtpClient.Send($Message)
$Message.Dispose()
}

Get-EditStatusInstalled $ComputerName
