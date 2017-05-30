function Get-VirusInfo
{
    #TODO
    #need to check depending of OS version
    #need to check regarding driveletter, folder, version
	$fileContents = Get-Content "C:\ProgramData\Symantec\Symantec Endpoint Protection\14.0.1904.0000.105\Data\Definitions\SDSDefs\definfo.dat"
	if ($fileContents -ne $null)
	{
		# Get second line in file
		$versionInfoLine = $fileContents[1]
	
		# Get virus def version from second line in file
		$defResult = $versionInfoLine -match "^.+\=(?<def>.+)"
		$defversion = $matches.def
	
		# Determine date of definition from line in file
		$defYear = $versionInfoLine.substring(8,4)
		$defMonth = $versionInfoLine.substring(12,2)
		$defDay = $versionInfoLine.substring(14,2)
		$defRevision = $versionInfoLine.substring(17,3)
	
		# build date from information from file
		$definitionDate = "$defMonth" + "/"+ "$defDay" + "/" + "$defYear"
	
		# Convert to Date time
		$virusDefinitionDate =[datetime]$definitionDate
	
		# Get the current date time
		$currentTimeDate = Get-Date
	
		# Compare current date vs virus definition date
		$dateDifference = $currentTimeDate - $virusDefinitionDate
		return $dateDifference.Days, $defversion, $virusDefinitionDate.Date.ToString("d")
	}
	else
	{
		return $null
	}
}


function Get-ServiceInfo
{
#ServiceName: SepMasterService
#DisplayName: Symantec Endpoint Protection
$status = Get-Service | Where-Object {$_.displayname -eq "Symantec Endpoint Protection"}
return $status.Status
}


################################################################################
# Start Script
################################################################################
	$output = @()

    $staleDays = 2

    $hostname = $env:computername

	$os = Get-WmiObject -class Win32_OperatingSystem
    #$os
	if ($os -ne $null)
	{
		# Get OS type x86 or x64
		$processor = Invoke-Expression "Get-WmiObject Win32_Processor -namespace root\cimv2 $ST_CC | where {`$_.DeviceID -eq `"CPU0`"} | select AddressWidth"
        #$processor
		
		# Connect to registry on target system
		$wmiRegistry = Invoke-Expression "Get-WmiObject -list -namespace root\default $ST_CC | where-object { `$_.name -eq `"StdRegProv`" }"
        #$wmiRegistry

        #get info from file
        $arrayfile = Get-VirusInfo
        #$arrayfile
		
        #get info from registry
        #TODO
        #need to check depending of OS version
        $arrayreg = Get-ItemProperty "HKLM:\SOFTWARE\Symantec\Symantec Endpoint Protection\CurrentVersion\Public-Opstate"
        #$arrayreg
        
        if ($arrayfile[0] -lt $staleDays) {
        $statusupdate = "Definition is up to date."}
        else {
        $statusupdate = "Definition is NOT up to date." }

        $output = "" | Select-Object @{Name="Computer Name"; Expression={$hostname}},
							@{Name="Symantec Endpoint Protection Version (registry)"; Expression={$arrayreg.DeployRunningVersion}},
                            @{Name="AV Definition Date (registry)"; Expression={$arrayreg.LatestVirusDefsDate}}, 
                            @{Name="Management Server (registry)"; Expression={$arrayreg.LastServerIP}}, 
                            @{Name="Infected (registry)"; Expression={$arrayreg.Infected}},
							@{Name="AV Definition Version (file)"; Expression={$arrayfile[1]}}, 
							@{Name="AV Definition Date (file)"; Expression={$arrayfile[2]}},
							@{Name="Symantec Endpoint Protection agent"; Expression={Get-ServiceInfo}},
							@{Name="Status"; Expression={$statusupdate}}
        }
        $output