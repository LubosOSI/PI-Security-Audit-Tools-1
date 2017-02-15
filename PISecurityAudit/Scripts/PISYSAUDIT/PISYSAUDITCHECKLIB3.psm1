# ***********************************************************************
# Validation library
# ***********************************************************************
# * Modulename:   PISYSAUDIT
# * Filename:     PISYSAUDITCHECKLIB3.psm1
# * Description:  Validation rules for PI AF Server.
# *
# * Copyright 2016 OSIsoft, LLC
# * Licensed under the Apache License, Version 2.0 (the "License");
# * you may not use this file except in compliance with the License.
# * You may obtain a copy of the License at
# * 
# *   <http://www.apache.org/licenses/LICENSE-2.0>
# * 
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# *
# * Modifications copyright (C) <YYYY> <Name>, <Org>
# * <Description of modification>
# *
# ************************************************************************
# Version History:
# ------------------------------------------------------------------------
# Version 1.0.0.8 Initial release on OSIsoft Users Community.
# Authors:  Jim Davidson, Bryan Owen and Mathieu Hamel from OSIsoft.
#
# ************************************************************************

# ........................................................................
# Internal Functions
# ........................................................................
function GetFunctionName
{ return (Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name }

# ........................................................................
# Public Functions
# ........................................................................
function Get-PISysAudit_FunctionsFromLibrary3
{
<#  
.SYNOPSIS
Get functions from PI AF Server library.
#>
	# Form a list of all functions that need to be called to test
	# the PI AF Server compliance.
	[System.Collections.HashTable]$listOfFunctions = @{}	
	$listOfFunctions.Add("Get-PISysAudit_CheckPIAFServiceConfiguredAccount", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckPImpersonationModeForAFDataSets", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckPIAFServicePrivileges", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckPlugInVerifyLevel", 1)	
	$listOfFunctions.Add("Get-PISysAudit_CheckFileExtensionWhitelist", 1)	
	$listOfFunctions.Add("Get-PISysAudit_CheckAFServerVersion", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckAFSPN", 1)
	$listOfFunctions.Add("Get-PISysAudit_CheckAFServerAdminRight", 1)
	# Return the list.
	return $listOfFunctions
}

function Get-PISysAudit_CheckPIAFServiceConfiguredAccount
{
<#  
.SYNOPSIS
AU30001 - PI AF Server Service Account Check
.DESCRIPTION
VALIDATION: verifies that the AF Server application service is not running as the account 
Local System. <br/>
COMPLIANCE: run the AF Server Application service as a user other than Local System.  In 
order to change the user that the service is running as, open control panel, go to Programs, 
Programs and Features, select the entry for the PI AF Server and click Change.  This will 
launch the installer where you will be given the option to change configuration settings, 
including the service account.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS
{				
	# Get and store the function Name.
	$fn = GetFunctionName

	try
	{				
		# Get the service account.
		$value = Get-PISysAudit_ServiceProperty -sn 'afservice' -sp LogOnAccount -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel				
		
		# Check if the value is <> LocalSystem		
		if($value.ToLower() -eq "localsystem") 
		{
			$result =  $false 
			$msg = "AFService is running as Local System"
		} 
		else 
		{ 
			$result = $true 
			$msg = "AFService is not running as Local System"
		}				
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
	
	# Define the results in the audit table		
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU30001" `
										-aif $fn -msg $msg `
										-ain "Configured Account" -aiv $result `
										-Group1 "PI System" -Group2 "PI AF Server" `
										-Severity "Severe"
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckPImpersonationModeForAFDataSets
{
<#  
.SYNOPSIS
AU30002 - Impersonation mode for AF Data Sets Check
.DESCRIPTION
VALIDATION:  verifies the impersonation mode for external data tables. <br/>
COMPLIANCE: set the Configuration Setting ExternalDataTablesAllowNonImpersonatedUsers to 
false, thereby requiring impersonation for access to external tables.  This setting can be 
changed by running the AFDiag utility with the /ExternalDataTablesAllowNonImpersonatedUsers- 
flag.  For more information, see "AFDiag utility parameters" in the PI Live Library. <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v7/GUID-7092DD14-7901-4D63-8B9D-4414C569EA5F">https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v7/GUID-7092DD14-7901-4D63-8B9D-4414C569EA5F </a>
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		
BEGIN {}
PROCESS
{		
	# Get and store the function Name.
	$fn = GetFunctionName
	
	try
	{						
		# Invoke the afdiag.exe command.		
		$outputFileContent = Invoke-PISysAudit_AFDiagCommand -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel -oper "Read"
		
		# Verify that we can read AF Diag output.
		if($null -eq $outputFileContent)
		{
			$msg = "AFDiag output not found.  Cannot continue processing the validation check"
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			$result = "N/A"
		}
		else
		{
			#.................................
			# Validate rules
			# (Do not remove)
			#.................................
			# Example of output.
			# SQL Connection String: 'Persist Security Info=False;Integrated
			# Security=SSPI;server=PISYSTEM2;database=PIFD;Application Name=AF
			# Application Server;'

			# System Name = PISYSTEM2
			# SystemID = 6a5c9048-38c7-40fb-a65f-bcaf729580c5
			# Database Settings:
			# ...
			# Configuration Settings:
			# 	Audit Trail = Disabled
			# 	EnableExternalDataTables = True
			# 	ExternalDataTablesAllowNonImpersonatedUsers = False
			# 	EnableExternalDataTablesWithAF20 = False
			# 	EnableSandbox = True
			# 	EnablePropagateElementDeletesToAnalysisandNotification = True
			# 	EnableEventFrames = True
		
			# Read each line to find the one containing the token to replace.
			# Check if the value is false = compliant, true it is not compliant
			$result = $true
			foreach($line in $outputFileContent)
			{								
				if($line.ToLower().Contains("externaldatatablesallownonimpersonatedusers"))
				{								
					if($line.ToLower().Contains("true")) 
					{ 
						$result = $false
						$msg = "Non Impersonated Users are allowed for external tables." 
					}
					break
				}						
			}
			if($result){$msg = "Non Impersonated Users are not allowed for external tables."}	
		}			
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}	
	
	# Define the results in the audit table			
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU30002" `
										-ain "Impersonation mode for AF Data Sets" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "PI System" -Group2 "PI AF Server" `
										-Severity "Low"
										
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckPIAFServicePrivileges
{
<#  
.SYNOPSIS
AU30003 - PI AF Server Service Access Check
.DESCRIPTION
VALIDATION: verifies that the PI AF application server service does not have excessive 
rights. <br/>
COMPLIANCE: ensure that the account does not have the following privileges: 
SeDebugPrivilege, SeTakeOwnershipPrivilege and SeTcbPrivilege.  For information on these 
rights and how to set them, see "User Rights" on TechNet: <br/>
<a href="https://technet.microsoft.com/en-us/library/dd349804(v=ws.10).aspx">https://technet.microsoft.com/en-us/library/dd349804(v=ws.10).aspx</a>
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)
BEGIN {}
PROCESS
{				
	# Get and store the function Name.
	$fn = GetFunctionName
	$msg = ""
	try
	{										
		$IsElevated = (Get-Variable "PISysAuditIsElevated" -Scope "Global" -ErrorAction "SilentlyContinue").Value
		# Verify running elevated.
		if(-not($IsElevated))
		{
			$msg = "Elevation required to check process privilege.  Run Powershell as Administrator to complete these checks"
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			$result = "N/A"
		}
		else
		{
			# Initialize objects.
			$securityWeaknessCounter = 0	
			$securityWeakness = $false
			$privilegeFound = $false		
		
			# Get the service account.
			$listOfPrivileges = Get-PISysAudit_CheckPrivilege -lc $LocalComputer -rcn $RemoteComputerName -priv "All" -sn "AFService" -dbgl $DBGLevel					
		
			# Read each line to find granted privileges.		
			foreach($line in $listOfPrivileges)
			{											
				# Reset.
				$securityWeakness = $false						
				$privilegeFound = $false			
			
				# Skip any line not starting with 'SE'
				if($line.ToUpper().StartsWith("SE")) 
				{								
					# Validate that the tokens contains these privileges.
					if($line.ToUpper().Contains("SEDEBUGPRIVILEGE")) { $privilegeFound = $true }
					if($line.ToUpper().Contains("SETAKEOWNERSHIPPRIVILEGE")) { $privilegeFound = $true }
					if($line.ToUpper().Contains("SETCBPRIVILEGE")) { $privilegeFound = $true }
				
					# Validate that the privilege is enabled, if yes a weakness was found.
					if($privilegeFound -and ($line.ToUpper().Contains("ENABLED"))) { $securityWeakness = $true }
				}							

				# Increment the counter if a weakness has been discovered.
				if($securityWeakness)
				{
					$securityWeaknessCounter++
				
					# Store the privilege found that might compromise security.
					if($securityWeaknessCounter -eq 1)
					{ $msg = $line.ToUpper() }
					else
					{ $msg = $msg + ", " + $line.ToUpper() }
				}					
			}
		
			# Check if the counter is 0 = compliant, 1 or more it is not compliant		
			if($securityWeaknessCounter -gt 0)
			{
				$result = $false
				if($securityWeaknessCounter -eq 1)
				{ $msg = "The following privilege: " + $msg + " is enabled." }
				else
				{ $msg = "The following privileges: " + $msg + " are enabled." }
			}
			else 
			{ 
				$result = $true 
				$msg = "No weaknesses were detected."
			}
		}
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
	
	# Define the results in the audit table		
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU30003" `
										-ain "PI AF Server Service privileges" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "PI System" -Group2 "PI AF Server" `
										-Severity "Severe"																					
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckPlugInVerifyLevel
{
<#  
.SYNOPSIS
AU30004 - PI AF Server Plugin Verify Level Check
.DESCRIPTION
VALIDATION: verifies that PI AF requires plugins to be validated. <br/>
COMPLIANCE: set the Configuration Setting PlugInVerifyLevel to RequireSigned or 
RequireSignedTrustedProvider.  This can be done with AFDiag /PluginVerifyLevel:<Level>.
For more information, see "AFDiag utility parameters" in the PI Live Library. <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v7/GUID-7092DD14-7901-4D63-8B9D-4414C569EA5F">https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v7/GUID-7092DD14-7901-4D63-8B9D-4414C569EA5F </a>
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		
BEGIN {}
PROCESS
{		
	# Get and store the function Name.
	$fn = GetFunctionName
	$msg = ""
	try
	{						
		# Read the afdiag.exe command output.
		$outputFileContent = Invoke-PISysAudit_AFDiagCommand -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel -oper "Read"

		# Verify that we can read AF Diag output.
		if($null -eq $outputFileContent)
		{
			$msg = "AFDiag output not found.  Cannot continue processing the validation check"
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			$result = "N/A"
		}
		else
		{
			# Read each line to find the one containing the token to replace.
			$result = $true
			foreach($line in $outputFileContent)
			{								
				if($line.ToLower().Contains("pluginverifylevel"))
				{								
					if($line.ToLower().Contains("allowunsigned") -or $line.ToLower().Contains("none")) 
					{ 
						$result = $false 
						$msg = "Unsigned plugins are permitted."
					}
					break
				}						
			}	
			if($result){$msg = "Signatures are required for plugins."}	
		}		
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}	
	
	# Define the results in the audit table			
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU30004" `
										-ain "PI AF Server Plugin Verify Level" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "PI System" -Group2 "PI AF Server" `
										-Severity "Moderate"
										
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckFileExtensionWhitelist
{
<#  
.SYNOPSIS
AU30005 - PI AF Server File Extension Whitelist
.DESCRIPTION
VALIDATION: verifies file extension whitelist for PI AF. <br/>
COMPLIANCE: set the Configuration Setting FileExtensions to only include the file 
extensions: docx:xlsx:csv:pdf:txt:rtf:jpg:jpeg:png:svg:tiff:gif or a subset thereof.
This can be done with AFDiag /FileExtensions:<ExtensionList>.  For more information, 
see "AFDiag utility parameters" in the PI Live Library. <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v7/GUID-7092DD14-7901-4D63-8B9D-4414C569EA5F">https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v7/GUID-7092DD14-7901-4D63-8B9D-4414C569EA5F </a>
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		
BEGIN {}
PROCESS
{		
	# Get and store the function Name.
	$fn = GetFunctionName
	$msg = ""
	try
	{						
		# Read the afdiag.exe command output.		
		$outputFileContent = Invoke-PISysAudit_AFDiagCommand -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel -oper "Read"

		# Read each line to find the one containing the token to replace.
		$result = $true
		
		if($null -eq $outputFileContent)
		{
			$msg = "AFDiag output not found.  Cannot continue processing the validation check"
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			$result = "N/A"
		}
		else
		{
			foreach($line in $outputFileContent)
			{								
				# Locate FileExtensions parameter
				if($line.ToLower().Contains("fileextensions"))
				{								
					# Master whitelist of approved extensions
					[System.Collections.ArrayList] $allowedExtensions = 'docx','xlsx','csv','pdf','txt','rtf','jpg','jpeg','png','svg','tiff','gif'
					# Extract configured whitelist from parameter value
					[string] $extensionList = $line.Split('=')[1].Trim()
					if($extensionList -ne "")
					{
						[string[]] $extensions = $extensionList.Split(':')
						# Loop through the configured extensions
						foreach($extension in $extensions) 
						{ 
							# Assume extension is a violation until proven compliant
							$result = $false
							# As soon as the extension is found in the master list, we move to the next one
							foreach($allowedExtension in $allowedExtensions)
							{
								if($extension -eq $allowedExtension) 
								{ 
									$result = $true
									# There should not be duplicates so we don't need include that extension in further iterations
									$allowedExtensions.Remove($extension)
									break
								}
								else {$result = $false}
							}
							# If we detect any rogue extension, the validation check fails, no need to look further
							if($result -eq $false) 
							{
								$msg = "Setting contains non-compliant extenions."
								break
							}
						} 
						if($result){$msg = "No non-compliant extensions identified."}
						break
					}
					break
				}						
			}	
		}			
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}		
	
	# Define the results in the audit table			
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU30005" `
										-ain "PI AF Server File Extension Whitelist" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "PI System" -Group2 "PI AF Server" `
										-Severity "Moderate"
										
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckAFServerVersion
{
<#  
.SYNOPSIS
AU30006 - PI AF Server Version
.DESCRIPTION
VALIDATION: verifies PI AF Server version. <br/>
COMPLIANCE: upgrade to the latest version of PI AF Server.  For more information, 
see "PI AF Server upgrades" in the PI Live Library. <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v7/GUID-CF854B20-29C7-4A5A-A303-922B74CE03C6">https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v7/GUID-CF854B20-29C7-4A5A-A303-922B74CE03C6 </a>
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		
BEGIN {}
PROCESS
{		
	# Get and store the function Name.
	$fn = GetFunctionName
	$msg = ""
	$installVersion = $null
	try
	{						
		# Get install version via PowerShell
		$installVersion = $global:AFServerConnection.ServerVersion
		
		# Perform logic on install version
		if($null -ne $installVersion)
		{
			$installVersionTokens = $installVersion.Split(".")
			# Form an integer value with all the version tokens.
			[string]$temp = $InstallVersionTokens[0] + $installVersionTokens[1] + $installVersionTokens[2] + $installVersionTokens[3]
			$installVersionInt64 = [Convert]::ToInt64($temp)
			if($installVersionInt64 -gt 2850000)
			{
				$result = $true
				$msg = "Server version is compliant."
			}
			else
			{
				$result = $false
				$msg = "Server version is non-compliant: {0}."
				$msg = [string]::Format($msg, $installVersion)
			}		
		}
		else
		{
			$msg = "AF version not found.  Cannot continue processing the validation check"
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			$result = "N/A"
		}	
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
	
	# Define the results in the audit table			
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU30006" `
										-ain "PI AF Server Version" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "PI System" -Group2 "PI AF Server" `
										-Severity "Moderate"
										
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckAFSPN
{
<#  
.SYNOPSIS
AU30007 - Verify AF Server SPN exists
.DESCRIPTION
	VALIDATION: Checks PI AF Server SPN assignment.<br/>
	COMPLIANCE: PI AF Server SPNs exist and are assigned to the AF Service account. This makes Kerberos Authentication possible.
For more information, see "PI AF and Kerberos authentication" in the PI Live Library. <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v7/GUID-531FFEC4-9BBB-4CA0-9CE7-7434B21EA06D">https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v7/GUID-531FFEC4-9BBB-4CA0-9CE7-7434B21EA06D</a>
#>

[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		
BEGIN {}
PROCESS
{		
	# Get and store the function Name.
	$fn = GetFunctionName
	$msg = ""
	try
	{		
		$serviceType = "afserver"
		$serviceName = "afservice"

		$result = Invoke-PISysAudit_SPN -svctype $serviceType -svcname $serviceName -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel

		If ($result) 
		{ 
			$msg = "The Service Principal Name exists and it is assigned to the correct Service Account."
		} 
		Else 
		{ 
			$msg = "The Service Principal Name does NOT exist or is NOT assigned to the correct Service Account."
		}			
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}	
	
	# Define the results in the audit table			
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU30007" `
										-ain "PI AF Server SPN Check" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "PI System" -Group2 "PI AF Server"`
										-Severity "Moderate"
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckAFServerAdminRight
{
<#  
.SYNOPSIS
AU30008 - PI AF Server Admin Right
.DESCRIPTION
VALIDATION: verifies PI AF Server Admin right on the server object is not set improperly. <br/>
COMPLIANCE: for compliance, there should be a single identity with the Admin right at the server 
level.  That identity should have a single custom account or group mapped to it.  Admin rights 
at the server level should not be necessary for ordinary administration tasks.
For more information, see "PI AF Access rights" in the PI Live Library. <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v7/GUID-23016CF4-6CF1-4904-AAEC-418EEB00B399">https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v7/GUID-23016CF4-6CF1-4904-AAEC-418EEB00B399</a>
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		
BEGIN {}
PROCESS
{		
	# Get and store the function Name.
	$fn = GetFunctionName
	$msg = ""
	$Severity = 'Unknown'
	
	try
	{						
		$afServer = $global:AFServerConnection.ConnectionInfo.PISystem
		# Get identities with Admin Right on the AF Server object
		$afAdminIdentities = Get-AFSecurity -AFObject $afserver `
									| ForEach-Object {if($_.Rights -like '*Admin*'){$_}} `
									| Select-Object -ExpandProperty Identity
		# Flag if more than one Identity is an AF super user 
		$hasSingleIdentity = $false
		If($afAdminIdentities.Count -eq 1){ $hasSingleIdentity = $true }

		# Find all mappings to super user identities. 
		$afAdminMappings = Get-AFSecurityMapping -AFServer $afserver `
									| ForEach-Object {if($_.SecurityIdentity -in $afAdminIdentities){$_}} `
									| Select-Object Name, SecurityIdentity, Account
		# Flag if more than one mapping exists to the AF super user 
		$hasSingleMapping = $false
		If($afAdminMappings.Count -eq 1){ $hasSingleMapping = $true }

		$endUserMappings = @{}
		$osAdminMappings = @{}
		$wellKnownMappings = @{}
		ForEach($afAdminMapping in $afAdminMappings)
		{
			$accountType = Test-PISysAudit_PrincipalOrGroupType -SID $afAdminMapping.Account 
			
			If($null -ne $accountType){
				switch ($accountType)
				{
					'LowPrivileged' {
										$endUserMappings.Add($afAdminMapping.Name, $afAdminMapping.SecurityIdentity)
										$wellKnownMappings.Add($afAdminMapping.Name, $afAdminMapping.SecurityIdentity)
									}
					'Administrator' {
										$osAdminMappings.Add($afAdminMapping.Name, $afAdminMapping.SecurityIdentity)
										$wellKnownMappings.Add($afAdminMapping.Name, $afAdminMapping.SecurityIdentity)
									}
					default {$wellKnownMappings.Add($afAdminMapping.Name, $afAdminMapping.SecurityIdentity)}
				}
			}
		}

		if($wellKnownMappings.Count -eq 0) # Check for well known mappings first
		{
			if($hasSingleMapping) # Ideal case, a single compliant mapping
			{
				$result = $true
				$msg = "A single AF Identity has AF Admin rights and that AF Identity has a single mapping to a custom group."
			}
			else # One Identity but multiple mappings which may not be necessary
			{
				$result = $false
				$Severity = 'Low'
				if($hasSingleIdentity)
				{
					$msg = "Multiple Windows Principals mapped to an AF Identity with Admin rights.  Evaluate whether Admin rights are necessary for: "
				}
				else # Multiple Identities should not have super user access
				{
					$msg = "Multiple AF Identities have AF Admin rights.  Evaluate whether Admin rights are necessary for: "	
				}
				foreach ($afAdminMapping in $afAdminMappings) { $msg += " Mapping-" + $afAdminMapping.Name + '; AF Identity-' + $afAdminMapping.SecurityIdentity + "|" } 
			}	
		}
		else # Evaluate well known accounts for severity
		{
			$result = $false
			if($endUserMappings.Count -gt 0) # RED ALERT if super user rights are granted to end user groups like Everyone or Domain Users
			{
				$Severity = 'severe'
				$msg = "End user account(s) are mapped to an AF Identities with AF Admin rights:"
				$priorityMappings = $endUserMappings
			}
			else
			{
				$Severity = 'moderate'
				if($osAdminMappings.Count -gt 0)
				{
					$msg = "Default Administrator account(s) are mapped to an AF Identities with AF Admin rights:"
					$priorityMappings = $osAdminMappings
				}
				else
				{
					$msg = "Well known principals are mapped to an AF Identities with AF Admin rights, this could lead to unintentional privileged access:"
					$priorityMappings = $wellKnownMappings
				}
			}
			foreach($priorityMapping in $priorityMappings.GetEnumerator()) { $msg += " Mapping-" + $priorityMapping.Key + '; AF Identity-' + $priorityMapping.Value.Name + "|" }
		}
		$msg = $msg.Trim('|')
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
	
	# Define the results in the audit table			
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU30008" `
										-ain "PI AF Server Admin Right" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "PI System" -Group2 "PI AF Server" `
										-Severity $Severity
										
}

END {}

#***************************
#End of exported function
#***************************
}

# ........................................................................
# Add your cmdlet after this section. Don't forget to add an intruction
# to export them at the bottom of this script.
# ........................................................................
function Get-PISysAudit_TemplateAU3xxxx
{
<#  
.SYNOPSIS
AU3xxxx - <Name>
.DESCRIPTION
VERIFICATION: <Enter what the verification checks>
COMPLIANCE: <Enter what it needs to be compliant>
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at")]
		[System.Collections.HashTable]
		$AuditTable,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean]
		$LocalComputer = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("rcn")]
		[string]
		$RemoteComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0)		
BEGIN {}
PROCESS
{		
	# Get and store the function Name.
	$fn = GetFunctionName
	$msg = ""
	try
	{		
		# Enter routine.			
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check"					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}	
	
	# Define the results in the audit table			
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
										-at $AuditTable "AU3xxxx" `
										-ain "<Name>" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "<Category 1>" -Group2 "<Category 2>" -Group3 "<Category 3>" -Group4 "<Category 4>"`
										-Severity "<Severity>"
}

END {}

#***************************
#End of exported function
#***************************
}

# ........................................................................
# Export Module Member
# ........................................................................
# <Do not remove>
Export-ModuleMember Get-PISysAudit_FunctionsFromLibrary3
Export-ModuleMember Get-PISysAudit_CheckPIAFServiceConfiguredAccount
Export-ModuleMember Get-PISysAudit_CheckPImpersonationModeForAFDataSets
Export-ModuleMember Get-PISysAudit_CheckPIAFServicePrivileges
Export-ModuleMember Get-PISysAudit_CheckPlugInVerifyLevel
Export-ModuleMember Get-PISysAudit_CheckFileExtensionWhitelist
Export-ModuleMember Get-PISysAudit_CheckAFServerVersion
Export-ModuleMember Get-PISysAudit_CheckAFSPN
Export-ModuleMember Get-PISysAudit_CheckAFServerAdminRight
# </Do not remove>

# ........................................................................
# Add your new Export-ModuleMember instruction after this section.
# Replace the Get-PISysAudit_TemplateAU3xxxx with the name of your
# function.
# ........................................................................
# Export-ModuleMember Get-PISysAudit_TemplateAU3xxxx