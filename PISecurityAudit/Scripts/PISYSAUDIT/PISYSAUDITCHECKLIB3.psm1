# ************************************************************************
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
Get functions from PI AF Server library at or below the specified level.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lvl")]
		[int]
		$AuditLevelInt = 1)

	# Form a list of all functions that need to be called to test
	# the PI AF Server compliance.
	$listOfFunctions = @()
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckPIAFServiceConfiguredAccount"    1 "AU30001"
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckPImpersonationModeForAFDataSets" 1 "AU30002"
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckPIAFServicePrivileges"           1 "AU30003"
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckPlugInVerifyLevel"               1 "AU30004"
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckFileExtensionWhitelist"          1 "AU30005"
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckAFServerVersion"                 1 "AU30006"
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckAFSPN"                           1 "AU30007"
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckAFServerAdminRight"              1 "AU30008"
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckAFConnectionString"              1 "AU30009"
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckAFWorldIdentity"                 1 "AU30010"
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckAFWriteAccess"                   1 "AU30011"

	# Return all items at or below the specified AuditLevelInt
	return $listOfFunctions | Where-Object Level -LE $AuditLevelInt
}

function Get-PISysAudit_CheckPIAFServiceConfiguredAccount
{
<#  
.SYNOPSIS
AU30001 - PI AF Server Service Account
.DESCRIPTION
VALIDATION: Verifies that the AF Server application service is not running as 
the account Local System. <br/>
COMPLIANCE: Run the AF Server Application service as a user other than Local 
System.  In order to change the user that the service is running as, open 
control panel, go to Programs, Programs and Features, select the entry for the 
PI AF Server and click Change.  This will launch the installer where you will 
be given the option to change configuration settings, including the service 
account.
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
										-Severity "High"
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
AU30002 - Impersonation mode for AF Data Sets
.DESCRIPTION
VALIDATION: Verifies the impersonation mode for external data tables. <br/>
COMPLIANCE: Set the Configuration Setting 
ExternalDataTablesAllowNonImpersonatedUsers to false, thereby requiring 
impersonation for access to external tables.  This setting can be changed by 
running the AFDiag utility with the 
/ExternalDataTablesAllowNonImpersonatedUsers- flag.  For more information, see 
"AFDiag utility parameters" in the PI Live Library: <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v10/GUID-7092DD14-7901-4D63-8B9D-4414C569EA5F">https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v10/GUID-7092DD14-7901-4D63-8B9D-4414C569EA5F </a>
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
		# Verify that we can read AF Diag output.
		if($null -eq $global:AFDiagOutput)
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
			foreach($line in $global:AFDiagOutput)
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
AU30003 - PI AF Server Service Access
.DESCRIPTION
VALIDATION: Verifies that the PI AF application server service does not have 
excessive rights. <br/>
COMPLIANCE: Ensure that the account does not have the following privileges: 
SeDebugPrivilege, SeTakeOwnershipPrivilege and SeTcbPrivilege.  For information
on these rights and how to set them, see "User Rights" on TechNet: <br/>
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
			$msg = "Elevation required to check process privilege.  Run Powershell as Administrator to complete this check"
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			$result = "N/A"
		}
		elseif($ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage")
		{
			$msg = "Constrained Language Mode detected.  This check will be skipped"
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
			$listOfPrivileges = Get-PISysAudit_ServicePrivilege -lc $LocalComputer -rcn $RemoteComputerName -sn "AFService" -dbgl $DBGLevel					
		
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
										-Severity "High"																					
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
AU30004 - PI AF Server Plugin Verify Level
.DESCRIPTION
VALIDATION: Verifies that PI AF requires plugins to be validated. <br/>
COMPLIANCE: Set the Configuration Setting PlugInVerifyLevel to RequireSigned 
or RequireSignedTrustedProvider. This can be done with AFDiag 
/PluginVerifyLevel:<Level>. For more information, see "AFDiag utility 
parameters" in the PI Live Library: <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v10/GUID-7092DD14-7901-4D63-8B9D-4414C569EA5F">https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v10/GUID-7092DD14-7901-4D63-8B9D-4414C569EA5F </a>
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
		# Verify that we can read AF Diag output.
		if($null -eq $global:AFDiagOutput)
		{
			$msg = "AFDiag output not found.  Cannot continue processing the validation check"
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			$result = "N/A"
		}
		else
		{
			# Read each line to find the one containing the token to replace.
			$result = $true
			foreach($line in $global:AFDiagOutput)
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
										-Severity "Medium"
										
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
VALIDATION: Verifies file extension whitelist for PI AF. <br/>
COMPLIANCE: Set the FileExtensions configuration setting to only include the 
file extensions: docx:xlsx:csv:pdf:txt:rtf:jpg:jpeg:png:svg:tiff:gif or a 
subset thereof. This can be done with AFDiag /FileExtensions:<ExtensionList>. 
For more information, see "AFDiag utility parameters" in the PI Live Library: <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v10/GUID-7092DD14-7901-4D63-8B9D-4414C569EA5F">https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v10/GUID-7092DD14-7901-4D63-8B9D-4414C569EA5F </a><br/>
By default, the only noncompliant extension included is PDI, which corresponds
to PI ProcessBook displays. Caution is recommended with PDI files as they can
contain VBA Macros. Clients are encouraged to leverage Macro Protection with
PI ProcessBook. For more information, see "Macro protection" in the Live Library: <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/processbook-v4/GUID-312C3C85-B06D-4271-AE9D-4FE08E093137">https://livelibrary.osisoft.com/LiveLibrary/content/en/processbook-v4/GUID-312C3C85-B06D-4271-AE9D-4FE08E093137</a>
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
		# Read each line to find the one containing the token to replace.
		$result = $true
		
		if($null -eq $global:AFDiagOutput)
		{
			$msg = "AFDiag output not found.  Cannot continue processing the validation check"
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			$result = "N/A"
		}
		else
		{
			foreach($line in $global:AFDiagOutput)
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
								$msg = "Setting contains non-compliant extensions."
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
										-Severity "Medium"
										
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
VALIDATION: Verifies PI AF Server version. <br/>
COMPLIANCE: Upgrade to the latest version of PI AF Server. See the PI AF product
page for the latest version and associated documentation:<br/>
<a href="https://techsupport.osisoft.com/Products/PI-Server/PI-AF">https://techsupport.osisoft.com/Products/PI-Server/PI-AF </a><br/>
For more information on the upgrade procedure, see "PI AF Server upgrades" in 
the PI Live Library: <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v10/GUID-CF854B20-29C7-4A5A-A303-922B74CE03C6">https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v10/GUID-CF854B20-29C7-4A5A-A303-922B74CE03C6 </a><br/>
Associated security bulletins:<br/>
<a href="https://techsupport.osisoft.com/Products/PI-Server/PI-AF/Alerts">https://techsupport.osisoft.com/Products/PI-Server/PI-AF/Alerts</a>
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
		if($global:ArePowershellToolsAvailable)
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
				if($installVersionInt64 -gt 2900000)
				{
					$result = $true
					$msg = "Server version is compliant."
				}
				else
				{
					$result = $false
					$msg = "Noncompliant version ($installVersion) detected. Upgrading to the latest PI AF version is recommended. "
					$msg += "See https://techsupport.osisoft.com/Products/PI-Server/PI-AF/ for the latest version and associated documentation."
				}		
			}
			else
			{
				$msg = "AF version not found.  Cannot continue processing the validation check"
				Write-PISysAudit_LogMessage $msg "Warning" $fn
				$result = "N/A"
			}
		}
		else
		{
			# OSIsoft.Powershell not available
			$result = "N/A"
			$msg = "PowerShell Tools for the PI System (OSIsoft.Powershell module) not found. " 
			$msg += "Cannot continue processing the validation check. " 
			$msg += "Check if PI System Management Tools are installed on the machine running the audit tools."
			Write-PISysAudit_LogMessage $msg "Error" $fn
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
										-Severity "Medium"
										
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
AU30007 - AF Server SPN
.DESCRIPTION
VALIDATION: Checks PI AF Server SPN assignment.<br/>
COMPLIANCE: PI AF Server SPNs exist and are assigned to the AF Service account. 
This makes Kerberos Authentication possible. For more information, see "PI AF 
and Kerberos authentication" in the PI Live Library: <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v10/GUID-531FFEC4-9BBB-4CA0-9CE7-7434B21EA06D">https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v10/GUID-531FFEC4-9BBB-4CA0-9CE7-7434B21EA06D</a>
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
										-Severity "Medium"
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
VALIDATION: Verifies PI AF Server Admin right on the server object is not set 
improperly. <br/>
COMPLIANCE: Ensure there is a single identity with the Admin right at the 
server level. That identity should have a single custom account or group mapped
to it. Admin rights at the server level should not be necessary for ordinary 
administration tasks. For more information, see "PI AF Access rights" in the PI
Live Library: <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v10/GUID-23016CF4-6CF1-4904-AAEC-418EEB00B399">https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v10/GUID-23016CF4-6CF1-4904-AAEC-418EEB00B399</a>
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
		if($global:ArePowerShellToolsAvailable)
		{
			$version = [int]($global:AFServerConnection.ServerVersion -replace '\.', '')
			if($version -ge 2700000)
			{
				$afServer = $global:AFServerConnection.ConnectionInfo.PISystem
				# Get identities with Admin Right on the AF Server object
				$afAdminIdentities = @()
				$afAdminIdentities += Get-AFSecurity -AFObject $afserver `
											| ForEach-Object {if($_.Rights -like '*Admin*' -or $_.Rights -like '*All*'){$_}} `
											| Select-Object -ExpandProperty Identity
				if($afAdminIdentities.Count -eq 0)
				{
					$result = $true
				    $msg = "No AF Identity has AF Server level Admin rights. Consider adding a single identity for disaster recovery."
				}
				else
				{
					# Flag if more than one Identity is an AF super user 
					$hasSingleIdentity = $false
					If($afAdminIdentities.Count -eq 1){ $hasSingleIdentity = $true }

					# Find all mappings to super user identities. 
					$afAdminMappings = @()
					$afAdminMappings += Get-AFSecurityMapping -AFServer $afserver `
												| ForEach-Object {if($_.SecurityIdentity -in $afAdminIdentities){$_}} `
												| Select-Object Name, SecurityIdentity, Account
					if($afAdminMappings.Count -eq 0)
					{
						$result = $true
						$msg = "No AF Mappings involve an AF Identity with AF Server level Admin rights. Consider adding a mapping for a single identity for disaster recovery."
					}
					else
					{
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
									foreach ($afAdminMapping in $afAdminMappings) { $msg += " Mapping-" + $afAdminMapping.Name + '; AF Identity-' + $afAdminMapping.SecurityIdentity + "|" }
								}
								else # Multiple Identities should not have super user access
								{
									$msg = "Multiple AF Identities have AF Admin rights.  Evaluate whether Admin rights are necessary for: "	
									foreach ($afAdminIdentity in $afAdminIdentities) { $msg += " AF Identity-" + $afAdminIdentity.Name + "|" }
								}
							}	
						}
						else # Evaluate well known accounts for severity
						{
							$result = $false
							if($endUserMappings.Count -gt 0) # RED ALERT if super user rights are granted to end user groups like Everyone or Domain Users
							{
								$Severity = 'High'
								$msg = "End user account(s) are mapped to an AF Identities with AF Admin rights:"
								$priorityMappings = $endUserMappings
							}
							else
							{
								$Severity = 'Medium'
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
				} 
			}
			else
			{
				$result = "N/A"
				$msg = "PI AF Server 2.7 or later is required for this check."
				Write-PISysAudit_LogMessage $msg "Error" $fn
			}
		}
		else
		{
			# OSIsoft.Powershell not available
			$result = "N/A"
			$msg = "PowerShell Tools for the PI System (OSIsoft.Powershell module) not found. " 
			$msg += "Cannot continue processing the validation check. " 
			$msg += "Check if PI System Management Tools are installed on the machine running the audit tools."
			Write-PISysAudit_LogMessage $msg "Error" $fn
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

function Get-PISysAudit_CheckAFConnectionString
{
<#  
.SYNOPSIS
AU30009 - AF Connection to SQL
.DESCRIPTION
VERIFICATION: AF Service connects to the SQL Server with Windows 
authentication. <br/>
COMPLIANCE: Ensure that the AF Application service connects to the SQL Server
with Windows Authentication. Windows Authentication is the preferred method, 
see:
<a href="https://msdn.microsoft.com/en-us/library/ms144284.aspx">https://msdn.microsoft.com/en-us/library/ms144284.aspx</a>
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
		if($null -eq $global:AFDiagOutput)
		{
			$msg = "AFDiag output not found.  Cannot continue processing the validation check"
			Write-PISysAudit_LogMessage $msg "Warning" $fn
			$result = "N/A"
		}
		else
		{
			# Make regex object that supports matches across multiple lines, search for a match on afdiag output
			$regex = New-Object Text.RegularExpressions.Regex "SQL Connection String.*\;\'", ('singleline', 'multiline')
			$match = $regex.Match($global:AFDiagOutput)
			if($match.Success)
			{
				# Sanitize connection string by removing white space
				$connectStr = $match.Value -replace '\s', ''
				if($connectStr.Contains('IntegratedSecurity=SSPI'))
				{
					$result = $true
					$msg = "AF Service connects to SQL using Windows Integrated Security."
				}
				else
				{
					$result = $false
					$msg = "AF Service connectes to SQL using SQL Server login."
				}
			}
			else
			{
				$result = "N/A"
				$msg = "Unable to parse connection string from AFDiag output."
				Write-PISysAudit_LogMessage $msg "Error" $fn 
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
										-at $AuditTable "AU30009" `
										-ain "AF Connection to SQL" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "PI System" -Group2 "PI AF Server" `
										-Severity "Medium"
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckAFWorldIdentity
{
<#  
.SYNOPSIS
AU30010 - Restrict AF World Identity
.DESCRIPTION
VERIFICATION: Verifies the World Identity has been disabled or restricted.<br/>
COMPLIANCE: Ensure that the World Identity is disabled on the AF Server. 
Alternatively, remove the mapping to the \Everyone group and re-map it to an 
appropriate group with only users who need access to PI AF.  For more 
information on default PI AF Identities, see:
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v10/GUID-748615A9-8A01-46EB-A907-00353D5AFBE0">https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v10/GUID-748615A9-8A01-46EB-A907-00353D5AFBE0</a>
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
		if($global:ArePowerShellToolsAvailable -and (Test-AFServerConnectionAvailable))
		{
			$con = $global:AFServerConnection
			$version = [int]($con.ServerVersion -replace '\.', '')
			if($version -ge 2700000)
			{
				$world = $con.SecurityIdentities | Where-Object Name -EQ 'World'
				if($world)
				{
					if($world.IsEnabled)
					{
						# World identity exists and is enabled, check its mappings
						$mappings = Get-AFSecurityMapping -AFServer $con
						$worldMappings = $mappings | Where-Object { $_.SecurityIdentity.Name -eq 'World' }
						# \Everyone = 'S-1-1-0'
						$everyoneMapping = $worldMappings | Where-Object Account -eq 'S-1-1-0' 
						if($everyoneMapping)
						{
							$result = $false
							$msg = "World Identity is mapped to the Everyone group."
						}
						else
						{
							$result = $true
							$msg = "World Identity is not mapped to the Everyone group."
						}
					}
					else
					{
						$result = $true
						$msg = "World Identity has been disabled."
					}
				}
				else
				{
					# Check if any IDs were loaded, if they were then it is likely that
					# World was deleted
					if($con.SecurityIdentities)
					{
						$result = $true
						$msg = "World Identity has been removed."
					}
					else
					{
						$result = "N/A"
						$msg = "Failed to load any AF Identities."
					}
				}
			}
			else
			{
				$result = "N/A"
				$msg = "PI AF Server 2.7 or later is required for this check."
				Write-PISysAudit_LogMessage $msg "Error" $fn
			}
		}
		else
		{
			$result = "N/A"
			$msg = "Connection to AF Server using OSIsoft.Powershell is required."
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
										-at $AuditTable "AU30010" `
										-ain "Restrict AF World" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "PI System" -Group2 "PI AF Server" `
										-Severity "Low"
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckAFWriteAccess
{
<#  
.SYNOPSIS
AU30011 - Restrict Write Access
.DESCRIPTION
VERIFICATION: Write access to objects should be limited to power users. <br/>
COMPLIANCE: Database level write access should not be granted to any well-known, 
end user groups, such as \Everyone or Domain Users. Similarly, write access to 
analyses should be limited. For more information on PI AF access writes, please 
see: 
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v10/GUID-23016CF4-6CF1-4904-AAEC-418EEB00B399 ">https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v10/GUID-23016CF4-6CF1-4904-AAEC-418EEB00B399</a><br/>
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
		if($global:ArePowerShellToolsAvailable -and (Test-AFServerConnectionAvailable))
		{
			$con = $global:AFServerConnection

			$version = [int]($con.ServerVersion -replace '\.', '')
			if($version -ge 2700000)
			{
				# ............................................................................................................
				# Compile list of identities with any write access to server or a database
				# ............................................................................................................
				$writeIdentities = @() 

				# Server access
				$serverAccess = Get-AFSecurity -AFObject $con
				# Filter for IDs with access the mentions Write OR Admin OR All
				$tempIDs = $serverAccess | Where-Object { $_.AllowAccess -eq 'True' -and $_.Rights -match 'Write|Admin|All'}
				foreach($ID in $tempIDs)
				{
					if($writeIdentities -notcontains $ID.Identity) { $writeIdentities += $ID.Identity }
				}

				# Database access
				$databases = $con.Databases
				foreach($db in $databases)
				{
					if($db.Name -eq "Configuration")
                    {
                        # Configuration database ACL should be evaluated at the OSIsoft element. 
                        $dbAccess = Get-AFSecurity -AFObject (Get-AFElement -AFDatabase $db -Name "OSIsoft")
                    }
                    else
                    {
                        $dbAccess = Get-AFSecurity -AFObject $db
                    }
					$tempIDs = $dbAccess | Where-Object { $_.AllowAccess -eq 'True' -and $_.Rights -match 'Write|Admin|All'}
					foreach($ID in $tempIDs)
					{
						if($writeIdentities -notcontains $ID.Identity) { $writeIdentities += $ID.Identity }
					}
				}

				# ............................................................................................................
				# Compile list of mappings that grant write access to well-known accounts
				# ............................................................................................................
				$badWriteMappings = @()
				$writeMappings = $con.SecurityMappings | Where-Object { $_.SecurityIdentity -in $writeIdentities }
				foreach($mapping in $writeMappings)
				{
					$knownType = Test-PISysAudit_PrincipalOrGroupType -SID $mapping.Account
					if($knownType -eq 'LowPrivileged')
					{
						$badWriteMappings += $mapping
					}
				}

				# ............................................................................................................
				# Evaluate audit results based on list of bad mappings
				# ............................................................................................................

				if($badWriteMappings)
				{
					# Output message will report number of risky mappings and up to four accounts found.
					# Sample: "2 risky write access AF mapping(s) found for: Everyone, OSI\Domain Users."
					$result = $false
					$msg = "$($badWriteMappings.Count) risky write access AF mapping(s) found for: "
					$i = 0
					foreach($map in $badWriteMappings)
					{
						$i++
						$msg += $map.Name + ', '
						if($i -eq 4)
						{
							# add number of unlisted, pad with two characters (to be removed)
							$msg += "and $($badWriteMappings.Count - 4) others.  "
						}
					}
					# Trim extra comma and space
					$msg = $msg.Substring(0, $msg.Length-2) + '.'
				}
				else
				{
					if((-not $con.SecurityIdentities) -or (-not $con.SecurityMappings))
					{
						$result = "N/A"
						$msg = "There was a problem reading AF Identities or Mappings."
						Write-PISysAudit_LogMessage $msg "Error" $fn
					}
					else
					{
						$result = $true
						$msg = "No risky write access AF mappings found."
					}
				}
				if(-not $con.Security.HasAdmin)
				{
					# Add warning if not connecting as Admin as we can't guarantee completeness
					$msg += " WARNING: Not connected as AF Admin, results may not be reliable."
					Write-PISysAudit_LogMessage $msg "Warning" $fn
				}
			}
			else
			{
				$result = "N/A"
				$msg = 'PI AF Server 2.7 or later is required for this check.'
				Write-PISysAudit_LogMessage $msg "Error" $fn
			}
		}
		else
		{
			$result = "N/A"
			$msg = "PowerShell Tools for the PI System (OSIsoft.Powershell module) not found. " 
			$msg += "Cannot continue processing the validation check. " 
			$msg += "Check if PI System Management Tools are installed on the machine running the audit tools."
			Write-PISysAudit_LogMessage $msg "Error" $fn
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
										-at $AuditTable "AU30011" `
										-ain "Restrict Write Access" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "PI System" -Group2 "PI AF Server" `
										-Severity "High"
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
Export-ModuleMember Get-PISysAudit_CheckAFConnectionString
Export-ModuleMember Get-PISysAudit_CheckAFWorldIdentity
Export-ModuleMember Get-PISysAudit_CheckAFWriteAccess
# </Do not remove>

# ........................................................................
# Add your new Export-ModuleMember instruction after this section.
# Replace the Get-PISysAudit_TemplateAU3xxxx with the name of your
# function.
# ........................................................................
# Export-ModuleMember Get-PISysAudit_TemplateAU3xxxx