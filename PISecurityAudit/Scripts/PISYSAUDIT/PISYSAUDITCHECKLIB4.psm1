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
function Get-PISysAudit_FunctionsFromLibrary4
{
<#  
.SYNOPSIS
Get functions from SQL Server library at or below the specified level.
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("lvl")]
		[int]
		$AuditLevelInt = 1)

	# Form a list of all functions that need to be called to test
	# the SQL Server compliance.
	$listOfFunctions = @()
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckSQLXPCommandShell"           1 "AU40001"
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckSQLAdHocQueries"             1 "AU40002" 
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckSQLDBMailXPs"                1 "AU40003"
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckSQLOLEAutomationProcs"       1 "AU40004"
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckSQLCLR"                      1 "AU40005"
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckSQLCrossDBOwnershipChaining" 1 "AU40006"
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckSQLRemoteAccess"             1 "AU40007"
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckSQLsa"                       1 "AU40008"

	# Return all items at or below the specified AuditLevelInt
	return $listOfFunctions | Where-Object Level -LE $AuditLevelInt	
}

function Get-PISysAudit_CheckSQLXPCommandShell
{
<#  
.SYNOPSIS
AU40001 - SQL Server xp_CmdShell Check
.DESCRIPTION
VALIDATION: Verifies that SQL Server does not have xp_CmdShell enabled.<br/>
COMPLIANCE: Disable xp_CmdShell configuration option. This option can be
configured using the Policy-Based Management or the sp_configure stored
procedure.  For more information, see:<br/>
<a href="https://msdn.microsoft.com/en-us/library/ms190693.aspx">https://msdn.microsoft.com/en-us/library/ms190693.aspx</a>
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
		[string]
		$InstanceName = "Default",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$IntegratedSecurity = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("pf")]
		[string]
		$PasswordFile = "",
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
		# Build and execute the query.
		$requestedScalar = "value_in_use"			
		$queryTemplate = "SELECT {0} FROM Master.sys.configurations WHERE name = 'xp_cmdshell'"
		$query = [string]::Format($queryTemplate,$requestedScalar)

		$value = Invoke-PISysAudit_Sqlcmd_ScalarValue -Query $query -LocalComputer $LocalComputer -RemoteComputerName $RemoteComputerName `
												-InstanceName $InstanceName -ScalarValue $requestedScalar `
												-IntegratedSecurity $IntegratedSecurity `
												-Username $UserName -PasswordFile $PasswordFile `
												-DBGLevel $DBGLevel
								
		# Check if the value is 1 = not compliant, 0 it is.								
		if($null -eq $value)
		{
			# Return the error message.
			$msg = "A problem occurred during the processing of the validation check (logon issue, communication problem, etc.)"					
			Write-PISysAudit_LogMessage $msg "Error" $fn								
			$result = "N/A"
		}				
		elseif($value -eq 0) 
		{ 
			$result = $true 
			$msg = "xp_cmdshell disabled."
		}
		else 
		{ 
			$result = $false
			$msg = "xp_cmdshell enabled." 
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
										-at $AuditTable "AU40001" `
										-aif $fn -msg $msg `
										-ain "SQL Server xp_CmdShell Check" -aiv $result `
										-Group1 "Machine" -Group2 "SQL Server" `
										-Severity "High"
										
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckSQLAdHocQueries
{
<#  
.SYNOPSIS
AU40002 - SQL Server Adhoc Queries Check
.DESCRIPTION
VALIDATION: Verifies that SQL Server does not have Ad Hoc Distributed Queries
enabled.<br/>    
COMPLIANCE: Disable Ad Hoc Distributed Queries configuration option. This 
option can be configured using the Policy-Based Management or the sp_configure 
stored procedure. For more information, see:<br/> 
<a href="https://msdn.microsoft.com/en-us/library/ms187569.aspx">https://msdn.microsoft.com/en-us/library/ms187569.aspx </a>
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
		[string]
		$InstanceName = "Default",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$IntegratedSecurity = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("pf")]
		[string]
		$PasswordFile = "",
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
		# Build and execute the query.
		$requestedScalar = "value_in_use"			
		$queryTemplate = "SELECT {0} FROM Master.sys.configurations WHERE name = 'Ad Hoc Distributed Queries'"
		$query = [string]::Format($queryTemplate,$requestedScalar)
		
		$value = Invoke-PISysAudit_Sqlcmd_ScalarValue -Query $query -LocalComputer $LocalComputer -RemoteComputerName $RemoteComputerName `
												-InstanceName $InstanceName -ScalarValue $requestedScalar `
												-IntegratedSecurity $IntegratedSecurity `
												-Username $UserName -PasswordFile $PasswordFile `
												-DBGLevel $DBGLevel
		
		# Check if the value is 1 = not compliant, 0 it is.								
		if($null -eq $value)
		{
			# Return the error message.
			$msg = "A problem occurred during the processing of the validation check (logon issue, communication problem, etc.)"					
			Write-PISysAudit_LogMessage $msg "Error" $fn								
			$result = "N/A"
		}				
		elseif($value -eq 0) 
		{ 
			$result = $true 
			$msg = "Ad Hoc Distributed Queries disabled."
		}
		else 
		{ 
			$result = $false
			$msg = "Ad Hoc Distributed Queries enabled."
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
										-at $AuditTable "AU40002" `
										-aif $fn -msg $msg `
										-ain "SQL Server Adhoc Queries Check" -aiv $result `
										-Group1 "Machine" -Group2 "SQL Server" `
										-Severity "High"
										
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckSQLDBMailXPs
{
<#  
.SYNOPSIS
AU40003 - SQL Server DB Mail XPs Check
.DESCRIPTION
VALIDATION CHECK: Verifies that SQL Server does not have Ad Hoc Distributed 
Queries enabled.</br>
FOR COMPLIANCE: Disable Database Mail XPs configuration option. This option can
be configured using the Policy-Based Management or the sp_configure stored 
procedure. For more information, see:<br/>
<a href="https://msdn.microsoft.com/en-us/library/ms191189.aspx">https://msdn.microsoft.com/en-us/library/ms191189.aspx</a>
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
		[string]
		$InstanceName = "Default",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$IntegratedSecurity = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("pf")]
		[string]
		$PasswordFile = "",
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
		
		# Build and execute the query.
		$requestedScalar = "value_in_use"			
		$queryTemplate = "SELECT {0} FROM Master.sys.configurations WHERE name = 'Database Mail XPs'"
		$query = [string]::Format($queryTemplate,$requestedScalar)

		$value = Invoke-PISysAudit_Sqlcmd_ScalarValue -Query $query -LocalComputer $LocalComputer -RemoteComputerName $RemoteComputerName `
												-InstanceName $InstanceName -ScalarValue $requestedScalar `
												-IntegratedSecurity $IntegratedSecurity `
												-Username $UserName -PasswordFile $PasswordFile `
												-DBGLevel $DBGLevel
		
		# Check if the value is 1 = not compliant, 0 it is.								
		if($null -eq $value)
		{
			# Return the error message.
			$msg = "A problem occurred during the processing of the validation check (logon issue, communication problem, etc.)"					
			Write-PISysAudit_LogMessage $msg "Error" $fn
			$result = "N/A"
		}				
		elseif($value -eq 0) 
		{ 
			$result = $true 
			$msg = "Database Mail XPs disabled."
		}
		else 
		{ 
			$result = $false
			$msg = "Database Mail XPs enabled."
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
										-at $AuditTable "AU40003" `
										-aif $fn -msg $msg `
										-ain "SQL Server DB Mail XPs Check" -aiv $result `
										-Group1 "Machine" -Group2 "SQL Server" `
										-Severity "High"
										
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckSQLOLEAutomationProcs
{
<#  
.SYNOPSIS
AU40004 - SQL Server OLE Automation Procedures Check
.DESCRIPTION
VALIDATION: Verifies that SQL Server does not have OLE Automation Procedures 
enabled.<br/> 
COMPLIANCE: Disable the OLE Automation Procedures configuration option. This 
option can be configured using the Policy-Based Management or the sp_configure
stored procedure. For more information, see:<br/>
<a href="https://msdn.microsoft.com/en-us/library/ms191188.aspx">https://msdn.microsoft.com/en-us/library/ms191188.aspx</a>
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
		[string]
		$InstanceName = "Default",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$IntegratedSecurity = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("pf")]
		[string]
		$PasswordFile = "",
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
		
		# Build and execute the query.
		$requestedScalar = "value_in_use"			
		$queryTemplate = "SELECT {0} FROM Master.sys.configurations WHERE name = 'Ole Automation Procedures'"
		$query = [string]::Format($queryTemplate,$requestedScalar)
		$value = Invoke-PISysAudit_Sqlcmd_ScalarValue -Query $query -LocalComputer $LocalComputer -RemoteComputerName $RemoteComputerName `
												-InstanceName $InstanceName -ScalarValue $requestedScalar `
												-IntegratedSecurity $IntegratedSecurity `
												-Username $UserName -PasswordFile $PasswordFile `
												-DBGLevel $DBGLevel	
		
		# Check if the value is 1 = not compliant, 0 it is.								
		if($null -eq $value)
		{
			# Return the error message.
			$msg = "A problem occurred during the processing of the validation check (logon issue, communication problem, etc.)"					
			Write-PISysAudit_LogMessage $msg "Error" $fn
			$result = "N/A"
		}				
		elseif($value -eq 0) 
		{
			$result = $true 
			$msg = "Ole Automation Procedures disabled."
		}
		else 
		{ 
			$result = $false
			$msg = "Ole Automation Procedures enabled."
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
										-at $AuditTable "AU40004" `
										-ain "SQL Server OLE Automation Procedures Check" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "Machine" -Group2 "SQL Server" `
										-Severity "High"
										
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckSQLCLR
{
<#  
.SYNOPSIS
AU40005 - SQL Server CLR Configuration Option Check
.DESCRIPTION
VALIDATION: Verifies that SQL Server does not have CLR enabled.<br/> 
COMPLIANCE: Disable the CLR option.  This option can be configured using the 
Policy-Based Management or the sp_configure stored procedure. For more 
information, see:<br/>
<a href="https://msdn.microsoft.com/en-us/library/ms191188.aspx">https://msdn.microsoft.com/en-us/library/ms191188.aspx</a>
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
		[string]
		$InstanceName = "Default",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$IntegratedSecurity = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("pf")]
		[string]
		$PasswordFile = "",
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
		
		# Build and execute the query.
		$requestedScalar = "value_in_use"			
		$queryTemplate = "SELECT {0} FROM Master.sys.configurations WHERE name = 'clr enabled'"
		$query = [string]::Format($queryTemplate,$requestedScalar)
		$value = Invoke-PISysAudit_Sqlcmd_ScalarValue -Query $query -LocalComputer $LocalComputer -RemoteComputerName $RemoteComputerName `
												-InstanceName $InstanceName -ScalarValue $requestedScalar `
												-IntegratedSecurity $IntegratedSecurity `
												-Username $UserName -PasswordFile $PasswordFile `
												-DBGLevel $DBGLevel
		
		# Check if the value is 1 = not compliant, 0 it is.								
		if($null -eq $value)
		{
			# Return the error message.
			$msg = "A problem occurred during the processing of the validation check (logon issue, communication problem, etc.)"					
			Write-PISysAudit_LogMessage $msg "Error" $fn
			$result = "N/A"
		}				
		elseif($value -eq 0) 
		{
			$result = $true 
			$msg = "CLR disabled."
		}
		else 
		{ 
			$result = $false
			$msg = "CLR enabled."
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
										-at $AuditTable "AU40005" `
										-ain "SQL Server CLR Enabled Configuration Option Check" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "Machine" -Group2 "SQL Server" `
										-Severity "High"
										
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckSQLCrossDBOwnershipChaining
{
<#  
.SYNOPSIS
AU40006 - SQL Server Cross DB Ownership Chaining Option Check
.DESCRIPTION
VALIDATION: Verifies that SQL Server does not have Cross DB Ownership Chaining
enabled.<br/> 
COMPLIANCE: Disable the Cross DB Ownership Chaining option.  This option can be
configured using the Policy-Based Management or the sp_configure stored
procedure. For more information, see:<br/>
<a href="https://msdn.microsoft.com/en-us/library/ms191188.aspx">https://msdn.microsoft.com/en-us/library/ms191188.aspx</a>
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
		[string]
		$InstanceName = "Default",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$IntegratedSecurity = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("pf")]
		[string]
		$PasswordFile = "",
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
		
		# Build and execute the query.
		$requestedScalar = "value_in_use"			
		$queryTemplate = "SELECT {0} FROM Master.sys.configurations WHERE name = 'Cross db ownership chaining'"
		$query = [string]::Format($queryTemplate,$requestedScalar)
		$value = Invoke-PISysAudit_Sqlcmd_ScalarValue -Query $query -LocalComputer $LocalComputer -RemoteComputerName $RemoteComputerName `
												-InstanceName $InstanceName -ScalarValue $requestedScalar `
												-IntegratedSecurity $IntegratedSecurity `
												-Username $UserName -PasswordFile $PasswordFile `
												-DBGLevel $DBGLevel	
		
		# Check if the value is 1 = not compliant, 0 it is.								
		if($null -eq $value)
		{
			# Return the error message.
			$msg = "A problem occurred during the processing of the validation check (logon issue, communication problem, etc.)"					
			Write-PISysAudit_LogMessage $msg "Error" $fn
			$result = "N/A"
		}				
		elseif($value -eq 0) 
		{
			$result = $true 
			$msg = "Cross DB Ownership Chaining disabled."
		}
		else 
		{ 
			$result = $false
			$msg = "Cross DB Ownership Chaining enabled."
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
										-at $AuditTable "AU40006" `
										-ain "SQL Server Cross DB Ownership Chaining Check" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "Machine" -Group2 "SQL Server" `
										-Severity "High"
										
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckSQLRemoteAccess
{
<#  
.SYNOPSIS
AU40007 - SQL Server Remote Access Option Check
.DESCRIPTION
VALIDATION: Verifies that SQL Server does not have Remote Access enabled.<br/> 
COMPLIANCE: Disable the Remote Access option.  This option can be configured 
using the Policy-Based Management or the sp_configure stored procedure. For 
more information, see:<br/>
<a href="https://msdn.microsoft.com/en-us/library/ms191188.aspx">https://msdn.microsoft.com/en-us/library/ms191188.aspx</a>
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
		[string]
		$InstanceName = "Default",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$IntegratedSecurity = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("pf")]
		[string]
		$PasswordFile = "",
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
		
		# Build and execute the query.
		$requestedScalar = "value_in_use"			
		$queryTemplate = "SELECT {0} FROM Master.sys.configurations WHERE name = 'Remote access'"
		$query = [string]::Format($queryTemplate,$requestedScalar)
		$value = Invoke-PISysAudit_Sqlcmd_ScalarValue -Query $query -LocalComputer $LocalComputer -RemoteComputerName $RemoteComputerName `
												-InstanceName $InstanceName -ScalarValue $requestedScalar `
												-IntegratedSecurity $IntegratedSecurity `
												-Username $UserName -PasswordFile $PasswordFile `
												-DBGLevel $DBGLevel	
		
		# Check if the value is 1 = not compliant, 0 it is.								
		if($null -eq $value)
		{
			# Return the error message.
			$msg = "A problem occurred during the processing of the validation check (logon issue, communication problem, etc.)"					
			Write-PISysAudit_LogMessage $msg "Error" $fn
			$result = "N/A"
		}				
		elseif($value -eq 0) 
		{
			$result = $true 
			$msg = "Remote Access disabled."
		}
		else 
		{ 
			$result = $false
			$msg = "Remote Access enabled."
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
										-at $AuditTable "AU40007" `
										-ain "SQL Server Remote Access Check" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "Machine" -Group2 "SQL Server" `
										-Severity "High"
										
}

END {}

#***************************
#End of exported function
#***************************
}

function Get-PISysAudit_CheckSQLsa
{
<#  
.SYNOPSIS
AU40008 - SQL Server sa Login Check
.DESCRIPTION
VALIDATION: Verifies that SQL Server does not have the sa login enabled.<br/> 
COMPLIANCE: Disable the sa login.  This option can be configured using the 
Policy-Based Management or the sp_configure stored procedure. For more 
information, see:<br/>
<a href="https://msdn.microsoft.com/en-us/library/ms191188.aspx">https://msdn.microsoft.com/en-us/library/ms191188.aspx</a>
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
		[string]
		$InstanceName = "Default",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$IntegratedSecurity = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("pf")]
		[string]
		$PasswordFile = "",
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
	$Severity = "Unknown"
	try
	{											
		
		# Build and execute the query.
		$requestedScalar = "is_disabled"			
		$queryTemplate = "SELECT {0} FROM master.sys.server_principals WHERE sid = 0x01"
		$query = [string]::Format($queryTemplate,$requestedScalar)
		$value = Invoke-PISysAudit_Sqlcmd_ScalarValue -Query $query -LocalComputer $LocalComputer -RemoteComputerName $RemoteComputerName `
												-InstanceName $InstanceName -ScalarValue $requestedScalar `
												-IntegratedSecurity $IntegratedSecurity `
												-Username $UserName -PasswordFile $PasswordFile `
												-DBGLevel $DBGLevel	
		
		# Check if the value is 1 = not compliant, 0 it is.								
		if($null -eq $value)
		{
			# Return the error message.
			$msg = "A problem occurred during the processing of the validation check (logon issue, communication problem, etc.)"					
			Write-PISysAudit_LogMessage $msg "Error" $fn
			$result = "N/A"
		}				
		elseif($value -eq 1) 
		{
			$result = $true 
			$msg = "Login sa disabled."
		}
		else 
		{ 
			$result = $false
			$msg = "Login sa enabled."
			$Severity = "High"

			# Build and execute the query.
			$sarenamed = 0
			$requestedScalar = "sa_renamed"			
			$queryTemplate = "SELECT (CASE name WHEN 'sa' THEN 0 ELSE 1 END) as {0} FROM master.sys.server_principals WHERE sid = 0x01"
			$query = [string]::Format($queryTemplate,$requestedScalar)
			$sarenamed = Invoke-PISysAudit_Sqlcmd_ScalarValue -Query $query -LocalComputer $LocalComputer -RemoteComputerName $RemoteComputerName `
												-InstanceName $InstanceName -ScalarValue $requestedScalar `
												-IntegratedSecurity $IntegratedSecurity `
												-Username $UserName -PasswordFile $PasswordFile `
												-DBGLevel $DBGLevel
			
			if($sarenamed -eq 0)
			{
				$msg += "  Well known default name sa in use."
			}
			else
			{
				$msg += "  Login name changed from the default."
				$Severity = "Medium"
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
										-at $AuditTable "AU40008" `
										-ain "SQL Server sa Login Account Check" -aiv $result `
										-aif $fn -msg $msg `
										-Group1 "Machine" -Group2 "SQL Server" `
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
function Get-PISysAudit_TemplateAU4xxxx
{
<#  
.SYNOPSIS
AU4xxxx - <Name>
.DESCRIPTION
VERIFICATION: <Enter what the verification checks>
COMPLIANCE: <Enter what it needs to be compliant>
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]     
param(							
		[parameter(Mandatory=$true, Position=0, ParameterSetName = "Default")]
		[alias("at,AT")]
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
		[string]
		$InstanceName = "Default",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[boolean]
		$IntegratedSecurity = $true,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("user")]
		[string]
		$UserName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("pf")]
		[string]
		$PasswordFile = "",
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
Export-ModuleMember Get-PISysAudit_FunctionsFromLibrary4
Export-ModuleMember Get-PISysAudit_CheckSQLXPCommandShell
Export-ModuleMember Get-PISysAudit_CheckSQLAdHocQueries
Export-ModuleMember Get-PISysAudit_CheckSQLDBMailXPs
Export-ModuleMember Get-PISysAudit_CheckSQLOLEAutomationProcs
Export-ModuleMember Get-PISysAudit_CheckSQLCLR
Export-ModuleMember Get-PISysAudit_CheckSQLCrossDBOwnershipChaining
Export-ModuleMember Get-PISysAudit_CheckSQLRemoteAccess
Export-ModuleMember Get-PISysAudit_CheckSQLsa
# </Do not remove>

# ........................................................................
# Add your new Export-ModuleMember instruction after this section.
# Replace the Get-PISysAudit_TemplateAU4xxxx with the name of your
# function.
# ........................................................................
# Export-ModuleMember Get-PISysAudit_TemplateAU4xxxx