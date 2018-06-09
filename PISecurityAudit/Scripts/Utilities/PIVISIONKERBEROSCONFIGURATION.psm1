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

function SetFolders
{
	# Retrieve the folder from which this script is called ..\Scripts and split the path
	# to remove the Scripts part.	
	$modulePath = $PSScriptRoot
	
	# ..\
	# ..\Scripts
	# ..\Scripts\PISYSAUDIT
	# ..\Export
	$scriptsPath = Split-Path $modulePath
	$rootPath = Split-Path $scriptsPath				
	
	$exportPath = PathConcat -ParentPath $rootPath -ChildPath "Export"
	if (!(Test-Path $exportPath)){
	New-Item $exportPath -type directory
	}

	$logFile = PathConcat -ParentPath $exportPath -ChildPath "PISystemAudit.log"		
	
	# Store at the global scope range.	
	if($null -eq (Get-Variable "ExportPath" -Scope "Global" -ErrorAction "SilentlyContinue").Value)
	{
		New-Variable -Name "ExportPath" -Option "Constant" -Scope "Global" -Visibility "Public" -Value $exportPath
	}
	if($null -eq (Get-Variable "PISystemAuditLogFile" -Scope "Global" -ErrorAction "SilentlyContinue").Value)
	{
		New-Variable -Name "PISystemAuditLogFile" -Option "Constant" -Scope "Global" -Visibility "Public" -Value $logFile	
	}
}

function Get-ServiceLogonAccountType 
{
<#
.SYNOPSIS
Query the Service account object in AD for the object type.
.DESCRIPTION
Query AD for the object type of the service account.  This function requires RSAT-AD-Tools.
#>
	param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("sa")]
		[string]
		$ServiceAccount,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("sad")]
		[string]
		$ServiceAccountDomain = $null,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("cn")]
		[string]
		$ComputerName,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	
	)	

	$fn = GetFunctionName
	# Check for Local Account, Machine Account or Null value
	$blnDomainResolved = $null -ne $ServiceAccountDomain -and $ServiceAccountDomain -ne '.' -and $ServiceAccountDomain -ne 'MACHINEACCOUNT'
	If (!$blnDomainResolved -and `
	   ($ServiceAccount -eq "LocalSystem" -or $ServiceAccount -eq "Local System" -or $ServiceAccount -eq "NetworkService" -or $ServiceAccount -eq "Network Service" -or $ServiceAccount -eq "AFService" -or $ServiceAccount -eq "pinetmgr")) 
		{ 
			# Truncate to the hostname for processing of logon type
			$pos = $ComputerName.IndexOf('.')
			If($pos -eq -1){ $ServiceAccount = $ComputerName }
			Else {
				$ServiceAccount = $ComputerName.Substring(0,$pos)
				$ServiceAccountDomain = $ComputerName.Substring($pos+1)
				$blnDomainResolved = $true
			}
		}
	
	$ServiceAccount = $ServiceAccount.TrimEnd('$')

	If(!$blnDomainResolved)
	{
		$DomainObjectType = Get-ADObject -Filter { Name -like $ServiceAccount } -Properties ObjectCategory | Select -ExpandProperty objectclass
		$msgTemplate = "Querying AD for {0}"
		$msg = [string]::Format($msgTemplate, $ServiceAccount)
		Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2
	}
	Else
	{
		$DomainObjectType = Get-ADObject -Filter { Name -like $ServiceAccount } -Properties ObjectCategory -Server $ServiceAccountDomain | Select -ExpandProperty objectclass
		$msgTemplate = "Querying AD for {0} in domain {1}"
		$msg = [string]::Format($msgTemplate, $ServiceAccount, $ServiceAccountDomain)
		Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2
	}

	If ($DomainObjectType -eq "user") { $AccType = 1 } ElseIf ($DomainObjectType -eq "computer") { $AccType = 2 } ElseIf ($DomainObjectType -eq "msDS-GroupManagedServiceAccount" -or $DomainObjectType -eq "msDS-ManagedServiceAccount") {  $AccType = 3 } Else { $AccType = 0 }

	return $AccType
}

function Get-BackEndSPNs 
{
<#
.SYNOPSIS
Verify PI and AF Server SPN configuration.
.DESCRIPTION
Verify PI and AF Server SPN configuration. This function uses setspn.exe tool.
#>
	param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("st")]
		[string]
		$serviceType,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("sn")]
		[string]
		$serviceName,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("pan")]
		[string]
		$PIorAFServer,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	
	)	

		$fn = GetFunctionName

		# BACK-END (PI/AF) SPN CHECK
		
		# Construct short and FQDN of the back end service.
		$dot = "."
		If ($PIorAFServer -match [regex]::Escape($dot)) { 
		$fqdnpiaf = $PIorAFServer.ToLower() 
		$pos = $fqdnpiaf.IndexOf(".")
		$shortpiaf = $fqdnpiaf.Substring(0, $pos)
		}
		
		Else { 
		$shortpiaf = $PIorAFServer.ToLower() 
		$fqdnpiaf = ($PIorAFServer.ToLower() + "." + $WebServerDomain.ToLower()).ToString()
		}
		
		# PI/AF us local to PI Vision. Delegation shouldn't be required.
		#If ($fqdnpiaf -eq $WebServerFQDN) {
		#$global:strBackEndSPNS += "<p>$serviceType $PIorAFServer is running on $global:ProductName server. No Kerberos Delegation required.</p>"
		#}
		
		# PI/AF is remote. Delegation is required.
		#Else {
			$result = Invoke-PISysAudit_SPN -svctype $serviceType -svcname $serviceName -lc $false -rcn $PIorAFServer -dbgl $DBGLevel
			
			If ($result -ne $null) {

				# All good.
				If ($result) { $global:strBackEndSPNS += "<p><good>Service Principal Names for $serviceType $PIorAFServer are set up correctly.<br></good></p>" }
				
				# Misconfiguration identified. Look for a fix.
				Else { 
				$SvcAccount = Get-PISysAudit_ServiceProperty -sn $serviceName -sp LogOnAccount -lc $false -rcn $PIorAFServer -ErrorAction SilentlyContinue
				$SvcAccountObject = Get-PISysAudit_ParseDomainAndUserFromString -UserString $SvcAccount -DBGLevel $DBGLevel
				
				$SVCName = $SvcAccountObject.UserName

				$global:strBackEndSPNS += "<p><bad>Service Principal Names for $serviceType $PIorAFServer are NOT set up correctly.<br></bad> 
				<details>
				<summary>Commands to create the missing SPNs | Documentation</summary><br>
				<code>
				setspn -s $serviceType/$shortpiaf $SVCName<br>
				setspn -s $serviceType/$fqdnpiaf $SVCName<br>
				</code>
				</details></p>"
				}

			}
			
			# Can't reach the back (end)
			Else { 
			$global:strBackEndSPNS += "<p>Could not get the service account running $serviceType $PIorAFServer. Enable PSRemoting to the machine to proceed.<br>
			<details>
			<summary>How to run the script remotely</summary><br>
			<a href=`"https://github.com/osisoft/PI-Security-Audit-Tools/wiki/Tutorial2:-Running-the-scripts-remotely-(USERS)`" >Documentation at GitHub</a>
			</details></p>"
			}
		#}

		# Debug options
		$msgTemplate = "Back End SPNs for {0} {1} are {2} and {3}. Service account is {4}."
		$msg = [string]::Format($msgTemplate, $serviceType, $PIorAFServer, $shortpiaf, $fqdnpiaf, $SVCName)
		Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2 
}

Function Check-ResourceBasedConstrainedDelegationPrincipals 
{
<#
.SYNOPSIS
Verify RBCD configuration.
.DESCRIPTION
Verify RBCD configuration. This function uses RSAT-AD-PowerShell Module.
#>
	param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("sa")]
		[string]
		$ServiceAccount,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("sad")]
		[string]
		$ServiceAccountDomain = $null,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("sat")]
		[int]
		$ServiceAccountType = 0,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("api")]
		[string]
		$ApplicationPoolIdentity,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("sid")]
		[string]
        $ApplicationPoolIdentitySID,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("cn")]
		[string]
		$ComputerName,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("rt")]
		[string]
		$ResourceType,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	
	)	

    If ($ServiceAccountType -eq 2)  
	{ 
		# Truncate to the hostname for processing of logon type
		$pos = $ComputerName.IndexOf('.')
		If($pos -eq -1){ $ServiceAccount = $ComputerName }
		Else {
			$ServiceAccount = $ComputerName.Substring(0,$pos)
			$ServiceAccountDomain = $ComputerName.Substring($pos+1)
			$blnDomainResolved = $true
		}
	}
	# In case gMSA or MSA is used, remove the trailing $ character.
	Else { $ServiceAccount = $ServiceAccount.TrimEnd('$') }

	# Reset the main variable
	$RBKCDPrincipal = ""
	
	$blnResolveDomain = $null -ne $ServiceAccountDomain -and $ServiceAccountDomain -ne "MACHINEACCOUNT" -and $ServiceAccountDomain -ne '.'

	# Back end identity is domain user.
	If ($ServiceAccountType -eq 1) 
	{ 
		If($blnResolveDomain) { 
			$RBKCDADProperties = Get-ADUser $ServiceAccount -Properties PrincipalsAllowedToDelegateToAccount -Server $ServiceAccountDomain 
    
 		}
		Else { 
			$RBKCDADProperties = Get-ADUser $ServiceAccount -Properties PrincipalsAllowedToDelegateToAccount
		}
    $ADObjType_RBCD = "Set-ADUser"
	}

	# Back end identity is domain computer.
	If ($ServiceAccountType -eq 2) { 
		If($blnResolveDomain) { 
			$RBKCDADProperties = Get-ADComputer $ServiceAccount -Properties PrincipalsAllowedToDelegateToAccount -Server $ServiceAccountDomain 
		}
		Else { 
			$RBKCDADProperties = Get-ADComputer $ServiceAccount -Properties PrincipalsAllowedToDelegateToAccount
		}
    $ADObjType_RBCD = "Set-ADComputer"
	}

	# MSA or gMSA. MSA is not recommended.
	If ($ServiceAccountType -eq 3) { 
		If($blnResolveDomain) {
			$RBKCDADProperties = Get-ADServiceAccount $ServiceAccount -Properties PrincipalsAllowedToDelegateToAccount -Server $ServiceAccountDomain 
 		}
		Else { 
			$RBKCDADProperties = Get-ADServiceAccount $ServiceAccount -Properties PrincipalsAllowedToDelegateToAccount 
		}
    $ADObjType_RBCD = "Set-ADServiceAccount"
	}
	
	# Select string value within PrincipalsAllowedToDelegateToAccount parameter of the back-end Service Account 
	$RBKCDPrincipals = $RBKCDADProperties.PrincipalsAllowedToDelegateToAccount
	
	# Debug options
	$msgTemplate = "Principals for Account {0} (Type:{1}): {2}"
	$msg = [string]::Format($msgTemplate, $ServiceAccount, $AccType, $RBKCDPrincipals)
	Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2 

	# Template for correct rbcd config.   
	$msgCanDelegateTo = "<p><good>$global:SvcAccountFriendlyName can delegate to $ResourceType $ComputerName running under $ServiceAccount</good></p>"


    # Check the Principals for a match (based on name or SID)
	If ($RBKCDPrincipals -match $ApplicationPoolIdentity -or $RBKCDPrincipals -match $ApplicationPoolIdentitySID) 
	{ 
		$global:RBCDstring += $msgCanDelegateTo
	} 

    ElseIf ($ComputerName -eq $global:WebServerName -or $ComputerName -eq $global:WebServerFQDN) { 
    $global:RBCDstring += "<p><good>$global:SvcAccountFriendlyName doesn't need to delegate to $ResourceType $ComputerName because they're on the same machine.</good></p>"    
    }

	# Resource-Based Kerberos Delegation is not configured properly - compiling a set of PS commands to fix the rbcd config.
	Else {
			# The AppPool identity will always be the first principal to add to PrincipalsAllowedToDelegateToAccount list.
			# Get-ADObject is used to fetch Principal Name, allowing for combination of multiple object types (e.g User + Computer) within a single Set- command.

			# AppPool is user
			If ($global:ADAccType -eq 1) { 
				$DNAME_RBCD = Get-ADUser -Identity $ApplicationPoolIdentity | Select-Object -ExpandProperty "DistinguishedName" 
			}
			# AppPool is computer
			ElseIf ($global:ADAccType -eq 2) { 
				$DNAME_RBCD = Get-ADComputer -Identity $ApplicationPoolIdentity | Select-Object -ExpandProperty "DistinguishedName" 	
			}
			# AppPool is gMSA or MSA
			ElseIf ($global:ADAccType -eq 3) { 
				$DNAME_RBCD = Get-ADServiceAccount -Identity $ApplicationPoolIdentity | Select-Object -ExpandProperty "DistinguishedName" 		
			}
		
			
			$DNAME_RBCD = $DNAME_RBCD -split ","
		
			# Get AppPool name
			$DNAME_RBCD_Name = $DNAME_RBCD[0].Substring(($DNAME_RBCD[0].lastIndexOf("=") + 1))

			# Get AppPool type
			$DNAME_RBCDobjt = ($DNAME_RBCD[1].Substring(($DNAME_RBCD[0].lastIndexOf("=") + 1))).TrimEnd('s')
			If ($DNAME_RBCDobjt -eq "Managed Service Account") { $DNAME_RBCDobjt = "msDS-GroupManagedServiceAccount" }
			
			# Get AppPool Domain FQDN
			$DNAME_RBCD_server = $DNAME_RBCD[2].Substring(($DNAME_RBCD[0].lastIndexOf("=") + 1)) + "." + $DNAME_RBCD[3].Substring(($DNAME_RBCD[0].lastIndexOf("=") + 1))

			# Get current principals allowed to delegate to back-end and save them.
			$RBCDfixArray = @()
			$RBCDfixvarNo = 2 # existing list of principals will start at #2

			$RBCDfixPrincipalList = $null
			
			# Construct the first Principal to be added
			$RBCDfixfirst = "`$Principal1 = Get-ADObject -filter {(cn -eq `"$DNAME_RBCD_Name`") -and (ObjectClass -eq `"$DNAME_RBCDobjt`")} -Server $DNAME_RBCD_server" #1 reserved for the AppPool DN
			
			foreach($RBCDfixline in $RBKCDPrincipals) {

				# Split distinguished name into 4 parts
				$RBCDfixline = $RBCDfixline -split ","
					
					# Principal and Back End are in the same domain > name is listed instead of SID			
					If ($RBCDfixline[0] -match "CN=") {

						# Get Principal name
						$name = $RBCDfixline[0].Substring(($RBCDfixline[0].lastIndexOf("=") + 1))

						# Get Principal object type
						$objt = ($RBCDfixline[1].Substring(($RBCDfixline[0].lastIndexOf("=") + 1))).TrimEnd('s')
							If ($objt -eq "Managed Service Account") {
							$objt = "msDS-GroupManagedServiceAccount"
							}

						# Get Principal domain
						$server = $RBCDfixline[2].Substring(($RBCDfixline[0].lastIndexOf("=") + 1)) + "." + $RBCDfixline[3].Substring(($RBCDfixline[0].lastIndexOf("=") + 1))
						
						# Create PS command for end user
						$RBCDfixArray += "`$Principal$RBCDfixvarNo = Get-ADObject -filter {(cn -eq `"$name`") -and (ObjectClass -eq `"$objt`")} -Server $server<br>"
						
						# Update Principals list and increase Principal ID
						$RBCDfixPrincipalList += "," +  "`$Principal$RBCDfixvarNo"
						$RBCDfixvarNo++
					}

					# Principal and Back End are not in the same domain. Request the user to construct PrincipalsToAllowedToDelegate manually.
					Else {
						$name = $RBCDfixline[0]
						$global:RBCDstring = "<p><bad>$global:SvcAccountFriendlyName CAN'T delegate to $ResourceType $ComputerName running under $ServiceAccount</bad><br>
						An account from another domain (SID: $name) has been identified on PrincipalsToAllowedToDelegate list.<br>
						Manual PrincipalsToAllowedToDelegate construction required. <br>
						See OSIsoft <a href=`"http://techsupport.osisoft.com/Troubleshooting/KB/KB01222`" target=`"_blank`" >KB01222 - Types of Kerberos Delegation</a><br></p>"
						break
					}
			}
            
			    # Print the final command for the end user to see.
			    $RBCDfixFinished = "$($ADObjType_RBCD) -Identity $($ServiceAccount) -PrincipalsAllowedToDelegateToAccount `$Principal1$($RBCDfixPrincipalList) -Server $ServiceAccountDomain"

			    # Cannot delegate + fix
			    $global:RBCDstring += "<p><bad>$global:SvcAccountFriendlyName CAN'T delegate to $ResourceType $ComputerName running under $ServiceAccount</bad><br>
			    <details>
			    <summary><a href=`"http://techsupport.osisoft.com/Troubleshooting/KB/KB01222`" target=`"_blank`" >Documentation</a> | PowerShell commands to fix the issue:</summary><br>
			    <code>
			    $RBCDfixfirst<br>
			    $RBCDfixArray<br>
			    $RBCDfixFinished<br>
			    </code>		
			    </details></p>" 
                }
}

Function Check-ClassicDelegation
{
<#
.SYNOPSIS
Verify Classic Kerberos Delegation configuration.
.DESCRIPTION
Verify Classic Kerberos Delegation configuration. This function uses RSAT-AD-PowerShell Module.
#>
	param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("sspn")]
		[string]
		$ClassicShortSPNtoDelegateTo,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("lspn")]
		[string]
		$ClassicLongSPNtoDelegateTo,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("csspn")]
		[string]
		$CSShortSPN,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("clspn")]
		[string]
		$CSLongSPN,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("cap")]
		[string]
		$ClassicAppPool,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("crt")]
		[string]
		$ClassicResourceType,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("cse")]
		[string]
		$ClassicServer,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("cat")]
		[int]
		$ClassicAccType,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("dnsa")]
		[boolean]
		$DNSAtype,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	
	)	

	# The list of SPNs IIS AppPool can delegate to AND Protocol Transition property need to be retrieved only once.
	If ($global:FirstPass -ne $true) {

		    $global:FirstPass = $true
		    
            If ($ClassicAccType -eq 1) {
		    $ClassicADproperties = Get-ADUser $ClassicAppPool -Properties TrustedForDelegation, msDS-AllowedToDelegateTo, TrustedToAuthForDelegation, ServicePrincipalNames
            $global:ADObjType = "Set-ADUser"
            $ClassicAppPoolPT = $ClassicAppPool
            }

		    If ($ClassicAccType -eq 2) { 
		    $ClassicADproperties = Get-ADComputer $ClassicAppPool -Properties TrustedForDelegation, msDS-AllowedToDelegateTo, TrustedToAuthForDelegation, ServicePrincipalNames
            $global:ADObjType = "Set-ADComputer"
            $ClassicAppPoolPT = $ClassicAppPool + '$'
            }

		    If ($ClassicAccType -eq 3) { 
		    $ClassicADproperties = Get-ADServiceAccount $ClassicAppPool -Properties TrustedForDelegation, msDS-AllowedToDelegateTo, TrustedToAuthForDelegation, ServicePrincipalNames
            $global:ADObjType = "Set-ADServiceAccount"
            $ClassicAppPoolPT = $ClassicAppPool + '$'
            }

		    $ClassicAppPoolDelegation = $ClassicADproperties.'msDS-AllowedToDelegateTo'	
		    $ClassicProtocolTransition = $ClassicADproperties.TrustedToAuthForDelegation
		    $ClassicUnconstrainedKerberos = $ClassicADproperties.TrustedForDelegation

		    # Protocol Transition messaging.
		    If ($ClassicProtocolTransition -eq $false) {
		    $global:strClassicDelegation +="<p><bad>Protocol Transition is Disabled - Kerberos Delegation may fail.</bad><br>
											<details>
											<summary>PowerShell commands to fix the issue and <a href=`"https://livelibrary.osisoft.com/LiveLibrary/content/en/vision-v1/GUID-68329569-D75C-406D-AE2D-9ED512E74D46`" target=`"_blank`" >documentation</a></summary><br>
											<code>
											Set-ADAccountControl -Identity  $ClassicAppPoolPT -TrustedToAuthForDelegation `$true
											</code>				
											</details></p>"
		    }

            # Remove unnecessary characters from the SPN string

            # Handling empty SPN property
            If ([string]::IsNullOrWhitespace($ClassicADproperties.ServicePrincipalNames)) {
            $ClassicSPNs = $null
            }
            # Non-empty SPN property
            Else {
		    $ClassicSPNs = $ClassicADproperties.ServicePrincipalNames.ToLower().Trim()	
            }

		    # Check PI Vision SPNs for a match
        
            # Host (A) DNS Record is used - only one SPN needed!
		    If ($DNSAtype) {
			    If ($ClassicSPNs -match $CSShortSPN) { 
				    $global:strSPNs = "<p><good>$global:ProductName Service Principal Name $CSShortSPN exists and is assigned to the service identity: $global:SvcAccountFriendlyName.</good></p>" 			
			    }
			    Else { 
				    $global:strSPNs = "<p><bad>Kerberos authentication will fail. Please make sure $CSShortSPN Service Principal Name is assigned to the correct service identity: $global:SvcAccountFriendlyName.</bad><br>
				    <details>
					<summary><a href=`"https://livelibrary.osisoft.com/LiveLibrary/content/en/vision-v1/GUID-68329569-D75C-406D-AE2D-9ED512E74D46 `" target=`"_blank`" >Documentation</a> | Command to create the missing SPN:</summary><br>
                    <code>
					setspn -s $CSShortSPN $global:ServiceAccount
					</code>
					</details></p>"
				}
            }
        
            # CNAME or FQDN/hostname is used.
		    Else {
			    If ($ClassicSPNs -match $CSShortSPN -and $ClassicSPNs -match $CSLongSPN) { 
				    $global:strSPNs = "<p><good>Service Principal Names $CSShortSPN and $CSLongSPN exist and are assigned to the service identity: $global:SvcAccountFriendlyName.</good></p>"   
			    }
			    Else { 
				    $global:strSPNs = "<p><bad>Kerberos authentication will fail. Please make sure $CSShortSPN and $CSLongSPN Service Principal Names are assigned to the correct service identity: $global:SvcAccountFriendlyName.</bad><br>
				    <details>
					<summary><a href=`"https://livelibrary.osisoft.com/LiveLibrary/content/en/vision-v1/GUID-68329569-D75C-406D-AE2D-9ED512E74D46 `" target=`"_blank`" >Documentation</a> | Commands to create the missing SPNs</summary><br>
					<code>
                    setspn -s $CSShortSPN $global:ServiceAccount<br>
                    setspn -s $CSLongSPN $global:ServiceAccount
					</code>
					</details></p>"
				}
		    
            }
	

	        # Unconstrained Kerberos Delegation is not supported (and rather insecure)
	        If ($ClassicUnconstrainedKerberos -eq $true) { 
	        $global:strClassicDelegation = "<p><bad>$global:SvcAccountFriendlyName is trusted for Unconstrained Kerberos Delegation!<br> 
	        This is neither supported nor secure!</bad><br>
			Enable Constrained Kerberos Delegation as per <a href=`"http://techsupport.osisoft.com/Troubleshooting/KB/KB01222`" target=`"_blank`" >OSIsoft KB01222 - Types of Kerberos Delegation</a><br>  
	        </p>"
	        }
	}

	# Delegation is configured within a single Windows Domain.
	If ($ClassicLongSPNtoDelegateTo -match $WebServerDomain) {
    $DelegationFix ="<p><details><summary>
	<a href=`"https://livelibrary.osisoft.com/LiveLibrary/content/en/vision-v1/GUID-68329569-D75C-406D-AE2D-9ED512E74D46`" target=`"_blank`" >Documentation</a> | PowerShell commands to fix the issue:</summary><br>
	<code>$global:ADObjType -Identity $ClassicAppPool -Add @{ `"msDS-AllowedToDelegateTo`" = '$ClassicShortSPNtoDelegateTo' }<br>
    $global:ADObjType -Identity $ClassicAppPool -Add @{ `"msDS-AllowedToDelegateTo`" = '$ClassicLongSPNtoDelegateTo' } </code><br>
    </details></p>"		
	}
	# Classic Kebreros Constrained Delegation doesn't work cross-domain. Go for rbcd.
	Else {
	$DelegationFix ="<p><a href=`"https://livelibrary.osisoft.com/LiveLibrary/content/en/vision-v1/GUID-68329569-D75C-406D-AE2D-9ED512E74D46`" target=`"_blank`" >Configure Resource-Based Constrained Kerberos Delegation.</a></p>"
	}
	
	# Debug option.
	$msgTemplate = "AppPool Identity {0} can delegate to {1}"
	#$msg = [string]::Format($msgTemplate, $PIVisionUserSvc, $ClassicDelegationList)
	$msg = [string]::Format($msgTemplate, $PIVisionUserSvc, $ClassicAppPoolDelegation)
	Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2


    If ($ClassicServer -ne $Global:WebServerName -and $ClassicServer -ne $Global:WebServerFQDN) {

	# All good.
	$msgCanDelegateToClassic = "<p><good>$global:SvcAccountFriendlyName  can delegate to $ClassicResourceType $ClassicServer.</good></p>"
	
	# Issue found - include fix.
	$msgCanNotDelegateToClassic = "<p><bad>$global:SvcAccountFriendlyName  CAN'T delegate to $ClassicResourceType $ClassicServer.</bad></p>
    $DelegationFix"
	}

    Else { 
    $global:strClassicDelegation +=  "<p><good>$global:SvcAccountFriendlyName doesn't need to delegate to $ClassicResourceType $ClassicServer because it's all in one machine.</good></p>" }


	# Look through the list of SPNs PI Vision (Coresight) can delegate to for a match.
	If ($ClassicAppPoolDelegation -contains $ClassicShortSPNtoDelegateTo -and $ClassicAppPoolDelegation -contains $ClassicLongSPNtoDelegateTo) { 
		$global:strClassicDelegation += $msgCanDelegateToClassic
	} 
	Else { 
		$global:strClassicDelegation += $msgCanNotDelegateToClassic
	}
}

Function Check-KernelModeAuth
{
<#
.SYNOPSIS
Verify Kernel-mode Authentication configuration.
.DESCRIPTION
Verify Kernel-mode Authentication configuration based on combination of AppPool identity and Windows Authentication settings.
#>
	param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("CustomAppPool")]
		[boolean]
		$blnCustomAppPoolAccount,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("UseAppPoolCreds")]
		[boolean]
		$blnUAppPoolPwdKerbTicketDecrypt,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("UseKernelModeAuth")]
		[boolean]
		$blnUseKernelModeAuth,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	
	)	
        
# PS command to enable Kernel-mode authentication property
$KernelFix=@"
Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/windowsAuthentication' -Name useKernelMode -location '$($global:PIVisionConfiguration.KernelLocation)' -Value True<br>
"@  

# PS command to enabled useAppPoolCreds property
$KerbDecryptFix=@"
Set-WebConfigurationProperty -Filter '/system.webServer/security/authentication/windowsAuthentication' -Name useAppPoolCredentials -location '$($global:PIVisionConfiguration.KernelLocation)' -Value True<br>
"@ 

		# Kernel-mode Authentication is disabled
		If ($blnUseKernelModeAuth -eq $false) {

			# Non-default account is running AppPools
			If ($blnCustomAppPoolAccount -eq $True) {
				$global:Kernel = "<p><bad>Kernel-mode Authentication is disabled.</bad><br>
				<details>
				<summary><a href=`"http://aka.ms/kcdpaper`" target=`"_blank`" >Documentation download</a> | PowerShell commands to fix the issue:</summary><br>
				<code>
				$KernelFix
				$KerbDecryptFix
				</code>
				</details></p>"
			}

			# Default account is running AppPools
			Else {
				$global:Kernel = "<p><bad>Kernel-mode Authentication is disabled.</bad><br>
				<details>
				<summary><a href=`"http://aka.ms/kcdpaper`" target=`"_blank`" >Documentation download</a> | PowerShell commands to fix the issue:</summary><br>
				<code>
				$KernelFix
				</code>
				</details><br></p>"
			}
		}
		# Kernel-mode Authentication is enabled
		Else {
            
			# Custom account is used, useAppPoolCreds is FALSE
			If ($blnCustomAppPoolAccount -eq $True -and $blnUAppPoolPwdKerbTicketDecrypt -eq $false) {
       
            $global:Kernel = "<p><bad>Kerberos Authentication to PI Vision can't work.</bad><br>
            <details>
			<summary><a href=`"http://aka.ms/kcdpaper`" target=`"_blank`" >Documentation download</a> | PowerShell commands to fix the issue:</summary><br>
            <code>
			$KerbDecryptFix
            </code>
			</details></p>"
			}

			# Custom account is used, useAppPoolCreds is TRUE OR Default is used
			Else {
			$global:Kernel = "<p><good>Kernel-Mode Authentication is enabled and configured properly.</good></p>"
			}
		}
}

Function Get-AppNetworkIdentityName
{
<#
.SYNOPSIS
Parse Service Account Name and type.
.DESCRIPTION
Parse Service Account Name and type.
#>
	param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("IDType")]
		[string]
		$IdentityType,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("UserString")]
		[string]
		$UsernameValue,
		[alias("ServerName")]
		[string]
		$IISserverName,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	
	)	

	$CSUserGMSA = $UsernameValue | Out-String

    If ($IdentityType -ne "NetworkService" -and $IdentityType -ne "ApplicationPoolIdentity" -and $IdentityType -ne "LocalSystem" -and $IdentityType -ne "Local System" -and $IdentityType -ne "Network Service" -and $IdentityType -ne "piwebapi"-and $IdentityType -ne "pisqldas")
    { 
        $global:blnCustomAccount = $true

		# $global:CSAppPoolIdentity = $UsernameValue
        
		#MSA or gMSA
        If ($CSUserGMSA.contains('$')) { 
			$global:blngMSA = $True 
			$global:ADAccType = 3
			$global:gMSA = "<p><good>$global:ProductName is run by Group Managed Service Account $UsernameValue.</good></p>"
		} 
		Else {  # Standard User 
			$global:blngMSA = $false 
            $global:gMSA = "<p><bad>$global:ProductName is by Domain User $UsernameValue. <a href=`"https://blogs.technet.microsoft.com/askpfeplat/2012/12/16/windows-server-2012-group-managed-service-accounts`" target=`"_blank`" >Use Group Managed Service Account instead.</a></bad></p>"
			$global:ADAccType = 1
		}

		$CSAppPoolPosition = $UsernameValue.IndexOf("\")
		$global:ServiceAccount = $UsernameValue.Substring($CSAppPoolPosition+1)
		$global:ServiceAccount = $global:ServiceAccount.TrimEnd('$')
		$global:ServiceAccount = $global:ServiceAccount.ToLower()
		
		$global:SvcAccountFriendlyName = $UsernameValue
    }

    Else
    {
			# Computer Account
            $global:blnCustomAccount = $false
            $global:blngMSA = $false
			$global:ADAccType = 2
            $global:gMSA = "<p><bad>$global:ProductName is run by Default Account $IdentityType. <a href=`"https://blogs.technet.microsoft.com/askpfeplat/2012/12/16/windows-server-2012-group-managed-service-accounts`" target=`"_blank`" >Use Group Managed Service Account instead.</a></bad></p>"
						
			# $global:CSAppPoolIdentity = $IdentityType
			$global:ServiceAccount = $IISserverName.ToLower()
			
			$global:SvcAccountFriendlyName = $global:ServiceAccount.ToUpper()
    }
}

Function Check-ServicePrincipalName
{
	param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("chh")]
		[boolean]
		$HostA,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("SPN1")]
		[string]
		$SPNstring1,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("SPN2")]
		[string]
		$SPNstring2,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]		
		[alias("TargetAccountName")]
		[string]
		$strSPNtargetAccount,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]		
		[alias("TargetDomain")]
		[string]
		$strSPNtargetDomain="",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	
	)	
		If ($strSPNtargetDomain -eq "" -or $strSPNtargetDomain -eq "." -or $strSPNtargetDomain -eq "MACHINEACCOUNT") {	$SPNCheck = $(setspn -l $strSPNtargetAccount).ToLower() | Out-String }
		Else { $SPNCheck = $(setspn -l $($strSPNtargetDomain + '\' + $strSPNtargetAccount)).ToLower() | Out-String }
		
        If ($HostA) {

			If ($SPNCheck -match $SPNstring1) { 
				$global:strSPNs = "<p><good>Service Principal Name $SPNstring1 exists and is assigned to $global:SvcAccountFriendlyName.</good></p>" 			
			}
			Else { 
				$global:strSPNs = "<p><bad>Kerberos authentication to $global:ProductName will fail.<br></bad>
				<details>
				<summary><a href=`"https://livelibrary.osisoft.com/LiveLibrary/content/en/vision-v1/GUID-68329569-D75C-406D-AE2D-9ED512E74D46`" target=`"_blank`" >Documentation</a> | Command to create the missing SPN:</summary><br>
				<code>
                setspn -s $SPNstring1 $strSPNtargetAccount<br>
                </code>
				</details></p>"

			}
		}

		Else {
			If ($SPNCheck -match $SPNstring1 -and $SPNCheck -match $SPNstring2) { 
				$global:strSPNs = "<p><good>Service Principal Names $SPNstring1 and $SPNstring2 exist and are assigned to $global:SvcAccountFriendlyName.</good></p>"   
			}
			Else { 
				$global:strSPNs = "<p><bad>Kerberos authentication to $global:ProductName will fail.<br></bad>
				<details>
				<summary><a href=`"https://livelibrary.osisoft.com/LiveLibrary/content/en/vision-v1/GUID-68329569-D75C-406D-AE2D-9ED512E74D46`" target=`"_blank`" >Documentation</a> | Commands to create the missing SPNs</summary><br>
				<code>
                setspn -s $SPNstring1 $strSPNtargetAccount<br>
                setspn -s $SPNstring2 $strSPNtargetAccount<br>
				</code>
				</details></p>"
			}
		}
		
}

Function Get-PIVisionProperties
{
<#
.SYNOPSIS
Query PI Vision (PI Coresight) machine for information about the application.
.DESCRIPTION
Query PI Vision (PI Coresight) machine for information about the application.  
This function reduces the number of PSSessions compared with calling separately to the core module.
#>
	param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean] $LocalComputer,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("rcn")]
		[string] $RemoteComputerName,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int] $DBGLevel = 0	
	)	
	
	$fn = GetFunctionName
    $global:PIVisionConfiguration = $null

$IISscriptBlock = {

    Import-Module WebAdministration

	$pisystemKey = "HKLM:\Software\PISystem\"
	if(Test-Path -Path $($pisystemKey + "PIVision"))
	{ $ProductName = 'PIVision' }
	elseif(Test-Path -Path $($pisystemKey + "Coresight"))
	{ $ProductName = 'Coresight' }
    else { Write-Warning "PI Vision/PI Coresight not found. Aborting." 
    exit 
    }

    $IISWebSite = Get-ItemProperty -Path $($pisystemKey + $ProductName) | Select-Object -ExpandProperty "WebSite"
	$InstallDir = Get-ItemProperty -Path $($pisystemKey + $ProductName) | Select-Object -ExpandProperty "InstallationDirectory"
    
	$WebServerName = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" -Name "ComputerName" | Select-Object -ExpandProperty "ComputerName"
	$WebServerDomain = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" -Name "Domain" | Select-Object -ExpandProperty "Domain"

    $PIVisionAppPoolUserType = Get-ItemProperty $('iis:\apppools\' + $ProductName + 'serviceapppool') -Name processmodel.identitytype

	if($PIVisionAppPoolUserType -eq 'SpecificUser'){
        $PIVisionAppPoolUser = Get-ItemProperty $('iis:\apppools\' + $ProductName + 'serviceapppool') -Name processmodel.username.value
	}
	else { 
		$PIVisionAppPoolUser = $PIVisionAppPoolUserType 
	}

	$WindowsAuthenticationEnabled = Get-WebConfigurationProperty -Filter /system.webServer/security/authentication/windowsAuthentication -Name Enabled -location $($IISWebSite.ToString() + '/' + $ProductName) | select -expand Value
	
	$AuthenticationProviders = Get-WebConfigurationProperty -Filter /system.webServer/security/authentication/windowsAuthentication/providers -Name * -location $($IISWebSite.ToString() + '/' + $ProductName)
    $strAuthenticationProviders = ""
	foreach($provider in $AuthenticationProviders.Collection){$strAuthenticationProviders+=$provider.Value + " and "}
    $strAuthenticationProviders = $strAuthenticationProviders.TrimEnd(" and ")

	$KernelModeEnabled = Get-WebConfigurationProperty -Filter /system.webServer/security/authentication/windowsAuthentication -Name useKernelMode -location $($IISWebSite.ToString() + '/' + $ProductName) | select -expand Value	
    $KernelLocation = $($IISWebSite.ToString() + '/' + $ProductName).ToString()
    
    $UseAppPoolCredentials = Get-WebConfigurationProperty -Filter /system.webServer/security/authentication/windowsAuthentication -Name useAppPoolCredentials -location $($IISWebSite.ToString() + '/' + $ProductName) | select -expand Value	
	$SiteBindings = Get-WebBinding -Name $IISWebSite
    $ClaimsAuth = Get-WebConfigurationProperty -Filter "/appSettings/add[@key='owin:AutomaticAppStartup']" -name * -location $($IISWebSite.ToString() + '/' + $ProductName) | select -expand Value


	$IISConfiguration = New-Object PSCustomObject
	$IISConfiguration | Add-Member -MemberType NoteProperty -Name "MachineName" -Value $WebServerName
	$IISConfiguration | Add-Member -MemberType NoteProperty -Name "MachineDomain" -Value $WebServerDomain
	$IISConfiguration | Add-Member -MemberType NoteProperty -Name "AppPoolUserType" -Value $PIVisionAppPoolUserType
	$IISConfiguration | Add-Member -MemberType NoteProperty -Name "AppPoolUser" -Value $PIVisionAppPoolUser
	$IISConfiguration | Add-Member -MemberType NoteProperty -Name "WindowsAuthenticationEnabled" -Value $WindowsAuthenticationEnabled	
	$IISConfiguration | Add-Member -MemberType NoteProperty -Name "AuthenticationProviders" -Value $strAuthenticationProviders
	$IISConfiguration | Add-Member -MemberType NoteProperty -Name "KernelModeEnabled" -Value $KernelModeEnabled		
    $IISConfiguration | Add-Member -MemberType NoteProperty -Name "KernelLocation" -Value $KernelLocation			
	$IISConfiguration | Add-Member -MemberType NoteProperty -Name "UseAppPoolCredentials" -Value $UseAppPoolCredentials
	$IISConfiguration | Add-Member -MemberType NoteProperty -Name "SiteBindings" -Value $SiteBindings
	$IISConfiguration | Add-Member -MemberType NoteProperty -Name "ClaimsAuth" -Value $ClaimsAuth

	return $IISConfiguration
}

		if($LocalComputer)
		{ $global:PIVisionConfiguration = & $IISscriptBlock }
		else
		{ $global:PIVisionConfiguration = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $IISscriptBlock }

}

Function Get-PIWebAPIProperties
{
<#
.SYNOPSIS
Query PI WebAPI machine for information about the application.
.DESCRIPTION
Query  PI WebAPI machine for information about the application.  
This function reduces the number of PSSessions compared with calling separately to the core module.
#>
	param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean] $LocalComputer,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("rcn")]
		[string] $RemoteComputerName,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int] $DBGLevel = 0	
	)	
	
	$fn = GetFunctionName
    $global:PIWebAPIProperties = $null

$WebAPIscriptBlock = {

    If (!(Test-Path ($env:PIHOME64 + "WebAPI\InstallationConfig.json"))) { 
    Write-Warning "PI WebAPI not found. Aborting."
    exit
    }

	$WebServerName = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" -Name "ComputerName" | Select-Object -ExpandProperty "ComputerName"
	$WebServerDomain = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" -Name "Domain" | Select-Object -ExpandProperty "Domain"
    
    $pisystemKey = "HKLM:\Software\PISystem\"
    $PIWebApiDirectory = Get-ItemProperty -Path $($pisystemKey + "WebAPI") -Name "InstallationDirectory" | Select-Object -ExpandProperty "InstallationDirectory"
    $InstallationConfig = Get-Content -Path $(Join-Path $PIWebApiDirectory "InstallationConfig.json")
    $CrawlerSubmitUrl = $InstallationConfig | Select-String -Pattern 'CrawlerSubmitUrl\": \"(.*)\"'
    $ApiServiceAccountUsername = $InstallationConfig | Select-String -Pattern 'ApiServiceAccountUsername\": \"(.*)\"'

	$WebAPIConfiguration = New-Object PSCustomObject
	$WebAPIConfiguration | Add-Member -MemberType NoteProperty -Name "MachineName" -Value $WebServerName
	$WebAPIConfiguration | Add-Member -MemberType NoteProperty -Name "MachineDomain" -Value $WebServerDomain
    $WebAPIConfiguration | Add-Member -MemberType NoteProperty -Name "CrawlerSubmitUrl" -Value $CrawlerSubmitUrl
	$WebAPIConfiguration | Add-Member -MemberType NoteProperty -Name "ApiServiceAccountUsername" -Value $ApiServiceAccountUsername

	return $WebAPIConfiguration
}

		if($LocalComputer)
		{ $global:PIWebAPIProperties = & $WebAPIscriptBlock }
		else
		{ $global:PIWebAPIProperties = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $WebAPIscriptBlock }

}

Function Get-PISQLDASProperties
{
<#
.SYNOPSIS
Query PI SQL DAS for OLEDB machine for information about the application.
.DESCRIPTION
Query PI SQL DAS for OLEDB machine for information about the application.  
This function reduces the number of PSSessions compared with calling separately to the core module.
#>
	param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean] $LocalComputer,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("rcn")]
		[string] $RemoteComputerName,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int] $DBGLevel = 0	
	)	
	
	$fn = GetFunctionName
    $global:SQLDASProperties = $null

$SQLDASscriptBlock = {

	$WebServerName = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" -Name "ComputerName" | Select-Object -ExpandProperty "ComputerName"
	$WebServerDomain = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" -Name "Domain" | Select-Object -ExpandProperty "Domain"
    
    If (!(Test-Path ($env:PIHOME64 + "SQLDAS\OLE DB\PISqlDas.exe.config"))) { 
    Write-Warning "PI SQL DAS for OLEDB not found. Aborting."
    exit
    }

    # SQL DAS will automatically register SPNs in the future. 
    # It will also use different SPN class based on product (SQL DAS for OLEDB, for Integrator ..) and based on binding (HTTPS vs NET.TCP).
    # For now, let's grab the binding information from SQL DAS for OLEDB config file for future use (future SQLDAS will use ports in SPNs, among other things).
    # Assume HTTP SPN class for the time being.

    #$SQLDASconfig.Load($env:PIHOME64 + "\SQLDAS\OLE DB\PISqlDas.exe.config")
    #$SQLDASnetTCP = $SQLDASconfig.SelectSingleNode("//configuration/system.serviceModel/services/service/host/baseAddresses/add[starts-with(@baseAddress, 'net.tcp')]")
    #$SQLDAShttps = $SQLDASconfig.SelectSingleNode("//configuration/system.serviceModel/services/service/host/baseAddresses/add[starts-with(@baseAddress, 'https')]")

	$SQLDASConfiguration = New-Object PSCustomObject
	$SQLDASConfiguration | Add-Member -MemberType NoteProperty -Name "MachineName" -Value $WebServerName
	$SQLDASConfiguration | Add-Member -MemberType NoteProperty -Name "MachineDomain" -Value $WebServerDomain
    #$SQLDASConfiguration | Add-Member -MemberType NoteProperty -Name "SQLDAShttps" -Value $SQLDAShttps.baseAddress
    #$SQLDASConfiguration | Add-Member -MemberType NoteProperty -Name "SQLDASnettcp" -Value $SQLDASnetTCP.baseAddress

	return $SQLDASConfiguration
}

		if($LocalComputer)
		{ $global:PISQLDASProperties = & $SQLDASscriptBlock }
		else
		{ $global:PISQLDASProperties = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $SQLDASscriptBlock }

}


Function Initialize-KerberosConfigurationTest
{
<#
.SYNOPSIS
Break down user input.
.DESCRIPTION
Break down user input.
#>
	param(
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("cn")]
		[string] $ComputerName,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("lc")]
		[boolean] $LocalComputer,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("app")]
		[ValidateSet('pivision','piwebapi', 'pisqldas', 'Menu')]
		[string] $Product,
		[parameter(Mandatory=$true, ParameterSetName = "Default")]
		[alias("kc")]
		[ValidateSet('None','Classic','ResourceBased','Menu')]
		[string] $KerberosCheck,
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0	
	)	

	# Initialize Globals if not set
	if($null -eq (Get-Variable "PISystemAuditLogFile" -Scope "Global" -ErrorAction "SilentlyContinue").Value -or $null -eq (Get-Variable "ExportPath" -Scope "Global" -ErrorAction "SilentlyContinue").Value){ SetFolders }
	if($null -eq (Get-Variable "PISysAuditShowUI" -Scope "Global" -ErrorAction "SilentlyContinue").Value){New-Variable -Name "PISysAuditShowUI" -Scope "Global" -Visibility "Public" -Value $true}

	$global:strClassicDelegation = $null
	$global:RBCDstring = $null
	$global:strBackEndSPNS = $null
	$global:strSPNS = $null

	# Test non-local computer to validate if WSMan is working.
	if($LocalComputer)
	{							
		$msgTemplate = "The server: {0} does not need WinRM communication because it will use a local connection"
		$msg = [string]::Format($msgTemplate, $ComputerName)
		Write-PISysAudit_LogMessage $msg "Debug" $fn -dbgl $DBGLevel -rdbgl 1					
	}
	else
	{								
		try
		{
			$resultWinRMTest = $null
			$resultWinRMTest = Test-WSMan -authentication default -ComputerName $ComputerName
			if($null -eq $resultWinRMTest)
			{
				$msgTemplate = @"
	`n
	The server: {0} has a problem with WinRM communication. 
	This issue will occur if there is an HTTP/hostname or HTTP/fqdn SPN assigned to a 
	custom account.  In this situation the scripts may need to be run locally.  
	For more information, see - https://github.com/osisoft/PI-Security-Audit-Tools/wiki/Tutorial2:-Running-the-scripts-remotely-(USERS).

	Exiting...
"@
				$msg = [string]::Format($msgTemplate, $ComputerName)
				Write-PISysAudit_LogMessage $msg "Error" $fn
				$result = 999
				break
			}
		}
		catch
		{
			$msg = "A problem has occurred during the validation with WSMan.  Exiting..."						
			Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
			$result = 999
			break
		}						
	}

	# Resolve Product selection
	if($Product -eq 'Menu')
	{
		$title = "Product"
		$message = "Select PI product to check."

		$AppPIVision = New-Object System.Management.Automation.Host.ChoiceDescription "&PI Vision"
		$AppPIVWebAPI = New-Object System.Management.Automation.Host.ChoiceDescription "&PI WebAPI"
        $AppSQLDAS = New-Object System.Management.Automation.Host.ChoiceDescription "&PI SQL DAS"

		$options = [System.Management.Automation.Host.ChoiceDescription[]]($AppPIVision,$AppPIVWebAPI, $AppSQLDAS)

		$ProductResult = $host.ui.PromptForChoice($title, $message, $options, 0) 
	}
	else
	{
		# Assign compatible result from friendly name
		switch($Product)
		{
			'pivision' {$ProductResult = 0}
			'piwebapi' {$ProductResult = 1}
            'pisqldas' {$ProductResult = 2}
		}
	}

	# Resolve KerberosCheck selection
	if($KerberosCheck -eq 'Menu')
	{
		$title = "Kerberos Delegation"
		$message = "Would you like to check Kerberos Delegation configuration? This requires installation of RSAT-AD-PowerShell module."

		$NoKerberos = New-Object System.Management.Automation.Host.ChoiceDescription "&Do not check Kerberos delegation configuration"
		$ClassicKerberos = New-Object System.Management.Automation.Host.ChoiceDescription "&Check Classic Kerberos delegation configuration"
		$RBKerberos = New-Object System.Management.Automation.Host.ChoiceDescription "&Check Resource-Based Kerberos delegation configuration"

		$options = [System.Management.Automation.Host.ChoiceDescription[]]($NoKerberos,$ClassicKerberos,$RBKerberos)

		$KerberosResult = $host.ui.PromptForChoice($title, $message, $options, 0) 
	}
	else
	{
		# Assign compatible result from friendly name
		switch($KerberosCheck)
		{
			'None' {$KerberosResult = 0}
			'Classic' {$KerberosResult = 1}
			'ResourceBased' {$KerberosResult = 2}
		}
	}

    $result = $ProductResult.ToString() + $KerberosResult.ToString()

# Test for WebAdministration module only if PI Vision is selected.
If ( $result -in "00", "01", "02"  ) {
    
	if(Test-WebAdministrationModuleAvailable -lc $LocalComputer -rcn $ComputerName -dbgl $DBGLevel)
	{
		$msg = 'WebAdministration module loaded successfully.'
		Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2
	}
	else
	{
		$msgTemplate=@"
	`n    
	Unable to load the WebAdministration module on {0}.  Exiting... 
	Ensure the Web-Scripting-Tools feature is installed on the target server and 
	you have sufficient privilege to load the module
"@
		$msg = [string]::Format($msgTemplate, $ComputerName)
		Write-PISysAudit_LogMessage $msg "Error" $fn
		$result = 998
		break
	}
}
    return $result
    
}

# ........................................................................
# Exported Functions
# ........................................................................
Function Test-KerberosConfiguration {
<#  
.SYNOPSIS
Designed to check PI Vision, PI WebAPI, or PI SQL DAS for OLEDB configuration to ensure Kerberos authentication and delegation
are configured correctly.  

.DESCRIPTION
Dubbed 'PI Dog' after Kerberos, the three-headed guardian of Hades. This utility is designed to
examine the configuration of a PI Vision web application, PI WebAPI application, or PI SQL DAS for OLEDB service related to Kerberos delegation and 
provide actionable information if any issues or deviation from best practices are detected.
	
PI Dog has best support when run locally due to complications with WS-Man, SPN resolution or 
cross domain complications.  If there is an HTTP/hostname or HTTP/fqdn SPN for the web server
assigned to a custom account, the scripts may need to be run locally.  For more information, 
see - https://github.com/osisoft/PI-Security-Audit-Tools/wiki/Tutorial2:-Running-the-scripts-remotely-(USERS).

The syntax is...				 
Test-KerberosConfiguration [[-ComputerName | -cn] <string> [-Product | -app] <string> [-KerberosCheck | -kc] <string>]

Import the PISYSAUDIT module to make this function available.

.PARAMETER cn
The computer hosting the target application.
.PARAMETER kc
The type of kerberos delegation configuration check to perform.  Supported values
are None, Classic, ResourceBased and Menu (select interactively).
.PARAMETER app
The product you'd like to check configuration for. Supported values
are piwebapi, pivision, pisqldas, and Menu (select interactively).
.EXAMPLE
Test-KerberosConfiguration -ComputerName piomnibox -Product pivision -KerberosCheck ResourceBased
Test-KerberosConfiguration -Product piwebapi -KerberosCheck None
Unleash-PI_Dog -app pisqldas -cn hal9000 -kc Classic
.LINK
https://pisquare.osisoft.com
#>
[CmdletBinding(DefaultParameterSetName="Default", SupportsShouldProcess=$false)]
param(
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("cn")]
		[string] $ComputerName = "",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("app")]
		[ValidateSet('pivision','piwebapi','pisqldas','Menu')]
		[string] $Product = "Menu",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("kc")]
		[ValidateSet('None','Classic','ResourceBased','Menu')]
		[string] $KerberosCheck = "Menu",
		[parameter(Mandatory=$false, ParameterSetName = "Default")]
		[alias("dbgl")]
		[int]
		$DBGLevel = 0		
	)	

	# Initialize local variables
	$fn = GetFunctionName
	$FEKerberosDelegation = $null
	
	# Obtain the machine name from the environment variable.
	$localComputerName = get-content env:computername
	$localComputerDomain = Get-PISysAudit_RegistryKeyValue "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" "Domain" -lc $true -rcn $ComputerName -dbgl $DBGLevel
	
	# Validate if the server name refers to the local one	
	if(($ComputerName -eq "") -or ($ComputerName.ToLower() -eq "localhost"))
	{												
		$ComputerName = $localComputerName.ToLower()
		$LocalComputer = $true
	}
	elseif($localComputerName.ToLower() -eq $ComputerName.ToLower() -or ($localComputerName.ToLower() + "." + $localComputerDomain.ToLower()) -eq $ComputerName.ToLower())
	{									
		$ComputerName = $localComputerName.ToLower()
		$LocalComputer = $true
	}
	else
	{			
		$LocalComputer = $false			
		$ComputerName = $ComputerName.ToLower()
	}
	$RemoteComputerName = $ComputerName

	$result = Initialize-KerberosConfigurationTest -cn $ComputerName -lc $LocalComputer -app $Product -kc $KerberosCheck
	
	# If initialization fails with code 999 (WSMan) we can verify that the issue isn't due to an alias 
	if($result -eq 999)
	{
		$resolvedName = Get-PISysAudit_ResolveDnsName -LookupName $ComputerName -Attribute HostName -DBGLevel $DBGLevel
		if($resolvedName.ToLower() -eq $localComputerName.ToLower())
		{ 
			$LocalComputer = $true
			$msg = "The server: {0} does not need WinRM communication because it will use a local connection (alias used)" -f $ComputerName
			$result = Initialize-KerberosConfigurationTest -cn $ComputerName -lc $LocalComputer -kc $KerberosCheck
			Write-Host $msg
		}
		else
		{
			$msg = "The server: {0} has a problem with WinRM communication, please see https://github.com/osisoft/PI-Security-Audit-Tools/wiki/Running-the-scripts-remotely for more information on running this tool remotely." -f $ComputerName
			Write-Warning $msg
		}
		
	}

# Break down user selection into usable bits.
switch ($result)
    {
        "00" {"PI Vision + No Kerberos"
            $AppToCheck = "pivision"
			$blnDelegationCheckConfirmed = $false
			$rbcd = $false
			$RSATcheck = $false
        }


        "01" {"PI Vision + Kerberos"
            $AppToCheck = "pivision"
			$RSATcheck = $(Get-WindowsFeature -Name RSAT-AD-PowerShell | Select-Object –ExpandProperty 'InstallState') -ne 'Installed'
			$blnDelegationCheckConfirmed = $true
			$rbcd = $false
        }


        "02" {"PI Vision + RBCD"
			$AppToCheck = "pivision"
            $RSATcheck = $(Get-WindowsFeature -Name RSAT-AD-PowerShell | Select-Object –ExpandProperty 'InstallState') -ne 'Installed'
			$blnDelegationCheckConfirmed = $true
			$rbcd = $true
        }

        "10" {"PI WebAPI + No Kerberos"
            $AppToCheck = "piwebapi"
			$blnDelegationCheckConfirmed = $false
			$rbcd = $false
			$RSATcheck = $false
        }


        "11" {"PI WebAPI + Kerberos"
            $AppToCheck = "piwebapi"
			$RSATcheck = $(Get-WindowsFeature -Name RSAT-AD-PowerShell | Select-Object –ExpandProperty 'InstallState') -ne 'Installed'
			$blnDelegationCheckConfirmed = $true
			$rbcd = $false
        }


        "12" {"PI WebAPI + RBCD"
            $AppToCheck = "piwebapi"
			$RSATcheck = $(Get-WindowsFeature -Name RSAT-AD-PowerShell | Select-Object –ExpandProperty 'InstallState') -ne 'Installed'
			$blnDelegationCheckConfirmed = $true
			$rbcd = $true
        }

        "20" {"PI SQL DAS + No Kerberos"
            $AppToCheck = "pisqldas"
			$blnDelegationCheckConfirmed = $false
			$rbcd = $false
			$RSATcheck = $false
        }


        "21" {"PI SQL DAS + Kerberos"
            $AppToCheck = "pisqldas"
			$RSATcheck = $(Get-WindowsFeature -Name RSAT-AD-PowerShell | Select-Object –ExpandProperty 'InstallState') -ne 'Installed'
			$blnDelegationCheckConfirmed = $true
			$rbcd = $false
        }


        "22" {"PI SQL DAS + RBCD"
            $AppToCheck = "pisqldas"
			$RSATcheck = $(Get-WindowsFeature -Name RSAT-AD-PowerShell | Select-Object –ExpandProperty 'InstallState') -ne 'Installed'
			$blnDelegationCheckConfirmed = $true
			$rbcd = $true
        }

 		# Initialization failed
		998 {
			Write-Warning "Initialization failed due to an issue loading the IIS module."
			break
        }

		# Initialization failed
		999 {
			Write-Warning "Initialization failed due to an issue verifying WSMan."
			break
        }
    }

# If needed, give user option to install 'Remote Active Directory Administration' PS Module.
If ($RSATcheck) {
	$localOS = (Get-CimInstance Win32_OperatingSystem).Caption
	If($localOS -like "*Windows 10*" -or $localOS -like "*Windows 8*" -or $localOS -like "*Windows 7*"){
		$messageRSAT = @"
		'Remote Active Directory Administration' Module is not installed.  This module is required on the 
		machine running Test-KerberosConfiguration.  A client operating system was detected, so 
		ServerManager is not available; the tool must be downloaded and installed.  
		For more information, see - https://support.microsoft.com/en-us/kb/2693643

		'Remote Active Directory Administration' is required to check Kerberos Delegation settings. Aborting.
"@
		Write-Warning $messageRSAT
		break
	}
	Else
	{
		$titleRSAT = "RSAT-AD-PowerShell required"
		$messageRSAT = @"
	'Remote Active Directory Administration' Module is required on the machine running Test-KerberosConfiguration.
	Installing this module does not require a reboot.  If it is desired to uninstall the module afterward, a reboot will be
	required to complete the removal.
"@
		$yesRSAT = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes, install the module."
		$noRSAT = New-Object System.Management.Automation.Host.ChoiceDescription "&No, don't install the module and abort."
		$optionsRSAT = [System.Management.Automation.Host.ChoiceDescription[]]($yesRSAT,$noRSAT)

		$resultRSAT = $host.ui.PromptForChoice($titleRSAT, $messageRSAT, $optionsRSAT, 0) 

		If ($resultRSAT -eq 0) {
			Write-Output "Installation of 'Remote Active Directory Administration' module is about to start.."
			Add-WindowsFeature RSAT-AD-PowerShell
		}
		Else { Write-Warning "'Remote Active Directory Administration' is required to check Kerberos Delegation settings. Aborting." 
			break
		}
	}
}	

#### PI Vision specific Section
If ($AppToCheck -eq "pivision") {	
	$global:ProductName = "PI Vision"

    # Get PI Vision (Coresight) properties
	Get-PIVisionProperties -lc $LocalComputer -rcn $RemoteComputerName -DBGLevel $DBGLevel

    # Claims Auth
    $blnClaimsAuth = $global:PIVisionConfiguration.ClaimsAuth

    # PI Vision (Coresight) AppPool User Account type
	$CSAppPoolSvcType = $global:PIVisionConfiguration.AppPoolUserType

    # PI Vision (Coresight) AppPool User Account name
	$PIVisionUserSvc = $global:PIVisionConfiguration.AppPoolUser
    
    # Windows Authentication
    $blnWindowsAuth = $global:PIVisionConfiguration.WindowsAuthenticationEnabled

    # Windows Authentication Providers
    $strProviders = $global:PIVisionConfiguration.AuthenticationProviders
    
    # Kernel-mode Authentication
    $blnKernelMode = $global:PIVisionConfiguration.KernelModeEnabled

    # UseAppPoolCredentials (ensures proper Kerberos ticket decryption)
    $blnUseAppPoolCredentials = $global:PIVisionConfiguration.UseAppPoolCredentials
	
    # Web Bindings
    $VisionWebBindings = $global:PIVisionConfiguration.SiteBindings

    # Get hostname and FQDN for later use
    $global:WebServerName = $global:PIVisionConfiguration.MachineName
    $global:WebServerDomain = $global:PIVisionConfiguration.MachineDomain
    $global:WebServerFQDN = $WebServerName + "." + $WebServerDomain 

	# GET APPPOOL IDENTITY
	Get-AppNetworkIdentityName -IDType $CSAppPoolSvcType -UserString $PIVisionUserSvc -ServerName $WebServerName

    # KERNEL-MODE AUTHENTICATION CHECK
	Check-KernelModeAuth -CustomAppPool $global:blnCustomAccount -UseAppPoolCreds $blnUseAppPoolCredentials -UseKernelModeAuth $blnKernelMode -DBGLevel $DBGLevel      
	

	# CHECK BINDINGS AND CUSTOM HOST HEADER
	$blnCustomHeader = $false
	$HostA = $False 
    
    # Convert Web Bindings collection to string
	$BindingsToString = $($VisionWebBindings) | Out-String
	
    # Look for Custom Host Header. If multiple headers exist, get the first one.
    $matches = [regex]::Matches($BindingsToString, ':{1}\d+:{1}(\S+)\s') 
				foreach ($match in $matches) { 
						$CSheader = $match.Groups[1].Captures[0].Value 
							If ($CSheader) { 
								$blnCustomHeader = $true
								$CScustomHeader = $CSheader
							break 
							}
						}
	
	$ProductUserSvcObject = Get-PISysAudit_ParseDomainAndUserFromString -UserString $PIVisionUserSvc -DBGLevel $DBGLevel


#### PI WebAPI specific Section
}
ElseIf ($AppToCheck -eq "piwebapi") { 

        $global:ProductName = "PI WebAPI"

        Get-PIWebAPIProperties -lc $LocalComputer -rcn $RemoteComputerName -DBGLevel $DBGLevel

        # CHECK CUSTOM HOST HEADER
	    $blnCustomHeader = $false
	    $HostA = $False 
        # Get hostname and FQDN for later use
        $global:WebServerName =  $global:PIWebAPIProperties.MachineName
        $global:WebServerDomain =  $global:PIWebAPIProperties.MachineDomain
        $global:WebServerFQDN = $WebServerName + "." + $WebServerDomain 

        # Get WebAPI URL
        $WebAPIURL =  ($global:PIWebAPIProperties.CrawlerSubmitUrl -split '/*/')[1]
        
        # Check if WebAPI URL matches the Web Server name
        If ($WebAPIURL -ne $global:WebServerName -and $WebAPIURL -ne $global:WebServerFQDN -and $WebAPIURL -ne "localhost") { 
        $blnCustomHeader = $True 
        $CScustomHeader = $WebAPIURL
        }
     
        $WebAPIServiceAccountName = Get-PISysAudit_ServiceProperty -sn 'piwebapi' -sp LogOnAccount -lc $LocalComputer -rcn $RemoteComputerName -ErrorAction SilentlyContinue
        
        $ProductUserSvcObject = Get-PISysAudit_ParseDomainAndUserFromString -UserString $WebAPIServiceAccountName -DBGLevel $DBGLevel
        
        If ( $ProductUserSvcObject.domain -eq "MACHINEACCOUNT" ) { $global:ServiceAccount = $global:WebServerName }
        Else { $global:ServiceAccount = $ProductUserSvcObject.UserName }


        Get-AppNetworkIdentityName -IDType $ProductUserSvcObject.UserName -UserString $WebAPIServiceAccountName -ServerName $global:WebServerName


}
#### PI SQL DAS specific Section
ElseIf ($AppToCheck -eq "pisqldas") { 
        
        $global:ProductName = "PI SQL DAS for OLEDB"

        Get-PISQLDASProperties -lc $LocalComputer -rcn $RemoteComputerName -DBGLevel $DBGLevel

        # CHECK CUSTOM HOST HEADER - assuming computer/FQDN is used with PI SQL DAS.
	    $blnCustomHeader = $false
	    $HostA = $False 

        # Get hostname and FQDN for later use
        $global:WebServerName =  $global:PISQLDASProperties.MachineName
        $global:WebServerDomain =  $global:PISQLDASProperties.MachineDomain
        $global:WebServerFQDN = $WebServerName + "." + $WebServerDomain 

        $SQLDASServiceAccountName = Get-PISysAudit_ServiceProperty -sn 'pisqldas' -sp LogOnAccount -lc $LocalComputer -rcn $RemoteComputerName -ErrorAction SilentlyContinue

        $ProductUserSvcObject = Get-PISysAudit_ParseDomainAndUserFromString -UserString $SQLDASServiceAccountName -DBGLevel $DBGLevel
        
        If ( $ProductUserSvcObject.domain -eq "MACHINEACCOUNT" ) { $global:ServiceAccount = $global:WebServerName }
        Else { $global:ServiceAccount = $ProductUserSvcObject.UserName }


        Get-AppNetworkIdentityName -IDType $ProductUserSvcObject.UserName -UserString $SQLDASServiceAccountName -ServerName $global:WebServerName
        

}

### Commencing general section common for all apps.
###

        # Check Custom Host Header type - CNAME vs HOST (A)	- currently relevant only for Vision and WebAPI
	    If ($blnCustomHeader -eq $True) {								
	        $AliasTypeCheck = Resolve-DnsName $CScustomHeader | Select -ExpandProperty Type
		        If ($AliasTypeCheck -match "CNAME") { 
			        $HostA = $False 
			        }
		        Else {
			        $HostA = $True
		        }

                # HOST (A) DNS record is preferred	
	            If ($HostA -ne $true) {
	            $global:CustomHostHeader = "<p><bad>Custom Host Header $($CScustomHeader) is used (CNAME DNS Alias)).
		        Using CNAME DNS Alias can potentially cause issues with Kerberos Authentication.</bad>
		        <details>
		        <summary>Documentation Download links</summary>
		        <a href=`"http://aka.ms/kcdpaper`" target=`"_blank`" >Microsoft Understanding Kerberos Constrained Delegation Whitepaper</a><br>
		        <a href=`"https://benchmarks.cisecurity.org/tools2/iis/CIS_Microsoft_IIS_8_Benchmark_v1.0.0.pdf`" target=`"_blank`" >CIS Microsoft IIS 8 Benchmark</a>
		        </details></p>"
	            }
		        Else {
		        # All good
		        $global:CustomHostHeader = "<p><good>Custom Host Header $($CScustomHeader) is used (type: $($CScustomHeaderType)).</good></p>"

		        }
	    }
    
        # Custom Host Header is not used.
	    Else {
	        $global:CustomHostHeader = "<p><bad>Custom Host Header is not configured for $global:ProductName. Using Custom Host Header is recommended.</bad><br> 
		    <details>
		    <summary>Documentation Download links</summary>	    
		    <a href=`"http://aka.ms/kcdpaper`" target=`"_blank`" >Microsoft Understanding Kerberos Constrained Delegation Whitepaper</a><br>
		    <a href=`"https://benchmarks.cisecurity.org/tools2/iis/CIS_Microsoft_IIS_8_Benchmark_v1.0.0.pdf`" target=`"_blank`" >CIS Microsoft IIS 8 Benchmark</a><br>
		    </details></p>"
	    }

	# FRONT-END SERVICE PRINCIPAL NAMES CHECK	
	# Only need one SPN for HOST (A) DNS record
    If ($global:blnCustomAccount -eq $true -and $HostA -eq $true) {
	
    	$SPNone = ("http/" + $CScustomHeader).ToLower()
		$SPNtwo = $null
	}

	# Otherwise SPNs should be created for both hostname and FQDN
    ElseIf ($global:blnCustomAccount -eq $true -and $HostA -eq $false) {
		$SPNone = ("http/" + $global:WebServerName).ToLower()
		$SPNtwo = ("http/" + $global:WebServerFQDN).ToLower()
	}
	
    # Default config is used
    Else {
		$SPNone = ("host/" + $global:WebServerName).ToLower()
		$SPNtwo = ("host/" + $global:WebServerFQDN).ToLower()
	}

	# If Classic Kerberos Delegation is to be checked, SPNs can ge obtained in one AD call to improve performance. Othertwise, SETSPN tool is used.
	If ($blnDelegationCheckConfirmed -eq $false -or $rbcd -eq $true) {
    
	Check-ServicePrincipalName -chh $HostA -spn1 $SPNone -spn2 $SPNtwo -TargetAccountName $global:ServiceAccount -TargetDomain $ProductUserSvcObject.Domain
	}


	# KERBEROS DELEGATION CHECK CONFIRMED
	If ($blnDelegationCheckConfirmed) {
    
		$global:FirstPass = $false		   
	    # Get PI and AF Servers from the web server KST
	    $AFServers = Get-PISysAudit_KnownServers -lc $LocalComputer -rcn $RemoteComputerName -st AFServer 
	    $PIServers = Get-PISysAudit_KnownServers -lc $LocalComputer -rcn $RemoteComputerName -st PIServer
			
	    # RESOURCE BASED KERBEROS DELEGATION
	    If ($rbcd) {
        
        # Help variable
	    $ServiceAccountString = $global:ServiceAccount.ToString()      
        
            # Get SID of the middle-tier app to check in cross-domain RBCD config.

                # Standard User 
                If ($global:ADAccType -eq 1) { 
                $ServiceAccountSID = (Get-ADUser -Identity $ServiceAccountString -Properties SID).SID.Value
                }

                # Computer 
                ElseIf ($global:ADAccType -eq 2) { 
                $ServiceAccountSID = (Get-ADComputer -Identity $ServiceAccountString -Properties SID).SID.Value
                }

                # gMSA
                Else { 
                $ServiceAccountSID = (Get-ADServiceAccount -Identity $ServiceAccountString -Properties SID).SID.Value
                }

            # Check AF Servers (back-ends) for rbcd (PrincipalsAllowedToDelegateToAccount)					
            foreach ($AFServerTemp in $AFServers) { 
		        $AccType = 0
		        $AFServer = $AFServerTemp.Groups[1].Captures[0].Value
						
		        $msgTemplate = "Processing RBCD check for AF Server {0}"
		        $msg = [string]::Format($msgTemplate, $AFServer)
		        Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2

		        $AFSvcAccount = Get-PISysAudit_ServiceProperty -sn 'afservice' -sp LogOnAccount -lc $false -rcn $AFServer -ErrorAction SilentlyContinue
									
		        If ($AFSvcAccount -ne $null ) { 
		        $AFSvcAccountObject = Get-PISysAudit_ParseDomainAndUserFromString -UserString $AFSvcAccount -DBGLevel $DBGLevel
		        $AccType = Get-ServiceLogonAccountType -sa $AFSvcAccountObject.UserName -sad $AFSvcAccountObject.Domain -cn $AFServer -DBGLevel $DBGLevel
							
		            if($AccType -eq 0) {
		            Write-Output "Unable to locate type of ADObject $AFSvcAccount."
		            continue
		            }
							
		        Check-ResourceBasedConstrainedDelegationPrincipals -sa $AFSvcAccountObject.UserName -sad $AFSvcAccountObject.Domain -sat $AccType -api $global:ServiceAccount -sid $ServiceAccountSID -cn $AFServer -rt "AF Server" -DBGLevel $DBGLevel
		    
                }
							
		        Else { 
		        $global:RBCDstring += "Could not get the service account running AF Server $AFServer. Enable PSRemoting to the machine to proceed.<br>
		        <a href=`"https://github.com/osisoft/PI-Security-Audit-Tools/wiki/Tutorial2:-Running-the-scripts-remotely-(USERS)`" >How to run the script remotely</a>"
		        }
				
				# BACK-END CHECK
				Get-BackEndSPNs -st "afserver" -sn "afservice" -pan $AFServer		
            }

            # Check PI Servers (back-ends) for rbcd (PrincipalsAllowedToDelegateToAccount)
            foreach ( $PIServer in $PIServers ) { 
		        $AccType = 0
		        $PISvcAccount = Get-PISysAudit_ServiceProperty -sn "pinetmgr" -sp LogOnAccount -lc $false -rcn $PIServer -ErrorAction SilentlyContinue
									
		        $msgTemplate = "Processing RBCD check for PI Server {0}"
		        $msg = [string]::Format($msgTemplate, $PIServer)
		        Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2

		        If ( $PISvcAccount -ne $null ) { 
		        $PISvcAccountObject = Get-PISysAudit_ParseDomainAndUserFromString -UserString $PISvcAccount -DBGLevel $DBGLevel
		        $AccType = Get-ServiceLogonAccountType -sa $PISvcAccountObject.UserName -sad $PISvcAccountObject.Domain -cn $PIServer -DBGLevel $DBGLevel
		
                    If($AccType -eq 0) {
		            Write-Output "Unable to locate type of ADObject $PISvcAccount."
		            continue
		            }
		
                Check-ResourceBasedConstrainedDelegationPrincipals -sa $PISvcAccountObject.UserName -sad $PISvcAccountObject.Domain -sat $AccType -api $global:ServiceAccount -sid $ServiceAccountSID -cn $PIServer -rt "PI Server" -DBGLevel $DBGLevel
		    
                }
		
                Else { 
		        $global:RBCDstring += "Could not get the service account running PI Server $PIServer. Enable PSRemoting to the machine to proceed.<br>
		        <a href=`"https://github.com/osisoft/PI-Security-Audit-Tools/wiki/Tutorial2:-Running-the-scripts-remotely-(USERS)`" >How to run the script remotely</a>"
		        }
				
				# BACK END CHECK
				Get-BackEndSPNs -st "piserver" -sn "pinetmgr" -pan $PIServer
		    }

		    # Helper variable for easy output
		    $FEKerberosDelegation = $global:RBCDstring
	    }
	
        # CLASSIC KERBEROS DELEGATION
	    Else {
    
        # Initializing variables needed to construct an SPN
	    $dot = '.'
	    $PISPNClass = "piserver/"
	    $AFSPNClass = "afserver/"

	        foreach ($PIServer in $PIServers) {
							
	            # Debug option
	            $msgTemplate = "Processing Classic Delegation check for PI Server {0}"
	            $msg = [string]::Format($msgTemplate, $PIServer)
	            Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2

					# PI Server is specified as FQDN
					If ($PIServer -match [regex]::Escape($dot)) { 
	                $fqdnPI = $PIServer.ToLower() 
	                $pos = $fqdnPI.IndexOf(".")
	                $shortPI = $fqdnPI.Substring(0, $pos)
	                }

	                # PI Server is specified as short host name
                    Else { 
	                $shortPI = $PIServer.ToLower() 
	                $fqdnPI = ($PIServer.ToLower() + "." + $WebServerDomain.ToLower()).ToString()
	                }
						
	                # Construct SPNs
	                $shortPISPN = ($PISPNClass + $shortPI).ToString()
	                $longPISPN = ($PISPNClass + $fqdnPI).ToString()

	                # Check if the SPN is on the list the PI Vision AppPool can delegate to
	                Check-ClassicDelegation -sspn $shortPISPN -lspn $longPISPN -csspn $SPNone -clspn $SPNtwo -dnsa $HostA -cap $global:ServiceAccount -crt "PI Data Server" -cse $PIServer -cat $global:ADAccType
					
					# BACK END CHECK
					Get-BackEndSPNs -st "piserver" -sn "pinetmgr" -pan $PIServer
	         }

					
	        foreach ($AFServerTemp in $AFServers) {
						$AFServer = $AFServerTemp.Groups[1].Captures[0].Value
						
						# Debug option
						$msgTemplate = "Processing Classic Delegation check for AF Server {0}"
						$msg = [string]::Format($msgTemplate, $AFServer)
						Write-PISysAudit_LogMessage $msg "debug" $fn -dbgl $DBGLevel -rdbgl 2

							If ($AFServer -match [regex]::Escape($dot)) { 
							# AF Server is specified as FQDN
							$fqdnAF = $AFServer.ToLower() 
							$pos = $fqdnAF.IndexOf(".")
							$shortAF = $fqdnAF.Substring(0, $pos)
							}
							# AF Server is specified as short host name
							Else { 
							$shortAF = $AFServer.ToLower() 
							$fqdnAF = ($AFServer.ToLower() + "." + $WebServerDomain.ToLower()).ToString()
							}
								
						# Construct SPNs
						$shortAFSPN = ($AFSPNClass + $shortAF).ToString()
						$longAFSPN = ($AFSPNClass + $fqdnAF).ToString()

						# Check if the SPN is on the list the PI Vision AppPool can delegate to
						Check-ClassicDelegation -sspn $shortAFSPN -lspn $longAFSPN -csspn $SPNone -clspn $SPNtwo -dnsa $HostA -cap $global:ServiceAccount -crt "AF Server" -cse $AFServer -cat $global:ADAccType
						
						# BACK-END CHECK
						Get-BackEndSPNs -st "afserver" -sn "afservice" -pan $AFServer		
            }
								
        $FEKerberosDelegation = $global:strClassicDelegation
	    }
	}

#############################################
### HTML ###################################
############################################

# Define export path for the HTLML report
$exportPath = (Get-Variable "ExportPath" -Scope "Global" -ErrorAction "SilentlyContinue").Value
$HTMLFile = $exportPath + "\KerberosConfig.html"

# Compose Authentication section 

# Windows Auth available
If($blnWindowsAuth)
{
	$strIISAuthenticationSection="<p><good>Windows Authentication is enabled with $strProviders provider(s). Kerberos Authentication is possible.</good></p>"
}

# ClaimsAuth!
ElseIf ($blnClaimsAuth -eq $true) { 
    $strIISAuthenticationSection="<p><good>Claims Authentication is enabled.</good></p>"
    $global:Kernel = "<p><good>Windows Authentication not checked as it's superseded by Claims Authentication.</good></p>"
}

# Windows/Claims Auth is N/A
Else {
    $strIISAuthenticationSection="<p><bad>Windows Authentication is not enabled.</bad></p>"
}

# Compose Kerberos/SPN section 
If($blnDelegationCheckConfirmed)
{
    $secondArticle = "Kerberos Authentication and Delegation settings"
	$strKerberosDelegationsSection=@"
		<tr>
        <td><b>$global:ProductName - Authentication</b></td>
        <td>$($global:strSPNs)</td>
        </tr>
        <tr>
        <td><b>PI and AF Servers - SPNs</b></td>
        <td>$($global:strBackEndSPNS)</td>
        </tr>
        <tr>
        <td><b>Kerberos Delegation from $global:ProductName to PI and AF Servers</b></td>
        <td>$($FEKerberosDelegation)</td>
        </tr>
"@
}
Else
{
    $secondArticle = "Service Principal Names"
	$strKerberosDelegationsSection=@"
		<tr>
        <td><b>$global:ProductName</b></td>
        <td>$($global:strSPNs)</td>
        </tr>
"@
}

# Create HTML report 
            $dogTime = Get-Date -Format F
			$reportHTML = @"
			<html>
				<head><meta name="viewport" content="width=device-width" />
					<style type="text/css">
						article {
							box-shadow: 5px 5px 5px #aaa;
							padding: 1em 1em 1em 1em;
						}
						body {
							font-size: 1.5em;
							font-family: 'Segoe UI Light','Segoe UI','Lucida Grande',Verdana,Arial,Helvetica,sans-serif;
						}
						header {
							font-size: 2.0em;
							background-color: #0099ff;
							color: white;
                            width:100%;
						}
						header2 {
							font-size: 1.8em;
							padding: 2px 2px 2px 2px;
						}
						.summarytable {
							width: 100%;
							border-collapse: collapse;
						}

						.summarytable td, .summarytable th {
							border: 1px solid #ddd;
							font-size: 1.5em;
						}
						.summarytable th{
							background-color: #f2f2f2;
						}
						a {
							background: #white;
							color: #3C6478;
							transition: background .5s, color .5s;
						}

						a:hover {
							color: white;
							background: #3C6478;
						}
						good {
                                color: #26B317;
						}			
						bad {
                                color: #C02F1D;
						}				
				</style>
			
				</head>
"@
			
#PI Vision body	
If ($AppToCheck -eq "pivision") {
                    $body = @"
                    <body>
                    <header>PI Dog Report for server $WebServerFQDN on $dogtime</header>
                    <div style="margin-right: auto; margin-left: auto;width: 90%;">                    
                    <header2>IIS AppPool, Authentication, and Bindings</header2>
                    <article>
					<ul>
					<li>$strIISAuthenticationSection</li>
					<li>$global:Kernel</li>
					<li>$global:gMSA</li>
	                <li>$global:CustomHostHeader</li> 
					</ul>
					</article>
					<article>
    				<table class="summarytable table">
                    <thead><header2>$secondArticle</header2></thead>
					$strKerberosDelegationsSection
					</table>                    
					</article>
					</div>			
				</body>
                </html>
"@
}

# PI WebAPI body
ElseIf ($AppToCheck -eq "piwebapi") {
        $body = @"
                    <body>
                    <header>PI Dog Report for server $WebServerFQDN on $dogtime</header>
                    <div style="margin-right: auto; margin-left: auto;width: 90%;">                    
                    <header2>PI SQL DAS Configuration</header2>
                    <article>
					<ul>
					<li>$global:gMSA</li>
					</ul>
					</article>
					<article>
    				<table class="summarytable table">
                    <thead><header2>$secondArticle</header2></thead>
					$strKerberosDelegationsSection
					</table>                    
					</article>
					</div>			
				</body>
                </html>
                </html>
"@
}

# SQL DAS for OLEDB body
Else {
        $body = @"
                    <body>
                    <header>PI Dog Report for server $WebServerFQDN on $dogtime</header>
                    <div style="margin-right: auto; margin-left: auto;width: 90%;">                    
                    <header2>PI SQL DAS for OLEDB Configuration</header2>
                    <article>
					<ul>
					<li>$global:gMSA</li>
					</ul>
					</article>
					<article>
    				<table class="summarytable table">
                    <thead><header2>$secondArticle</header2></thead>
					$strKerberosDelegationsSection
					</table>                    
					</article>
					</div>			
				</body>
                </html>
                </html>
"@
}

$reportHTML = $reportHTML + $body
			
# Print report to file.
$reportHTML | Out-File $HTMLFile

# Open the resulting HTML report
Invoke-Expression $HTMLFile
}

Export-ModuleMember -Function Test-KerberosConfiguration
Set-Alias -Name Unleash-PI_Dog -Value Test-KerberosConfiguration -Description “Check Kerberos Authentication and Delegation configuration.”
Export-ModuleMember -Alias Unleash-PI_Dog