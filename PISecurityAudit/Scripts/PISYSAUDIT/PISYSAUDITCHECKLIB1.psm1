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
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "", Justification="Needed to avoid redundant calls to the target systems.")]
param()

# ........................................................................
# Internal Functions
# ........................................................................
function GetFunctionName
{ return (Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name }

# ........................................................................
# Public Functions
# ........................................................................
function Get-PISysAudit_FunctionsFromLibrary1 {
    <#
.SYNOPSIS
Get functions from machine library at or below the specified level.
#>
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess = $false)]
    param(
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("lvl")]
        [int]
        $AuditLevelInt = 1)

    # Form a list of all functions that need to be called to test
    # the machine compliance.
    $listOfFunctions = @()
    $listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckDomainMemberShip"   1 "AU10001"
    $listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckOSInstallationType" 1 "AU10002"
    $listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckFirewallEnabled"    1 "AU10003"
    $listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckAppLockerEnabled"   1 "AU10004"
    $listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckUACEnabled"         1 "AU10005"
    $listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckManagedPI"          1 "AU10006"
    $listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckIEEnhancedSecurity" 1 "AU10007"
    $listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckSoftwareUpdate"     1 "AU10008"
    $listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckInternetAccess"     1 "AU10009"
	$listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckDeviceGuard"        1 "AU10010"

    # Return all items at or below the specified AuditLevelInt
    return $listOfFunctions | Where-Object Level -LE $AuditLevelInt
}

function Get-PISysAudit_GlobalMachineConfiguration {
    <#
.SYNOPSIS
Gathers global data that can be used by all machine checks.
.DESCRIPTION
Some checks reuse information.  This command puts the configuration information
in a global object to reduce the number of remote calls, improving performance and
simplifying validation logic.

Information included in global configuration:
	PSVersion          - PowerShell version
	InstallationType   - Edition of Windows installed
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "MachineConfiguration", Justification="Global variable set that is used by the validation checks.")]
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess = $false)]
    param(
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("lc")]
        [boolean]
        $LocalComputer = $true,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("rcn")]
        [string]
        $RemoteComputerName = "",
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("dbgl")]
        [int]
        $DBGLevel = 0)
    BEGIN {}
    PROCESS {
        $fn = GetFunctionName

        # Reset global config object.
        $global:MachineConfiguration = $null

        $scriptBlock = {

            $PSVersion = $PSVersionTable.PSVersion.Major
            $InstallationType = Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion" -Name "InstallationType" | Select-Object -ExpandProperty "InstallationType" | Out-String
            $InstallationType = $InstallationType.Trim() # Remove any leading or trailing white space
            # Construct a custom object to store the config information
            $Configuration = New-Object PSCustomObject
            $Configuration | Add-Member -MemberType NoteProperty -Name PSVersion -Value $PSVersion
            $Configuration | Add-Member -MemberType NoteProperty -Name InstallationType -Value $InstallationType

            return $Configuration
        }
        try {
            if ($LocalComputer)
            { $global:MachineConfiguration = & $scriptBlock }
            else
            { $global:MachineConfiguration = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock }
        }
        catch {
            # Return the error message.
            $msg = "A problem occurred during the retrieval of the global machine configuration."
            Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
        }
    }
    END {}

}

function Get-PISysAudit_CheckDomainMemberShip {
    <#
.SYNOPSIS
AU10001 - Domain Membership
.DESCRIPTION
VALIDATION: Verifies that the machine is a member of an Active Directory
Domain.<br/>
COMPLIANCE: Join the machine to an Active Directory Domain. Use of a domain is
encouraged as AD provides Kerberos authentication and is our best available
technology for securing a PI System. Furthermore, the implementation of
transport security in the PI System relies on Windows Integrated Security and
AD to automatically enable higher strength ciphers.
#>
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess = $false)]
    param(
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "Default")]
        [alias("at")]
        [System.Collections.HashTable]
        $AuditTable,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("lc")]
        [boolean]
        $LocalComputer = $true,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("rcn")]
        [string]
        $RemoteComputerName = "",
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("dbgl")]
        [int]
        $DBGLevel = 0)
    BEGIN {}
    PROCESS {
        # Get and store the function Name.
        $fn = GetFunctionName
        $msg = ""
        try {
            # Read the registry key.
            $value = Get-PISysAudit_RegistryKeyValue "HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters" "Domain" `
                -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel

            # Compliance is to have computer belonging to a domain.
            # If the value is null or empty, it means it is not defined and the result of
            # the test is False (fail), otherwise it is true (pass).
            if (($null -eq $value) -or ($value -eq "")) {
                $result = $false
                $msg = "Machine is not a member of an AD Domain."
            }
            else {
                $result = $true
                $msg = "Machine is a member of an AD Domain."
            }
        }
        catch {
            # Return the error message.
            $msg = "A problem occurred during the processing of the validation check."
            Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
            $result = "N/A"
        }

        # Define the results in the audit table
        $AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
            -at $AuditTable "AU10001" `
            -ain "Domain Membership Check" -aiv $result `
            -aif $fn -msg $msg `
            -Group1 "Machine" -Group2 "Domain" `
            -Severity "High"
    }

    END {}

    #***************************
    #End of exported function
    #***************************
}

function Get-PISysAudit_CheckOSInstallationType {
    <#
.SYNOPSIS
AU10002 - Operating System Installation Type
.DESCRIPTION
VALIDATION: Verifies that the OS installation type is server core for the
reduced surface area.<br/>
COMPLIANCE: The operating system installation type should be Server Core. This
check is rated as a critical severity because as an application, PI can only be
as secure as the platform it runs on. Server core provides a dramatically
reduced software footprint compared to the standard server installation with
all graphic components. Fewer application running and fewer services
communicating over the network amount to a reduced attack surface area overall.
The critical severity rating is intended to reflect our stance that if an
administrator were to only implement one change, switching to server core would
have the greatest impact.
For more on the advantages of Windows Server Core, please see:<br/>
<a href="https://msdn.microsoft.com/en-us/library/hh846314(v=vs.85).aspx">https://msdn.microsoft.com/en-us/library/hh846314(v=vs.85).aspx </a>
#>
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess = $false)]
    param(
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "Default")]
        [alias("at")]
        [System.Collections.HashTable]
        $AuditTable,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("lc")]
        [boolean]
        $LocalComputer = $true,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("rcn")]
        [string]
        $RemoteComputerName = "",
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("dbgl")]
        [int]
        $DBGLevel = 0)
    BEGIN {}
    PROCESS {
        # Get and store the function Name.
        $fn = GetFunctionName
        $msg = ""
        try {
            $InstallationType = $global:MachineConfiguration.InstallationType
            if ($InstallationType -eq "Server Core") {
                $result = $true
                $msg = "Server Core installation detected."
            }
            else {
                $result = $false
                $msg = "Installation is not Server Core. The following installation type is used: " + $InstallationType + ". Leveraging a Core installation offers dramatically reduced attack surface over other installation types."
            }
        }
        catch {
            # Return the error message.
            $msg = "A problem occurred during the processing of the validation check."
            Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
            $result = "N/A"
        }

        # Define the results in the audit table
        $AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
            -at $AuditTable "AU10002" `
            -ain "Operating System Installation Type" -aiv $result `
            -aif $fn -msg $msg `
            -Group1 "Machine" -Group2 "Operating System" `
            -Severity "Critical"
    }

    END {}

    #***************************
    #End of exported function
    #***************************
}

function Get-PISysAudit_CheckFirewallEnabled {
    <#
.SYNOPSIS
AU10003 - Windows Firewall Enabled
.DESCRIPTION
VALIDATION: Verifies that the Windows host based firewall is enabled.<br/>
COMPLIANCE: Enable the Windows firewall for Domain, Private and Public Scope.
A firewall's effectiveness is heavily dependent on the configuration. For PI-
specific port requirements, please see:<br/>
<a href="https://techsupport.osisoft.com/Troubleshooting/KB/KB01162">https://techsupport.osisoft.com/Troubleshooting/KB/KB01162 </a> <br/>
For more general information on the Windows firewall, see "Windows Firewall
with Advanced Security Overview" on TechNet: <br/>
<a href="https://technet.microsoft.com/en-us/library/hh831365(v=ws.11).aspx">https://technet.microsoft.com/en-us/library/hh831365(v=ws.11).aspx </a>
#>
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess = $false)]
    param(
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "Default")]
        [alias("at")]
        [System.Collections.HashTable]
        $AuditTable,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("lc")]
        [boolean]
        $LocalComputer = $true,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("rcn")]
        [string]
        $RemoteComputerName = "",
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("dbgl")]
        [int]
        $DBGLevel = 0)
    BEGIN {}
    PROCESS {
        # Get and store the function Name.
        $fn = GetFunctionName
        $msg = ""
        try {

            $firewallState = Get-PISysAudit_FirewallState -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel

            $result = $false
            $validationCounter = 0
            $disabledProfiles = ""

            foreach ($profile in $firewallState) {
                # Explicitly check if [bool]$true because GPOboolean "False" will give misleading result in PS4
                If ($profile.Enabled -eq $true)
                { $validationCounter++ }
                Else
                { $disabledProfiles += " " + $profile.Name + ";" }
            }

            # Check if the counter is 3 = compliant, 2 or less it is not compliant
            if ($validationCounter -eq 3) {
                $result = $true
                $msg = "All Firewall profiles enabled."
            }
            else {
                $result = $false
                $msg = "The following Firewall profiles are not enabled:" + $disabledProfiles
                $msg = $msg.Trim(';')
            }
        }
        catch {
            # Return the error message.
            $msg = "A problem occurred during the processing of the validation check."
            Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
            $result = "N/A"
        }

        # Define the results in the audit table
        $AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
            -at $AuditTable "AU10003" `
            -ain "Firewall Enabled" -aiv $result `
            -aif $fn -msg $msg `
            -Group1 "Machine" -Group2 "Policy" `
            -Severity "Medium"
    }

    END {}

    #***************************
    #End of exported function
    #***************************
}

function Get-PISysAudit_CheckAppLockerEnabled {
    <#
.SYNOPSIS
AU10004 - AppLocker Enabled
.DESCRIPTION
VALIDATION: Verifies that AppLocker is enabled. <br/>
COMPLIANCE: Set AppLocker to Enforce mode after establishing a policy and ensure
that the Application Identity service is not disabled.  For a primer on running
AppLocker on a PI Data Archive, see: <br/>
<a href="https://techsupport.osisoft.com/Troubleshooting/KB/KB00994">https://techsupport.osisoft.com/Troubleshooting/KB/KB00994</a>
#>
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess = $false)]
    param(
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "Default")]
        [alias("at")]
        [System.Collections.HashTable]
        $AuditTable,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("lc")]
        [boolean]
        $LocalComputer = $true,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("rcn")]
        [string]
        $RemoteComputerName = "",
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("dbgl")]
        [int]
        $DBGLevel = 0)
    BEGIN {}
    PROCESS {
        # Get and store the function Name.
        $fn = GetFunctionName

        try {
            $result = $false

            # Check first to see if Server Core is used.
            if ($global:MachineConfiguration.InstallationType -eq "Server Core") {
                $result = $true
                $msg = "Windows Server Core detected.  Core edition does not support AppLocker.  Passing check due to reduced attack surface of Server Core"
            }
            else {
                if ($global:MachineConfiguration.PSVersion -ge 3) {
                    # Read the AppLocker policy.
                    $appLockerConfiguration = Get-PISysAudit_AppLockerState -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel
                    if ($null -ne $appLockerConfiguration.Policy) {
                        if ($(Select-Xml -xml $appLockerConfiguration.Policy -XPath "//RuleCollection[@Type='Exe']").Node.EnforcementMode -eq "Enabled" -and `
                            $(Select-Xml -xml $appLockerConfiguration.Policy -XPath "//RuleCollection[@Type='Msi']").Node.EnforcementMode -eq "Enabled") {
                            if ($appLockerConfiguration.ServiceEnabled) {
                                $result = $true
                                $msg = "AppLocker is configured to enforce."
                            }
                            else {
                                $msg = "AppLocker is configured to enforce but the Application Identity Service is disabled."
                            }
                        }
                        else {
                            $msg = "AppLocker is not configured to enforce."
                        }
                    }
                    else {
                        $msg = "No AppLocker policy returned."
                    }
                }
                else {
                    $result = "N/A"
                    $msg = "The server: {0} has PowerShell {1}, so the AppLocker configuration could not be retrieved" -f $RemoteComputerName, $global:MachineConfiguration.PSVersion
                    Write-PISysAudit_LogMessage $msg "Error" $fn
                    $AuditTable = New-PISysAuditError -lc $LocalComputer -rcn $RemoteComputerName `
                        -at $AuditTable -an 'Computer' -fn $fn -msg $msg
                    return
                }
            }
        }
        catch {
            # Return the error message.
            $msg = "A problem occurred during the processing of the validation check."
            Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
            $result = "N/A"
        }

        # Define the results in the audit table
        $AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
            -at $AuditTable "AU10004" `
            -ain "AppLocker Enabled" -aiv $result `
            -aif $fn -msg $msg `
            -Group1 "Machine" -Group2 "Policy" `
            -Severity "Medium"
    }

    END {}

    #***************************
    #End of exported function
    #***************************
}

function Get-PISysAudit_CheckUACEnabled {
    <#
.SYNOPSIS
AU10005 - UAC Enabled
.DESCRIPTION
VALIDATION: Verifies that UAC is enabled.  More precisely, it verifies the
following default features: EnableLUA, ConsentPromptBehaviorAdmin,
EnableInstallerDetection, PromptOnSecureDesktop and EnableSecureUIAPaths.
Additionally, a check is performed for the feature ValidateAdminCodeSignatures.
Lower severity is assigned if this is the only feature disabled.<br/>
COMPLIANCE: Enable the flagged UAC features through Local Security Policy. For
more information on specific UAC features, see: <br/>
<a href="https://technet.microsoft.com/en-us/library/dd835564(v=ws.10).aspx">https://technet.microsoft.com/en-us/library/dd835564(v=ws.10).aspx </a>
#>
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess = $false)]
    param(
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "Default")]
        [alias("at")]
        [System.Collections.HashTable]
        $AuditTable,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("lc")]
        [boolean]
        $LocalComputer = $true,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("rcn")]
        [string]
        $RemoteComputerName = "",
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("dbgl")]
        [int]
        $DBGLevel = 0)
    BEGIN {}
    PROCESS {
        # Get and store the function Name.
        $fn = GetFunctionName
        $severity = "Unknown"

        try {
            if ($global:MachineConfiguration.InstallationType -ne "Server Core") {
                $result = $true
                $uacKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system"
                $defaultEnabledUACFeatures = "EnableLUA", "ConsentPromptBehaviorAdmin", "EnableInstallerDetection", "PromptOnSecureDesktop", "EnableSecureUIAPaths"

                # Loop through key default enabled UAC features
                $tmpmsg = "Some default UAC features are disabled: "
                foreach ($uacFeature in $defaultEnabledUACFeatures) {
                    if ($(Get-PISysAudit_RegistryKeyValue -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel -RegKeyPath $uacKeyPath -Attribute $uacFeature) -eq 0) {
                        $result = $false
                        $severity = "Medium"
                        $tmpmsg += $uacFeature + "; "
                    }
                }

                # If the default features are enabled, check for additional feature for added security.
                if ($result) {
                    # Assigning lower severity since the default features are in place.
                    $severity = "Low"
                    $additionalUACFeature = "ValidateAdminCodeSignatures"
                    if ($(Get-PISysAudit_RegistryKeyValue -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel -RegKeyPath $uacKeyPath -Attribute $additionalUACFeature) -eq 0) {
                        $result = $false
                        $msg = "Recommended UAC feature {0} disabled."
                        $msg = [string]::Format($msg, $additionalUACFeature)
                    }
                    else {$msg = "UAC features enabled."}
                }
                else
                {$msg = $tmpmsg}
            }
            else {
                # Server Core does not require UAC, pass this check
                $result = $true
                $msg = "UAC is not required on Server Core."
            }
        }
        catch {
            # Return the error message.
            $msg = "A problem occurred during the processing of the validation check."
            Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
            $result = "N/A"
        }

        # Define the results in the audit table
        $AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
            -at $AuditTable "AU10005" `
            -ain "UAC Enabled" -aiv $result `
            -aif $fn -msg $msg `
            -Group1 "Machine" -Group2 "Policy" `
            -Severity $severity
    }

    END {}

    #***************************
    #End of exported function
    #***************************
}

function Get-PISysAudit_CheckManagedPI {
    <#
.SYNOPSIS
AU10006 - Health Monitoring (OSIsoft NOC)
.DESCRIPTION
VALIDATION: Checks if PI Diagnostics and PI Agent are installed and enabled,
indicating that the machine is monitored in the OSIsoft NOC. <br/>
COMPLIANCE: The goal of this check is to ensure that the PI System component
has monitoring for notification and response, of which mPI is one example. If
an equivalent independent solution is in place for monitoring, this check can
be safely ignored.  To ensure compliance with this check PI Agent and PI
Diagnostics need to be installed and running on the machine so that the OSIsoft
NOC will detect issues. <br/>
#>
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess = $false)]
    param(
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "Default")]
        [alias("at")]
        [System.Collections.HashTable]
        $AuditTable,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("lc")]
        [boolean]
        $LocalComputer = $true,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("rcn")]
        [string]
        $RemoteComputerName = "",
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("dbgl")]
        [int]
        $DBGLevel = 0)
    BEGIN {}
    PROCESS {
        # Get and store the function Name.
        $fn = GetFunctionName
        $msg = ""
        try {
            $installedPrograms = Get-PISysAudit_InstalledComponent -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel
            $agent = $installedPrograms | Where-Object DisplayName -EQ 'PI Agent'
            $diagnostics = $installedPrograms | Where-Object DisplayName -EQ 'PI Diagnostics'
            if (-not ($agent -and $diagnostics)) {
                $result = $false
                $msg = "PI Agent and/or PI Diagnostics not installed."
            }
            else {
                $agentServiceState = Get-PISysAudit_ServiceProperty -sn 'OSISoftPIAgent' -sp State `
                    -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel
                $diagnosticsServiceState = Get-PISysAudit_ServiceProperty -sn 'PIDiagnosticsService' -sp State `
                    -lc $LocalComputer -rcn $RemoteComputerName -dbgl $DBGLevel
                if (($agentServiceState -ne 'Running') -or ($diagnosticsServiceState -ne 'Running')) {
                    $result = $false
                    $msg = "PI Agent and PI Diagnostics installed but one or both services are not running."
                }
                else {
                    $agentVersion = $agent.DisplayVersion + '.0'
                    $agentConfigPath = [string]::Format("C:\ProgramData\OSIsoft\PI Agent\{0}\user.config", $agentVersion)
                    $scriptBlock = {param([string]$ConfigPath) [xml](Get-Content -Path $ConfigPath)}
                    if ($LocalComputer) {
                        $agentConfig = & $scriptBlock -ConfigPath $agentConfigPath
                    }
                    else {
                        $agentConfig = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock -ArgumentList $agentConfigPath
                    }
                    $agentSettings = $agentConfig.configuration.userSettings.'SIS.Properties.Settings'.setting
                    $agentRegistered = $agentSettings | Where-Object Name -EQ 'IsRegistered'
                    if ($agentRegistered.value -eq 'True') {
                        $result = $true
                        $msg = "Machine is registered with the OSIsoft NOC."
                    }
                    else {
                        $result = $false
                        $msg = "PI Agent and PI Diagnostics installed and running, but not registered with OSIsoft NOC."
                    }
                }
            }
            if ($result -eq $false)
            { $msg += " If there is an independent solution implemented for monitoring, then this check can be safely ignored." }
        }
        catch {
            # Return the error message.
            $msg = "A problem occurred during the processing of the validation check."
            Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
            $result = "N/A"
        }

        # Define the results in the audit table
        $AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
            -at $AuditTable "AU10006" `
            -ain "OSIsoft NOC Monitoring" -aiv $result `
            -aif $fn -msg $msg `
            -Group1 "Machine" -Group2 "Montitoring"`
            -Severity "Medium"
    }

    END {}

    #***************************
    #End of exported function
    #***************************
}

function Get-PISysAudit_CheckIEEnhancedSecurity {
    <#
.SYNOPSIS
AU10007 - Internet Explorer Enhanced Security
.DESCRIPTION
VERIFICATION: Validates that IE Enhanced Security is enabled <br/>
COMPLIANCE: Ensure that Internet Explorer Enhanced Security is enabled for both
Administrators and Users. More information is available at:<br/>
<a href="https://technet.microsoft.com/en-us/library/dd883248(v=ws.10).aspx">https://technet.microsoft.com/en-us/library/dd883248(v=ws.10).aspx </a> <br/>
#>
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess = $false)]
    param(
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "Default")]
        [alias("at")]
        [System.Collections.HashTable]
        $AuditTable,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("lc")]
        [boolean]
        $LocalComputer = $true,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("rcn")]
        [string]
        $RemoteComputerName = "",
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("dbgl")]
        [int]
        $DBGLevel = 0)
    BEGIN {}
    PROCESS {
        # Get and store the function Name.
        $fn = GetFunctionName
        $msg = ""
        try {
            if ($global:MachineConfiguration.InstallationType -eq "Server Core") {
                $result = $true
                $msg = "Server Core detected.  Core installation does not include IE."
            }
            else {
                $adminKeyPath = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
                $userKeyPath = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
                # Attribute is 0 or 1 for enabled/disabled
                $adminIsEnabled = Get-PISysAudit_RegistryKeyValue -rkp $adminKeyPath -a "IsInstalled" -lc $LocalComputer -rcn $RemoteComputerName
                $userIsEnabled = Get-PISysAudit_RegistryKeyValue -rkp $userKeyPath -a "IsInstalled" -lc $LocalComputer -rcn $RemoteComputerName
                if ($adminIsEnabled -eq 1 -and $userIsEnabled -eq 1) {
                    $result = $true
                    $msg = "IE Enhanced Security is enabled for Users and Admins."
                }
                elseif ($adminIsEnabled -eq 1) {
                    $result = $false
                    $msg = "IE Enhanced Security is disabled for Users."
                }
                elseif ($userIsEnabled -eq 1) {
                    $result = $false
                    $msg = "IE Enhanced Security is disabled for Admins."
                }
                else {
                    $result = $false
                    $msg = "IE Enhanced Security is disabled for Users and Admins."
                }
            }
        }
        catch {
            # Return the error message.
            $msg = "A problem occurred during the processing of the validation check."
            Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
            $result = "N/A"
        }

        # Define the results in the audit table
        $AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
            -at $AuditTable "AU10007" `
            -ain "IE Enhanced Security" -aiv $result `
            -aif $fn -msg $msg `
            -Group1 "Machine" -Group2 "Policy" `
            -Severity "Medium"
    }

    END {}

    #***************************
    #End of exported function
    #***************************
}

function Get-PISysAudit_CheckSoftwareUpdate {
    <#
.SYNOPSIS
AU10008 - Software Updates
.DESCRIPTION
VERIFICATION: Validates that the operating system and Microsoft applications
receive updates <br/>
COMPLIANCE: Ensure that the operating system and the Microsoft applications
have been updated in the last 120 days.
<a href="https://support.microsoft.com/en-us/help/311047/how-to-keep-your-windows-computer-up-to-date">https://support.microsoft.com/en-us/help/311047/how-to-keep-your-windows-computer-up-to-date</a> <br/>
#>
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess = $false)]
    param(
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "Default")]
        [alias("at")]
        [System.Collections.HashTable]
        $AuditTable,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("lc")]
        [boolean]
        $LocalComputer = $true,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("rcn")]
        [string]
        $RemoteComputerName = "",
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("dbgl")]
        [int]
        $DBGLevel = 0)
    BEGIN {}
    PROCESS {
        # Get and store the function Name.
        $fn = GetFunctionName
        $msg = ""
        try {
            $isServerCore = $global:MachineConfiguration.InstallationType -eq "Server Core"
            $cutoff = 120
            $cutoffDate = (Get-Date).AddDays(-1 * $cutoff).ToFileTimeUtc()
            # Get most recent OS patch
            $lastInstalledHotFix = Get-PISysAudit_InstalledKB -LocalComputer $LocalComputer -RemoteComputerName $RemoteComputerName -Type HotFix `
																| sort-object InstalledOn -Descending `
																| select-object -ExpandProperty InstalledOn -First 1
            if (!$isServerCore) {
                # win32_reliabilityRecords not included on Server Core
                $lastInstalledReliability = Get-PISysAudit_InstalledKB -LocalComputer $LocalComputer -RemoteComputerName $RemoteComputerName -Type Reliability `
                    | sort-object InstalledOn -Descending `
                    | select-object -ExpandProperty InstalledOn -First 1
            }

            function IsPatchLevelCurrent ($lastPatch, $cutoffDate) {
                if ($null -eq $lastPatch) { return $false }
                else
                { return ([datetime]$lastPatch).ToFileTimeUtc() -gt $cutoffDate }
            }

            if ($isServerCore) {
                # On Server Core, only check OS Patches
                $IsOSPatched = IsPatchLevelCurrent $lastInstalledHotFix $cutoffDate
                if ($IsOSPatched) {
                    $result = $true
                    $msg = "Server Core operating system updates have been applied within the past $cutoff days."
                }
                else {
                    $result = $false
                    $msg = "Server Core operating system updates have NOT been applied within the past $cutoff days."
                }
                if ($lastInstalledHotFix) {$msg += " Last update: $($lastInstalledHotFix.ToShortDateString())."}
                else {$msg += " No updates found."}
            }
            else {
                # On Server Standard, check OS and App Patches
                $IsOSPatched = IsPatchLevelCurrent $lastInstalledHotFix $cutoffDate
                $AreAppsPatched = IsPatchLevelCurrent $lastInstalledReliability $cutoffDate

                if ($IsOSPatched -and $AreAppsPatched) {
                    $result = $true
                    $msg = "Operating system and application updates have been applied to the server within the past $cutoff days."
                }
                else {
                    $result = $false
                    if (!$IsOSPatched)
                    {$msg += "Operating system updates have NOT been applied in the last $cutoff days."}
                    if (!$AreAppsPatched)
                    {$msg += "Application updates have NOT been applied in the last $cutoff days."}
                }
                if ($lastInstalledHotFix)
                {$msg += " Last OS update: $($lastInstalledHotFix.ToShortDateString())."}
                else
                {$msg += " No OS updates found."}
                if ($lastInstalledReliability)
                {$msg += " Last App update: $($lastInstalledReliability.ToShortDateString())."}
                else
                {$msg += " No App updates found."}
            }
        }
        catch {
            # Return the error message.
            $msg = "A problem occurred during the processing of the validation check."
            Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
            $result = "N/A"
        }

        # Define the results in the audit table
        $AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
            -at $AuditTable "AU10008" `
            -ain "Software Updates" -aiv $result `
            -aif $fn -msg $msg `
            -Group1 "Machine" -Group2 "Policy" `
            -Severity "Critical"
    }

    END {}

    #***************************
    #End of exported function
    #***************************
}

function Get-PISysAudit_CheckInternetAccess {
    <#
.SYNOPSIS
AU10009 - No Internet Access
.DESCRIPTION
VERIFICATION: Checks that this server is not able to access the internet.<br/>
COMPLIANCE: Implement firewall restrictions to prevent access to the internet
from the server.
#>
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess = $false)]
    param(
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "Default")]
        [alias("at")]
        [System.Collections.HashTable]
        $AuditTable,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("lc")]
        [boolean]
        $LocalComputer = $true,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("rcn")]
        [string]
        $RemoteComputerName = "",
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("dbgl")]
        [int]
        $DBGLevel = 0)
    BEGIN {}
    PROCESS {
        # Get and store the function Name.
        $fn = GetFunctionName
        $msg = ""
        try {
            # Test ping response from Google's DNS server
            $testAddress = '8.8.8.8'
            $scriptBlock = {
                param([string]$Address)
                Test-Connection -ComputerName $Address -Count 4 -Quiet -ErrorAction SilentlyContinue # Quiet simply returns true or false
            }
            if ($LocalComputer) {
                $canConnect = & $scriptBlock -Address $testAddress
            }
            else {
                $canConnect = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock -ArgumentList $testAddress
            }

            if ($canConnect -eq $true) {
                $result = $false
                $msg = "Server has internet access."
            }
            else {
                $result = $true
                $msg = "Server does not appear to have internet access."
            }
        }
        catch {
            # Return the error message.
            $msg = "A problem occurred during the processing of the validation check."
            Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
            $result = "N/A"
        }

        # Define the results in the audit table
        $AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
            -at $AuditTable "AU10009" `
            -ain "No Internet Access" -aiv $result `
            -aif $fn -msg $msg `
            -Group1 "Machine" -Group2 "Policy" `
            -Severity "Medium"
    }

    END {}

    #***************************
    #End of exported function
    #***************************
}

function Get-PISysAudit_CheckDeviceGuard
{
<#  
.SYNOPSIS
AU10010 - Device Guard
.DESCRIPTION
VERIFICATION: Check to make sure that Credential Guard and HVCI are configured. <br/>
COMPLIANCE:
Enable Windows Defender Device Guard hardware-based security features. <br/>
<a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-virtualization-based-protection-of-code-integrity">https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-virtualization-based-protection-of-code-integrity</a> <br/>
VirtualizationBasedSecurityStatus should be 2 (enabled & running) SecurityServicesConfigured & SecurityServicesRunning should include 1 & 2 (Credential Guard and HVCI) and policy should be set to enforce. <br/>
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
		$os = $null
		$dg = $null
		$os = (Get-PISysAudit_CimInstance -cl Win32_OperatingSystem -lc $LocalComputer -rcn $RemoteComputerName).version
		$tmp = $os.split('.')
		$majorVersion = [int]$tmp[0]
		if($majorVersion -ge 10)
		{
			$dg = (Get-PISysAudit_CimInstance -cl Win32_DeviceGuard -ns root\Microsoft\Windows\DeviceGuard -lc $LocalComputer -rcn $RemoteComputerName)
			if($dg.SecurityServicesConfigured[0] -eq 1 -and $dg.SecurityServicesConfigured[1] -eq 2 -and $dg.SecurityServicesRunning[0] -eq 1 -and $dg.SecurityServicesRunning[1] -eq 2 -and $dg.VirtualizationBasedSecurityStatus -eq 2)
			{
				$result = $true
				$msg = "Credential Guard and HVCI are configured."
			}
			else
			{
				$result = $false
				$msg = "Credential Guard and HVCI were not configured."
			}
		}
		else
		{
			$result = $false
			$msg = "Device Guard is not supported with your operating system. Please upgrade to Win10 or Server2016."
		}
	}
	catch
	{
		# Return the error message.
		$msg = "A problem occurred during the processing of the validation check."					
		Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_									
		$result = "N/A"
	}
	
	# Define the results in the audit table	
	$AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
									-at $AuditTable "AU10010" `
									-ain "Windows Defender Device Guard" -aiv $result `
									-aif $fn -msg $msg `
									-Group1 "Machine" -Group2 "Policy" `
									-Severity "Medium"																																																
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
function Get-PISysAudit_TemplateAU1xxxx {
    <#
.SYNOPSIS
AU1xxxx - <Name>
.DESCRIPTION
VERIFICATION: <Enter what the verification checks>
COMPLIANCE: <Enter what it needs to be compliant>
#>
    [CmdletBinding(DefaultParameterSetName = "Default", SupportsShouldProcess = $false)]
    param(
        [parameter(Mandatory = $true, Position = 0, ParameterSetName = "Default")]
        [alias("at")]
        [System.Collections.HashTable]
        $AuditTable,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("lc")]
        [boolean]
        $LocalComputer = $true,
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("rcn")]
        [string]
        $RemoteComputerName = "",
        [parameter(Mandatory = $false, ParameterSetName = "Default")]
        [alias("dbgl")]
        [int]
        $DBGLevel = 0)
    BEGIN {}
    PROCESS {
        # Get and store the function Name.
        $fn = GetFunctionName
        $msg = ""
        try {
            # Enter routine.
        }
        catch {
            # Return the error message.
            $msg = "A problem occurred during the processing of the validation check."
            Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
            $result = "N/A"
        }

        # Define the results in the audit table
        $AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
            -at $AuditTable "AU1xxxx" `
            -ain "<Name>" -aiv $result `
            -aif $fn -msg $msg `
            -Group1 "<Category 1>" -Group2 "<Category 2>" `
            -Group3 "<Category 3>" -Group4 "<Category 4>" `
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
Export-ModuleMember Get-PISysAudit_GlobalMachineConfiguration
Export-ModuleMember Get-PISysAudit_FunctionsFromLibrary1
Export-ModuleMember Get-PISysAudit_CheckDomainMemberShip
Export-ModuleMember Get-PISysAudit_CheckOSInstallationType
Export-ModuleMember Get-PISysAudit_CheckFirewallEnabled
Export-ModuleMember Get-PISysAudit_CheckAppLockerEnabled
Export-ModuleMember Get-PISysAudit_CheckUACEnabled
Export-ModuleMember Get-PISysAudit_CheckManagedPI
Export-ModuleMember Get-PISysAudit_CheckIEEnhancedSecurity
Export-ModuleMember Get-PISysAudit_CheckSoftwareUpdate
Export-ModuleMember Get-PISysAudit_CheckInternetAccess
Export-ModuleMember Get-PISysAudit_CheckDeviceGuard
# </Do not remove>

# ........................................................................
# Add your new Export-ModuleMember instruction after this section.
# Replace the Get-PISysAudit_TemplateAU1xxxx with the name of your
# function.
# ........................................................................
# Export-ModuleMember Get-PISysAudit_TemplateAU1xxxx