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
[Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidGlobalVars", "")]
param()

# ........................................................................
# Internal Functions
# ........................................................................
function GetFunctionName
{ return (Get-Variable MyInvocation -Scope 1).Value.MyCommand.Name }

# ........................................................................
# Public Functions
# ........................................................................
function Get-PISysAudit_FunctionsFromLibrary6 {
    <#
.SYNOPSIS
Get functions from PI Web API library at or below the specified level.
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
    $listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckPIWebAPIVersion"   1 "AU60001"
    $listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckPIWebApiCSRF"      1 "AU60002"
    $listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckPIWebAPIDebugMode" 1 "AU60003"
    $listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckPIWebApiHeaders"   1 "AU60004"
    $listOfFunctions += NewAuditFunction "Get-PISysAudit_CheckPIWebApiCORS"      1 "AU60005"

    # Return all items at or below the specified AuditLevelInt
    return $listOfFunctions | Where-Object Level -LE $AuditLevelInt
}

function Get-PISysAudit_GlobalPIWebApiConfiguration {
    <#
.SYNOPSIS
Gathers global data for all PI Web API checks.
.DESCRIPTION
Several checks reuse information.  This command puts the configuration information
in a global object to reduce the number of remote calls, improving performance and
simplifying validation logic.

Information included in global configuration:
	Version            - application version
	AFServer           - configuration AF Server
	AFElement          - configuration AF Element

#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseDeclaredVarsMoreThanAssignments", "PIWebApiConfiguration", Justification="Global variable set that is used by the validation checks.")]
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
        $global:PIWebApiConfiguration = $null

        $scriptBlock = {
            $pisystemKey = "HKLM:\Software\PISystem\"

            # Registry keys
            $PIWebApiVersion = Get-ItemProperty -Path $($pisystemKey + "WebAPI") -Name "Version" | Select-Object -ExpandProperty "Version"
            $PIWebApiDirectory = Get-ItemProperty -Path $($pisystemKey + "WebAPI") -Name "InstallationDirectory" | Select-Object -ExpandProperty "InstallationDirectory"

            # PI Web API Configuration
            $InstallationConfig = Get-Content -Path $(Join-Path $PIWebApiDirectory "InstallationConfig.json")
            $afMatch = $InstallationConfig | Select-String -Pattern 'ConfigAssetServer\": \"(.*)\"'
            if ($afMatch) { $PIWebApiAF = $afMatch.Matches.Groups[1].Value }
            $elemMatch = $InstallationConfig | Select-String -Pattern 'ConfigInstance\": \"(.*)\"'
            if ($elemMatch) { $PIWebApiElement = $elemMatch.Matches.Groups[1].Value }

            # Construct a custom object to store the config information
            $Configuration = New-Object PSCustomObject
            $Configuration | Add-Member -MemberType NoteProperty -Name Version -Value $PIWebApiVersion
            $Configuration | Add-Member -MemberType NoteProperty -Name AFServer -Value $PIWebApiAF
            $Configuration | Add-Member -MemberType NoteProperty -Name AFElement -Value $PIWebApiElement

            return $Configuration
        }
        try {
            if ($LocalComputer)
            { $global:PIWebApiConfiguration = & $scriptBlock }
            else
            { $global:PIWebApiConfiguration = Invoke-Command -ComputerName $RemoteComputerName -ScriptBlock $scriptBlock }
        }
        catch {
            $msg = "A problem occurred during the retrieval of the Global PI Web API configuration."
            Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
        }
    }
    END {}

}

function Get-PISysAudit_CheckPIWebApiVersion {
    <#
.SYNOPSIS
AU60001 - PI Web API Version
.DESCRIPTION
VALIDATION: Verifies PI Web API version.<br/>
COMPLIANCE: Upgrade to the latest version of PI Web API. See the PI Web API
product page for the latest version and associated documentation:<br/>
<a href="https://techsupport.osisoft.com/Products/Developer-Technologies/PI-Web-API/">https://techsupport.osisoft.com/Products/Developer-Technologies/PI-Web-API/ </a><br/>
For more information on the upgrade procedure, see "PI Web API Installation"
in the PI Live Library:<br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v10/GUID-1B8C5B9F-0CD5-4B98-9283-0F5801AB850B">https://livelibrary.osisoft.com/LiveLibrary/content/en/server-v10/GUID-1B8C5B9F-0CD5-4B98-9283-0F5801AB850B</a><br/>
Associated security bulletins:<br/>
<a href="https://techsupport.osisoft.com/Products/Developer-Technologies/PI-Web-API/Alerts">https://techsupport.osisoft.com/Products/Developer-Technologies/PI-Web-API/Alerts</a>
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
            $installVersion = $global:PIWebApiConfiguration.Version

            $installVersionTokens = $installVersion.Split(".")
            # Form an integer value with all the version tokens.
            [string]$temp = $InstallVersionTokens[0] + $installVersionTokens[1] + $installVersionTokens[2] + $installVersionTokens[3]
            $installVersionInt64 = [int64]$temp
            if ($installVersionInt64 -ge 190000) {
                $result = $true
                $msg = "Version $installVersion is compliant."
            }
            else {
                $result = $false
                $msg = "Noncompliant version ($installVersion) detected. Upgrading to the latest PI Web API version is recommended. "
                $msg += "See https://techsupport.osisoft.com/Products/Developer-Technologies/PI-Web-API/ for the latest version and associated documentation."
            }
        }
        catch {
            # Return the error message.
            $msg = "A problem occurred during the processing of the validation check"
            Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
            $result = "N/A"
        }

        # Define the results in the audit table
        $AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
            -at $AuditTable "AU60001" `
            -ain "PI Web API Version" -aiv $result `
            -aif $fn -msg $msg `
            -Group1 "PI System" -Group2 "PI Web API" `
            -Severity "Medium"
    }

    END {}

    #***************************
    #End of exported function
    #***************************
}

function Get-PISysAudit_CheckPIWebApiCSRF {
    <#
.SYNOPSIS
AU60002 - PI Web API CSRF
.DESCRIPTION
VALIDATION: Checks for enabled CSRF Defense in the PI Web API.<br/>
COMPLIANCE: Verify that Cross-Site Request Forgery defense is enabled. This is
configured by setting "EnableCSRFDefense" to True on the PI Web API
configuration element. for more information, see AL00316:<br/>
<a href="https://techsupport.osisoft.com/Troubleshooting/Alerts/AL00316">https://techsupport.osisoft.com/Troubleshooting/Alerts/AL00316</a>
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
            # CSRF Defense only available in 1.9 and later
            $installVersion = $global:PIWebApiConfiguration.Version
            $installVersionInt64 = [int64]($installVersion.Split('.') -join '')

            if ($installVersionInt64 -ge 190000) {
                # Attempt connection to configuration AF Server
                $configAF = Get-AFServer $global:PIWebApiConfiguration.AFServer
                if ($configAF) {
                    $configAF = Connect-AFServer -AFServer $configAF

                    # Drill into Configuration DB to get Web API config element
                    $configDB = Get-AFDatabase -AFServer $configAF -Name 'Configuration'
                    if ($null -ne $configDB) { $osisoft = Get-AFElement -AFDatabase $configDB -Name 'OSIsoft' }
                    if ($null -ne $osisoft) { $webAPI = Get-AFElement -AFElement $osisoft -Name 'PI Web API' }
                    if ($null -ne $webAPI) { $configElem = Get-AFElement -AFElement $webAPI -Name $global:PIWebApiConfiguration.AFElement }
                    if ($null -ne $configElem) { $systemConfig = Get-AFElement -AFElement $configElem -Name 'System Configuration' }
                    if ($null -ne $systemConfig) { $CsrfDefense = Get-AFAttribute -AFElement $systemConfig -Name 'EnableCSRFDefense' }

                    if ($null -ne $systemConfig) {
                        if ($null -ne $CsrfDefense) {
                            $CsrfEnabled = $CsrfDefense.GetValue()
                            if ($CsrfEnabled.Value -eq $true) {
                                $result = $true
                                $msg = "CSRF Defense is enabled on the PI Web API."
                            }
                            else {
                                $result = $false
                                $msg = "CSRF Defense is disabled on the PI Web API."
                            }
                        }
                        else {
                            $result = $false
                            $msg = "Unable to locate EnableCSRFDefense setting for the PI Web API."
                        }
                    }
                    else {
                        # problem finding config element
                        $result = "N/A"
                        $msg = "Unable to locate PI Web API configuration element '$($global:PIWebApiConfiguration.AFElement)'"
                        $msg += " on $($global:PIWebApiConfiguration.AFServer)"
                        Write-PISysAudit_LogMessage $msg "Error" $fn
                    }
                }
                else {
                    $result = "N/A"
                    $msg = "Unable to connect to PI Web API configuration AF Server '$($global:PIWebApiConfiguration.AFServer)'"
                    Write-PISysAudit_LogMessage $msg "Error" $fn
                }
            }
            else {
                $result = $false
                $msg = "CSRF Defense only available in PI Web API 2017 or later."
            }
        }
        catch {
            # Return the error message.
            $msg = "A problem occurred during the processing of the validation check"
            Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
            $result = "N/A"
        }

        # Define the results in the audit table
        $AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
            -at $AuditTable "AU60002" `
            -ain "PI Web API CSRF" -aiv $result `
            -aif $fn -msg $msg `
            -Group1 "PI System" -Group2 "PI Web API" `
            -Severity "Medium"
    }

    END {}

    #***************************
    #End of exported function
    #***************************
}

function Get-PISysAudit_CheckPIWebApiDebugMode {
    <#
.SYNOPSIS
AU60003 - PI Web API Debug Mode
.DESCRIPTION
VALIDATION: Verifies that debug mode is disabled in the PI Web API. <br/>
COMPLIANCE: Disable debug mode in PI Web API 2017 R2 or later by setting the
DebugMode attribute to False in the PI Web API configuration element, if this
attribute exists. If the DebugMode attribute is not present, debug mode is
disabled by default. Debug mode should only be enabled for troubleshooting
purposes. For more information, see Live Library:<br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/web-api-v9/GUID-E8BF02E2-77C1-40B1-9F1F-0637F94BB8B9">https://livelibrary.osisoft.com/LiveLibrary/content/en/web-api-v9/GUID-E8BF02E2-77C1-40B1-9F1F-0637F94BB8B9</a>
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
            # Debug mode setting only available in 1.10 and later
            $installVersion = $global:PIWebApiConfiguration.Version
            $installVersionInt64 = [int64]($installVersion.Split('.') -join '')

            if ($installVersionInt64 -ge 1100000) {
                # Attempt connection to configuration AF Server
                $configAF = Get-AFServer $global:PIWebApiConfiguration.AFServer
                if ($configAF) {
                    $configAF = Connect-AFServer -AFServer $configAF

                    # Drill into Configuration DB to get Web API config element
                    $configDB = Get-AFDatabase -AFServer $configAF -Name 'Configuration'
                    if ($null -ne $configDB) { $osisoft = Get-AFElement -AFDatabase $configDB -Name 'OSIsoft' }
                    if ($null -ne $osisoft) { $webAPI = Get-AFElement -AFElement $osisoft -Name 'PI Web API' }
                    if ($null -ne $webAPI) { $configElem = Get-AFElement -AFElement $webAPI -Name $global:PIWebApiConfiguration.AFElement }
                    if ($null -ne $configElem) { $systemConfig = Get-AFElement -AFElement $configElem -Name 'System Configuration' }
                    if ($null -ne $systemConfig) { $debugMode = Get-AFAttribute -AFElement $systemConfig -Name 'DebugMode' }

                    if ($null -ne $systemConfig) {
                        if ($null -ne $debugMode) {
                            $debugEnabled = $debugMode.GetValue()
                            if ($debugEnabled.Value -eq $true) {
                                $result = $false
                                $msg = "Debug mode is enabled on the PI Web API."
                            }
                            else {
                                $result = $true
                                $msg = "Debug mode is disabled on the PI Web API."
                            }
                        }
                        else {
                            # No DebugMode attribute means debug mode disabled
                            $result = $true
                            $msg = "Debug mode is disabled on the PI Web API."
                        }
                    }
                    else {
                        # problem finding config element
                        $result = "N/A"
                        $msg = "Unable to locate PI Web API configuration element '$($global:PIWebApiConfiguration.AFElement)'"
                        $msg += " on $($global:PIWebApiConfiguration.AFServer)"
                        Write-PISysAudit_LogMessage $msg "Error" $fn
                    }
                }
                else {
                    # no connection to AF
                    $result = "N/A"
                    $msg = "Unable to connect to PI Web API configuration AF Server '$($global:PIWebApiConfiguration.AFServer)'"
                    Write-PISysAudit_LogMessage $msg "Error" $fn
                }
            }
            else {
                $result = $false
                $msg = "Disabling debug mode is only available in PI Web API 2017 R2 or later."
            }
        }
        catch {
            # Return the error message.
            $msg = "A problem occurred during the processing of the validation check"
            Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
            $result = "N/A"
        }

        # Define the results in the audit table
        $AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
            -at $AuditTable "AU60003" `
            -ain "PI Web API Debug Mode" -aiv $result `
            -aif $fn -msg $msg `
            -Group1 "PI System" -Group2 "PI Web API" `
            -Severity "Low"
    }

    END {}

    #***************************
    #End of exported function
    #***************************
}

function Get-PISysAudit_CheckPIWebApiHeaders {
    <#
.SYNOPSIS
AU60004 - PI Web API HTTP Headers
.DESCRIPTION
VALIDATION: Verifies that best practices for HTTP headers are implemented
in the PI Web API. <br/>
COMPLIANCE: Ensure that the X-Frame-Options header is set to enforce framing
restrictions and the Strict-Transport-Security header is set to enforce HTTP
strict transport security (HSTS). Both of these protections can be configured
as custom headers in the PI Web API. For configuration steps, see Custom
headers in the PI Web API Live Library documentation: <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/web-api-v9/GUID-AF281636-B731-443E-879D-202C1062932B">https://livelibrary.osisoft.com/LiveLibrary/content/en/web-api-v9/GUID-AF281636-B731-443E-879D-202C1062932B</a> <br/>
Information on X-Frame-Options and supported values can be found here: <br/>
<a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options">https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options</a> <br/>
Information on HSTS and supported values can be found here: <br/>
<a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security">https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security</a> <br/>
For additional web security recommendations, see KB01631: <br/>
<a href="https://techsupport.osisoft.com/Troubleshooting/KB/KB01631/">https://techsupport.osisoft.com/Troubleshooting/KB/KB01631/</a> <br/>
#>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSUseSingularNouns", "", Justification="Grammatically and logically a plural noun is more appropriate.")]
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
            $installVersion = $global:PIWebApiConfiguration.Version
            $installVersionInt64 = [int64]($installVersion.Split('.') -join '')

            # X-Frame-Options support added in PI Web API 2017
            if ($installVersionInt64 -ge 190000) {
                # Define X-Frame-Options values that will pass the check
                $xfoValuesAllowed = @(
                    'DENY',
                    'SAMEORIGIN',
                    'ALLOW-FROM*'
                )

                # Attempt connection to configuration AF Server
                $configAF = Get-AFServer $global:PIWebApiConfiguration.AFServer
                if ($configAF) {
                    $configAF = Connect-AFServer -AFServer $configAF

                    # Drill into Configuration DB to get Web API config element
                    $configDB = Get-AFDatabase -AFServer $configAF -Name 'Configuration'
                    if ($null -ne $configDB) { $osisoft = Get-AFElement -AFDatabase $configDB -Name 'OSIsoft' }
                    if ($null -ne $osisoft) { $webAPI = Get-AFElement -AFElement $osisoft -Name 'PI Web API' }
                    if ($null -ne $webAPI) { $configElem = Get-AFElement -AFElement $webAPI -Name $global:PIWebApiConfiguration.AFElement }
                    if ($null -ne $configElem) { $systemConfig = Get-AFElement -AFElement $configElem -Name 'System Configuration' }
                    if ($null -ne $systemConfig) { $xFrameOptions = Get-AFAttribute -AFElement $systemConfig -Name 'XFrameOptions' }
                    if ($installVersionInt64 -ge 1100000) {
                        if ($null -ne $systemConfig) { $customHeaders = Get-AFAttribute -AFElement $systemConfig -Name 'CustomHeaders' }
                        if ($null -ne $systemConfig) { $customHeadersEnabled = Get-AFAttribute -AFElement $systemConfig -Name 'CustomHeadersEnabled' }
                    }

                    if ($null -ne $systemConfig) {
                        if ($null -ne $xFrameOptions) {
                            $xfoValue = $xFrameOptions.GetValue()
                            $xFramePassed = $false
                            foreach ($allowed in $xfoValuesAllowed) {
                                if ($xfoValue.Value -like $allowed) {
                                    $xFramePassed = $true
                                }
                            }
                        }
                        else {
                            # no XFrameOptions attribute
                            $xFramePassed = $false
                        }

                        if ($installVersionInt64 -ge 1100000) {
                            if (($null -ne $customHeadersEnabled) -and ($null -ne $customHeaders)) {
                                $hstsPassed = $false
                                $customHeadersEnabledValue = $customHeadersEnabled.GetValue()
                                $customHeadersValue = $customHeaders.GetValue()
                                if ($customHeadersEnabledValue.Value -eq $true) {
                                    foreach ($header in $customHeadersValue.Value) {
                                        # check for HSTS header
                                        if ($header -like 'strict-transport-security:*') { $hstsPassed = $true }
                                        # check for X-Frame-Options again
                                        foreach ($allowed in $xfoValuesAllowed) {
                                            if ($header -like ("x-frame-options: $allowed")) {
                                                $xFramePassed = $true
                                            }
                                        }
                                    }
                                }
                                else {
                                    $hstsPassed = $false
                                }
                            }
                            else {
                                # CustomHeaders are missing or not enabled.
                                # Fail all checks for headers that are only in this attribute
                                $hstsPassed = $false
                            }

                            # Evaluate results for PI Web API 2017 R2
                            if ($xFramePassed -and $hstsPassed) {
                                $result = $true
                                $msg = "Recommended HTTP headers are enabled in the PI Web API."
                            }
                            elseif ($xFramePassed) {
                                $result = $false
                                $msg = "X-Frame-Options is enabled, but HSTS is not enabled in the PI Web API."
                            }
                            elseif ($hstsPassed) {
                                $result = $false
                                $msg = "HSTS is enabled, but X-Frame-Options is not enabled in the PI Web API."
                            }
                            else {
                                $result = $false
                                $msg = "No recommended HTTP headers are enabled in the PI Web API."
                            }
                        }
                        else {
                            # version is not 2017 R2 or later, can't pass check fully
                            $result = $false
                            if ($xFramePassed) {
                                $msg = "X-Frame-Option is enabled, but other custom headers require PI Web API 2017 or later."
                            }
                            else {
                                $msg = "X-Frame-Option is not enabled, and other custom headers require PI Web API 2017 or later."
                            }
                        }
                    }
                    else {
                        # problem finding config element
                        $result = "N/A"
                        $msg = "Unable to locate PI Web API configuration element '$($global:PIWebApiConfiguration.AFElement)'"
                        $msg += " on $($global:PIWebApiConfiguration.AFServer)"
                        Write-PISysAudit_LogMessage $msg "Error" $fn
                    }
                }
                else {
                    # no connection to AF
                    $result = "N/A"
                    $msg = "Unable to connect to PI Web API configuration AF Server '$($global:PIWebApiConfiguration.AFServer)'"
                    Write-PISysAudit_LogMessage $msg "Error" $fn
                }
            }
            else {
                # version is earlier than 2017
                $result = $false
                $msg = "Custom HTTP headers are supported in PI Web API 2017 R2 or later."
            }
        }
        catch {
            # Return the error message.
            $msg = "A problem occurred during the processing of the validation check"
            Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
            $result = "N/A"
        }

        # Define the results in the audit table
        $AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
            -at $AuditTable "AU60004" `
            -ain "PI Web API HTTP Headers" -aiv $result `
            -aif $fn -msg $msg `
            -Group1 "PI System" -Group2 "PI Web API" `
            -Severity "Low"
    }

    END {}

    #***************************
    #End of exported function
    #***************************
}

function Get-PISysAudit_CheckPIWebApiCORS {
    <#
.SYNOPSIS
AU60005 - PI Web API CORS
.DESCRIPTION
VALIDATION: Verifies that CORS origins are restricted to a whitelist of domains, if CORS is enabled. <br/>
COMPLIANCE: Ensure that the CORSOrigins attribute in the PI Web API configuration element
is either empty (CORS disabled) or contains a list of allowed domains. Do not use CORSOrigins = *,
as this allows cross-origin requests from any origin. For more information, see Live Library: <br/>
<a href="https://livelibrary.osisoft.com/LiveLibrary/content/en/web-api-v9/GUID-D0AF8333-3E78-4F4F-A233-4794DD71819C">https://livelibrary.osisoft.com/LiveLibrary/content/en/web-api-v9/GUID-D0AF8333-3E78-4F4F-A233-4794DD71819C</a>
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
            # Attempt connection to configuration AF Server
            $configAF = Get-AFServer $global:PIWebApiConfiguration.AFServer
            if ($configAF) {
                $configAF = Connect-AFServer -AFServer $configAF

                # Drill into Configuration DB to get Web API config element
                $configDB = Get-AFDatabase -AFServer $configAF -Name 'Configuration'
                if ($null -ne $configDB) { $osisoft = Get-AFElement -AFDatabase $configDB -Name 'OSIsoft' }
                if ($null -ne $osisoft) { $webAPI = Get-AFElement -AFElement $osisoft -Name 'PI Web API' }
                if ($null -ne $webAPI) { $configElem = Get-AFElement -AFElement $webAPI -Name $global:PIWebApiConfiguration.AFElement }
                if ($null -ne $configElem) { $systemConfig = Get-AFElement -AFElement $configElem -Name 'System Configuration' }
                if ($null -ne $systemConfig) { $corsOrigins = Get-AFAttribute -AFElement $systemConfig -Name 'CORSOrigins' }

                if ($null -ne $systemConfig) {
                    if ($null -ne $corsOrigins) {
                        $corsOriginsStr = $corsOrigins.GetValue().Value
                        if ($null -ne $corsOriginsStr) {
                            $corsOriginsStr = $corsOriginsStr.Trim()
                            if ($corsOriginsStr -eq '*') {
                                $result = $false
                                $msg = "CORS origins are unrestricted on the PI Web API."
                            }
                            else {
                                $result = $true
                                $msg = "CORS origins are restricted on the PI Web API."
                            }
                        }
                        else {
                            # Null CORSOrigins attribute means CORS access is disabled
                            $result = $true
                            $msg = "CORS is disabled on the PI Web API."
                        }
                    }
                    else {
                        # No CORSOrigins attribute means CORS access is disabled
                        $result = $true
                        $msg = "CORS is disabled on the PI Web API."
                    }
                }
                else {
                    # problem finding config element
                    $result = "N/A"
                    $msg = "Unable to locate PI Web API configuration element '$($global:PIWebApiConfiguration.AFElement)'"
                    $msg += " on $($global:PIWebApiConfiguration.AFServer)"
                    Write-PISysAudit_LogMessage $msg "Error" $fn
                }
            }
            else {
                # no connection to AF
                $result = "N/A"
                $msg = "Unable to connect to PI Web API configuration AF Server '$($global:PIWebApiConfiguration.AFServer)'"
                Write-PISysAudit_LogMessage $msg "Error" $fn
            }
        }
        catch {
            # Return the error message.
            $msg = "A problem occurred during the processing of the validation check"
            Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
            $result = "N/A"
        }

        # Define the results in the audit table
        $AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
            -at $AuditTable "AU60005" `
            -ain "PI Web API CORS" -aiv $result `
            -aif $fn -msg $msg `
            -Group1 "PI System" -Group2 "PI Web API" `
            -Severity "Low"
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
function Get-PISysAudit_TemplateAU6xxxx {
    <#
.SYNOPSIS
AU6xxxx - <Name>
.DESCRIPTION
VALIDATION: <Enter what the verification checks>
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

        try {
            # Enter routine.
            # Use information from $global:PIVisionConfiguration whenever possible to
            # focus on validation simplify logic.
        }
        catch {
            # Return the error message.
            $msg = "A problem occurred during the processing of the validation check"
            Write-PISysAudit_LogMessage $msg "Error" $fn -eo $_
            $result = "N/A"
        }

        # Define the results in the audit table
        $AuditTable = New-PISysAuditObject -lc $LocalComputer -rcn $RemoteComputerName `
            -at $AuditTable "AU6xxxx" `
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
Export-ModuleMember Get-PISysAudit_GlobalPIWebApiConfiguration
Export-ModuleMember Get-PISysAudit_FunctionsFromLibrary6
Export-ModuleMember Get-PISysAudit_CheckPIWebApiVersion
Export-ModuleMember Get-PISysAudit_CheckPIWebApiCSRF
Export-ModuleMember Get-PISysAudit_CheckPIWebAPIDebugMode
Export-ModuleMember Get-PISysAudit_CheckPIWebApiHeaders
Export-ModuleMember Get-PISysAudit_CheckPIWebApiCORS
# </Do not remove>

# ........................................................................
# Add your new Export-ModuleMember instruction after this section.
# Replace the Get-PISysAudit_TemplateAU6xxxx with the name of your
# function.
# ........................................................................
# Export-ModuleMember Get-PISysAudit_TemplateAU1xxxx