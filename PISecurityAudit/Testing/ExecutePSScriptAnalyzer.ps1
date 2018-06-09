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

# Note: PSScriptAnalyzer module must be installed.
# Documentation for PSScriptAnalyzer = https://github.com/PowerShell/PSScriptAnalyzer
Import-Module 'PSScriptAnalyzer'

# Wrapper to Invoke analyzer and send results to export folder
function InvokePSScriptAnalysis ($scripts, $scriptPath, $excludedRules, $PISecAuditRoot)
{
	foreach ($script in $scripts) 
	{
		Invoke-ScriptAnalyzer -Path $($scriptPath + $script + '.psm1') -ExcludeRule $excludedRules `
							 | Out-File $($PISecAuditRoot + '\Export\' + $script + '.staticanalysis.dat') -Force
	}
} 

# Get the root path for the scripts to analyze.
$PISecAuditTestPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$PISecAuditRoot = Split-Path -Parent -Path $PISecAuditTestPath

# Define set of rules to exclude from the analysis, globally.
$excludedRules = @( 'PSUseShouldProcessForStateChangingFunctions' )

# Example: Scan a specific script
# Invoke-ScriptAnalyzer -Path $($PISecAuditRoot + '\Scripts\PISysAudit\' + 'PISYSAUDITCHECKLIB5' + '.psm1') -ExcludeRule $excludedRules 

# Scan all audit check modules
$libraries = @( 'PISYSAUDITCORE', 'PISYSAUDITCHECKLIB1', 'PISYSAUDITCHECKLIB2', 'PISYSAUDITCHECKLIB3', 'PISYSAUDITCHECKLIB4', 'PISYSAUDITCHECKLIB5' )
$libraryPath = $PISecAuditRoot + '\Scripts\PISysAudit\'
InvokePSScriptAnalysis $libraries $libraryPath $excludedRules $PISecAuditRoot

# Scan all utilities
$utilities = @( 'PISECCONFIGEXPORT', 'PIVISIONKERBEROSCONFIGURATION' )
$utilityPath = $PISecAuditRoot + '\Scripts\Utilities\'
InvokePSScriptAnalysis $utilities $utilityPath $excludedRules $PISecAuditRoot
