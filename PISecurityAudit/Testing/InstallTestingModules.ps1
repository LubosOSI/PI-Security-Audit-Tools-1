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

#region - Parameters declaration.

$testingModules = @( 'PSScriptAnalyzer', 'Pester' )

#endregion

#region - Internal Helper Functions

function InstallTestingModule ($moduleName)
{	
	$moduleObj = $null
	$moduleObj = Get-InstalledModule -Name $moduleName -ErrorAction 'SilentlyContinue'
	if($moduleObj -eq $null)
	{
		# Install the PSScriptAnalyzer module for all users on this computer.
		Install-Module -Name $moduleName -Repository 'PSGallery' -Scope 'AllUsers'
	}
	else
	{
		$msg = '{0} module {1} is already installed' -f $moduleName, $moduleObj.Version.ToString()
		Write-Host $msg
	}
}

#endregion

#region - Main routine

try
{
	# Try to import PowerShellGet module.
	$moduleObj = $null
	$moduleObj = Import-Module 'PowerShellGet' -PassThru
	if($moduleObj -eq $null)
	{
		$msg = 'PowerShellGet module is not installed on this machine'
		Throw $msg
	}

	# Try to retrieve the PSGallery repository.
	$repositoryObj = $null
	$repositoryObj = Get-PSRepository -Name 'PSGallery'

	if($repositoryObj -eq $null)
	{
		# Register the PowerShell Gallery.
		Register-PSRepository -Name 'PSGallery' -SourceLocation 'https://www.powershellgallery.com/api/v2/' -InstallationPolicy 'Trusted'
	}
	else
	{
		# Validate the PSGallery repository.
		if($repositoryObj.InstallationPolicy -notmatch '^trusted$')
		{
			$msg = 'The PSGallery is not trusted'
			Throw $msg
		}

		if($repositoryObj.SourceLocation -notmatch '^https://www\.powershellgallery\.com/api/v2/$')
		{
			$msg = 'The PSGallery location is incorrect'
			Throw $msg
		}
	}

	foreach ($testingModule in $testingModules) { InstallTestingModule $testingModule }

}
catch
{ Throw }

#endregion