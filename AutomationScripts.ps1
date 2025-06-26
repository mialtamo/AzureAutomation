# Connect to Azure AD
Connect-AzAccount -Environment AzureUSGovernment
$context = Get-AzContext
$username = $context.Account
Write-Host "Signed-in username is: $username" -ForegroundColor DarkYellow
Connect-MgGraph -Scopes "User.Read.All" -Environment USGov

# Define Global Variables
$resourceGroupName = "AutomationTest-RSG"
$location = "usgovarizona"
$vnetName = "vnetauto"
$subnetName = "default"
$subscriptionId = ""
###############################

# Define APP REGISTRATION VARIABLES
$appName = "MyAppRegistrationTEST"
$CertName = "MyAppCert"
$ValidYears = 1  # You can set this to however many years you want
$Password = "P@ssword123!"  # Change to a secure password or pass it securely
$CertificatePath = "$env:TEMP"

# Define Key Vault Variables
$keyVaultName = "miaKVTEST123"  # Must be globally unique
$privateEndpointName = "TESTKV-PE"
$secretName = "MySecret"
$secretValue = "MySecretValue123!"

# Define APIM Variables
$apimServiceName = "my-apim-instance-TESTMIALTAMO"
$publisherEmail = "admin@example.com"
$publisherName = "MyCompany"
$skuName = "Premium"  # Use Basic, Standard, Premium as needed
$skuCapacity = 1
$apimNamedValueName = "keyvaultNamedValue"
$apimNamedValueDisplayName = "keyVaultNamedValueDisplayName"

# Define Automation Runbook Variables
$automationAccount = "myAutomationAccountTEST"
$runbookName = "MyRunbookTESTmia" # Must be globally unique
$runbookDescription = "This will create auto key rotation in Key Vault"
$scheduleName = "RunEvery90Days"
$runbookType = "PowerShell"  # Options: PowerShell, Graph, Python2, Python3
$runbookrunAs = "KeyVaultUpdatesRunAs"

$scriptContent = @"
$connectionName = "$runbookrunAs"
# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave –Scope Process
$connectionRB = Get-AutomationConnection -Name $connectionName
# Wrap authentication in retry logic for transient network failures
$logonAttempt = 0
while(!($connectionResult) -And ($logonAttempt -le 10))
{
    $LogonAttempt++
    # Logging in to Azure...
    $connectionResult = Connect-AzAccount -Environment AzureCloud -ServicePrincipal -Tenant $connectionRB.TenantID -ApplicationId $connectionRB.ApplicationID -CertificateThumbprint $connection.CertificateThumbprint}
###############################
#create Secret
$secret = -join ((48..57) + (65..90) + (97..122) + 126 | Get-Random -Count 43 | ForEach-Object { [char]$_ }); $secret
$secret
# Variables
`$resourceGroupRB = $resourceGroupName
`$keyVaultNameRB = $keyVaultName
`$secretNameRB = $secretName
`$expiryRB = (Get-Date).AddDays(90)
`$apimNameRB = $apimServiceName
`$apimNamedValueRB = $apimNamedValueName
`$subscriptionIdRB = $subscriptionId

# Check if the secret already exists
$existingSecret = Get-AzKeyVaultSecret -VaultName $keyVaultNameRB -Name $secretNameRB

if ($existingSecret) {
    Write-Output "[Key Vault] Secret '$secretNameRB' exists. Creating new version (rotating secret)..."
} else {
    Write-Output "[Key Vault] Secret '$secretNameRB' not found. Creating new secret..."
}

# Create or rotate the secret
$setSecret = Set-AzKeyVaultSecret -VaultName $keyVaultNameRB `
    -Name $secretNameRB `
    -SecretValue (ConvertTo-SecureString $secret -AsPlainText -Force) `
    -Expires $expiryRB

Write-Output "[Key Vault] Secret '$secretNameRB' set/rotated successfully."

# Get all versions and disable the old Ones
$allVersions = Get-AzKeyVaultSecret -VaultName "$keyVaultNameRB" -Name "$secretNameRB" -IncludeVersions
foreach ($secret in $allVersions) {
    if ($secret.Version -ne $setsecret.Version -and $secret.Enabled -eq $true) {
        Write-Output "Disabling version: $($secret.Version)"
        Set-AzKeyVaultSecretAttribute -VaultName $keyVaultNameRB -Name $secretNameRB -Version $secret.Version -Enable $false
    }
}
Write-host "[Key Vault] Successfully Disabled old versions."


# Update APIM to use the new Key

# Obtain an access token for Azure Resource Manager
$accessToken = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/").Token
$baseUri = "https://management.azure.com"
$path = "subscriptions/$subscriptionIdRB/resourceGroups/$resourceGroupRB/providers/Microsoft.ApiManagement/service/$apimNameRB/namedValues/$apimNamedValueRB/refreshSecret"
$apiVersion = "2024-05-01"
$accessToken

# Construct the REST API URL
$apiVersion = "2024-05-01"
$refreshUrl = "$($baseUri)/$($path)?api-version=$apiVersion"
$refreshUrl

# Invoke the REST API to refresh the secret
$response = Invoke-RestMethod -Method Post -Uri $refreshUrl -Headers @{
    Authorization = "Bearer $accessToken"
}
$response

Write-Host "[APIM] Successfully Updated API Management Access Keys""
"@

# Define Application Gateway Variables

$appGwName = "MyAppGateway"
$publicIPName = "MyAppGatewayPIP"
$subnetPrefix = "10.1.0.0/24"
$gwSubnetName = "default2"
$frontendPort = 443
$skuName = "WAF_v2"
$skuTier = "WAF_v2"
$capacity = 2
$backendPoolName = "mybackendPool123"
$frontendPortName = "myFrontEndPort123"
$frontendGWName = "myFrontGWName123"
$backendHTTPName = "BackendHTTPName123"
$gwListenerName = "ListenerName123"
$gwRoutingRuleName = "RoutingName123"
$GWpfxPath = "$CertificatePath\$CertName.pfx"
$GWpfxPassword = ConvertTo-SecureString -String "P@ssword123!" -AsPlainText -Force
$GWcertName = "MyAppCert"

##############################################################################

##############################################################################

##############################################################################

##############################################################################
#DO NOT MODIFY ANYTHING BELOW

##############################################################################

##############################################################################

$CertPath = "$CertificatePath\$CertName.pfx"
$pfxPath =  $CertPath
$cerPath = "$CertificatePath\$CertName.cer"

$createAR = Read-Host "Do you want to Create the App Registration? [Y/N]"

if ($createAR -in @("Y", "y")) {

Write-Host "[Start] Creating App Registration" -ForegroundColor DarkCyan
# Create the application
$app = New-AzADApplication -DisplayName $appName -AvailableToOtherTenants $false
#################################################################################

# Output the result
Write-Host "[RESULT] ✅ App registration created:" -ForegroundColor Green
Write-Host "[RESULT] ✅ App Name: $($app.DisplayName)" -ForegroundColor Green
Write-Host "[RESULT] ✅ App ID: $($app.AppId)" -ForegroundColor Green
Write-Host "[RESULT] ✅ Object ID: $($app.Id)" -ForegroundColor Green
Write-Host "[START] Generating Self Signed Certificate..." -ForegroundColor DarkCyan
#####################################################################################

# Define certificate subject and expiration
$certSubject = "CN=$CertName"
$certEndDate = (Get-Date).AddYears($ValidYears)

# Create the self-signed certificate in the user's Personal store
$cert = New-SelfSignedCertificate -Subject $certSubject `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy Exportable `
    -KeySpec Signature `
    -KeyLength 2048 `
    -HashAlgorithm "SHA256" `
    -NotAfter $certEndDate

# Export to a PFX file
$securePwd = ConvertTo-SecureString -String $Password -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $CertPath -Password $securePwd

# Output info
Write-Host "[RESULT] ✅ Certificate created and saved to: $CertPath" -ForegroundColor Green
Write-Host "[RESULT] ✅ Thumbprint: $($cert.Thumbprint)" -ForegroundColor Green
Write-Host "[RESULT] ✅ Valid until: $($cert.NotAfter)" -ForegroundColor Green
Write-Host "[Start] Creating CER file..." -ForegroundColor DarkCyan
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
$cert.Import($pfxPath, $securePwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
$certBase64 = [Convert]::ToBase64String($cert.RawData)

sleep 5
$updateApp = Get-MgApplication -Filter "DisplayName eq '$appName'"


Write-Host "[Start] Uploading Certificate to App Registration $appName" -ForegroundColor Green

$keyCredential = [Microsoft.Graph.PowerShell.Models.MicrosoftGraphKeyCredential]::new()
$keyCredential.Type = "AsymmetricX509Cert"
$keyCredential.Usage = "Verify"
$keyCredential.Key = $cert.RawData
$keyCredential.DisplayName = "$CertName"
$keyCredential.KeyId = [Guid]::NewGuid()
$keyCredential.StartDateTime = (Get-Date).ToUniversalTime()
$keyCredential.EndDateTime = $cert.NotAfter.ToUniversalTime()

Sleep 5
Update-MgApplication -ApplicationId $app.Id -KeyCredentials @($keyCredential)

Write-Host "[RESULT] ✅ Certificate uploaded successfully to $($app.DisplayName)" -ForegroundColor Green

}


# Start Create Key Vault
Sleep 1
$createKV = Read-Host "Do you want to create the Key Vault? [Y/N]"
if ($createKV -in @("Y", "y")) {
Write-Host "[START] Creating Key Vault" -ForegroundColor DarkCyan
$keyVault = New-AzKeyVault -Name $keyVaultName -ResourceGroupName $resourceGroupName -Location $location -Sku Premium -PublicNetworkAccess Enabled
Write-Host "[RESULT] ✅ Key Vault Created" -ForegroundColor Green

#Grant Secret Officer Access to Key Vault
$user = Get-AzADUser -UserPrincipalName $username.id
New-AzRoleAssignment -ObjectId $user.Id -RoleDefinitionName "Key Vault Secrets Officer" -Scope $keyvault.ResourceId | Out-Null

# Create Secret
Set-AzKeyVaultSecret -VaultName $keyVaultName -Name $secretName -SecretValue (ConvertTo-SecureString $secretValue -AsPlainText -Force)


#################################
#  Create Private Endpoint
#################################


Write-Host "[START] Creating Private Endpoint" -ForegroundColor DarkCyan
$subnet = Get-AzVirtualNetworkSubnetConfig -Name $subnetName -VirtualNetwork (Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $resourceGroupName)

# Create a Private Endpoint for Key Vault
$peConnection = @{
    Name = $privateEndpointName
    ResourceGroupName = $resourceGroupName
    Location = $location
    Subnet = $subnet
    PrivateLinkServiceConnection = @(
        @{
            Name = "kv-link"
            PrivateLinkServiceId = $keyVault.ResourceId
            GroupIds = @("vault")
        }
    )
}

$kvPE = New-AzPrivateEndpoint @peConnection
Write-Host "[RESULT] ✅ IP Address is: $($kvPE.CustomDnsConfigs[0].IpAddresses[0])" -ForegroundColor Green
Write-Host "[RESULT] ✅ FQDN is: $($kvPE.CustomDnsConfigs[0].Fqdn)" -ForegroundColor Green


Update-AzKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -PublicNetworkAccess "Enabled" | Out-Null

Write-Host "[RESULT] ✅ Key Vault '$keyVaultName' created with Private Endpoint and secret '$secretName' added." -ForegroundColor Green
}

$createAPIM = Read-Host "Do you want to create API Management? [Y/N]"

if ($createAPIM -in @("Y", "y")) {
Write-Host "[START] Creating API Management instance..." -ForegroundColor DarkCyan
$apimDetails = New-AzApiManagement -ResourceGroupName $resourceGroupName -Location $location -Name $apimServiceName -Organization $publisherName -AdminEmail $publisherEmail -Sku $skuName -Capacity $skuCapacity
Sleep 6
Write-Host "[RESULT] ✅ API Management Service created Successfully." -ForegroundColor Green
sleep 6
Set-AzApiManagement -InputObject $apimDetails -SystemAssignedIdentity
$apimUpdatedDetails = Get-AZApiManagement -ResourceGroupName $resourceGroupName -Name $apimServiceName

Write-Host "[START] Granting APIM access to Key Vault Secrets as Reader" -ForegroundColor DarkCyan
New-AzRoleAssignment -ObjectId $apimUpdatedDetails.Identity.PrincipalId -RoleDefinitionName "Key Vault Secrets User" -Scope $keyVault.ResourceId
Write-Host "[RESULT] ✅ API Management Service created Successfully." -ForegroundColor Green
Write-Host "[START] Creating Named Value in API Management"

$apimContext = New-AzApiManagementContext -ResourceGroupName $resourceGroupName -ServiceName $apimServiceName
$keyVaultSecretUri = "$($keyVault.VaultUri)secrets/$secretName"  # This is the full Key Vault secret URI

$keyvaultDetails = New-AzApiManagementKeyVaultObject -SecretIdentifier $keyVaultSecretUri
$keyVaultNamedValue = New-AzApiManagementNamedValue -Context $apimcontext -NamedValueId $apimNamedValueName -Name $apimNamedValueDisplayName -keyVault $keyVaultDetails -Secret
Write-Host "[RESULT] ✅ Named Value Created Successfully" -ForegroundColor Green
Update-AzKeyVault -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -PublicNetworkAccess "Disabled" |Out-Null
}


$createRB = Read-Host "Do you want to create the Automation Runbook? [Y/N]"

if ($createRB -in @("Y", "y")) {

#Create Automation Account
Write-Host "[START] Creating Automation Runbook Account" -ForegroundColor DarkCyan

$AutomationAccountDetails = New-AzAutomationAccount -ResourceGroupName $resourceGroupName -Name $automationAccount -Location $location | Out-Null
Write-Host "[RESULT] ✅ Created Automation Runbook Account $($AutomationAccountDetails.AutomationAccountName)" -ForegroundColor Green
sleep 1
Write-Host "[START] Creating Automation Runbook" -ForegroundColor DarkCyan
New-AzAutomationRunbook -AutomationAccountName $automationAccount -ResourceGroupName $resourceGroupName -Name $runbookName -Type $runbookType -Description $runbookDescription
Write-Host "[RESULT] ✅ Created Automation Runbook" -ForegroundColor Green

Write-Host "[START] Creating RunBook Connection Details" -ForegroundColor DarkCyan
$uploadCertRunBook = New-AzAutomationCertificate -ResourceGroupName $resourceGroupName -AutomationAccountName $automationAccount -Name $CertName -Path $CertPath -Password (ConvertTo-SecureString -String $Password -AsPlainText -Force) -Exportable
New-AzAutomationConnection -ResourceGroupName $resourceGroupName -AutomationAccountName $automationAccount -Name $runbookrunAs -ConnectionTypeName "AzureServicePrincipal" -ConnectionFieldValues @{ "ApplicationId" = $app.AppId; "TenantId" = (Get-AzContext).Tenant.Id; "CertificateThumbprint" = $uploadCertRunBook.Thumbprint; "SubscriptionId" = $subscriptionId }
Write-Host "[RESULT] ✅ Created Automation Runbook Connection Details" -ForegroundColor Green
sleep 5
Write-Host "[START] Creating RunBook Powershell script" -ForegroundColor DarkCyan

$tempPathPS = "$env:TEMP\TempRunbook.ps1"
$scriptContent | Out-File -FilePath $tempPathPS -Encoding UTF8 -Force

# Re-import it into the runbook (overwrites draft)
Import-AzAutomationRunbook -AutomationAccountName $automationAccount -ResourceGroupName $resourceGroupName -Name $runbookName -Path $tempPathPS -Type PowerShell -Force
Write-Host "[RESULt] ✅ Syccessfully uploaded PS Script to the automation Runbook" -ForegroundColor Green
}

$createGW = Read-Host "Do you want to create the Application Gateway? [Y/N]"

if ($createGW -in @("Y", "y")) {
Write-Host "[START] Creating Public IP for App Gateway" -ForegroundColor DarkCyan
# Create Public IP
$publicIPGW = New-AzPublicIpAddress -Name $publicIPName -ResourceGroupName $resourceGroupName -Location $location -AllocationMethod Static -Sku Standard
$vnetGW = Get-AzVirtualNetwork -Name $vnetName -ResourceGroupName $resourceGroupName
$subnetGW = Get-AzVirtualNetworkSubnetConfig -Name $gwSubnetName -VirtualNetwork $vnetGW
$gwIPConfig = New-AzApplicationGatewayIPConfiguration -Name "appGwIpConfig" -Subnet $subnetGW
Write-Host "[RESULT] ✅ Successfully Created Public IP for App Gateway" -ForegroundColor Green

# Create Frontend IP Configuration
Write-Host "[START] Creating App Gateway Configuration Details" -ForegroundColor DarkCyan
$frontendIP = New-AzApplicationGatewayFrontendIPConfig -Name $frontendGWName -PublicIPAddress $publicIPGW

# Create Frontend Port
$frontendPortConfig = New-AzApplicationGatewayFrontendPort -Name $frontendPortName -Port $frontendPort

# Create Backend Address Pool
$backendPoolGW = New-AzApplicationGatewayBackendAddressPool -Name $backendPoolName

# Create Backend HTTP Settings
$backendHTTPSettings = New-AzApplicationGatewayBackendHttpSettings -Name $backendHTTPName -Port $frontendPort -Protocol Https -CookieBasedAffinity Disabled

# Upload SSL Certificate
$sslCertGW = New-AzApplicationGatewaySslCertificate -Name $GWcertName -CertificateFile $GWpfxPath -Password $GWpfxPassword


# Create Listener
$listener = New-AzApplicationGatewayHttpListener -Name $gwListenerName -FrontendIPConfiguration $frontendIP -FrontendPort $frontendPortConfig -Protocol Https -SslCertificate $sslCertGW

# Create Rule
$rule = New-AzApplicationGatewayRequestRoutingRule -Name $gwRoutingRuleName -RuleType Basic -HttpListener $listener -BackendAddressPool $backendPoolGW -BackendHttpSettings $backendHTTPSettings -Priority 100

# Create WAF Config
$wafConfig = New-AzApplicationGatewayWebApplicationFirewallConfiguration -Enabled $true -FirewallMode "Prevention" -RuleSetType "OWASP" -RuleSetVersion "3.2"

Write-Host "[RESULT] ✅ Successfully Created Configuration file for App Gateway" -ForegroundColor Green

Write-Host "[START] Creating App Gateway" -ForegroundColor DarkCyan

# Create Application Gateway
$appGw = New-AzApplicationGateway -Name $appGwName -ResourceGroupName $resourceGroupName -Location $location `
  -BackendAddressPools $backendPoolGW -BackendHttpSettingsCollection $backendHTTPSettings `
  -FrontendIPConfigurations $frontendIP -FrontendPorts $frontendPortConfig `
  -GatewayIPConfigurations $gwIPConfig -HttpListeners $listener -RequestRoutingRules $rule `
  -Sku @{Name=$skuName; Tier=$skuTier; Capacity=$capacity} -WebApplicationFirewallConfig $wafConfig -SslCertificates $sslCertGW

Write-Host "[RESULT] ✅ Successfully Created Application Gateway" -ForegroundColor Green

}

sleep 2
Write-Host "[END] ✅✅✅✅✅✅✅✅✅✅" -ForegroundColor DarkGreen
Write-Host "[END] ✅ SUCCESSFULLY FINISHED ✅" -ForegroundColor DarkGreen
