<#
.SYNOPSIS
Clean OVS bridge and HnsNetwork created by Antrea Agent
#>

function GetHnsnetworkId($NetName) {
    $NetList= $(Get-HnsNetwork -ErrorAction SilentlyContinue)
    if ($NetList -eq $null) {
        return $null
    }
    foreach ($Net in $NetList) {
        if ($Net.Name -eq $NetName) {
            return $Net.Id
        }
    }
    return $null
}
$AntreaHnsNetworkName = "antrea-hnsnetwork"

Write-Host "Delete OVS bridge: br-int"
ovs-vsctl.exe --no-wait --if-exists del-br br-int
$MaxRetryCount = 10
$RetryCountRange = 1..$MaxRetryCount
$BrIntDeleted = $false
foreach ($RetryCount in $RetryCountRange) {
    Write-Host "Waiting for OVS bridge deletion complete ($RetryCount/$MaxRetryCount)..."
    $BrIntAdapter = $(Get-NetAdapter br-int -ErrorAction SilentlyContinue)
    if ($BrIntAdapter -eq $null) {
        $BrIntDeleted = $true
        break
    }
    if ($RetryCount -eq $MaxRetryCount) {
        break
    }
    Start-Sleep -Seconds 5
}
if (!$BrIntDeleted) {
    Write-Host "Failed to delete OVS Bridge, please retry the script or delete the bridge and HNS network manually."
    return
}


$NetId = GetHnsnetworkId($AntreaHnsNetworkName)
if ($NetId -ne $null) {
    Write-Host "Remove HnsNetwork: $AntreaHnsNetworkName"
    Get-HnsNetwork -Id $NetId | Remove-HnsNetwork
}
