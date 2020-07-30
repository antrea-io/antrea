Param(
    [parameter(Mandatory = $false, HelpMessage="Stop kube-proxy")] [bool] $StopKubeProxy=$false
)

Write-Host "Stopping antrea-agent..."
taskkill /im antrea-agent.exe /f
if ($StopKubeProxy) {
    Write-Host "Stopping kube-proxy..."
    taskkill /im kube-proxy.exe /f
}
