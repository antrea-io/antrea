Param(
    [parameter(Mandatory = $false)] [ValidateSet("enable", "disable")] [string] $VMSwitchExtension = "disable"
)
$networkName = "antrea-hnsnetwork"
$net=$(Get-HnsNetwork | Where-Object {$_.Name -eq $networkName})
if ($net -ne $null) {
    switch ($VMSwitchExtension)
    {
        "enable" {
            Enable-VMSwitchExtension -Name "Open vSwitch Extension" -VMSwitchName $networkName
        }
        "disable" {
            Disable-VMSwitchExtension -Name "Open vSwitch Extension" -VMSwitchName $networkName
        }
    }
}
