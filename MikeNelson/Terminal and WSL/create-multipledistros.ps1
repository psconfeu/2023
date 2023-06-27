workflow test-workflow1
{
$VMNames =@(1..4)
ForEach -Parallel ($VM in $VMNames)
{
$VM = "demovm"+$VM
New-WslInstance -Version 2 -NoUpdate -InstanceName $VM
}
}