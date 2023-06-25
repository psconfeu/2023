function Get-VMData {
  param()

  Begin {
    [System.Collections.ArrayList]$AllVMsOutput = @()
    [System.Collections.ArrayList]$AllDisksOutput = @()
  }

  Process {
    $CollectedVMs = Get-View -ViewType VirtualMachine

    #region CollectedVMs

    foreach ($EachVM in $CollectedVMs) {

      $VMOutputResult = [pscustomobject][ordered] @{
        'VM'                = $EachVM.Name
        'PowerState'        = $EachVM.Summary.Runtime.PowerState
        'DNSName'           = $EachVM.Guest.HostName
        'IPAddress'         = $EachVM.Guest.IpAddress
        'HWVersion'         = $EachVM.Config.Version
        'GuestOSVMTools'    = $EachVM.Guest.GuestFullName
        'GuestOSConfigFile' = $EachVM.Config.GuestFullName
        'GuestFamily'       = $EachVM.Guest.GuestFamily
        'CPUSockets'        = $EachVM.Config.Hardware.NumCPU
        'CPUCores'          = ($EachVM.Config.Hardware.NumCoresPerSocket * $EachVM.Config.Hardware.NumCPU)
        'IsUseMB'           = $EachVM.Summary.Storage.Committed
        'ProvisionedMB'     = ($EachVM.Summary.Storage.Committed + $EachVM.Summary.Storage.Uncommitted)
        'UnsharedMB'        = $EachVM.Summary.Storage.Unshared
        'Memory'            = $EachVM.Config.Hardware.MemoryMB
        'VMToolsStatus'     = $EachVM.Guest.ToolsStatus
        'CBT'               = $EachVM.Config.ChangeTrackingEnabled
        'Snapshot'          = [bool]$EachVM.Snapshot
        'Template'          = $EachVM.Config.Template
        'Path'              = $EachVM.Summary.Config.VmPathName
        'ID'                = $EachVM.MoRef.Value
        'vCenter'           = $(($EachVM.Client.ServiceUrl -replace 'https://', '') -replace '/sdk', '')
      }

      $AllVMsOutput.Add($VMOutputResult) | Out-Null

      $vDisk = $EachVM.Config.Hardware.Device | Where-Object { $_.GetType() -like '*VirtualDisk' }

      foreach ($EachDisk in $vDisk) {
        $VMDiskOutputResult = [pscustomobject][ordered] @{
          'VM'         = $EachVM.Name
          'PowerState' = $EachVM.Summary.Runtime.PowerState
          'Template'   = $EachVM.Config.Template
          'Disk'       = $EachDisk.DeviceInfo.Label
          'CapacityMB' = ($EachDisk.CapacityInKB / 1024)
          'Raw'        = [bool]($($EachDisk.Backing.GetType().Name) -eq 'VirtualDiskRawDiskMappingVer1BackingInfo')
          'DiskMode'   = $EachDisk.Backing.DiskMode
          'Path'       = $EachDisk.Backing.FileName
          'Host'       = $Esx.Name
          'vCenter'    = $(($EachVM.Client.ServiceUrl -replace 'https://', '') -replace '/sdk', '')
        }

        $AllDisksOutput.Add($VMDiskOutputResult) | Out-Null
      }

    }

    $AllVMsOutput | Export-Csv .\Output\VMResults.csv -NoTypeInformation

    $AllDisksOutput | Export-Csv .\Output\VMDiskResults.csv -NoTypeInformation

    #endregion CollectedVMs


  }

  End { }
}

