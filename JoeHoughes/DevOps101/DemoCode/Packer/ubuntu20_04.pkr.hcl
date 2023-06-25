source "vsphere-iso" "ubuntu20_04" {
  CPUs            = var.CPUs
  RAM             = var.RAM
  RAM_reserve_all = var.ram_reserve_all
  boot_command    = var.boot_command
  boot_order      = var.boot_order
  boot_wait       = var.boot_wait
  cluster         = var.vsphere_compute_cluster
  content_library_destination {
    destroy = var.library_vm_destroy
    library = var.content_library_destination
    name    = var.template_library_Name
    ovf     = var.ovf
  }
  datacenter           = var.vsphere_datacenter
  datastore            = var.vsphere_datastore
  disk_controller_type = var.disk_controller_type
  firmware             = var.firmware
  floppy_files             = var.config_files
  folder               = var.vsphere_folder
  guest_os_type        = var.guest_os_type
  insecure_connection  = var.insecure_connection
  iso_paths = [var.os_iso_path,var.vmtools_iso_path]
  network_adapters {
    network      = var.vsphere_portgroup_name
    network_card = var.network_card
  }
  notes        = var.notes
  password     = var.vsphere_password
  ssh_password = var.ssh_password
  ssh_timeout  = var.ssh_timeout
  ssh_username = var.ssh_username
  storage {
    disk_size             = var.disk_size
    disk_thin_provisioned = var.disk_thin_provisioned
  }
  username       = var.vsphere_user
  vcenter_server = var.vsphere_server
  vm_name        = var.vm_name
  vm_version     = var.vm_version
}

build {
  name    = "Ubuntu 20.04"
  sources = ["source.vsphere-iso.ubuntu20_04"]

  provisioner "shell" {
    execute_command = "echo '${"var.ssh_password"}' | sudo -S -E sh -eux '{{ .Path }}'"
    scripts         = var.script_files
  }

  post-processor "manifest" {
    output = "output/out-ubuntu20_04.json"
    strip_path = false
  }
}