//  variables.pkr.hcl
variable "vsphere_server" {
  type    = string
  default = "corevcenter.lb.fullstackgeek.net"
  description = "vCenter Server"
}
variable "vsphere_user" {
  type      = string
  default   = "packer@vsphere.local"
  sensitive = true
}
variable "vsphere_password" {}
variable "insecure_connection" {
  type    = bool
  default = true
}
variable "vsphere_folder" {
  type    = string
  default = "Templates"
}
variable "vsphere_datacenter" {}
variable "vsphere_compute_cluster" {}
variable "vsphere_portgroup_name" {}
variable "vsphere_datastore" {}


variable "library_vm_destroy" {
  type    = bool
  default = true
}
variable "ovf" {
  type    = bool
  default = true
}
variable "vm_name" {}
variable "CPUs" {}
variable "RAM" {}
variable "disk_size" {}
variable "ram_reserve_all" {
  type    = bool
  default = true
}
variable "firmware" {}
variable "vm_version" {}
variable "notes" {}
variable "guest_os_type" {}
variable "boot_order" {
  type    = string
  default = "disk,cdrom"
}
variable "ssh_username" {}
variable "ssh_password" {}
variable "ssh_timeout" {}
variable "disk_controller_type" {}
variable "disk_thin_provisioned" {
  type    = bool
  default = true
}
variable "network_card" {
  type    = string
  default = "vmxnet3"
}

variable "os_iso_path" {}
variable "vmtools_iso_path" {}
variable "boot_wait" {}
variable "boot_command" {}
variable "config_files" {}
variable "script_files" {}