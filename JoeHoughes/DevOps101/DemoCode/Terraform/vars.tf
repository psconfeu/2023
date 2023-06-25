# vsphere login account. defaults to admin account
variable "vsphere_user" {
  default = "administrator@vsphere.local"
}

# vsphere account password. empty by default.
variable "vsphere_password" {
  default = "<my vCenter Server Password>"
}

# vsphere server, defaults to localhost
variable "vsphere_server" {
  default = "corevcenter.fsglab.local"
}

# vsphere datacenter the virtual machine will be deployed to. empty by default.
variable "vsphere_datacenter" {}

# vsphere resource pool the virtual machine will be deployed to. empty by default.
variable "vsphere_resource_pool" {}

# vsphere datastore the virtual machine will be deployed to. empty by default.
variable "vsphere_datastore" {}

# vsphere cluster the virtual machine will be deployed to. empty by default.
variable "vsphere_cluster" {}

# vsphere network the virtual machine will be connected to. empty by default.
variable "vsphere_network" {}

# vsphere network the VM will be deployed to. empty by default.
#variable "vsphere_host" {}

# the name of the folder to place the virtual machine in. empty by default.
variable "vsphere_virtual_machine_folder" {}

variable "vsphere_template_name" {}

#details for guest VM
variable "vsphere_virtual_machine_name" {}
variable "vsphere_virtual_machine_cpus" {}
variable "vsphere_virtual_machine_memory" {}