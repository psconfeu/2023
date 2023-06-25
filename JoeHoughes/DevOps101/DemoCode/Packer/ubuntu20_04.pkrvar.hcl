//Defined User Variables
vsphere_datacenter      = "CastleRock"
vsphere_password        = "VMware123!"
vsphere_compute_cluster = "Lab"
vsphere_portgroup_name  = "CASTLEROCK-Prod"
vsphere_datastore       = "ESXi_AllFlash"
template_library_Name   = "ubu_20_04"
vm_name                 = "ubuntu20_04"
CPUs                    = "1"
RAM                     = "2048"
disk_size               = "25600"
firmware                = "bios"
vm_version              = "17"
notes                   = "Built via Packer"
guest_os_type           = "ubuntu64Guest"
ssh_username            = "linux_user"
ssh_password            = "VMware123!"
ssh_timeout             = "30m"
disk_controller_type    = ["pvscsi"]
os_iso_path             = "[ESXi_ISO] /Media/ubuntu-20.04.1-legacy-server-amd64.iso"
vmtools_iso_path        = "[ESXi_ISO] /Media/VMTools/linux.iso"
boot_wait               = "12s"
boot_command            = [
                            "<wait><wait><enter><wait><esc><wait><enter>",
                            "/install/vmlinuz",
                            " initrd=/install/initrd.gz<wait>",
                            " auto-install/enable=true",
                            " debconf/priority=critical",
                            " url=http://ububtudev.lab.fullstackgeek.net:80/boot_files/ubuntu2004/preseed.cfg",
                            " -- <wait>",
                            "<enter><wait>"
                        ]
config_files            = []
script_files            = ["scripts/update.sh"]