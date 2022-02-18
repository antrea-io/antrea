#!/bin/bash
# Copyright 2022 Antrea Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This scripts create vfs on the interface and switch them to switchdev mode
# it accepts two parameters, the first is the name of the interface and the
# second is the number of vfs

set -o pipefail

interface=""
vfs_num=""

vendor_id=""
vfs_pci_list=""
interface_pci=""
nm_managed="false"

udev_rule_file='/etc/udev/rules.d/80-persistent-vf-config.rules'


##################################################
##################################################
##################   input   #####################
##################################################
##################################################


while test $# -gt 0; do
  case "$1" in

   --interface | -i)
      interface=$2
      shift
      shift
      ;;

   --vfs | -v)
      vfs_num=$2
      shift
      shift
      ;;

   --nm-managed)
      nm_managed="true"
      shift
      ;;

   --help | -h)
      echo "
switchdev_setup.sh -i <interface> -v <number of vfs>: create vfs on the \
specified interface and switch them to switchdev mode.

options:

	--interface | -i) <interface>			The interface to \
enable the switchdev mode on.

        --vfs-num | -v) <vfs number>			The number of vfs \
to create on the interface.

	--nm-managed)					An option to manage \
the vfs by the network manager. By default the vfs will be set to not be managed \
by the network manager.

"
      exit 0
      ;;

   *)
      echo "No such option!!"
      echo "Exitting ...."
      exit 1
  esac
done

set -x
exec 1> >(logger -s -t $(basename $0)) 2>&1


##################################################
##################################################
###############   Functions   ####################
##################################################
##################################################


check_interface(){
   if [[ ! -d /sys/class/net/"$interface" ]]
   then
      echo "ERROR: No interface named $interface exist on the machine, \
please check the interface name spelling, or make sure the \
interface really exist."
      echo "Exiting ...."
      exit 1
   fi
}

check_vendor(){
   vendor_id=$(cat /sys/class/net/"$interface"/device/vendor)
   if [[ "$vendor_id" != "0x15b3" ]]
   then
      echo "ERROR: the card is not a Mellanox product!!"
      echo "Exiting ...."
      exit 1
   fi
}

configure_vfs(){
   if [ $(cat /sys/class/net/"$interface"/device/sriov_numvfs) != "0" ]
   then
      echo 0 > /sys/class/net/"$interface"/device/sriov_numvfs
      sleep 2
   fi
   echo "$vfs_num" > /sys/class/net/"$interface"/device/sriov_numvfs
}

unbind_vfs(){
   vfs_pci_list=$(grep PCI_SLOT_NAME /sys/class/net/"$interface"/device/virtfn*/uevent | cut -d'=' -f2)
   for pci in $vfs_pci_list
   do
      echo "$pci" > /sys/bus/pci/drivers/mlx5_core/unbind
   done
}

enable_switchdev(){
   interface_pci=$(grep PCI_SLOT_NAME /sys/class/net/"$interface"/device/uevent\
                  | cut -d'=' -f2 -s)
   /usr/sbin/devlink dev eswitch set pci/"$interface_pci" mode switchdev
}

bind_vfs(){
   for pci in $vfs_pci_list
   do
      echo "$pci" > /sys/bus/pci/drivers/mlx5_core/bind
   done
}

check_switchdev(){
   if [[ "$(/usr/sbin/devlink dev eswitch show pci/"$interface_pci")" =~ "mode switchdev" ]]
   then
      echo "PCI device $interface_pci set to mode switchdev."
   else
      echo "Failed to set PCI device $interface_pci to switchdev mode."
      exit 1
   fi
}

check_vfs_num(){
   if [[ $(ls -l /sys/class/net/"$interface"/device/virtfn[0-9]* | wc -l) != "$vfs_num" ]]
   then
      echo "ERROR: No vfs created. unexpected error encountered."
      echo "Exiting ...."
      exit 1
   fi
}

##################################################
##################################################
##############   validation   ####################
##################################################
##################################################


if [[ -z "$interface" ]]
then
   echo "No interface was provided, please provide one using the \
--interface or the -i options."
   echo "Exiting ...."
   exit 1
fi

if [[ -z "$vfs_num" ]]
then
   echo "The number of vfs was not specified, please specify it using the \
--vfs or -v options."
   echo "Exiting ...."
   exit 1
fi

check_interface

check_vendor


##################################################
##################################################
####################   MAIN   ####################
##################################################
##################################################

set -e

configure_vfs

unbind_vfs

enable_switchdev

bind_vfs

/usr/sbin/ifup "$interface"

check_switchdev

check_vfs_num

