sudo dmesg -C
sudo insmod myhypervisor.ko
sudo dmesg -t | grep -e VMLAUNCH
sudo rmmod myhypervisor