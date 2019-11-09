#!/bin/bash 

# This is the FriendlyARM NanoPi Duo Kali ARM build script - http://nanopi.io/
# A trusted Kali Linux image created by Offensive Security - http://www.offensive-security.com

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

if [[ $# -eq 0 ]] ; then
    echo "Please pass version number, e.g. $0 2.0"
    exit 0
fi

basedir=`pwd`/nanopiduo-$1

# Custom hostname variable
hostname=${2:-kali}
# Custom image file name variable - MUST NOT include .img at the end.
imagename=${3:-kali-linux-$1-nanopiduo}
# Size of image in megabytes (Default is 4000=4G)
size=4000

# Generate a random machine name to be used.
machine=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)

# Make sure that the cross compiler can be found in the path before we do
# anything else, that way the builds don't fail half way through.
export CROSS_COMPILE=arm-linux-gnueabihf-
if [ $(compgen -c $CROSS_COMPILE | wc -l) -eq 0 ] ; then
    echo "Missing cross compiler. Set up PATH according to the README"
    exit 1
fi
# Unset CROSS_COMPILE so that if there is any native compiling needed it doesn't
# get cross compiled.
#unset CROSS_COMPILE

# Package installations for various sections.
# This will build a minimal XFCE Kali system with the top 10 tools.
# This is the section to edit if you would like to add more packages.
# See http://www.kali.org/new/kali-linux-metapackages/ for meta packages you can
# use. You can also install packages, using just the package name, but keep in
# mind that not all packages work on ARM! If you specify one of those, the
# script will throw an error, but will still continue on, and create an unusable
# image, keep that in mind.

arm="abootimg cgpt fake-hwclock ntpdate u-boot-tools vboot-utils vboot-kernel-utils"
base="apt-transport-https apt-utils console-setup dialog e2fsprogs firmware-linux firmware-realtek firmware-atheros firmware-libertas ifupdown initramfs-tools iw kali-defaults man-db mlocate netcat-traditional net-tools parted psmisc rfkill screen snmpd snmp sudo tftp tmux unrar usbutils vim wget whiptail zerofree"
#desktop="kali-menu fonts-croscore fonts-crosextra-caladea fonts-crosextra-carlito gnome-theme-kali gtk3-engines-xfce kali-desktop-xfce kali-root-login lightdm network-manager network-manager-gnome xfce4 xserver-xorg-video-fbdev xfce4-terminal firefox-esr"
tools="aircrack-ng crunch cewl dnsrecon dnsutils ethtool exploitdb hydra john libnfc-bin medusa metasploit-framework mfoc ncrack nmap passing-the-hash proxychains recon-ng sqlmap tcpdump theharvester tor tshark usbutils whois windows-binaries winexe wpscan"
services="apache2 atftpd haveged openssh-server openvpn"
extras="bluetooth libnss-systemd network-manager psmisc wpasupplicant xfonts-terminus"

packages="${arm} ${base} ${services}"
architecture="armhf"
# If you have your own preferred mirrors, set them here.
# After generating the rootfs, we set the sources.list to the default settings.
mirror=http.kali.org

# Set this to use an http proxy, like apt-cacher-ng, and uncomment further down
# to unset it.
#export http_proxy="http://localhost:8080/"

mkdir -p ${basedir}
cd ${basedir}

# create the rootfs - not much to modify here, except maybe the hostname.
debootstrap --foreign  --keyring=/usr/share/keyrings/kali-archive-keyring.gpg --include=kali-archive-keyring --arch ${architecture} kali-rolling kali-${architecture} http://${mirror}/kali

#I don't why this dir disappeared so just create it
#mkdir -p kali-${architecture}/usr/bin/
cp /usr/bin/qemu-arm-static kali-${architecture}/usr/bin/

# The machine name is a randomly generated 16 character string.
LANG=C systemd-nspawn -M ${machine} -D kali-${architecture} /debootstrap/debootstrap --second-stage
mkdir -p kali-${architecture}/etc/apt/
cat << EOF > kali-${architecture}/etc/apt/sources.list
deb http://${mirror}/kali kali-rolling main contrib non-free
EOF

echo "${hostname}" > kali-${architecture}/etc/hostname

cat << EOF > kali-${architecture}/etc/hosts
127.0.0.1       ${hostname}    localhost
::1             localhost ip6-localhost ip6-loopback
fe00::0         ip6-localnet
ff00::0         ip6-mcastprefix
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
EOF

mkdir -p kali-${architecture}/etc/network
cat << EOF > kali-${architecture}/etc/network/interfaces
auto lo
iface lo inet loopback

# This prevents NetworkManager from attempting to use this
# device to connect to wifi, since NM doesn't show which device is which.
# Unfortunately, it still SHOWS the device, just that it's not managed.
iface p2p0 inet manual
EOF

cat << EOF > kali-${architecture}/etc/resolv.conf
nameserver 8.8.8.8
EOF

export MALLOC_CHECK_=0 # workaround for LP: #520465
export LC_ALL=C
export DEBIAN_FRONTEND=noninteractive

#mount -t proc proc kali-${architecture}/proc
#mount -o bind /dev/ kali-${architecture}/dev/
#mount -o bind /dev/pts kali-${architecture}/dev/pts

cat << EOF > kali-${architecture}/debconf.set
console-common console-data/keymap/policy select Select keymap from full list
console-common console-data/keymap/full select en-latin1-nodeadkeys
EOF

mkdir -p kali-${architecture}/usr/lib/systemd/system
cat << 'EOF' > kali-${architecture}/usr/lib/systemd/system/regenerate_ssh_host_keys.service
[Unit]
Description=Regenerate SSH host keys
Before=ssh.service
[Service]
Type=oneshot
ExecStartPre=-/bin/dd if=/dev/hwrng of=/dev/urandom count=1 bs=4096
ExecStartPre=-/bin/sh -c "/bin/rm -f -v /etc/ssh/ssh_host_*_key*"
ExecStart=/usr/bin/ssh-keygen -A -v
ExecStartPost=/bin/sh -c "for i in /etc/ssh/ssh_host_*_key*; do actualsize=$(wc -c <\"$i\") ;if [ $actualsize -eq 0 ]; then echo size is 0 bytes ; exit 1 ; fi ; done ; /bin/systemctl disable regenerate_ssh_host_keys"
[Install]
WantedBy=multi-user.target
EOF
chmod 644 kali-${architecture}/usr/lib/systemd/system/regenerate_ssh_host_keys.service

cat << EOF > kali-${architecture}/usr/lib/systemd/system/smi-hack.service
[Unit]
Description=shared-mime-info update hack
Before=regenerate_ssh_host_keys.service
[Service]
Type=oneshot
Environment=DEBIAN_FRONTEND=noninteractive
ExecStart=/bin/sh -c "rm -rf /etc/ssl/certs/*.pem && dpkg -i /root/ca-certificates*all.deb /root/fontconfig*armhf.deb /root/libgdk-pixbuf*armhf.deb"
ExecStart=/bin/sh -c "dpkg-reconfigure shared-mime-info"
ExecStart=/bin/sh -c "dpkg-reconfigure xfonts-base"
ExecStart=/bin/sh -c "rm -f /root/*.deb"
ExecStartPost=/bin/systemctl disable smi-hack

[Install]
WantedBy=multi-user.target
EOF
chmod 644 kali-${architecture}/usr/lib/systemd/system/smi-hack.service

cat << EOF > kali-${architecture}/usr/lib/systemd/system/rpiwiggle.service
[Unit]
Description=Resize filesystem
After=regenerate_ssh_host_keys.service
[Service]
Type=oneshot
ExecStart=/root/scripts/rpi-wiggle.sh
ExecStartPost=/bin/systemctl disable rpiwiggle
[Install]
WantedBy=multi-user.target
EOF
chmod 644 kali-${architecture}/usr/lib/systemd/system/rpiwiggle.service



cat << EOF > kali-${architecture}/third-stage
#!/bin/bash
set -e
dpkg-divert --add --local --divert /usr/sbin/invoke-rc.d.chroot --rename /usr/sbin/invoke-rc.d
cp /bin/true /usr/sbin/invoke-rc.d
echo -e "#!/bin/sh\nexit 101" > /usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d

apt-get update
apt-get --yes --allow-change-held-packages install locales-all

debconf-set-selections /debconf.set
rm -f /debconf.set
apt-get update
apt-get -y install git-core binutils ca-certificates initramfs-tools u-boot-tools
apt-get -y install locales console-common less nano git
echo "root:toor" | chpasswd
rm -f /etc/udev/rules.d/70-persistent-net.rules
export DEBIAN_FRONTEND=noninteractive
# This looks weird, but we do it twice because every so often, there's a failure to download from the mirror
# So to workaround it, we attempt to install them twice.
apt-get --yes --allow-change-held-packages install ${packages} || apt-get --yes --fix-broken install
apt-get --yes --allow-change-held-packages install ${packages} || apt-get --yes --fix-broken install
apt-get --yes --allow-change-held-packages install ${desktop} ${extras} ${tools} || apt-get --yes --fix-broken install
apt-get --yes --allow-change-held-packages install ${desktop} ${extras} ${tools} || apt-get --yes --fix-broken install
apt-get --yes --allow-change-held-packages dist-upgrade
apt-get --yes --allow-change-held-packages autoremove

# Because copying in authorized_keys is hard for people to do, let's make the
# image insecure and enable root login with a password.
sed -i -e 's/PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Regenerated the shared-mime-info database on the first boot
# since it fails to do so properly in a chroot.
systemctl enable smi-hack

# Resize FS on first run (hopefully)
systemctl enable rpiwiggle

# Generate SSH host keys on first run
systemctl enable regenerate_ssh_host_keys
systemctl enable ssh

# There's no graphical output on this device so
systemctl set-default multi-user

# Copy over the default bashrc
cp  /etc/skel/.bashrc /root/.bashrc

cd /root
apt download ca-certificates
apt download libgdk-pixbuf2.0-0
apt download fontconfig

# Enable bluetooth - we do this way because we haven't written a systemd service
# file for it yet.
#update-rc.d brcm_patchram_plus defaults

# Because they have it in the system image, lets go ahead and clone these as
# well.
cd /root
git clone --depth 1 https://github.com/friendlyarm/WiringNP
git clone --depth 1 https://github.com/auto3000/RPi.GPIO_NP
cd /

# Set the terminus font for a bit nicer display.
sed -ie 's/FONTFACE=.*/FONTFACE="Terminus"/g' /etc/default/console-setup
sed -ie 's/FONTSIZE=.*/FONTSIZE="6x12"/g' /etc/default/console-setup

rm -f /usr/sbin/policy-rc.d
rm -f /usr/sbin/invoke-rc.d
dpkg-divert --remove --rename /usr/sbin/invoke-rc.d

rm -f /third-stage
EOF

chmod 755 kali-${architecture}/third-stage
LANG=C systemd-nspawn -M ${machine} -D kali-${architecture} /third-stage

cat << EOF > kali-${architecture}/cleanup
#!/bin/bash
rm -rf /root/.bash_history
apt-get update
apt-get clean
rm -f /0
rm -f /hs_err*
rm -f cleanup
rm -f /usr/bin/qemu*
EOF

chmod 755 kali-${architecture}/cleanup
LANG=C systemd-nspawn -M ${machine} -D kali-${architecture} /cleanup

#umount kali-${architecture}/proc/sys/fs/binfmt_misc
#umount kali-${architecture}/dev/pts
#umount kali-${architecture}/dev/
#umount kali-${architecture}/proc

cat << EOF > kali-${architecture}/etc/resolv.conf
nameserver 8.8.8.8
EOF

# Serial console settings.
# (No auto login)
echo 'T1:12345:respawn:/sbin/agetty 115200 ttyAMA0 vt100' >> ${basedir}/kali-${architecture}/etc/inittab

cat << EOF > ${basedir}/kali-${architecture}/etc/apt/sources.list
deb http://http.kali.org/kali kali-rolling main non-free contrib
deb-src http://http.kali.org/kali kali-rolling main non-free contrib
EOF

# Uncomment this if you use apt-cacher-ng otherwise git clones will fail.
#unset http_proxy

# Kernel section. If you want to use a custom kernel, or configuration, replace
# them in this section.
# Warning: There may be a kernel bug when you try to resize root file system with friendlyArm official kernel. To avoid 
# this, resize the root file system manually after fish the dd command.
git clone https://github.com/friendlyarm/linux.git -b sunxi-4.14.y --depth 1 ${basedir}/kali-${architecture}/usr/src/kernel
cd ${basedir}/kali-${architecture}/usr/src/kernel
git rev-parse HEAD > ${basedir}/kali-${architecture}/usr/src/kernel-at-commit
touch .scmversion
export ARCH=arm
export CROSS_COMPILE=arm-linux-gnueabihf-
cp ${basedir}/../kernel-configs/nanopiduo.config ${basedir}/kali-${architecture}/usr/src/kernel/.config
cp ${basedir}/../kernel-configs/nanopiduo.config ${basedir}/kali-${architecture}/usr/src/
patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/kali-wifi-injection-4.14.patch
patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/fixsecclass.patch
patch -p1 --no-backup-if-mismatch < ${basedir}/../patches/0001-wireless-carl9170-Enable-sniffer-mode-promisc-flag-t.patch
#make xconfig
make -j $(grep -c processor /proc/cpuinfo)
make modules
make modules_install INSTALL_MOD_PATH=${basedir}/kali-${architecture}
cp arch/arm/boot/Image ${basedir}/kali-${architecture}/boot
cp arch/arm/boot/dts/sun8i-h2-plus-nanopi-duo.dtb ${basedir}/kali-${architecture}/boot/

make mrproper
cd ${basedir}

cd ${basedir}

# Fix up the symlink for building external modules
# kernver is used so we don't need to keep track of what the current compiled
# version is
kernver=$(ls ${basedir}/kali-${architecture}/lib/modules/)
cd ${basedir}/kali-${architecture}/lib/modules/${kernver}
rm build
rm source
ln -s /usr/src/kernel build
ln -s /usr/src/kernel source
cd ${basedir}

cp ${basedir}/../misc/zram ${basedir}/kali-${architecture}/etc/init.d/zram
chmod 755 ${basedir}/kali-${architecture}/etc/init.d/zram

# Required to kick the bluetooth chip.
#cp ${basedir}/../misc/bins/brcm_patchram_plus-64 ${basedir}/kali-${architecture}/bin/brcm_patchram_plus
#chmod 755 ${basedir}/kali-${architecture}/bin/brcm_patchram_plus

sed -i -e 's/^#PermitRootLogin.*/PermitRootLogin yes/' ${basedir}/kali-${architecture}/etc/ssh/sshd_config

cat << EOF > ${basedir}/kali-${architecture}/boot/boot.cmd
# Recompile with: mkimage -C none -A arm -T script -d boot.cmd boot.scr
# CPU=H3
# OS=friendlycore/ubuntu-oled/ubuntu-wifiap/openwrt/debian/debian-nas...

echo "running boot.scr"
setenv fsck.repair yes
setenv ramdisk rootfs.cpio.gz
setenv kernel zImage

setenv env_addr 0x45000000
setenv kernel_addr 0x46000000
setenv ramdisk_addr 0x47000000
setenv dtb_addr 0x48000000

fatload mmc 0 ${kernel_addr} ${kernel}
fatload mmc 0 ${ramdisk_addr} ${ramdisk}
setenv ramdisk_size ${filesize}

fatload mmc 0 ${dtb_addr} sun8i-${cpu}-${board}.dtb
fdt addr ${dtb_addr}

# setup MAC address 
fdt set ethernet0 local-mac-address ${mac_node}

# setup XR819 MAC address
if test $board = nanopi-duo; then fdt set xr819 local-mac-address ${wifi_mac_node}; fi

# setup boot_device
fdt set mmc${boot_mmc} boot_device <1>

setenv fbcon map:0
setenv overlayfs data=/dev/mmcblk0p3
#setenv hdmi_res drm_kms_helper.edid_firmware=HDMI-A-1:edid/1280x720.bin video=HDMI-A-1:1280x720@60

setenv bootargs console=ttyS0,115200 earlyprintk root=/dev/mmcblk0p2 rootfstype=ext4 rw rootwait fsck.repair=${fsck.repair} panic=10 ${extra} fbcon=${fbcon} ${hdmi_res} ${overlayfs}
bootz ${kernel_addr} ${ramdisk_addr}:${ramdisk_size} ${dtb_addr}
EOF
mkimage -C none -A arm -T script -d ${basedir}/kali-${architecture}/boot/boot.cmd ${basedir}/kali-${architecture}/boot/boot.scr

# rpi-wiggle
mkdir -p ${basedir}/kali-${architecture}/root/scripts
#download will failed , suggest to download manually
wget https://raw.github.com/steev/rpiwiggle/master/rpi-wiggle -O ${basedir}/kali-${architecture}/root/scripts/rpi-wiggle.sh
chmod 755 ${basedir}/kali-${architecture}/root/scripts/rpi-wiggle.sh

echo "Running du to see how big kali-${architecture} is"
du -sh ${basedir}/kali-${architecture}
echo "the above is how big the sdcard needs to be"

# Create the disk and partition it
# We start out at around 3MB so there is room to write u-boot without issues.
echo "Creating image file for NanoPi Duo "
dd if=/dev/zero of=${basedir}/${imagename}.img bs=1M count=${size}
parted ${imagename}.img --script -- mklabel msdos
parted ${imagename}.img --script -- mkpart primary ext4 4096s 264191s
parted ${imagename}.img --script -- mkpart primary ext4 264192s 100%

# Set the partition variables
loopdevice=`losetup -f --show ${basedir}/${imagename}.img`
device=`kpartx -va ${loopdevice} | sed 's/.*\(loop[0-9]\+\)p.*/\1/g' | head -1`
sleep 5
device="/dev/mapper/${device}"
bootp=${device}p1
rootp=${device}p2

# Create file systems
mkfs.vfat ${bootp}
mkfs.ext4 -O ^64bit -O ^flex_bg -O ^metadata_csum ${rootp}

# Create the dirs for the partitions and mount them
mkdir -p ${basedir}/root
mount ${rootp} ${basedir}/root
mkdir -p ${basedir}/root/boot
mount ${bootp} ${basedir}/root/boot

# We do this down here to get rid of the build system's resolv.conf after running through the build.
cat << EOF > kali-${architecture}/etc/resolv.conf
nameserver 8.8.8.8
EOF

echo "Rsyncing rootfs into image file"
rsync -HPavz -q ${basedir}/kali-${architecture}/ ${basedir}/root/

# Unmount partitions
sync
umount -l ${bootp}
umount -l ${rootp}
kpartx -dv ${loopdevice}

cd ${basedir}
git clone https://github.com/friendlyarm/u-boot.git
cd u-boot
git checkout sunxi-v2017.x
make nanopi_h3_defconfig
make
dd if=u-boot-sunxi-with-spl.bin of=${loopdevice} bs=1024 seek=8

sync

cd ${basedir}

losetup -d ${loopdevice}

# Don't pixz on 32bit, there isn't enough memory to compress the images.
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
echo "Compressing ${imagename}.img"
pixz ${basedir}/${imagename}.img ${basedir}/../${imagename}.img.xz
unxz -t ${basedir}/../${imagename}.img.xz || rm ${basedir}/../${imagename}.img.xz &&  pixz ${basedir}/${imagename}.img ${basedir}/../${imagename}.img.xz && unxz -t ${basedir}/../${imagename}.img.xz
echo "Deleting ${imagename}.img"
rm ${basedir}/${imagename}.img
fi

# Comment this out to keep things around if you want to see what may have gone
# wrong.
echo "Clean up the build system"
rm -rf ${basedir}
