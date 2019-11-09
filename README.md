# Kali Linux build script for Friendly ARM NanoPi Duo,
This is Kali Linux build script for Friendly ARM NanoPi Duo.
I modified the official build script for NanoPi Neo Plus 2 form Kali Linux GitLab Web Site at https://gitlab.com/kalilinux/build-scripts/kali-arm

- These scripts have been tested on my Ubuntu 19.10 64 bit Laptop only. Run build-deps.sh will install all the dependencies you need.
- ~~ If you are running a Ubuntu or Debian based host, you need a gpg file located at /usr/share/keyrings/kali-archive-keyring.gpg ~~


**_IF YOU ARE BUILDING IN A VM, YOU WILL NEED TO DEDICATE AT LEAST 8GB OF RAM, OR USE A SWAP FILE_**

A sample workflow would look similar to (armhf):

    mkdir ~/arm-stuff
    cd ~/arm-stuff
    git clone https://github.com/HanasakiShidou/kali_arm_nanopi_duo.git
    cd ~/kali_arm_nanopi_duo
    ./build-deps.sh
    ./nanopiduo.sh 2019.11

If you are on 32bit, after the script finishes running, you will have an image
file located in ~/arm-stuff/kali-arm called
kali-linux-2019.2-exynos.img.  32bit does not have enough memory to compress the image
**_You will need to use your own preferred compression if you want to distribute it._**

On 64bit systems, after the script finishes running, you will have an image
files located in ~/arm-stuff/kali-arm/ called
kali-linux-2019.11-nanopiduo.img.xz

	To do: 
----
- fix XR819
- add support for NanoPi Duo 2

