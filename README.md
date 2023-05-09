This is a minimalistic script that helps you manage your IPv4 address space.
The script does not require any additional libs except the standard ones (for Python 3.6+).

Usage:

    python -m netshred ADDR_1 MASK_1 ADDR_2 MASK_2
    python -m netshred ADDR_1/PLEN_1 ADDR2/PLEN_2


The script checks whether the second network is a part of the first one and then split the latter into a minimal number of subnets except the former.

For example, if you need to know a minimal number of subnets inside 10.0.0.0/24 excluding 10.0.0.0/27, the script will give you:

    10.0.0.128/25 or 10.0.0.128 255.255.255.128
    10.0.0.64/26 or 10.0.0.64 255.255.255.192
    10.0.0.32/27 or 10.0.0.32 255.255.255.224

