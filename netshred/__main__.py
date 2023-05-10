import re
import sys

from .subneting import (
    REG_IPV4_PREFIX,
    REG_IPV4_ADDR,
    ipv4_address_to_bitmap,
    ipv4_prefix_to_subnet_bitmap,
    ipv4_address_to_subnet_bitmap,
    bitmap_to_ipv4_prefix,
    plen_to_ipv4_mask,
    Trie,
    TrieNode,
)


HELP_MESSAGE = '''
Usage: python -m netshred SUBNET_ADDR1 SUBNET_MASK1 SUBNET_ADDR2 SUBNET_MASK2 [cidr]
E.g., python -m netshred 10.0.0.0 255.255.254.0 10.0.0.10 255.255.255.254

OR

python -m netshred PREFIX1 PREFIX2 [cidr] (e.g., python -m netshred 10.0.0.0/23 10.0.0.10/31)

cidr -- an optional keyword that modifies the output from the prefixed view to a CIDR based
'''


def help(err: str) -> None:
    print(err)
    print(HELP_MESSAGE)

def check_coverage(base: str, target: str) -> bool:
    '''
    Checks whether a target is a part of a superior (base) subnet.
    `base` and `target` are bitmaps.
    Empty `base` is equal to the default route.
    '''
    rtm = Trie()
    if not base:
        if check_coverage(ipv4_prefix_to_subnet_bitmap('0.0.0.0/1'), target):
            return True
        if check_coverage(ipv4_prefix_to_subnet_bitmap('128.0.0.0/1'), target):
            return True
    else:
        rtm.insert(base, 'shlop')
        if rtm.search(target):
            return True
    return False

def shred_subnet(base: str, exception: str) -> list:
    '''
    Splits the `base` into a minimal number of subnets that don't contain the `exception`.
    `base` and `exception` are bitmaps.
    Empty `base` is equal to the default route.
    Returns a list of tuples of an address (str) and prefix len (int).
    '''
    result: list = []
    rtm = Trie()
    node: TrieNode = None
    if not base:
        r = rtm.insert(ipv4_prefix_to_subnet_bitmap('0.0.0.0/1'), 'root')
        if rtm.search(exception):
            node = r
            result.append(('128.0.0.0', 1))
        else:
            node = rtm.insert(ipv4_prefix_to_subnet_bitmap('128.0.0.0/1'), 'root')
            result.append(('0.0.0.0', 1))
    else:
        node = rtm.insert(base, 'root')
    rtm.insert(exception, 'target')
    while node:
        if 'target' in node.ptypes:
            break
        if not node.left and not node.right:
            break
        if not node.left:
            result.append(bitmap_to_ipv4_prefix(f'{node.key}0'))
            node = node.right
        elif not node.right:
            result.append(bitmap_to_ipv4_prefix(f'{node.key}1'))
            node = node.left
    return result

def validate_prefixes(prefixes: list) -> bool:
    '''
    Returns False if at least one of the prefixes is not valid
    '''
    for prefix in prefixes:
        if not re.match(fr'^{REG_IPV4_PREFIX}$', prefix):
            return False
        address, length = prefix.split('/')
        length = int(length)
        if len(ipv4_address_to_bitmap(address)) > 32 or length < 0 or length > 32:
            return False
    return True

def validate_addresses(addresses: list) -> bool:
    '''
    Returns False if at least one of the addresses is not valid
    '''
    for address in addresses:
        if not re.match(REG_IPV4_ADDR, address) or len(ipv4_address_to_bitmap(address)) > 32:
            return False
    return True

def main(args: list) -> None:
    routes: list = []
    is_prefix_view: bool = True
    if len(args) in (3, 4):
        if not validate_prefixes(args[1:3]):
            raise Exception('Inserted prefixes aren`t valid.')
        if not check_coverage(ipv4_prefix_to_subnet_bitmap(args[1]), ipv4_prefix_to_subnet_bitmap(args[2])):
            raise Exception(f'The prefix {args[2]} is not part of {args[1]}.')
        routes = shred_subnet(ipv4_prefix_to_subnet_bitmap(args[1]), ipv4_prefix_to_subnet_bitmap(args[2]))
        if len(args) == 4 and args[3].lower() == 'cidr':
            is_prefix_view = False
    elif len(args) in (5, 6):
        if not validate_addresses(args[1:5]):
            raise Exception('Inserted addresses or mask aren`t valid.')
        if not check_coverage(ipv4_address_to_subnet_bitmap(args[1], args[2]), ipv4_address_to_bitmap(args[3])):
            raise Exception(f'The network address {args[3]} is not part of {args[1]} {args[2]}.')
        routes = shred_subnet(
            ipv4_address_to_subnet_bitmap(args[1], args[2]),
            ipv4_address_to_subnet_bitmap(args[3], args[4])
        )
        if len(args) == 6 and args[5].lower() == 'cidr':
            is_prefix_view = False
    else:
        raise Exception('Not enough arguments.')
    if not routes:
        print('No possible options.')
        sys.exit(127)
    for address, length in routes:
        if is_prefix_view:
            print(f'{address}/{length}')
        else:
            print(f'{address} {plen_to_ipv4_mask(length)}')


if __name__ == '__main__':
    try:
        main(sys.argv)
    except Exception as err:
        help(err.args[0])
