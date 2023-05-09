from __future__ import annotations

import re

from typing import Optional
from collections.abc import Generator


REG_IPV4_ADDR = r'^(?:\d{1,3}\.){3}\d{1,3}$'
REG_IPV4_PREFIX = rf'{REG_IPV4_ADDR[:-1]}\/\d{{1,2}}$'
REG_IPV4_BITMASK = r'^[01]{1,32}$'


def ipv4_address_to_bitmap(address: str) -> str:
    if not re.match(REG_IPV4_ADDR, address):
        return ''
    octets = address.split('.')
    template = '{:08b}' * 4
    return ''.join(template.format(*(int(x) for x in octets)))

def ipv4_address_to_subnet_bitmap(address: str, mask: str) -> str:
    if not re.match(REG_IPV4_ADDR, address) or not re.match(REG_IPV4_ADDR, mask):
        return ''
    addr_bitmap = ipv4_address_to_bitmap(address)
    mask_bitmap = ipv4_address_to_bitmap(mask)
    plen = mask_bitmap.count('1')
    return addr_bitmap[:plen]

def ipv4_prefix_to_subnet_bitmap(prefix: str) -> str:
    if not re.match(REG_IPV4_PREFIX, prefix):
        return ''
    address, plen = prefix.split('/')
    plen = int(plen)
    if plen < 0 or plen > 32:
        return ''
    # mask = '0' if not plen else '1' * plen
    # mask = f'{mask:032}'
    # mask = '.'.join(str(int(mask[x * 8:(x * 8) + 8], 2)) for x in range(4))
    mask = plen_to_ipv4_mask(plen)
    return ipv4_address_to_subnet_bitmap(address, mask)

def bitmap_to_ipv4_prefix(bitmap: str) -> tuple[str, int]:
    if not re.match(REG_IPV4_BITMASK, bitmap):
        return '', -1
    plen = len(bitmap)
    bitmap = f'{bitmap:032}'
    address = '.'.join(str(int(bitmap[x * 8:(x * 8) + 8], 2)) for x in range(4))
    return address, plen

def plen_to_ipv4_mask(plen: int) -> str:
    if plen < 0 or plen > 32:
        return ''
    mask = '0' if not plen else '1' * plen
    mask = f'{mask:032}'
    return '.'.join(str(int(mask[x * 8:(x * 8) + 8], 2)) for x in range(4))


class TrieNode:
    def __init__(self, key: str) -> None:
        if type(key) is not str or not re.match(REG_IPV4_BITMASK, key):
            raise ValueError('Incorrect value for the key.')
        self.key = key
        self.left: Optional[TrieNode] = None
        self.right: Optional[TrieNode] = None
        self.ptypes: list[str] = []

class Trie:
    def __init__(self) -> None:
        self.key = None
        self.left: Optional[TrieNode] = None
        self.right: Optional[TrieNode] = None
        self.ptypes = []

    def insert(self, bitmap: str, ptype: str) -> Optional[TrieNode]:
        if type(bitmap) is not str or not re.match(REG_IPV4_BITMASK, bitmap):
            return
        current_node: Trie | TrieNode = self
        for x in range(1, len(bitmap) + 1):
            bslice = bitmap[:x]
            lsb = int(bslice[-1])
            if lsb:
                if not current_node.right:
                    current_node.right = TrieNode(bslice)
                current_node = current_node.right
            else:
                if not current_node.left:
                    current_node.left = TrieNode(bslice)
                current_node = current_node.left
        if ptype not in current_node.ptypes:
            current_node.ptypes.append(ptype)
        return current_node

    def search(self, bitmap: str) -> Optional[TrieNode]:
        if type(bitmap) is not str or not re.match(REG_IPV4_BITMASK, bitmap):
            return
        current_node: Trie | TrieNode = self
        for x in range(1, len(bitmap) + 1):
            bslice = bitmap[:x]
            lsb = int(bslice[-1])
            if lsb:
                if current_node.right:
                    current_node = current_node.right
                else:
                    if current_node.ptypes:
                        return current_node
                    return
            else:
                if current_node.left:
                    current_node = current_node.left
                else:
                    if current_node.ptypes:
                        return current_node
                    return
        if current_node.ptypes:
            return current_node

    def delete(self, bitmap: str, ptype: str) -> Optional[TrieNode]:
        if node := self.search(bitmap):
            if ptype in node.ptypes:
                node.ptypes.remove(ptype)
            return node

    def __build_table(self, node: Trie | TrieNode) -> Generator[TrieNode, None, None]:
        if node.ptypes:
            yield node
        if node.right:
            yield from self.__build_table(node.right)
        if node.left:
            yield from self.__build_table(node.left)

    def build_table(self) -> Generator[TrieNode, None, None]:
        yield from self.__build_table(self)
