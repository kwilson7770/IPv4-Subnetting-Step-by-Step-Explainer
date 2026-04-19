class IPv4Address:
    """This class represents an IPv4 address and provides methods to manipulate and analyze the address. It supports various operations like determining address class, calculating subnets, supernets, and performing validations on IPv4 address and prefix lengths."""

    TEN_NET_START = 0x0A000000 # 10.0.0.0
    TEN_NET_END   = 0x0AFFFFFF # 10.255.255.255

    LOOPBACK_START = 0x7F000000 # 127.0.0.0
    LOOPBACK_END   = 0x7FFFFFFF # 127.255.255.255

    PRIVATE_172_START = 0xAC100000 # 172.16.0.0
    PRIVATE_172_END   = 0xAC1FFFFF # 172.31.255.255

    LINKLOCAL_START = 0xA9FE0000 # 169.254.0.0
    LINKLOCAL_END   = 0xA9FEFFFF # 169.254.255.255

    PRIVATE_192_START = 0xC0A80000 # 192.168.0.0
    PRIVATE_192_END   = 0xC0A8FFFF # 192.168.255.255

    MULTICAST_START = 0xE0000000 # 224.0.0.0
    MULTICAST_END   = 0xEFFFFFFF # 239.255.255.255

    ALL_ONES = 0xFFFFFFFF # 2 ^ 32 - 1 or 4294967295 or 11111111111111111111111111111111 (32 1s) or 255.255.255.255 or simply 0xFFFFFFFF

    RESERVED_START = 0xF0000000 # 240.0.0.0
    RESERVED_END = ALL_ONES # same value as ALL_ONES

    @staticmethod
    def ip_string_from_int(ipInt):
        return ".".join(str(i) for i in ipInt.to_bytes(4, "big"))

    @staticmethod
    def ip_int_from_string(ipStr):
        return int.from_bytes(bytes([int(i, 10) for i in ipStr.split(".")]), "big")

    @staticmethod
    def _space_out_binary_string(binStr):
        sign = '-' if binStr.startswith('-') else ''
        binStr = binStr.lstrip('-')

        groups = []
        while binStr:
            groups.append(binStr[-8:])
            binStr = binStr[:-8]

        return sign + ' '.join(reversed(groups))

    @staticmethod
    def calculate_netmask_int(prefixLen):
        # Calculate the netmask for the provided prefix length by performing a bitwise left shift (<<) operation on 32 1-bits (IPv4Address.ALL_ONES).
        # After the left shift, a bitwise AND (&) with IPv4Address.ALL_ONES ensures that the result stays within 32 bits, discarding any bits beyond the 32nd.
        # These operations set the first prefixLen number of bits to 1, and the remaining bits to 0, forming the desired netmask.
        #
        # For example, if prefixLen == 16:
        # IPv4Address.ALL_ONES  = 11111111 11111111 11111111 11111111
        # 32 - 16               = 16
        # (11111111 11111111 11111111 11111111 << 16) = 11111111 11111111 11111111 11111111 00000000 00000000
        # The result is a 48-bit value in memory.
        # Note: In languages like C or Java, which use fixed-width integers (e.g., 32-bit), the left shift will overflow and discard the bits beyond 32.
        # In contrast, Python supports arbitrary precision integers, so the result expands beyond 32 bits to accommodate the shifted value.
        # Finally, the bitwise AND with IPv4Address.ALL_ONES ensures that only the lower 32 bits are retained:
        # 11111111 11111111 11111111 11111111 00000000 00000000 & IPv4Address.ALL_ONES
        # 11111111 11111111 11111111 11111111 00000000 00000000 & 11111111 11111111 11111111 11111111 = 11111111 11111111 00000000 00000000
        # The result is the subnet netmask:
        # 11111111 11111111 00000000 00000000 = 255.255.0.0
        return (IPv4Address.ALL_ONES << (32 - prefixLen)) & IPv4Address.ALL_ONES

    @staticmethod
    def calculate_network_id_int(ipInt, netmaskInt):
        # Calculate the network ID by performing a bitwise AND (&) operation between an IP address within the network (ipInt) and the subnet mask (netmaskInt).
        # This operation filters out the host portion of the IP address, since the subnet mask, by design, has 1s in the network portion and 0s in the host portion.
        # The bitwise AND (&) operation keeps a bit as 1 only if both bits are 1, otherwise, it sets the bit to 0.
        #
        # For example, if ipInt = 10.111.112.113 and netmaskInt = 255.240.0.0:
        # 10.111.112.113 = 00001010 01101111 01110000 01110001
        # 255.240.0.0    = 11111111 11110000 00000000 00000000
        # Perform the bitwise AND (&) to get the network bits:
        # 00001010 01101111 01110000 01110001 & 11111111 11110000 00000000 00000000 = 00001010 01100000 00000000 00000000
        # The result is the network ID:
        # 00001010 01100000 00000000 00000000 = 10.96.0.0
        return ipInt & netmaskInt

    def __init__(self, IPv4, showSteps=False, explainHowToCalculate=False):
        # _ipv4_address_parser() sets ipInt, ipStr, ipBin, netmaskInt, netmaskStr, netmaskBin, prefixLen, and cidrAdr
        self._ipv4_address_parser(IPv4)

        # Setup the object based on the prefix length
        if self.prefixLen == 32:
            self._setup_single_host()
        elif self.prefixLen == 31:
            self._setup_point_to_point()
        else: # _validate_ipv4_prefix_len() ensured this is between 1 and 30
            self._setup_normal_subnet()

        # Set various attributes as they apply to the IP address
        self.adrClass = self._calculate_address_class()
        self.privateUse = IPv4Address.TEN_NET_START <= self.ipInt <= IPv4Address.TEN_NET_END or IPv4Address.PRIVATE_172_START <= self.ipInt <= IPv4Address.PRIVATE_172_END or IPv4Address.PRIVATE_192_START <= self.ipInt <= IPv4Address.PRIVATE_192_END
        self.linkLocal = IPv4Address.LINKLOCAL_START <= self.ipInt <= IPv4Address.LINKLOCAL_END
        self.multicast = IPv4Address.MULTICAST_START <= self.ipInt <= IPv4Address.MULTICAST_END
        self.reserved = IPv4Address.RESERVED_START <= self.ipInt <= IPv4Address.RESERVED_END
        self.loopback = IPv4Address.LOOPBACK_START <= self.ipInt <= IPv4Address.LOOPBACK_END
        self.limitedBroadcast = self.ipInt == IPv4Address.ALL_ONES

        # Set flag(s) if showing how the calculations are performed
        self.showSteps = showSteps
        self.explainHowToCalculate = explainHowToCalculate

        if self.showSteps:
            self._print_steps()

        if self.explainHowToCalculate:
            self._explain_how_to_calculate()

    def _setup_single_host(self):
        # Single host network (/32)

        self.netIDInt = self.ipInt
        self.netIDStr = self.ipStr
        self.netIDBin = self.ipBin
        self.netIDCIDR = f"{self.ipStr}/32"

        self.broadcastInt = self.ipInt
        self.broadcastStr = self.ipStr
        self.broadcastBin = self.ipBin

        self.totalAddresses = 1
        self.usableHosts = 1
        self.firstHost = self.ipStr
        self.lastHost = self.ipStr

    def _setup_point_to_point(self):
        # point-to-point link (/31). According to RFC3021, the network ID (first host) and broadcast address (last host) are both treated as usable hosts.

        # sets the network ID to be the first IP address in a network
        self._set_network_id()

        # sets the broadcast address to be the last IP address in a network
        self._set_broadcast_address()

        self.totalAddresses = 2
        self.usableHosts = 2
        self.firstHost = self.netIDStr
        self.lastHost = self.broadcastStr

    def _setup_normal_subnet(self):
        # Normal subnets (/1 to /30)

        # sets the network ID to be the first IP address in a network
        self._set_network_id()

        # sets the broadcast address to be the last IP address in a network
        self._set_broadcast_address()

        # The total addresses is the number of hosts that can fit within the host bits (hence the 2^host-bits math)
        self.totalAddresses = 2 ** (32 - self.prefixLen)
        self.usableHosts = self.totalAddresses - 2 # this is true for /1 to /30
        self.firstHost = IPv4Address.ip_string_from_int(self.netIDInt + 1) # this is the first address after the network ID
        self.lastHost = IPv4Address.ip_string_from_int(self.broadcastInt - 1) #  this is the first address before the broadcast address

    def _set_broadcast_address(self):
        # Calculate the broadcast address by using the netmask, network ID, and bitwise XOR (^) and OR (|) operations.
        # The bitwise XOR (^) between the netmask and IPv4Address.ALL_ONES inverts all the bits of the netmask.
        # This operation flips the 1s in the netmask to 0s and the 0s to 1s, creating the inverse of the netmask.
        # Next, the bitwise OR (|) between the inverted netmask and the network ID creates the broadcast address.
        # This ensures that all host bits (which are 0s in the network ID) are set to 1s, resulting in the highest possible address in the network (the broadcast address).
        #
        # For example, if self.netmaskInt = 255.255.255.0 and self.netIDInt = 192.168.1.0:
        # 255.255.255.0 = 11111111 11111111 11111111 00000000
        # 192.168.1.0 = 11000000 10101000 00000001 00000000
        # IPv4Address.ALL_ONES = 11111111 11111111 11111111 11111111
        # First, apply the bitwise XOR (^) operation between the two numbers to invert the bits:
        # 11111111 11111111 11111111 00000000 ^ 11111111 11111111 11111111 11111111 = 00000000 00000000 00000000 11111111
        # Next, apply the bitwise OR (|) operation to set all the host bits to 1:
        # 00000000 00000000 00000000 11111111 | 11000000 10101000 00000001 00000000 = 11000000 10101000 00000001 11111111
        # The result is the broadcast address:
        # 11000000 10101000 00000001 11111111 = 192.168.1.255
        self.broadcastInt = (self.netmaskInt ^ IPv4Address.ALL_ONES) | self.netIDInt
        self.broadcastStr = IPv4Address.ip_string_from_int(self.broadcastInt)
        self.broadcastBin = IPv4Address._space_out_binary_string(format(self.broadcastInt, '032b'))

    def _set_network_id(self):
        self.netIDInt = IPv4Address.calculate_network_id_int(self.ipInt, self.netmaskInt)
        self.netIDStr = IPv4Address.ip_string_from_int(self.netIDInt)
        self.netIDBin = IPv4Address._space_out_binary_string(format(self.netIDInt, '032b'))
        self.netIDCIDR = f"{self.netIDStr}/{self.prefixLen}"

    def _ipv4_address_parser(self, IPv4):
        """IPv4 Arg can be:
        a dotted decimal IPv4 string (e.g. 172.30.5.0),
        a CIDR address (e.g. 127.0.5.1/24),
        a dotted decimal IPv4 string with a dotted decimal IPv4 subnet mask (space separated) (e.g. 10.0.6.7 255.255.255.0),
        a string of the decimal IPv4 with the prefix len (space separated) (e.g. 16843009 /8),
        or an integer of an IPv4 address (e.g. 1157895235).
        """

        if isinstance(IPv4, str):
            ipStr = IPv4
            # clean up the ipStr by removing extra spaces
            ipStr = ipStr.strip()
            while "  " in ipStr:
                ipStr = ipStr.replace("  ", " ")
        elif isinstance(IPv4, int):
            # _validate_ipv4_int returns ipInt if validated, otherwise raises ValueError
            self.ipInt = self._validate_ipv4_int(IPv4)
            ipStr = IPv4Address.ip_string_from_int(self.ipInt)

        if "/" in ipStr and " " not in ipStr: # CIDR notation (e.g. 10.0.0.1/8), but not IP (as an int) + prefix format
            ipStr, prefixLenStr = ipStr.split("/")
        elif " " in ipStr:  # IP (dotted decimal) + netmask format OR IP (as an int) + prefix format
            obj1, obj2 = ipStr.split() # If there are too many spaces, this will error out (which is good!)
            if obj1.isdigit() and obj2.startswith("/") and obj2[1:].isdigit(): # netmask format OR IP (as an int) + prefix format
                # _validate_ipv4_int returns ipInt if validated, otherwise raises ValueError
                self.ipInt = self._validate_ipv4_int(int(obj1))
                ipStr = IPv4Address.ip_string_from_int(self.ipInt)
                prefixLenStr = obj2[1:]
            else: # IP (dotted decimal) + netmask format
                ipStr = obj1
                netmaskStr = obj2
                self.netmaskInt = IPv4Address.ip_int_from_string(netmaskStr)
                prefixLenStr = str(format(self.netmaskInt, "032b").count("1"))
        else:
            prefixLenStr = "32"
            self.netmaskInt = IPv4Address.ALL_ONES

        # _validate_ipv4_prefix_len returns prefixLen as an int if validated, otherwise raises ValueError
        self.prefixLen = self._validate_ipv4_prefix_len(prefixLenStr)

        # If _validate_ipv4_octets returns ipStr if validated, otherwise raises ValueError
        self.ipStr = self._validate_ipv4_octets(ipStr)
        if not hasattr(self, "ipInt"):
            self.ipInt = IPv4Address.ip_int_from_string(ipStr)
        self.ipBin = IPv4Address._space_out_binary_string(format(self.ipInt, '032b'))

        # Calculate the netmask for the new prefix length by performing a bitwise left shift (<<) operation on 32 1-bits (IPv4Address.ALL_ONES).
        # After the left shift, a bitwise AND (&) with IPv4Address.ALL_ONES ensures that the result stays within 32 bits, discarding any bits beyond the 32nd.
        # These operations set the first self.prefixLen number of bits to 1, and the remaining bits to 0, forming the desired netmask.
        #
        # For example, if self.prefixLen == 24:
        # IPv4Address.ALL_ONES  = 11111111 11111111 11111111 11111111
        # 32 - 24               = 8
        # (11111111 11111111 11111111 11111111 << 8) = 11111111 11111111 11111111 11111111 00000000
        # The result is a 40-bit value in memory.
        # Note: In languages like C or Java, which use fixed-width integers (e.g., 32-bit), the left shift will overflow and discard the bits beyond 32.
        # In contrast, Python supports arbitrary precision integers, so the result expands beyond 32 bits to accommodate the shifted value.
        # Finally, the bitwise AND with IPv4Address.ALL_ONES ensures that only the lower 32 bits are retained:
        # 11111111 11111111 11111111 11111111 00000000 & IPv4Address.ALL_ONES
        # 11111111 11111111 11111111 11111111 00000000 & 11111111 11111111 11111111 11111111 = 11111111 11111111 11111111 00000000
        if not hasattr(self, "netmaskInt"):
            self.netmaskInt = IPv4Address.calculate_netmask_int(self.prefixLen)

        self.netmaskStr = IPv4Address.ip_string_from_int(self.netmaskInt) # convert int to string
        self.netmaskBin = IPv4Address._space_out_binary_string(format(self.netmaskInt, '032b'))

        self.hostmaskInt = self.netmaskInt ^ IPv4Address.ALL_ONES
        self.hostmaskStr = IPv4Address.ip_string_from_int(self.hostmaskInt) # convert int to string
        self.hostmaskBin = IPv4Address._space_out_binary_string(format(self.hostmaskInt, '032b'))


        self.cidrAdr = f"{ipStr}/{self.prefixLen}"

    def _validate_ipv4_int(self, ipInt):
        if ipInt >= 0 and ipInt <= IPv4Address.ALL_ONES:
            return ipInt
        else:
            raise ValueError(f"The IPv4 integer {ipInt} must be between 0 and {IPv4Address.ALL_ONES}")

    def _validate_ipv4_octets(self, ipStr):
        octets = ipStr.split(".")
        if len(octets) != 4:
            raise ValueError(f"The IPv4 Address {ipStr} must contain 4 octets, {len(octets)} != 4")

        for i in octets:
            if i.isdigit():
                if int(i) < 0 or int(i) > 255:
                    raise ValueError(f"The IPv4 Address {ipStr} must contain 4 octets with number between 0 and 255 and {i} is not valid")
                elif i != "0" and i[0] == "0":
                    raise ValueError(f"The IPv4 Address {ipStr} can't have octets that have leading zeros and {i} is not valid")
            else:
                raise ValueError(f"The IPv4 Address {ipStr} must contain 4 octets made up of digits. {i} is not a digit")

        return ipStr

    def _validate_ipv4_prefix_len(self, prefixLenStr):
        if prefixLenStr.isdigit():
            # After validation, keep prefixLen as an int
            prefixLenInt = int(prefixLenStr)
            if prefixLenInt == 0:
                raise NotImplementedError("While RFC 4632 specifics 0.0.0.0/0 as the default route, it is not meaningful for this class. As such, a CIDR prefix length of 0 is not implemented.")
            elif prefixLenInt > 0 and prefixLenInt <= 32:
                return prefixLenInt
            else:
                raise ValueError(f"The CIDR prefix length {prefixLenInt} must be a valid integer between 1 and 32")
        else:
            raise ValueError(f"The CIDR prefix length {prefixLenStr} must be a valid integer between 1 and 32")

    def _calculate_address_class(self):
        # Determine the class of the IP address based on the first few bits (address class is based on the most significant bits)
        if self.ipInt & 0x80000000 == 0: # First bit is set to 0
            # 00000000 00000000 00000000 00000000 = 0.0.0.0
            # 01111111 11111111 11111111 11111111 = 127.255.255.255
            self.adrClassStr = "Class A"
            return "A"
        elif self.ipInt & 0xC0000000 == 0x80000000: # First two bits are 10
            # 10000000 00000000 00000000 00000000 = 128.0.0.0
            # 10111111 11111111 11111111 11111111 = 191.255.255.255
            self.adrClassStr = "Class B"
            return "B"
        elif self.ipInt & 0xE0000000 == 0xC0000000: # First three bits are 110
            # 11000000 00000000 00000000 00000000 = 192.0.0.0
            # 11011111 11111111 11111111 11111111 = 223.255.255.255
            self.adrClassStr = "Class C"
            return "C"
        elif self.ipInt & 0xF0000000 == 0xE0000000: # First four bits are 1110
            # 11100000 00000000 00000000 00000000 = 224.0.0.0
            # 11101111 11111111 11111111 11111111 = 239.255.255.255
            self.adrClassStr = "Class D (Multicast)"
            return "D"
        else: # First four bits are 1111
            # 11110000 00000000 00000000 00000000 = 240.0.0.0
            # 11111111 11111111 11111111 11111111 = 255.255.255.255
            self.adrClassStr = "Class E (Reserved / Experimental)"
            return "E"

    def contains(self, ip):
        """Determines if a given IP address is part of the network represented by this IPv4 object."""

        # Convert the provided ip input to an integer
        if isinstance(ip, str):
            ipInt = IPv4Address.ip_int_from_string(self._validate_ipv4_octets(ip))
        elif isinstance(ip, int):
            ipInt = self._validate_ipv4_int(ip)
        elif isinstance(ip, IPv4Address):
            ipInt = ip.ipInt
        else:
            raise ValueError("IP must be string, integer, or IPv4Address")

        # If the network is a single host (/32), just need to check if the addresses are the same
        if self.prefixLen == 32:
            return ipInt == self.ipInt # The below logic would work too, but checking here is clearer

        # Otherwise, check if the IP falls within the network range (from network ID to broadcast address)
        return self.netIDInt <= ipInt <= self.broadcastInt

    def subnets(self, newPrefix):
        """Generates subnets from the current network based on the given prefix length."""

        if newPrefix <= self.prefixLen or newPrefix > 32:
            raise ValueError(f"newPrefix must be greater than the current prefix length ({self.prefixLen}) and <= 32")

        # If newPrefix is 31 or 32, no subnets are possible
        if newPrefix >= 31:
            yield from ()  # return an empty iterator because there are no subnets

        # Calculate the size of each subnet (block size) based on the new prefix length
        block = 2 ** (32 - newPrefix)

        # Generate block size subnets by stepping through the IP range from the network ID and stopping right before the broadcast address
        for subnetIPInt in range(self.netIDInt, self.broadcastInt + 1, block):
            if subnetIPInt >= self.broadcastInt:
                break  # Stop generating subnets if the next subnet would go beyond the broadcast address

            yield IPv4Address(f"{subnetIPInt} /{newPrefix}", self.showSteps) # Yield the new subnet as an IPv4Address object

    def supernet(self, newPrefix):
        """Generate a supernet (larger network) by combining smaller networks into one, based on the provided new prefix length."""

        if newPrefix >= self.prefixLen or newPrefix < 0:
            raise ValueError("newPrefix must be < current prefix and >=0")

        # Calculate the subnet mask using the new prefix
        netmaskInt = IPv4Address.calculate_netmask_int(newPrefix)

        # Calculate the supernet network ID using the new prefix.
        supernetNetIDInt = IPv4Address.calculate_network_id_int(self.ipInt, netmaskInt)

        # Return a new IPv4Address object representing the supernet with the new prefix length
        return IPv4Address(f"{supernetNetIDInt} /{newPrefix}", self.showSteps)

    def __str__(self):
        return f"""IPv4 Address:                    {self.ipStr}
Subnet Mask:                     {self.netmaskStr}
Host Mask (Inverse Subnet Mask): {self.hostmaskStr}
Prefix Length:                   {self.prefixLen}

Network ID:        {self.netIDStr}
Broadcast Address: {self.broadcastStr}

First Host:      {self.firstHost}
Last Host:       {self.lastHost}
Total Addresses: {self.totalAddresses:,d}
Usable Hosts:    {self.usableHosts:,d}

Host (CIDR):    {self.cidrAdr}
Network (CIDR): {self.netIDCIDR}

Binary (IPv4 Address):      {self.ipBin}
Binary (Subnet Mask):       {self.netmaskBin}
Binary (Host Mask):         {self.hostmaskBin}
Binary (Network ID):        {self.netIDBin}
Binary (Broadcast Address): {self.broadcastBin}

Address Class (Historical):                       {self.adrClassStr}
Private Address, Non-Publicly Routable (RFC1918): {self.privateUse}
Link-Local Address, Non-Routable (RFC3927):       {self.linkLocal}
Multicast:                                        {self.multicast}
Loopback:                                         {self.loopback}
"""

    def _print_steps(self):
        if self.prefixLen == 32:
            print("""This is a /32 network.

A /32 represents a single IP address, not a range. That means:
- Network ID = the IP address itself
- Broadcast address = the same IP address
- There are no additional usable host addresses

Since there is only one address, subnetting calculations do not really apply here.
""")
            return

        elif self.prefixLen == 31:
            print("""This is a /31 network.

A /31 network contains exactly 2 IP addresses. Unlike most subnets:
- Both addresses are usable
- There is no traditional network ID or broadcast address

This type of subnet is typically used for point-to-point links (like between two routers).

Because of this special behavior, many of the usual subnetting steps do not apply.
""")
            return

        # General case explanation
        self._print_binary_steps()
        self._print_block_size_steps()

    def _print_binary_steps(self):
        print(f"""Binary steps for {self.cidrAdr} ({self.ipStr} {self.netmaskStr})

IP Address
{self.ipStr} -> {', '.join(self.ipStr.split('.'))} -> {self.ipBin}

Subnet Mask
{self.netmaskStr} -> {', '.join(self.netmaskStr.split('.'))} -> {self.netmaskBin}

CIDR Prefix Length -> Subnet Mask (binary)
{self.cidrAdr} -> {self.prefixLen} -> {self.netmaskBin.replace('0','').rstrip(' ')} -> {self.netmaskBin}

Host Mask
Subnet mask:                      {self.netmaskBin}
Host mask (inverted subnet mask): {self.hostmaskBin}

Network ID
 IP address:   {self.ipBin}
Subnet mask: & {self.netmaskBin}
               -----------------------------------
 Network ID:   {self.netIDBin}

Broadcast
  Host mask:   {self.hostmaskBin}
 Network ID: | {self.netIDBin}
               -----------------------------------
  Broadcast:   {self.broadcastBin}

First Host
Network ID:   {self.netIDBin}
            + 00000000 00000000 00000000 00000001
              -----------------------------------
First Host:   {IPv4Address._space_out_binary_string(format(self.netIDInt + 1, '032b'))}

Last Host
Broadcast:   {self.broadcastBin}
           - 00000000 00000000 00000000 00000001
             -----------------------------------
Last Host:   {IPv4Address._space_out_binary_string(format(self.broadcastInt - 1, '032b'))}

Total Addresses
      Broadcast:   {self.broadcastBin}
     Network ID: - {self.netIDBin}
                   -----------------------------------
                   {IPv4Address._space_out_binary_string(format(self.broadcastInt - self.netIDInt, '032b'))}
          Add 1: + 00000000 00000000 00000000 00000001
                   -----------------------------------
Total Addresses:  {IPv4Address._space_out_binary_string(format(self.broadcastInt - self.netIDInt + 1, '032b'))}

IP Address
{self.ipStr}

Subnet Mask
{self.netmaskBin} -> {self.netmaskStr}

Host Mask
{self.hostmaskBin} -> {self.hostmaskStr}

Network ID
{IPv4Address._space_out_binary_string(format(self.ipInt & self.netmaskInt, '032b'))} -> {self.netIDStr}

Broadcast
{IPv4Address._space_out_binary_string(format(self.netmaskInt ^ IPv4Address.ALL_ONES | self.netIDInt, '032b'))} -> {self.broadcastStr}

First Host
{IPv4Address._space_out_binary_string(format(self.netIDInt + 1, '032b'))} -> {self.firstHost}

Last Host
{IPv4Address._space_out_binary_string(format(self.broadcastInt - 1, '032b'))} -> {self.lastHost}

Total Addresses
{IPv4Address._space_out_binary_string(format(self.broadcastInt - self.netIDInt + 1, '032b'))} -> {self.totalAddresses}

Usable Hosts
{self.totalAddresses} - 2 = {self.usableHosts}""")

    def _print_block_size_steps(self):
        blockSize = 2**(8 - self.prefixLen % 8)
        interestingOctet = self.prefixLen // 8 + 1
        octets = self.ipStr.split(".")
        if self.prefixLen % 8 == 0:
            boundaryOctet = self.prefixLen // 8  # last fully fixed octet
            print(f"""
Block size steps for {self.cidrAdr}

The prefix falls on an octet boundary (/8, /16, /24), so there is no interesting octet.

Host Mask
All ones:      255.255.255.255
Subnet mask: - {self.netmaskStr}
               ---------------
Host mask:     {self.hostmaskStr}

Network ID
Copy the first {boundaryOctet} octet(s) from the IP address and set the rest to 0 -> {self.netIDStr}

Broadcast Address
Set all host octets (everything after octet {boundaryOctet}) to 255 -> {self.broadcastStr}

First Host
{self.netIDStr} + 1 = {self.firstHost}

Last Host
{self.broadcastStr} - 1 = {self.lastHost}

Total Addresses
{self.cidrAdr} -> {self.prefixLen} -> 32 - {self.prefixLen} = {32 - self.prefixLen} -> 2^{32 - self.prefixLen} = {2**(32 - self.prefixLen)} total addresses

Usable Hosts
{self.totalAddresses} - 2 = {self.usableHosts}
""")
            return

        print(f"""
Block size steps for {self.cidrAdr}

Block Size
{self.cidrAdr} -> {self.prefixLen} -> {8 - self.prefixLen % 8} host bits in octet {interestingOctet} (the interesting octet) -> block size = 2^{8 - self.prefixLen % 8} = {blockSize}

Host Mask
All ones:      255.255.255.255
Subnet mask: - {self.netmaskStr}
               ---------------
Host mask:     {self.hostmaskStr}

Network ID
Octet {interestingOctet} value for network ID = {octets[interestingOctet - 1]} // {blockSize} * {blockSize} -> {int(octets[interestingOctet - 1]) // blockSize * blockSize}
Octet {interestingOctet} value set to {int(octets[interestingOctet - 1]) // blockSize * blockSize} and all octets to the right of it set to 0 -> {self.netIDStr}

Broadcast Address
Add {blockSize} to octet {interestingOctet} in {self.netIDStr} and subtract 1 = {self.broadcastStr.split('.')[interestingOctet - 1]}. Then replace octets to the right of the interesting octet with 255 -> {self.broadcastStr}

First Host
{self.netIDStr} + 1 = {self.firstHost}

Last Host
{self.broadcastStr} - 1 = {self.lastHost}

Total Addresses
{self.cidrAdr} -> {self.prefixLen} -> 32 - {self.prefixLen} = {32 - self.prefixLen} -> 2^{32 - self.prefixLen} = {2**(32 - self.prefixLen)} total addresses

Usable Hosts
{self.totalAddresses} - 2 = {self.usableHosts}
""")

    def _explain_how_to_calculate(self):
        # Handle special cases first
        if self.prefixLen == 32:
            print("""This is a /32 network.

A /32 represents a single IP address, not a range. That means:
- Network ID = the IP address itself
- Broadcast address = the same IP address
- There are no additional usable host addresses

Since there is only one address, subnetting calculations do not really apply here.
""")
            return

        elif self.prefixLen == 31:
            print("""This is a /31 network.

A /31 network contains exactly 2 IP addresses. Unlike most subnets:
- Both addresses are usable
- There is no traditional network ID or broadcast address

This type of subnet is typically used for point-to-point links (like between two routers).

Because of this special behavior, many of the usual subnetting steps do not apply.
""")
            return

        # General case explanation
        print("""There are two main ways to calculate subnetting information from an IP address and prefix length:

1. Binary Method
- Converts everything into binary (1s and 0s)
- Shows exactly how network and host bits are separated
- Most detailed and reliable method, but can be slower by hand

2. Block Size Method
- Uses patterns in decimal (no binary conversion needed)
- Faster once you understand how subnet ranges work
- Commonly used in real-world scenarios and exams

Both methods will give you the same final answers:
- Network ID
- Broadcast address
- First and last usable host
- Total number of addresses

Both methods will be gone through step-by-step so you can see how they work and compare them.
""")

        # Show both methods
        self._explain_binary_steps()
        self._explain_block_method_steps()

    def _explain_binary_steps(self):
        print(f"\n--- Binary Method for {self.cidrAdr} ---\n")

        # Step 1: IP to Binary
        octets = self.ipStr.split('.')
        print(f"Step 1: Convert the IP address {self.ipStr} to binary by splitting octets: {', '.join(octets)}")
        self._show_binary_conversion_methods(octets)

        # Step 2: Subnet Mask
        self._show_mask_to_binary()

        # Step 3: Host Mask
        self._show_hostmask_to_binary()

        # Step 4: Network ID
        self._show_network_id_calc()

        # Step 5: Broadcast Address
        self._show_broadcast_calc()

        # Step 6: First and Last Usable Hosts
        self._show_first_last_host_calc()

        # Step 7: Total Addresses and Total Usable Hosts
        self._show_calc_total_hosts()

        # Step 8: Convert binary addresses to dotted-decimal notation
        self._show_binary_to_dotted_decimal_notation()

    def _show_binary_conversion_methods(self, octets):
        print(f"First you need to split the IP address into its four octets: {self.ipStr} -> {', '.join(octets)}")
        print("Next, you need to convert each octet into binary. There are 2 primary methods to do this:\n1. Subtract Powers of 2\n2. Repeated Division by 2")

        # Method 1: Subtract Powers of 2
        self._show_method_subtract_powers(octets)

        # Method 2: Repeated Division by 2
        self._show_method_repeated_division(octets)

    def _show_method_subtract_powers(self, octets):
        print("""
Method 1: Subtract Powers of 2

1.1.1 Write the base 10 equivalent (since the IP address octets are in base 10) for the powers of 2
2^7  2^6  2^5  2^4  2^3  2^2  2^1  2^0
128  64   32   16   8    4    2    1

1.1.2 For each octet, subtract powers of 2 starting from the largest that fits:
""")
        bins = []
        for i in octets:
            i = int(i)

            binStr = ""
            print(f"Octet {i}")
            for j in reversed(range(8)):
                j = 2**j
                if i >= j:
                    binStr += "1"
                    msg = f"and subtract {j} from {i} ({i} - {j} = {i - j})"
                    print(f"Since {str(i).rjust(3)} >= {str(j).ljust(3)}, add a 1 to the binary number ({binStr}){' ' * (8-len(binStr))} {msg}{' ' * (43 - len(msg))} then go to the next power")
                    i -= j
                else:
                    binStr += "0"
                    print(f"Since {str(i).rjust(3)} <  {str(j).ljust(3)}, add a 0 to the binary number ({binStr}){' ' * (8-len(binStr))} {' ' * 43} then go to the next power")
                #print(str(binStr).ljust(8))

            bins.append(binStr)
            print("\nThis results in:")
            for j in binStr:
                print(j + "    ", end="")

            print("""
2^7  2^6  2^5  2^4  2^3  2^2  2^1  2^0
128  64   32   16   8    4    2    1
""")

        print(f"1.1.3 Combine each binary octet (in the original order of the IPv4 octets):\n{' '.join(bins)} == {self.ipStr}")
        # Check my "work" with an assertion (the class uses a simpler calculation method that should have zero errors)
        assert " ".join(bins) == self.ipBin

    def _show_method_repeated_division(self, octets):
        print("\nMethod 2: Repeated Division by 2\n\n1.2.1 Divide each octet by 2 until you reach 0 and record each remainder.")

        remainders = []
        for i in octets:
            i = int(i)

            toAdd = []
            print(f"\nOctet {i}")
            num = 1
            while i > 0:
                print(f"{str(i).rjust(3)} / 2 = {str(i//2).ljust(3)}, remainder {num} = {i % 2}")
                toAdd.append(str(i % 2))
                i //= 2
                num += 1

            remainders.append(toAdd)

        print(f"\n1.2.2 In reverse order, write the recorded remainders from left to right to create the binary number. As necessary, prefix the binary number with 0s until there are 8 digits")

        bins = []
        for j, i in enumerate(octets):
            i = int(i)

            print(f"\nOctet {i}")

            revRemainders = list(reversed(remainders[j]))

            for j in range(len(revRemainders)):
                print(f"r{len(revRemainders) - j} ", end="")
            print("")

            for j in revRemainders:
                print(f" {j}", end=" ")
            print("")

            binStr = "".join(revRemainders).rjust(8, "0")
            bins.append(binStr)
            print(binStr)

        print(f"\n1.2.3 Combine each binary octet (in the original order of the IPv4 octets):\n{' '.join(bins)} == {self.ipStr}")
        # Check my "work" with an assertion (the class uses a simpler calculation method that should have zero errors)
        assert " ".join(bins) == self.ipBin

    def _show_mask_to_binary(self):
        print("\nStep 2: Convert the subnet mask to binary.")
        print(f"If this is in dotted-decimal notation already ({self.netmaskStr}) then repeat everything in step 1. If the subnet mask was provided as a prefix length ({self.prefixLen}) from CIDR notation ({self.cidrAdr}) then simply write out {self.prefixLen} '1's (prefix length) and {32 - self.prefixLen} '0's (32 - {self.prefixLen} = {32 - self.prefixLen}).")

        netmask = '1' * self.prefixLen + '0' * (32 - self.prefixLen)
        print(IPv4Address._space_out_binary_string(netmask))

        # Check my "work" with an assertion (the class uses a simpler calculation method that should have zero errors)
        assert IPv4Address._space_out_binary_string(netmask) == self.netmaskBin

    def _show_hostmask_to_binary(self):
        print("\nStep 3: Calculate the host mask in binary from the subnet mask.")

        print(f"""
To start, it is important to know that the host mask is the inverse of the subnet mask, and it represents the bits in the IP address that can be used for hosts in the network. This mask is useful in determining which bits are allocated for host addresses. The host mask is also known as the inverse subnet mask, the host bits mask, the match mask, and the wildcard mask.

To calculate the host mask, take the subnet mask binary value from earlier and inverse the bits by changing all of the 1s to a 0 and all of the 0s to a 1:
Subnet mask: {self.netmaskBin}
Host mask:   {IPv4Address._space_out_binary_string(format(self.netmaskInt ^ IPv4Address.ALL_ONES, '032b'))}

If you have the CIDR notation ({self.cidrAdr}), you can skip writing out the subnet mask in binary just to invert it, and instead write the host mask in binary directly using the prefix length. Using the prefix length of {self.prefixLen}, write {self.prefixLen} '0's and {32 - self.prefixLen} '1's (32 - {self.prefixLen} = {32 - self.prefixLen}):""")

        hostmask = '0' * self.prefixLen + '1' * (32 - self.prefixLen)
        print(f"Host mask:   {IPv4Address._space_out_binary_string(hostmask)}")

        print(f"""
Bonus info: computers can calculate the host mask two different ways to get the same result, but it is more complicated than the process of "flipping bits". This information is provided for a general understanding of how computers perform this task and the bitwise operations won't explained.

Computer Method 1. Bitwise NOT (~) the subnet mask and bitwise AND (&) the result with 32 1's (0xFFFFFFFF or 11111111 11111111 11111111 11111111)

A computer can calculate the host mask by bitwise NOT (~) the subnet mask and, if necessary, bitwise AND (&) the result with 32 1's to keep the number a positive 32-bit integer. This gives us the host mask:

Subnet mask: ~ {self.netmaskBin}
               -----------------------------------
              {IPv4Address._space_out_binary_string(format(~ self.netmaskInt, '032b'))}

Note: Python treats this as a negative number because unsigned integers aren't supported. If it was an unsigned 32-bit integer, the result would be the host mask. As such, the next step is to bitwise AND (&) the result with 32 1's to change the number back to a 32-bit positive number:

              {IPv4Address._space_out_binary_string(format(~ self.netmaskInt, '032b'))}
   All Ones: & 11111111 11111111 11111111 11111111
               -----------------------------------
  Host mask:   {IPv4Address._space_out_binary_string(format(~ self.netmaskInt & IPv4Address.ALL_ONES, '032b'))}

Computer Method 2. Bitwise XOR (^) the subnet mask and 32 1's (0xFFFFFFFF or 11111111 11111111 11111111 11111111)

Another way a computer can calculate the host mask is by bitwise XOR (^) the subnet mask and 32 1's. This operation flips the bits of the subnet mask, resulting in the same host mask as the first method. The benefit is not needing to worry about signed and unsigned integers.

Subnet mask:   {self.netmaskBin}
   All Ones: ^ 11111111 11111111 11111111 11111111
               -----------------------------------
  Host mask:   {IPv4Address._space_out_binary_string(format(self.netmaskInt ^ IPv4Address.ALL_ONES, '032b'))}""")

        # Check my "work" with an assertion (the class uses a simpler calculation method that should have zero errors)
        assert IPv4Address._space_out_binary_string(hostmask) == self.hostmaskBin

        # double check that python is performing bitwise operations as expected
        assert self.netmaskInt ^ IPv4Address.ALL_ONES == self.hostmaskInt
        assert ~ self.netmaskInt & IPv4Address.ALL_ONES == self.hostmaskInt

    def _show_network_id_calc(self):
        print("\nStep 4: Calculate the network ID using the IP address and subnet mask.")
        print("This is done using a binary operation called bitwise AND (&). If both bits equal 1, the network ID bit is set to 1. Otherwise, the network ID is set to 0\n")
        print(f" IP address:   {self.ipBin}")
        print(f"Subnet mask: & {self.netmaskBin}")
        print("               " + "-" * 35)
        print(" Network ID:   " + IPv4Address._space_out_binary_string(format(self.ipInt & self.netmaskInt, '032b')))

        # This is not necessary since this is how the class calculates the netmaskBin
        assert IPv4Address._space_out_binary_string(format(self.ipInt & self.netmaskInt, '032b')) == self.netIDBin

    def _show_broadcast_calc(self):
        print(f"""
Step 5: Calculate the broadcast address.

To get the broadcast address, bitwise OR (|) the host mask ({self.hostmaskBin}) with the network ID. If both bits equal 0, the broadcast bit is set to 0. Otherwise, the broadcast bit is set to 1.

  Host mask:   {IPv4Address._space_out_binary_string(format(self.netmaskInt ^ IPv4Address.ALL_ONES, '032b'))}
 Network ID: | {self.netIDBin}
               -----------------------------------
  Broadcast:   {IPv4Address._space_out_binary_string(format(self.netmaskInt ^ IPv4Address.ALL_ONES | self.netIDInt, '032b'))}""")

        # Check my "work" with an assertion (the class uses a simpler calculation method that should have zero errors)
        assert self.netmaskInt ^ IPv4Address.ALL_ONES | self.netIDInt == self.broadcastInt

    def _show_first_last_host_calc(self):
        print("\nStep 6: Calculate the first usable host and last usable host.")

        print(f"""
To get the first usable host, simply add 1 to the network ID
Network ID:   {self.netIDBin}
            + 00000000 00000000 00000000 00000001
              -----------------------------------
First Host:   {IPv4Address._space_out_binary_string(format(self.netIDInt + 1, '032b'))}

To get the last usable host, simply subtract 1 from the broadcast
Broadcast:   {self.broadcastBin}
           - 00000000 00000000 00000000 00000001
             -----------------------------------
Last Host:   {IPv4Address._space_out_binary_string(format(self.broadcastInt - 1, '032b'))}""")

        # Check my "work" with an assertion (the class uses a simpler calculation method that should have zero errors)
        assert IPv4Address.ip_string_from_int(self.netIDInt + 1) == self.firstHost
        assert IPv4Address.ip_string_from_int(self.broadcastInt - 1) == self.lastHost

    def _show_calc_total_hosts(self):
        print("\nStep 7: Calculate the total addresses available and total usable hosts.")

        print(f"""
There are two methods to get the total addresses available:
1. Take the broadcast and subtract the network ID, then add 1. Then convert to decimal.
2. Raise 2 to the the host bits power.""")

        # Method 1: Take the broadcast and subtract the network ID, then add 1. Afterwards, convert the binary to decimal.
        self._method_subtract_and_add_to_get_total_hosts()

        # Method 2: Raise 2 to the host bits power.
        self._method_host_bits_exponent_total_hosts()

    def _method_subtract_and_add_to_get_total_hosts(self):
        print(f"""
Method 1: Take the broadcast and subtract the network ID, then add 1. Afterwards, convert the binary to decimal.

 Broadcast:   {self.broadcastBin}
Network ID: - {self.netIDBin}
              -----------------------------------
              {IPv4Address._space_out_binary_string(format(self.broadcastInt - self.netIDInt, '032b'))}
     Add 1: + 00000000 00000000 00000000 00000001
              -----------------------------------
              {IPv4Address._space_out_binary_string(format(self.broadcastInt - self.netIDInt + 1, '032b'))}""")

        # Check my "work" with an assertion (the class uses a simpler calculation method that should have zero errors)
        assert self.broadcastInt - self.netIDInt + 1 == self.totalAddresses

        usableHosts = 1 if self.prefixLen == 32 else 2 if self.prefixLen == 31 else self.totalAddresses - 2
        assert usableHosts == self.usableHosts

        # Convert binary number to decimal to get total addresses
        self._show_binary_to_decimal()

        print(f"""Knowing the total number of addresses, calculating the usable hosts is as simple as total addresses - 2. The minus 2 comes from not being able to use the network ID and not being able to use the broadcast. The two exceptions are a 255.255.255.254 (/31) subnet or 255.255.255.255 (/32) subnet. For both of these, the total usable hosts are the same as the total addresses (no minus 2).

For {self.cidrAdr}, the {self.totalAddresses:,d} total addresses - 2 = {self.totalAddresses - 2:,d} usable hosts.""")

        # Check my "work" with an assertion (the class uses a simpler calculation method that should have zero errors)
        if self.prefixLen < 31:
            assert self.totalAddresses - 2 == self.usableHosts
        else:
            assert self.usableHosts in (1, 2)

    def _show_binary_to_decimal(self):
        print(f"""
Next, convert it to decimal (base 10). The rules of this conversion is slightly different than IP addresses because those are split into 4 equal chunks of 8 bits (1 byte) known as octets, which actually makes the conversion between decimal and binary simpler because the numbers are smaller. However, the conversion process is still the same and the two primary methods of converting binary (base 2) to decimal (base 10) are:
1. Add Powers of 2
2. Multiply By 2 and Add""")

        binStr = format(self.totalAddresses, "032b")

        # Method 1: Add Powers of 2
        self._show_method_add_powers_of_2(binStr)

        # Method 2: Multiply By 2 and Add
        self._show_method_multiply_by_2_and_add(binStr)

    def _show_method_add_powers_of_2(self, binStr):
        print(f"""
Method 1: Add Powers of 2

This is essentially the reverse of method 1 for converting decimal to binary, this should be familiar. The big difference is that the total addresses could be 2,147,483,648 if the prefix length was 1. As such, you will need a much bigger base 10 equivalent for the powers of 2 if you have a small prefix. Here is a cheat sheet:

/1          /2          /3         /4         /5         /6        /7        /8        /9       /10      /11      /12      /13     /14     /15     /16    /17    /18    /19   /20   /21   /22   /23  /24  /25  /26  /27  /28  /29  /30  /31  /32
2^31        2^30        2^29       2^28       2^27       2^26      2^25      2^24      2^23     2^22     2^21     2^20     2^19    2^18    2^17    2^16   2^15   2^14   2^13  2^12  2^11  2^10  2^9  2^8  2^7  2^6  2^5  2^4  2^3  2^2  2^1  2^0
2147483648  1073741824  536870912  268435456  134217728  67108864  33554432  16777216  8388608  4194304  2097152  1048576  524288  262144  131072  65536  32768  16384  8192  4096  2048  1024  512  256  128  64   32   16   8    4    2    1

To start, add the base 10 value associated with the power of 2 wherever the binary digit is 1 and skip adding the value when the binary digit is 0. Given the total addresses value in binary is:
{IPv4Address._space_out_binary_string(format(self.broadcastInt - self.netIDInt + 1, '032b'))}
if you decided to include all of the zeros when following these steps, it would turn into this mess:""")

        toPrint = ""
        toPrint2 = ""
        num = 0
        for j in range(31, -1, -1):
            toPrint += f"{binStr[31 - j]} * 2^{j} + "
            toPrint2 += f"{int(binStr[31 - j])* 2**j} + "
            num += int(binStr[31 - j])* 2**j

        print(f"""{toPrint.rstrip(' +')} =

Which simplifies too:
{toPrint2.rstrip(' +')} = {num}

However, if you only wrote down a number to add when the value is 1, it would be this:""")

        toPrint = ""
        toPrint2 = ""
        num2 = 0
        for j in range(31, -1, -1):
            if binStr[31 - j] == "1":
                toPrint += f"{binStr[31 - j]} * 2^{j} + "
                toPrint2 += f"{int(binStr[31 - j])* 2**j} + "
                num2 += int(binStr[31 - j])* 2**j

        if toPrint == "":
            print("Since all 0s, it simply = 0")

        if toPrint2 != "":
            print(f"""{toPrint.rstrip(' +')} =

Which simplifies too:
{toPrint2.rstrip(' +')} = {num2}""")

        assert num == num2 and num == self.totalAddresses

    def _method_host_bits_exponent_total_hosts(self):
        print(f"""
Method 2: Raise 2 to the host bits power.

To get the number of host bits using the subnet mask in binary format, count the total number of 0s:
{self.netmaskBin}
# of 0s = {self.netmaskBin.count("0")}
host bits = {self.netmaskBin.count("0")}

The other method involves subtracting the CIDR address ({self.cidrAdr}) prefix length from 32.
32 - {self.prefixLen} = {32 - self.prefixLen}
host bits = {32 - self.prefixLen}

Now raise 2 to the power of {32 - self.prefixLen} (# of host bits) to get the total addresses:
2^{32 - self.prefixLen} = {2**(32 - self.prefixLen):,d}

If desired, you can estimate the total number of hosts using the number of host bits:

Total addresses = 2^{32 - self.prefixLen}

Break the exponent into groups of 10. Since 2^10 approximately equals 1000, this simplifies the math for estimating by hand.

Rewrite the exponent as:

2^{32 - self.prefixLen} = {'2^10 * ' * ((32 - self.prefixLen) // 10)}2^{(32 - self.prefixLen) % 10}

Replace each 2^10 with 1000, solve the remaining exponents, and multiply.

{'1000 * ' * ((32 - self.prefixLen) // 10)}{2**((32 - self.prefixLen) % 10)} = {1000**((32 - self.prefixLen) // 10) * 2**((32 - self.prefixLen) % 10):,d} total addresses

This gives a quick estimate that is slightly lower than the exact value but much easier to calculate.

For a full explanation, see the block size section.""")

    def _show_method_multiply_by_2_and_add(self, binStr):
        binStr = IPv4Address._space_out_binary_string(binStr)
        oneIndex = binStr.index('1')

        print(f"""
Method 2: Multiply By 2 and Add

The first method could be intimidating and tedious when the prefix length is unusually small. Fortunately, this method involves a formula that prevents the need to write base 10 equivalents for the powers of 2.

For this method, you use this formula:

Start at left-most digit, set total to 0, plug in values, and solve:
total * 2 + value of current digit (a 1 or 0) = new total.
Move right 1 digit and repeat.

To save time and skip adding and multiplying by 0, find the left-most 1 digit in the binary number. This 1 digit will be the starting total for the total addresses since 0 (previous total) * 2 + 1 (current digit) = 1.

{binStr}
{' ' * oneIndex}^
start = 1

Then move right 1 digit, multiply the current total by 2, and add that digit to the product. Repeat this process until all binary digits have been processed.

Here is the rest of the process:
""")

        num = 1
        for j in range(1, len(binStr) - oneIndex):
            index = oneIndex + j
            if binStr[index] == " ":
                continue

            print(f"{binStr}\n{' ' * index}^\n{num} * 2 + {binStr[index]} = {num * 2 + int(binStr[index])}\n")
            num = num * 2 + int(binStr[index])

        # Check my "work" with an assertion (the class uses a simpler calculation method that should have zero errors)
        assert num == self.totalAddresses

    def _show_binary_to_dotted_decimal_notation(self):
        print(f"""
Step 8: Convert the binary addresses back to the more common dotted-decimal notation. At this point, these are the known addresses and binary values:

IPv4 Address: {self.ipStr}
 Subnet Mask: {self.netmaskBin} (or if started with a dotted-decimal address, then {self.netmaskStr})
   Host Mask: {self.hostmaskBin}
  Network ID: {self.netIDBin}
Broadcast ID: {self.broadcastBin}
  First Host: {IPv4Address._space_out_binary_string(format(self.netIDInt + 1, '032b'))}
   Last Host: {IPv4Address._space_out_binary_string(format(self.broadcastInt - 1, '032b'))}

Once again, you will need the base-10 equivalents for the powers of 2. Fortunately, since dotted-decimal notation only allows a maximum value of 255 per octet, you only need 8 bits, making this a reasonable and common approach for converting by hand.

Note: While you can use the "multiply by 2 and add current digit" process demonstrated in calculating the total addresses, it is recommended to write out the following cheat sheet when working with octets, as this often makes conversions easier and reduces the amount of multiplication required.

2^7  2^6  2^5  2^4  2^3  2^2  2^1  2^0
128  64   32   16   8    4    2    1

Using this, add the base-10 value wherever the binary digit is 1, and add nothing where the digit is 0.\n""")

        binaryData = [
            ("subnet mask", "Subnet Mask", self.netmaskBin, self.netmaskStr),
            ("host mask", "Host Mask", self.hostmaskBin, self.hostmaskStr),
            ("network ID", "Network ID", self.netIDBin, self.netIDStr),
            ("broadcast", "Broadcast", self.broadcastBin, self.broadcastStr),
            ("first host address", "First Host", IPv4Address._space_out_binary_string(format(self.netIDInt + 1, '032b')), self.firstHost),
            ("last host address", "Last Host", IPv4Address._space_out_binary_string(format(self.broadcastInt - 1, '032b')), self.lastHost),
        ]

        for label1, label2, binStr, ipAdr in binaryData:
            print(f"This is the conversion process for the {label1} ({binStr})")
            octets = []
            for n, j in enumerate(binStr.split(" ")):
                toPrint = ""
                toPrint2 = ""
                num = 0

                print(f"\nOctet {n + 1}: {j}")
                for k in range(8):
                    if j[k] == "1":
                        toPrint += f"{j[k]} * 2^{7-k} + "
                        toPrint2 += f"{int(j[k]) * 2**(7-k)} + "
                        num += int(j[k]) * 2**(7-k)

                if toPrint == "":
                    print("Since all 0s = 0")

                if toPrint2 != "":
                    print(f"{toPrint.rstrip(' +')} = ")

                    print("\nThen simplified")

                    print(f"{toPrint2.rstrip(' +')} = {num}")

                octets.append(str(num))

            print(f"\nFinally, combine them together with a period separating them:\n{label2}: {'.'.join(octets)}\n")

            # Check my "work" with an assertion (the class uses a simpler calculation method that should have zero errors)
            assert '.'.join(octets) == ipAdr




        print(f"""Note: instead of converting from binary to get the first and last host addresses, you could have added 1 to the network address {self.netIDStr} to get the first host {self.firstHost} and subtracted 1 from the broadcast address {self.broadcastStr} to get the last host {self.lastHost}.

If you rather use "multiply by 2 and add current digit" process for each octet, this is how you would do it for all of the values:
""")
        for label1, label2, binStr, ipAdr in binaryData:
            print(f"This is the conversion process for the {label1} ({binStr})")

            binOctets = binStr.split(" ")
            octets = []

            for octetNum, binStr in enumerate(binOctets):
                if "1" not in binStr:
                    print(f"\nOctet {octetNum + 1}\n{binStr}\nSince all 0s = 0")
                    num = 0
                else:
                    num = 1
                    oneIndex = binStr.index("1")
                    print(f"\nOctet {octetNum + 1}\n{binStr}\n{' ' * oneIndex}^\nstart = 1")
                    for j in range(1, len(binStr) - oneIndex):
                        index = oneIndex + j
                        if binStr[index] == " ":
                            continue

                        print(f"\n{binStr}\n{' ' * index}^\n{num} * 2 + {binStr[index]} = {num * 2 + int(binStr[index])}")
                        num = num * 2 + int(binStr[index])

                print(f"Octet {octetNum + 1} = {num}")
                octets.append(str(num))

            print(f"\nFinally, combine them together with a period separating them:\n{label2}: {'.'.join(octets)}\n")

            # Check my "work" with an assertion (the class uses a simpler calculation method that should have zero errors)
            assert '.'.join(octets) == ipAdr

    def _explain_block_method_steps(self):
        print(f"\n--- Block Size Method for {self.cidrAdr} ---\n")

        print(f"""
Steps to calculate key IPv4 information for {self.cidrAdr} -- Block Size/Host Bits method

There are two primary non-binary methods of calculating subnetting information. The Block Size and Host Bits methods are essentially the same in concept, but they approach subnetting from different angles.

In practice, both methods are used to determine the total number of addresses in a subnet (not just usable hosts).

To simplify things, the Host Bits method can be adjusted to only consider the host bits in the interesting octet. The interesting octet is the first octet where the subnet mask stops being 255. This is where subnetting actually happens, meaning this is the only part of the IP address that changes between subnets. Keeping the
Applying the host bits method to the interesting octet keeps the math simple and aligns it directly with the block size method. Since this modification produces the same result for calculating key networking information, this will only refer to the process as the block size method from this point forward.""")

        # Step 1: Calculate the block size
        # Note: this sets octetNum and blockSize in self for future function calls
        self._show_block_size_calc()

        # Step 2: Host mask
        self._show_hostmask_calc_block_method()

        # Step 3: Calculate the network ID for the IP address
        self._show_calculate_network_id()

        # Step 4: Broadcast Address
        self._show_broadcast_calc_block_method()

        # Step 5: First and Last Usable Hosts
        self._show_first_last_host_calc_block_method()

        # Step 6: Total Addresses and Total Usable Hosts
        self._show_calc_total_hosts_block_method()

    def _show_block_size_calc(self):
        print("""
Step 1: Calculate the block size

The block size is the total number of IP addresses in each subnet (including network and broadcast addresses). The main advantage of this method is that it avoids binary conversion and allows you to quickly determine subnet ranges. The tradeoff is that it may require some memorization, quick mental math, or guess work, which are issues the binary method does not have.

Since each octet can hold 256 values (0 to 255 or 2^8 values for 8 bits), the subnet mask tells us how many of those are used for the network. When you are tasking the subnet mask or CIDR prefix length that applies to the interesting octet, you are finding out how many of those values can be used for the network (block size)

There are two methods of calculating the block size:
1. Using the subnet mask (in dotted decimal notation)
2. Using the prefix length (from the CIDR address)""")

        # Method 1: Using subnet mask to calculate the block size
        # Note: this sets octetNum and blockSize in self for future function calls
        self._show_method_subnet_mask_block_size()

        # Method 2: Using prefix length to calculate the block size
        # Note: this sets octetNum and blockSize in self for future function calls
        self._show_method_prefix_length_block_size()

    def _show_method_subnet_mask_block_size(self):
        # Note: this sets octetNum and blockSize in self for future function calls

        octetVal = ""
        octetNum = 0
        for k, j in enumerate(self.netmaskStr.split(".")):
            if j != "255":
                octetVal = j
                octetNum = k + 1
                break

        if octetVal != "":
            blockSize = 256 - int(octetVal)

        print(f"""
Method 1: Using subnet mask to calculate the block size.

First, identify the interesting octet, which determines the subnet boundaries. This is the first octet in the subnet mask that is not 255. If the interesting octet's value is 0 this means the subnet falls exactly on an octet boundary (/8, /16, /24) and the entire octet is dedicated to host bits. In this case, it is not necessary to calculate the block size since the octet is not being subnetted.

Here are some simple examples to help illustrate this:

IP address = 10.1.2.3

Subnet mask = 255.255.255.0
The interesting octet's value is 0. As such, the network ID will match the IP address up to, but not including, that octet. All remaining octets, including the interesting octet, will be 0. As an added benefit, there is no need to calculate the block size, network bits, or host bits.
Network ID = 10.1.2.0

Subnet mask = 255.255.192.0
Interesting octet = 3, value = 192

Subnet mask = 255.224.0.0
Interesting octet = 2, value = 224

Subnet mask = 128.0.0.0
Interesting octet = 1, value = 128

For {self.netmaskStr}, the interesting octet is #{octetNum} = {octetVal}.
""")

        if blockSize == 256:
            print("Since the interesting octet equals 0, you don't need to figure out the block size")
        else:
            print(f"To calculate the block size, you subtract the interesting octet value from 256:\n256 - {octetVal} = {blockSize} = block size")

        if not hasattr(self, "octetNum"):
            self.octetNum = self.prefixLen // 8 + 1 # Note: this math works great to calculate the interesting octet for prefixLen 0 to 31. If 32, the value is wrong, but at least /32 is already handled above and not allowed to get this far
        if not hasattr(self, "blockSize"):
            self.blockSize = 2**(8 - self.prefixLen % 8)
        assert octetNum == self.octetNum
        assert blockSize == self.blockSize

    def _show_method_prefix_length_block_size(self):
        # Note: this sets octetNum and blockSize in self for future function calls

        print(f"""
Method 2: Using prefix length to calculate the block size.

The interesting octet concept still applies when using CIDR notation, but it is less obvious due to the subnet mask not being in dotted-decimal notation. If you understand that each octet of an IP address in dotted-decimal format represents 8 bits, then the concept should translate easily when you break your prefix length up into chunks of 8. Converting the prefix length to a dotted-decimal subnet mask also works, is unnecessary. If needed, review the binary section to see how both dotted-decimal notation and CIDR notation are represented "under the hood."

This method works by breaking the prefix length into groups of 8 bits (one octet at a time). As you move through the prefix in chunks of 8, each full 8 bits represents a complete octet of network bits. The first chunk that is not a full 8 bits identifies the interesting octet. In dotted-decimal terms, this is the first octet that is not 255. If the prefix falls on an octet boundary (/8, /16, /24), then just like dotted-decimal, it is not necessary to calculate the block size. The network ID will match the IP address for all octets fully covered by the prefix, and remaining octets will be 0.

Here are some examples to help compare the two notations when it comes to interesting octets:
With a prefix of /6  the subnet mask would be 252.0.0.0       (interesting octet = 1)
With a prefix of /8  the subnet mask would be 255.0.0.0       (no calculation needed since prefix ends on an octet boundary)
With a prefix of /10 the subnet mask would be 255.240.0.0     (interesting octet = 2)
With a prefix of /16 the subnet mask would be 255.255.0.0     (interesting octet = 3)
With a prefix of /19 the subnet mask would be 255.255.224.0   (interesting octet = 3)
With a prefix of /24 the subnet mask would be 255.255.255.0   (interesting octet = 4)
With a prefix of /31 the subnet mask would be 255.255.255.254 (interesting octet = 4)

The main benefit of breaking a prefix into 8 bit chunks is that the block size will always fall between 2 and 128, which simplifies the math involved. It also helps reinforce how CIDR notation maps directly to dotted-decimal notation.

Note: This method does not apply to a /32 prefix, since a /32 represents a single host and cannot be subnetted.

To figure out the interesting octet, subtract 8 from the prefix length repeatedly until the remaining value is less than 8. Count how many times you subtracted 8, then add 1. This result is the interesting octet.

The remaining value after the subtraction represents the number of network bits in the interesting octet. To find the number of host bits in the interesting octet, subtract the network bits from 8.

Finally, to get the block size, raise 2 to the power of the number of host bits 2^(host bits).

Here are examples of the process:

If the prefix is /7, then
7 is already less than 8
7 (network bits)
You subtracted 0 times, so the interesting octet (0 + 1) = 1
8 - 7 = 1 host bit
block size = 2^1 = 2

If the prefix is /14, then
14 - 8 = 6 (network bits)
You subtracted 1 time, so the interesting octet (1 + 1) = 2
8 - 6 = 2 host bits
block size = 2^2 = 4

If the prefix is /18, then
18 - 8 = 10, 10 - 8 = 2 (network bits)
You subtracted 2 times, so the interesting octet (2 + 1) = 3
8 - 2 = 6 host bits
block size = 2^6 = 64

If the prefix is /24, then
The prefix falls on an octet boundary (/8, /16, /24) and there is no interesting octet. As such, the network ID will match the IP address up to, but not including, the last octet the prefix covered, and all remaining octets will be 0. As an added benefit, there is no need to calculate the block size, network bits, or host bits.

If the prefix is /29, then
29 - 8 = 21, 21 - 8 = 13, 13 - 8 = 5 (network bits)
You subtracted 3 times, so the interesting octet (3 + 1) = 4
8 - 5 = 3 host bits
block size = 2^3 = 8


For {self.cidrAdr}, the prefix is {self.prefixLen}.""")

        networkBits = self.prefixLen
        octetNum = 1
        toPrint = f"{networkBits}  "


        if networkBits < 8:
            print(f"{networkBits} is already less than 8")
        else:
            while networkBits >= 8:
                toPrint += f"{networkBits} - {8} = {networkBits - 8}, "
                octetNum += 1
                networkBits -= 8

        hostBits = 8 - networkBits
        blockSize = 2**hostBits

        print(f"""{toPrint[:-2]} (network bit{'s' if networkBits != 1 else ''})
You subtracted {octetNum - 1} time{'s' if octetNum - 1 != 1 else ''}, so the interesting octet ({octetNum - 1} + 1) = {octetNum}
8 - {networkBits} = {hostBits} host bit{'s' if hostBits != 1 else ''}
block size = 2^{hostBits} = {blockSize}""")

        print("""
Note: if you are familiar with integer division and modular arithmetic, you could skip the basic arithmetic above and get the interesting octet by doing using this formula using integer division:
interesting octet = prefix_length // 8 + 1
You can also compute the host bits by taking the prefix length modulo 8 and subtracting the result from 8:
host bits = 8 - prefix_length % 8
The above math was chosen since it is simpler to understand.""")

        if not hasattr(self, "octetNum"):
            self.octetNum = self.prefixLen // 8 + 1 # Note: this math works great to calculate the interesting octet for prefixLen 0 to 31. If 32, the value is wrong, but at least /32 is already handled above and not allowed to get this far
        if not hasattr(self, "blockSize"):
            self.blockSize = 2**(8 - self.prefixLen % 8)
        assert octetNum == self.octetNum
        assert blockSize == self.blockSize
        assert hostBits == 8 - self.prefixLen % 8
        assert networkBits == self.prefixLen % 8

    def _show_hostmask_calc_block_method(self):
        print("""
Step 2: Calculate the host mask

Since the host mask is the inverse of the subnet mask there are two methods for calculating it:
1. Using the subnet mask (in dotted decimal notation)
2. Using the prefix length (from the CIDR address)""")

        # Method 1: Using subnet mask to calculate the host mask
        self._show_method_subnet_mask_host_mask()

        # Method 2: Using prefix length to calculate the host mask
        self._show_method_prefix_length_host_mask()

    def _show_method_subnet_mask_host_mask(self):
        octets = self.netmaskStr.split(".")
        for i in range(len(octets)):
            octets[i] = str(255 - int(octets[i]))
        print(f"""
Method 1: Using the subnet mask to calculate the host mask.

Just like the binary method, you will invert the subnet mask, in dotted-decimal notation, to get the host mask. To do this without needing to revert to binary, you take 32 1's in dotted-decimal notation (255.255.255.255) and subtract the subnet mask {self.netmaskStr}. This gives you the host mask.

   All ones:   255.255.255.255
Subnet mask: - {self.netmaskStr}
               ---------------
  Host mask:   {'.'.join(octets)}""")

    def _show_method_prefix_length_host_mask(self):
        groups = [f"/{(32 - self.prefixLen) % 8}"]
        if groups[0] == "/0":
            del groups[0]
        for _ in range((32 - self.prefixLen) // 8):
            groups.append("/8")
        hostMask = "0." * (4 - len(groups))

        print(f"""
Method 2: Using the prefix length to calculate the host mask.

You can calculate the host mask using the prefix length ({self.prefixLen}) from the CIDR address ({self.cidrAdr}) by doing the following:

First, get the number of host bits by subtracting the prefix length from 32:
32 - {self.prefixLen} = {32 - self.prefixLen}

Next, break the host bits into chunks of 8 or less, from left to right, starting with the smallest chunk:
{', '.join(groups)}

Each chunk represents the number of host bits in one octet. If there are fewer than 4 chunks, the remaining octets are filled with 0.

With {len(groups)} chunk{'s' if len(groups) != 1 else ''}, you need {4 - len(groups)} octet{'s' if 4 - len(groups) != 1 else ''} of 0.
{"No 0's needed" if hostMask == '' else hostMask}

Next, calculate the octet values using this formula:
Octet value = 2^(number of host bits in that octet) - 1""")

        for j, i in enumerate(groups):
            i = int(i.lstrip('/'))
            print(f"""
For octet {4 - len(groups) + j + 1}, the chunk has {i} bit{'s' if i != 1 else ''}, so:
2^{i} - 1 = {2**i} - 1 = {2**i - 1}
Octet {4 - len(groups) + j + 1} = {2**i - 1}""")
            hostMask += f"{2**i - 1}."

        hostMask = hostMask.rstrip(".")
        print(f"\nFinally, combine the octet values into a dotted decimal number{'' if 4 - len(groups) == 0 else ' and prefix it with the 0'}{'s' if 4 - len(groups) != 1 else ''}.")
        print(hostMask)

        assert hostMask == self.hostmaskStr

    def _show_calculate_network_id(self):
        print(f"""
Step 3: Calculate the network ID that contains the IP address {self.cidrAdr}

The network ID is the closest multiple of the block size that does not exceed the IP address in the subnetted octet. There are three methods to calculate the network ID:
1. Compute subnets until the desired one is found (works great for large block sizes)
2. Perform integer division on the interesting octet value (works great for small to medium block sizes)
3. Perform modular arithmetic on the interesting octet value (works great for small to medium block sizes)
""")

        # Method 1: compute subnets until the desired one is found
        self._method_calculate_subnets_until_network_id_found()

        # Method 2: perform integer division on the interesting octet value
        self._method_find_network_id_from_integer_division()

        # Method 3: perform modular arithmetic on the interesting octet value
        self._method_find_network_id_from_modular_arithmetic()

    def _method_calculate_subnets_until_network_id_found(self):
        networkOctets = ""
        hostOctets = "(there are none since the interesting octet is 4)"
        justZeroedHostsOctets = '.0' * (4 - self.octetNum)
        octets = self.ipStr.split('.')
        octetVal = int(octets[self.octetNum - 1])
        if self.octetNum > 1:
            networkOctets = '.'.join(octets[:self.octetNum - 1])
        if self.octetNum < 4:
            hostOctets =  f"{'x.' * self.octetNum}{'.'.join(octets[self.octetNum:])}"

        if networkOctets == "":
            strippedIP = f"0{justZeroedHostsOctets}"
        else:
            strippedIP = f"{networkOctets}.0{justZeroedHostsOctets}"


        print(f"""Method 1: compute subnets until the desired one is found. This method works great for large block sizes.

With the block size of {self.blockSize} and the interesting octet #{self.octetNum}, you can now calculate the network ID. Since this is not binary math, there will be some inefficiencies since there is no straight forward method of calculating the network needed, but the primary benefit of not having to convert to and from binary makes this a viable option.

This involves up to two steps. The first is setting the interesting octet {self.octetNum} to 0. The second is setting the octets with only host bits to 0 (everything to the right of the interesting octet). For {self.ipStr}, the octets with only host bits are {hostOctets}.

{self.ipStr} -> {strippedIP}
""")

        if self.prefixLen % 8 == 0: # /8, /16, /24
            subnetID = strippedIP
            print(f"Since the prefix falls on an octet boundary (/8, /16, /24), you don't need to do anything else. {subnetID} is the network ID")
        else:
            print(f"Next, starting from 0, keep adding the block size until the sum is <= the current value in the interesting octet {self.octetNum} and the sum + block size ({self.blockSize}) is > {octetVal}.\n")

            num = 0
            subnetID = strippedIP
            print(f"starting interesting octet = {num}, is {num} <= {octetVal}? {'Yes' if num <= octetVal else 'no'}, is {num} + {self.blockSize} ({num + self.blockSize}) > {octetVal}? {'Yes' if num + self.blockSize > octetVal else 'no'}, subnet ID = {subnetID}\n")
            if self.blockSize >= octetVal:
                print("Nice! No addition necessary since the first subnet ID is the network ID!")
            else:
                toPrintLines = []
                while num < octetVal:
                    num += self.blockSize
                    if networkOctets == "":
                        subnetID = f"{num}{justZeroedHostsOctets}"
                    else:
                        subnetID = f"{networkOctets}.{num}{justZeroedHostsOctets}"

                    toPrintLines.append(f"interesting octet = {str(num - self.blockSize).rjust(3)} + {str(self.blockSize).ljust(3)} = {str(num).ljust(3)}, is {str(num).rjust(3)} <= {str(octetVal).ljust(3)}? {'yes' if num <= octetVal else 'no '}, is {str(num).rjust(3)} + {str(self.blockSize).ljust(3)} = {str(num + self.blockSize).ljust(3)} > {str(octetVal).ljust(3)}? {'yes' if num + self.blockSize > octetVal else 'no '}, subnet ID = {subnetID}")

                    if num <= octetVal and num + self.blockSize > octetVal:
                        if len(toPrintLines) > 15:
                            for j in range(8):
                                print(toPrintLines[j])
                            print("...")
                            for j in range(len(toPrintLines) - 8, len(toPrintLines)):
                                print(toPrintLines[j])
                        else:
                            for j in toPrintLines:
                                print(j)
                        print(f"\nSince both conditions match, the subnet ID, {subnetID}, is the network ID")
                        break

        assert subnetID == self.netIDStr

    def _method_find_network_id_from_integer_division(self):
        networkOctets = ""
        hostOctets = "(there are none since the interesting octet is 4)"
        justZeroedHostsOctets = '.0' * (4 - self.octetNum)
        octets = self.ipStr.split('.')
        octetVal = int(octets[self.octetNum - 1])

        if self.octetNum > 1:
            networkOctets = '.'.join(octets[:self.octetNum - 1])
        if self.octetNum < 4:
            hostOctets =  f"{'x.' * self.octetNum}{'.'.join(octets[self.octetNum:])}"

        if networkOctets == "":
            strippedIP = f"0{justZeroedHostsOctets}"
            subnetID = f"{octetVal // self.blockSize * self.blockSize}{justZeroedHostsOctets}"
        else:
            strippedIP = f"{networkOctets}.0{justZeroedHostsOctets}"
            subnetID = f"{networkOctets}.{octetVal // self.blockSize * self.blockSize}{justZeroedHostsOctets}"

        print("\nMethod 2: find the network ID from integer division. This method works great for small to medium block sizes.")

        if self.prefixLen % 8 == 0: # /8, /16, /24
            print(f"""
Since the prefix falls on an octet boundary (/8, /16, /24), you don't need to do the normal process. Set the interesting octet to 0 (octet {self.octetNum}). Then perform the final step of setting the octets with only host bits to 0 (everything to the right of the interesting octet). For {self.ipStr}, the octets with only host bits are {hostOctets}.

{self.ipStr} -> {strippedIP}

Now you have the network ID: {subnetID}""")
        else:
            print(f"""
Fortunately, for smaller or medium block sizes, performing integer division or modular arithmetic is the easiest and fastest way to calculate the network ID. The process is, in math terms:

Take the interesting octet value ({octetVal}), divide it by the block size ({self.blockSize}) using integer division, then multiply the result by the block size ({self.blockSize}) to get the network ID value in the interesting octet:
Network ID octet value = octet_value // block_size * block_size

Examples:
If the IP address is 10.200.100.1/9, then the interesting octet value is 200, the block size is 128:
Network ID octet value = 200 // 128 * 128
Network ID octet value = 1 * 128
Network ID octet value = 128

If the IP address is 10.200.100.1/12, then the interesting octet value is 200, the block size is 16:
Network ID octet value = 200 // 16 * 16
Network ID octet value = 12 * 16
Network ID octet value = 192

If the IP address is 10.200.100.1/15, then the interesting octet value is 200, the block size is 2:
Network ID octet value = 200 // 2 * 2
Network ID octet value = 100 * 2
Network ID octet value = 200

For {self.cidrAdr}, the interesting octet value is {octetVal}, and the block size is {self.blockSize}
Network ID octet value = {octetVal} // {self.blockSize} * {self.blockSize}
Network ID octet value = {octetVal // self.blockSize} * {self.blockSize}
Network ID octet value = {octetVal // self.blockSize * self.blockSize}

With the Network ID value calculated for the interesting octet (#{self.octetNum}), set that value in the IP address {self.ipStr}. Then set the octets with only host bits to 0 (everything to the right of the interesting octet). For {self.ipStr}, the octets with only host bits are {hostOctets}.

{self.ipStr} -> {subnetID} = network ID""")

        assert subnetID == self.netIDStr

    def _method_find_network_id_from_modular_arithmetic(self):
        networkOctets = ""
        hostOctets = "(there are none since the interesting octet is 4)"
        justZeroedHostsOctets = '.0' * (4 - self.octetNum)
        octets = self.ipStr.split('.')
        octetVal = int(octets[self.octetNum - 1])

        if self.octetNum > 1:
            networkOctets = '.'.join(octets[:self.octetNum - 1])
        if self.octetNum < 4:
            hostOctets =  f"{'x.' * self.octetNum}{'.'.join(octets[self.octetNum:])}"

        if networkOctets == "":
            strippedIP = f"0{justZeroedHostsOctets}"
            subnetID = f"{octetVal - octetVal % self.blockSize}{justZeroedHostsOctets}"
        else:
            strippedIP = f"{networkOctets}.0{justZeroedHostsOctets}"
            subnetID = f"{networkOctets}.{octetVal - octetVal % self.blockSize}{justZeroedHostsOctets}"

        print("\nMethod 3: find the network ID from modular arithmetic. This method works great for small to medium block sizes.")

        if self.prefixLen % 8 == 0: # /8, /16, /24
            subnetID = strippedIP
            print(f"""
Since the prefix falls on an octet boundary (/8, /16, /24), you don't need to do the normal process. Set the interesting octet to 0 (octet {self.octetNum}). Then perform the final step of setting the octets with only host bits to 0 (everything to the right of the interesting octet). For {self.ipStr}, the octets with only host bits are {hostOctets}.

{self.ipStr} -> {subnetID} = network ID""")
        else:
            print(f"""
Take the interesting octet value ({octetVal}), find the remainder (modulo) when dividing it by the block size ({self.blockSize}), then subtract that remainder from the octet value ({octetVal}) to get the network ID value in the interesting octet:
Network ID octet value = octet_value - (octet_value % block_size)

Examples:
If the IP address is 10.200.100.1/9, then the interesting octet value is 200, the block size is 128:
Network ID octet value = 200 - (200 % 128)
Network ID octet value = 200 - 72
Network ID octet value = 128

If the IP address is 10.200.100.1/12, then the interesting octet value is 200, the block size is 16:
Network ID octet value = 200 - (200 % 16)
Network ID octet value = 200 - 8
Network ID octet value = 192

If the IP address is 10.200.100.1/15, then the interesting octet value is 200, the block size is 2:
Network ID octet value = 200 - (200 % 2)
Network ID octet value = 200 - 0
Network ID octet value = 200

For {self.cidrAdr}, the interesting octet value is {octetVal}, and the block size is {self.blockSize}
Network ID octet value = {octetVal} - ({octetVal} % {self.blockSize})
Network ID octet value = {octetVal} - {octetVal % self.blockSize}
Network ID octet value = {octetVal - octetVal % self.blockSize}

With the Network ID value calculated for the interesting octet (#{self.octetNum}), set that value in the IP address {self.ipStr}. Then set the octets with only host bits to 0 (everything to the right of the interesting octet). For {self.ipStr}, the octets with only host bits are {hostOctets}.

{self.ipStr} -> {subnetID} = network ID""")

        assert subnetID == self.netIDStr

    def _show_broadcast_calc_block_method(self):
        networkOctets = ""
        hostOctets = ""
        justMaxedHostsOctets = '.255' * (4 - self.octetNum)
        octets = self.netIDStr.split('.')
        octetVal = int(octets[self.octetNum - 1])
        if self.octetNum > 1:
            networkOctets = '.'.join(octets[:self.octetNum - 1])
        if self.octetNum < 4:
            hostOctets =  '.'.join(octets[self.octetNum:])

        if networkOctets == "":
            updatedIP = f"{octetVal + self.blockSize - 1}"
            broadcast = f"{octetVal + self.blockSize - 1}{justMaxedHostsOctets}"
        else:
            updatedIP = f"{networkOctets}.{octetVal + self.blockSize - 1}"
            broadcast = f"{networkOctets}.{octetVal + self.blockSize - 1}{justMaxedHostsOctets}"

        if hostOctets != "":
            updatedIP += f".{hostOctets}"

        print(f"""
Step 4: Calculate the broadcast address

With the network ID ({self.netIDStr}/{self.prefixLen}) and block size ({self.blockSize}) known, the next step is to calculate the broadcast address.""")

        if self.prefixLen % 8 == 0: # /8, /16, /24
            print(f"""
Since the prefix falls on an octet boundary (/8, /16, /24), you don't need to do the normal process. Set the interesting octet to 255 (octet {self.octetNum}). Then perform the final step of setting the octets with only host bits to 255 (everything to the right of the interesting octet). For {self.netIDStr}, the octets with only host bits are {'x.' * (self.octetNum - 1)}{octetVal}{'.' if hostOctets != '' else ''}{hostOctets}.

{self.netIDStr} -> {broadcast} = broadcast address""")
        else:
            print(f"""
This involves adding the block size to the interesting octet value in the network ID ({octetVal}) and subtracting 1. Then setting the octets with only host bits to 255 (the ones to the right of the interesting octet). This gives you the broadcast address.

Note: the network only octets (if applicable) stay the same.

Examples:

If the network ID is 172.30.4.80/28 and the block size is 16 then:
Update interesting octet value = 80 + 16 - 1 = 95 = 172.30.4.95
Host only bits to 255 = 172.30.4.80 -> 172.30.4.80 (there are none)
Broadcast address = 172.30.4.95

If the network ID is 172.160.160.0/19 and the block size is 32 then:
Update interesting octet value = 160 + 32 - 1 = 191 = 172.160.191.0
Host only bits to 255 = 172.160.191.0 -> 172.160.191.255
Broadcast address = 172.160.191.255

If the network ID is 200.128.0.0/9 and the block size is 128 then:
Update interesting octet value = 128 + 128 - 1 = 255 = 200.255.0.0
Host only bits to 255 = 200.255.0.0 -> 200.255.255.255
Broadcast address = 200.255.255.255

If the network ID is 132.0.0.0/7 and the block size is 2 then:
Update interesting octet value = 132 + 2 - 1 = 133 = 133.0.0.0
Host only bits to 255 = 133.0.0.0 -> 133.255.255.255
Broadcast address = 133.255.255.255

For {self.netIDStr}/{self.prefixLen} and the block size of {self.blockSize}:
Update interesting octet value = {octetVal} + {self.blockSize} - 1 = {octetVal + self.blockSize - 1} = {updatedIP}
Host only bits to 255 = {updatedIP} -> {broadcast}
Broadcast address = {broadcast}
""")

        assert broadcast == self.broadcastStr

    def _show_first_last_host_calc_block_method(self):
        firstHost = self.netIDStr.split('.')
        firstHost = '.'.join(firstHost[:3] + [str(int(firstHost[3]) + 1)])
        lastHost = self.broadcastStr.split('.')
        lastHost = '.'.join(lastHost[:3] + [str(int(lastHost[3]) - 1)])

        print(f"""
Step 5: Calculate the first and last usable hosts

With the network ID {self.netIDStr} and broadcast address {self.broadcastStr}, calculating the first and last usable host is rather simple. For the first host, add 1 to the network ID. For the last host, subtract 1 from the broadcast address.

First host = {self.netIDStr} + 1 = {firstHost}
Last host = {self.broadcastStr} - 1 = {lastHost}""")
        assert firstHost == self.firstHost
        assert lastHost == self.lastHost

    def _show_calc_total_hosts_block_method(self):
        print(f"""
Step 6: Calculate the total addresses and total usable hosts

There are two methods to calculate the total addresses within a network:
1. Compute the total addresses using the block size
2. Compute the total addresses using the prefix length

Afterwards, calculating the usable hosts is quite simple
""")

        # Method 1: compute total addresses using the block size
        self._method_get_total_hosts_with_block_size()

        # Method 2: compute total addresses using the prefix length
        self._method_get_total_hosts_with_prefix_length()

        if self.prefixLen == 31 or self.prefixLen == 32:
            message = f"applies and the total usable hosts are {self.totalAddresses}."
        else:
            message = "does not apply."


        print(f"""
Now that the number of total addresses is known to be {self.totalAddresses:,d}, you simply subtract 2 (1 for the broadcast and 1 for the network ID) to get the total usable hosts:
{self.totalAddresses:,d} - 2 = {self.totalAddresses - 2:,d}

The only exception is a /31 network where the total addresses = the total usable hosts and a /32 where there is always only one host.

Since this is a /{self.prefixLen}, this {message}""")

    def _method_get_total_hosts_with_block_size(self):
        numHostOctets = (32 - self.prefixLen) // 8
        if self.prefixLen % 8 == 0: # /8, /16, /24
            numHostOctets -= 1
        print(f"""Method 1: compute the total addresses using the block size

This method involves taking the known block size {self.blockSize} and multiplying it by 256 for each octet with only host bits in the network ID {self.netIDStr}. For prefixes that fall on an octet boundary (/8, /16, /24), the "interesting octet" is just treated as another host bits octet.

For example:

If the network ID is 1.0.0.0/8 and the block size is 256 then:
There are 3 host only octets so:
256 * 256 * 256 = 16777216 = total addresses

If the network ID is 10.128.0.0/9 and the block size is 128 then:
There are 2 host only octets so:
128 * 256 * 256 = 8388608 = total addresses

If the network ID is 172.17.36.0/22 and the block size is 4 then:
There is 1 host only octets so:
4 * 256 = 1024 = total addresses

If the network ID is 192.168.0.0/26 and the block size is 64 then:
There are 0 host only octets so:
64 = total addresses

For {self.netIDStr}/{self.prefixLen} with a block size of {self.blockSize}:
There are {numHostOctets} host only octet{'s' if numHostOctets != 1 else ''} so:""")
        if numHostOctets == 0:
            print(f"{self.blockSize} = total addresses")
        else:
            print(f"{self.blockSize}{' * 256' * numHostOctets} = {self.blockSize * 256**numHostOctets} = total addresses")

            print(f"""
If you need to estimate the total number of hosts and don't need an exact value, you can do this with the block method without resorting to exponents. Note that the prefix-length method is usually easier for estimation. This is just an alternative approach.

This method works directly with the factors in the subnet size. Subnet sizes are always products of numbers that can be broken into factors of 2, which allows you to rearrange factors to create easier-to-multiply numbers.

Each full octet contributes a factor of 256. Since 256 * 4 = 1024 (which is close to 1000), the goal is to take two factors of 2 from other parts of the equation and combine them with each 256 to turn it into about 1000. In other words, each 256 needs two additional factors of 2 to become about 1000.

Note: This does not change the value, as you are only rearranging factors. The only change in value comes from rounding 1024 down to 1000.

For example, if you have a block size of 64 with two full host octets:
64 * 256 * 256

64 = 2 * 2 * 2 * 2 * 2 * 2

Take 4 factors of 2 (all from 64) and move them to the 2 256 terms:

256 * 2 * 2 = 1024 or approx. 1000
256 * 2 * 2 = 1024 or approx. 1000

Remaining:
64 / (2 * 2 * 2 * 2) = 4

Final estimate:
4 * 1000 * 1000 = 4,000,000

As another example, if you have a block size of 2 with two full host octets:
2 * 256 * 256

2 = 2
256 = 2 * 2 * 2 * 2 * 2 * 2 * 2

Take 2 factors of 2 (1 from 2, 1 from 256) and move them to the 1 256 term:

256 * 2 * 2 = 1024 or approx. 1000

Remaining:
2 / 2 = 1
256 / 2 = 128

Final estimate:
128 * 1000 = 128,000

""")

            print(f"For {self.netIDStr}/{self.prefixLen} with a block size of {self.blockSize} and {numHostOctets} full host octet{'s' if numHostOctets != 1 else ''}:")
            blockSizeFactors = []
            hostOctetFactors = []
            num = self.blockSize
            while num != 1:
                hostOctetFactors.append(2)
                num /= 2

            factorsNeeded = numHostOctets * 2

            if len(hostOctetFactors) / 4 < numHostOctets:
                factorsNeeded -= 2
                num = 256
                while num != 1:
                    blockSizeFactors.append(2)
                    num /= 2

            hostRemoved = 0
            blockRemoved = 0
            temp = hostOctetFactors.copy()
            while len(temp) > 0 and factorsNeeded > 0:
                if len(temp) == 0:
                    break
                del temp[0]
                factorsNeeded -= 1
                hostRemoved += 1

            if len(temp) == 0:
                temp = blockSizeFactors.copy()
                while factorsNeeded > 0:
                    del temp[0]
                    factorsNeeded -= 1
                    blockRemoved += 1

            print(f"{self.blockSize}{' * 256' * numHostOctets}\n")
            print(f"{self.blockSize} = {' * '.join(str(j) for j in hostOctetFactors)}")
            if blockRemoved > 0:
                print(f"256 = {' * '.join(str(j) for j in blockSizeFactors)}")
                thousandLines = '256 * 2 * 2 = 1024 or approx. 1000\n' * (numHostOctets - 1)
                print(f"""
Take {hostRemoved + blockRemoved} factor{'s' if factorsNeeded != 1 else ''} of 2 ({hostRemoved} from {self.blockSize}, {blockRemoved} from 256) and move them to the {numHostOctets - 1} 256 term{'s' if numHostOctets - 1 != 1 else ''}:

{thousandLines}
Remaining:""")

            else:
                thousandLines = '256 * 2 * 2 = 1024 or approx. 1000\n' * (numHostOctets)
                print(f"""
Take {hostRemoved + blockRemoved} factor{'s' if hostRemoved != 1 else ''} of 2 (all from {self.blockSize}) and move them to the {numHostOctets} 256 term{'s' if numHostOctets != 1 else ''}:

{thousandLines}
Remaining:""")

            hostRemovedStr = " 2 = 1"
            if hostRemoved > 1:
                hostRemovedStr = '2 * ' * hostRemoved
                hostRemovedStr = hostRemovedStr.rstrip(' ').rstrip('*').rstrip(' ')
                hostRemovedStr = f" ({hostRemovedStr}) = {2**(len(hostOctetFactors) - hostRemoved)}"
            if blockRemoved > 0:
                blockRemovedStr = " 2 = 1"
                if blockRemoved > 1:
                    blockRemovedStr = '2 * ' * blockRemoved
                    blockRemovedStr = blockRemovedStr.rstrip(' ').rstrip('*').rstrip(' ')
                    blockRemovedStr = f" ({blockRemovedStr}) = {2**(8 - blockRemoved)}"
                print(f"""{self.blockSize} /{hostRemovedStr}
256 /{blockRemovedStr}

Final estimate:
{2**(8 - blockRemoved)}{' * 1000' * (numHostOctets - 1)} = {2**(8 - blockRemoved) * 1000**(numHostOctets - 1):,d}""")
            else:
                print(f"""{self.blockSize} /{hostRemovedStr}

Final estimate:
{2**(len(hostOctetFactors) - hostRemoved)}{' * 1000' * numHostOctets} = {2**(len(hostOctetFactors) - hostRemoved) * 1000**numHostOctets:,d}""")

        assert self.blockSize * 256**numHostOctets == self.totalAddresses

    def _method_get_total_hosts_with_prefix_length(self):
        print(f"""Method 2: compute the total addresses using the prefix length

Using the prefix length is simpler, but does potentially require calculating large exponents. To get the total addresses, you take the prefix length ({self.prefixLen}) and subtract it from 32 (the total number of bits in an IPv4 address). Then you take the difference and raise 2 to that power.

For example, if the prefix was /1 then:
32 - 1 = 31
2^31 = 2,147,483,648 total addresses

If the prefix was /12 then:
32 - 12 = 20
2^20 = 1,048,576 total addresses

If the prefix was /16 then:
32 - 16 = 16
2^16 = 65,536 total addresses

If the prefix was /27 then:
32 - 27 = 5
2^5 = 32 total addresses

For {self.cidrAdr}:
32 - {self.prefixLen} = {32 - self.prefixLen}
2^{32 - self.prefixLen} = {2**(32 - self.prefixLen):,d} total addresses

If you need to estimate the total number of hosts and don't need an exact value, you can do this directly from the CIDR prefix using exponents. This is usually the easier way to estimate since everything is already expressed as a power of 2.

This method works by starting with the number of host bits. If the prefix length is /n, then the number of host bits is (32 - n), and the total number of addresses is:

2^(32 - n)

From here, instead of calculating the exact value, you break the exponent into chunks that are easy to estimate. Since 2^10 = 1024 (which is close to 1000), the goal is to group the exponent into terms of 2^10 * 2^10 * 2^k as needed.

In other words, every group of 10 bits gives you about 1000.

Note: This does not significantly change the value, since you are only regrouping the exponent. The only change comes from rounding 1024 down to 1000.

For example, if the prefix was /1 then:
32 - 1 = 31
2^31 = 2^10 * 2^10 * 2^10 * 2^1

Final estimate:
1000 * 1000 * 1000 * 2 = 2,000,000,000 total addresses

If the prefix was /12 then:
32 - 12 = 20
2^20 = 2^10 * 2^10

Final estimate:
1000 * 1000 = 1,000,000 total addresses

If the prefix was /16 then:
32 - 16 = 16
2^16 = 2^10 * 2^6

Final estimate:
1000 * 64 = 64,000 total addresses

If the prefix was /27 then:
32 - 27 = 5
2^5 = 32 total addresses

For {self.cidrAdr}:""")

        hostBits = 32 - self.prefixLen
        print(f"""
32 - {self.prefixLen} = {hostBits}
2^{32 - self.prefixLen} = {'2^10 * ' * (hostBits // 10)}2^{hostBits % 10}

Final estimate:
{'1000 * ' * (hostBits // 10)}{2**(hostBits % 10)} = {1000**(hostBits // 10) * 2**(hostBits % 10):,d} total addresses""")

        assert 2**(32 - self.prefixLen) == self.totalAddresses
