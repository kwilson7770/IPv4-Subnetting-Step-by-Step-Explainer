class IPv4Address:
    """This class represents an IPv4 address and provides methods to manipulate and analyze the address. It supports various operations like determining address class, calculating subnets, supernets, and performing validations on IPv4 address and prefix lengths."""

    PRIVATE_10_START = 0x0A000000 # 10.0.0.0
    PRIVATE_10_END   = 0x0AFFFFFF # 10.255.255.255

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
        if len(binStr) <= 32:
            binStr = binStr.zfill(32)

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
    def calculate_network_address_int(ipInt, netmaskInt):
        # Calculate the network address by performing a bitwise AND (&) operation between an IP address within the network (ipInt) and the subnet mask (netmaskInt).
        # This operation filters out the host portion of the IP address, since the subnet mask, by design, has 1s in the network portion and 0s in the host portion.
        # The bitwise AND (&) operation keeps a bit as 1 only if both bits are 1, otherwise, it sets the bit to 0.
        #
        # For example, if ipInt = 10.111.112.113 and netmaskInt = 255.240.0.0:
        # 10.111.112.113 = 00001010 01101111 01110000 01110001
        # 255.240.0.0    = 11111111 11110000 00000000 00000000
        # Perform the bitwise AND (&) to get the network bits:
        # 00001010 01101111 01110000 01110001 & 11111111 11110000 00000000 00000000 = 00001010 01100000 00000000 00000000
        # The result is the network address:
        # 00001010 01100000 00000000 00000000 = 10.96.0.0
        return ipInt & netmaskInt

    def __init__(self, IPv4, showSteps=False, explainHowToCalculate=False):
        # _ipv4_address_parser() sets ipInt, ipStr, ipBin, netmaskInt, netmaskStr, netmaskBin, prefixLen, and ipAdrCIDR
        self._ipv4_address_parser(IPv4)

        # Setup the object based on the prefix length
        if self.prefixLen == 32:
            self._setup_host_route()
        elif self.prefixLen == 31:
            self._setup_point_to_point()
        else: # _validate_ipv4_prefix_len() ensured this is between 1 and 30
            self._setup_normal_subnet()

        # Set various attributes as they apply to the IP address
        self.adrClass = self._calculate_address_class()
        self.privateUse = IPv4Address.PRIVATE_10_START <= self.ipInt <= IPv4Address.PRIVATE_10_END or IPv4Address.PRIVATE_172_START <= self.ipInt <= IPv4Address.PRIVATE_172_END or IPv4Address.PRIVATE_192_START <= self.ipInt <= IPv4Address.PRIVATE_192_END
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

    def _setup_host_route(self):
        # Host route (/32)

        self.netAdrInt = self.ipInt
        self.netAdrStr = self.ipStr
        self.netAdrBin = self.ipBin
        self.netAdrCIDR = f"{self.ipStr}/32"

        self.broadcastInt = self.ipInt
        self.broadcastStr = self.ipStr
        self.broadcastBin = self.ipBin

        self.totalAddresses = 1
        self.usableHosts = 1
        self.firstHost = self.ipStr
        self.lastHost = self.ipStr

    def _setup_point_to_point(self):
        # point-to-point link (/31). According to RFC3021, the network address (first host) and broadcast address (last host) are both treated as usable hosts.

        # sets the network address to be the first IP address in a network
        self._set_network_address()

        # sets the broadcast address to be the last IP address in a network
        self._set_broadcast_address()

        self.totalAddresses = 2
        self.usableHosts = 2
        self.firstHost = self.netAdrStr
        self.lastHost = self.broadcastStr

    def _setup_normal_subnet(self):
        # Normal subnets (/1 to /30)

        # sets the network address to be the first IP address in a network
        self._set_network_address()

        # sets the broadcast address to be the last IP address in a network
        self._set_broadcast_address()

        # The total addresses is the number of hosts that can fit within the host bits (hence the 2^host-bits math)
        self.totalAddresses = 2 ** (32 - self.prefixLen)
        self.usableHosts = self.totalAddresses - 2 # this is true for /1 to /30
        self.firstHost = IPv4Address.ip_string_from_int(self.netAdrInt + 1) # this is the first address after the network address
        self.lastHost = IPv4Address.ip_string_from_int(self.broadcastInt - 1) #  this is the first address before the broadcast address

    def _set_broadcast_address(self):
        # Calculate the broadcast address by using the netmask, network address, and bitwise XOR (^) and OR (|) operations.
        # The bitwise XOR (^) between the netmask and IPv4Address.ALL_ONES inverts all the bits of the netmask.
        # This operation flips the 1s in the netmask to 0s and the 0s to 1s, creating the inverse of the netmask.
        # Next, the bitwise OR (|) between the inverted netmask and the network address creates the broadcast address.
        # This ensures that all host bits (which are 0s in the network address) are set to 1s, resulting in the highest possible address in the network (the broadcast address).
        #
        # For example, if self.netmaskInt = 255.255.255.0 and self.netAdrInt = 192.168.1.0:
        # 255.255.255.0 = 11111111 11111111 11111111 00000000
        # 192.168.1.0 = 11000000 10101000 00000001 00000000
        # IPv4Address.ALL_ONES = 11111111 11111111 11111111 11111111
        # First, apply the bitwise XOR (^) operation between the two numbers to invert the bits:
        # 11111111 11111111 11111111 00000000 ^ 11111111 11111111 11111111 11111111 = 00000000 00000000 00000000 11111111
        # Next, apply the bitwise OR (|) operation to set all the host bits to 1:
        # 00000000 00000000 00000000 11111111 | 11000000 10101000 00000001 00000000 = 11000000 10101000 00000001 11111111
        # The result is the broadcast address:
        # 11000000 10101000 00000001 11111111 = 192.168.1.255
        self.broadcastInt = (self.netmaskInt ^ IPv4Address.ALL_ONES) | self.netAdrInt
        self.broadcastStr = IPv4Address.ip_string_from_int(self.broadcastInt)
        self.broadcastBin = IPv4Address._space_out_binary_string(format(self.broadcastInt, '032b'))

    def _set_network_address(self):
        self.netAdrInt = IPv4Address.calculate_network_address_int(self.ipInt, self.netmaskInt)
        self.netAdrStr = IPv4Address.ip_string_from_int(self.netAdrInt)
        self.netAdrBin = IPv4Address._space_out_binary_string(format(self.netAdrInt, '032b'))
        self.netAdrCIDR = f"{self.netAdrStr}/{self.prefixLen}"

    def _ipv4_address_parser(self, IPv4):
        """IPv4 Arg can be:
        a dotted decimal IPv4 string (e.g. 172.30.5.0),
        a CIDR address (e.g. 127.0.5.1/24),
        a dotted decimal IPv4 string with a dotted decimal IPv4 subnet mask (space separated) (e.g. 10.0.6.7 255.255.255.0),
        a string of the decimal IPv4 with the prefix len (space separated) (e.g. 16843009 /8),
        or an integer of an IPv4 address (e.g. 1157895235).
        """

        if isinstance(IPv4, int) or IPv4.isdigit():
            # _validate_ipv4_int returns ipInt if validated, otherwise raises ValueError
            self.ipInt = self._validate_ipv4_int(int(IPv4))
            ipStr = IPv4Address.ip_string_from_int(self.ipInt)
        elif isinstance(IPv4, str):
            ipStr = IPv4
            # clean up the ipStr by removing extra spaces
            ipStr = ipStr.strip()
            while "  " in ipStr:
                ipStr = ipStr.replace("  ", " ")

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


        self.ipAdrCIDR = f"{ipStr}/{self.prefixLen}"

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
            if prefixLenInt >= 0 and prefixLenInt <= 32:
                return prefixLenInt
            else:
                raise ValueError(f"The CIDR prefix length {prefixLenInt} must be a valid integer between 0 and 32")
        else:
            raise ValueError(f"The CIDR prefix length {prefixLenStr} must be a valid integer between 0 and 32")

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

        # If the network is a host route (/32), just need to check if the addresses are the same
        if self.prefixLen == 32:
            return ipInt == self.ipInt # The below logic would work too, but checking here is clearer

        # Otherwise, check if the IP falls within the network range (from network address to broadcast address)
        return self.netAdrInt <= ipInt <= self.broadcastInt

    def subnets(self, newPrefix, limit=1000, subnetByOctetBoundary=False):
        """
        Generates subnet blocks using fixed-size stepping derived from CIDR prefix length.

        The method computes a constant block size (2^(32 - newPrefix)) and iterates
        through the address space from the network address upward in equal increments.

        Parameters:
            newPrefix (int): Target subnet prefix length that is greater than the existing prefix length
            limit (int): Maximum number of subnets to generate (0 = no limit).
            subnetByOctetBoundary (bool):
                if True, limits subnet output to an octet-aligned segment of the address space.

                This does NOT change subnet sizing, block size, stepping behavior, or subnet
                generation logic. It only restricts which generated subnet results are displayed
                for visualization purposes.

        Behavior Notes:
            - Subnets are always generated using fixed-size block stepping.
            - Octet-boundary mode only restricts which generated results are displayed and does not affect subnet calculation or generation.
        """

        # Validate prefix range
        if newPrefix <= self.prefixLen or newPrefix > 32:
            raise ValueError(f"newPrefix must be greater than the current prefix length ({self.prefixLen}) and <= 32")

        # Validate limit
        if limit < 0:
            raise ValueError(f"Provided limit ({limit}) is invalid. Limit must be >= 0")

        # Calculate number of IPs per subnet
        blockSize = 2 ** (32 - newPrefix)

        finalSubnetInt = self.broadcastInt

        # Optional: constrain subnetting to octet boundaries (/0, /8, /16, /24) if the new prefix length is in a different octet than the current one
        if subnetByOctetBoundary and self.prefixLen // 8 != newPrefix // 8:
            # Adjust broadcast range so subnetting stays within a single octet boundary
            if newPrefix > 24:
                finalSubnetInt = (self.broadcastInt & 0x000000FF) | self.netAdrInt
            elif newPrefix > 16:
                finalSubnetInt = (self.broadcastInt & 0x0000FF00) | self.netAdrInt
            elif newPrefix > 8:
                finalSubnetInt = (self.broadcastInt & 0x00FF0000) | self.netAdrInt
            else:
                finalSubnetInt = (self.broadcastInt & 0xFF000000) | self.netAdrInt

            # If subnetting exactly on an octet boundary, include the final subnet
            if newPrefix % 8 == 0:
                finalSubnetInt += 1
        else:
            if newPrefix == 32: # if subnet is a host route, then you can include the original networks broadcast address as a valid /32 host route (e.g. 10.0.5.0/24 -> 10.0.5.255/32)
                finalSubnetInt += 1

        count = 0

        for subnetIPInt in range(self.netAdrInt, finalSubnetInt + 1, blockSize):
            # Prevent going over or reaching the broadcast value
            if subnetIPInt >= finalSubnetInt:
                break

            # Enforce subnet limit (if limit > 0)
            if limit > 0 and count >= limit:
                print(f"Limit of {limit} subnet{'s' if limit != 1 else ''} reached. Stopping subnet generation.")
                break

            yield IPv4Address(f"{subnetIPInt} /{newPrefix}")

            count += 1

    def supernet(self, newPrefix):
        """Generate a supernet (larger network) by combining smaller networks into one, based on the provided new prefix length."""

        if newPrefix >= self.prefixLen or newPrefix < 0:
            raise ValueError("newPrefix must be < current prefix and >=0")

        # Calculate the subnet mask using the new prefix
        netmaskInt = IPv4Address.calculate_netmask_int(newPrefix)

        # Calculate the supernet address using the new prefix.
        supernetAdrInt = IPv4Address.calculate_network_address_int(self.ipInt, netmaskInt)

        # Return a new IPv4Address object representing the supernet with the new prefix length
        return IPv4Address(f"{supernetAdrInt} /{newPrefix}", self.showSteps)

    def __str__(self):
        return f"""IPv4 Address:                    {self.ipStr}
Subnet Mask:                     {self.netmaskStr}
Host Mask (Inverse Subnet Mask): {self.hostmaskStr}
Prefix Length:                   {self.prefixLen}

Network address:   {self.netAdrStr}
Broadcast Address: {self.broadcastStr}

First Host:      {self.firstHost}
Last Host:       {self.lastHost}
Total Addresses: {self.totalAddresses:,d}
Usable Hosts:    {self.usableHosts:,d}

IP Address (CIDR):      {self.ipAdrCIDR}
Network Address (CIDR): {self.netAdrCIDR}

Binary (IPv4 Address):      {self.ipBin}
Binary (Subnet Mask):       {self.netmaskBin}
Binary (Host Mask):         {self.hostmaskBin}
Binary (Network Address):   {self.netAdrBin}
Binary (Broadcast Address): {self.broadcastBin}

Address Class (Historical):                       {self.adrClassStr}
Private Address, Non-Publicly Routable (RFC1918): {self.privateUse}
Link-Local Address, Non-Routable (RFC3927):       {self.linkLocal}
Multicast:                                        {self.multicast}
Loopback:                                         {self.loopback}
"""

    def _print_steps(self):
        if self.prefixLen == 32:
            print("""Per RFC4632, a /32 is a host route.

A host route represents a single IP address, not a range. That means:
- Network address = the IP address itself
- There is no meaningful broadcast address since a /32 does not support broadcasting
- There are no additional host addresses

Since there is only one address, it is not necessary to perform calculations to derive other values. Despite this, the underlying binary rules still apply mathematically as seen below. However, since a /32 has no host bits, there is no interesting octet. As a result, standard block size subnetting methods cannot be applied to derive subnetting information.
""")
            self._print_binary_steps()

            print("\nSince a /32 host route has no host bits, there is no interesting octet. As a result, standard block size subnetting methods cannot be applied to derive subnetting information and the block size section will be skipped.")
            return

        elif self.prefixLen == 31:
            print("""Per RFC3021, a /31 is a point-to-point link.

A /31 network contains exactly 2 IP addresses. Unlike most subnets:
- Both addresses are usable
- There is no traditional network address or broadcast address
""")

        self._print_binary_steps()
        self._print_block_size_steps()

    def _print_binary_steps(self):
        firstHost = self.netAdrInt + 1
        lastHost = self.broadcastInt - 1
        if self.prefixLen >= 31:
            firstHost -= 1
            lastHost += 1

        print(f"""Binary steps for {self.ipAdrCIDR} ({self.ipStr} {self.netmaskStr})

IP Address
{self.ipStr} -> {', '.join(self.ipStr.split('.'))} -> {self.ipBin}

Subnet Mask
{self.netmaskStr} -> {', '.join(self.netmaskStr.split('.'))} -> {self.netmaskBin}

CIDR Prefix Length -> Subnet Mask (binary)
{self.ipAdrCIDR} -> {self.prefixLen} -> {self.netmaskBin.replace('0','').rstrip(' ')}{' -> ' + self.netmaskBin if '0' in self.netmaskBin else ''}

Host Mask
Subnet mask:                      {self.netmaskBin}
Host mask (inverted subnet mask): {self.hostmaskBin}

Network Address
     IP address:   {self.ipBin}
    Subnet mask: & {self.netmaskBin}
                   -----------------------------------
Network address:   {self.netAdrBin}

Broadcast
      Host mask:   {self.hostmaskBin}
Network address: | {self.netAdrBin}
                   -----------------------------------
      Broadcast:   {self.broadcastBin}""")

        if self.prefixLen == 31:
            print(f"""
First Host
Since according to RFC3021 this is a point-to-point link (/31), the network address is the first host and the broadcast address is the last host.
Network address: {self.netAdrBin}
     First Host: {IPv4Address._space_out_binary_string(format(firstHost, '032b'))}

Last Host
Broadcast: {self.broadcastBin}
Last Host: {IPv4Address._space_out_binary_string(format(lastHost, '032b'))}""")
        elif self.prefixLen == 32:
            print(f"""
First Host
Since according to RFC4632 this is a host route (/32), the first and last host are both equal the IP address since the network size only allows a single address.
IP Address: {self.ipBin}
First Host: {IPv4Address._space_out_binary_string(format(firstHost, '032b'))}

Last Host
IP Address: {self.ipBin}
Last Host:  {IPv4Address._space_out_binary_string(format(lastHost, '032b'))}""")
        else:
            print(f"""
First Host
Network address:   {self.netAdrBin}
                 + 00000000 00000000 00000000 00000001
                   -----------------------------------
     First Host:   {IPv4Address._space_out_binary_string(format(firstHost, '032b'))}

Last Host
Broadcast:   {self.broadcastBin}
           - 00000000 00000000 00000000 00000001
             -----------------------------------
Last Host:   {IPv4Address._space_out_binary_string(format(lastHost, '032b'))}""")

        print(f"""
Total Addresses
      Broadcast:   {self.broadcastBin}
Network address: - {self.netAdrBin}
                   -----------------------------------
                   {IPv4Address._space_out_binary_string(format(self.broadcastInt - self.netAdrInt, '032b'))}
          Add 1: + 00000000 00000000 00000000 00000001
                   -----------------------------------
Total Addresses: {(IPv4Address._space_out_binary_string(format(self.broadcastInt - self.netAdrInt + 1, '032b'))).rjust(37)}

IP Address (CIDR notation)
{self.ipAdrCIDR}

Subnet Mask
{self.netmaskBin} -> {self.netmaskStr}

Host Mask
{self.hostmaskBin} -> {self.hostmaskStr}

Network Address
{IPv4Address._space_out_binary_string(format(self.ipInt & self.netmaskInt, '032b'))} -> {self.netAdrStr}

Broadcast
{IPv4Address._space_out_binary_string(format(self.netmaskInt ^ IPv4Address.ALL_ONES | self.netAdrInt, '032b'))} -> {self.broadcastStr}

First Host
{IPv4Address._space_out_binary_string(format(firstHost, '032b'))} -> {self.firstHost}

Last Host
{IPv4Address._space_out_binary_string(format(lastHost, '032b'))} -> {self.lastHost}

Total Addresses
{IPv4Address._space_out_binary_string(format(self.broadcastInt - self.netAdrInt + 1, '032b'))} -> {self.totalAddresses:,d}""")
        
        if self.prefixLen >= 31:
            print(f"""
Usable Hosts
{self.totalAddresses:,d} = {self.usableHosts:,d}""")
        else:
            print(f"""
Usable Hosts
{self.totalAddresses:,d} - 2 = {self.usableHosts:,d}""")

    def _print_block_size_steps(self):
        blockSize = 2**(8 - self.prefixLen % 8)
        interestingOctet = self.prefixLen // 8 + 1
        octets = self.ipStr.split(".")
        if self.prefixLen % 8 == 0 and self.prefixLen != 32:
            boundaryOctet = self.prefixLen // 8  # last fully fixed octet
            print(f"""
Block size steps for {self.ipAdrCIDR}

The prefix falls on an octet boundary (/0, /8, /16, /24), so there is no interesting octet.

Host Mask
All ones:      255.255.255.255
Subnet mask: - {self.netmaskStr}
               ---------------
Host mask:     {self.hostmaskStr}

Network address
Copy the first {boundaryOctet} octet(s) from the IP address and set the rest to 0 -> {self.netAdrStr}

Broadcast Address
Set all host octets (everything after octet {boundaryOctet}) to 255 -> {self.broadcastStr}

First Host
{self.netAdrStr} + 1 = {self.firstHost}

Last Host
{self.broadcastStr} - 1 = {self.lastHost}

Total Addresses
{self.ipAdrCIDR} -> {self.prefixLen} -> 32 - {self.prefixLen} = {32 - self.prefixLen} -> 2^{32 - self.prefixLen} = {2**(32 - self.prefixLen):,d} total addresses

Usable Hosts
{self.totalAddresses} - 2 = {self.usableHosts:,d}
""")
            return

        print(f"""
Block size steps for {self.ipAdrCIDR}

Block Size
{self.ipAdrCIDR} -> {self.prefixLen} -> {8 - self.prefixLen % 8} host bits in octet {interestingOctet} (the interesting octet) -> block size = 2^{8 - self.prefixLen % 8} = {blockSize}

Host Mask
All ones:      255.255.255.255
Subnet mask: - {self.netmaskStr}
               ---------------
Host mask:     {self.hostmaskStr}

Network address
Octet {interestingOctet} value for network address = {octets[interestingOctet - 1]} // {blockSize} * {blockSize} -> {int(octets[interestingOctet - 1]) // blockSize * blockSize}
Octet {interestingOctet} value set to {int(octets[interestingOctet - 1]) // blockSize * blockSize} and all octets to the right of it set to 0 -> {self.netAdrStr}

Broadcast Address
Add {blockSize} to octet {interestingOctet} in {self.netAdrStr} and subtract 1 = {self.broadcastStr.split('.')[interestingOctet - 1]}. Then replace octets to the right of the interesting octet with 255 -> {self.broadcastStr}""")

        if self.prefixLen >= 31:
             print(f"""
First Host
{self.netAdrStr} = {self.firstHost}

Last Host
{self.broadcastStr} = {self.lastHost}""")
        else:
             print(f"""
First Host
{self.netAdrStr} + 1 = {self.firstHost}

Last Host
{self.broadcastStr} - 1 = {self.lastHost}""")

        print(f"""
Total Addresses
{self.ipAdrCIDR} -> {self.prefixLen} -> 32 - {self.prefixLen} = {32 - self.prefixLen} -> 2^{32 - self.prefixLen} = {2**(32 - self.prefixLen):,d} total addresses""")

        if self.prefixLen == 31:
            print(f"""
Usable Hosts
{self.totalAddresses:,d} = {self.usableHosts:,d}""")
        else:
            print(f"""
Usable Hosts
{self.totalAddresses:,d} - 2 = {self.usableHosts:,d}""")

    def _explain_how_to_calculate(self):
        # Handle special cases first
        if self.prefixLen == 32:
            print("""Per RFC4632, a /32 is a host route.

A host route represents a single IP address, not a range. That means:
- Network address = the IP address itself
- There is no meaningful broadcast address since a /32 does not support broadcasting
- There are no additional host addresses

Since there is only one address, it is not necessary to perform calculations to derive other values. Despite this, the underlying binary rules still apply mathematically as seen below. However, since a /32 has no host bits, there is no interesting octet. As a result, standard block size subnetting methods cannot be applied to derive subnetting information.
""")

        elif self.prefixLen == 31:
            print("""Per RFC3021, a /31 is a point-to-point link.

A /31 network contains exactly 2 IP addresses. Unlike most subnets:
- Both addresses are usable
- There is no traditional network address or broadcast address

This type of subnet is typically used for point-to-point links (like between two routers).

Because of this special behavior, some of the usual subnetting steps do not apply.
""")

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
- Network address
- Broadcast address
- First and last usable host
- Total number of addresses

Both methods will be gone through step-by-step so you can see how they work and compare them.""")

        self._explain_binary_steps()
        if self.prefixLen != 32:
            self._explain_block_method_steps()
        else:
            print("\nSince a /32 host route has no host bits, there is no interesting octet. As a result, standard block size subnetting methods cannot be applied to derive subnetting information and the block size section will be skipped.")

    def _explain_binary_steps(self):
        print(f"""

+{'=' * len(f'--- Binary Method for {self.ipAdrCIDR} ---')}+
|--- Binary Method for {self.ipAdrCIDR} ---|
+{'=' * len(f'--- Binary Method for {self.ipAdrCIDR} ---')}+

""")

        # Step 1: IP to Binary
        octets = self.ipStr.split('.')
        print(f"Step 1: Convert the IP address {self.ipStr} to binary by splitting octets: {', '.join(octets)}\n")
        self._show_binary_conversion_methods(octets)

        # Step 2: Subnet Mask
        self._show_mask_to_binary()

        # Step 3: Host Mask
        self._show_hostmask_to_binary()

        # Step 4: Network address
        self._show_network_address_calc()

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
        for octetNum, i in enumerate(octets):
            i = int(i)

            binStr = ""
            print(f"Octet {octetNum + 1} = {i}")
            for j in reversed(range(8)):
                message = " then go to the next power" if j > 0 else ''
                j = 2**j
                if i >= j:
                    binStr += "1"
                    print(f"Since {str(i).rjust(3)} >= {str(j).ljust(3)}, add a 1 to the binary number ({binStr}){' ' * (8-len(binStr))} {(f'and subtract {j} from {i} ({i} - {j} = {i - j})').ljust(43)}{message}")
                    i -= j
                else:
                    binStr += "0"
                    print(f"Since {str(i).rjust(3)} <  {str(j).ljust(3)}, add a 0 to the binary number ({binStr}){' ' * (8-len(binStr))} {' ' * 43}{message}")

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
        print("\nStep 2: Convert the subnet mask to binary.\n")
        print(f"If this is in dotted-decimal notation already ({self.netmaskStr}) then repeat everything in step 1. If the subnet mask was provided as a prefix length ({self.prefixLen}) from CIDR notation ({self.ipAdrCIDR}) then simply write out {self.prefixLen} '1's (prefix length) and {32 - self.prefixLen} '0's (32 - {self.prefixLen} = {32 - self.prefixLen}).")

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

If you have the CIDR notation ({self.ipAdrCIDR}), you can skip writing out the subnet mask in binary just to invert it, and instead write the host mask in binary directly using the prefix length. Using the prefix length of {self.prefixLen}, write {self.prefixLen} '0's and {32 - self.prefixLen} '1's (32 - {self.prefixLen} = {32 - self.prefixLen}):""")

        hostmask = '0' * self.prefixLen + '1' * (32 - self.prefixLen)
        invertedNetmaskRaw = IPv4Address._space_out_binary_string(format(~ self.netmaskInt, '032b'))
        print(f"Host mask:   {IPv4Address._space_out_binary_string(hostmask)}")

        print(f"""
Bonus info: computers can calculate the host mask two different ways to get the same result, but it is more complicated than the process of "flipping bits". This information is provided for a general understanding of how computers perform this task and the bitwise operations won't explained.

Computer Method 1. Bitwise NOT (~) the subnet mask and bitwise AND (&) the result with 32 1's (0xFFFFFFFF or 11111111 11111111 11111111 11111111)

A computer can calculate the host mask by bitwise NOT (~) the subnet mask and, if necessary, bitwise AND (&) the result with 32 1's to keep the number a positive 32-bit integer. This gives us the host mask:

Subnet mask: ~ {self.netmaskBin}
               -----------------------------------
{invertedNetmaskRaw.rjust(50)}

Note: Python treats this as a negative number because unsigned integers aren't supported. If it was an unsigned 32-bit integer, the result would be the host mask. As such, the next step is to bitwise AND (&) the result with 32 1's to change the number back to a 32-bit positive number:

{invertedNetmaskRaw.rjust(50)}
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

    def _show_network_address_calc(self):
        print(f"""
Step 4: Calculate the network address using the IP address and subnet mask.

This is done using a binary operation called bitwise AND (&). If both bits equal 1, the network address bit is set to 1. Otherwise, the network address is set to 0

     IP address:   {self.ipBin}
    Subnet mask: & {self.netmaskBin}
                   -----------------------------------
Network address:   {IPv4Address._space_out_binary_string(format(self.ipInt & self.netmaskInt, '032b'))}""")

        # This is not necessary since this is how the class calculates the netmaskBin
        assert IPv4Address._space_out_binary_string(format(self.ipInt & self.netmaskInt, '032b')) == self.netAdrBin

    def _show_broadcast_calc(self):
        print(f"""
Step 5: Calculate the broadcast address.

To get the broadcast address, bitwise OR (|) the host mask ({self.hostmaskBin}) with the network address. If both bits equal 0, the broadcast bit is set to 0. Otherwise, the broadcast bit is set to 1.

       Host mask:   {IPv4Address._space_out_binary_string(format(self.netmaskInt ^ IPv4Address.ALL_ONES, '032b'))}
 Network address: | {self.netAdrBin}
                    -----------------------------------
       Broadcast:   {IPv4Address._space_out_binary_string(format(self.netmaskInt ^ IPv4Address.ALL_ONES | self.netAdrInt, '032b'))}""")

        # Check my "work" with an assertion (the class uses a simpler calculation method that should have zero errors)
        assert self.netmaskInt ^ IPv4Address.ALL_ONES | self.netAdrInt == self.broadcastInt

    def _show_first_last_host_calc(self):
        print("\nStep 6: Calculate the first usable host and last usable host.")

        firstHost = self.netAdrInt + 1
        lastHost = self.broadcastInt - 1
        if self.prefixLen >= 31:
            firstHost -= 1
            lastHost += 1

        if self.prefixLen == 31:
            print(f"""
Since according to RFC3021 this is a point-to-point link (/31), the network address is the first host and the broadcast address is the last host.

Network address: {self.netAdrBin}
     First Host: {IPv4Address._space_out_binary_string(format(firstHost, '032b'))}

      Broadcast: {self.broadcastBin}
      Last Host: {IPv4Address._space_out_binary_string(format(lastHost, '032b'))}""")
        elif self.prefixLen == 32:
            print(f"""
Since according to RFC4632 this is a host route (/32), the first and last host are both equal the IP address since the network size only allows a single address.

IP Address: {self.ipBin}
First Host: {IPv4Address._space_out_binary_string(format(firstHost, '032b'))}
Last Host:  {IPv4Address._space_out_binary_string(format(lastHost, '032b'))}""")
        else:
            print(f"""
To get the first usable host, simply add 1 to the network address
Network address:   {self.netAdrBin}
                 + 00000000 00000000 00000000 00000001
                   -----------------------------------
     First Host:   {IPv4Address._space_out_binary_string(format(firstHost, '032b'))}

To get the last usable host, simply subtract 1 from the broadcast
Broadcast:   {self.broadcastBin}
           - 00000000 00000000 00000000 00000001
             -----------------------------------
Last Host:   {IPv4Address._space_out_binary_string(format(lastHost, '032b'))}""")

        # Check my "work" with an assertion (the class uses a simpler calculation method that should have zero errors)
        assert IPv4Address.ip_string_from_int(firstHost) == self.firstHost
        assert IPv4Address.ip_string_from_int(lastHost) == self.lastHost

    def _show_calc_total_hosts(self):
        print("\nStep 7: Calculate the total addresses available and total usable hosts.")

        print(f"""
There are two methods to get the total addresses available:
1. Take the broadcast and subtract the network address, then add 1. Then convert to decimal.
2. Raise 2 to the the host bits power.""")

        # Method 1: Take the broadcast and subtract the network address, then add 1. Afterwards, convert the binary to decimal.
        self._method_subtract_and_add_to_get_total_hosts()

        # Method 2: Raise 2 to the host bits power.
        self._method_host_bits_exponent_total_hosts()

    def _method_subtract_and_add_to_get_total_hosts(self):
        print(f"""
Method 1: Take the broadcast and subtract the network address, then add 1. Afterwards, convert the binary to decimal.

      Broadcast:   {self.broadcastBin}
Network address: - {self.netAdrBin}
                   -----------------------------------
                   {IPv4Address._space_out_binary_string(format(self.broadcastInt - self.netAdrInt, '032b'))}
          Add 1: + 00000000 00000000 00000000 00000001
                   -----------------------------------
                   {IPv4Address._space_out_binary_string(format(self.broadcastInt - self.netAdrInt + 1, '032b'))}""")

        # Check my "work" with an assertion (the class uses a simpler calculation method that should have zero errors)
        assert self.broadcastInt - self.netAdrInt + 1 == self.totalAddresses

        usableHosts = 1 if self.prefixLen == 32 else 2 if self.prefixLen == 31 else self.totalAddresses - 2
        assert usableHosts == self.usableHosts

        # Convert binary number to decimal to get total addresses
        self._show_binary_to_decimal()

        if self.prefixLen == 31:
            print(f"""Since this is a point-to-point link (/31), the total usable addresses is the same as the total addresses because the broadcast address and network address are both usable hosts.

For {self.ipAdrCIDR}, since it has {self.totalAddresses:,d} total addresses, it has {self.totalAddresses:,d} usable hosts.""")
        elif self.prefixLen == 32:
            print(f"""Since this is a host route (/32), the total usable addresses is the same as the total addresses because the network size only allows a single address.
                  
For {self.ipAdrCIDR}, since it has {self.totalAddresses:,d} total addresses, it has {self.totalAddresses:,d} usable hosts.""")
        else:
            print(f"""Knowing the total number of addresses, calculating the usable hosts is as simple as total addresses - 2. The minus 2 comes from not being able to use the network address and not being able to use the broadcast. The two exceptions are a /31 network or a /32 network. For both of these, the total usable hosts are the same as the total addresses (no minus 2).

For {self.ipAdrCIDR}, since it has {self.totalAddresses:,d} total addresses, it has {self.totalAddresses:,d} - 2 = {self.totalAddresses - 2:,d} usable hosts.""")


        if self.prefixLen < 31:
            assert self.totalAddresses - 2 == self.usableHosts
        elif self.prefixLen >= 31:
            assert self.totalAddresses == self.usableHosts

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
        totalAddressesBin = IPv4Address._space_out_binary_string(format(self.broadcastInt - self.netAdrInt + 1, '032b'))
        digits = len(totalAddressesBin.replace(" ","")) - 1
        print(f"""
Method 1: Add Powers of 2

This is essentially the reverse of method 1 for converting decimal to binary, this should be familiar. The big difference is that the total addresses could be 4,294,967,296 if the prefix length was 0. As such, you will need a much bigger base 10 equivalent for the powers of 2 if you have a small prefix. Here is a cheat sheet:

/0             /1             /2             /3           /4           /5           /6          /7          /8          /9         /10        /11        /12        /13      /14      /15      /16     /17     /18     /19    /20    /21    /22    /23  /24  /25  /26  /27  /28  /29  /30  /31  /32
2^32           2^31           2^30           2^29         2^28         2^27         2^26        2^25        2^24        2^23       2^22       2^21       2^20       2^19     2^18     2^17     2^16    2^15    2^14    2^13   2^12   2^11   2^10   2^9  2^8  2^7  2^6  2^5  2^4  2^3  2^2  2^1  2^0
4,294,967,296  2,147,483,648  1,073,741,824  536,870,912  268,435,456  134,217,728  67,108,864  33,554,432  16,777,216  8,388,608  4,194,304  2,097,152  1,048,576  524,288  262,144  131,072  65,536  32,768  16,384  8,192  4,096  2,048  1,024  512  256  128  64   32   16   8    4    2    1

To start, add the base 10 value associated with the power of 2 wherever the binary digit is 1 and skip adding the value when the binary digit is 0. Given the total addresses value in binary is:
{totalAddressesBin}
if you decided to include all of the zeros when following these steps, it would turn into this mess:""")

        toPrint = ""
        toPrint2 = ""
        num = 0
        for j in range(digits, -1, -1):
            toPrint += f"{binStr[digits - j]} * 2^{j} + "
            toPrint2 += f"{int(binStr[digits - j])* 2**j:,d} + "
            num += int(binStr[digits - j])* 2**j

        print(f"""{toPrint.rstrip(' +')} =

Which simplifies too:
{toPrint2.rstrip(' +')} = {num:,d}

However, if you only wrote down a number to add when the value is 1, it would be this:""")

        toPrint = ""
        toPrint2 = ""
        num2 = 0
        for j in range(digits, -1, -1):
            if binStr[digits - j] == "1":
                toPrint += f"{binStr[digits - j]} * 2^{j} + "
                toPrint2 += f"{int(binStr[digits - j])* 2**j:,d} + "
                num2 += int(binStr[digits - j])* 2**j

        if toPrint == "":
            print("Since all 0s, it simply = 0")

        if toPrint2 != "":
            print(f"""{toPrint.rstrip(' +')} =

Which simplifies too:
{toPrint2.rstrip(' +')} = {num2:,d}""")

        assert num == num2 and num == self.totalAddresses

    def _method_host_bits_exponent_total_hosts(self):
        print(f"""
Method 2: Raise 2 to the host bits power.

To get the number of host bits using the subnet mask in binary format, count the total number of 0s:
{self.netmaskBin}
# of 0s = {self.netmaskBin.count("0")}
host bits = {self.netmaskBin.count("0")}

The other method involves subtracting the CIDR prefix length (/{self.prefixLen}) prefix length from 32.
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

For the complete explanation, see the block size section.""")

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

            print(f"{binStr}\n{' ' * index}^\n{num:,d} * 2 + {binStr[index]} = {num * 2 + int(binStr[index]):,d} total addresses\n")
            num = num * 2 + int(binStr[index])

        # Check my "work" with an assertion (the class uses a simpler calculation method that should have zero errors)
        assert num == self.totalAddresses

    def _show_binary_to_dotted_decimal_notation(self):
        firstHost = IPv4Address._space_out_binary_string(format(IPv4Address.ip_int_from_string(self.firstHost), '032b'))
        lastHost = IPv4Address._space_out_binary_string(format(IPv4Address.ip_int_from_string(self.lastHost), '032b'))
        print(f"""
Step 8: Convert the binary addresses back to the more common dotted-decimal notation. At this point, these are the known addresses and binary values:

     IPv4 Address: {self.ipStr}
      Subnet Mask: {self.netmaskBin} (or if started with a dotted-decimal address, then you already have it: {self.netmaskStr})
        Host Mask: {self.hostmaskBin}
  Network address: {self.netAdrBin}
        Broadcast: {self.broadcastBin}
       First Host: {firstHost}
        Last Host: {lastHost}

Once again, you will need the base-10 equivalents for the powers of 2. Fortunately, since dotted-decimal notation only allows a maximum value of 255 per octet, you only need 8 bits, making this a reasonable and common approach for converting by hand.

Note: While you can use the "multiply by 2 and add current digit" process demonstrated in calculating the total addresses, it is recommended to write out the following cheat sheet when working with octets, as this often makes conversions easier and reduces the amount of multiplication required.

2^7  2^6  2^5  2^4  2^3  2^2  2^1  2^0
128  64   32   16   8    4    2    1

Using this, add the base-10 value wherever the binary digit is 1, and add nothing where the digit is 0.\n""")

        binaryData = [
            ("subnet mask", "Subnet Mask", self.netmaskBin, self.netmaskStr),
            ("host mask", "Host Mask", self.hostmaskBin, self.hostmaskStr),
            ("network address", "Network address", self.netAdrBin, self.netAdrStr),
            ("broadcast", "Broadcast", self.broadcastBin, self.broadcastStr),
        ]

        if self.prefixLen < 31:
            binaryData.append(("first host address", "First Host", firstHost, self.firstHost))
            binaryData.append(("last host address", "Last Host", lastHost, self.lastHost))

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


        print('\nIf you rather use "multiply by 2 and add current digit" process for each octet, this is how you would do it for all of the values:\n')

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

            print(f"\nFinally, combine them together with a period separating them:\n{label2}: {'.'.join(octets)}")

            # Check my "work" with an assertion (the class uses a simpler calculation method that should have zero errors)
            assert '.'.join(octets) == ipAdr

        
        if self.prefixLen < 31:
            print(f"\nNote: instead of converting from binary to get the first and last host addresses, you could have added 1 to the network address {self.netAdrStr} to get the first host {self.firstHost} and subtracted 1 from the broadcast address {self.broadcastStr} to get the last host {self.lastHost}.")
        elif self.prefixLen == 31:
            print(f"\nNote: since the first host address is the same as the network address {self.netAdrStr} and the last host address is the same as the broadcast address {self.broadcastStr}, the calculation of these were skipped.")

    def _explain_block_method_steps(self):
        print(f"""

+{'=' * len(f'--- Block Size Method for {self.ipAdrCIDR} ---')}+
|--- Block Size Method for {self.ipAdrCIDR} ---|
+{'=' * len(f'--- Block Size Method for {self.ipAdrCIDR} ---')}+
""")

        print(f"""
Steps to calculate key IPv4 information for {self.ipAdrCIDR} -- Block Size/Host Bits method

There are two primary non-binary methods of calculating subnetting information. The Block Size and Host Bits methods are essentially the same in concept, but they approach subnetting from different angles.

In practice, both methods are used to determine the total number of addresses in a subnet (not just usable hosts).

To simplify things, the Host Bits method can be adjusted to only consider the host bits in the interesting octet. The interesting octet is the first octet where the subnet mask stops being 255. This is where subnetting actually happens, meaning this is the only part of the IP address that changes between subnets. Keeping the
Applying the host bits method to the interesting octet keeps the math simple and aligns it directly with the block size method. Since this modification produces the same result for calculating key networking information, this will only refer to the process as the block size method from this point forward.""")

        # Step 1: Calculate the block size
        # Note: this sets octetNum and blockSize in self for future function calls
        self._show_block_size_calc()

        # Step 2: Host mask
        self._show_hostmask_calc_block_method()

        # Step 3: Calculate the network address for the IP address
        self._show_calculate_network_address()

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

First, identify the interesting octet, which determines the subnet boundaries. This is the first octet in the subnet mask that is not 255. If the interesting octet's value is 0 this means the subnet falls exactly on an octet boundary (/0, /8, /16, /24) and the entire octet is dedicated to host bits. In this case, it is not necessary to calculate the block size since the octet is not being subnetted.

Here are some simple examples to help illustrate this:

IP address = 10.1.2.3

Subnet mask = 255.255.255.0
The interesting octet's value is 0. As such, the network address will match the IP address up to, but not including, that octet. All remaining octets, including the interesting octet, will be 0. As an added benefit, there is no need to calculate the block size, network bits, or host bits.
Network address = 10.1.2.0

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

This method works by breaking the prefix length into groups of 8 bits (one octet at a time). As you move through the prefix in chunks of 8, each full 8 bits represents a complete octet of network bits. The first chunk that is not a full 8 bits identifies the interesting octet. In dotted-decimal terms, this is the first octet that is not 255. If the prefix falls on an octet boundary (/0, /8, /16, /24), then just like dotted-decimal, it is not necessary to calculate the block size. The network address will match the IP address for all octets fully covered by the prefix, and remaining octets will be 0.

Here are some examples to help compare the two notations when it comes to interesting octets:
With a prefix of /6  the subnet mask would be 252.0.0.0       (interesting octet = 1)
With a prefix of /8  the subnet mask would be 255.0.0.0       (no calculation needed since prefix ends on an octet boundary)
With a prefix of /10 the subnet mask would be 255.240.0.0     (interesting octet = 2)
With a prefix of /16 the subnet mask would be 255.255.0.0     (interesting octet = 3)
With a prefix of /19 the subnet mask would be 255.255.224.0   (interesting octet = 3)
With a prefix of /24 the subnet mask would be 255.255.255.0   (interesting octet = 4)
With a prefix of /31 the subnet mask would be 255.255.255.254 (interesting octet = 4)

The main benefit of breaking a prefix into 8 bit chunks is that the block size will always fall between 2 and 128, which simplifies the math involved. It also helps reinforce how CIDR notation maps directly to dotted-decimal notation.

Note: This method does not apply to a /32 prefix, since a /32 represents a host route and cannot be subnetted.

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
The prefix falls on an octet boundary (/0, /8, /16, /24) and there is no interesting octet. As such, the network address will match the IP address up to, but not including, the last octet the prefix covered, and all remaining octets will be 0. As an added benefit, there is no need to calculate the block size, network bits, or host bits.

If the prefix is /29, then
29 - 8 = 21, 21 - 8 = 13, 13 - 8 = 5 (network bits)
You subtracted 3 times, so the interesting octet (3 + 1) = 4
8 - 5 = 3 host bits
block size = 2^3 = 8

For {self.ipAdrCIDR}, the prefix is {self.prefixLen}.""")

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

You can calculate the host mask using the prefix length ({self.prefixLen}) from the CIDR address ({self.ipAdrCIDR}) by doing the following:

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

    def _show_calculate_network_address(self):
        print(f"""
Step 3: Calculate the network address that contains the IP address {self.ipAdrCIDR}

The network address is the closest multiple of the block size that does not exceed the IP address in the subnetted octet. There are three methods to calculate the network address:
1. Compute subnets until the desired one is found (works great for large block sizes)
2. Perform integer division on the interesting octet value (works great for small to medium block sizes)
3. Perform modular arithmetic on the interesting octet value (works great for small to medium block sizes)
""")

        # Method 1: compute subnets until the desired one is found
        self._method_calculate_subnets_until_network_address_found()

        # Method 2: perform integer division on the interesting octet value
        self._method_find_network_address_from_integer_division()

        # Method 3: perform modular arithmetic on the interesting octet value
        self._method_find_network_address_from_modular_arithmetic()

    def _method_calculate_subnets_until_network_address_found(self):
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

With the block size of {self.blockSize} and the interesting octet #{self.octetNum}, you can now calculate the network address. Since this is not binary math, there will be some inefficiencies since there is no straight forward method of calculating the network needed, but the primary benefit of not having to convert to and from binary makes this a viable option.

This involves up to two steps. The first is setting the interesting octet {self.octetNum} to 0. The second is setting the octets with only host bits to 0 (everything to the right of the interesting octet). For {self.ipStr}, the octets with only host bits are {hostOctets}.

{self.ipStr} -> {strippedIP}
""")

        if self.prefixLen % 8 == 0: # /0, /8, /16, /24
            subnetAdr = strippedIP
            print(f"Since the prefix falls on an octet boundary (/0, /8, /16, /24), you don't need to do anything else. {subnetAdr} is the network address")
        else:
            print(f"Next, starting from 0, keep adding the block size until the sum is <= the current value in the interesting octet {self.octetNum} and the sum + block size ({self.blockSize}) is > {octetVal}.\n")

            num = 0
            subnetAdr = strippedIP
            print(f"starting interesting octet = {num}, is {num} <= {octetVal}? {'Yes' if num <= octetVal else 'no'}, is {num} + {self.blockSize} ({num + self.blockSize}) > {octetVal}? {'Yes' if num + self.blockSize > octetVal else 'no'}, subnet address = {subnetAdr}\n")
            if self.blockSize >= octetVal:
                print("Nice! No addition necessary since the first subnet is the network address!")
            else:
                toPrintLines = []
                while num < octetVal:
                    num += self.blockSize
                    if networkOctets == "":
                        subnetAdr = f"{num}{justZeroedHostsOctets}"
                    else:
                        subnetAdr = f"{networkOctets}.{num}{justZeroedHostsOctets}"

                    toPrintLines.append(f"interesting octet = {str(num - self.blockSize).rjust(3)} + {str(self.blockSize).ljust(3)} = {str(num).ljust(3)}, is {str(num).rjust(3)} <= {str(octetVal).ljust(3)}? {'yes' if num <= octetVal else 'no '}, is {str(num).rjust(3)} + {str(self.blockSize).ljust(3)} = {str(num + self.blockSize).ljust(3)} > {str(octetVal).ljust(3)}? {'yes' if num + self.blockSize > octetVal else 'no '}, subnet address = {subnetAdr}")

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
                        print(f"\nSince both conditions match, the subnet address, {subnetAdr}, is the network address")
                        break

        assert subnetAdr == self.netAdrStr

    def _method_find_network_address_from_integer_division(self):
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
            subnetAdr = f"{octetVal // self.blockSize * self.blockSize}{justZeroedHostsOctets}"
        else:
            strippedIP = f"{networkOctets}.0{justZeroedHostsOctets}"
            subnetAdr = f"{networkOctets}.{octetVal // self.blockSize * self.blockSize}{justZeroedHostsOctets}"

        print("\nMethod 2: find the network address from integer division. This method works great for small to medium block sizes.")

        if self.prefixLen % 8 == 0: # /0, /8, /16, /24
            print(f"""
Since the prefix falls on an octet boundary (/0, /8, /16, /24), you don't need to do the normal process. Set the interesting octet to 0 (octet {self.octetNum}). Then perform the final step of setting the octets with only host bits to 0 (everything to the right of the interesting octet). For {self.ipStr}, the octets with only host bits are {hostOctets}.

{self.ipStr} -> {strippedIP}

Now you have the network address: {subnetAdr}""")
        else:
            print(f"""
Fortunately, for smaller or medium block sizes, performing integer division or modular arithmetic is the easiest and fastest way to calculate the network address. The process is, in math terms:

Take the interesting octet value ({octetVal}), divide it by the block size ({self.blockSize}) using integer division, then multiply the result by the block size ({self.blockSize}) to get the network address value in the interesting octet:
Network address octet value = octet_value // block_size * block_size

Examples:
If the IP address is 10.200.100.1/9, then the interesting octet value is 200, the block size is 128:
Network address octet value = 200 // 128 * 128
Network address octet value = 1 * 128
Network address octet value = 128

If the IP address is 10.200.100.1/12, then the interesting octet value is 200, the block size is 16:
Network address octet value = 200 // 16 * 16
Network address octet value = 12 * 16
Network address octet value = 192

If the IP address is 10.200.100.1/15, then the interesting octet value is 200, the block size is 2:
Network address octet value = 200 // 2 * 2
Network address octet value = 100 * 2
Network address octet value = 200

For {self.ipAdrCIDR}, the interesting octet value is {octetVal}, and the block size is {self.blockSize}
Network address octet value = {octetVal} // {self.blockSize} * {self.blockSize}
Network address octet value = {octetVal // self.blockSize} * {self.blockSize}
Network address octet value = {octetVal // self.blockSize * self.blockSize}

With the Network address value calculated for the interesting octet (#{self.octetNum}), set that value in the IP address {self.ipStr}. Then set the octets with only host bits to 0 (everything to the right of the interesting octet). For {self.ipStr}, the octets with only host bits are {hostOctets}.

{self.ipStr} -> {subnetAdr} = network address""")

        assert subnetAdr == self.netAdrStr

    def _method_find_network_address_from_modular_arithmetic(self):
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
            subnetAdr = f"{octetVal - octetVal % self.blockSize}{justZeroedHostsOctets}"
        else:
            strippedIP = f"{networkOctets}.0{justZeroedHostsOctets}"
            subnetAdr = f"{networkOctets}.{octetVal - octetVal % self.blockSize}{justZeroedHostsOctets}"

        print("\nMethod 3: find the network address from modular arithmetic. This method works great for small to medium block sizes.")

        if self.prefixLen % 8 == 0: # /0, /8, /16, /24
            subnetAdr = strippedIP
            print(f"""
Since the prefix falls on an octet boundary (/0, /8, /16, /24), you don't need to do the normal process. Set the interesting octet to 0 (octet {self.octetNum}). Then perform the final step of setting the octets with only host bits to 0 (everything to the right of the interesting octet). For {self.ipStr}, the octets with only host bits are {hostOctets}.

{self.ipStr} -> {subnetAdr} = network address""")
        else:
            print(f"""
Take the interesting octet value ({octetVal}), find the remainder (modulo) when dividing it by the block size ({self.blockSize}), then subtract that remainder from the octet value ({octetVal}) to get the network address value in the interesting octet:
Network address octet value = octet_value - (octet_value % block_size)

Examples:
If the IP address is 10.200.100.1/9, then the interesting octet value is 200, the block size is 128:
Network address octet value = 200 - (200 % 128)
Network address octet value = 200 - 72
Network address octet value = 128

If the IP address is 10.200.100.1/12, then the interesting octet value is 200, the block size is 16:
Network address octet value = 200 - (200 % 16)
Network address octet value = 200 - 8
Network address octet value = 192

If the IP address is 10.200.100.1/15, then the interesting octet value is 200, the block size is 2:
Network address octet value = 200 - (200 % 2)
Network address octet value = 200 - 0
Network address octet value = 200

For {self.ipAdrCIDR}, the interesting octet value is {octetVal}, and the block size is {self.blockSize}
Network address octet value = {octetVal} - ({octetVal} % {self.blockSize})
Network address octet value = {octetVal} - {octetVal % self.blockSize}
Network address octet value = {octetVal - octetVal % self.blockSize}

With the Network address value calculated for the interesting octet (#{self.octetNum}), set that value in the IP address {self.ipStr}. Then set the octets with only host bits to 0 (everything to the right of the interesting octet). For {self.ipStr}, the octets with only host bits are {hostOctets}.

{self.ipStr} -> {subnetAdr} = network address""")

        assert subnetAdr == self.netAdrStr

    def _show_broadcast_calc_block_method(self):
        networkOctets = ""
        hostOctets = ""
        justMaxedHostsOctets = '.255' * (4 - self.octetNum)
        octets = self.netAdrStr.split('.')
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

With the network address ({self.netAdrStr}/{self.prefixLen}) and block size ({self.blockSize}) known, the next step is to calculate the broadcast address.""")

        if self.prefixLen % 8 == 0: # /0, /8, /16, /24
            print(f"""
Since the prefix falls on an octet boundary (/0, /8, /16, /24), you don't need to do the normal process. Set the interesting octet to 255 (octet {self.octetNum}). Then perform the final step of setting the octets with only host bits to 255 (everything to the right of the interesting octet). For {self.netAdrStr}, the octets with only host bits are {'x.' * (self.octetNum - 1)}{octetVal}{'.' if hostOctets != '' else ''}{hostOctets}.

{self.netAdrStr} -> {broadcast} = broadcast address""")
        else:
            print(f"""
This involves adding the block size to the interesting octet value in the network address ({octetVal}) and subtracting 1. Then setting the octets with only host bits to 255 (the ones to the right of the interesting octet). This gives you the broadcast address.

Note: the network only octets (if applicable) stay the same.

Examples:

If the network address is 172.30.4.80/28 and the block size is 16 then:
Update interesting octet value = 80 + 16 - 1 = 95 = 172.30.4.95
Host only bits to 255 = 172.30.4.80 -> 172.30.4.80 (there are none)
Broadcast address = 172.30.4.95

If the network address is 172.160.160.0/19 and the block size is 32 then:
Update interesting octet value = 160 + 32 - 1 = 191 = 172.160.191.0
Host only bits to 255 = 172.160.191.0 -> 172.160.191.255
Broadcast address = 172.160.191.255

If the network address is 200.128.0.0/9 and the block size is 128 then:
Update interesting octet value = 128 + 128 - 1 = 255 = 200.255.0.0
Host only bits to 255 = 200.255.0.0 -> 200.255.255.255
Broadcast address = 200.255.255.255

If the network address is 132.0.0.0/7 and the block size is 2 then:
Update interesting octet value = 132 + 2 - 1 = 133 = 133.0.0.0
Host only bits to 255 = 133.0.0.0 -> 133.255.255.255
Broadcast address = 133.255.255.255

For {self.netAdrStr}/{self.prefixLen} and the block size of {self.blockSize}:
Update interesting octet value = {octetVal} + {self.blockSize} - 1 = {octetVal + self.blockSize - 1} = {updatedIP}
Host only bits to 255 = {updatedIP} -> {broadcast}
Broadcast address = {broadcast}""")

        assert broadcast == self.broadcastStr

    def _show_first_last_host_calc_block_method(self):
        print("\nStep 5: Calculate the first and last usable hosts")

        if self.prefixLen >= 31:
            firstHost = self.netAdrStr
            lastHost = self.broadcastStr
        else:
            firstHost = self.netAdrStr.split('.')
            firstHost = '.'.join(firstHost[:3] + [str(int(firstHost[3]) + 1)])
            lastHost = self.broadcastStr.split('.')
            lastHost = '.'.join(lastHost[:3] + [str(int(lastHost[3]) - 1)])

        if self.prefixLen == 31:
            print(f"""
Since according to RFC3021 this is a point-to-point link (/31), the network address is the first host and the broadcast address is the last host.

Network address: {self.netAdrStr}
     First Host: {firstHost}

      Broadcast: {self.broadcastStr}
      Last Host: {lastHost}""")
        elif self.prefixLen == 32:
            print(f"""
Since according to RFC4632 this is a host route (/32), the first and last host are both equal the IP address since the network size only allows a single address.

IP Address: {self.ipStr}
First Host: {firstHost}
Last Host:  {lastHost}""")
        else:
            print(f"""
With the network address {self.netAdrStr} and broadcast address {self.broadcastStr}, calculating the first and last usable host is rather simple. For the first host, add 1 to the network address. For the last host, subtract 1 from the broadcast address.

First host = {self.netAdrStr} + 1 = {firstHost}
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
Now that the number of total addresses is known to be {self.totalAddresses:,d}, you simply subtract 2 (1 for the broadcast and 1 for the network address) to get the total usable hosts:
{self.totalAddresses:,d} - 2 = {self.totalAddresses - 2:,d}

The two exceptions are a /31 network or a /32 network. For both of these, the total usable hosts are the same as the total addresses (no minus 2).

Since this is a /{self.prefixLen}, this {message}""")

    def _distribute(self, powers, sourceIndex, startIndex):
        taken = 0
        for i in range(len(powers) - 1, startIndex, -1):
            while powers[sourceIndex] > 0 and powers[i] < 10:
                powers[sourceIndex] -= 1
                powers[i] += 1
                taken += 1
        return taken

    def _method_get_total_hosts_with_block_size(self):
        numHostOctets = (32 - self.prefixLen) // 8
        if self.prefixLen % 8 == 0: # /0, /8, /16, /24
            numHostOctets -= 1

        message = "there are no full host octets"
        if numHostOctets > 1:
            message = f"the last {numHostOctets} octets are entirely host bits ({('0.' * numHostOctets)[:-1]})"
        elif numHostOctets == 1:
            message = "the last octet is entirely host bits (0)"

        print(f"""Method 1: compute the total number of addresses using the block size

This method uses the block size and multiplies it by 256 for each octet that consists entirely of host bits in the network address.

For prefixes that fall on an octet boundary (/0, /8, /16, /24), the "interesting octet" is treated as a full host octet, since its block size is 256.

For example:

If the network address is 1.0.0.0/8 and the block size is 256 then the last 3 octets are entirely host bits.
256 * 256 * 256 = 16,777,216 = total addresses

If the network address is 10.128.0.0/9 and the block size is 128 then the last 2 octets are entirely host bits.
128 * 256 * 256 = 8,388,608 = total addresses

If the network address is 172.17.36.0/22 and the block size is 4 then the last octet is entirely host bits.
There is 1 host only octets so:
4 * 256 = 1,024 = total addresses

If the network address is 192.168.0.0/26 and the block size is 64 then there are no full host octets.
64 = total addresses

For the network {self.netAdrStr}/{self.prefixLen}, with a block size of {self.blockSize}, {message}.""")

        if numHostOctets == 0:
            print(f"{self.blockSize:,d} = total addresses")
        else:
            print(f"{self.blockSize}{' * 256' * numHostOctets} = {self.blockSize * 256**numHostOctets:,d} = total addresses")

            print(f"""
If you need to estimate the total number of hosts and don't require an exact value, you can use this block-based method instead of working with exponents. The prefix-length method is usually simpler for quick estimates, but this provides an alternative way to approach the problem.

This method works directly with the factors that make up the subnet size. Since subnet sizes are powers of 2, they can always be broken down into factors of 2. These factors can then be rearranged to form numbers that are easier to work with mentally.

Each octet that is entirely host bits contributes a factor of 256. Since 256 * 4 = 1024 (which is close to 1000), the idea is to take two factors of 2 from elsewhere in the expression and combine them with each 256 to turn it into approximately 1000. In other words, each 256 needs two additional factors of 2 to become about 1000.

Note: rearranging factors does not change the value. The change comes from rounding 1024 down to 1000.

For example, to estimate the number of address for the network 10.0.0.0/10, with a block size of 64, the last 2 octets are entirely host bits (0.0.0):
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
256 = 2 * 2 * 2 * 2 * 2 * 2 * 2 * 2

Take 2 factors of 2 (1 from 2, 1 from 256) and move them to the 1 256 term:

256 * 2 * 2 = 1024 or approx. 1000

Remaining:
2 / 2 = 1
256 / 2 = 128

Final estimate:
128 * 1000 = 128,000

For the network {self.netAdrStr}/{self.prefixLen}, with a block size of {self.blockSize}, the last {numHostOctets} octet{'s' if numHostOctets != 1 else ''} are entirely host bits ({('0.' * numHostOctets)[:-1]}):""")

            takenFromBlock = 0
            takenFrom256 = 0

            # index 0 is for blockSize
            powers = [0] + [8] * numHostOctets

            # get blockSize factors of 2
            num = self.blockSize
            while num != 1:
                powers[0] += 1
                num //= 2

            # distribute block pool (powers[0]) into host octets (right to left) until they are 2^10 or blockSize factors runs out
            takenFromBlock += self._distribute(powers, 0, 0)

            # Rebalance from first host octet (powers[1]) to maximize number of 2^10-sized octets
            takenFrom256 += self._distribute(powers, 1, 1)

            totalTaken = takenFromBlock + takenFrom256
            upgradedOctets = 0
            for i in powers[1:]:
                if i > 8: # larger than original size
                    upgradedOctets += 1

            takeLine = f"Take {totalTaken} factor{'s' if totalTaken != 1 else ''} of 2 "

            factorsFromBorrowedNumbers = f"{self.blockSize} = {('2 * ' * (powers[0] + takenFromBlock))[:-3]}"

            if takenFrom256 > 0:
                takeLine += f"({takenFromBlock} from {self.blockSize}, {takenFrom256} from 256)"
                factorsFromBorrowedNumbers += "\n256 = 2 * 2 * 2 * 2 * 2 * 2 * 2 * 2"
            else:
                takeLine += f"(all from {self.blockSize})"

            takeLine += f" and move them to the {upgradedOctets} 256 term{'s' if upgradedOctets != 1 else ''}:"

            factors = [2 ** powers[0]]
            thousandLines = ""

            for i, p in enumerate(powers[1:]):
                value = 2 ** p
                if p > 8:
                    line = "256" + " * 2" * (p - 8)
                    if p == 10:
                        factors.append(1000)
                        thousandLines += f"{line} = {value} or approx. 1000\n"
                    else:
                        factors.append(value)
                        thousandLines += f"{line} = {value}\n"
                else:
                    factors.append(value)

            remainingLines = "Remaining:\n"

            if takenFromBlock > 1:
                remainingLines += f"{self.blockSize} / ({('2 * ' * takenFromBlock)[:-3]}) = {self.blockSize // (2 ** takenFromBlock)}"
            elif takenFromBlock == 1:
                remainingLines += f"{self.blockSize} / 2 = {self.blockSize // 2}"

            if takenFrom256 > 1:
                remainingLines += f"\n256 / ({('2 * ' * takenFrom256)[:-3]}) = {256 // (2 ** takenFrom256)}"
            elif takenFrom256 == 1:
                remainingLines += "\n256 / 2 = 128"
            elif powers[1] == 8: # since the estimation code has > 0 numHostOctets, don't need to worry about IndexError Exception
                remainingLines += "\n256"

            estimateLines = "Final estimate:\n"

            total = 1
            for i in factors:
                total *= i
                if i > 1:
                    estimateLines += f"{i} * "

            estimateLines = estimateLines[:-2] + f"= {total:,d}"

            print(f"""{self.blockSize}{' * 256' * numHostOctets}

{factorsFromBorrowedNumbers}

{takeLine}

{thousandLines}
{remainingLines}

{estimateLines}""")

        assert self.blockSize * 256**numHostOctets == self.totalAddresses

    def _method_get_total_hosts_with_prefix_length(self):
        print(f"""
Method 2: compute the total addresses using the prefix length

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

For {self.ipAdrCIDR}:
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

For {self.ipAdrCIDR}:""")

        hostBits = 32 - self.prefixLen
        print(f"""
32 - {self.prefixLen} = {hostBits}
2^{32 - self.prefixLen} = {'2^10 * ' * (hostBits // 10)}2^{hostBits % 10}

Final estimate:
{'1000 * ' * (hostBits // 10)}{2**(hostBits % 10)} = {1000**(hostBits // 10) * 2**(hostBits % 10):,d} total addresses""")

        assert 2**(32 - self.prefixLen) == self.totalAddresses
