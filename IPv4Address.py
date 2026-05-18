class IPv4Address:
    """Represents an IPv4 address and provides methods to analyze and manipulate the address.

Supports operations such as determining the address class, calculating subnet and supernet information, and validating IPv4 addresses and prefix lengths.

Can display calculation steps or provide detailed explanations of the underlying networking concepts.
"""

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

    ALL_ONES = 0xFFFFFFFF # 32-bit value with all bits set to 1. Equivalent to 4294967295, 255.255.255.255, or 11111111111111111111111111111111.

    RESERVED_START = 0xF0000000 # 240.0.0.0
    RESERVED_END = ALL_ONES # Same value as ALL_ONES.

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
    def calculate_subnet_mask_int(prefixLen):
        """
Calculate the subnet mask from the provided prefix length by performing a bitwise left shift (<<) operation on a 32-bit value containing all 1s (IPv4Address.ALL_ONES).
After the shift, a bitwise AND (&) with IPv4Address.ALL_ONES keeps only the lower 32 bits and discards any overflow bits.
The result contains prefixLen network bits set to 1 and the remaining host bits set to 0, forming the subnet mask.
        """

        # Example
        # prefixLen = 16
        # IPv4Address.ALL_ONES = 11111111 11111111 11111111 11111111
        #
        # 32 - 16 = 16
        # 11111111 11111111 11111111 11111111 << 16
        # =
        # 11111111 11111111 11111111 11111111 00000000 00000000
        #
        # The result is a 48-bit value in memory. Python integers support arbitrary precision, so the result temporarily expands beyond 32 bits.
        # The bitwise AND operation keeps only the lower 32 bits:
        #
        # 11111111 11111111 11111111 11111111 00000000 00000000
        # &
        # 11111111 11111111 11111111 11111111
        # =
        # 11111111 11111111 00000000 00000000
        #
        # Result:
        # 11111111 11111111 00000000 00000000 = 255.255.0.0

        return (IPv4Address.ALL_ONES << (32 - prefixLen)) & IPv4Address.ALL_ONES

    @staticmethod
    def calculate_network_address_int(ipInt, subnetMaskInt):
        """
Calculate the network address by performing a bitwise AND (&) operation between the IPv4 address (ipInt) and the subnet mask (subnetMaskInt).
This operation clears the host portion of the IP address because the subnet mask contains 1s in the network portion and 0s in the host portion.
As a result, the bitwise AND (&) operation preserves the network bits and clears the host bits.

A bitwise AND operation produces a 1 only when both bits are 1. Otherwise, the result is 0.
        """

        # Example:
        # ipInt         = 10.111.112.113
        # subnetMaskInt = 255.240.0.0
        #
        # 10.111.112.113 = 00001010 01101111 01110000 01110001
        # 255.240.0.0    = 11111111 11110000 00000000 00000000
        #
        # Apply the bitwise AND (&) operation:
        # 00001010 01101111 01110000 01110001
        # &
        # 11111111 11110000 00000000 00000000
        # =
        # 00001010 01100000 00000000 00000000
        #
        # Result:
        # 00001010 01100000 00000000 00000000 = 10.96.0.0

        return ipInt & subnetMaskInt

    def __init__(self, IPv4, showSteps=False, explainHowToCalculate=False):
        # Parse the IPv4 input and initialize the core address and subnet attributes.
        self._ipv4_address_parser(IPv4)

        # Initialize subnet-related attributes based on the prefix length.
        if self.prefixLen == 32:
            self._setup_host_route()
        elif self.prefixLen == 31:
            self._setup_point_to_point()
        else: # Remaining valid prefix lengths (/0 to /30) use standard subnet behavior.
            self._setup_normal_subnet()

        # Set address classification and special-use address flags.
        self.adrClass = self._calculate_address_class()
        self.privateUse = IPv4Address.PRIVATE_10_START <= self.ipInt <= IPv4Address.PRIVATE_10_END or IPv4Address.PRIVATE_172_START <= self.ipInt <= IPv4Address.PRIVATE_172_END or IPv4Address.PRIVATE_192_START <= self.ipInt <= IPv4Address.PRIVATE_192_END
        self.linkLocal = IPv4Address.LINKLOCAL_START <= self.ipInt <= IPv4Address.LINKLOCAL_END
        self.multicast = IPv4Address.MULTICAST_START <= self.ipInt <= IPv4Address.MULTICAST_END
        self.reserved = IPv4Address.RESERVED_START <= self.ipInt <= IPv4Address.RESERVED_END
        self.loopback = IPv4Address.LOOPBACK_START <= self.ipInt <= IPv4Address.LOOPBACK_END
        self.limitedBroadcast = self.ipInt == IPv4Address.ALL_ONES

        # Store flags that control calculation output and teaching explanations.
        self.showSteps = showSteps
        self.explainHowToCalculate = explainHowToCalculate

        if self.showSteps:
            self._print_steps()

        if self.explainHowToCalculate:
            self._explain_how_to_calculate()

    def _setup_host_route(self):
        # Configure attributes for a host route (/32).

        self.netAdrInt = self.ipInt
        self.netAdrStr = self.ipStr
        self.netAdrBin = self.ipBin
        self.netAdrCIDR = f"{self.ipStr}/32"

        self.broadcastInt = self.ipInt
        self.broadcastStr = self.ipStr
        self.broadcastBin = self.ipBin

        self.totalAddresses = 1
        self.usableHostAddresses = 1
        self.firstHost = self.ipStr
        self.lastHost = self.ipStr

    def _setup_point_to_point(self):
        # Configure attributes for a point-to-point link (/31).
        # RFC 3021 defines both addresses in the subnet as usable host addresses.

        # Set the network address to the first address in the subnet.
        self._set_network_address()

        # Set the broadcast address to the last address in the subnet.
        self._set_broadcast_address()

        self.totalAddresses = 2
        self.usableHostAddresses = 2
        self.firstHost = self.netAdrStr
        self.lastHost = self.broadcastStr

    def _setup_normal_subnet(self):
        # Configure attributes for standard subnets (/0 to /30).

        # Set the network address to the first address in the subnet.
        self._set_network_address()

        # Set the broadcast address to the last address in the subnet.
        self._set_broadcast_address()

        # Total addresses are determined by the number of available host bits (2^host_bits).
        self.totalAddresses = 2 ** (32 - self.prefixLen)
        self.usableHostAddresses = self.totalAddresses - 2 # Standard IPv4 subnets reserve the network and broadcast addresses.
        self.firstHost = IPv4Address.ip_string_from_int(self.netAdrInt + 1) # First usable host address.
        self.lastHost = IPv4Address.ip_string_from_int(self.broadcastInt - 1) # Last usable host address.

    def _set_broadcast_address(self):
        """
Calculate the broadcast address using the subnet mask, network address, and bitwise XOR (^) and OR (|) operations.
First, perform a bitwise XOR (^) operation between the subnet mask and IPv4Address.ALL_ONES to invert the subnet mask.
This changes all network bits to 0 and all host bits to 1.

Next, perform a bitwise OR (|) operation between the inverted subnet mask and the network address.
This sets all host bits to 1, producing the highest address in the subnet, which is the broadcast address.
        """

        # Example:
        # self.subnetMaskInt = 255.255.255.0
        # self.netAdrInt     = 192.168.1.0
        #
        # 255.255.255.0          = 11111111 11111111 11111111 00000000
        # 192.168.1.0            = 11000000 10101000 00000001 00000000
        # IPv4Address.ALL_ONES   = 11111111 11111111 11111111 11111111
        #
        # Invert the subnet mask by performing bitwise XOR (^) operation between subnet mask and all ones:
        # 11111111 11111111 11111111 00000000
        # ^
        # 11111111 11111111 11111111 11111111
        # =
        # 00000000 00000000 00000000 11111111
        #
        # Apply the bitwise OR (|) operation to set all the host bits to 1:
        # 00000000 00000000 00000000 11111111
        # |
        # 11000000 10101000 00000001 00000000
        # =
        # 11000000 10101000 00000001 11111111
        #
        # Result:
        # 11000000 10101000 00000001 11111111 = 192.168.1.255

        self.broadcastInt = (self.subnetMaskInt ^ IPv4Address.ALL_ONES) | self.netAdrInt
        self.broadcastStr = IPv4Address.ip_string_from_int(self.broadcastInt)
        self.broadcastBin = IPv4Address._space_out_binary_string(format(self.broadcastInt, '032b'))

    def _set_network_address(self):
        self.netAdrInt = IPv4Address.calculate_network_address_int(self.ipInt, self.subnetMaskInt)
        self.netAdrStr = IPv4Address.ip_string_from_int(self.netAdrInt)
        self.netAdrBin = IPv4Address._space_out_binary_string(format(self.netAdrInt, '032b'))
        self.netAdrCIDR = f"{self.netAdrStr}/{self.prefixLen}"

    def _ipv4_address_parser(self, IPv4):
        """Supported IPv4 input formats:

        - Dotted-decimal IPv4 address
        Example: 172.30.5.0

        - CIDR notation
        Example: 127.0.5.1/24

        - Dotted-decimal IPv4 address with a dotted-decimal subnet mask
        Example: 10.0.6.7 255.255.255.0

        - Integer IPv4 address with a prefix length
        Example: 16843009 /8

        - Integer representation of an IPv4 address
        Example: 1157895235
        """

        if isinstance(IPv4, int) or IPv4.isdigit():
            # _validate_ipv4_int() returns the validated integer representation or raises ValueError.
            self.ipInt = self._validate_ipv4_int(int(IPv4))
            ipStr = IPv4Address.ip_string_from_int(self.ipInt)
        elif isinstance(IPv4, str):
            ipStr = IPv4
            # Normalize whitespace in the IPv4 input string.
            ipStr = ipStr.strip()
            while "  " in ipStr:
                ipStr = ipStr.replace("  ", " ")

        if "/" in ipStr and " " not in ipStr: # CIDR notation (e.g. 10.0.0.1/8), but not IP (as an int) + prefix format
            ipStr, prefixLenStr = ipStr.split("/")
        elif " " in ipStr:  # IP (dotted decimal) + subnet mask format OR IP (as an int) + prefix format
            obj1, obj2 = ipStr.split() # Additional unexpected fields should raise an error.
            if obj1.isdigit() and obj2.startswith("/") and obj2[1:].isdigit(): # subnet mask format OR IP (as an int) + prefix format
                # _validate_ipv4_int() returns the validated integer representation or raises ValueError.
                self.ipInt = self._validate_ipv4_int(int(obj1))
                ipStr = IPv4Address.ip_string_from_int(self.ipInt)
                prefixLenStr = obj2[1:]
            else: # IP (dotted decimal) + subnet mask format
                ipStr = obj1
                subnetMaskStr = obj2
                self.subnetMaskInt = IPv4Address.ip_int_from_string(subnetMaskStr)
                prefixLenStr = str(format(self.subnetMaskInt, "032b").count("1"))
        else:
            prefixLenStr = "32"
            self.subnetMaskInt = IPv4Address.ALL_ONES

        # _validate_ipv4_prefix_len() returns the validated prefix length or raises ValueError.
        self.prefixLen = self._validate_ipv4_prefix_len(prefixLenStr)

        # _validate_ipv4_octets() returns the validated IPv4 string or raises ValueError.
        self.ipStr = self._validate_ipv4_octets(ipStr)
        if not hasattr(self, "ipInt"):
            self.ipInt = IPv4Address.ip_int_from_string(ipStr)
        self.ipBin = IPv4Address._space_out_binary_string(format(self.ipInt, '032b'))

        if not hasattr(self, "subnetMaskInt"):
            self.subnetMaskInt = IPv4Address.calculate_subnet_mask_int(self.prefixLen)

        self.subnetMaskStr = IPv4Address.ip_string_from_int(self.subnetMaskInt) # Convert integer representation to dotted-decimal format.
        self.subnetMaskBin = IPv4Address._space_out_binary_string(format(self.subnetMaskInt, '032b'))

        self.hostmaskInt = self.subnetMaskInt ^ IPv4Address.ALL_ONES
        self.hostmaskStr = IPv4Address.ip_string_from_int(self.hostmaskInt) # Convert integer representation to dotted-decimal format.
        self.hostmaskBin = IPv4Address._space_out_binary_string(format(self.hostmaskInt, '032b'))


        self.ipAdrCIDR = f"{ipStr}/{self.prefixLen}"

    def _validate_ipv4_int(self, ipInt):
        if ipInt >= 0 and ipInt <= IPv4Address.ALL_ONES:
            return ipInt
        else:
            raise ValueError(f"IPv4 integer values must be between 0 and {IPv4Address.ALL_ONES}. Received: {ipInt}")

    def _validate_ipv4_octets(self, ipStr):
        octets = ipStr.split(".")
        if len(octets) != 4:
            raise ValueError(f"IPv4 address '{ipStr}' must contain exactly 4 octets. Received: {len(octets)}")

        for i in octets:
            if i.isdigit():
                if int(i) < 0 or int(i) > 255:
                    raise ValueError(f"IPv4 address '{ipStr}' must contain octets with values between 0 and 255. Invalid octet: {i}")
                elif i != "0" and i[0] == "0":
                    raise ValueError(f"IPv4 address '{ipStr}' cannot contain octets with leading zeros. Invalid octet: {i}")
            else:
                raise ValueError(f"The IPv4 Address {ipStr} must contain 4 octets made up of digits. {i} is not a digit")


        return ipStr

    def _validate_ipv4_prefix_len(self, prefixLenStr):
        if prefixLenStr.isdigit():
            # Store the validated prefix length as an integer.
            prefixLenInt = int(prefixLenStr)
            if prefixLenInt >= 0 and prefixLenInt <= 32:
                return prefixLenInt
            else:
                raise ValueError(f"CIDR prefix lengths must be integers between 0 and 32. Received: {prefixLenInt}")
        else:
            raise ValueError(f"CIDR prefix lengths must be integers between 0 and 32. Received: {prefixLenStr}")

    def _calculate_address_class(self):
        # Determine the historical IPv4 address class from the most significant bits.
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
        """Determine whether the provided IPv4 address belongs to this network."""

        # Convert the provided IPv4 input to its integer representation.
        if isinstance(ip, str):
            ipInt = IPv4Address.ip_int_from_string(self._validate_ipv4_octets(ip))
        elif isinstance(ip, int):
            ipInt = self._validate_ipv4_int(ip)
        elif isinstance(ip, IPv4Address):
            ipInt = ip.ipInt
        else:
            raise ValueError("IPv4 input must be a string, integer, or IPv4Address object")

        # A /32 host route contains only one IPv4 address.
        if self.prefixLen == 32:
            return ipInt == self.ipInt # Direct comparison is clearer for a /32 host route.

        # Otherwise, check whether the IPv4 address falls within the subnet range.
        return self.netAdrInt <= ipInt <= self.broadcastInt

    def subnets(self, newPrefix, limit=1000, subnetByOctetBoundary=False):
        """
        Generate subnet blocks using fixed-size increments derived from the CIDR prefix length.

        The method calculates a constant block size (2^(32 - newPrefix)) and iterates through the address space in equal increments starting from the network address.

        Parameters:
            newPrefix (int):
                Target subnet prefix length that is greater than the current prefix length.
            limit (int):
                Maximum number of subnets to generate (0 = no limit).
            subnetByOctetBoundary (bool):
                If True, restricts displayed subnet results to a single octet-aligned portion of the address space.
                This does not change subnet size, block size, stepping behavior, or subnet generation logic. It only limits the generated subnet results for visualization purposes.

        Behavior Notes:
            - Subnets are always generated using fixed-size block stepping.
            - Octet-boundary mode only restricts which generated results are displayed and does not affect subnet calculation or generation.
        """

        # Validate the target prefix length.
        if newPrefix <= self.prefixLen or newPrefix > 32:
            raise ValueError(f"newPrefix must be greater than the current prefix length ({self.prefixLen}) and <= 32")

        # Validate the subnet generation limit.
        if limit < 0:
            raise ValueError(f"Provided limit ({limit}) is invalid. Limit must be >= 0")

        # Calculate the number of IPv4 addresses per subnet.
        blockSize = 2 ** (32 - newPrefix)

        finalSubnetInt = self.broadcastInt

        # Optionally restrict displayed subnets to a single octet boundary (/0, /8, /16, or /24) when the new prefix length enters a different octet.
        if subnetByOctetBoundary and self.prefixLen // 8 != newPrefix // 8:
            # Adjust the final subnet boundary to remain within a single octet range.
            if newPrefix > 24:
                finalSubnetInt = (self.broadcastInt & 0x000000FF) | self.netAdrInt
            elif newPrefix > 16:
                finalSubnetInt = (self.broadcastInt & 0x0000FF00) | self.netAdrInt
            elif newPrefix > 8:
                finalSubnetInt = (self.broadcastInt & 0x00FF0000) | self.netAdrInt
            else:
                finalSubnetInt = (self.broadcastInt & 0xFF000000) | self.netAdrInt

            # Include the final subnet when subnetting exactly on an octet boundary.
            if newPrefix % 8 == 0:
                finalSubnetInt += 1
        else:
            if newPrefix == 32: # A /32 host route may use the original subnet broadcast address as a valid host route (for example, 10.0.5.255/32 from 10.0.5.0/24).
                finalSubnetInt += 1

        count = 0

        for subnetIPInt in range(self.netAdrInt, finalSubnetInt + 1, blockSize):
            # Prevent iteration beyond the valid subnet range.
            if subnetIPInt >= finalSubnetInt:
                break

            # Enforce the subnet generation limit when enabled.
            if limit > 0 and count >= limit:
                print(f"Subnet generation limit reached ({limit} subnet{'s' if limit != 1 else ''}). Stopping generation.")
                break

            yield IPv4Address(f"{subnetIPInt} /{newPrefix}")

            count += 1

    def supernet(self, newPrefix):
        """Generate a supernet from an existing smaller network using the provided larger prefix length."""

        if newPrefix >= self.prefixLen or newPrefix < 0:
            raise ValueError("newPrefix must be < current prefix and >=0")

        # Calculate the subnet mask for the new prefix length.
        subnetMaskInt = IPv4Address.calculate_subnet_mask_int(newPrefix)

        # Calculate the supernet network address using the new prefix length.
        supernetAdrInt = IPv4Address.calculate_network_address_int(self.ipInt, subnetMaskInt)

        # Return a new IPv4Address object representing the supernet.
        return IPv4Address(f"{supernetAdrInt} /{newPrefix}", self.showSteps)

    def __str__(self):
        return f"""IPv4 Address:  {self.ipStr}
Subnet Mask:   {self.subnetMaskStr}
Host Mask:     {self.hostmaskStr}
Prefix Length: {self.prefixLen}

Network Address:   {self.netAdrStr}
Broadcast Address: {self.broadcastStr}

First Host Address:    {self.firstHost}
Last Host Address:     {self.lastHost}
Total Addresses:       {self.totalAddresses:,d}
Usable Host Addresses: {self.usableHostAddresses:,d}

IP Address (CIDR):      {self.ipAdrCIDR}
Network Address (CIDR): {self.netAdrCIDR}

Binary (IPv4 Address):      {self.ipBin}
Binary (Subnet Mask):       {self.subnetMaskBin}
Binary (Host Mask):         {self.hostmaskBin}
Binary (Network Address):   {self.netAdrBin}
Binary (Broadcast Address): {self.broadcastBin}

Address Class (Historical):                        {self.adrClassStr}
Private Address, Non-Publicly Routable (RFC 1918): {self.privateUse}
Link-Local Address, Non-Routable (RFC 3927):       {self.linkLocal}
Multicast:                                         {self.multicast}
Loopback:                                          {self.loopback}
"""

    def _calculate_block_size_and_interesting_octet(self):
        if self.prefixLen == 32: # A /32 host route requires separate handling because it has no host bits.
            self.blockSize = 1
            self.interestingOctet = 4
        else:
            self.interestingOctet = (self.prefixLen // 8) + 1
            self.blockSize = 2**(8 - self.prefixLen % 8)

    def _calculate_octet_portions(self):
        self.octets = self.ipStr.split('.')

        # Store octet values as strings for display and explanation output.
        self.networkOctets = []
        self.hostOctets = []
        self.zeroedHostOctets = []

        for i in range(self.interestingOctet - 1):
            self.networkOctets.append(self.octets[i])

        for i in range(self.interestingOctet, 4):
            self.hostOctets.append(self.octets[i])
            self.zeroedHostOctets.append("0")

        # Store the interesting octet value as an integer.
        self.interestingOctetVal = int(self.octets[self.interestingOctet - 1])

    def _print_steps(self):
        self._calculate_block_size_and_interesting_octet()
        self._calculate_octet_portions()

        if self.prefixLen == 32:
            print("""Per RFC 4632, a /32 is a host route.

A host route represents a single IP address, not a range. That means:
- Network address = the IP address itself
- A /32 does not have a meaningful broadcast address because it does not support broadcasting
- There are no additional host addresses

Since the subnet contains only one address, additional subnet calculations are unnecessary. However, the underlying binary rules still apply mathematically, as shown below. Because a /32 contains no host bits, standard block size subnetting methods cannot derive additional subnet information.
""")

        elif self.prefixLen == 31:
            print("""Per RFC 3021, a /31 is a point-to-point link.

A /31 network contains exactly 2 IP addresses. Unlike most subnets:
- Both addresses are usable
- Traditional network and broadcast addresses are not used
""")

        self._print_binary_steps()

        if self.prefixLen != 32:
            self._print_block_size_steps()
        else:
            print("\nSince a /32 host route contains no host bits, there is no interesting octet. As a result, standard block size subnetting methods cannot be applied, and the block size section will be skipped.")

    def _print_binary_steps(self):
        firstHost = self.netAdrInt + 1
        lastHost = self.broadcastInt - 1
        if self.prefixLen >= 31:
            firstHost -= 1
            lastHost += 1

        print(f"""Binary steps for {self.ipAdrCIDR} ({self.ipStr} {self.subnetMaskStr})

IP Address
{self.ipStr} -> {', '.join(self.octets)} -> {self.ipBin}

Subnet Mask
{self.subnetMaskStr} -> {', '.join(self.subnetMaskStr.split('.'))} -> {self.subnetMaskBin}

CIDR Prefix Length (Derived from the Binary Subnet Mask)
{self.subnetMaskBin} -> {self.subnetMaskBin.count('1')} 1s -> /{self.prefixLen}

CIDR Prefix Length -> Binary Subnet Mask
{self.ipAdrCIDR} -> /{self.prefixLen} -> {self.subnetMaskBin.replace('0','').rstrip(' ')}{' -> ' + self.subnetMaskBin if '0' in self.subnetMaskBin else ''}

Host Mask
Subnet mask:                      {self.subnetMaskBin}
Host mask (inverted subnet mask): {self.hostmaskBin}

Network Address
     IP address:   {self.ipBin}
    Subnet mask: & {self.subnetMaskBin}
                   -----------------------------------
Network address:   {self.netAdrBin}

Broadcast Address
        Host mask:   {self.hostmaskBin}
  Network address: | {self.netAdrBin}
                     -----------------------------------
Broadcast address:   {self.broadcastBin}""")

        if self.prefixLen == 31:
            print(f"""
First Host Address
According to RFC 3021, a /31 point-to-point link treats the network address as the first host address and the broadcast address as the last host address.
        Network address: {self.netAdrBin}
     First Host Address: {IPv4Address._space_out_binary_string(format(firstHost, '032b'))}

Last Host Address
Broadcast address: {self.broadcastBin}
Last host address: {IPv4Address._space_out_binary_string(format(lastHost, '032b'))}""")
        elif self.prefixLen == 32:
            print(f"""
First Host Address
According to RFC 4632, a /32 host route represents a single IPv4 address.
        IP Address: {self.ipBin}
First Host Address: {IPv4Address._space_out_binary_string(format(firstHost, '032b'))}

Last Host Address
       IP Address: {self.ipBin}
Last Host Address:  {IPv4Address._space_out_binary_string(format(lastHost, '032b'))}""")
        else:
            print(f"""
First Host Address
   Network address:   {self.netAdrBin}
                    + 00000000 00000000 00000000 00000001
                      -----------------------------------
First host address:   {IPv4Address._space_out_binary_string(format(firstHost, '032b'))}

Last Host Address
Broadcast address:   {self.broadcastBin}
                   - 00000000 00000000 00000000 00000001
                     -----------------------------------
Last host address:   {IPv4Address._space_out_binary_string(format(lastHost, '032b'))}""")

        print(f"""
Total Addresses
Broadcast address:   {self.broadcastBin}
  Network address: - {self.netAdrBin}
                     -----------------------------------
                     {IPv4Address._space_out_binary_string(format(self.broadcastInt - self.netAdrInt, '032b'))}
            Add 1: + 00000000 00000000 00000000 00000001
                     -----------------------------------
  Total addresses: {(IPv4Address._space_out_binary_string(format(self.broadcastInt - self.netAdrInt + 1, '032b'))).rjust(37)}

IP Address (CIDR Notation)
{self.ipAdrCIDR}

Subnet Mask
{self.subnetMaskBin} -> {self.subnetMaskStr}

Host Mask
{self.hostmaskBin} -> {self.hostmaskStr}

Network Address
{IPv4Address._space_out_binary_string(format(self.ipInt & self.subnetMaskInt, '032b'))} -> {self.netAdrStr}

Broadcast Address
{IPv4Address._space_out_binary_string(format(self.subnetMaskInt ^ IPv4Address.ALL_ONES | self.netAdrInt, '032b'))} -> {self.broadcastStr}

First Host Address
{IPv4Address._space_out_binary_string(format(firstHost, '032b'))} -> {self.firstHost}

Last Host Address
{IPv4Address._space_out_binary_string(format(lastHost, '032b'))} -> {self.lastHost}

Total Addresses
{IPv4Address._space_out_binary_string(format(self.broadcastInt - self.netAdrInt + 1, '032b'))} -> {self.totalAddresses:,d}""")

        if self.prefixLen >= 31:
            print(f"""
Usable Host Addresses
{self.totalAddresses:,d} = {self.usableHostAddresses:,d}""")
        else:
            print(f"""
Usable Host Addresses
{self.totalAddresses:,d} - 2 = {self.usableHostAddresses:,d}""")

    def _print_block_size_steps(self):
        groups, _, _ = self._calculate_prefix_length_groups()
        octetVal = int(self.subnetMaskStr.split(".")[self.interestingOctet - 1])
        networkInterestingOctetValue = int(self.netAdrStr.split(".")[self.interestingOctet - 1])
        if self.interestingOctet == 4:
            message1 = f"No octets to the right -> {self.netAdrStr}"
            message2 = f"No octets to the right -> {self.broadcastStr}"
        else:
            message1 = f"Right of octet {self.interestingOctet} set to 0 -> {self.netAdrStr}"
            message2 = f"Right of octet {self.interestingOctet} set to 255 -> {self.broadcastStr}"

        print(f"""
Block Size Steps for {self.ipAdrCIDR}

Block Size
{self.subnetMaskStr} -> interesting octet {self.interestingOctet}'s value = {octetVal} -> block size = 256 - {octetVal} = {256 - octetVal}
{self.ipAdrCIDR} -> {self.prefixLen} -> /{', /'.join(groups)} -> /{groups[self.interestingOctet - 1]} (interesting octet = {self.interestingOctet}) -> 8 - {groups[self.interestingOctet - 1]} = {8 - int(groups[self.interestingOctet - 1])} host bits -> block size = 2^{1 if self.prefixLen == 32 else 8 - self.prefixLen % 8} = {self.blockSize}

Subnet Mask/CIDR Prefix Length Lookup Table
128=1, 192=2, 224=3, 240=4, 248=5, 252=6, 254=7, 255=8

CIDR Prefix Length -> Subnet Mask
{self.ipAdrCIDR} -> /{self.prefixLen} -> /{', /'.join(groups)} -> {', '.join(self.subnetMaskStr.split('.'))} -> {self.subnetMaskStr}

Subnet Mask to CIDR Prefix Length
{self.subnetMaskStr} -> {', '.join(self.subnetMaskStr.split('.'))} -> {' + '.join(groups)} = {sum(int(i) for i in groups)} -> /{self.prefixLen}

Host Mask
   All ones:   255.255.255.255
Subnet mask: - {self.subnetMaskStr}
               ---------------
  Host mask:   {self.hostmaskStr}

Network Address
Interesting octet {self.interestingOctet} = {self.interestingOctetVal}, block size = {self.blockSize}
{self.interestingOctetVal} // {self.blockSize} * {self.blockSize} -> {self.interestingOctetVal // self.blockSize * self.blockSize}
{message1}

Broadcast Address
Interesting octet {self.interestingOctet} = {networkInterestingOctetValue}, block size = {self.blockSize}
{networkInterestingOctetValue} + {self.blockSize} - 1 -> {networkInterestingOctetValue + self.blockSize - 1}
{message2}""")

        if self.prefixLen >= 31:
            print(f"""
First Host Address
{self.netAdrStr} = {self.firstHost}

Last Host Address
{self.broadcastStr} = {self.lastHost}""")
        else:
            print(f"""
First Host Address
{self.netAdrStr} + 1 -> {self.firstHost}

Last Host Address
{self.broadcastStr} - 1 -> {self.lastHost}""")

        print(f"""
Total Addresses
{self.ipAdrCIDR} -> {self.prefixLen} -> 32 - {self.prefixLen} = {32 - self.prefixLen} -> 2^{32 - self.prefixLen} = {2**(32 - self.prefixLen):,d} total addresses""")

        if self.prefixLen == 31:
            print(f"""
Usable Host Addresses
{self.totalAddresses:,d} = {self.usableHostAddresses:,d}""")
        else:
            print(f"""
Usable Host Addresses
{self.totalAddresses:,d} - 2 = {self.usableHostAddresses:,d}""")

    def _explain_how_to_calculate(self):
        self._calculate_block_size_and_interesting_octet()
        self._calculate_octet_portions()

        if self.prefixLen == 32:
            print("""Per RFC 4632, a /32 is a host route.

A host route represents a single IP address, not a range. That means:
- Network address = the IP address itself
- There is no meaningful broadcast address since a /32 does not support broadcasting
- There are no additional host addresses

Since the subnet contains only one address, additional subnet calculations are unnecessary. However, the underlying binary rules still apply mathematically, as shown below. Because a /32 contains no host bits, standard block size subnetting methods cannot derive additional subnet information.
""")

        elif self.prefixLen == 31:
            print("""Per RFC 3021, a /31 is a point-to-point link.

A /31 network contains exactly 2 IP addresses. Unlike most subnets:
- Both addresses are usable
- Traditional network and broadcast addresses are not used

This subnet type is commonly used for point-to-point links between network devices.

Because of this behavior, some standard subnetting calculations do not apply.
""")

        print("""There are two primary methods for calculating subnetting information from an IPv4 address using either a subnet mask or a CIDR prefix length:

1. Binary Method
- Converts the IPv4 address into binary (1s and 0s)
- Makes the network and host portions fully visible
- Slower than the block size method, but highly reliable and useful for learning

2. Block Size Method
- Uses predictable decimal subnet increments instead of binary calculations
- Faster once common subnet increments are memorized
- Commonly used in operational environments and certification exams

Both methods produce the same subnetting results:
- Subnet mask and prefix length
- Host mask
- Network address
- Broadcast address
- First and last usable host addresses
- Total number of addresses and usable host addresses

The following sections demonstrate both methods step-by-step so the calculation process and resulting values can be compared directly.""")

        self._explain_binary_steps()

        if self.prefixLen != 32:
            self._explain_block_method_steps()
        else:
            print("\nSince a /32 host route has no host bits, there is no interesting octet. As a result, standard block size subnetting methods cannot derive additional subnet information, and the block size section is skipped.")

    def _explain_binary_steps(self):
        print(f"""

+{'=' * len(f'--- Binary Method for {self.ipAdrCIDR} ---')}+
|--- Binary Method for {self.ipAdrCIDR} ---|
+{'=' * len(f'--- Binary Method for {self.ipAdrCIDR} ---')}+

""")

        # Step 1: Convert the IPv4 address to binary
        self._show_binary_conversion_methods()

        # Step 2: Subnet Mask
        self._show_mask_to_binary()

        # Step 3: Host Mask
        self._show_hostmask_to_binary()

        # Step 4: Network address
        self._show_network_address_calc()

        # Step 5: Broadcast Address
        self._show_broadcast_calc()

        # Step 6: First and Last Usable Host Addresses
        self._show_first_last_host_calc()

        # Step 7: Total Addresses and Total Usable Host Addresses
        self._show_calc_total_addresses()

        # Step 8: Convert binary addresses to dotted-decimal notation
        self._show_binary_to_dotted_decimal_notation()

    def _show_binary_conversion_methods(self):
        print(f"""Step 1: Convert the IPv4 address {self.ipStr} to binary by separating it into octets.

First you need to split the IP address into its four octets: {self.ipStr} -> {', '.join(self.octets)}
Next, convert each octet to binary. There are two primary methods:
1. Subtract powers of 2
2. Repeated division by 2""")

        # Method 1: Subtract powers of 2
        self._show_method_subtract_powers()

        # Method 2: Repeated Division by 2
        self._show_method_repeated_division()

    def _show_method_subtract_powers(self):
        print("""
Method 1: Subtract Powers of 2

1.1.1 Write the decimal values (base 10) for each power of 2 because IPv4 octets are represented in decimal notation.
2^7  2^6  2^5  2^4  2^3  2^2  2^1  2^0
128  64   32   16   8    4    2    1

1.1.2 For each octet, subtract the largest possible power of 2 at each step:
""")
        bins = []
        for octetNum, i in enumerate(self.octets):
            i = int(i)

            binStr = ""
            print(f"Octet {octetNum + 1} = {i}")
            for j in reversed(range(8)):
                message = " then continue to the next power of 2" if j > 0 else ''
                j = 2**j
                if i >= j:
                    binStr += "1"
                    print(f"Since {str(i).rjust(3)} >= {str(j).ljust(3)}, add a 1 to the binary number ({binStr}){' ' * (8-len(binStr))} {(f'and subtract {j} from {i} ({i} - {j} = {i - j})').ljust(43)}{message}")
                    i -= j
                else:
                    binStr += "0"
                    print(f"Since {str(i).rjust(3)} <  {str(j).ljust(3)}, add a 0 to the binary number ({binStr}){' ' * (8-len(binStr))} {' ' * 43}{message}")

            bins.append(binStr)
            print("\nResult:")
            for j in binStr:
                print(j + "    ", end="")

            print("""
2^7  2^6  2^5  2^4  2^3  2^2  2^1  2^0
128  64   32   16   8    4    2    1
""")

        print(f"1.1.3 Combine the binary octets in the original IPv4 address order:\n{' '.join(bins)} == {self.ipStr}")
        # Verify the result using the internal calculation method
        assert " ".join(bins) == self.ipBin

    def _show_method_repeated_division(self):
        print("\nMethod 2: Repeated Division by 2\n\n1.2.1 Divide each octet by 2 repeatedly until the quotient equals 0 and record each remainder.")

        remainders = []
        for i in self.octets:
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

        print(f"\n1.2.2 Reverse the recorded remainders and write them from left to right to form the binary number. Add leading 0s as necessary until the value contains 8 bits.")

        bins = []
        for j, i in enumerate(self.octets):
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

        print(f"\n1.2.3 Combine the binary octets in the original IPv4 address order:\n{' '.join(bins)} == {self.ipStr}")
        # Verify the result using the internal calculation method
        assert " ".join(bins) == self.ipBin

    def _show_mask_to_binary(self):
        print(f"""
Step 2: Convert the subnet mask to binary.

If the subnet mask is already in dotted-decimal notation ({self.subnetMaskStr}), repeat the binary conversion process from step 1. The following example uses a condensed version of Method 1:

Subtract Powers of 2 (Condensed Form)
""")
        octets = self.subnetMaskStr.split(".")
        bins = []
        for octetNum, i in enumerate(octets):
            subtraction = i
            print(f"Octet {octetNum + 1} = {i}")
            binStr = ""

            i = int(i)
            for j in reversed(range(8)):
                j = 2**j
                if i >= j:
                    binStr += "1"
                    subtraction += f" - {j}"
                    i -= j
                else:
                    binStr += "0"

            bins.append(binStr)
            print(f"{subtraction} = 0 remaining")
            print("\nResult:")
            for j in binStr:
                print(j + "    ", end="")

            print("""
2^7  2^6  2^5  2^4  2^3  2^2  2^1  2^0
128  64   32   16   8    4    2    1
""")

        print(f"""Now combine the binary octets in the original IPv4 address order:
{' '.join(bins)} == {self.subnetMaskStr}

To calculate the CIDR prefix length from the binary subnet mask, count the number of 1 bits.
{' '.join(bins)} -> {' '.join(bins).count('1')} 1s -> /{' '.join(bins).count('1')}

If the IPv4 address is written in CIDR notation ({self.ipAdrCIDR}), write {self.prefixLen} consecutive '1' bits followed by {32 - self.prefixLen} consecutive '0' bits (32 - {self.prefixLen} = {32 - self.prefixLen}).""")

        subnetMask = '1' * self.prefixLen + '0' * (32 - self.prefixLen)
        print(IPv4Address._space_out_binary_string(subnetMask))

        assert ' '.join(bins) == self.subnetMaskBin
        assert ' '.join(bins).count('1') == self.prefixLen
        assert IPv4Address._space_out_binary_string(subnetMask) == self.subnetMaskBin

    def _show_hostmask_to_binary(self):
        print("\nStep 3: Calculate the host mask in binary from the subnet mask.")

        print(f"""
The host mask is the inverse of the subnet mask and identifies the bits available for host addresses within the subnet. It identifies which bits are allocated to the host portion of the address. The host mask is also called the inverse subnet mask or wildcard mask.

To calculate the host mask, invert the subnet mask bits by changing each 1 to 0 and each 0 to 1:
Subnet mask: {self.subnetMaskBin}
Host mask:   {IPv4Address._space_out_binary_string(format(self.subnetMaskInt ^ IPv4Address.ALL_ONES, '032b'))}

If the IPv4 address is already written in CIDR notation ({self.ipAdrCIDR}), the host mask can be written directly from the prefix length without first converting the subnet mask to binary. Using the prefix length of {self.prefixLen}, write {self.prefixLen} '0's and {32 - self.prefixLen} '1's (32 - {self.prefixLen} = {32 - self.prefixLen}):""")

        hostmask = '0' * self.prefixLen + '1' * (32 - self.prefixLen)
        invertedSubnetMaskRaw = IPv4Address._space_out_binary_string(format(~ self.subnetMaskInt, '032b'))
        print(f"Host mask:   {IPv4Address._space_out_binary_string(hostmask)}")

        print(f"""
Additional Information: computers can calculate the host mask two different ways to get the same result, but it is more complicated than the process of "flipping bits". This section provides general context for how computers perform these operations. The underlying bitwise operations are not explained in detail.

Computer Method 1. Bitwise NOT (~) the subnet mask and bitwise AND (&) the result with 32 1's (0xFFFFFFFF or 11111111 11111111 11111111 11111111)

A computer can calculate the host mask by bitwise NOT (~) the subnet mask and, if necessary, bitwise AND (&) the result with 32 1's to keep the number a positive 32-bit integer. This gives us the host mask:

Subnet mask: ~ {self.subnetMaskBin}
               -----------------------------------
{invertedSubnetMaskRaw.rjust(50)}

Note: Python treats this as a negative number because unsigned integers aren't supported. If it was an unsigned 32-bit integer, the result would be the host mask. As such, the next step is to bitwise AND (&) the result with 32 1's to change the number back to a 32-bit positive number:

{invertedSubnetMaskRaw.rjust(50)}
   All Ones: & 11111111 11111111 11111111 11111111
               -----------------------------------
  Host mask:   {IPv4Address._space_out_binary_string(format(~ self.subnetMaskInt & IPv4Address.ALL_ONES, '032b'))}

Computer Method 2. Bitwise XOR (^) the subnet mask and 32 1's (0xFFFFFFFF or 11111111 11111111 11111111 11111111)

Another method uses bitwise XOR (^) between the subnet mask and 32 consecutive 1 bits. This operation flips the bits of the subnet mask, resulting in the same host mask as the first method. This approach avoids signed versus unsigned integer handling concerns.

Subnet mask:   {self.subnetMaskBin}
   All Ones: ^ 11111111 11111111 11111111 11111111
               -----------------------------------
  Host mask:   {IPv4Address._space_out_binary_string(format(self.subnetMaskInt ^ IPv4Address.ALL_ONES, '032b'))}""")

        # Verify the result using the internal calculation method
        assert IPv4Address._space_out_binary_string(hostmask) == self.hostmaskBin

        # Verify that Python bitwise operations produce the expected result
        assert self.subnetMaskInt ^ IPv4Address.ALL_ONES == self.hostmaskInt
        assert ~ self.subnetMaskInt & IPv4Address.ALL_ONES == self.hostmaskInt

    def _show_network_address_calc(self):
        print(f"""
Step 4: Calculate the network address using the IP address and subnet mask.

This calculation uses the bitwise AND (&) operation. If both input bits equal 1, the resulting bit is set to 1. Otherwise, the resulting bit is set to 0.

     IP address:   {self.ipBin}
    Subnet mask: & {self.subnetMaskBin}
                   -----------------------------------
Network address:   {IPv4Address._space_out_binary_string(format(self.ipInt & self.subnetMaskInt, '032b'))}""")

        # Verify that the calculated binary network address matches the stored value
        assert IPv4Address._space_out_binary_string(format(self.ipInt & self.subnetMaskInt, '032b')) == self.netAdrBin

    def _show_broadcast_calc(self):
        print(f"""
Step 5: Calculate the broadcast address.

To calculate the broadcast address, apply bitwise OR (|) between the host mask and the network address. If both input bits equal 0, the resulting bit is set to 0. Otherwise, the resulting bit is set to 1.

        Host mask:   {IPv4Address._space_out_binary_string(format(self.subnetMaskInt ^ IPv4Address.ALL_ONES, '032b'))}
  Network address: | {self.netAdrBin}
                     -----------------------------------
Broadcast address:   {IPv4Address._space_out_binary_string(format(self.subnetMaskInt ^ IPv4Address.ALL_ONES | self.netAdrInt, '032b'))}""")

        # Verify the result using the internal calculation method
        assert self.subnetMaskInt ^ IPv4Address.ALL_ONES | self.netAdrInt == self.broadcastInt

    def _show_first_last_host_calc(self):
        print("\nStep 6: Calculate the first and last usable host addresses.")

        firstHost = self.netAdrInt + 1
        lastHost = self.broadcastInt - 1
        if self.prefixLen >= 31:
            firstHost -= 1
            lastHost += 1

        if self.prefixLen == 31:
            print(f"""
According to RFC 3021, a /31 point-to-point link treats the network address as the first usable host address and the broadcast address as the last usable host address.

   Network address: {self.netAdrBin}
First Host Address: {IPv4Address._space_out_binary_string(format(firstHost, '032b'))}

Broadcast address: {self.broadcastBin}
Last Host Address: {IPv4Address._space_out_binary_string(format(lastHost, '032b'))}""")
        elif self.prefixLen == 32:
            print(f"""
According to RFC 4632, a /32 host route contains only a single IPv4 address. As a result, the first and last usable host addresses are both equal to the IP address.

        IP Address: {self.ipBin}
First Host Address: {IPv4Address._space_out_binary_string(format(firstHost, '032b'))}
 Last Host Address: {IPv4Address._space_out_binary_string(format(lastHost, '032b'))}""")
        else:
            print(f"""
To calculate the first usable host address, add 1 to the network address.
   Network address:   {self.netAdrBin}
                    + 00000000 00000000 00000000 00000001
                      -----------------------------------
First host address:   {IPv4Address._space_out_binary_string(format(firstHost, '032b'))}

To calculate the last usable host address, subtract 1 from the broadcast address.
Broadcast address:   {self.broadcastBin}
                   - 00000000 00000000 00000000 00000001
                     -----------------------------------
Last host address:   {IPv4Address._space_out_binary_string(format(lastHost, '032b'))}""")

        # Verify the result against the internal calculation method.
        assert IPv4Address.ip_string_from_int(firstHost) == self.firstHost
        assert IPv4Address.ip_string_from_int(lastHost) == self.lastHost

    def _show_calc_total_addresses(self):
        print(f"""
Step 7: Calculate the total number of addresses and usable host addresses.

There are two primary methods for calculating the total number of addresses:
1. Subtract the network address from the broadcast address, then add 1 and convert the result to decimal.
2. Raise 2 to the power of the number of host bits.""")

        # Method 1: Subtract the network address from the broadcast address, add 1, then convert the binary result to decimal.
        self._method_subtract_and_add_to_get_total_addresses()

        # Method 2: Raise 2 to the host bits power.
        self._method_host_bits_exponent_total_addresses()

    def _method_subtract_and_add_to_get_total_addresses(self):
        print(f"""
Method 1: Subtract the network address from the broadcast address, add 1, then convert the binary result to decimal.

Broadcast address:   {self.broadcastBin}
  Network address: - {self.netAdrBin}
                     -----------------------------------
                     {IPv4Address._space_out_binary_string(format(self.broadcastInt - self.netAdrInt, '032b'))}
            Add 1: + 00000000 00000000 00000000 00000001
                     -----------------------------------
{str(IPv4Address._space_out_binary_string(format(self.broadcastInt - self.netAdrInt + 1, '032b'))).rjust(56)}""")

        # Verify the result using the internal calculation method
        assert self.broadcastInt - self.netAdrInt + 1 == self.totalAddresses

        usableHostAddresses = 1 if self.prefixLen == 32 else 2 if self.prefixLen == 31 else self.totalAddresses - 2
        assert usableHostAddresses == self.usableHostAddresses

        # Convert the binary value to decimal to determine the total number of addresses.
        self._show_binary_to_decimal()

        if self.prefixLen == 31:
            print(f"""Since this is a /31 point-to-point link, the number of usable host addresses equals the total number of addresses because both addresses are usable host addresses.

For {self.ipAdrCIDR}, since it has {self.totalAddresses:,d} total addresses, it has {self.totalAddresses:,d} usable host addresses.""")
        elif self.prefixLen == 32:
            print(f"""Since this is a /32 host route, the number of usable host addresses equals the total number of addresses because the subnet contains only a single IPv4 address.

For {self.ipAdrCIDR}, since it has {self.totalAddresses:,d} total addresses, it has {self.totalAddresses:,d} usable host addresses.""")
        else:
            print(f"""Once the total number of addresses is known, calculate the usable host addresses by subtracting 2 from the total number of addresses. The subtraction accounts for the network address and broadcast address, which are normally reserved and cannot be assigned to hosts. The exceptions are /31 and /32 networks, where the number of usable host addresses equals the total number of addresses.

For {self.ipAdrCIDR}, since it has {self.totalAddresses:,d} total addresses, it has {self.totalAddresses:,d} - 2 = {self.totalAddresses - 2:,d} usable host addresses.""")

        if self.prefixLen < 31:
            assert self.totalAddresses - 2 == self.usableHostAddresses
        elif self.prefixLen >= 31:
            assert self.totalAddresses == self.usableHostAddresses

    def _show_binary_to_decimal(self):
        print(f"""
Next, convert the binary value to decimal (base 10). Unlike IPv4 addresses, this value is not divided into four 8-bit octets, so the binary number may be much larger. However, the conversion process still follows the same binary-to-decimal rules.

The two primary methods for converting binary (base 2) to decimal (base 10) are:
1.1. Add Powers of 2
1.2. Multiply by 2 and Add""")

        binStr = format(self.totalAddresses, "032b")

        # Method 1.1: Add Powers of 2
        self._show_method_add_powers_of_2(binStr)

        # Method 1.2: Multiply By 2 and Add
        self._show_method_multiply_by_2_and_add(binStr)

    def _show_method_add_powers_of_2(self, binStr):
        totalAddressesBin = IPv4Address._space_out_binary_string(format(self.broadcastInt - self.netAdrInt + 1, '032b'))
        digits = len(totalAddressesBin.replace(" ","")) - 1
        print(f"""
Method 1.1: Add Powers of 2

This method is essentially the reverse of the "Subtract Powers of 2" method used earlier for converting decimal to binary. The big difference is that the total addresses could be 4,294,967,296 if the prefix length was 0. Small prefix lengths require much larger decimal equivalents for the powers of 2. Here is a cheat sheet:

/0             /1             /2             /3           /4           /5           /6          /7          /8          /9         /10        /11        /12        /13      /14      /15      /16     /17     /18     /19    /20    /21    /22    /23  /24  /25  /26  /27  /28  /29  /30  /31  /32
2^32           2^31           2^30           2^29         2^28         2^27         2^26        2^25        2^24        2^23       2^22       2^21       2^20       2^19     2^18     2^17     2^16    2^15    2^14    2^13   2^12   2^11   2^10   2^9  2^8  2^7  2^6  2^5  2^4  2^3  2^2  2^1  2^0
4,294,967,296  2,147,483,648  1,073,741,824  536,870,912  268,435,456  134,217,728  67,108,864  33,554,432  16,777,216  8,388,608  4,194,304  2,097,152  1,048,576  524,288  262,144  131,072  65,536  32,768  16,384  8,192  4,096  2,048  1,024  512  256  128  64   32   16   8    4    2    1

Add the decimal value associated with each power of 2 whenever the corresponding binary digit is 1. Skip the value whenever the binary digit is 0. Given the total addresses value in binary is:
{totalAddressesBin}
Including every 0 digit in the calculation produces the following expanded expression:""")

        toPrint = ""
        toPrint2 = ""
        num = 0
        for j in range(digits, -1, -1):
            toPrint += f"{binStr[digits - j]} * 2^{j} + "
            toPrint2 += f"{int(binStr[digits - j])* 2**j:,d} + "
            num += int(binStr[digits - j])* 2**j

        print(f"""{toPrint.rstrip(' +')} =

Which simplifies to:
{toPrint2.rstrip(' +')} = {num:,d}

A shorter approach is to include only the values associated with binary digits equal to 1:""")

        toPrint = ""
        toPrint2 = ""
        num2 = 0
        for j in range(digits, -1, -1):
            if binStr[digits - j] == "1":
                toPrint += f"{binStr[digits - j]} * 2^{j} + "
                toPrint2 += f"{int(binStr[digits - j])* 2**j:,d} + "
                num2 += int(binStr[digits - j])* 2**j

        if toPrint == "":
            print("Since all binary digits are 0, the decimal value is 0.")

        if toPrint2 != "":
            print(f"""{toPrint.rstrip(' +')} =

Which simplifies to:
{toPrint2.rstrip(' +')} = {num2:,d}""")

        assert num == num2 and num == self.totalAddresses

    def _method_host_bits_exponent_total_addresses(self):
        print(f"""
Method 2: Raise 2 to the power of the number of host bits.

To determine the number of host bits from the binary subnet mask, count the total number of 0 bits:
{self.subnetMaskBin}
# of 0s = {self.subnetMaskBin.count("0")}
host bits = {self.subnetMaskBin.count("0")}

Another method is to subtract the CIDR prefix length (/{self.prefixLen}) from 32.
32 - {self.prefixLen} = {32 - self.prefixLen}
host bits = {32 - self.prefixLen}

Raise 2 to the power of {32 - self.prefixLen} (the number of host bits) to calculate the total number of addresses:
2^{32 - self.prefixLen} = {2**(32 - self.prefixLen):,d}""")
        if self.totalAddresses > 512:
            print(f"""
The number of host bits can also be used to estimate the total number of addresses:

Total addresses = 2^{32 - self.prefixLen}

Break the exponent into groups of 10. Since 2^10 is approximately equal to 1000, this simplifies manual estimation.

Rewrite the exponent as:

2^{32 - self.prefixLen} = {'2^10 * ' * ((32 - self.prefixLen) // 10)}2^{(32 - self.prefixLen) % 10}

Replace each 2^10 with 1000, solve the remaining exponents, and multiply.

{'1000 * ' * ((32 - self.prefixLen) // 10)}{2**((32 - self.prefixLen) % 10)} = {1000**((32 - self.prefixLen) // 10) * 2**((32 - self.prefixLen) % 10):,d} total addresses

This produces a quick estimate that is slightly lower than the exact value but easier to calculate manually.

The block size section provides a more detailed explanation of this estimation method.""")

    def _show_method_multiply_by_2_and_add(self, binStr):
        binStr = IPv4Address._space_out_binary_string(binStr)
        oneIndex = binStr.index('1')

        print(f"""
Method 1.2: Multiply by 2 and Add

The previous method can become tedious when the prefix length is very small. This method avoids the need to write the decimal equivalents for every power of 2.

This method uses the following formula:

Start at the left-most digit, set the total to 0, then apply the formula:
total * 2 + value of current digit (a 1 or 0) = new total.
Move one digit to the right and repeat the process.

To reduce unnecessary calculations, locate the left-most 1 digit in the binary number. This digit becomes the starting total because:
0 (previous total) * 2 + 1 (current digit) = 1

{binStr}
{' ' * oneIndex}^
start = 1

Move one digit to the right, multiply the current total by 2, then add the current digit to the result. Repeat this process until all binary digits have been processed.

{'The remaining calculation steps are shown below:' if len(binStr) - oneIndex != 1 else 'There are no remaining digits, so the final value is 1.'}
""")

        num = 1
        for j in range(1, len(binStr) - oneIndex):
            index = oneIndex + j
            if binStr[index] == " ":
                continue

            print(f"{binStr}\n{' ' * index}^\n{num:,d} * 2 + {binStr[index]} = {num * 2 + int(binStr[index]):,d} total addresses\n")
            num = num * 2 + int(binStr[index])

        # Verify the result using the internal calculation method
        assert num == self.totalAddresses

    def _show_binary_to_dotted_decimal_notation(self):
        firstHost = IPv4Address._space_out_binary_string(format(IPv4Address.ip_int_from_string(self.firstHost), '032b'))
        lastHost = IPv4Address._space_out_binary_string(format(IPv4Address.ip_int_from_string(self.lastHost), '032b'))
        print(f"""
Step 8: Convert the binary addresses back to dotted-decimal notation. At this point, the following binary values and addresses are known:

      IPv4 Address: {self.ipStr}
       Subnet Mask: {self.subnetMaskBin} (or if started with a dotted-decimal address, then you already have it: {self.subnetMaskStr})
         Host Mask: {self.hostmaskBin}
   Network Address: {self.netAdrBin}
 Broadcast Address: {self.broadcastBin}
First Host Address: {firstHost}
 Last Host Address: {lastHost}

This process again uses the decimal equivalents for the powers of 2. Since each octet in dotted-decimal notation ranges from 0 to 255, only 8 bits are required per octet. This makes manual conversion practical and commonly used.

Note: The "Multiply by 2 and Add" method demonstrated earlier can also be used here. However, when working with octets, the following reference table often makes manual conversion easier and reduces repeated multiplication.

2^7  2^6  2^5  2^4  2^3  2^2  2^1  2^0
128  64   32   16   8    4    2    1

Using this table, add the decimal value wherever the binary digit is 1. Ignore positions where the binary digit is 0.
""")

        binaryData = [
            ("subnet mask", "Subnet mask", self.subnetMaskBin, self.subnetMaskStr),
            ("host mask", "Host mask", self.hostmaskBin, self.hostmaskStr),
            ("network address", "Network address", self.netAdrBin, self.netAdrStr),
            ("broadcast address", "Broadcast address", self.broadcastBin, self.broadcastStr),
        ]

        if self.prefixLen < 31:
            binaryData.append(("first host address", "First Host Address", firstHost, self.firstHost))
            binaryData.append(("last host address", "Last Host Address", lastHost, self.lastHost))

        for label1, label2, binStr, ipAdr in binaryData:
            print(f"The following steps convert the {label1} from binary to dotted-decimal notation ({binStr})")
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
                    print("Since all binary digits are 0, the decimal value is 0.")

                if toPrint2 != "":
                    print(f"{toPrint.rstrip(' +')} = ")

                    print("\nSimplified expression:")

                    print(f"{toPrint2.rstrip(' +')} = {num}")

                octets.append(str(num))

            print(f"\nFinally, combine the octets using periods to form the dotted-decimal value:\n{label2}: {'.'.join(octets)}\n")

            # Verify the result against the internal calculation method.
            assert ".".join(octets) == ipAdr

        print('\nThe following examples use the "Multiply by 2 and Add" method for each octet:\n')

        for label1, label2, binStr, ipAdr in binaryData:
            print(f'The following steps convert the {label1} using the "Multiply by 2 and Add" method ({binStr})')

            binOctets = binStr.split(" ")
            octets = []

            for octetNum, binStr in enumerate(binOctets):
                if "1" not in binStr:
                    print(f"\nOctet {octetNum + 1}\n{binStr}\nSince all binary digits are 0, the decimal value is 0.")
                    num = 0
                else:
                    num = 1
                    oneIndex = binStr.index("1")
                    print(f"\nOctet {octetNum + 1}\n{binStr}\n{' ' * oneIndex}^\nstarting value = 1")
                    for j in range(1, len(binStr) - oneIndex):
                        index = oneIndex + j
                        if binStr[index] == " ":
                            continue

                        print(f"\n{binStr}\n{' ' * index}^\n{num} * 2 + {binStr[index]} = {num * 2 + int(binStr[index])}")
                        num = num * 2 + int(binStr[index])

                print(f"Octet {octetNum + 1} = {num}")
                octets.append(str(num))

            print(f"\nFinally, combine the octets using periods to form the dotted-decimal value:\n{label2}: {'.'.join(octets)}")

            # Verify the result using the internal calculation method
            assert ".".join(octets) == ipAdr

        if self.prefixLen < 31:
            print(f"\nNote: Instead of converting from binary to determine the first and last usable host addresses, add 1 to the network address {self.netAdrStr} to calculate the first host address {self.firstHost}, and subtract 1 from the broadcast address {self.broadcastStr} to calculate the last host address {self.lastHost}.")

        elif self.prefixLen == 31:
            print(f"\nNote: Since the first usable host address is equal to the network address {self.netAdrStr} and the last usable host address is equal to the broadcast address {self.broadcastStr}, these calculations were skipped.")

    def _explain_block_method_steps(self):
        print(f"""

+{'=' * len(f'--- Block Size Method for {self.ipAdrCIDR} ---')}+
|--- Block Size Method for {self.ipAdrCIDR} ---|
+{'=' * len(f'--- Block Size Method for {self.ipAdrCIDR} ---')}+
""")

        print(f"""
Steps to calculate IPv4 subnetting information for {self.ipAdrCIDR} using the Block Size and Host Bits methods

There are two common non-binary methods for calculating subnetting information: the Block Size method and the Host Bits method. Both give the same results, but they approach the problem differently.

The Host Bits method counts the number of bits available for hosts, which determines the total number of addresses in the subnet. The Block Size method looks at how subnet ranges increment within an octet, making it easier to find network and broadcast boundaries.

Both methods can be used to determine key subnetting information, including total addresses, network and broadcast addresses, and usable host range.

An important concept used in both methods is the interesting octet, which is the first octet that contains host bits. If all octets contain only network bits and no host bits, the fourth octet is treated as the interesting octet. This is where subnet boundaries occur and where block size calculations are applied.

Focusing on the interesting octet allows the Host Bits method to align closely with the Block Size method while simplifying the calculations. For consistency, only the Block Size method will be used in the explanations.

For a /32 host route, subnetting calculations are unnecessary because the address represents a single host and contains no host bits.""")

        # Step 1: Calculate the block size
        self._show_block_size_calc()

        # Step 2: Convert CIDR prefix to subnet mask and vice versa
        self._show_cidr_to_mask_and_vice_versa()

        # Step 3: Host mask
        self._show_hostmask_calc_block_method()

        # Step 4: Calculate the network address for the IP address
        self._show_calculate_network_address()

        # Step 5: Broadcast Address
        self._show_broadcast_calc_block_method()

        # Step 6: First and Last Usable Host Addresses
        self._show_first_last_host_calc_block_method()

        # Step 7: Total Addresses and Total Usable Host Addresses
        self._show_calc_total_addresses_block_method()

    def _show_block_size_calc(self):
        print("""
Step 1: Calculate the block size.

The block size is the total number of IPv4 addresses in each subnet, including the network and broadcast addresses. The main advantage of this method is that it avoids binary conversion and allows subnet ranges to be identified quickly. The tradeoff is that it may require memorization, mental arithmetic, or estimation, which are limitations not present in the binary method.

Since each octet can hold 256 values (0 to 255 or 2^8 values for 8 bits), the subnet mask tells us how many of those are used for the network. The subnet mask or CIDR prefix length associated with the interesting octet determines how many values are allocated to each subnet block (block size).

There are two primary methods for calculating the block size:
1. Using the subnet mask (in dotted decimal notation)
2. Using the prefix length (from the CIDR address)""")

        # Method 1: Using subnet mask to calculate the block size
        self._show_method_subnet_mask_block_size()

        # Method 2: Using prefix length to calculate the block size
        self._show_method_prefix_length_block_size()

    def _show_method_subnet_mask_block_size(self):
        octetVal = ""
        interestingOctet = 0
        for k, j in enumerate(self.subnetMaskStr.split(".")):
            if j != "255":
                octetVal = j
                interestingOctet = k + 1
                break

        blockSize = 256 - int(octetVal)

        print(f"""
Method 1: Use the subnet mask to calculate the block size.

First, identify the interesting octet, which determines the subnet boundaries within the address. This is the first octet in the subnet mask that is not 255. In other words, this is the first octet that contains host bits.

Note: This method does not apply to the subnet mask 255.255.255.255 because it contains no host bits.

The following examples demonstrate this concept:

IP address = 10.1.2.3

Subnet mask = 128.0.0.0
Interesting octet = 1, value = 128

Subnet mask = 255.192.0.0
Interesting octet = 2, value = 192

Subnet mask = 255.255.224.0
Interesting octet = 3, value = 224

Subnet mask = 255.255.255.0
Interesting octet = 4, value = 0

Subnet mask = 255.255.255.240
Interesting octet = 4, value = 240

For {self.subnetMaskStr}, the interesting octet is octet {interestingOctet} with a value of {octetVal}.

Calculate the block size by subtracting the interesting octet value from 256:
256 - {octetVal} = {blockSize} = block size""")

        assert interestingOctet == self.interestingOctet
        assert blockSize == self.blockSize

    def _calculate_prefix_length_groups(self):
        groups = []
        num = self.prefixLen
        toPrint = str(num)
        interestingOctet = 1

        while num >= 8:
            groups.append("8")
            toPrint += f" - 8"
            num -= 8
            interestingOctet += 1

        if num > 0:
            groups.append(str(num))
            if toPrint != str(self.prefixLen):
                toPrint += f" = {num}"
        else:
            toPrint += " = 0"

        while len(groups) < 4:
            groups.append("0")

        if self.prefixLen == 32:
            interestingOctet = 4

        return groups, interestingOctet, toPrint

    def _show_method_prefix_length_block_size(self):
        print(f"""
Method 2: Using prefix length to calculate the block size.

The interesting octet concept also applies when using CIDR notation. When the prefix length is divided into groups of 8, the result aligns with the dotted-decimal subnet mask. Each /8 group represents a complete octet of network bits. The first group that is not /8 contains host bits and identifies the interesting octet. This also applies when the prefix length ends on an octet boundary, where the next group becomes /0.

To break a prefix length into groups of 8, repeatedly subtract 8 from the prefix length until the remainder is 7 or less. Each subtraction forms a new /8 group. The remaining value becomes the next group. If needed, add /0-sized groups to reach a total of four groups.

The first group that is not /8 contains the initial host bits and identifies the interesting octet. To determine the number of host bits, subtract the group's prefix length from 8. The block size is then calculated as 2^(host bits).

Note: This method does not apply to a /32 prefix, as it contains no host bits.

Here are examples of the process:

If the prefix is /7, then
7 -> /7, /0, /0, /0
Interesting octet: group 1 (/7) contains initial host bits -> interesting octet = 1
Host bits: 8 - 7 = 1
Block size: 2^hostBits = 2^1 = 2

If the prefix is /14, then
14 - 8 = 6 -> /8, /6, /0, /0
Interesting octet: group 2 (/6) contains initial host bits -> interesting octet = 2
Host bits: 8 - 6 = 2
Block size: 2^hostBits = 2^2 = 4

If the prefix is /18, then
18 - 8 - 8 = 2 -> /8, /8, /2, /0
Interesting octet: group 3 (/2) contains initial host bits -> interesting octet = 3
Host bits: 8 - 2 = 6
Block size: 2^hostBits = 2^6 = 64

If the prefix is /24, then
24 - 8 - 8 - 8 = 0 -> /8, /8, /8, /0
Interesting octet: group 4 (/0) contains initial host bits -> interesting octet = 4
Host bits: 8 - 0 = 8
Block size: 2^hostBits = 2^8 = 256

If the prefix is /29, then
29 - 8 - 8 - 8 = 5 -> /8, /8, /8, /5
Interesting octet: group 4 (/5) contains initial host bits -> interesting octet = 4
Host bits: 8 - 5 = 3
Block size: 2^hostBits = 2^3 = 8

For {self.ipAdrCIDR}, the prefix is {self.prefixLen}.""")

        groups, interestingOctet, toPrint = self._calculate_prefix_length_groups()

        hostBits = 8 - int(groups[interestingOctet - 1])

        print(f"""{toPrint} -> /{', /'.join(groups)}
Interesting octet: group {interestingOctet} (/{groups[interestingOctet - 1]}) contains the initial host bits -> interesting octet = {interestingOctet}
Host bits: 8 - {groups[interestingOctet - 1]} = {hostBits}
Block size: 2^hostBits = 2^{hostBits} = {2**hostBits}

Note: If familiar with integer division and modular arithmetic, the interesting octet and block size can be calculated more directly:
Interesting octet = (prefix_length // 8) + 1
Block size = 2^(8 - prefix_length % 8)

The grouping method is used as the primary explanation because it is generally easier to understand. The formulas are included to demonstrate another way to reach the same results. In the edge case of a /32 prefix, these formulas produce invalid results because there are no host bits.""")

        assert interestingOctet == self.interestingOctet
        assert 2**hostBits == self.blockSize
        assert hostBits == 8 - self.prefixLen % 8

    def _show_cidr_to_mask_and_vice_versa(self):
        bitsToDecimal = {
            "0": "0",
            "1": "128",
            "2": "192",
            "3": "224",
            "4": "240",
            "5": "248",
            "6": "252",
            "7": "254",
            "8": "255",
        }

        decimalToBits = {
            "0": "0",
            "128": "1",
            "192": "2",
            "224": "3",
            "240": "4",
            "248": "5",
            "252": "6",
            "254": "7",
            "255": "8",
        }

        decimalGroups = self.subnetMaskStr.split('.')
        prefixGroups, _, toPrint = self._calculate_prefix_length_groups()

        print(f"""
Step 2: Convert CIDR prefix length to subnet mask and vice versa

Some block size calculations require the subnet mask in dotted-decimal notation. Representing the subnet mask as a prefix length can also be useful because it enables additional calculation methods, although it is not strictly required for the block size method.

To convert between CIDR prefix length and subnet mask, a reference table is useful. In the binary method, this was unnecessary because the calculations were performed directly in binary before deriving the missing value. In the block size method, you often need the subnet mask and may want the prefix length early on, so having both values available beforehand is helpful.

Subnet Mask / CIDR Prefix Length Lookup Table
Decimal Value (Octet) -> Number of Leading 1 Bits (Prefix Length)
  0 -> 0
128 -> 1
192 -> 2
224 -> 3
240 -> 4
248 -> 5
252 -> 6
254 -> 7
255 -> 8

For reference, each value corresponds to the number of leading '1' bits in the octet's binary representation:
  0 = 00000000 -> 0 ones
128 = 10000000 -> 1 one
192 = 11000000 -> 2 ones
224 = 11100000 -> 3 ones
240 = 11110000 -> 4 ones
248 = 11111000 -> 5 ones
252 = 11111100 -> 6 ones
254 = 11111110 -> 7 ones
255 = 11111111 -> 8 ones

Using the reference table, convert the CIDR prefix length to the subnet mask in dotted-decimal format.

To convert a prefix length to dotted-decimal format, split it up into groups of 8 by repeatedly subtracting 8 from the prefix length until the remainder is 7 or less. Each subtraction forms a new /8 group. The remaining value becomes the next group. If needed, add /0-sized groups to reach a total of four groups.

For {self.ipAdrCIDR}, the prefix length is {self.prefixLen}.

{toPrint}
Groups = /{', /'.join(prefixGroups)}

Next, convert each value in the group using the Subnet Mask/CIDR Prefix Length Lookup Table:""")
        for i in prefixGroups:
            print(f"{i} -> {bitsToDecimal[i]}")

        print(f"""Finally, combine the values in order to form the subnet mask:

Subnet Mask: {'.'.join(bitsToDecimal[i] for i in prefixGroups)}

Converting the subnet mask back to the prefix length follows the same process in reverse. Take the subnet mask {self.subnetMaskStr} and split it into four octets:

{', '.join(self.subnetMaskStr.split('.'))}

Use the lookup table to convert each octet to its corresponding prefix length:""")

        for i in decimalGroups:
            print(f"{i} -> {decimalToBits[i]}")

        print(f"""
Add the values together to get the prefix length:

Prefix Length: {' + '.join(decimalToBits[i] for i in decimalGroups)} = {sum(int(decimalToBits[i]) for i in decimalGroups)}""")

        assert ".".join(bitsToDecimal[i] for i in prefixGroups) == self.subnetMaskStr
        assert sum(int(decimalToBits[i]) for i in decimalGroups) == self.prefixLen

    def _show_hostmask_calc_block_method(self):
        print("""
Step 3: Calculate the host mask

Since the host mask is the inverse of the subnet mask, there are two methods for calculating it:
1. Using the subnet mask in dotted decimal notation
2. Using the prefix length from the CIDR address""")

        # Method 1: Using subnet mask to calculate the host mask
        self._show_method_subnet_mask_host_mask()

        # Method 2: Using prefix length to calculate the host mask
        self._show_method_prefix_length_host_mask()

    def _show_method_subnet_mask_host_mask(self):
        octets = self.subnetMaskStr.split(".")
        for i in range(len(octets)):
            octets[i] = str(255 - int(octets[i]))

        print(f"""
Method 1: Using the subnet mask to calculate the host mask.

Like the binary method, the host mask is calculated by inverting the subnet mask. This is done by subtracting the subnet mask {self.subnetMaskStr} from 255.255.255.255, which represents 32 binary 1s in dotted-decimal notation.

   All ones:   255.255.255.255
Subnet mask: - {self.subnetMaskStr}
               ---------------
  Host mask:   {'.'.join(octets)}""")

        assert ".".join(octets) == self.hostmaskStr

    def _show_method_prefix_length_host_mask(self):
        hostMask = ""
        groups = [str((32 - self.prefixLen) % 8)]

        if groups[0] == "0":
            del groups[0]

        for _ in range((32 - self.prefixLen) // 8):
            groups.append("8")

        while len(groups) < 4:
            groups.insert(0, "0")

        print(f"""
Method 2: Using the prefix length to calculate the host mask.

The host mask can also be calculated from the prefix length ({self.prefixLen}) in the CIDR address ({self.ipAdrCIDR}) using the following process:

First, get the number of host bits by subtracting the prefix length from 32:
32 - {self.prefixLen} = {32 - self.prefixLen}

Next, divide the host bits into groups of 8. A key difference is that the groups start on the right, and new ones are added to the left. This is done by repeatedly subtracting 8 from the host bit count until the remainder is 7 or less. Each subtraction forms a new /8 group. The remaining value becomes the next group. If needed, add /0-sized groups to reach a total of four groups.

/{', /'.join(groups)}

Then, calculate the octet values using this formula:
Octet value = 2^(number of host bits in that octet) - 1""")

        for j, i in enumerate(groups):
            i = int(i.lstrip('/'))
            print(f"""
For octet {4 - len(groups) + j + 1}, the chunk has {i} bit{'s' if i != 1 else ''}, so:
2^{i} - 1 = {2**i} - 1 = {2**i - 1}
Octet {4 - len(groups) + j + 1} = {2**i - 1}""")
            hostMask += f"{2**i - 1}."

        hostMask = hostMask.rstrip(".")
        print(f"""
Finally, combine the octet values into a dotted-decimal address:
Host mask = {hostMask}""")

        assert hostMask == self.hostmaskStr

    def _show_calculate_network_address(self):
        print(f"""
Step 4: Calculate the network address that contains the IP address {self.ipAdrCIDR}

The network address is the nearest multiple of the block size that does not exceed the IP address value in the interesting octet. There are three ways to calculate it:
1. Enumerate subnet ranges until the correct subnet is found. This method works well with large block sizes.
2. Use integer division on the interesting octet. This method works well for any block size.
3. Use modular arithmetic on the interesting octet. This method works well for small to medium block sizes.
""")

        # Method 1: Compute subnets until desired network address found
        self._method_calculate_subnets_until_network_address_found()

        # Method 2: Compute network address using integer division
        self._method_find_network_address_from_integer_division()

        # Method 3: Compute network address using modular arithmetic
        self._method_find_network_address_from_modular_arithmetic()

    def _method_calculate_subnets_until_network_address_found(self):
        toBeZeroedOctets = ".".join(["x"] * len(self.networkOctets) + [str(self.interestingOctetVal)] + self.hostOctets)
        zeroedIP = ".".join(self.networkOctets + ["0"] + self.zeroedHostOctets)

        print(f"""Method 1: Compute subnets until the desired network is found.

This iterative method is most practical for large block sizes. It may perform unnecessary subnet calculations, but it avoids binary conversion and remains straightforward to follow.

The process begins with the lowest possible network value by setting the interesting octet and all octets to the right to 0. The network value is then repeatedly incremented by the block size until the network containing the current IP address is found.

The IP address {self.ipAdrCIDR} has a block size of {self.blockSize}, and the interesting octet {self.interestingOctet}'s value is {self.interestingOctetVal}. The interesting octet and all octets to the right are shown as {toBeZeroedOctets}. Next, set all of these to 0.

{self.ipStr} -> {zeroedIP}

Next, repeatedly add the block size to the interesting octet value. Stop when the current value is less than or equal to the target value and the next increment would exceed it.

IP Address: {self.ipStr}, Interesting Octet: Octet {self.interestingOctet}, Target Octet Value: {self.interestingOctetVal}, Block Size: {self.blockSize}
""")

        num = 0
        subnetAdr = zeroedIP

        header = f"{'Potential Network':<17}  {'Current Value':<13}  {'Is <= ' + str(self.interestingOctetVal) + '?':<10}  {'Value + Block':<13}  {'Is > ' + str(self.interestingOctetVal) + '?':<9}"
        print(header)
        print("-" * len(header))

        toPrintLines = [f"{subnetAdr:<17}  {num:<13}  {'yes' if num <= self.interestingOctetVal else 'no':<10}  {num + self.blockSize:<13}  {'yes' if num + self.blockSize > self.interestingOctetVal else 'no':<9}"]

        while num < self.interestingOctetVal and num + self.blockSize <= self.interestingOctetVal:
            num += self.blockSize

            subnetAdr = ".".join(self.networkOctets + [str(num)] + self.zeroedHostOctets)

            toPrintLines.append(f"{subnetAdr:<17}  {num:<13}  {'yes' if num <= self.interestingOctetVal else 'no':<10}  {num + self.blockSize:<13}  {'yes' if num + self.blockSize > self.interestingOctetVal else 'no':<9}")

        if len(toPrintLines) > 10:
            for l in toPrintLines[:5]:
                print(l)
            print("...")
            for l in toPrintLines[-5:]:
                print(l)
        else:
            for l in toPrintLines:
                print(l)

        print(f"\nSince {num} is less than or equal to {self.interestingOctetVal}, and {num + self.blockSize} exceeds {self.interestingOctetVal}, the network address is {subnetAdr}.")

        if self.prefixLen % 8 == 0: # /0, /8, /16, /24
            print("\nNote: Since the prefix falls on an octet boundary (/0, /8, /16, /24), the network address can be determined directly by setting the interesting octet and all octets to the right to 0. A block size of 256 means the interesting octet can only have the value 0. Any further increment would carry into the octet to the left.")

        assert subnetAdr == self.netAdrStr

    def _method_find_network_address_from_integer_division(self):
        networkValue = self.interestingOctetVal // self.blockSize * self.blockSize
        intermediate = ".".join(self.networkOctets + [str(networkValue)] + self.hostOctets)
        subnetAdr = ".".join(self.networkOctets + [str(networkValue)] + self.zeroedHostOctets)

        if len(self.hostOctets) == 0:
            message = "Since there are no octets to the right of the interesting octet, the process is complete."
        else:
            message = f"Next, set any octets to the right of the interesting octet to 0 to obtain the network address:\n{intermediate} -> {subnetAdr}"

        print(f"""
Method 2: Compute the network address using integer division.

This method works efficiently for any block size. Integer division ignores the remainder, which allows direct computation of the network address. The process divides the interesting octet value by the block size to determine how many complete blocks fit within the value. The remainder is discarded, and the quotient is multiplied by the block size to obtain the new value for the interesting octet.

The IP address {self.ipAdrCIDR} has a block size of {self.blockSize} and interesting octet {self.interestingOctet}'s value is {self.interestingOctetVal}.
{self.interestingOctetVal} // {self.blockSize} * {self.blockSize} -> {self.interestingOctetVal // self.blockSize} * {self.blockSize} = {networkValue}

Set the new value in the interesting octet:
{self.ipStr} -> {intermediate}

{message}

Network address: {subnetAdr}
""")

        assert subnetAdr == self.netAdrStr

    def _method_find_network_address_from_modular_arithmetic(self):
        networkValue = self.interestingOctetVal - (self.interestingOctetVal % self.blockSize)
        intermediate = '.'.join(self.networkOctets + [str(networkValue)] + self.hostOctets)
        subnetAdr = ".".join(self.networkOctets + [str(networkValue)] + self.zeroedHostOctets)

        if len(self.hostOctets) == 0:
            message = "Since there are no octets to the right of the interesting octet, the process is complete."
        else:
            message = f"Next, set any octets to the right of the interesting octet to 0 to obtain the network address:\n{intermediate} -> {subnetAdr}"

        print(f"""
Method 3: Compute the network address using modular arithmetic.

This method is practical for small to medium block sizes. Like method 2, this method directly computes the network address by subtracting the remainder produced when dividing the interesting octet value by the block size. This rounds the value down to the nearest block boundary.

The IP address {self.ipAdrCIDR} has a block size of {self.blockSize} and interesting octet {self.interestingOctet}'s value is {self.interestingOctetVal}.
{self.interestingOctetVal} - ({self.interestingOctetVal} % {self.blockSize}) -> {self.interestingOctetVal} - {self.interestingOctetVal % self.blockSize} = {networkValue}

The new value is set in the interesting octet:
{self.ipStr} -> {intermediate}

{message}

Network address: {subnetAdr}
""")

        assert subnetAdr == self.netAdrStr

    def _show_broadcast_calc_block_method(self):
        octets = self.netAdrStr.split('.')

        networkOctets = []
        hostOctets = []
        maxedHostOctets = []
        interestingOctetVal = octets[self.interestingOctet - 1]

        for i in range(self.interestingOctet - 1):
            networkOctets.append(octets[i])

        for i in range(self.interestingOctet, 4):
            hostOctets.append(octets[i])
            maxedHostOctets.append("255")

        broadcastValue = str(int(interestingOctetVal) + self.blockSize - 1)
        intermediate = ".".join(networkOctets + [broadcastValue] + hostOctets)
        broadcastAdr = ".".join(networkOctets + [broadcastValue] + maxedHostOctets)

        if len(self.hostOctets) == 0:
            message = "Since there are no octets to the right of the interesting octet, the process is complete."
        else:
            message = f"Next, set any octets to the right of the interesting octet to 255 to obtain the broadcast address:\n{intermediate} -> {broadcastAdr}"

        print(f"""
Step 5: Calculate the broadcast address

The process adds the block size to the interesting octet value to determine the next subnet boundary. Next, subtract 1 to obtain the broadcast value for the interesting octet.

The network address {self.netAdrCIDR} has a block size of {self.blockSize} and interesting octet {self.interestingOctet}'s value is {interestingOctetVal}.
{interestingOctetVal} + {self.blockSize} - 1 -> {int(interestingOctetVal) + self.blockSize} - 1 = {broadcastValue}

The new value is set in the interesting octet:
{self.netAdrStr} -> {intermediate}

{message}

Broadcast address: {broadcastAdr}
""")

        assert broadcastAdr == self.broadcastStr

    def _show_first_last_host_calc_block_method(self):
        print("\nStep 6: Calculate the first and last usable host addresses")

        if self.prefixLen >= 31:
            firstHost = self.netAdrStr
            lastHost = self.broadcastStr
        else:
            firstHost = self.netAdrStr.split('.')
            firstHost = ".".join(firstHost[:3] + [str(int(firstHost[3]) + 1)])
            lastHost = self.broadcastStr.split('.')
            lastHost = ".".join(lastHost[:3] + [str(int(lastHost[3]) - 1)])

        if self.prefixLen == 31:
            print(f"""
According to RFC 3021, a /31 network is treated as a point-to-point link. In this special case, both addresses in the subnet are considered usable host addresses. Traditional network and broadcast address rules do not apply because point-to-point links only require two endpoints.

The lower address in the subnet is treated as the first host address, while the higher address is treated as the last host address.

 Network Address / First Host Address: {firstHost}
Broadcast Address / Last Host Address: {lastHost}""")

        elif self.prefixLen == 32:
            print(f"""
According to RFC 4632, a /32 prefix represents a host route containing exactly one IP address. Because the subnet size only permits a single address, the network address, first host address, last host address, and broadcast-related interpretation all refer to the same value.

        IP Address: {self.ipStr}
First Host Address: {firstHost}
 Last Host Address: {lastHost}""")

        else:
            print(f"""
For standard IPv4 subnets, the network address identifies the beginning of the subnet, and the broadcast address identifies the end of the subnet. These two addresses are reserved and normally cannot be assigned to hosts.

Calculate the first usable host address by adding 1 to the network address.
First Host Address -> {self.netAdrStr} + 1 -> {firstHost}

Calculate the last usable host address by subtracting 1 from the broadcast address.
Last Host Address -> {self.broadcastStr} - 1 -> {lastHost}""")

        assert firstHost == self.firstHost
        assert lastHost == self.lastHost

    def _show_calc_total_addresses_block_method(self):
        print(f"""
Step 7: Calculate the total addresses and total usable host addresses

There are two common methods for calculating the total number of addresses in an IPv4 subnet:
1. Block-size method
2. Prefix-length method

Both methods produce the same total address count.
""")

        # Method 1: Calculate total addresses using block size
        self._method_get_total_addresses_with_block_size()

        # Method 2: Calculate total addresses using prefix length
        self._method_get_total_addresses_with_prefix_length()

        print("\nNext, calculate the total number of usable host addresses.")

        if self.prefixLen == 31:
            print(f"""
According to RFC 3021, a /31 network is treated as a point-to-point link. In this case, both addresses are considered usable host addresses.

Total Addresses -> {self.totalAddresses:,d}
Usable Host Addresses -> {self.totalAddresses:,d}""")

        elif self.prefixLen == 32:
            print(f"""
According to RFC 4632, a /32 network represents a host route containing a single address.

Total Addresses -> {self.totalAddresses:,d}
Usable Host Addresses -> {self.totalAddresses:,d}""")

        else:
            print(f"""
For standard IPv4 subnets, 2 addresses are reserved:
- the network address
- the broadcast address

Calculate the number of usable host addresses by subtracting 2 from the total number of addresses:

Total Addresses - 2

{self.totalAddresses:,d} - 2 = {self.totalAddresses - 2:,d} usable host addresses""")

    def _distribute(self, powers, sourceIndex, startIndex):
        taken = 0
        for i in range(len(powers) - 1, startIndex, -1):
            while powers[sourceIndex] > 0 and powers[i] < 10:
                powers[sourceIndex] -= 1
                powers[i] += 1
                taken += 1
        return taken

    def _method_get_total_addresses_with_block_size(self):
        numHostOctets = (32 - self.prefixLen) // 8
        if self.prefixLen % 8 == 0: # Prefix falls on an octet boundary (/8, /16, /24, /32)
            numHostOctets -= 1

        message = "there are no octets that consist entirely of host bits"
        if numHostOctets > 1:
            message = f"the last {numHostOctets} octets consist entirely of host bits"
        elif numHostOctets == 1:
            message = "the last octet consists entirely of host bits"

        print(f"""Method 1: Compute the total number of addresses using the block size

This method computes the total number of addresses by starting with the block size of the interesting octet and multiplying by 256 for each octet that consists entirely of host bits. Since the interesting octet is the first octet that contains host bits, the block size is determined within that octet.

Each remaining octet that consists entirely of host bits contributes a factor of 256. For prefixes that fall on an octet boundary (/0, /8, /16, /24), there is no partially used octet, so the next octet is treated as the interesting octet. Any remaining octets that consist entirely of host bits then contribute factors of 256.

Examples:

If the network address is 1.0.0.0/8 and the block size is 256, then the last 2 octets consist entirely of host bits.
256 * 256 * 256 = 16,777,216 = total addresses

If the network address is 10.128.0.0/9 and the block size is 128, then the last 2 octets consist entirely of host bits.
128 * 256 * 256 = 8,388,608 = total addresses

If the network address is 172.17.36.0/22 and the block size is 4, then the last octet consists entirely of host bits.
4 * 256 = 1,024 = total addresses

If the network address is 192.168.0.0/26 and the block size is 64, then there are no full host octets.
64 = total addresses

For the network {self.netAdrCIDR}, the block size is {self.blockSize}, and {message}.""")

        if numHostOctets == 0:
            print(f"{self.blockSize:,d} = total addresses")
        else:
            print(f"""{self.blockSize}{' * 256' * numHostOctets} = {self.blockSize * 256**numHostOctets:,d} = total addresses

Estimating Large Subnet Sizes

When an exact value is not required, the block-size method can also estimate large subnet sizes. This method works directly with the factors that make up the total number of addresses. Since the number of addresses is always a power of 2, it can be separated into factors of 2 and rearranged into values that are easier to estimate.

Specifically, group factors into sets of 2^10, since 2^10 = 1024. Each group can then be approximated as 1000 to produce a quick estimate.

For the network {self.netAdrStr}/{self.prefixLen}, the block size is {self.blockSize}, and the last {numHostOctets} octet{'s' if numHostOctets != 1 else ''} consist{'s' if numHostOctets != 1 else ''} entirely of host bits:""")

            takenFromBlock = 0
            takenFrom256 = 0

            # Index 0 stores the block size exponent.
            powers = [0] + [8] * numHostOctets

            # Convert the block size into powers of 2.
            num = self.blockSize
            while num != 1:
                powers[0] += 1
                num //= 2

            # Distribute factors from the block size into the host octets, from right to left, until each reaches 2^10 or no factors remain.
            takenFromBlock += self._distribute(powers, 0, 0)

            # Redistribute factors from the first host octet to maximize the number of 2^10-sized groups.
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

            takeLine += f" and apply them to {upgradedOctets} 256 term{'s' if upgradedOctets != 1 else ''} to form as many 1024-sized groups as possible:"

            factors = [2 ** powers[0]]
            thousandLines = ""

            for i, p in enumerate(powers[1:]):
                value = 2 ** p
                if p > 8:
                    line = "256" + " * 2" * (p - 8)
                    if p == 10:
                        factors.append(1000)
                        thousandLines += f"{line} = {value} or approximately 1000\n"
                    else:
                        factors.append(value)
                        thousandLines += f"{line} = {value}\n"
                else:
                    factors.append(value)

            remainingLines = "Remaining factors:\n"

            if takenFromBlock > 1:
                remainingLines += f"{self.blockSize} / ({('2 * ' * takenFromBlock)[:-3]}) = {self.blockSize // (2 ** takenFromBlock)}"
            elif takenFromBlock == 1:
                remainingLines += f"{self.blockSize} / 2 = {self.blockSize // 2}"

            if takenFrom256 > 1:
                remainingLines += f"\n256 / ({('2 * ' * takenFrom256)[:-3]}) = {256 // (2 ** takenFrom256)}"
            elif takenFrom256 == 1:
                remainingLines += "\n256 / 2 = 128"
            elif powers[1] == 8: # numHostOctets is guaranteed to be greater than 0 in this estimation path
                remainingLines += "\n256"

            estimateLines = "Approximate address count:\n"

            total = 1
            for i in factors:
                total *= i
                if i > 1:
                    estimateLines += f"{i} * "

            estimateLines = estimateLines[:-2] + f"= {total:,d} addresses"

            print(f"""{self.blockSize}{' * 256' * numHostOctets}

{factorsFromBorrowedNumbers}

{takeLine}

{thousandLines}
{remainingLines}

{estimateLines}

Note: the prefix-length method is usually simpler for quick estimates, but this block-size method provides an alternative approach to the problem.""")

        assert self.blockSize * 256**numHostOctets == self.totalAddresses

    def _method_get_total_addresses_with_prefix_length(self):
        hostBits = 32 - self.prefixLen
        print(f"""
Method 2: Compute the total number of addresses using the prefix length

Using the prefix length is simpler, but it may require calculating large exponents. To get the total addresses, subtract the prefix length ({self.prefixLen}) from 32 (the total number of bits in an IPv4 address). The difference is then used as the exponent for 2.

For example, if the prefix is /1:
32 - 1 = 31
2^31 = 2,147,483,648 total addresses

If the prefix is /12:
32 - 12 = 20
2^20 = 1,048,576 total addresses

If the prefix is /16:
32 - 16 = 16
2^16 = 65,536 total addresses

If the prefix is /27:
32 - 27 = 5
2^5 = 32 total addresses

For {self.netAdrCIDR}:
32 - {self.prefixLen} = {32 - self.prefixLen}
2^{32 - self.prefixLen} = {2**(32 - self.prefixLen):,d} total addresses""")

        if hostBits > 8:
            print(f"""
Estimating Large Subnet Sizes

When an exact value is not required, large subnet sizes can be estimated by separating the exponent into groups of 10 bits:

2^10 = 1024 or approximately 1000

Smaller remaining powers are calculated exactly. Using this approximation, large subnet sizes can often be estimated without calculating the exact value.

For {self.netAdrCIDR}:
32 - {self.prefixLen} = {hostBits}
2^{32 - self.prefixLen} = {'2^10 * ' * (hostBits // 10)}2^{hostBits % 10}

Approximate address count:
{'1000 * ' * (hostBits // 10)}{2**(hostBits % 10)} = {1000**(hostBits // 10) * 2**(hostBits % 10):,d} addresses""")

        assert 2**(32 - self.prefixLen) == self.totalAddresses
