from IPv4Address import IPv4Address

ip1 = IPv4Address("10.0.0.1/8")
print(ip1)

print(f"Does {ip1.netAdrStr}/{ip1.prefixLen} contain the IPv4 address 10.255.0.255?")
if ip1.contains('10.0.255.255'):
    print("Yes")
else:
    print("No")

print(f"\nWhich /11 subnets exist within {ip1.netAdrStr}/{ip1.prefixLen}?")
for ip in ip1.subnets(11):
    print(f"{ip.netAdrStr}/{ip.prefixLen}")

print(f"\nWhich /4 supernet contains {ip1.netAdrStr}/{ip1.prefixLen}, and what is the usable host range?")
ip2 = ip1.supernet(4)
print(f"Network Address: {ip2.netAdrStr}/{ip2.prefixLen}")
print(f"First usable host: {ip2.firstHost}")
print(f"Last usable host: {ip2.lastHost}")