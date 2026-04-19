from IPv4Address import IPv4Address

ip1 = IPv4Address("10.0.0.1/8")
print(ip1)

print(f"Does {ip1.netIDStr}/{ip1.prefixLen} contain 10.255.0.255? ")
if ip1.contains('10.0.255.255'):
    print("Yes")
else:
    print("No")

print(f"\nWhat are the /11 subnets within {ip1.netIDStr}/{ip1.prefixLen}?")
for ip in ip1.subnets(11):
    print(f"{ip.netIDStr}/{ip.prefixLen}")

print(f"\nWhich /4 supernet (a larger network with a shorter prefix) contains {ip1.netIDStr}/{ip1.prefixLen}, and what is its usable host range?")
ip2 = ip1.supernet(4)
print(f"Network ID: {ip2.netIDStr}/{ip2.prefixLen}")
print(f"First usable host: {ip2.firstHost}")
print(f"Last usable host: {ip2.lastHost}")