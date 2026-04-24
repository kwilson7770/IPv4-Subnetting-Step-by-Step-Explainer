from IPv4Address import *
import argparse

def handleArguments():
    parser = argparse.ArgumentParser(description="This is a subnet calculator tool that can teach the process or just show you the answers")

    # Mutually exclusive flags
    group = parser.add_mutually_exclusive_group()

    # Accept 1 or 2 positional inputs
    parser.add_argument(
        "address",
        help="""IPv4 address in various formats. Supported formats are:
a dotted decimal IPv4 string (e.g. 172.30.5.0),
a CIDR address (e.g. 127.0.5.1/24),
a dotted decimal IPv4 string with a dotted decimal IPv4 subnet mask (space separated) (e.g. 10.0.6.7 255.255.255.0),
a string of the decimal IPv4 with the prefix len (space separated) (e.g. 16843009 /8),
or an integer of an IPv4 address (e.g. 1157895235)."""
    )

    parser.add_argument(
        "extra",
        nargs="?",
        help="Optional second part of the IP address (for inputs like 10.0.6.7 255.255.255.0 or 16843009 /8)"
    )

    group.add_argument(
        "--explain",
        action="store_true",
        help="Verbose explanation of subnetting"
    )

    group.add_argument(
        "--show-steps",
        action="store_true",
        help="Show steps only (no explanations)"
    )

    parser.add_argument(
        "--subnet",
        type=int,
        choices=range(1, 33),
        metavar="[1-32]",
        help="Target CIDR prefix length for subnet generation (1-32)"
    )

    parser.add_argument(
        "--subnet-limit",
        type=int,
        default=1000,
        help="Maximum number of subnet entries to display (0 = no limit, default: 1000)"
    )

    parser.add_argument(
        "--octet-boundary",
        action="store_true",
        help="Limits displayed subnet range to an octet-aligned window for visualization only. Does not change subnet sizing, block size, or subnet calculation logic."
    )

    parser.add_argument(
        "--supernet",
        type=int,
        choices=range(1, 33),
        metavar="[1-32]",
        help="Target CIDR prefix length for supernet generation (1-32)"
    )

    args = parser.parse_args()

    ipAddressInput = args.address
    if args.extra is not None:
        ipAddressInput += f" {args.extra}"

    if args.explain:
        ip = IPv4Address(ipAddressInput, explainHowToCalculate=True)
    elif args.show_steps:
        ip = IPv4Address(ipAddressInput, showSteps=True)
    else:
        ip = IPv4Address(ipAddressInput)
        print(str(ip))

    if args.subnet:
        subnetByOctetBoundary = args.octet_boundary

        print(f"Subnets with a /{args.subnet} prefix:")

        for subnet in ip.subnets(args.subnet, args.subnet_limit, subnetByOctetBoundary):
            print(f"  - {subnet.netIDStr}/{subnet.prefixLen}")

        print("")

    if args.supernet:
        supernet = ip.supernet(args.supernet)
        print(f"""Supernet with a /{args.supernet} prefix:
  - {supernet.netIDStr}/{supernet.prefixLen}

Supernet Info

{supernet}""")
        
def main():
    handleArguments()

if __name__ == "__main__":
    main()
