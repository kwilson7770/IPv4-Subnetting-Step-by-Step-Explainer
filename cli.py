from IPv4Address import *
import argparse

def handleArguments():
    parser = argparse.ArgumentParser(description="IPv4 subnet calculator that can display calculation steps or provide detailed subnetting explanations")

    # Mutually exclusive output modes
    group = parser.add_mutually_exclusive_group()

    # Accept one or two positional arguments
    parser.add_argument(
        "address",
        help="""IPv4 address input in one of the following formats:
a dotted-decimal IPv4 address (e.g. 172.30.5.0),
a CIDR address (e.g. 127.0.5.1/24),
a dotted-decimal IPv4 address with a dotted-decimal subnet mask separated by a space (e.g. 10.0.6.7 255.255.255.0),
a decimal IPv4 value with a prefix length separated by a space (e.g. 16843009 /8),
or an integer representation of an IPv4 address (e.g. 1157895235)."""
    )

    parser.add_argument(
        "extra",
        nargs="?",
        help="Optional second component of the IPv4 input (for example: 10.0.6.7 255.255.255.0 or 16843009 /8)"
    )

    group.add_argument(
        "--explain",
        action="store_true",
        help="Display detailed subnetting explanations"
    )

    group.add_argument(
        "--show-steps",
        action="store_true",
        help="Display calculation steps without detailed explanations"
    )

    parser.add_argument(
        "--subnet",
        type=int,
        choices=range(1, 33),
        metavar="[1-32]",
        help="Target CIDR prefix length used for subnet generation (1-32)"
    )

    parser.add_argument(
        "--subnet-limit",
        type=int,
        default=1000,
        help="Maximum number of subnet entries to display (0 disables the limit, default: 1000)"
    )

    parser.add_argument(
        "--octet-boundary",
        action="store_true",
        help="Limit the displayed subnet range to an octet-aligned window for visualization purposes only. This option does not modify subnet sizing, block size, or subnet calculation logic."
    )

    parser.add_argument(
        "--supernet",
        type=int,
        choices=range(0, 32),
        metavar="[0-31]",
        help="Target CIDR prefix length used for supernet generation (0-31)"
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

        print(f"Subnets using a /{args.subnet} prefix:")

        for subnet in ip.subnets(args.subnet, args.subnet_limit, subnetByOctetBoundary):
            print(f"  - {subnet.netAdrStr}/{subnet.prefixLen}")

        print("")

    if args.supernet:
        supernet = ip.supernet(args.supernet)
        print(f"""Supernet using a /{args.supernet} prefix:
  - {supernet.netAdrStr}/{supernet.prefixLen}

Supernet Information

{supernet}""")

def main():
    handleArguments()

if __name__ == "__main__":
    main()
