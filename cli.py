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
        help="New CIDR prefix length for subnets of given IP between 1 and 32"
    )

    parser.add_argument(
        "--supernet",
        type=int,
        choices=range(1, 33),
        metavar="[1-32]",
        help="New CIDR prefix length for supernet of given IP between 1 and 32"
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
        print(f"Subnets with a /{args.subnet} prefix:")
        for subnet in ip.subnets(args.subnet):
            print(f"  - {subnet.netIDStr}/{subnet.prefixLen}")

    if args.supernet:
        print(f"Supernet with a /{args.supernet} prefix:")
        supernet = ip.supernet(args.supernet)
        print(f"  - {supernet.netIDStr}/{supernet.prefixLen}")
        print("Supernet info:")
        print(supernet)

def main():
    handleArguments()

if __name__ == "__main__":
    main()
