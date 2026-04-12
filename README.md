# IPv4 Subnetting Step-by-Step Explainer

## Overview

This project is a **learning-focused** Python script that walks through how IPv4 subnetting works in a step-by-step, fully explained way.

Instead of just giving answers, it shows the entire process used to calculate:

* Subnet mask
* Network ID
* Broadcast address
* First and last usable host
* Total and usable hosts

It is designed to help you understand subnetting, not just memorize it.

---

## Quick Start

This will walk you through the full subnetting process step by step.

```bash
python ipv4_subnet_calculator.py 192.168.1.10/24 --explain
```

---

## Purpose

Subnetting can feel confusing because:

* There are multiple ways to solve the same problem
* Many tutorials skip steps or assume prior knowledge

This script solves that by:

* Breaking calculations into clear steps
* Showing multiple methods (binary, block size, prefix math)
* Printing the reasoning behind each step

Think of it as a guided walkthrough, similar to how an instructor would explain problems on a whiteboard.

---

## Target Audience

This tool is best suited for:

* Students learning networking
* Beginners struggling with subnetting concepts
* Anyone who wants to verify their work step-by-step
* Anyone who wants to learn additional subnetting methods.

---

## How to Use

This tool is designed to be run from the command line and accepts a variety of IPv4 address formats. You can use it either to quickly calculate subnet information, learn the subnetting process step by step, or simply show the calculation steps to check your own work.

### Basic Usage

```bash
python ipv4_subnet_calculator.py <addr> [extra] [options]
```

### Arguments

- `addr`  
  The IPv4 address in one of several supported formats:

  - Dotted decimal  
    ```bash
    172.30.5.0
    ```

  - CIDR notation  
    ```bash
    127.0.5.1/24
    ```

  - IP address + subnet mask  
    ```bash
    10.0.6.7 255.255.255.0
    ```

  - Integer representation + prefix length  
    ```bash
    16843009 /8
    ```

  - Integer representation only  
    ```bash
    1157895235
    ```

- `extra` *(optional)*  
  Used when the address format requires a second value (e.g., subnet mask or prefix length).

### Options

- `--explain`  
  Provides a detailed, educational explanation of how the subnet is calculated.

- `--show-steps`  
  Displays the calculation steps without additional explanations.

---

### Examples

**Basic subnet calculation:**
```bash
python ipv4_subnet_calculator.py 192.168.1.10/24
```

**Using IP + subnet mask:**
```bash
python ipv4_subnet_calculator.py 10.0.0.1 255.255.255.0
```

**Show step-by-step process:**
```bash
python ipv4_subnet_calculator.py 172.16.5.4/20 --show-steps
```

**Full explanation mode (learning-focused):**
```bash
python ipv4_subnet_calculator.py 192.168.1.10/24 --explain
```

---

## What It Teaches

The script walks through two major approaches:

### 1. Binary Method

* Converts addresses to binary
* Shows bit-level operations
* Converts results back to decimal

### 2. Block Size Method

* Identifies the interesting octet
* Calculates block size
* Finds subnet ranges using:

  * Iteration
  * Integer division
  * Modular arithmetic

### 3. Host Calculations

* First and last usable addresses
* Total vs usable hosts
* Prefix-length math

---

## Built-in Verification

The script uses internal validation checks to:

* Confirm calculations are correct
* Ensure all methods produce consistent results

Note: These checks are primarily intended for development and debugging.

---

## Features

- Step-by-step subnetting explanations
- Multiple solving methods (binary, block size, prefix math)
- Supports multiple input formats
- Built-in validation checks
- Beginner-friendly output
- /31 and /32 networks are handled according to standard rules
- Input validation is performed for supported formats

---

## Requirements

- Python 3.8+
- No external dependencies

---

# Example Output

## Default Output

Below is the output when running `python ipv4_subnet_calculator.py 172.30.197.10/19`

```text
IPv4 Address: 172.30.197.10
Netmask Address: 255.255.224.0
Network ID Address: 172.30.192.0
Broadcast Address: 172.30.223.255
IPv4 Address (binary): 10101100 00011110 11000101 00001010
Netmask Address (binary): 11111111 11111111 11100000 00000000
Network ID Address (binary): 10101100 00011110 11000000 00000000
Broadcast Address (binary): 10101100 00011110 11011111 11111111
Prefix Length: 19
CIDR Address: 172.30.197.10/19
Total Hosts: 8192
Usable Hosts: 8190
First Host: 172.30.192.1
Last Host: 172.30.223.254
Address Class: B
Private, Routable Address (RFC1918): True
Private, Non-Routable, Link-Local Address (RFC3927): False
Multicast: False
Loopback: False
```

---

## Show Steps Output

Below is the output when running `python ipv4_subnet_calculator.py 172.30.197.10/19 --show-steps`

```text
Binary steps for 172.30.197.10/19 (172.30.197.10 255.255.224.0)

IP Address
172.30.197.10 -> 172, 30, 197, 10 -> 10101100 00011110 11000101 00001010

Subnet Mask
255.255.224.0 -> 255, 255, 224, 0 -> 11111111 11111111 11100000 00000000

CIDR Prefix Length -> Subnet Mask (binary)
172.30.197.10/19 -> 19 -> 11111111 11111111 111  -> 11111111 11111111 11100000 00000000

Network ID
 IP address:   10101100 00011110 11000101 00001010
Subnet mask: & 11111111 11111111 11100000 00000000
               -----------------------------------
 Network ID:   10101100 00011110 11000000 00000000

Broadcast
Subnet mask:   11111111 11111111 11100000 00000000
   All Ones: ^ 11111111 11111111 11111111 11111111
               -----------------------------------
  Host mask:   00000000 00000000 00011111 11111111
 Network ID: | 10101100 00011110 11000000 00000000
               -----------------------------------
  Broadcast:   10101100 00011110 11011111 11111111

First Host
Network ID:   10101100 00011110 11000000 00000000
            + 00000000 00000000 00000000 00000001
              -----------------------------------
First Host:   10101100 00011110 11000000 00000001

Last Host:
Broadcast:   10101100 00011110 11011111 11111111
           - 00000000 00000000 00000000 00000001
             -----------------------------------
Last Host:   10101100 00011110 11011111 11111110

Total Hosts:
 Broadcast:   10101100 00011110 11011111 11111111
Network ID: - 10101100 00011110 11000000 00000000
              -----------------------------------
              00000000 00000000 00011111 11111111
     Add 1: + 00000000 00000000 00000000 00000001
              -----------------------------------
Total Hosts:  00000000 00000000 00100000 00000000

IP Address
172.30.197.10

Subnet Mask
11111111 11111111 11100000 00000000 -> 255.255.224.0

Network ID
10101100 00011110 11000000 00000000 -> 172.30.192.0

Broadcast
10101100 00011110 11011111 11111111 -> 172.30.223.255

First Host
10101100 00011110 11000000 00000001 -> 172.30.192.1

Last Host:
10101100 00011110 11011111 11111110 -> 172.30.223.254

Total Hosts:
00000000 00000000 00100000 00000000 -> 8192

Usable Hosts:
8192 - 2 = 8190

Block size steps for 172.30.197.10/19

Block Size
172.30.197.10/19 -> 19 -> 5 host bits in octet 3 (the interesting octet) -> block size = 2^5 = 32

Network ID
Octet 3 value for network ID = 197 // 32 * 32 -> 192
Octet 3 value set to 192 and all octets to the right of it set to 0 -> 172.30.192.0

Broadcast Address
Add 32 to octet 3 in 172.30.192.0 and subtract 1 = 223. Then replace octets to the right of the interesting octet with 255 -> 172.30.223.255

First Host
172.30.192.0 + 1 = 172.30.192.1

Last Host
172.30.223.255 - 1 = 172.30.223.254

Total Hosts
172.30.197.10/19 -> 19 -> 32 - 19 = 13 -> 2^13 = 8192 total hosts

Usable Hosts
8192 - 2 = 8190
```

---

## Explain Output

Below are small snippets of output when running `python ipv4_subnet_calculator.py 172.30.197.10/19 --explain`

```text
Step 2: Convert the subnet mask to binary.
If this is in dotted-decimal notation already (255.255.224.0) then repeat everything in step 1. If the subnet mask was provided as a prefix length (19) from CIDR notation (172.30.197.10/19) then simply write out 19 '1's (prefix length) and 13 '0's (32 - 19 = 13).
11111111 11111111 11100000 00000000

Step 3: Calculate the network ID using the IP address and subnet mask.
This is done using a binary operation called bitwise AND (&). If both bits equal 1, the network ID bit is set to 1. Otherwise, the network ID is set to 0

 IP address:   10101100 00011110 11000101 00001010
Subnet mask: & 11111111 11111111 11100000 00000000
               -----------------------------------
 Network ID:   10101100 00011110 11000000 00000000

Method 1: compute the total hosts using the block size

This method involves taking the known block size 32 and multiplying it by 256 for each octet with only host bits in the network ID 172.30.192.0. For prefixes that fall on an octet boundary (/8, /16, /24), the "interesting octet" is just treated as another host bits octet.

For example:

If the network ID is 1.0.0.0/8 and the block size is 256 then:
There are 3 host only octets so:
256 * 256 * 256 = 16777216 = total hosts

For 172.30.192.0/19 with a block size of 32:
There are 1 host only octet so:
32 * 256 = 8192 = total hosts

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
```
