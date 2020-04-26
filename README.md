# arm-worms

# Table of contents

- [arm-worms](#arm-worms)
- [Table of contents](#table-of-contents)
- [Intro](#intro)
- [Installation for local tests](#installation-for-local-tests)
- [Map](#map)
- [Architecture](#architecture)
- [Computer memory](#computer-memory)
- [Custom syscalls](#custom-syscalls)
  - [SYS_GET_CRC16](#sysgetcrc16)
    - [x86](#x86)
    - [arm](#arm)
  - [SYS_SEND_CRC16](#syssendcrc16)
    - [x86](#x86-1)
    - [arm](#arm-1)
  - [SYS_SCAN](#sysscan)
    - [x86](#x86-2)
    - [arm](#arm-2)
  - [SYS_INFECT](#sysinfect)
    - [x86](#x86-3)
    - [arm](#arm-3)
  - [SYS_READ_DATA](#sysreaddata)
    - [x86](#x86-4)
    - [arm](#arm-4)
- [Rules](#rules)
- [Visualization](#visualization)

# Intro

This is a game in which computers fight each other to infect as many nodes on the network as possible and score points for mining.

At the beginning of the game, each team is provided with a computer (node) on which the team runs its shellcode. The initial position of each command is determined randomly among all computers with x86 architecture.

All computers execute one instruction per turn. The order of moves is randomly determined each round. The total time allocated to the round is 2 minutes.
The total number of instructions that can be executed on one computer is `2**17`.

# Installation for local tests

Installation steps:

* `git clone https://github.com/unicorn-engine/unicorn.git`
* `git clone https://github.com/aquynh/capstone.git`
* `docker-compose up --build`

After installation, check the following URLs:

* `http://0.0.0.0:5000/test`
* `http://0.0.0.0:5000/test_all`

# Map

There are 2 types of network in which computers are located: a 121-node grid and a 121-node ternary tree. At the beginning of each round, the network is randomly selected.
Each node has its own ID.

In the case of the ternary tree:

* the central node has identifier `0`
* neighbors of the central node have identifiers `1`, `2`, `3`
* etc

In the case of the grid:

* node `(0, 0)` has identifier `0`
* node `(0, 1)` has identifier `1`
* node `(0, 2)` has identifier `2`
* etc

# Architecture

Each node is a computer with a specific type of architecture and scoring model:

* x86
    - X86 architecture
    - extreme nodes for ternary tree and perimeter nodes for the grid
    - 1 point for mining
    - at startup all commands have this architecture
* arm
    - ARM architecture
    - all internal nodes except the center
    - 2 points for mining
* super
    - ARM architecture
    - central node
    - 4 points for mining

# Computer memory

Each computer has the following memory structure:

| start  | end    | memory |
| ------ | ------ | ------ |
| 0x0000 | 0x03ff | code   |
| 0x0400 | 0x07ff | stack  |
| 0x0800 | 0x0fff | data   |

Each team can execute shellcode 512 bytes long.
Shellcode starts its execution from address 0x0000.

# Custom syscalls

Сommands can cause special syscalls for every architecture:

* SYS_GET_CRC16
* SYS_SEND_CRC16
* SYS_SCAN
* SYS_INFECT
* SYS_READ_DATA

## SYS_GET_CRC16

### x86

Input

* `nothing`

Output

* `EDI = crc16`
* `EAX = 0/1 (failure/success)`

Example

```
    mov eax, 0xb0 ; syscall number
    int 0x80      ; syscall
    mov eax, edi  ; move crc16 value to eax registry
    ...
```

### arm

Input

* `nothing`

Output

* `R8 = crc16`
* `R7 = 0/1 (failure/success)`

Example

```
    mov r7, #0xb0 ; syscall number
    swi 0x00      ; syscall
    mov r7, r8    ; move crc16 value to r7 registry
    ...
```

## SYS_SEND_CRC16

### x86

Input

* `EDI = crc16_inv (1-byte-size string)`

Output

* `EAX = number of points`

Example

```
    mov edi, 0x31   ; set crc16_inv
    mov eax, 0xb1   ; syscall number
    int 0x80        ; syscall
    test eax, eax   ; check result
    ...
```

### arm

Input

* `R8 = crc16_inv (1-byte-size string)`

Output

* `R7 = number of points`

Example

```
    mov r8, #0x31   ; set crc16_inv
    mov r7, #0xb1   ; syscall number
    swi #0x00       ; syscall
    ...
```

## SYS_SCAN

### x86

Input

* `nothing`

Output

* `0x0800 dw neighbors_num`
* `0x0802 dw neighbor_1_arch`
* `0x0804 dw neighbor_1_id`
* `0x0806 dw neighbor_2_arch`
* `0x0808 dw neighbor_2_id`
* `...`

ARCH definitions

* `0x0004 - unicorn.UC_ARCH_X86`
* `0x0001 - unicorn.UC_ARCH_ARM`

ID definitions

* `0x0000 - 0x7fff`

Example

```
    mov eax, 0xb2     ; syscall number
    int 0x80          ; syscall
    mov cx,  [0x0800] ; get number of neighbors
    mov ebx, [0x0802] ; get first neighbor
    mov edx, [0x0806] ; get second neighbor
    ...
```

### arm

Input

* `nothing`

Output

* `0x0800 dw neighbors_num`
* `0x0802 dw neighbor_1_arch`
* `0x0804 dw neighbor_1_id`
* `0x0806 dw neighbor_2_arch`
* `0x0808 dw neighbor_2_id`
* `...`

ARCH definitions

* `0x0004 - unicorn.UC_ARCH_X86`
* `0x0001 - unicorn.UC_ARCH_ARM`

ID definitions

* `0x0000 - 0x7fff`

Example

```
    mov r7, #0xb2     ; syscall number
    swi #0x00         ; syscall
    mov r0, #0x0800   ; save number of neighbors address
    ldr r1, [r0]      ; get number of neighbors
    mov r0, #0x0802   ; save first neighbor address
    ldr r2, [r0]      ; get first neighbor
    mov r0, #0x0806   ; save second neighbor address
    ldr r3, [r0]      ; get second neighbor
    ...
```

## SYS_INFECT

### x86

Input

* `EDX = computer id`
* `EDI = code address (in current memory)`
* `ECX = code size`
* `EBX = crc16_inv`

Output

* `EAX = 0/1 (failure/success)`

Example

```
    mov edx, 0x1111 ; set computer id
    mov edi, 0x0800 ; set code address
    mov ecx, 0x20   ; set code size
    mov eax, 0xb3   ; syscall number
    mov ebx, 0x31   ; set crc16_inv
    int 0x80        ; syscall
    test eax, eax   ; test result
    ...
```

### arm

Input

* `r0 = computer id`
* `r8 = code address (in current memory)`
* `r9 = code size`
* `r6 = crc16_inv`

Output

* `r7 = 0/1 (failure/success)`

Example

```
    mov r0, #0x1111 ; set computer id
    mov r8, #0x0800 ; set code address
    mov r9, #0x20   ; set code size
    mov r7, #0xb3   ; syscall number
    mov r6, #0x31   ; set crc16_inv
    swi #0x00       ; syscall
    ...
```

## SYS_READ_DATA

### x86

Input

* `EDX = computer id`
* `EDI = data address`
* `ECX = data size`

Output

* `EAX = 0/1 (failure/success)`
* `0x0800 db byte_0`
* `0x0801 db byte_1`
* `...`

Example

```
    mov edx, 0x1111   ; set computer id
    mov edi, 0x0800   ; set data address
    mov ecx, 0x20     ; set data size
    mov eax, 0xb4     ; syscall number
    int 0x80          ; syscall
    mov eax, [0x0800] ; get first data dword
    ...
```

### arm

Input

* `r0 = computer id`
* `r8 = data address`
* `r9 = data size`

Output

* `r7 = 0/1 (failure/success)`
* `0x0800 db byte_0`
* `0x0801 db byte_1`
* `...`

Example

```
    mov r0, #0x1111   ; set computer id
    mov r8, #0x0800   ; set data address
    mov r9, #0x20     ; set data size
    mov r7, #0xb4     ; syscall number
    swi #0x00         ; syscall
    mov r0, #0x0800   ; save first data dword address
    ldr r1, [r0]      ; get first data dword
    ...
```

# Rules

The goal of the team is to mine as many points as possible per round.
In order to get points for mining, you must perform the following steps:

* get new crc16 value with `SYS_GET_CRC16`
* find the inverse value to the received crc16
* send `crc16_inv` with `SYS_SEND_CRC16`

In order to infect neighbour computer, you must perform the following steps:

* get new crc16 value with `SYS_GET_CRC16`
* find the inverse value to the received crc16
* infect a neighbor using its identifier and `crc16_inv` value with `SYS_INFECT`

# Visualization

To view the result of each round, just follow the link `http://100.100.51.52`.
