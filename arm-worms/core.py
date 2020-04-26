#!/usr/bin/env python3

import binascii
import json
import os
import random
import struct
import time

import click
from terminaltables import AsciiTable

import capstone
import unicorn
from map_gen import Grid, Tree
from settings import (ARM_MINING_SCORE, DATA_SIZE, DEFAULT_SHELLCODE, MAP_FILE,
                      MAX_COMPUTER_ITERATIONS, MAX_TIME, MEMORY_SIZE,
                      REPLAY_FILE, SCORE_FILE, SHELLCODE_SIZE, STACK_SIZE,
                      SUPER_MINING_SCORE, TEAMS, X86_MINING_SCORE)
from utils import crc16, dump, get_random_data

# computers objects
computers = []

replay_step = []
scores = {TEAMS[team]: 0 for team in TEAMS}

# for debug
X86_DEBUG = False
ARM_DEBUG = False
HOOK_BLOCK = False


# helper for x86 emulation
class x86():
    @staticmethod
    def _disasm(team_name, data, address):
        cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        for i in cs.disasm(data, address):
            print('[{}]\t{:#08x}\t{}\t{}'.format(team_name, i.address,
                                                 i.mnemonic, i.op_str))

    # callback for tracing basic blocks
    @classmethod
    def hook_block(cls, computer, address, size, user_data):
        if X86_DEBUG:
            print('[{}]\ttracing basic block at {:#x}, block size = {:#x}'.
                  format(computer.team_name, address, size))

    # callback for tracing instructions
    @classmethod
    def hook_code(cls, computer, address, size, user_data):
        if X86_DEBUG:
            cls = cls()
            data = computer.mem_read(address, size)
            print(
                '[{}]\ttracing instruction at {:#x}, instruction size = {:#x}, opcodes = {}'
                .format(computer.team_name, address, size, dump(data)))
            cls._disasm(computer.team_name, data, address)

    # ========================================
    #  SYS_GET_CRC16 handler
    #
    #  IN
    #      nothing
    #  OUT
    #      EDI = crc16
    #      EAX = 0/1 (failure/success)
    #  EXAMPLE
    #      mov eax, 0xb0 ; syscall number
    #      int 0x80      ; syscall
    #      mov eax, edi  ; get crc16 value
    #      ...
    # ========================================
    @classmethod
    def sys_get_crc16(cls, computer):
        if X86_DEBUG:
            eip = computer.reg_read(unicorn.x86_const.UC_X86_REG_EIP)
            print('[{}]\t{:#08x}: SYS_GET_CRC16'.format(
                computer.team_name, eip))
        random_data = get_random_data(length=1)
        computer.crc16_value = crc16(random_data)
        if X86_DEBUG:
            print('[{}]\tdata = {}, crc16 = {:#x}'.format(
                computer.team_name, dump(random_data), computer.crc16_value))
        computer.reg_write(unicorn.x86_const.UC_X86_REG_EDI,
                           computer.crc16_value)
        # success
        computer.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 1)
        return True

    # ========================================
    #  SYS_SEND_CRC16 handler
    #
    #  IN
    #      EDI = crc16_inv (1-byte-size string)
    #  OUT
    #      EAX = number of points
    #  EXAMPLE
    #      mov edi, 0x31   ; set crc16_inv
    #      mov eax, 0xb1   ; syscall number
    #      int 0x80        ; syscall
    #      test eax, eax   ; check result
    #      ...
    # ========================================
    @classmethod
    def sys_send_crc16(cls, computer):
        if X86_DEBUG:
            eip = computer.reg_read(unicorn.x86_const.UC_X86_REG_EIP)
            print('[{}]\t{:#08x}: SYS_SEND_CRC16'.format(
                computer.team_name, eip))
        edi = computer.reg_read(unicorn.x86_const.UC_X86_REG_EDI)
        string = [(edi & 0xff)]
        if X86_DEBUG:
            print('[{}]\tstring = {}'.format(computer.team_name, dump(string)))
        crc16_from_edi = crc16(string)
        if computer.crc16_value != None and computer.crc16_value == crc16_from_edi:
            computer.score += X86_MINING_SCORE
            global scores
            scores[computer.team_name] += X86_MINING_SCORE
            computer.crc16_value = None
            # success
            computer.reg_write(unicorn.x86_const.UC_X86_REG_EAX,
                               X86_MINING_SCORE)
            computer.mining = True
            computer.src = computer.graph.ids[computer.node]
            return True
        # failure
        computer.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 0)
        return False

    # ========================================
    #  SYS_SCAN handler
    #
    #  IN
    #      nothing
    #  OUT
    #      0x0800 dw neighbors_num
    #      0x0802 dw neighbor_1_arch
    #      0x0804 dw neighbor_1_id
    #      0x0806 dw neighbor_2_arch
    #      0x0808 dw neighbor_2_id
    #      ...
    #  ARCH
    #      0x0004 - unicorn.UC_ARCH_X86
    #      0x0001 - unicorn.UC_ARCH_ARM
    #  ID
    #      0x0000 - 0x7fff
    #  EXAMPLE
    #      mov eax, 0xb2     ; syscall number
    #      int 0x80          ; syscall
    #      mov cx,  [0x0800] ; get number of neighbors
    #      mov ebx, [0x0802] ; get first neighbor
    #      mov edx, [0x0806] ; get second neighbor
    #      ...
    # ========================================
    @classmethod
    def sys_scan(cls, computer):
        if X86_DEBUG:
            eip = computer.reg_read(unicorn.x86_const.UC_X86_REG_EIP)
            print('[{}]\t{:#08x}: SYS_SCAN'.format(computer.team_name, eip))
        computer_node = computer.node
        computer_id = computer.graph.ids[computer_node]
        neighbors = computer.graph.neighbors[computer_id]
        offset = 0
        neighbors_num = struct.pack('h', len(neighbors))
        computer.mem_write(SHELLCODE_SIZE + STACK_SIZE + offset, neighbors_num)
        # write neighbors information in DATA memory area
        for neighbor in neighbors:
            neighbor_id = computer.graph.ids[neighbor]
            arch = 0
            if neighbor in computer.graph.x86:
                arch = unicorn.UC_ARCH_X86
            if neighbor in computer.graph.arm:
                arch = unicorn.UC_ARCH_ARM
            if neighbor in computer.graph.super:
                arch = unicorn.UC_ARCH_ARM
            arch = struct.pack('h', arch)
            neighbor_id = struct.pack('h', neighbor_id)
            computer.mem_write(SHELLCODE_SIZE + STACK_SIZE + offset + 2, arch)
            computer.mem_write(SHELLCODE_SIZE + STACK_SIZE + offset + 4,
                               neighbor_id)
            offset += 4
        # success
        computer.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 1)
        return True

    # ========================================
    #  SYS_INFECT handler
    #
    #  IN
    #      EDX = computer id
    #      EDI = code address (in current memory)
    #      ECX = code size
    #      EBX = crc16_inv (1-byte-size string)
    #  OUT
    #      EAX = 0/1 (failure/success)
    #  EXAMPLE
    #      mov edx, 0x1111 ; set computer id
    #      mov edi, 0x0800 ; set code address
    #      mov ecx, 0x20   ; set code size
    #      mov eax, 0xb3   ; syscall number
    #      mov ebx, 0x31   ; set crc16_inv
    #      int 0x80        ; syscall
    #      test eax, eax   ; test result
    # ========================================
    @classmethod
    def sys_infect(cls, computer):
        if X86_DEBUG:
            eip = computer.reg_read(unicorn.x86_const.UC_X86_REG_EIP)
            print('[{}]\t{:#08x}: SYS_INFECT'.format(computer.team_name, eip))

        # check if computer can infect
        crc16_inv_ebx = computer.reg_read(unicorn.x86_const.UC_X86_REG_EBX)
        string = [(crc16_inv_ebx & 0xff)]
        crc16_ebx = crc16(string)
        if not (crc16_ebx != None and crc16_ebx == computer.crc16_value):
            computer.crc16_value = None
            # failure
            computer.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 0)
            return False

        # read computer id
        id_edx = computer.reg_read(unicorn.x86_const.UC_X86_REG_EDX)

        # verify that the id belongs to the neighbor
        success = False
        computer_node = computer.node
        computer_id = computer.graph.ids[computer_node]
        neighbors = computer.graph.neighbors[computer_id]
        for node in neighbors:
            neighbor_id = computer.graph.ids[node]
            if neighbor_id == id_edx:
                success = True
        if not success:
            # failure
            computer.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 0)
            return False

        # get neighbor object by id
        success = False
        for node in computer.graph.ids:
            if computer.graph.ids[node] == id_edx:
                success = True
                break
        if not success:
            # failure
            computer.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 0)
            return False
        global computers
        for new_computer in computers:
            if new_computer.node == node:
                break

        # check if node is empty
        free_node = True
        if new_computer.team_name:
            free_node = False

        # check current replay
        global replay_step
        for comp in replay_step:
            if (comp['target'] == new_computer.graph.ids[new_computer.node]
                ) or (comp['target'] == computer.graph.ids[computer.node]):
                computer.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 0)
                return False

        # read pointer
        pointer_edi = computer.reg_read(unicorn.x86_const.UC_X86_REG_EDI)

        # read size
        size_ecx = computer.reg_read(unicorn.x86_const.UC_X86_REG_ECX)
        if (size_ecx > 1024) or (pointer_edi < 0) or (pointer_edi >=
                                                      MEMORY_SIZE - size_ecx):
            # write 0 in EAX and exit
            computer.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 0)
            return False

        # read shellcode
        shellcode = computer.mem_read(pointer_edi, size_ecx)

        # infect neighbor computer
        if not free_node:
            new_computer.mem_unmap(new_computer.base_address, MEMORY_SIZE)
            new_computer.emu_stop()
            new_computer.free()
        new_computer.team_name = computer.team_name
        new_computer.emulator_init(bytes(shellcode))

        # success
        computer.infect = True
        computer.src = computer.graph.ids[computer.node]
        computer.dst = new_computer.graph.ids[new_computer.node]

        computer.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 1)
        return True

    # ========================================
    #  SYS_READ_DATA handler
    #
    #  IN
    #      EDX = computer id
    #      EDI = data address
    #      ECX = data size
    #  OUT
    #      EAX = 0/1 (failure/success)
    #      0x0800 db byte_0
    #      0x0801 db byte_1
    #      ...
    #  EXAMPLE
    #      mov edx, 0x1111   ; set computer id
    #      mov edi, 0x0800   ; set data address
    #      mov ecx, 0x20     ; set data size
    #      mov eax, 0xb4     ; syscall number
    #      int 0x80          ; syscall
    #      mov eax, [0x0800] ; get first data dword
    # ========================================
    @classmethod
    def sys_read_data(cls, computer):
        if X86_DEBUG:
            eip = computer.reg_read(unicorn.x86_const.UC_X86_REG_EIP)
            print('[{}]\t{:#08x}: SYS_READ_DATA'.format(
                computer.team_name, eip))

        # read neighbor id
        id_edx = computer.reg_read(unicorn.x86_const.UC_X86_REG_EDX)

        # verify that the id belongs to the neighbor
        success = False
        computer_node = computer.node
        computer_id = computer.graph.ids[computer_node]
        neighbors = computer.graph.neighbors[computer_id]
        for node in neighbors:
            neighbor_id = computer.graph.ids[node]
            if neighbor_id == id_edx:
                success = True
        if not success:
            # failure
            computer.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 0)
            return False

        # read data address
        address_edi = computer.reg_read(unicorn.x86_const.UC_X86_REG_EDI)

        # read data size
        size_ecx = computer.reg_read(unicorn.x86_const.UC_X86_REG_ECX)

        # check address and size
        if (address_edi < 0) and (address_edi >= MEMORY_SIZE - size_ecx) and (
                size_ecx > 2048):
            # failure
            computer.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 0)
            return False

        # get neighbor object by id
        success = False
        for node in computer.graph.ids:
            if computer.graph.ids[node] == id_edx:
                success = True
                break
        if not success:
            # failure
            computer.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 0)
            return False
        global computers
        for new_computer in computers:
            if new_computer.node == node:
                break

        # check if node is empty
        if not new_computer.team_name:
            # write 0 in EAX and exit
            computer.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 0)
            return False

        # read data from neighbor computer
        try:
            data = new_computer.mem_read(
                new_computer.base_address + address_edi, size_ecx)
        except Exception as e:
            if X86_DEBUG:
                print('[{}]\tread data error: {}'.format(
                    computer.team_name, repr(e)))
            computer.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 0)
            return False

        # write data to DATA memory region
        computer.mem_write(computer.base_address + SHELLCODE_SIZE + STACK_SIZE,
                           bytes(data))

        # success
        computer.reg_write(unicorn.x86_const.UC_X86_REG_EAX, 1)
        return True

    # callback for tracing Linux interrupt (not syscall)
    @classmethod
    def hook_intr(cls, computer, intno, user_data):
        cls = cls()

        # only handle syscall
        if intno != 0x80:
            if X86_DEBUG:
                print('[{}]\tgot interrupt {:#x}'.format(
                    computer.team_name, intno))
            computer.emu_stop()
            return False

        eax = computer.reg_read(unicorn.x86_const.UC_X86_REG_EAX)

        # custom syscalls definitions
        SYS_GET_CRC16 = 0xb0
        SYS_SEND_CRC16 = 0xb1
        SYS_SCAN = 0xb2
        SYS_INFECT = 0xb3
        SYS_READ_DATA = 0xb4

        if (eax == SYS_GET_CRC16):
            cls.sys_get_crc16(computer)
            return True

        if (eax == SYS_SEND_CRC16):
            cls.sys_send_crc16(computer)
            return True

        if (eax == SYS_SCAN):
            cls.sys_scan(computer)
            return True

        if (eax == SYS_INFECT):
            cls.sys_infect(computer)
            return True

        if (eax == SYS_READ_DATA):
            cls.sys_read_data(computer)
            return True

        computer.emu_stop()
        return False


# helper for ARM emulation
class arm():
    @staticmethod
    def _disasm(team_name, data, address):
        cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        for i in cs.disasm(data, address):
            print('[{}]\t{:#08x}\t{}\t{}'.format(team_name, i.address,
                                                 i.mnemonic, i.op_str))

    # callback for tracing basic blocks
    @classmethod
    def hook_block(cls, computer, address, size, user_data):
        if ARM_DEBUG:
            print('[{}]\ttracing basic block at {:#x}, block size = {:#x}'.
                  format(computer.team_name, address, size))

    # callback for tracing instructions
    @classmethod
    def hook_code(cls, computer, address, size, user_data):
        if ARM_DEBUG:
            cls = cls()
            data = computer.mem_read(address, size)
            print(
                '[{}]\ttracing instruction at {:#x}, instruction size = {:#x}, opcodes = {}'
                .format(computer.team_name, address, size, dump(data)))
            cls._disasm(computer.team_name, data, address)

    # ========================================
    #  SYS_GET_CRC16 handler
    #
    #  IN
    #      nothing
    #  OUT
    #      R8 = crc16
    #      R7 = 0/1 (failure/success)
    #  EXAMPLE
    #      mov r7, #0xb0 ; syscall number
    #      swi 0x00      ; syscall
    #      mov r7, r8    ; get crc16 value
    #      ...
    # ========================================
    @classmethod
    def sys_get_crc16(cls, computer):
        if ARM_DEBUG:
            pc = computer.reg_read(unicorn.arm_const.UC_ARM_REG_PC)
            print('[{}]\t{:#08x}: SYS_GET_CRC16'.format(
                computer.team_name, pc))
        random_data = get_random_data(length=1)
        computer.crc16_value = crc16(random_data)
        if ARM_DEBUG:
            print('[{}]\tdata = {}, crc16 = {:#x}'.format(
                computer.team_name, dump(random_data), computer.crc16_value))
        # write crc16 value to R8 registry
        computer.reg_write(unicorn.arm_const.UC_ARM_REG_R8,
                           computer.crc16_value)
        # success
        computer.reg_write(unicorn.arm_const.UC_ARM_REG_R7, 1)
        return True

    # ========================================
    #  SYS_SEND_CRC16 handler
    #
    #  IN
    #      R8 = crc16_inv (1-byte-size string)
    #  OUT
    #      R7 = number of points
    #  EXAMPLE
    #      mov r8, #0x31   ; set crc16_inv
    #      mov r7, #0xb1   ; syscall number
    #      swi #0x00       ; syscall
    #      ...
    # ========================================
    @classmethod
    def sys_send_crc16(cls, computer):
        if ARM_DEBUG:
            pc = computer.reg_read(unicorn.arm_const.UC_ARM_REG_PC)
            print('[{}]\t{:#08x}: SYS_SEND_CRC16'.format(
                computer.team_name, pc))
        r8 = computer.reg_read(unicorn.arm_const.UC_ARM_REG_R8)
        string = [(r8 & 0xff)]
        if ARM_DEBUG:
            print('[{}]\tstring = {}'.format(computer.team_name, dump(string)))
        crc16_from_r8 = crc16(string)
        if computer.crc16_value != None and computer.crc16_value == crc16_from_r8:
            computer.score += ARM_MINING_SCORE
            global scores
            scores[computer.team_name] += ARM_MINING_SCORE
            computer.crc16_value = None
            # success
            computer.reg_write(unicorn.arm_const.UC_ARM_REG_R7,
                               ARM_MINING_SCORE)
            computer.mining = True
            computer.src = computer.graph.ids[computer.node]
            return True
        # failure
        computer.reg_write(unicorn.arm_const.UC_ARM_REG_R7, 0)
        return False

    # ========================================
    #  SYS_SCAN handler
    #
    #  IN
    #      nothing
    #  OUT
    #      0x0800 dw neighbors_num
    #      0x0802 dw neighbor_1_arch
    #      0x0804 dw neighbor_1_id
    #      0x0806 dw neighbor_2_arch
    #      0x0808 dw neighbor_2_id
    #      ...
    #  ARCH
    #      0x0004 - unicorn.UC_ARCH_X86
    #      0x0001 - unicorn.UC_ARCH_ARM
    #  ID
    #      0x0000 - 0x7fff
    #  EXAMPLE
    #      mov r7, #0xb2     ; syscall number
    #      swi #0x00         ; syscall
    #      mov r0, #0x0800   ; save number of neighbors address
    #      ldr r1, [r0]      ; get number of neighbors
    #      mov r0, #0x0804   ; save first neighbor address
    #      ldr r2, [r0]      ; get first neighbor
    #      mov r0, #0x0806   ; save second neighbor address
    #      ldr r3, [r0]      ; get second neighbor
    #      ...
    # ========================================
    @classmethod
    def sys_scan(cls, computer):
        if ARM_DEBUG:
            pc = computer.reg_read(unicorn.arm_const.UC_ARM_REG_PC)
            print('[{}]\t{:#08x}: SYS_SCAN'.format(computer.team_name, pc))
        computer_node = computer.node
        computer_id = computer.graph.ids[computer_node]
        neighbors = computer.graph.neighbors[computer_id]
        offset = 0
        neighbors_num = struct.pack('h', len(neighbors))
        computer.mem_write(SHELLCODE_SIZE + STACK_SIZE + offset, neighbors_num)
        # write neighbors information in DATA memory area
        for neighbor in neighbors:
            neighbor_id = computer.graph.ids[neighbor]
            arch = 0
            if neighbor in computer.graph.x86:
                arch = unicorn.UC_ARCH_X86
            if neighbor in computer.graph.arm:
                arch = unicorn.UC_ARCH_ARM
            if neighbor in computer.graph.super:
                arch = unicorn.UC_ARCH_ARM
            arch = struct.pack('h', arch)
            neighbor_id = struct.pack('h', neighbor_id)
            computer.mem_write(SHELLCODE_SIZE + STACK_SIZE + offset + 2, arch)
            computer.mem_write(SHELLCODE_SIZE + STACK_SIZE + offset + 4,
                               neighbor_id)
            offset += 4
        # success
        computer.reg_write(unicorn.arm_const.UC_ARM_REG_R7, 1)
        return True

    # ========================================
    #  SYS_INFECT handler
    #
    #  IN
    #      r0 = computer id
    #      r8 = code address (in current memory)
    #      r9 = code size
    #      r6 = crc16_inv
    #  OUT
    #      r7 = 0/1 (failure/success)
    #  EXAMPLE
    #      mov r0, #0x1111 ; set computer id
    #      mov r8, #0x0800 ; set code address
    #      mov r9, #0x20   ; set code size
    #      mov r7, #0xb3   ; syscall number
    #      mov r6, #0x31   ; set crc16_inv
    #      swi #0x00       ; syscall
    # ========================================
    @classmethod
    def sys_infect(cls, computer):
        if ARM_DEBUG:
            pc = computer.reg_read(unicorn.arm_const.UC_ARM_REG_PC)
            print('[{}]\t{:#08x}: SYS_INFECT'.format(computer.team_name, pc))

        # check if computer can infect
        crc16_inv_r6 = computer.reg_read(unicorn.arm_const.UC_ARM_REG_R6)
        string = [(crc16_inv_r6 & 0xff)]
        crc16_r6 = crc16(string)
        if not (crc16_r6 != None and crc16_r6 == computer.crc16_value):
            computer.crc16_value = None
            # failure
            computer.reg_write(unicorn.arm_const.UC_ARM_REG_R7, 0)
            return False

        # read computer id
        id_reg = computer.reg_read(unicorn.arm_const.UC_ARM_REG_R0)

        # verify that the id belongs to the neighbor
        success = False
        computer_node = computer.node
        computer_id = computer.graph.ids[computer_node]
        neighbors = computer.graph.neighbors[computer_id]
        for node in neighbors:
            neighbor_id = computer.graph.ids[node]
            if neighbor_id == id_reg:
                success = True
        if not success:
            # failure
            computer.reg_write(unicorn.arm_const.UC_ARM_REG_R7, 0)
            return False

        # get neighbor object by id
        success = False
        for node in computer.graph.ids:
            if computer.graph.ids[node] == id_reg:
                success = True
                break
        if not success:
            # failure
            computer.reg_write(unicorn.arm_const.UC_ARM_REG_R7, 0)
            return False
        global computers
        for new_computer in computers:
            if new_computer.node == node:
                break

        # check if node is empty
        free_node = True
        if new_computer.team_name:
            free_node = False

        # check current replay
        global replay_step
        for comp in replay_step:
            if (comp['target'] == new_computer.graph.ids[new_computer.node]
                ) or (comp['target'] == computer.graph.ids[computer.node]):
                computer.reg_write(unicorn.arm_const.UC_ARM_REG_R7, 0)
                return False

        # read pointer
        code_address = computer.reg_read(unicorn.arm_const.UC_ARM_REG_R8)

        # read size
        code_size = computer.reg_read(unicorn.arm_const.UC_ARM_REG_R9)
        if (code_size > 1024) or (code_address < 0) or (
                code_address >= MEMORY_SIZE - code_size):
            # write 0 in R7 and exit
            computer.reg_write(unicorn.arm_const.UC_ARM_REG_R7, 0)
            return False

        # get shellcode
        shellcode = computer.mem_read(code_address, code_size)

        # infect neighbor computer
        if not free_node:
            new_computer.mem_unmap(new_computer.base_address, MEMORY_SIZE)
            new_computer.emu_stop()
            new_computer.free()
        new_computer.team_name = computer.team_name
        new_computer.emulator_init(bytes(shellcode))

        # success
        computer.infect = True
        computer.src = computer.graph.ids[computer.node]
        computer.dst = new_computer.graph.ids[new_computer.node]

        computer.reg_write(unicorn.arm_const.UC_ARM_REG_R7, 1)
        return True

    # ========================================
    #  SYS_READ_DATA handler
    #
    #  IN
    #      r0 = computer id
    #      r8 = data address
    #      r9 = data size
    #  OUT
    #      r7 = 0/1 (failure/success)
    #      0x0800 db byte_0
    #      0x0801 db byte_1
    #      ...
    #  EXAMPLE
    #      mov r0, #0x1111   ; set computer id
    #      mov r8, #0x0800   ; set data address
    #      mov r9, #0x20     ; set data size
    #      mov r7, #0xb4     ; syscall number
    #      swi #0x00         ; syscall
    #      mov r0, #0x0800   ; save first data dword address
    #      ldr r1, [r0]      ; get first data dword
    # ========================================
    @classmethod
    def sys_read_data(cls, computer):
        if ARM_DEBUG:
            pc = computer.reg_read(unicorn.arm_const.UC_ARM_REG_PC)
            print('[{}]\t{:#08x}: SYS_READ_DATA'.format(
                computer.team_name, pc))

        # read neighbor id
        id_reg = computer.reg_read(unicorn.arm_const.UC_ARM_REG_R0)

        # verify that the id belongs to the neighbor
        success = False
        computer_node = computer.node
        computer_id = computer.graph.ids[computer_node]
        neighbors = computer.graph.neighbors[computer_id]
        for node in neighbors:
            neighbor_id = computer.graph.ids[node]
            if neighbor_id == id_reg:
                success = True
        if not success:
            # failure
            computer.reg_write(unicorn.arm_const.UC_ARM_REG_R7, 0)
            return False

        # read data address
        data_address = computer.reg_read(unicorn.arm_const.UC_ARM_REG_R8)

        # read data size
        data_size = computer.reg_read(unicorn.arm_const.UC_ARM_REG_R9)

        # check address and size
        if (data_address < 0) and (data_address >= MEMORY_SIZE -
                                   data_size) and (data_size > 2048):
            # failure
            computer.reg_write(unicorn.arm_const.UC_ARM_REG_R7, 0)
            return False

        # get neighbor object by id
        success = False
        for node in computer.graph.ids:
            if computer.graph.ids[node] == id_reg:
                success = True
                break
        if not success:
            # failure
            computer.reg_write(unicorn.arm_const.UC_ARM_REG_R7, 0)
            return False
        global computers
        for new_computer in computers:
            if new_computer.node == node:
                break

        # check if node is empty
        if not new_computer.team_name:
            # write 0 in R7 and exit
            computer.reg_write(unicorn.arm_const.UC_ARM_REG_R7, 0)
            return False

        # read data from neighbor computer
        try:
            data = new_computer.mem_read(
                new_computer.base_address + data_address, data_size)
        except Exception as e:
            if ARM_DEBUG:
                print('[{}]\tread data error: {}'.format(
                    computer.team_name, repr(e)))
            computer.reg_write(unicorn.arm_const.UC_ARM_REG_R7, 0)
            return False

        # write data to DATA memory region
        computer.mem_write(computer.base_address + SHELLCODE_SIZE + STACK_SIZE,
                           bytes(data))

        # success
        computer.reg_write(unicorn.arm_const.UC_ARM_REG_R7, 1)
        return True

    @classmethod
    def hook_intr(cls, computer, intno, data):
        cls = cls()

        # only handle syscall (intno = 0x00)
        if intno != 2:
            if ARM_DEBUG:
                print('[{}]\tgot interrupt {:#x}'.format(
                    computer.team_name, intno))
            computer.emu_stop()
            return False

        r7 = computer.reg_read(unicorn.arm_const.UC_ARM_REG_R7)

        # custom syscalls definitions
        SYS_GET_CRC16 = 0xb0
        SYS_SEND_CRC16 = 0xb1
        SYS_SCAN = 0xb2
        SYS_INFECT = 0xb3
        SYS_READ_DATA = 0xb4

        if (r7 == SYS_GET_CRC16):
            cls.sys_get_crc16(computer)
            return True

        if (r7 == SYS_SEND_CRC16):
            cls.sys_send_crc16(computer)
            return True

        if (r7 == SYS_SCAN):
            cls.sys_scan(computer)
            return True

        if (r7 == SYS_INFECT):
            cls.sys_infect(computer)
            return True

        if (r7 == SYS_READ_DATA):
            cls.sys_read_data(computer)
            return True

        computer.emu_stop()
        return False


# each node of the graph is an object of this class
class Computer(unicorn.Uc):
    def add_params(self, team_name, node, graph):
        # get capstone object
        if self._arch == unicorn.UC_ARCH_X86:
            cs_arch = capstone.CS_ARCH_X86
        else:
            cs_arch = capstone.CS_ARCH_ARM
        self.cs = capstone.Cs(cs_arch, self._mode)
        # set team name
        self.team_name = team_name
        # set start node
        self.node = node
        # set base shellcode address
        self.base_address = 0
        # set score
        self.score = 0
        # set shellcode
        self.shellcode = None
        self.current_instruction_offset = 0
        # done is True if emulation completed
        self.done = False
        # init crc16 field
        self.crc16_value = None
        # set map
        self.graph = graph
        # set iteration counter
        self.iteration_counter = 0
        # if infect
        self.infect = False
        self.src = None
        self.dst = None
        # if mining
        self.mining = False

    def free(self):
        self.base_address = 0
        self.score = 0
        self.shellcode = None
        self.current_instruction_offset = 0
        self.done = False
        self.crc16_value = None
        self.iteration_counter = 0
        self.infect = False
        self.src = None
        self.dst = None
        self.mining = False

    # init memory, write shellcode and set hooks
    def emulator_init(self, shellcode):
        self.shellcode = shellcode
        if self._arch == unicorn.UC_ARCH_X86:
            self._init_x86()
        if self._arch == unicorn.UC_ARCH_ARM:
            self._init_arm()

    def step(self):
        if self.current_instruction_offset < 0 or self.current_instruction_offset >= SHELLCODE_SIZE:
            self.done = True
            return False
        # get bytes of at least one instruction
        try:
            insn_bytes = self.mem_read(self.current_instruction_offset, 0x10)
        except Exception as e:
            print('[error] {}'.format(repr(e)))
            self.done = True
            return False
        if not insn_bytes:
            self.done = True
            return False
        cs_ds = self.cs.disasm(insn_bytes, self.current_instruction_offset)
        insn0 = next(cs_ds, None)
        # if can't disasm, just exit
        if insn0 is None:
            self.done = True
            return False
        # emulate single insn
        try:
            self.emu_start(self.current_instruction_offset,
                           self.current_instruction_offset + len(insn0.bytes),
                           timeout=0,
                           count=1)
        except Exception as e:
            print('[error] {}'.format(repr(e)))
            self.done = True
            return False
        # update current_instruction_offset
        if self._arch == unicorn.UC_ARCH_X86:
            self.current_instruction_offset = self.reg_read(
                unicorn.x86_const.UC_X86_REG_EIP)
        if self._arch == unicorn.UC_ARCH_ARM:
            pc = self.reg_read(unicorn.arm_const.UC_ARM_REG_PC)
            if self.current_instruction_offset == pc:
                self.current_instruction_offset += 4
            else:
                self.current_instruction_offset = pc
        return True

    def _init_x86(self):
        # map memory and write shellcode in memory
        self.mem_map(self.base_address, MEMORY_SIZE)
        self.mem_write(self.base_address, self.shellcode)

        # initialize stack (1024 bytes after shellcode)
        self.reg_write(unicorn.x86_const.UC_X86_REG_ESP,
                       self.base_address + SHELLCODE_SIZE)

        # tracing all basic blocks with customized callback
        if HOOK_BLOCK:
            self.hook_add(unicorn.UC_HOOK_BLOCK, x86.hook_block)

        # tracing all instructions with customized callback
        self.hook_add(unicorn.UC_HOOK_CODE, x86.hook_code)

        # hook instruction
        self.hook_add(unicorn.UC_HOOK_INTR, x86.hook_intr)

    def _init_arm(self):
        # map memory and write shellcode in memory
        self.mem_map(self.base_address, MEMORY_SIZE)
        self.mem_write(self.base_address, self.shellcode)

        # initialize stack (1024 bytes after shellcode)
        self.reg_write(unicorn.arm_const.UC_ARM_REG_SP,
                       self.base_address + SHELLCODE_SIZE)

        # tracing all basic blocks with customized callback
        if HOOK_BLOCK:
            self.hook_add(unicorn.UC_HOOK_BLOCK, arm.hook_block)

        # tracing all instructions with customized callback
        self.hook_add(unicorn.UC_HOOK_CODE, arm.hook_code)

        # hook instruction
        self.hook_add(unicorn.UC_HOOK_INTR, arm.hook_intr)


def init_x86_computers(graph):
    nodes = graph.x86
    seed = int.from_bytes(os.urandom(8), byteorder='little')
    random.seed(seed)
    random.shuffle(nodes)
    computers = []
    teams = [name for name in TEAMS.values()]
    teams_len = len(teams)
    for i in range(len(nodes)):
        team_name = ''
        if i < teams_len:
            team_name = teams[i]
        computer = Computer(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        computer.add_params(team_name=team_name, node=nodes[i], graph=graph)
        computers.append(computer)
    return computers


def init_arm_computers(graph):
    nodes_arm = graph.arm
    computers = []
    for node in nodes_arm:
        computer = Computer(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
        computer.add_params(team_name='', node=node, graph=graph)
        computers.append(computer)
    return computers


def init_super_computers(graph):
    nodes_super = graph.super
    computers = []
    for node in nodes_super:
        computer = Computer(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
        computer.add_params(team_name='', node=node, graph=graph)
        computers.append(computer)
    return computers


def print_info(computers):
    table_data = []
    table_data.append([
        'team_name', 'node', 'id', 'arch', 'score',
        'shellcode (first 10 bytes)'
    ])
    arch = ''
    for computer in computers:
        if computer._arch == unicorn.UC_ARCH_X86:
            arch = 'X86'
        if computer._arch == unicorn.UC_ARCH_ARM:
            arch = 'ARM'
        shellcode = ''
        if computer.shellcode:
            shellcode = dump(computer.shellcode)
        table_data.append([
            computer.team_name, computer.node,
            '{:#06x}'.format(computer.graph.ids[computer.node]), arch,
            computer.score, shellcode[:30]
        ])
    table = AsciiTable(table_data)
    print('\n[computers]\n{}'.format(table.table))


def get_map_json(computers):
    assert (type(computers[0]) == Computer)
    map_json = {
        'nodes': [{
            'id': computer.graph.ids[computer.node],
            'team_name': computer.team_name
        } for computer in computers],
        'links': [{
            'source': computers[0].graph.ids[source_node],
            'target': computers[0].graph.ids[target_node]
        } for source_node, target_node in computers[0].graph.graph.edges()] +
        [{
            'source': computers[0].graph.ids[target_node],
            'target': computers[0].graph.ids[source_node]
        } for source_node, target_node in computers[0].graph.graph.edges()]
    }
    return map_json


def update_replay_step(replay_step: list, src, dst, team_name, score, mining):
    replay_step.append({
        'source': src,
        'target': dst,
        'team_name': team_name,
        'current_score': score,
        'mining': mining
    })
    return replay_step


def start_game():
    global computers
    replay_array = []

    # start game
    time_sg = time.time()
    while (True):
        if time.time() - time_sg > MAX_TIME:
            break
        end = True
        global replay_step
        replay_step = []
        for computer in computers:
            if computer.team_name and not computer.done:
                try:
                    computer.step()
                except Exception as e:
                    print('[error] {}'.format(repr(e)))
                update_replay = False
                mining = 0
                if computer.infect:
                    update_replay = True
                    src, dst, mining = computer.src, computer.dst, 0
                    computer.infect, computer.src, computer.dst = False, None, None
                if computer.mining:
                    update_replay = True
                    src, dst, mining = computer.src, computer.src, 1
                    computer.mining, computer.src = False, None
                if update_replay:
                    global scores
                    replay_step = update_replay_step(
                        replay_step, src, dst, computer.team_name,
                        scores[computer.team_name], mining)
                computer.iteration_counter += 1
                if (computer.iteration_counter == MAX_COMPUTER_ITERATIONS):
                    computer.done = True
                end = False
        if len(replay_step):
            replay_array.append(replay_step)
        if end: break

    return replay_array


@click.group()
def cli():
    pass


@click.command()
@click.argument('file_path')
def play_game(file_path):
    # computers objects
    global computers
    computers = []

    # init map
    seed = int.from_bytes(os.urandom(8), byteorder='little')
    random.seed(seed)
    if random.randint(0, 1):
        graph = Grid()
    else:
        graph = Tree()
    graph.init()

    # init computers objects
    computers += init_x86_computers(graph)
    computers += init_arm_computers(graph)
    computers += init_super_computers(graph)

    # get map json
    map_json = get_map_json(computers)

    # get shellcodes json
    with open(file_path, 'r') as f:
        shellcodes = json.load(f)

    # add shellcodes
    for computer in computers:
        if computer.team_name:
            shellcode = binascii.unhexlify(shellcodes[computer.team_name])
            computer.emulator_init(shellcode)

    replay_array = start_game()

    # write replay
    replay_file = file_path.replace('shellcode', 'replay')
    with open(replay_file, 'w') as f:
        json.dump(replay_array, f)

    # write map
    replay_file = file_path.replace('shellcode', 'map')
    with open(replay_file, 'w') as f:
        json.dump(map_json, f)

    global scores
    # write scores
    score_file = file_path.replace('shellcode', 'score')
    with open(score_file, 'w') as f:
        json.dump(scores, f)


@click.command()
def test():
    start = time.time()

    # computers objects
    global computers
    computers = []

    # init map
    seed = int.from_bytes(os.urandom(8), byteorder='little')
    random.seed(seed)
    if random.randint(0, 1):
        graph = Grid()
    else:
        graph = Tree()
    graph.init()

    # init computers objects
    computers += init_x86_computers(graph)
    computers += init_arm_computers(graph)
    computers += init_super_computers(graph)

    # get map object
    map_json = get_map_json(computers)
    with open(MAP_FILE, 'w') as f:
        json.dump(map_json, f)

    # get shellcodes json
    shellcodes = {TEAMS[team_id]: DEFAULT_SHELLCODE for team_id in TEAMS}

    # add shellcodes
    for computer in computers:
        if computer.team_name:
            shellcode = binascii.unhexlify(shellcodes[computer.team_name])
            computer.emulator_init(shellcode)

    print_info(computers)

    replay_array = start_game()

    # write replay
    with open(REPLAY_FILE, 'w') as f:
        json.dump(replay_array, f)

    global scores
    # write scores
    with open(SCORE_FILE, 'w') as f:
        json.dump(scores, f)

    # print all computers info with shellcodes
    print('[emulation completed]')
    print_info(computers)
    print('[time]\t{} s.\n'.format(round(time.time() - start, 3)))


cli.add_command(play_game)
cli.add_command(test)

if __name__ == '__main__':
    cli()
