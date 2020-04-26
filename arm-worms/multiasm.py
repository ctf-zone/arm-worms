#!/usr/bin/env python3

import binascii
import os

import click
import keystone


class Compiler():
    def __init__(self, arch, code):
        self.arch = arch
        self.code = code

    def compile_x86(self):
        ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_32)
        encoding, count = ks.asm(self.code)
        return encoding, count

    def compile_arm(self):
        ks = keystone.Ks(keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM)
        encoding, count = ks.asm(self.code)
        return encoding, count

    @classmethod
    def compile_code(cls, arch, code):
        compiler = cls(arch, code)
        assert ((arch == keystone.KS_ARCH_X86)
                or (arch == keystone.KS_ARCH_ARM))
        assert (type(code) == bytes)
        if arch == keystone.KS_ARCH_X86:
            return compiler.compile_x86()
        if arch == keystone.KS_ARCH_ARM:
            return compiler.compile_arm()


@click.group()
def cli():
    pass


@click.command()
@click.argument('asm_file')
@click.option('--out',
              default='shellcode.bin',
              help='File with shellcode (default: shellcode.bin)')
def x86(asm_file, out):
    assert (os.path.isfile(asm_file))
    with open(asm_file, 'rb') as f:
        code = f.read()
    shellcode, _ = Compiler.compile_code(keystone.KS_ARCH_X86, code)
    if shellcode is None:
        return False
    with open(out, 'wb') as f:
        f.write(bytearray(shellcode))
    dump = binascii.hexlify(bytes(shellcode))
    print('[shellcode] {}'.format(dump.decode()))
    return True


@click.command()
@click.argument('asm_file')
@click.option('--out',
              default='shellcode.bin',
              help='File with shellcode (default: shellcode.bin)')
def arm(asm_file, out):
    assert (os.path.isfile(asm_file))
    with open(asm_file, 'rb') as f:
        code = f.read()
    shellcode, _ = Compiler.compile_code(keystone.KS_ARCH_ARM, code)
    if shellcode is None:
        return False
    with open(out, 'wb') as f:
        f.write(bytearray(shellcode))
    dump = binascii.hexlify(bytes(shellcode))
    print('[shellcode] {}'.format(dump.decode()))
    return True


cli.add_command(x86)
cli.add_command(arm)

if __name__ == '__main__':
    cli()
