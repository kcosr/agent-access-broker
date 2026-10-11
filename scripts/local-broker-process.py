#!/usr/bin/env python3
"""Native process and socket helpers for the macOS/Linux local launchers."""

import argparse
import ctypes
import os
import socket
import struct
import subprocess
import sys


def process_identity(pid):
    if sys.platform == "darwin":
        libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        libproc.proc_pidpath.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
        libproc.proc_pidpath.restype = ctypes.c_int
        executable = ctypes.create_string_buffer(4096)
        if libproc.proc_pidpath(pid, executable, len(executable)) <= 0:
            raise OSError(ctypes.get_errno(), "cannot read process executable")

        libc = ctypes.CDLL(None, use_errno=True)
        libc.sysctl.argtypes = [
            ctypes.POINTER(ctypes.c_int), ctypes.c_uint,
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
            ctypes.c_void_p, ctypes.c_size_t,
        ]
        libc.sysctl.restype = ctypes.c_int
        mib = (ctypes.c_int * 3)(1, 49, pid)  # CTL_KERN, KERN_PROCARGS2
        size = ctypes.c_size_t()
        if libc.sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
            raise OSError(ctypes.get_errno(), "cannot size process arguments")
        buffer = ctypes.create_string_buffer(size.value)
        if libc.sysctl(mib, 3, buffer, ctypes.byref(size), None, 0) != 0:
            raise OSError(ctypes.get_errno(), "cannot read process arguments")
        data = buffer.raw[:size.value]
        argc = struct.unpack_from("i", data)[0]
        offset = data.index(b"\0", struct.calcsize("i")) + 1
        while offset < len(data) and data[offset] == 0:
            offset += 1
        arguments = data[offset:].split(b"\0")[:argc]
        return os.fsdecode(executable.value), [os.fsdecode(arg) for arg in arguments]

    if sys.platform.startswith("linux"):
        executable = os.readlink(f"/proc/{pid}/exe").removesuffix(" (deleted)")
        with open(f"/proc/{pid}/cmdline", "rb") as file:
            arguments = file.read().rstrip(b"\0").split(b"\0")
        return executable, [os.fsdecode(arg) for arg in arguments]
    raise OSError("local launchers support macOS and Linux")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    normalize = commands.add_parser("realpath")
    normalize.add_argument("path")
    matches = commands.add_parser("matches")
    matches.add_argument("pid", type=int)
    matches.add_argument("executable")
    matches.add_argument("config")
    port = commands.add_parser("check-port")
    port.add_argument("host")
    port.add_argument("port", type=int)
    spawn = commands.add_parser("spawn")
    spawn.add_argument("log")
    spawn.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if args.command == "realpath":
        print(os.path.realpath(args.path))
    elif args.command == "matches":
        executable, arguments = process_identity(args.pid)
        if os.path.realpath(executable) != os.path.realpath(args.executable):
            return 1
        if not any(
            arguments[i] == "--config" and arguments[i + 1] == args.config
            for i in range(len(arguments) - 1)
        ):
            return 1
    elif args.command == "check-port":
        for family, kind, protocol, _, address in socket.getaddrinfo(
            args.host, args.port, type=socket.SOCK_STREAM
        ):
            with socket.socket(family, kind, protocol) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(address)
    elif args.command == "spawn":
        arguments = args.arguments
        if arguments and arguments[0] == "--":
            arguments = arguments[1:]
        if not arguments:
            parser.error("spawn requires a command")
        with open(args.log, "ab", buffering=0) as log:
            child = subprocess.Popen(
                arguments, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                start_new_session=True,
            )
        print(child.pid)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f"local broker: {error}", file=sys.stderr)
        sys.exit(1)
