#!/usr/bin/env python3
# Copyright (C) 2019 baalajimaestro
# Copyright (C) 2020-2021 Giovix92

import argparse
import re
import os
import sys
import shutil


version = "v1.4.1"
wfixes = []
write = False
namefile = "fixes.txt"
inputfile = "denials.txt"
logname = None

if os.path.exists("sepolicy"):
    shutil.rmtree("sepolicy")

if os.path.exists("denials.txt"):
    os.remove("denials.txt")

if os.path.exists("fixes.txt"):
    os.remove("fixes.txt")


def gen_fix(string):
    test = re.search("{", string)
    test2 = re.search("}", string)
    se_context = string[test.span()[0]:test2.span()[0] + 1]
    test = re.search("scontext", string)
    scontext = string[(test.span()[0]):].split(":")[2]
    test = re.search("tcontext", string)
    tcontext = string[(test.span()[0]):].split(":")[2]
    test = re.search("tclass", string)
    tclass = string[(test.span()[0]):].split("=")[1].split(" ")[0]
    if scontext == tcontext:
        tcontext = "self"
    fix = f"allow {scontext} {tcontext}:{tclass} {se_context};\n"
    if tclass == "binder" and "call" in se_context or "transfer" in se_context:
        fix = f"binder_call({scontext}, {tcontext})\n"
    if "prop" in tcontext:
        if "read" in se_context or "getattr" in se_context or "ioctl" in se_context or "lock" in se_context or "open" in se_context:
            fix = f"get_prop({scontext}, {tcontext})\n"
        if "write" in se_context or "set" in se_context or "append" in se_context:
            fix = f"set_prop({scontext}, {tcontext})\n"
    return fix


parser = argparse.ArgumentParser(
    description="Address your SELinux denials.",
    prog="denials.py")
group = parser.add_mutually_exclusive_group()
group.add_argument("-1", "--oneshot", metavar="denial", nargs="?",
                   help="Takes as input a denial and just outputs the fix.")
parser.add_argument("-c", "--cleanup", action='store_true',
                    help="Cleans up the working directory.")
group.add_argument("-d", "--dmesg", default="dmesg.txt", metavar="dmesg_name", nargs='?',
                   help="Uses a custom dmesg file instead of the dmesg.txt default file.")
parser.add_argument("-i", "--interactive", action="store_true",
                    help="Interactive mode.")
group.add_argument("-l", "--logcat", default="logcat.txt", metavar="logcat_name", nargs='?',
                   help="Uses a custom logcat file instead of the logcat.txt default file.")
parser.add_argument("-s", "--sanitize", action='store_true',
                    help="Sanitizes logcat file encoding")
parser.add_argument("-v", "--verbose", action='store_true',
                    help="Enable verbose mode: outputs every denial into its respective file.")
args = parser.parse_args()

if not args.oneshot is None:
    print(gen_fix(args.oneshot).strip("\n"))
    sys.exit()

print(f"Giovix92's SELinux denial fixer, {version}.")

if args.cleanup:
    print("Cleaned up!")
    sys.exit()

if args.interactive:
    print("Interactive mode, enter your denials here.")
    print("Use exit/quit to quit this session.")
    while True:
        print("")
        string = input("> ")
        if string == "exit" or string == "quit":
            sys.exit()
        elif string == "clear":
            os.system("clear")
        else:
            try:
                print("Fix:", gen_fix(string).strip("\n"))
            except BaseException:
                print("Invalid denial. Did you type it correctly?")


if args.verbose:
    write = True
    os.makedirs("sepolicy")
    print("Verbose mode enabled!")
    print("Outputting every denial into its respective file.")

if args.dmesg is None or args.dmesg != "dmesg.txt":
    print("Parsing denials from dmesg!")
    logname = args.dmesg
    if args.dmesg is None:
        logname = "dmesg.txt"
    print(f"Using dmesg: {logname}")
    if not os.path.isfile(logname):
        print("Dmesg file is missing! Exiting.")
        sys.exit()
    os.system('cat %s | grep "avc:  denied" > denials.txt' % logname)

if args.logcat is None or logname is None:
    print("Parsing denials from logcat!")
    logname = args.logcat
    if args.logcat is None:
        logname = "logcat.txt"
    print(f"Using logcat: {logname}")
    if not os.path.isfile(logname):
        print("Logcat file is missing! Exiting.")
        sys.exit()
    os.system('cat %s | grep "avc:  denied" > denials.txt' % logname)

if args.sanitize:
    print("Sanitizing file encoding!")
    os.system('dos2unix %s' % logname)
    os.system('cat %s | grep "avc:  denied" > denials.txt' % logname)

if not os.path.isfile(inputfile):
    print("Denials file is missing! Exiting.")
    sys.exit()

with open(inputfile) as denfile:
    data = denfile.read()
data = data.split("\n")
data.remove(data[-1])

# Parsin' the data
for i in data:
    wfixes.append(gen_fix(i))

wfixes = list(dict.fromkeys(wfixes))
for i in wfixes:
    tempvar = i.split(" ")
    if write:
        namefile = "sepolicy/" + tempvar[1].strip("\n").strip(")") + ".te"
    if not os.path.exists(namefile):
        tmp = open(namefile, "w+")
        tmp.close()
    with open(namefile, "a") as ffnew:
        ffnew.write(i)
