#!/usr/bin/env python3

# List the least amount of smali files of Java classes
# that we can modify and are reachable from the inheritance
# tree of all the provided fully qualified names

import argparse
import os
import sys
import glob
import re

classes_to_modify = set() # Set of classes to modify

parser = argparse.ArgumentParser()
parser.add_argument("package_id", help="Package id")
parser.add_argument("fqns", nargs='+', help="Java fully qualified names")
parser.add_argument("--apk-path", dest='path', help="Path to decoded APK", default=os.getcwd())

args = parser.parse_args()
if not args.fqns:
    parser.error("No Java fully qualified names provided")

apkdir = args.path
super_re = re.compile('.super L(.+);$');

def get_smali_path(fqn):
    smali_path = glob.glob("{}/smali*/{}.smali".format(apkdir, "/".join(fqn.split('.'))))
    if len(smali_path) == 0:
        return None
    elif len(smali_path) > 1:
        raise Exception("Found multiple smali files for Java class: {}".format(fqn))
    return smali_path[0]

for fqn in args.fqns:
    if fqn.startswith("."):
        fqn = args.package_id + fqn
    elif not "." in fqn and get_smali_path(fqn) is None:
        # Names without dot prefix still resolve to classes relative to package id
        fqn = args.package_id + "." + fqn

    smali_path = get_smali_path(fqn)
    if smali_path is None:
        sys.stderr.write("No smali file found for given Java class: {} Does the manifest refer to components that have been removed?\n".format(fqn))
        continue
    while True:
        with open(smali_path) as f:
            superclass = ""
            for line in f:
                match = super_re.search(line)
                if match is not None:
                    superclass = match.group(1)
                    break
            # Each class has a superclass. All classes inherit from java.lang.Object
            if not superclass:
                raise Exception("No superclass found for smali file: " + smali_path)
            # Convert super class entity name to fqn
            superclass = ".".join(superclass.split('/'))
            superclass_smali_path = get_smali_path(superclass)
            if superclass_smali_path is None:
                # We assume the superclass is part of the Android Framework that we can't modify
                classes_to_modify.add(smali_path)
                break
            else:
                smali_path = get_smali_path(superclass)

for c in classes_to_modify:
    print(c)

