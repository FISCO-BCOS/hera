#!/bin/sh

sed -iE 's/COMMAND python /COMMAND /' src/passes/CMakeLists.txt
sed -iE 's/\#\!/usr/bin/env python/#!/usr/bin/env python2/' scripts/embedwast.py
