# yara-forensics-rules
A collection of yara rules that can be used for forensics (non malware) cases

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0) [![DFIR: Yara rules](https://img.shields.io/badge/DFIR-Yara%20Rules-brightgreen.svg)](https://yararules.com) [![Travis build](https://travis-ci.org/Xumeiquer/yara-forensics.svg)](https://github.com/Xumeiquer/yara-forensics)

`Yara` is the pattern matching swiss knife for malware researchers (and everyone else). Basically `Yara` allow us to scan files based on textual or binary patterns, thus we can take advantage of `Yara`'s potential and focus it in forensic investigations.

# Reason

If you start analysing a forensic image, a fast way to detect certain files like password safes is by using yara.
It can also be used to hunt on file repositories for interesting files.

# Malware

This repo is not meant to cover yara rules in regard to malware / rootkits / threat actors.

# Other projects

* https://github.com/Xumeiquer/yara-forensics focuses only on detecting magic bytes
