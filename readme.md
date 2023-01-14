# pe-packer
Simple pe file packer

## Using
``pinkie-pie.exe [in] [out] [-key] [-obf]``  
Before using disable ASLR (/DYNAMICBASE:NO)

## Changelog
- v0.3
    - Added WinAPI calls obfuscation (``-obf``)
    - Added argument ``-key`` which specifies length of key
- v0.2
    - Added argument parser
    - Updated sections parser
    - Minor changes

## To do
- Support for data sections
- ASLR support