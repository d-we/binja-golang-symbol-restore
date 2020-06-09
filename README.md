# Golang Symbol Restore (v1.0)
Author: **Daniel Weber**

_Binary Ninja plugin for restoring function names from stripped Golang binaries._
## Description:
The plugin parses the section `.gopclntab` where Golang stores debug symbols and restores 
the function names. If there is no section named `.gopclntab` it will try to search for the section.

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

 *  2.0.2170


## Required Dependencies

The following dependencies are required for this plugin:

 * Python 3.6


## License

This plugin is released under a MIT license.
## Metadata Version

2
