import binaryninja
from .golang_symbol_restore import restore_golang_symbols

binaryninja.plugin.PluginCommand.register("Restore Golang Symbols",
                                          "Fill region with breakpoint instructions.",
                                          restore_golang_symbols)
