from binaryninja import PluginCommand, BinaryView
from .deflat2 import deflat_cursor, deflat_nested, deflat_manual, deflat_with_check
from .dejmpreg import dejmpreg_auto, dejmpreg_cursor, dejmpreg_manual

def is_valid(bv: BinaryView, address: int) -> bool:
    return True

PluginCommand.register_for_address("detx\\deflat2\\deflat use this var", "use the variable on the line where the cursor is located as the switch variable", deflat_cursor, is_valid)
PluginCommand.register_for_address("detx\\deflat2\\deflat nested", "deflat nested at current cursor", deflat_nested, is_valid)
PluginCommand.register_for_address("detx\\deflat2\\deflat manual", "deflat use usr set value", deflat_manual, is_valid)
PluginCommand.register_for_address("detx\\deflat2\\deflat with check", "deflat with extra check", deflat_with_check, is_valid)

PluginCommand.register_for_address("detx\\dejmpreg\\dejmpreg here once", "remove jump reg obf here once", dejmpreg_cursor, is_valid)
PluginCommand.register_for_address("detx\\dejmpreg\\dejmpreg manual", "remove jump reg manual here once", dejmpreg_manual, is_valid)
PluginCommand.register_for_function("detx\\dejmpreg\\dejmpreg auto", "auto search jump reg insn", dejmpreg_auto, is_valid)

