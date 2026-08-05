from elftools.elf.elffile import ELFFile
import sys


def parse_dwarf_symbols(elf_path):
    results = []

    with open(elf_path, "rb") as f:
        elffile = ELFFile(f)

        dwarfinfo = elffile.get_dwarf_info()

        # 1. 第一步：解析 DIE 树，收集所有函数的名称及其起始/结束地址范围
        functions = []
        for cu in dwarfinfo.iter_CUs():
            for die in cu.iter_DIEs():
                if die.tag == "DW_TAG_subprogram":
                    # 获取函数名
                    name_attr = die.attributes.get("DW_AT_name")
                    func_name = (
                        name_attr.value.decode("utf-8")
                        if name_attr
                        else "<unknown>"
                    )

                    # 获取函数的低低地址 (low_pc) 和高地址 (high_pc)
                    low_pc_attr = die.attributes.get("DW_AT_low_pc")
                    high_pc_attr = die.attributes.get("DW_AT_high_pc")

                    if low_pc_attr and high_pc_attr:
                        low_pc = low_pc_attr.value
                        high_pc = high_pc_attr.value
                        # high_pc 有可能是相对 low_pc 的偏移值 (form 为 offset)
                        if (
                            high_pc_attr.form.startswith("DW_FORM_data")
                            or high_pc_attr.form == "DW_FORM_udata"
                        ):
                            high_pc += low_pc

                        functions.append({
                            "name": func_name,
                            "low_pc": low_pc,
                            "high_pc": high_pc,
                        })

        # 辅助函数：根据地址匹配函数名
        def find_function_name(pc):
            for func in functions:
                if func["low_pc"] <= pc < func["high_pc"]:
                    return func["name"]
            return "<unknown>"
        pass
        # 2. 第二步：遍历每个编译单元 (CU) 的行表 (Line Table)
        for cu in dwarfinfo.iter_CUs():
            line_program = dwarfinfo.line_program_for_CU(cu)
            if line_program is None:
                continue

            # 获取当前 CU 的源文件列表
            file_entries = line_program["file_entry"]

            # 遍历状态机输出的每一行映射 entry
            for entry in line_program.get_entries():
                state = entry.state
                # 过滤有效指令状态（非行表重置标识、且行号不为 0）
                if state is None or state.line == 0 or state.end_sequence:
                    continue

                # 获取文件名（索引从 1 开始）
                file_idx = state.file - 1
                if 0 <= file_idx < len(file_entries):
                    file_name = file_entries[file_idx].name.decode("utf-8")
                else:
                    file_name = "<unknown>"

                pc_addr = state.address
                func_name = find_function_name(pc_addr)

                results.append({
                    "addr": pc_addr,
                    "func": func_name,
                    "file": file_name,
                    "line": state.line,
                    "addr%p": hex(pc_addr),
                })

    return results

def write_to_stdout(dct):
    s = ',\n'.join([f'{{0x{_["addr%p"][2:]}, "{_["file"]}", "{_["func"]}()", {_["line"]}}}' for _ in dct])


    print(f"""#include "kernel/types.h"\n"""
          f"""#include "kernel/symbols.h"\n"""
          f"""const struct symbol symbols[] = {{ \n
    {s}
    \n}};\nconst int num_symbols = sizeof(symbols) / sizeof(symbols[0]);
""")

def main():
    if len(sys.argv) != 2:
        exit(1)
    symbols = parse_dwarf_symbols(sys.argv[1])
    # write to symbol.c
    write_to_stdout(symbols)


# --- 使用示例 ---
if __name__ == "__main__":
    main()