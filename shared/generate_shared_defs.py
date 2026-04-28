import csv
import pathlib
import sys




def read_rows(csv_path):
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_error_c_header(rows, out_path):
    lines = [
        "#pragma once",
        "",
        "/* Auto-generated from shared/errors.csv. Do not edit directly. */",
        "",
    ]
    for row in rows:
        lines.append(f"#define {row['name']} {row['code']}")
    lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")


def write_error_python_module(rows, out_path):
    lines = []
    for row in rows:
        lines.append(f"{row['name']} = {row['code']}")
    lines.append("")
    lines.append("ERROR_MESSAGES = {")
    for row in rows:
        lines.append(f"    {row['name']}: {row['message']!r},")
    lines.append("}")
    lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")


def write_command_c_header(rows, out_path,C2_HOST,C2_PORT):
    lines = [
        "#pragma once",
        "",
        f'#define C2_HOST L"{C2_HOST}" ',
        f'#define C2_PORT L"{C2_PORT}" ',
        "",
        "/* Auto-generated from shared/commands.csv. Do not edit directly. */",
        "",
        "typedef enum _CMD_ID",
        "{",
    ]

    for row in rows:
        lines.append(f"    {row['const_name']} = {row['id']},")

    lines.extend(
        [
            "    CMD_UNK",
            "} CMD_ID;",
            "",
        ]
    )

    out_path.write_text("\n".join(lines), encoding="utf-8")


def write_command_python_module(rows, out_path):
    lines = []

    for row in rows:
        lines.append(f"{row['const_name']} = {row['id']}")

    lines.extend(
        [
            "",
            "COMMAND_SPECS = [",
        ]
    )

    for row in rows:
        lines.append(
            "    {"
            f"'id': {row['const_name']}, "
            f"'name': {row['command_name']!r}, "
            f"'usage': {row['usage']!r}, "
            f"'description': {row['description']!r}"
            "},"
        )

    lines.extend(
        [
            "]",
            "",
            "CMD_NAMES = {spec['id']: spec['name'] for spec in COMMAND_SPECS}",
            "CMD_IDS = {spec['name']: spec['id'] for spec in COMMAND_SPECS}",
            "",
        ]
    )

    out_path.write_text("\n".join(lines), encoding="utf-8")


def main():
    if len(sys.argv) != 4   :
        raise SystemExit("usage: generate_shared_defs.py <project_root> <C2 HOST> <C2 PORT>")


    try: 
        C2_HOST = sys.argv[2]#"127.0.0.1"
        C2_PORT = int(sys.argv[3])#9002
        C2_PORT = sys.argv[3]

    except ValueError:
	    sys.exit("Error: Invalid Port C2 port")
    root = pathlib.Path(sys.argv[1]).resolve()

    error_rows = read_rows(root / "shared" / "errors.csv")
    command_rows = read_rows(root / "shared" / "commands.csv")

    write_error_c_header(error_rows, root / "include" / "generated_errors.h")
    write_error_python_module(error_rows, root / "server" / "errors.py")
    write_command_c_header(command_rows, root / "include" / "generated_commands.h",C2_HOST,C2_PORT)
    write_command_python_module(command_rows, root / "server" / "commands.py")


if __name__ == "__main__":
    main()
