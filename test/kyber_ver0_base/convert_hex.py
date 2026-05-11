import sys

def reverse_hex_content(input_path, output_path=None):
    """
    读取文件中的十六进制字符串，执行：
    1. 整体行序反转（最后一行变第一行）
    2. 每行内部 8 组数值顺序反转
    然后输出格式化后的结果。
    """
    with open(input_path, 'r') as f:
        # 按空白分割得到所有 token（每个 token 是一个 8 字符十六进制串）
        tokens = f.read().split()

    # 每 8 个 token 为一行
    lines = [tokens[i:i+8] for i in range(0, len(tokens), 8)]

    # 整体行序反转
    lines.reverse()

    # 每行内部 token 顺序反转
    reversed_lines = [line[::-1] for line in lines]

    # 格式化为每行空格分隔
    result = '\n'.join(' '.join(line) for line in reversed_lines)

    if output_path:
        with open(output_path, 'w') as f:
            f.write(result)
        print(f"反转结果已保存至: {output_path}")
    else:
        print(result)


def process_hex_file(input_path, output_path=None):
    """
    原功能：将任意格式的十六进制字符串整理为每行 8 组、每组 8 个字符的格式。
    """
    with open(input_path, 'r') as f:
        hex_str = ''.join(f.read().split())

    lines = [hex_str[i:i+64] for i in range(0, len(hex_str), 64)]
    if not lines:
        return

    formatted_lines = []
    for line in lines:
        groups = [line[i:i+8] for i in range(0, 64, 8)]
        formatted_lines.append(' '.join(groups))

    result = '\n'.join(formatted_lines)
    if output_path:
        with open(output_path, 'w') as f:
            f.write(result)
        print(f"结果已保存至: {output_path}")
    else:
        print(result)


def full_process_and_concat(input_path):
    """
    执行完整流程：
    1. 读取并格式化为每行8组、每组8字符（64字符/行）
    2. 行序反转 + 组内反转
    3. 拼接为一行连续的十六进制字符串
    返回该字符串
    """
    with open(input_path, 'r') as f:
        # 移除所有空白字符，得到纯十六进制字符串
        hex_str = ''.join(f.read().split())

    # 步骤1：分割为每行64字符（32字节）
    lines = [hex_str[i:i+64] for i in range(0, len(hex_str), 64)]

    # 步骤2：每行内部拆分为8组
    grouped_lines = []
    for line in lines:
        groups = [line[i:i+8] for i in range(0, 64, 8)]
        grouped_lines.append(groups)

    # 步骤3：整体行序反转
    grouped_lines.reverse()

    # 步骤4：每行内部组序反转
    reversed_grouped_lines = [line[::-1] for line in grouped_lines]

    # 步骤5：拼接为连续字符串
    result = ''.join(''.join(groups) for groups in reversed_grouped_lines)

    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法:")
        print("  格式化: python convert_hex.py <输入文件.txt> [输出文件.txt]")
        print("  反转  : python convert_hex.py -r <输入文件.txt> [输出文件.txt]")
        print("  拼接  : python convert_hex.py -j <输入文件.txt> [输出文件.txt]")
        sys.exit(1)

    if sys.argv[1] == '-r':
        # 原有反转功能
        if len(sys.argv) < 3:
            print("错误: 缺少输入文件")
            sys.exit(1)
        input_file = sys.argv[2]
        output_file = sys.argv[3] if len(sys.argv) > 3 else None
        reverse_hex_content(input_file, output_file)

    elif sys.argv[1] == '-j':
        # 新增拼接功能
        if len(sys.argv) < 3:
            print("错误: 缺少输入文件")
            sys.exit(1)
        input_file = sys.argv[2]
        output_file = sys.argv[3] if len(sys.argv) > 3 else None
        concated = full_process_and_concat(input_file)
        if output_file:
            with open(output_file, 'w') as f:
                f.write(concated)
            print(f"拼接结果已保存至: {output_file}")
        else:
            print(concated)

    else:
        # 原有格式化功能
        input_file = sys.argv[1]
        output_file = sys.argv[2] if len(sys.argv) > 2 else None
        process_hex_file(input_file, output_file)