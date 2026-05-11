#!/bin/bash

# 设置工作目录为当前脚本所在的目录，或者你可以改成固定的绝对路径
WORK_DIR=$(pwd)
ME="$(basename "$0")"  # 记住自己的名字，防止套娃

# 默认排除的脚本关键词（多个用 | 隔开）
EXCLUDE_PATTERNS="run_py_kyber768_test_ver"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 信号处理：Ctrl+C 安全退出
trap 'echo -e "\n${YELLOW}用户中断，退出。${NC}"; exit 0' INT

show_menu() {
    echo ""
    echo "================================================="
    echo "当前工作目录: $WORK_DIR"
    echo "================================================="
    echo "1. 执行全部 .sh 脚本 (自动跳过已 PASS 的)"
    echo "2. 按关键词过滤执行 .sh 脚本"
    echo "3. 强制运行全部 .sh 脚本 (无视 PASS 状态，不含 Py 测试)"
    echo "4. 单独执行 Python Kyber768 测试 (ver0/1/2)"
    echo "5. 删除全部 sim_standalone.log 文件"
    echo "0. 退出"
    echo "================================================="
}

run_scripts() {
    local filter="$1"
    local force="${2:-0}"
    local count=0
    local fail=0
    local pass_count=0
    local skip_count=0

    while IFS= read -r script; do
        count=$((count + 1))
        echo -e "\n${YELLOW}========================================${NC}"
        echo -e "${YELLOW}[$count] 检查: $script${NC}"
        echo -e "${YELLOW}========================================${NC}"

        if [ ! -x "$script" ]; then
            echo -e "${YELLOW}>>> 脚本缺少执行权限，自动 chmod +x ...${NC}"
            chmod +x "$script" || {
                echo -e "${RED}!!! chmod 失败，跳过: $script${NC}"
                fail=$((fail + 1))
                continue
            }
        fi

        local ABS_SCRIPT
        ABS_SCRIPT=$(realpath "$script")
        local SCRIPT_DIR
        SCRIPT_DIR="$(dirname "$ABS_SCRIPT")"
        local ELF_DIR="$SCRIPT_DIR/tmp-kybertest"
        local LOG_FILE="$ELF_DIR/sim_test.log"

        if [ -f "$LOG_FILE" ] && grep -q "ERROR" "$LOG_FILE"; then
            echo -e "${RED}>>> 发现 $LOG_FILE 中包含 ERROR。${NC}"
            echo -e "${RED}>>> 正在打印 sim_test.log 详情：${NC}"
            cat "$LOG_FILE"
            rm -f "$LOG_FILE"
            echo -e "${YELLOW}>>> 已删除错误日志，准备重新执行...${NC}"
        fi

        if [ "$force" != "1" ] && [ -f "$LOG_FILE" ] && grep -q "PASS" "$LOG_FILE"; then
            echo -e "${GREEN}>>> PASS 已存在，跳过。${NC}"
            skip_count=$((skip_count + 1))
            pass_count=$((pass_count + 1))
        else
            if [ -f "$LOG_FILE" ]; then
                echo ">>> 发现 sim_test.log 但未检测到 PASS，重新执行..."
            else
                echo ">>> 未发现 sim_test.log，开始执行..."
            fi

            (cd "$SCRIPT_DIR" && bash "./$(basename "$ABS_SCRIPT")")
            local exit_code=$?

            if [ $exit_code -ne 0 ]; then
                echo -e "${RED}!!! 执行失败: $script (退出码: $exit_code)${NC}"
                fail=$((fail + 1))
                echo -e "${RED}>>> 尝试打印本次运行的 sim_test.log：${NC}"
                if [ -f "$LOG_FILE" ]; then
                    cat "$LOG_FILE"
                else
                    echo -e "${YELLOW}>>> 警告: 执行失败且未找到 $LOG_FILE${NC}"
                fi
                echo -e "${RED}!!! 任务中止，共处理 $count 个脚本（失败 $fail，跳过 $skip_count）。${NC}"
                return 1
            fi
            pass_count=$((pass_count + 1))
            echo -e "${GREEN}>>> 成功完成: $script${NC}"
        fi
    done < <(find "$WORK_DIR" -maxdepth 4 -type f -name "*.sh" -not -name "$ME" | sort | { [ -n "$EXCLUDE_PATTERNS" ] && grep -vE "$EXCLUDE_PATTERNS" || cat; } | grep -E "$filter")

    echo ""
    echo -e "${GREEN}=================================================${NC}"
    echo -e "${GREEN}  任务完成！${NC}"
    echo -e "${GREEN}  总计: $count 个脚本${NC}"
    echo -e "${GREEN}  成功: $pass_count | 跳过: $skip_count | 失败: $fail${NC}"
    echo -e "${GREEN}=================================================${NC}"

    if [ $fail -eq 0 ] && [ $count -gt 0 ]; then
        return 0
    elif [ $count -eq 0 ]; then
        echo -e "${YELLOW}>>> 未找到匹配的脚本。${NC}"
        return 0
    else
        return 1
    fi
}

select_and_run_py() {
    local py_scripts=()
    
    while IFS= read -r script; do
        py_scripts+=("$script")
    done < <(find "$WORK_DIR" -maxdepth 4 -type f -name "run_py_kyber768_test_ver*.sh" -not -name "$ME" | sort)

    if [ ${#py_scripts[@]} -eq 0 ]; then
        echo -e "${YELLOW}>>> 未找到任何 Python Kyber768 测试脚本。${NC}"
        return
    fi

    echo "找到以下 Python Kyber768 测试脚本："
    for i in "${!py_scripts[@]}"; do
        echo "  $((i+1))) $(basename "${py_scripts[$i]}")"
    done
    echo "-------------------------------------------------"
    echo "请输入要执行的编号(如: 1 3)，输入 'a' 执行全部，输入 'q' 取消:"
    read -r -p "> " choice < /dev/tty

    if [[ "$choice" == "q" || "$choice" == "Q" ]]; then
        echo "已取消。"
        return
    fi

    local selected_filter=""
    if [[ "$choice" == "a" || "$choice" == "A" ]]; then
        selected_filter="run_py_kyber768_test_ver"
    else
        for num in $choice; do
            if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le ${#py_scripts[@]} ]; then
                idx=$((num-1))
                local fname
                fname=$(basename "${py_scripts[$idx]}")
                fname="${fname//./\\.}"
                
                if [ -z "$selected_filter" ]; then
                    selected_filter="$fname"
                else
                    selected_filter="$selected_filter|$fname"
                fi
            else
                echo -e "${RED}无效编号: $num，已取消操作。${NC}"
                return 1
            fi
        done
    fi

    EXCLUDE_PATTERNS=""
    run_scripts "$selected_filter"
}

clean_logs() {
    local filter="$1"
    local logs=()

    while IFS= read -r log; do
        logs+=("$log")
    done < <(find "$WORK_DIR" -path "*/tmp-kybertest/sim_standalone.log" | sort | grep -E "$filter")

    if [ ${#logs[@]} -eq 0 ]; then
        echo -e "${YELLOW}>>> 未找到匹配的 sim_standalone.log 文件。${NC}"
        return
    fi

    echo "找到以下 ${#logs[@]} 个 sim_standalone.log 文件："
    for i in "${!logs[@]}"; do
        echo "  $((i+1))) ${logs[$i]}"
    done
    echo "-------------------------------------------------"
    echo "请输入要删除的编号(如: 1 3 5)，输入 'a' 删除全部，输入 'q' 取消:"
    read -r -p "> " choice < /dev/tty

    if [[ "$choice" == "q" || "$choice" == "Q" ]]; then
        echo "已取消。"
        return
    fi

    if [[ "$choice" == "a" || "$choice" == "A" ]]; then
        rm -f "${logs[@]}"
        echo -e "${GREEN}>>> 已成功删除全部 ${#logs[@]} 个 sim_standalone.log 文件。${NC}"
        return
    fi

    local deleted=0
    for num in $choice; do
        if [[ "$num" =~ ^[0-9]+$ ]] && [ "$num" -ge 1 ] && [ "$num" -le ${#logs[@]} ]; then
            idx=$((num-1))
            rm -f "${logs[$idx]}"
            echo -e "${GREEN}已删除: ${logs[$idx]}${NC}"
            deleted=$((deleted + 1))
        else
            echo -e "${RED}无效编号: $num${NC}"
        fi
    done

    if [ $deleted -gt 0 ]; then
        echo -e "${GREEN}>>> 共删除 $deleted 个文件。${NC}"
    fi
}

# 主循环
while true; do
    show_menu
    read -r -p "请输入选项 [0-5]: " opt < /dev/tty
    case $opt in
        1)
            EXCLUDE_PATTERNS="run_py_kyber768_test_ver"
            run_scripts ".*"
            ;;
        2)
            read -r -p "请输入过滤关键词 (例如 ver1, hkdf, hmac): " keyword < /dev/tty
            if [ -z "$keyword" ]; then keyword=".*"; fi
            EXCLUDE_PATTERNS="run_py_kyber768_test_ver"
            run_scripts "$keyword"
            ;;
        3)
            EXCLUDE_PATTERNS="run_py_kyber768_test_ver"
            run_scripts ".*" "1"
            ;;
        4)
            select_and_run_py
            ;;
        5)
            clean_logs ".*"
            ;;
        0)
            echo "退出。"
            exit 0
            ;;
        *)
            echo -e "${RED}无效选项，请重新输入。${NC}"
            ;;
    esac
done
