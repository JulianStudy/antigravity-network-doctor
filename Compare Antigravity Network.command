#!/bin/zsh
cd -- "${0:A:h}" || exit 1
if ! command -v python3 >/dev/null 2>&1; then
    print -u2 '需要 Python 3.9 或更高版本。安装后重新运行此文件。'
    exit 1
fi
exec python3 ./agy_doctor.py wizard
