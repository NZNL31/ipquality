#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 ipquality 目录登记进「用户级」PATH，之后任意目录可直接用 ipq 命令。

只改 HKCU\\Environment\\Path（当前用户），不碰系统 PATH，不需要管理员权限。
可随时用 --remove 撤销。

用法：
    python install_path.py           加入 PATH
    python install_path.py --remove  从 PATH 移除
    python install_path.py --status  只查看当前是否已加入
"""
import ctypes
import os
import sys
import winreg

TARGET = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = r"Environment"
NAME = "Path"


def _read():
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY, 0,
                        winreg.KEY_READ) as key:
        try:
            val, typ = winreg.QueryValueEx(key, NAME)
            return val, typ
        except FileNotFoundError:
            return "", winreg.REG_EXPAND_SZ


def _write(value, typ):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, KEY, 0,
                        winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, NAME, 0, typ, value)


def _broadcast():
    """通知资源管理器环境变量已变，新开的终端才会读到。"""
    HWND_BROADCAST, WM_SETTINGCHANGE, SMTO_ABORTIFHUNG = 0xFFFF, 0x001A, 0x0002
    try:
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment",
            SMTO_ABORTIFHUNG, 3000, ctypes.byref(ctypes.c_void_p()))
    except Exception:
        pass


def _parts(value):
    return [p for p in (value or "").split(";") if p.strip()]


def main(argv):
    cur, typ = _read()
    parts = _parts(cur)
    present = any(os.path.normcase(p.strip()) == os.path.normcase(TARGET)
                  for p in parts)

    if "--status" in argv:
        print("目标目录：%s" % TARGET)
        print("当前状态：%s" % ("已在用户 PATH 中" if present else "未加入"))
        print("用户 PATH 条目数：%d" % len(parts))
        return 0

    if "--remove" in argv:
        if not present:
            print("未加入，无需移除。")
            return 0
        kept = [p for p in parts
                if os.path.normcase(p.strip()) != os.path.normcase(TARGET)]
        _write(";".join(kept), typ)
        _broadcast()
        print("已从用户 PATH 移除：%s" % TARGET)
        return 0

    if present:
        print("已在用户 PATH 中，无需重复添加。")
        print("新开一个终端即可用： ipq 1.2.3.4")
        return 0

    parts.append(TARGET)
    _write(";".join(parts), typ)
    _broadcast()
    print("已加入用户 PATH：%s" % TARGET)
    print("条目数：%d -> %d" % (len(parts) - 1, len(parts)))
    print()
    print("请【关闭并重开】终端，之后任意目录可直接运行：")
    print("    ipq 1.2.3.4")
    print("撤销： install.cmd --remove")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
