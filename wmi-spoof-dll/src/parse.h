// ============================================================================
//  parse.h —— WQL / 对象路径解析与 VARIANT 辅助（纯逻辑，可独立单测）
// ============================================================================
#pragma once

#include <windows.h>

#include <string>

// 从 WQL 中解析 FROM 后面的类名，返回小写形式；解析失败返回空串。
// 例："SELECT * FROM Win32_BaseBoard" -> L"win32_baseboard"
std::wstring ParseQueryClass(const wchar_t* wql);

// 从对象路径解析类名（小写）与实例判定；isInstance 指出路径是否含 '='。
// 详见 parse.cpp 处的形态示例与已知限制说明。
std::wstring ParseObjectPathClass(const wchar_t* path, bool* isInstance);

// 把任意 VARIANT 转成可读字符串（仅用于日志展示原值）
std::wstring VariantToString(const VARIANT& v);
