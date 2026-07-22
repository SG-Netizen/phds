# 贡献指南

感谢你对 PHDS（个人健康数据主权协议）的关注！我们欢迎所有形式的贡献。

## 行为准则

请保持专业、尊重和建设性的交流氛围。我们致力于为所有人提供一个友好、包容的协作环境。

---

## 如何参与贡献

### 提交 Issue

如果你发现了 bug、有功能建议或使用问题，请在 GitHub Issues 中提交：

1. 搜索已有 Issue，确认没有重复
2. 使用清晰的标题
3. 提供以下信息：
   - **环境**：操作系统、Python 版本、依赖版本
   - **复现步骤**：详细的步骤和代码示例
   - **期望行为** vs **实际行为**
   - **截图或错误日志**（如果有）

### 提交 Pull Request

1. **Fork 本仓库**，克隆到本地
2. **创建功能分支**：`git checkout -b feature/your-feature-name`
3. **编写代码**（遵循下方代码规范）
4. **运行测试**：`python -m pytest tests/ -v`
5. **提交变更**：使用清晰的 commit message
6. **推送分支**：`git push origin feature/your-feature-name`
7. **发起 Pull Request**，描述变更内容和解决的问题

---

## 代码规范

### Python 版本

- 最低支持 Python 3.10
- 使用 f-string、类型注解等现代特性

### 代码风格

- 遵循 [PEP 8](https://peps.python.org/pep-0008/) 风格指南
- 使用 4 空格缩进，不使用 Tab
- 每行不超过 120 字符
- 注释和 docstring 使用**中文**
- 所有公有函数/类必须有 docstring（Google 风格）
- 所有函数参数和返回值必须有类型注解

### 示例

```python
def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """使用 AES-256-GCM 加密数据。

    Args:
        key:       32 字节 AES 密钥
        plaintext: 明文数据

    Returns:
        密文（nonce + tag + ciphertext 拼接）

    Raises:
        ValueError: 密钥长度不正确
    """
    ...
```

### 命名规范

| 类型 | 规范 | 示例 |
|------|------|------|
| 模块/文件 | 小写下划线 | `bio_record.py` |
| 类 | 大驼峰 | `BioRecord` |
| 函数/方法 | 小写下划线 | `generate_keypair()` |
| 常量 | 大写下划线 | `DEFAULT_EXPIRE_SECONDS` |
| 私有成员 | 前缀下划线 | `_mine()` |

---

## 测试要求

### 运行测试

```bash
# 运行所有测试
python -m pytest tests/ -v

# 运行特定测试文件
python -m pytest tests/test_core.py -v
python -m pytest tests/test_chain.py -v
```

### 测试规范

- 使用 Python 标准库 `unittest`
- 每个模块对应一个测试文件（`tests/test_<module>.py`）
- 测试方法以 `test_` 开头
- 覆盖正常路径、边界条件和异常路径
- 新增功能必须有对应测试用例
- 提交 PR 前确保所有测试通过

---

## 项目结构约定

- `sdk/core/` — 核心密码学模块（密钥、加密、授权、链存证）
- `sdk/records/` — 数据结构定义
- `sdk/api/` — FastAPI 接口
- `demo/` — 可运行的演示脚本
- `tests/` — 单元测试
- `docs/` — 项目文档

新增模块遵循相同层次结构。SDK 内部使用相对导入，Demo 和测试使用 `from sdk.xxx` 导入。

---

## 问题反馈渠道

- **GitHub Issues**：[提交 Issue](https://github.com/SG-Netizen/phds/issues)

---

再次感谢你的贡献！
