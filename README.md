# PasswordManage-PC

## 模块
- **加密**：`Crypto/`（`CryptoService` AES-GCM、`RecordEncryptor`、`MasterPasswordVerifier`）
- **主密码验证**：`MasterPasswordVerifier`（Argon2id + HKDF-SHA256 RFC5869 + verifier）
- **数据库**：`Data/`（`VaultDatabase` + `VaultRepository`，SQLCipher）
- **单元测试**：`Tests/`（xUnit）

## 运行单元测试
需 **.NET 8 SDK**（Windows）。在仓库内执行：

```powershell
dotnet test "Tests\PasswordManage.PC.Tests.csproj"
```

## 建表 SQL
见 `schema/vault_schema.sql`。
