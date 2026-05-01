using System.IO;

namespace PasswordManage.PC;

/// <summary>便携版（解压即用）：数据位于可执行文件所在目录下的 <c>VaultData</c>，不写入「安装目录」式 AppData。</summary>
public static class VaultPaths
{
    public const string VaultDataFolderName = "VaultData";

    public static string GetPortableVaultDirectory()
    {
        var baseDir = AppContext.BaseDirectory;
        var dir = Path.GetFullPath(Path.Combine(baseDir, VaultDataFolderName));
        Directory.CreateDirectory(dir);
        return dir;
    }
}
