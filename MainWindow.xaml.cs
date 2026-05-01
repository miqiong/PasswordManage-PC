using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using System.Windows.Threading;
using PasswordManage.PC.Crypto;
using PasswordManage.PC.Data;

namespace PasswordManage.PC;

public partial class MainWindow : Window
{
    private const int MinMasterPasswordLength = 12;
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(10);

    private readonly string _vaultDir = VaultPaths.GetPortableVaultDirectory();

    private readonly MasterPasswordVerifier _mpv = new();
    private readonly MetaStore _meta;
    private readonly SessionSwitchEventHandler _sessionSwitchHandler;
    private readonly PowerModeChangedEventHandler _powerModeHandler;

    private byte[]? _kek;
    private VaultDatabase? _db;
    private VaultRepository? _repo;
    private RecordEncryptor? _enc;
    private readonly CryptoService _crypto = new();
    private bool _vaultExists;

    private DispatcherTimer? _idleTimer;
    private DateTime _lastActivityUtc = DateTime.UtcNow;

    private sealed record VaultListItem(string RecordId, string UpdatedAt, int Version)
    {
        public string Summary => $"{UpdatedAt}  ·  {RecordId}";
    }

    public MainWindow()
    {
        InitializeComponent();
        _meta = new MetaStore(_vaultDir);

        _sessionSwitchHandler = (_, e) =>
        {
            if (e.Reason == SessionSwitchReason.SessionLock)
                Dispatcher.BeginInvoke((Action)LockVault);
        };
        SystemEvents.SessionSwitch += _sessionSwitchHandler;

        _powerModeHandler = (_, e) =>
        {
            if (e.Mode == PowerModes.Suspend)
                Dispatcher.BeginInvoke((Action)LockVault);
        };
        SystemEvents.PowerModeChanged += _powerModeHandler;

        PreviewMouseDown += OnUserActivity;
        PreviewKeyDown += OnUserActivity;

        Loaded += (_, _) => RefreshUnlockUi();
    }

    private void OnUserActivity(object sender, InputEventArgs e)
    {
        if (_kek != null && ListPanel.Visibility == Visibility.Visible)
            _lastActivityUtc = DateTime.UtcNow;
    }

    private void EnsureIdleTimer()
    {
        if (_idleTimer != null) return;
        _idleTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(15) };
        _idleTimer.Tick += (_, _) =>
        {
            if (_kek == null || ListPanel.Visibility != Visibility.Visible) return;
            if (DateTime.UtcNow - _lastActivityUtc > IdleTimeout)
                LockVault();
        };
    }

    private void StartIdleTimer()
    {
        EnsureIdleTimer();
        _lastActivityUtc = DateTime.UtcNow;
        _idleTimer!.Start();
    }

    private void StopIdleTimer() => _idleTimer?.Stop();

    private void RefreshUnlockUi()
    {
        Directory.CreateDirectory(_vaultDir);
        _vaultExists = _meta.Exists;
        HintText.Text = _vaultExists ? "输入主密码以解锁" : $"创建主密码（至少 {MinMasterPasswordLength} 位）";
        PrimaryButton.Content = _vaultExists ? "解锁" : "创建并打开";
        ErrorText.Visibility = Visibility.Collapsed;
        MasterPasswordBox.Clear();
    }

    private void OnPrimaryClick(object sender, RoutedEventArgs e)
    {
        ErrorText.Visibility = Visibility.Collapsed;
        var pwdText = MasterPasswordBox.Password;
        if (string.IsNullOrEmpty(pwdText) || (!_vaultExists && pwdText.Length < MinMasterPasswordLength))
        {
            ErrorText.Text = _vaultExists ? "请输入主密码" : $"主密码至少 {MinMasterPasswordLength} 位";
            ErrorText.Visibility = Visibility.Visible;
            return;
        }

        var pwd = System.Text.Encoding.UTF8.GetBytes(pwdText);
        try
        {
            if (!_vaultExists)
            {
                var salt = new byte[16];
                RandomNumberGenerator.Fill(salt);
                try
                {
                    var (kek, verifier) = _mpv.DeriveKekAndVerifier(pwd, salt);
                    try
                    {
                        _meta.Write(salt, verifier);
                        OpenVault(kek);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(verifier);
                        CryptographicOperations.ZeroMemory(kek);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(salt);
                }
            }
            else
            {
                if (!_meta.TryRead(out var salt, out var verifier))
                {
                    ErrorText.Text = "无法读取保管库元数据";
                    ErrorText.Visibility = Visibility.Visible;
                    return;
                }
                try
                {
                    if (!_mpv.VerifyMasterPassword(pwd, salt, verifier))
                    {
                        ErrorText.Text = "主密码错误";
                        ErrorText.Visibility = Visibility.Visible;
                        return;
                    }
                    var mk = _mpv.DeriveMasterKey(pwd, salt);
                    try
                    {
                        var kek = _mpv.DeriveKek(mk);
                        try
                        {
                            OpenVault(kek);
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(kek);
                        }
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(mk);
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(salt);
                    CryptographicOperations.ZeroMemory(verifier);
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(pwd);
            MasterPasswordBox.Clear();
        }
    }

    private void OpenVault(byte[] kek)
    {
        var dbKey = _mpv.DeriveDatabasePassphrase(kek);
        try
        {
            var dbPath = Path.Combine(_vaultDir, "vault.db");
            _db = new VaultDatabase(dbPath, dbKey);
            _db.InitializeAsync().GetAwaiter().GetResult();
            _repo = new VaultRepository(_db);
            _enc = new RecordEncryptor(_crypto);
            _kek = new byte[kek.Length];
            Buffer.BlockCopy(kek, 0, _kek, 0, kek.Length);

            UnlockPanel.Visibility = Visibility.Collapsed;
            ListPanel.Visibility = Visibility.Visible;
            _vaultExists = true;
            StartIdleTimer();
            ReloadList();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dbKey);
        }
    }

    private async void ReloadList()
    {
        if (_repo == null) return;
        StatusText.Text = "加载中…";
        try
        {
            var summaries = await _repo.ListActiveSummariesAsync().ConfigureAwait(true);
            var items = new ObservableCollection<VaultListItem>();
            foreach (var s in summaries)
                items.Add(new VaultListItem(s.RecordId, s.UpdatedAt, s.Version));
            RecordList.ItemsSource = items;
            StatusText.Text = items.Count == 0 ? "暂无条目。双击可查看详情。" : $"{items.Count} 条（双击查看详情）";
        }
        catch
        {
            StatusText.Text = "列表加载失败，请重试。";
        }
    }

    private void OnRecordListDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (RecordList.SelectedItem is not VaultListItem item) return;
        OpenRecordDetail(item.RecordId);
    }

    private void OpenRecordDetail(string recordId)
    {
        if (_repo == null || _enc == null || _kek == null) return;
        var w = new RecordDetailWindow(recordId, async () =>
        {
            var row = await _repo.GetRecordAsync(recordId).ConfigureAwait(true);
            if (row == null) return null;
            return _enc.Decrypt(row, _kek);
        })
        {
            Owner = this
        };
        w.ShowDialog();
    }

    private void OnAddClick(object sender, RoutedEventArgs e)
    {
        if (_repo == null || _enc == null || _kek == null) return;
        var editor = new RecordEditWindow { Owner = this };
        if (editor.ShowDialog() != true || editor.Result == null) return;
        SaveRecord(Guid.NewGuid().ToString("N"), editor.Result, 0);
    }

    private void OnEditClick(object sender, RoutedEventArgs e)
    {
        if (_repo == null || _enc == null || _kek == null) return;
        if (RecordList.SelectedItem is not VaultListItem item)
        {
            StatusText.Text = "请先选择要编辑的条目。";
            return;
        }
        EditRecord(item);
    }

    private async void EditRecord(VaultListItem item)
    {
        if (_repo == null || _enc == null || _kek == null) return;
        try
        {
            var row = await _repo.GetRecordAsync(item.RecordId).ConfigureAwait(true);
            if (row == null)
            {
                StatusText.Text = "条目不存在或已删除。";
                ReloadList();
                return;
            }
            var plain = _enc.Decrypt(row, _kek);
            var editor = new RecordEditWindow(plain) { Owner = this };
            if (editor.ShowDialog() != true || editor.Result == null) return;
            SaveRecord(item.RecordId, editor.Result, row.Version);
        }
        catch
        {
            StatusText.Text = "编辑失败，请重试。";
        }
    }

    private void OnDeleteClick(object sender, RoutedEventArgs e)
    {
        if (_repo == null) return;
        if (RecordList.SelectedItem is not VaultListItem item)
        {
            StatusText.Text = "请先选择要删除的条目。";
            return;
        }
        var result = MessageBox.Show(this, $"确认删除条目：{item.RecordId}？", "删除确认", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (result != MessageBoxResult.Yes) return;
        DeleteRecord(item);
    }

    private async void DeleteRecord(VaultListItem item)
    {
        if (_repo == null) return;
        try
        {
            await _repo.SoftDeleteAsync(
                item.RecordId,
                item.Version + 1,
                DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
            ).ConfigureAwait(true);
            StatusText.Text = "已删除条目。";
            ReloadList();
        }
        catch
        {
            StatusText.Text = "删除失败，请重试。";
        }
    }

    private async void SaveRecord(string recordId, PlainRecord plain, int baseVersion)
    {
        if (_repo == null || _enc == null || _kek == null) return;
        try
        {
            var nextVersion = Math.Max(baseVersion + 1, 1);
            var updatedAt = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            var row = _enc.Encrypt(recordId, plain, _kek, nextVersion, updatedAt);
            await _repo.UpsertRecordAsync(row).ConfigureAwait(true);
            StatusText.Text = "保存成功。";
            ReloadList();
        }
        catch
        {
            StatusText.Text = "保存失败，请重试。";
        }
    }

    private void OnLockClick(object sender, RoutedEventArgs e) => LockVault();

    private void LockVault()
    {
        StopIdleTimer();
        if (_kek != null) CryptographicOperations.ZeroMemory(_kek);
        _kek = null;
        _repo = null;
        _enc = null;
        _db?.Dispose();
        _db = null;
        ListPanel.Visibility = Visibility.Collapsed;
        UnlockPanel.Visibility = Visibility.Visible;
        RecordList.ItemsSource = null;
        RefreshUnlockUi();
    }

    protected override void OnClosed(EventArgs e)
    {
        SystemEvents.SessionSwitch -= _sessionSwitchHandler;
        SystemEvents.PowerModeChanged -= _powerModeHandler;
        StopIdleTimer();
        if (_kek != null) CryptographicOperations.ZeroMemory(_kek);
        _kek = null;
        _repo = null;
        _enc = null;
        _db?.Dispose();
        _db = null;
        base.OnClosed(e);
    }
}
