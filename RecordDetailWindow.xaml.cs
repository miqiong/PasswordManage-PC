using System.Windows;
using System.Windows.Controls;
using PasswordManage.PC.Crypto;

namespace PasswordManage.PC;

/// <summary>单条解密展示；禁止向日志输出 <see cref="PlainRecord"/> 或任何字段。</summary>
public partial class RecordDetailWindow : Window
{
    public RecordDetailWindow(string recordId, Func<Task<PlainRecord?>> loadPlainAsync)
    {
        InitializeComponent();
        Title = $"条目 · {recordId}";
        Loaded += async (_, _) =>
        {
            try
            {
                var plain = await loadPlainAsync().ConfigureAwait(true);
                if (plain == null)
                {
                    DetailStatus.Text = "无法加载该条目。";
                    return;
                }
                TitleBox.Text = plain.Title;
                UserBox.Text = plain.Username;
                PassBox.Text = plain.Password;
                UrlBox.Text = plain.Url;
                NoteBox.Text = plain.Note;
                DetailStatus.Text = string.Empty;
            }
            catch
            {
                DetailStatus.Text = "加载失败，请重试。";
            }
        };
    }

    private void OnCloseClick(object sender, RoutedEventArgs e) => Close();

    protected override void OnClosed(EventArgs e)
    {
        TitleBox.Clear();
        UserBox.Clear();
        PassBox.Clear();
        UrlBox.Clear();
        NoteBox.Clear();
        base.OnClosed(e);
    }
}
