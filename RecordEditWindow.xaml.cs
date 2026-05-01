using System.Windows;
using PasswordManage.PC.Crypto;

namespace PasswordManage.PC;

public partial class RecordEditWindow : Window
{
    public PlainRecord? Result { get; private set; }

    public RecordEditWindow(PlainRecord? initial = null)
    {
        InitializeComponent();
        if (initial != null)
        {
            TitleBox.Text = initial.Title;
            UserBox.Text = initial.Username;
            PassBox.Text = initial.Password;
            UrlBox.Text = initial.Url;
            NoteBox.Text = initial.Note;
            Title = "编辑条目";
        }
        else
        {
            Title = "新增条目";
        }
    }

    private void OnSaveClick(object sender, RoutedEventArgs e)
    {
        var title = TitleBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(title))
        {
            ErrorText.Text = "标题不能为空。";
            return;
        }

        Result = new PlainRecord(
            title,
            UserBox.Text.Trim(),
            PassBox.Text,
            UrlBox.Text.Trim(),
            NoteBox.Text,
            Array.Empty<string>()
        );
        DialogResult = true;
        Close();
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}
