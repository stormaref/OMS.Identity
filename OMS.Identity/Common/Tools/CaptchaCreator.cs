using System.Text;
using SixLabors.Fonts;
using SixLabors.ImageSharp;
using SixLaborsCaptcha.Core;

namespace OMS.Identity.Common.Tools;

public static class CaptchaCreator
{
    const string Letters = "0123456789ABCDEFGHJKLMNPRTUVWXYZ";

    private static string GenerateCaptchaCode(byte length)
    {
        Random rand = new Random();
        int maxRand = Letters.Length - 1;

        StringBuilder sb = new StringBuilder();

        for (int i = 0; i < length; i++)
        {
            int index = rand.Next(maxRand);
            sb.Append(Letters[index]);
        }

        return sb.ToString();
    }

    public static (string Code, string Captcha) Create()
    {
        var slc = new SixLaborsCaptchaModule(
            new SixLaborsCaptchaOptions
            {
                DrawLines = 5,
                TextColor = GenerateRandomColors(2),
                Width = 200,
                Height = 60,
                DrawLinesColor = GenerateRandomColors(2),
                NoiseRate = 450,
                NoiseRateColor = GenerateRandomColors(2),
                MinLineThickness = 1f,
                MaxLineThickness = 3f,
                FontStyle = FontStyle.BoldItalic
            });

        var code = GenerateCaptchaCode(6);
        var bytes = slc.Generate(code);
        return (code, Convert.ToBase64String(bytes));
    }

    private static Color[] GenerateRandomColors(int count)
    {
        Random random = new();
        List<Color> colors = new();
        for (int i = 0; i < count; i++)
        {
            colors.Add(
                Color.FromRgba(
                    (byte) random.Next(25, 180),
                    (byte) random.Next(25, 180),
                    (byte) random.Next(25, 180),
                    255));
        }

        return colors.ToArray();
    }
}