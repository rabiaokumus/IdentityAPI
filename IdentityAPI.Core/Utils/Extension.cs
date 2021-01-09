using Microsoft.AspNetCore.WebUtilities;
using System;
using System.Text;

namespace IdentityAPI.Core.Utils
{
    public static class Extension 
    {
        public static string ToStringEx(this object value)
        {
            if (value == null)
                return string.Empty;

            return (Convert.ToString(value) ?? "").Replace("null", "").Trim();
        }

        public static int? ToIntEx(this object value)
        {
            if (value == null)
                return null;

            var v = 0;

            if (int.TryParse(value.ToStringEx(), out v))
                return v;
            else
                return null;
        }

        public static string DecodeText(string value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                var codeDecodedBytes = WebEncoders.Base64UrlDecode(value);
                var decodedText = Encoding.UTF8.GetString(codeDecodedBytes);

                return decodedText;
            }

            return value;
        }

        public static string EncodeText(string value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                byte[] tokenGeneratedBytes = Encoding.UTF8.GetBytes(value);
                var encodedText = WebEncoders.Base64UrlEncode(tokenGeneratedBytes);

                return encodedText;
            }

            return value;
        }
    }
}
