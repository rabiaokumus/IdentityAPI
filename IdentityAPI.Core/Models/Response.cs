using System;
using System.Collections.Generic;
using System.Text;

namespace IdentityAPI.Core.Models
{
    public class Response
    {
        public int Status { get; set; }
        public string Message { get; set; }

        public string Token { get; set; }

        public DateTime Expiration { get; set; }

    }
}
