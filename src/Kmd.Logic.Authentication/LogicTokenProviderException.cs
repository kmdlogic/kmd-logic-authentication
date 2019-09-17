using System;
using System.Runtime.Serialization;

namespace Kmd.Logic.Authentication
{
    [Serializable]
    public class LogicTokenProviderException : Exception
    {
        public LogicTokenProviderException()
        {
        }

        public LogicTokenProviderException(string message)
            : base(message)
        {
        }

        public LogicTokenProviderException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        protected LogicTokenProviderException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}