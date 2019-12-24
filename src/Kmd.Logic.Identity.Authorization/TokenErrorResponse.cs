using System.Collections.Generic;
using Newtonsoft.Json;

namespace Kmd.Logic.Identity.Authorization
{
    internal class TokenErrorResponse
    {
        [JsonProperty("error")]
        public string Error { get; set; }

        [JsonProperty("error_description")]
        public string ErrorDescription { get; set; }

        [JsonProperty("error_codes")]
        public List<int> ErrorCodes { get; set; }

        [JsonProperty("timestamp")]
        public string Timestamp { get; set; }

        [JsonProperty("trace_id")]
        public string TraceId { get; set; }

        [JsonProperty("correlation_id")]
        public string CorrelationId { get; set; }
    }
}