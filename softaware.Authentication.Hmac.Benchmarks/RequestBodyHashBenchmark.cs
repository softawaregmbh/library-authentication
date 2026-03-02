using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using softaware.Authentication.Hmac;
using softaware.Authentication.Hmac.Client;

namespace softaware.Authentication.Hmac.Benchmarks
{
    /// <summary>
    /// Benchmarks comparing the old approach (read entire body into byte array, then hash synchronously)
    /// versus the new approach (compute hash asynchronously by streaming through the body).
    /// <para>
    /// The new approach:
    /// <list type="bullet">
    ///   <item>Avoids the intermediate <see cref="MemoryStream"/> allocation and <c>ToArray()</c> copy.</item>
    ///   <item>Uses <see cref="HashAlgorithm.ComputeHashAsync"/> to hash the stream in chunks.</item>
    ///   <item>Combined with <c>Request.EnableBuffering()</c>, large bodies spill to a temp file
    ///         instead of being held entirely in memory.</item>
    /// </list>
    /// </para>
    /// </summary>
    [MemoryDiagnoser]
    [Orderer(SummaryOrderPolicy.FastestToSlowest)]
    public class RequestBodyHashBenchmark
    {
        private byte[] bodyBytes = Array.Empty<byte>();

        [Params(1_024, 1_024 * 1024, 10 * 1024 * 1024)]
        public int BodySizeBytes { get; set; }

        [Params(RequestBodyHashingMethod.MD5, RequestBodyHashingMethod.SHA256, RequestBodyHashingMethod.SHA512)]
        public RequestBodyHashingMethod HashingMethod { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            bodyBytes = new byte[BodySizeBytes];
            Random.Shared.NextBytes(bodyBytes);
        }

        /// <summary>
        /// Old approach: copies the body into a MemoryStream, calls ToArray(), then hashes the byte array synchronously.
        /// This is the original implementation of <c>ValidateAsync</c> / <c>ComputeRequestBodyBase64Hash</c>.
        /// </summary>
        [Benchmark(Baseline = true, Description = "Old: CopyToMemoryStream + byte[] + ComputeHash")]
        public async Task<string> OldApproach_CopyToMemoryStreamAndHashByteArray()
        {
            // Simulate the original code path from ValidateAsync / ComputeRequestBodyBase64Hash.
            var inputStream = new MemoryStream(bodyBytes, writable: false);

            var memoryStream = new MemoryStream();
            await inputStream.CopyToAsync(memoryStream);

            var body = memoryStream.ToArray();

            using var hashAlgorithm = HashingMethod.CreateHashAlgorithm();

            if (body.Length != 0)
            {
                var hash = hashAlgorithm.ComputeHash(body);
                return Convert.ToBase64String(hash);
            }

            return string.Empty;
        }

        /// <summary>
        /// New approach: uses <see cref="HashAlgorithm.ComputeHashAsync(Stream)"/> to stream-hash the body
        /// without loading it all into memory at once and without a separate <c>ToArray()</c> copy.
        /// This mirrors the new implementation that uses <c>Request.EnableBuffering()</c>.
        /// </summary>
        [Benchmark(Description = "New: ComputeHashAsync streaming")]
        public async Task<string> NewApproach_ComputeHashAsyncStreaming()
        {
            // Simulate the new code path. In production, Request.EnableBuffering() makes the body seekable;
            // here we use a plain MemoryStream (which is already seekable) to isolate the hashing logic.
            var body = new MemoryStream(bodyBytes, writable: false);

            using var hashAlgorithm = HashingMethod.CreateHashAlgorithm();
            await hashAlgorithm.ComputeHashAsync(body);

            return body.Position > 0 ? Convert.ToBase64String(hashAlgorithm.Hash!) : string.Empty;
        }
    }
}
