using AppStoreServerApi.Models;
using JWT.Algorithms;
using JWT.Builder;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.Dynamic;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AppStoreServerApi;

// see https://github.com/agisboye/app-store-server-api/blob/main/src/AppStoreServerAPI.ts
public class AppleAppstoreClient
{
    // https://www.apple.com/certificateauthority/
    // https://www.apple.com/certificateauthority/AppleRootCA-G3.cer
    private const string APPLE_ROOT_CA_G3_THUMBPRINT = "b52cb02fd567e0359fe8fa4d4c41037970fe01b0";

    // The maximum age that an authentication token is allowed to have, as decided by Apple.
    private static readonly int _maxTokenAge = 3600; // seconds, = 1 hour
    private readonly string _environment; // see: Environment
    private readonly string _baseUrl;
    private readonly string _privateKey;
    private readonly string _keyId;
    private readonly string _issuerId;
    private readonly string _bundleId;
    private readonly string _appstoreAudience;
    private string? _token;
    private DateTime? _tokenExpiry = null;

    /// <summary>
    /// 
    /// </summary>
    /// <param name="key">key the key downloaded from App Store Connect in PEM-encoded PKCS8 format.</param>
    /// <param name="keyId">keyId the id of the key, retrieved from App Store Connect</param>
    /// <param name="issuerId">issuerId your issuer ID, retrieved from App Store Connect</param>
    /// <param name="bundleId">bundleId bundle ID of your app</param>
    /// <param name="environment">Sandbox/Production</param>
    public AppleAppstoreClient(string privateKey, string keyId, string issuerId, string applicationId, string appstoreAudience = "appstoreconnect-v1", string environment = AppleEnvironment.Sandbox)
    {
        _privateKey = privateKey;

        _keyId = keyId;
        _issuerId = issuerId;
        _bundleId = applicationId;
        _appstoreAudience = appstoreAudience;
        _environment = environment;

        if (environment == AppleEnvironment.Sandbox)
        {
            _baseUrl = "https://api.storekit-sandbox.itunes.apple.com";
        }
        else
        {
            _baseUrl = "https://api.storekit.itunes.apple.com";
        }
    }

    private bool TokenExpired
    {
        get
        {
            // We consider the token to be expired slightly before it actually is to allow for some networking latency.
            var now = DateTime.Now;
            var cutoff = now.AddSeconds(-60);

            return _tokenExpiry == null || _tokenExpiry < cutoff;
        }
    }

    // https://developer.apple.com/documentation/appstoreserverapi/get_transaction_history
    public async Task<HistoryResponse?> GetTransactionHistory(string originalTransactionId, string? revision)
    {
        var query = revision != null ? $"?query={revision}" : "";

        return await MakeRequest<HistoryResponse>($"{_baseUrl}/inApps/v1/history/{originalTransactionId}{query}");
    }

    // https://developer.apple.com/documentation/appstoreserverapi/get_all_subscription_statuses
    public async Task<StatusResponse?> GetSubscriptionStatuses(string originalTransactionId)
    {
        return await MakeRequest<StatusResponse>($"{_baseUrl}/inApps/v1/subscriptions/{originalTransactionId}");
    }

    public async Task<OrderLookupResponse?> LookupOrder(string orderId)
    {
        return await MakeRequest<OrderLookupResponse>($"{_baseUrl}/inApps/v1/lookup/{orderId}");
    }

    #region Request utilities
    private async Task<T?> MakeRequest<T>(string url)
    {
        var token = GetToken();
        var httpClient = new HttpClient();
        httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var result = await httpClient.GetAsync(url);

        if (result.StatusCode == System.Net.HttpStatusCode.OK)
        {
            var body = await result.Content.ReadAsStringAsync();
            return JsonConvert.DeserializeObject<T>(body);
        }

        switch (result.StatusCode)
        {
            case System.Net.HttpStatusCode.BadRequest:
            case System.Net.HttpStatusCode.NotFound:
            case System.Net.HttpStatusCode.InternalServerError:
                var body = await result.Content.ReadAsStringAsync();
                dynamic json = JsonConvert.DeserializeObject<ExpandoObject>(body);
                throw new Exception(json?.errorMessage ?? "Apple server response error");
            case System.Net.HttpStatusCode.Unauthorized:
                _token = null;
                throw new Exception("The request is unauthorized; the JSON Web Token (JWT) is invalid.");
            default:
                throw new Exception("An unknown error occurred");
        }
    }

    private ECDsa GetEllipticCurveAlgorithm()
    {
        var privateKey = _privateKey.Replace("-----BEGIN PRIVATE KEY-----", string.Empty).Replace("-----END PRIVATE KEY-----", string.Empty).Replace(Environment.NewLine, "");

        var keyParams = (Org.BouncyCastle.Crypto.Parameters.ECPrivateKeyParameters)Org.BouncyCastle.Security.PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));

        var normalizedEcPoint = keyParams.Parameters.G.Multiply(keyParams.D).Normalize();

        return ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.CreateFromValue(keyParams.PublicKeyParamSet.Id),
            D = keyParams.D.ToByteArrayUnsigned(),
            Q =
        {
            X = normalizedEcPoint.XCoord.GetEncoded(),
            Y = normalizedEcPoint.YCoord.GetEncoded()
        }
        });
    }

    public ECDsaSecurityKey GetEcdsaSecuritKey()
    {
        var signatureAlgorithm = GetEllipticCurveAlgorithm();
        var eCDsaSecurityKey = new ECDsaSecurityKey(signatureAlgorithm)
        {
            KeyId = _keyId
        };

        return eCDsaSecurityKey;
    }

    private string GetToken()
    {
        // Reuse previously created token if it hasn't expired.
        if (!string.IsNullOrEmpty(_token) && !TokenExpired)
            return _token;

        // Tokens must expire after at most 1 hour.
        var now = DateTime.Now;
        var expiry = now.AddSeconds(_maxTokenAge);

        ECDsaSecurityKey eCDsaSecurityKey = GetEcdsaSecuritKey();

        var handler = new JsonWebTokenHandler();
        string jwt = handler.CreateToken(new SecurityTokenDescriptor
        {
            Issuer = _issuerId,
            Audience = _appstoreAudience,
            NotBefore = now,
            Expires = expiry,
            IssuedAt = now,
            Claims = new Dictionary<string, object> {
                { "bid", _bundleId },
                { "nonce", Guid.NewGuid().ToString("N") }
            },
            SigningCredentials = new SigningCredentials(eCDsaSecurityKey, SecurityAlgorithms.EcdsaSha256)
        });

        _token = jwt;
        _tokenExpiry = expiry;

        return jwt;
    }

    #endregion

    #region Decode signed fields
    public List<JWSTransactionDecodedPayload> DecodeTransactions(List<string> signedTransactions)
    {
        return signedTransactions.Select(s => DecodeJWS<JWSTransactionDecodedPayload>(s)).ToList();
    }

    public DecodedNotificationPayload DecodeNotificationPayload(string payload)
    {
        return DecodeJWS<DecodedNotificationPayload>(payload);
    }

    public JWSRenewalInfoDecodedPayload DecodeRenewalInfo(string info)
    {
        return DecodeJWS<JWSRenewalInfoDecodedPayload>(info);
    }

    public JWSTransactionDecodedPayload DecodeTransaction(string transaction)
    {
        return DecodeJWS<JWSTransactionDecodedPayload>(transaction);
    }

    /// <summary>
    /// Decodes and verifies an object signed by the App Store according to JWS.
    /// See: https://developer.apple.com/documentation/appstoreserverapi/jwstransaction
    /// </summary>
    /// <param name="token"></param>
    public T DecodeJWS<T>(string token)
    {
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var jwtSecurityToken = handler.ReadJwtToken(token);

        var x5cList = ((List<object>)jwtSecurityToken.Header["x5c"])?.Select(o => o.ToString()!).ToList()
            ?? throw new Exception("Header 'x5c' not found.");

        if (x5cList == null)
        {
            throw new CertificateValidationException(new());
        }

        var certs = ValidateCertificate(x5cList);

        var payload = JwtBuilder.Create()
                .WithAlgorithm(new ES256Algorithm(certs.First()))
                .MustVerifySignature()
                .Decode<T>(token);

        return payload;
    }

    /// <summary>
    /// Validates a certificate chain provided in the x5c field of a decoded header of a JWS.
    /// The certificates must be valid and have come from Apple.
    /// </summary>
    /// <param name="certificates"></param>
    /// <returns></returns>
    private static List<X509Certificate2> ValidateCertificate(List<string> certificates)
    {
        if (certificates.Count == 0)
            throw new CertificateValidationException(new());

        var x509certs = certificates.Select(c => new X509Certificate2((Convert.FromBase64String(c)))).ToList();

        // Check dates
        var now = DateTime.Now;
        var datesValid = x509certs.All(c => c.NotBefore < now && now < c.NotAfter);
        if (!datesValid)
            throw new CertificateValidationException(certificates);

        // Check that each certificate, except for the last, is issued by the subsequent one.
        if (certificates.Count >= 2)
        {
            for (var i = 0; i < x509certs.Count - 1; i++)
            {
                if (x509certs[i].Issuer != x509certs[i + 1].Subject)
                {
                    throw new CertificateValidationException(certificates);
                }
            }
        }

        // Ensure that the last certificate in the chain is the expected Apple root CA.
        if (!x509certs.Last().Thumbprint.Equals(APPLE_ROOT_CA_G3_THUMBPRINT, StringComparison.InvariantCultureIgnoreCase))
        {
            throw new CertificateValidationException(certificates);
        }

        return x509certs;
    }
    #endregion
}