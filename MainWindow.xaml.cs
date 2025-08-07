using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensibility;
using Microsoft.Web.WebView2.Core;
using System;
using System.Collections.Generic;
using System.IdentityModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using System.Windows;
using System.Windows.Controls;
using System.Xml;

namespace OktaMSALSample
{
    public enum OAuthProvider
    {
        Okta,
        Auth0
    }

    public enum AuthFlow
    {
        AuthorizationCode,
        ClientCredentials,
        OidcThenSaml // New hybrid flow
    }

    public class OAuthConfig
    {
        public string ClientId { get; set; }
        public string AuthorityUrl { get; set; }
        public string RedirectUri { get; set; }
        public string[] Scopes { get; set; }
        // SAML specific properties
        public string SamlIdpUrl { get; set; }
        public string SamlSpEntityId { get; set; }
        public string SamlAcsUrl { get; set; }
    }

    public class ClientCredentialsConfig
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string AuthorityUrl { get; set; }
        public string[] Scopes { get; set; }
        public string Audience { get; set; }
    }

    public class SamlAssertionResult
    {
        public string SamlResponse { get; set; }
        public string RelayState { get; set; }
        public Dictionary<string, string> Attributes { get; set; }
        public DateTime ExpiresAt { get; set; }
        public bool IsValid { get; set; }
        public string Error { get; set; }
        public string RawSamlXml { get; set; }
    }

    public partial class MainWindow : Window
    {
        private IPublicClientApplication _msalPublicApp;
        private IConfidentialClientApplication _msalConfidentialApp;
        private CustomWebView _customWebView;
        private OAuthProvider _currentProvider;
        private AuthFlow _currentFlow;
        private AuthenticationResult _currentAuthResult;
        private SamlAssertionResult _currentSamlResult;
        private TaskCompletionSource<SamlAssertionResult> _samlCompletionSource;

        // Enhanced OAuth Configuration with SAML support
        private readonly OAuthConfig _oktaConfig = new OAuthConfig
        {
            ClientId = "0oatjdh6ftvpqibz8697",
            AuthorityUrl = "https://integrator-1355928.okta.com/oauth2/default",
            RedirectUri = "https://localhost:5001/",
            Scopes = new[] { "openid", "profile", "email" },
            // SAML Configuration - Update these URLs according to your Okta SAML app configuration
            SamlIdpUrl = "https://integrator-1355928.okta.com/app/integrator-1355928_sts_1/exktpzi0kfWlX1Q0v697/sso/saml",
            SamlSpEntityId = "urn:altera:helios:wpf:client1",
            SamlAcsUrl = "http://localhost:5001/sso"
        };

        private readonly OAuthConfig _auth0Config = new OAuthConfig
        {
            ClientId = "EsiZ79MDvhK8fgNo7SPkU0HkW8TNcLIQ",
            AuthorityUrl = "https://dev-t2bzy5qqqml628wg.us.auth0.com",
            RedirectUri = "https://localhost:5001/",
            Scopes = new[] { "openid", "profile", "email" },
            // SAML Configuration for Auth0
            SamlIdpUrl = "https://dev-t2bzy5qqqml628wg.us.auth0.com/samlp/your-client-id",
            SamlSpEntityId = "urn:your-app:saml",
            SamlAcsUrl = "https://localhost:5001/saml/acs"
        };

        // Client Credentials Configuration (unchanged)
        private readonly ClientCredentialsConfig _oktaClientCredentialsConfig = new ClientCredentialsConfig
        {
            ClientId = "0oati8dzjrPdwCfYZ697",
            ClientSecret = "8K8ysI7Na87tz4DEvDcW7PEp7rIphXO_2nHIsXudt4F1Vk9Q1SgYjN-BWyCKzKdx",
            AuthorityUrl = "https://integrator-1355928.okta.com/oauth2/austos83vyikUni0E697",
            Scopes = new[] { "read:data" },
            Audience = "api://default"
        };

        private readonly ClientCredentialsConfig _auth0ClientCredentialsConfig = new ClientCredentialsConfig
        {
            ClientId = "0jNPEUVe168UiAitRREkJMTYwwiVPSNs",
            ClientSecret = "1MGfPINLyDYZV4ghq-sbd0PTakxc2DidaE6kes92M4NNrpKtfdw6r7z6lyjSisPe",
            AuthorityUrl = "https://dev-t2bzy5qqqml628wg.us.auth0.com",
            Scopes = new[] { "read:users" },
            Audience = "https://dev-t2bzy5qqqml628wg.us.auth0.com/api/v2/"
        };

        public MainWindow()
        {
            InitializeComponent();
            InitializeWebView();
            UpdateFlowComboBox();
        }

        private void UpdateFlowComboBox()
        {
            // Add the new OIDC + SAML flow option
            if (FlowComboBox.Items.Count == 2) // Only add if not already added
            {
                FlowComboBox.Items.Add(new ComboBoxItem { Content = "OIDC then SAML (Hybrid)" });
            }
        }

        private async void InitializeWebView()
        {
            try
            {
                await WebView.EnsureCoreWebView2Async(null);
                _customWebView = new CustomWebView(WebView);

                await SetupHttpInterception();

                StatusTextBlock.Text = "Ready for authentication with MSAL";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Failed to initialize WebView2: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async Task SetupHttpInterception()
        {
            // Enable DOM events and network access
            WebView.CoreWebView2.AddWebResourceRequestedFilter("*", CoreWebView2WebResourceContext.All);

            // Intercept all HTTP requests/responses
            WebView.CoreWebView2.WebResourceRequested += CoreWebView2_WebResourceRequested;
            WebView.CoreWebView2.WebResourceResponseReceived += CoreWebView2_WebResourceResponseReceived;

            // Also monitor navigation for backup detection
            WebView.CoreWebView2.NavigationStarting += CoreWebView2_NavigationStarting;
            WebView.CoreWebView2.NavigationCompleted += CoreWebView2_NavigationCompleted;
        }

        private async void CoreWebView2_WebResourceRequested(object sender, CoreWebView2WebResourceRequestedEventArgs e)
        {
            try
            {
                // Check if this is a POST request that might contain SAML data
                if (e.Request.Method == "POST" && _currentFlow == AuthFlow.OidcThenSaml && _samlCompletionSource != null)
                {
                    var uri = e.Request.Uri;
                    var config = _currentProvider == OAuthProvider.Okta ? _oktaConfig : _auth0Config;

                    // Check if this POST is to our ACS endpoint or contains SAML data
                    if (uri.Contains(config.SamlAcsUrl))
                    {
                        StatusTextBlock.Text = "Intercepting SAML POST request...";

                        // Try to get POST data
                        if (e.Request.Content != null)
                        {
                            var content = await GetStreamContentAsync(e.Request.Content);
                            var samlResult = ExtractSamlFromPostData(content);

                            if (samlResult.IsValid)
                            {
                                _samlCompletionSource?.TrySetResult(samlResult);
                                return;
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error in WebResourceRequested: {ex.Message}");
            }
        }

        private async Task<string> GetStreamContentAsync(System.IO.Stream stream)
        {
            try
            {
                using (var reader = new System.IO.StreamReader(stream))
                {
                    return await reader.ReadToEndAsync();
                }
            }
            catch
            {
                return string.Empty;
            }
        }

        private SamlAssertionResult ExtractSamlFromPostData(string postData)
        {
            try
            {
                var result = new SamlAssertionResult { Attributes = new Dictionary<string, string>() };

                // Parse form data
                var formData = HttpUtility.ParseQueryString(postData);
                var samlResponse = formData["SAMLResponse"];
                var relayState = formData["RelayState"];

                if (!string.IsNullOrEmpty(samlResponse))
                {
                    result.SamlResponse = samlResponse;
                    result.RelayState = relayState ?? "";
                    result.IsValid = true;
                    result.ExpiresAt = DateTime.UtcNow.AddHours(1);

                    // Parse the SAML assertion
                    Task.Run(async () => await ParseSamlAssertionAsync(result));
                }

                return result;
            }
            catch (Exception ex)
            {
                return new SamlAssertionResult
                {
                    IsValid = false,
                    Error = $"Failed to extract SAML from POST data: {ex.Message}",
                    Attributes = new Dictionary<string, string>()
                };
            }
        }

        private SamlAssertionResult ExtractSamlFromHtmlContent(string htmlContent)
        {
            try
            {
                var result = new SamlAssertionResult { Attributes = new Dictionary<string, string>() };

                // Look for SAML Response in HTML forms using regex
                var samlPattern = @"name=[""']SAMLResponse[""'][^>]*value=[""']([^""']+)[""']";
                var match = Regex.Match(htmlContent, samlPattern, RegexOptions.IgnoreCase);

                if (match.Success)
                {
                    result.SamlResponse = WebUtility.HtmlDecode(match.Groups[1].Value);
                    result.IsValid = true;
                    result.ExpiresAt = DateTime.UtcNow.AddHours(1);

                    // Look for RelayState
                    var relayPattern = @"name=[""']RelayState[""'][^>]*value=[""']([^""']+)[""']";
                    var relayMatch = Regex.Match(htmlContent, relayPattern, RegexOptions.IgnoreCase);
                    if (relayMatch.Success)
                    {
                        result.RelayState = relayMatch.Groups[1].Value;
                    }

                    Task.Run(async () => await ParseSamlAssertionAsync(result));
                }

                return result;
            }
            catch (Exception ex)
            {
                return new SamlAssertionResult
                {
                    IsValid = false,
                    Error = $"Failed to extract SAML from HTML: {ex.Message}",
                    Attributes = new Dictionary<string, string>()
                };
            }
        }

        private async void CoreWebView2_WebResourceResponseReceived(object sender, CoreWebView2WebResourceResponseReceivedEventArgs e)
        {
            try
            {
                if (_currentFlow == AuthFlow.OidcThenSaml && _samlCompletionSource != null)
                {
                    var uri = e.Request.Uri;
                    var config = _currentProvider == OAuthProvider.Okta ? _oktaConfig : _auth0Config;

                    // Check if this response might contain SAML data
                    if (uri.Contains(config.SamlIdpUrl))
                    {
                        try
                        {
                            // Corrected code: CreateWebResourceResponse expects a string for headers, not CoreWebView2HttpResponseHeaders.
                            var headers = string.Join("\r\n", e.Response.Headers.Select(header => $"{header.Key}: {header.Value}"));
                            var response = WebView.CoreWebView2.Environment.CreateWebResourceResponse(
                                await e.Response.GetContentAsync(), e.Response.StatusCode, e.Response.ReasonPhrase, headers);

                            if (response.Content != null)
                            {
                                var content = await GetStreamContentAsync(response.Content);
                                var samlResult = ExtractSamlFromHtmlContent(content);

                                if (samlResult.IsValid)
                                {
                                    _samlCompletionSource?.TrySetResult(samlResult);
                                }
                            }
                        }
                        catch
                        {
                            // Fallback to DOM inspection after the page loads
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error in WebResourceResponseReceived: {ex.Message}");
            }
        }

        private async void CoreWebView2_NavigationCompleted(object sender, CoreWebView2NavigationCompletedEventArgs e)
        {
            // Fallback: If we haven't captured SAML yet, try DOM inspection with immediate execution
            if (_currentFlow == AuthFlow.OidcThenSaml && _samlCompletionSource != null && !_samlCompletionSource.Task.IsCompleted)
            {
            }
        }

        private async void CoreWebView2_NavigationStarting(object sender, CoreWebView2NavigationStartingEventArgs e)
        {
            // Monitor for SAML ACS URL or SAML response handling
            if (_currentFlow == AuthFlow.OidcThenSaml && _samlCompletionSource != null)
            {
                var config = _currentProvider == OAuthProvider.Okta ? _oktaConfig : _auth0Config;

                // Check if this is navigation to our SAML ACS endpoint
                if (e.Uri.StartsWith(config.SamlAcsUrl) || e.Uri.Contains("saml") || e.Uri.Contains("SAMLResponse"))
                {
                    StatusTextBlock.Text = "Processing SAML response...";
                }
            }
        }

        private async void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _currentProvider = ProviderComboBox.SelectedIndex == 0 ? OAuthProvider.Okta : OAuthProvider.Auth0;
                _currentFlow = (AuthFlow)FlowComboBox.SelectedIndex;

                switch (_currentFlow)
                {
                    case AuthFlow.AuthorizationCode:
                        await InitializeMsalPublicApp();
                        await PerformInteractiveLogin();
                        break;
                    case AuthFlow.ClientCredentials:
                        await InitializeMsalConfidentialApp();
                        await PerformClientCredentialsFlow();
                        break;
                    case AuthFlow.OidcThenSaml:
                        await InitializeMsalPublicApp();
                        await PerformOidcThenSamlFlow();
                        break;
                }
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Login Error: {ex.Message}";
                TokenTextBox.Text = ex.ToString();
            }
        }

        private async Task PerformOidcThenSamlFlow()
        {
            try
            {
                StatusTextBlock.Text = $"Step 1: Authenticating with {_currentProvider} using OIDC...";
                WebView.Visibility = Visibility.Visible;

                var config = _currentProvider == OAuthProvider.Okta ? _oktaConfig : _auth0Config;

                // Step 1: Perform OIDC Authentication
                var authResult = await _msalPublicApp
                    .AcquireTokenInteractive(config.Scopes)
                    .WithPrompt(Prompt.SelectAccount)
                    .WithCustomWebUi(_customWebView)
                    .WithExtraQueryParameters(GetExtraQueryParameters())
                    .ExecuteAsync();

                _currentAuthResult = authResult;
                StatusTextBlock.Text = $"Step 1 Complete: OIDC authentication successful. Step 2: Initiating SAML flow...";

                // Step 2: Use the existing browser session to initiate SAML assertion
                var samlResult = await InitiateSamlAssertionWithBrowserSession(config);
                _currentSamlResult = samlResult;

                if (samlResult.IsValid)
                {
                    DisplayHybridAuthResult(authResult, samlResult);
                    StatusTextBlock.Text = $"Successfully completed OIDC + SAML hybrid authentication with {_currentProvider}";
                }
                else
                {
                    StatusTextBlock.Text = $"OIDC succeeded but SAML assertion failed: {samlResult.Error}";
                    DisplayAuthResult(authResult); // Show OIDC result only
                }

                LoginButton.IsEnabled = true;
                LogoutButton.IsEnabled = true;
                GetTokenSilentButton.IsEnabled = true;
                WebView.Visibility = Visibility.Collapsed;
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Hybrid Flow Error: {ex.Message}";
                TokenTextBox.Text = ex.ToString();
                LoginButton.IsEnabled = true;
                WebView.Visibility = Visibility.Collapsed;
            }
        }

        private async Task<SamlAssertionResult> InitiateSamlAssertionWithBrowserSession(OAuthConfig config)
        {
            try
            {
                // Create a completion source to wait for SAML response
                _samlCompletionSource = new TaskCompletionSource<SamlAssertionResult>();

                // Build IdP-initiated SAML URL
                var samlUrl = BuildIdpInitiatedSamlUrl(config);

                StatusTextBlock.Text = "Navigating to SAML IdP using existing browser session...";

                // Navigate to SAML IdP URL using the WebView with existing session cookies
                await WebView.Dispatcher.InvokeAsync(() =>
                {
                    WebView.CoreWebView2.Navigate(samlUrl);
                });

                // Wait for SAML response with timeout
                var timeoutTask = Task.Delay(TimeSpan.FromMinutes(2));
                var completedTask = await Task.WhenAny(_samlCompletionSource.Task, timeoutTask);

                if (completedTask == timeoutTask)
                {
                    return new SamlAssertionResult
                    {
                        IsValid = false,
                        Error = "SAML assertion timed out",
                        Attributes = new Dictionary<string, string>()
                    };
                }

                return await _samlCompletionSource.Task;
            }
            catch (Exception ex)
            {
                return new SamlAssertionResult
                {
                    IsValid = false,
                    Error = $"SAML assertion failed: {ex.Message}",
                    Attributes = new Dictionary<string, string>()
                };
            }
            finally
            {
                _samlCompletionSource = null;
            }
        }

        private string BuildIdpInitiatedSamlUrl(OAuthConfig config)
        {
            var urlBuilder = new StringBuilder(config.SamlIdpUrl);

            // Add query parameters for IdP-initiated flow
            var queryParams = new List<string>();

            if (!string.IsNullOrEmpty(config.SamlSpEntityId))
            {
                queryParams.Add($"spEntityID={Uri.EscapeDataString(config.SamlSpEntityId)}");
            }

            // Add RelayState to identify this as a hybrid flow
            //queryParams.Add($"RelayState={Uri.EscapeDataString("hybrid_oidc_saml_flow")}");

            // For Okta, you might need additional parameters
            if (_currentProvider == OAuthProvider.Okta)
            {
                // Add any Okta-specific parameters for IdP-initiated SAML
                // queryParams.Add("param=value");
            }

            if (queryParams.Any())
            {
                var separator = config.SamlIdpUrl.Contains("?") ? "&" : "?";
                urlBuilder.Append(separator);
                urlBuilder.Append(string.Join("&", queryParams));
            }

            return urlBuilder.ToString();
        }

        private async Task ParseSamlAssertionAsync(SamlAssertionResult result)
        {
            try
            {
                // Decode base64 SAML response
                var decodedSaml = Encoding.UTF8.GetString(Convert.FromBase64String(result.SamlResponse));
                result.RawSamlXml = decodedSaml;

                var doc = new XmlDocument();
                doc.LoadXml(decodedSaml);

                // Create namespace manager for SAML
                var nsManager = new XmlNamespaceManager(doc.NameTable);
                nsManager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
                nsManager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

                // Extract attributes
                var attributeNodes = doc.SelectNodes("//saml:Attribute", nsManager);
                if (attributeNodes != null)
                {
                    foreach (XmlNode attr in attributeNodes)
                    {
                        var name = attr.Attributes?["Name"]?.Value;
                        var valueNode = attr.SelectSingleNode("saml:AttributeValue", nsManager);
                        var value = valueNode?.InnerText;

                        if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(value))
                        {
                            result.Attributes[name] = value;
                        }
                    }
                }

                // Extract subject
                var subjectNode = doc.SelectSingleNode("//saml:Subject/saml:NameID", nsManager);
                if (subjectNode != null)
                {
                    result.Attributes["Subject"] = subjectNode.InnerText;
                    result.Attributes["SubjectFormat"] = subjectNode.Attributes?["Format"]?.Value ?? "";
                }

                // Extract expiration time
                var conditions = doc.SelectSingleNode("//saml:Conditions", nsManager);
                if (conditions?.Attributes?["NotOnOrAfter"] != null)
                {
                    if (DateTime.TryParse(conditions.Attributes["NotOnOrAfter"].Value, out var expirationTime))
                    {
                        result.ExpiresAt = expirationTime;
                    }
                }

                // Extract issuer
                var issuerNode = doc.SelectSingleNode("//saml:Issuer", nsManager);
                if (issuerNode != null)
                {
                    result.Attributes["Issuer"] = issuerNode.InnerText;
                }

                // Extract authentication context
                var authnContextNode = doc.SelectSingleNode("//saml:AuthnContext/saml:AuthnContextClassRef", nsManager);
                if (authnContextNode != null)
                {
                    result.Attributes["AuthnContextClassRef"] = authnContextNode.InnerText;
                }
            }
            catch (Exception ex)
            {
                result.Attributes["ParseError"] = $"Failed to parse SAML assertion: {ex.Message}";
            }
        }

        private void DisplayHybridAuthResult(AuthenticationResult oidcResult, SamlAssertionResult samlResult)
        {
            var tokenDisplay = new StringBuilder();
            tokenDisplay.AppendLine($"=== HYBRID AUTHENTICATION RESULT ===");
            tokenDisplay.AppendLine($"Provider: {_currentProvider}");
            tokenDisplay.AppendLine($"Flow: OIDC + SAML Hybrid");
            tokenDisplay.AppendLine($"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            tokenDisplay.AppendLine();

            // OIDC Results
            tokenDisplay.AppendLine("=== OIDC TOKEN INFORMATION ===");
            tokenDisplay.AppendLine($"Access Token: {oidcResult.AccessToken}");
            tokenDisplay.AppendLine($"Token Type: Bearer");
            tokenDisplay.AppendLine($"Expires On: {oidcResult.ExpiresOn:yyyy-MM-dd HH:mm:ss} UTC");

            if (!string.IsNullOrEmpty(oidcResult.IdToken))
                tokenDisplay.AppendLine($"ID Token: {oidcResult.IdToken}");

            tokenDisplay.AppendLine($"Scopes: {string.Join(" ", oidcResult.Scopes)}");
            tokenDisplay.AppendLine($"Account: {oidcResult.Account?.Username}");
            tokenDisplay.AppendLine($"Account ID: {oidcResult.Account?.HomeAccountId?.Identifier}");
            tokenDisplay.AppendLine();

            // SAML Results
            tokenDisplay.AppendLine("=== SAML ASSERTION INFORMATION ===");
            tokenDisplay.AppendLine($"SAML Valid: {samlResult.IsValid}");
            tokenDisplay.AppendLine($"SAML Expires: {samlResult.ExpiresAt:yyyy-MM-dd HH:mm:ss} UTC");

            if (!string.IsNullOrEmpty(samlResult.RelayState))
                tokenDisplay.AppendLine($"RelayState: {samlResult.RelayState}");

            if (samlResult.IsValid)
            {
                tokenDisplay.AppendLine($"SAML Response Length: {samlResult.SamlResponse?.Length ?? 0} characters");
                tokenDisplay.AppendLine("SAML Attributes:");
                foreach (var attr in samlResult.Attributes)
                {
                    tokenDisplay.AppendLine($"  {attr.Key}: {attr.Value}");
                }

                if (!string.IsNullOrEmpty(samlResult.RawSamlXml))
                {
                    tokenDisplay.AppendLine();
                    tokenDisplay.AppendLine("=== RAW SAML XML (First 500 chars) ===");
                    var xmlPreview = samlResult.RawSamlXml.Length > 500
                        ? samlResult.RawSamlXml.Substring(0, 500) + "..."
                        : samlResult.RawSamlXml;
                    tokenDisplay.AppendLine(xmlPreview);
                }
            }
            else
            {
                tokenDisplay.AppendLine($"SAML Error: {samlResult.Error}");
            }

            tokenDisplay.AppendLine();
            tokenDisplay.AppendLine($"Correlation ID: {oidcResult.CorrelationId}");
            tokenDisplay.AppendLine($"Token Source: {oidcResult.AuthenticationResultMetadata?.TokenSource}");

            TokenTextBox.Text = tokenDisplay.ToString();
        }

        // ... (rest of the existing methods remain the same)
        private async Task InitializeMsalPublicApp()
        {
            var config = _currentProvider == OAuthProvider.Okta ? _oktaConfig : _auth0Config;

            var builder = PublicClientApplicationBuilder
                .Create(config.ClientId)
                .WithExperimentalFeatures()
                .WithOidcAuthority(config.AuthorityUrl)
                .WithRedirectUri(config.RedirectUri);

            _msalPublicApp = builder.Build();
        }

        private async Task InitializeMsalConfidentialApp()
        {
            var config = _currentProvider == OAuthProvider.Okta ? _oktaClientCredentialsConfig : _auth0ClientCredentialsConfig;

            var builder = ConfidentialClientApplicationBuilder
                .Create(config.ClientId)
                .WithClientSecret(config.ClientSecret)
                .WithOidcAuthority(config.AuthorityUrl);

            if (_currentProvider == OAuthProvider.Auth0 && !string.IsNullOrEmpty(config.Audience))
            {
                builder = builder.WithExtraQueryParameters(new Dictionary<string, string>
                {
                    ["audience"] = config.Audience
                });
            }

            _msalConfidentialApp = builder.Build();
        }

        private async Task PerformInteractiveLogin()
        {
            try
            {
                StatusTextBlock.Text = $"Authenticating with {_currentProvider} using MSAL Authorization Code Flow...";
                WebView.Visibility = Visibility.Visible;

                var config = _currentProvider == OAuthProvider.Okta ? _oktaConfig : _auth0Config;

                var authResult = await _msalPublicApp
                    .AcquireTokenInteractive(config.Scopes)
                    .WithPrompt(Prompt.SelectAccount)
                    .WithCustomWebUi(_customWebView)
                    .WithExtraQueryParameters(GetExtraQueryParameters())
                    .ExecuteAsync();

                DisplayAuthResult(authResult);
                StatusTextBlock.Text = $"Successfully authenticated with {_currentProvider} (Authorization Code)";
                LoginButton.IsEnabled = true;
                LogoutButton.IsEnabled = true;
                GetTokenSilentButton.IsEnabled = true;
                WebView.Visibility = Visibility.Collapsed;
            }
            catch (MsalException msalEx)
            {
                StatusTextBlock.Text = $"MSAL Error: {msalEx.ErrorCode}";
                TokenTextBox.Text = $"MSAL Exception:\nError Code: {msalEx.ErrorCode}\nMessage: {msalEx.Message}\n\nFull Exception:\n{msalEx}";
                LoginButton.IsEnabled = true;
                WebView.Visibility = Visibility.Collapsed;
            }
        }

        private async Task PerformClientCredentialsFlow()
        {
            try
            {
                StatusTextBlock.Text = $"Authenticating with {_currentProvider} using Client Credentials Flow...";

                var config = _currentProvider == OAuthProvider.Okta ? _oktaClientCredentialsConfig : _auth0ClientCredentialsConfig;

                var authResult = await _msalConfidentialApp
                    .AcquireTokenForClient(config.Scopes)
                    .ExecuteAsync();

                DisplayClientCredentialsResult(authResult);
                StatusTextBlock.Text = $"Successfully authenticated with {_currentProvider} (Client Credentials)";
                LoginButton.IsEnabled = true;
                LogoutButton.IsEnabled = true;
                GetTokenSilentButton.IsEnabled = false;
            }
            catch (MsalException msalEx)
            {
                StatusTextBlock.Text = $"MSAL Client Credentials Error: {msalEx.ErrorCode}";
                TokenTextBox.Text = $"MSAL Exception:\nError Code: {msalEx.ErrorCode}\nMessage: {msalEx.Message}\n\nFull Exception:\n{msalEx}";
                LoginButton.IsEnabled = true;
            }
        }

        private async Task GetTokenSilent()
        {
            try
            {
                if (_currentFlow == AuthFlow.ClientCredentials)
                {
                    StatusTextBlock.Text = "Silent token refresh is only available for Authorization Code flow";
                    return;
                }

                var accounts = await _msalPublicApp.GetAccountsAsync();
                var firstAccount = accounts.FirstOrDefault();

                if (firstAccount == null)
                {
                    StatusTextBlock.Text = "No accounts found. Please login first.";
                    return;
                }

                var config = _currentProvider == OAuthProvider.Okta ? _oktaConfig : _auth0Config;

                StatusTextBlock.Text = "Getting token silently...";

                var authResult = await _msalPublicApp
                    .AcquireTokenSilent(config.Scopes, firstAccount)
                    .ExecuteAsync();

                // If this is hybrid flow, also refresh SAML assertion
                if (_currentFlow == AuthFlow.OidcThenSaml)
                {
                    _currentAuthResult = authResult;
                    StatusTextBlock.Text = "Token acquired silently. Refreshing SAML assertion...";
                    WebView.Visibility = Visibility.Visible;

                    var samlResult = await InitiateSamlAssertionWithBrowserSession(config);
                    _currentSamlResult = samlResult;
                    DisplayHybridAuthResult(authResult, samlResult);
                    WebView.Visibility = Visibility.Collapsed;
                }
                else
                {
                    DisplayAuthResult(authResult);
                }

                StatusTextBlock.Text = "Token acquired silently";
            }
            catch (MsalUiRequiredException)
            {
                StatusTextBlock.Text = "Silent token acquisition failed. User interaction required.";
                if (_currentFlow == AuthFlow.OidcThenSaml)
                {
                    await PerformOidcThenSamlFlow();
                }
                else
                {
                    await PerformInteractiveLogin();
                }
            }
        }

        private async Task PerformLogout()
        {
            try
            {
                if ((_currentFlow == AuthFlow.AuthorizationCode || _currentFlow == AuthFlow.OidcThenSaml) && _msalPublicApp != null)
                {
                    var accounts = await _msalPublicApp.GetAccountsAsync();

                    foreach (var account in accounts)
                    {
                        await _msalPublicApp.RemoveAsync(account);
                    }
                }

                TokenTextBox.Clear();
                _currentAuthResult = null;
                _currentSamlResult = null;
                _samlCompletionSource?.TrySetCanceled();
                _samlCompletionSource = null;

                var logoutLink = _currentProvider == OAuthProvider.Okta
                    ? "about:blank"
                    : $"{_auth0Config.AuthorityUrl}/v2/logout?client_id={_auth0Config.ClientId}&returnTo={_auth0Config.RedirectUri}";

                WebView.CoreWebView2.Navigate(logoutLink);
                StatusTextBlock.Text = "Logged out successfully";
                LoginButton.IsEnabled = true;
                LogoutButton.IsEnabled = false;
                GetTokenSilentButton.IsEnabled = false;
                WebView.Visibility = Visibility.Collapsed;
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Logout failed: {ex.Message}";
            }
        }

        private Dictionary<string, string> GetExtraQueryParameters()
        {
            var extraParams = new Dictionary<string, string>();

            if (_currentProvider == OAuthProvider.Auth0)
            {
                extraParams.Add("audience", "https://dev-t2bzy5qqqml628wg.us.auth0.com/api/v2/");
            }

            return extraParams;
        }

        private void DisplayClientCredentialsResult(AuthenticationResult authResult)
        {
            var tokenDisplay = new StringBuilder();
            tokenDisplay.AppendLine($"Provider: {_currentProvider}");
            tokenDisplay.AppendLine($"Flow: Client Credentials");
            tokenDisplay.AppendLine($"Access Token: {authResult.AccessToken}");
            tokenDisplay.AppendLine($"Token Type: Bearer");
            tokenDisplay.AppendLine($"Expires On: {authResult.ExpiresOn:yyyy-MM-dd HH:mm:ss} UTC");
            tokenDisplay.AppendLine($"Scopes: {string.Join(" ", authResult.Scopes)}");
            tokenDisplay.AppendLine($"Correlation ID: {authResult.CorrelationId}");
            tokenDisplay.AppendLine($"Token Source: {authResult.AuthenticationResultMetadata?.TokenSource}");

            tokenDisplay.AppendLine($"\nNote: Client Credentials flow is for service-to-service authentication");
            tokenDisplay.AppendLine($"No user context or ID token available");

            TokenTextBox.Text = tokenDisplay.ToString();
        }

        private void DisplayAuthResult(AuthenticationResult authResult)
        {
            var tokenDisplay = new StringBuilder();
            tokenDisplay.AppendLine($"Provider: {_currentProvider}");
            tokenDisplay.AppendLine($"Access Token: {authResult.AccessToken}");
            tokenDisplay.AppendLine($"Token Type: Bearer");
            tokenDisplay.AppendLine($"Expires On: {authResult.ExpiresOn:yyyy-MM-dd HH:mm:ss} UTC");

            if (!string.IsNullOrEmpty(authResult.IdToken))
                tokenDisplay.AppendLine($"ID Token: {authResult.IdToken}");

            tokenDisplay.AppendLine($"Scopes: {string.Join(" ", authResult.Scopes)}");
            tokenDisplay.AppendLine($"Account: {authResult.Account?.Username}");
            tokenDisplay.AppendLine($"Account ID: {authResult.Account?.HomeAccountId?.Identifier}");

            if (authResult.Account?.Environment != null)
                tokenDisplay.AppendLine($"Environment: {authResult.Account.Environment}");

            tokenDisplay.AppendLine($"\nCorrelation ID: {authResult.CorrelationId}");
            tokenDisplay.AppendLine($"Authentication Result Source: {authResult.AuthenticationResultMetadata?.TokenSource}");

            TokenTextBox.Text = tokenDisplay.ToString();
        }

        private async void LogoutButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                await PerformLogout();
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Logout Error: {ex.Message}";
            }
        }

        private async void GetTokenSilentButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                await GetTokenSilent();
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Silent Token Error: {ex.Message}";
                TokenTextBox.Text = ex.ToString();
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            _customWebView?.Dispose();
            _samlCompletionSource?.TrySetCanceled();

            // Unsubscribe from WebView events
            if (WebView?.CoreWebView2 != null)
            {
                WebView.CoreWebView2.NavigationStarting -= CoreWebView2_NavigationStarting;
                WebView.CoreWebView2.NavigationCompleted -= CoreWebView2_NavigationCompleted;
                WebView.CoreWebView2.WebResourceResponseReceived -= CoreWebView2_WebResourceResponseReceived;
                WebView.CoreWebView2.WebResourceRequested -= CoreWebView2_WebResourceRequested;
            }

            base.OnClosed(e);
        }
    }

    // Enhanced Custom WebView implementation for MSAL with SAML support
    public class CustomWebView : ICustomWebUi, IDisposable
    {
        private readonly Microsoft.Web.WebView2.Wpf.WebView2 _webView;
        private TaskCompletionSource<Uri> _tcs;

        public CustomWebView(Microsoft.Web.WebView2.Wpf.WebView2 webView)
        {
            _webView = webView;
            _webView.NavigationCompleted += OnNavigationCompleted;
        }

        public async Task<Uri> AcquireAuthorizationCodeAsync(Uri authorizationUri, Uri redirectUri, CancellationToken cancellationToken)
        {
            _tcs = new TaskCompletionSource<Uri>();

            // Navigate to the authorization URI
            await _webView.Dispatcher.InvokeAsync(() =>
            {
                _webView.CoreWebView2.Navigate(authorizationUri.ToString());
            });

            // Register cancellation
            cancellationToken.Register(() => {
                _tcs?.TrySetCanceled();
            });

            // Wait for the navigation to complete and return the redirect URI
            return await _tcs.Task;
        }

        private void OnNavigationCompleted(object sender, CoreWebView2NavigationCompletedEventArgs e)
        {
            var currentUri = new Uri(_webView.CoreWebView2.Source);

            // Check if this is the redirect URI
            if (currentUri.Authority.Contains("localhost") && currentUri.Port == 5001)
            {
                _tcs?.TrySetResult(currentUri);
            }
        }

        public void Dispose()
        {
            if (_webView != null)
            {
                _webView.NavigationCompleted -= OnNavigationCompleted;
            }
            _tcs?.TrySetCanceled();
        }
    }
}
