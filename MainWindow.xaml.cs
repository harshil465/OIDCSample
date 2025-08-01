using Microsoft.Identity.Client;
using Microsoft.Identity.Client.Extensibility;
using Microsoft.Web.WebView2.Core;
using System;
using System.Collections.Generic;
using System.IdentityModel;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace OktaMSALSample
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public enum OAuthProvider
    {
        Okta,
        Auth0
    }

    public enum AuthFlow
    {
        AuthorizationCode,
        ClientCredentials
    }

    public class OAuthConfig
    {
        public string ClientId { get; set; }
        public string AuthorityUrl { get; set; }
        public string RedirectUri { get; set; }
        public string[] Scopes { get; set; }
    }

    public class ClientCredentialsConfig
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
        public string AuthorityUrl { get; set; }
        public string[] Scopes { get; set; }
        public string Audience { get; set; }
    }

    public partial class MainWindow : Window
    {
        private IPublicClientApplication _msalPublicApp;
        private IConfidentialClientApplication _msalConfidentialApp;
        private CustomWebView _customWebView;
        private OAuthProvider _currentProvider;
        private AuthFlow _currentFlow;

        // OAuth Configuration for Authorization Code Flow

        private readonly OAuthConfig _oktaConfig = new OAuthConfig
        {
            ClientId = "0oatjdh6ftvpqibz8697",
            AuthorityUrl = "https://integrator-1355928.okta.com/oauth2/default",
            RedirectUri = "https://localhost:5001/",
            Scopes = new[] { "openid", "profile", "email" }
        };

        private readonly OAuthConfig _auth0Config = new OAuthConfig
        {
            ClientId = "EsiZ79MDvhK8fgNo7SPkU0HkW8TNcLIQ",
            AuthorityUrl = "https://dev-t2bzy5qqqml628wg.us.auth0.com",
            RedirectUri = "https://localhost:5001/",
            Scopes = new[] { "openid", "profile", "email" }
        };

        // Client Credentials Configuration
        private readonly ClientCredentialsConfig _oktaClientCredentialsConfig = new ClientCredentialsConfig
        {
            ClientId = "0oati8dzjrPdwCfYZ697",
            ClientSecret = "8K8ysI7Na87tz4DEvDcW7PEp7rIphXO_2nHIsXudt4F1Vk9Q1SgYjN-BWyCKzKdx",
            AuthorityUrl = "https://integrator-1355928.okta.com/oauth2/austos83vyikUni0E697",
            Scopes = new[] { "read:data" }, // Your custom scopes
            Audience = "api://default"
        };

        private readonly ClientCredentialsConfig _auth0ClientCredentialsConfig = new ClientCredentialsConfig
        {
            ClientId = "0jNPEUVe168UiAitRREkJMTYwwiVPSNs",
            ClientSecret = "1MGfPINLyDYZV4ghq-sbd0PTakxc2DidaE6kes92M4NNrpKtfdw6r7z6lyjSisPe",
            AuthorityUrl = "https://dev-t2bzy5qqqml628wg.us.auth0.com",
            Scopes = new[] { "read:users"}, // Your custom scopes
            Audience = "https://dev-t2bzy5qqqml628wg.us.auth0.com/api/v2/"
        };

        public MainWindow()
        {
            InitializeComponent();
            InitializeWebView();
        }

        private async void InitializeWebView()
        {
            try
            {
                await WebView.EnsureCoreWebView2Async(null);
                _customWebView = new CustomWebView(WebView);
                StatusTextBlock.Text = "Ready for authentication with MSAL";
            }
            catch (Exception ex)
            {   
                MessageBox.Show($"Failed to initialize WebView2: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                _currentProvider = ProviderComboBox.SelectedIndex == 0 ? OAuthProvider.Okta : OAuthProvider.Auth0;
                _currentFlow = FlowComboBox.SelectedIndex == 0 ? AuthFlow.AuthorizationCode : AuthFlow.ClientCredentials;

                if (_currentFlow == AuthFlow.AuthorizationCode)
                {
                    await InitializeMsalPublicApp();
                    await PerformInteractiveLogin();
                }
                else
                {
                    await InitializeMsalConfidentialApp();
                    await PerformClientCredentialsFlow();
                }
            }
            catch (Exception ex)
            {
                StatusTextBlock.Text = $"Login Error: {ex.Message}";
                TokenTextBox.Text = ex.ToString();
            }
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

            // Add audience for Auth0 if specified
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
                GetTokenSilentButton.IsEnabled = false; // Not applicable for client credentials
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
                if (_currentFlow != AuthFlow.AuthorizationCode)
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

                DisplayAuthResult(authResult);
                StatusTextBlock.Text = "Token acquired silently";
            }
            catch (MsalUiRequiredException)
            {
                StatusTextBlock.Text = "Silent token acquisition failed. User interaction required.";
                await PerformInteractiveLogin();
            }
        }

        private async Task PerformLogout()
        {
            try
            {
                if (_currentFlow == AuthFlow.AuthorizationCode && _msalPublicApp != null)
                {
                    var accounts = await _msalPublicApp.GetAccountsAsync();

                    foreach (var account in accounts)
                    {
                        await _msalPublicApp.RemoveAsync(account);
                    }
                }

                TokenTextBox.Clear();
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

            // Add provider-specific parameters for Authorization Code flow
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

            // Client credentials flow doesn't have ID token or user account
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

            // Display PKCE information (if available in logs)
            tokenDisplay.AppendLine($"\nCorrelation ID: {authResult.CorrelationId}");
            tokenDisplay.AppendLine($"Authentication Result Source: {authResult.AuthenticationResultMetadata?.TokenSource}");

            TokenTextBox.Text = tokenDisplay.ToString();
        }

        protected override void OnClosed(EventArgs e)
        {
            _customWebView?.Dispose();
            base.OnClosed(e);
        }
    }

    // Custom WebView implementation for MSAL
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
        }
    }
}
