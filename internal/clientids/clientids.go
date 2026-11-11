package clientids

const (
	TwitchClientID = "kimne78kx3ncx6brgo4mv6wki5h1ko"
	TwitchQuery    = `[{"operationName":"VerifyEmail_CurrentUser","variables":{},"extensions":{"persistedQuery":{"version":1,"sha256Hash":"f9e7dcdf7e99c314c82d8f7f725fab5f99d1df3d7359b53c9ae122deec590198"}}}]`

	ChatGPTStatsigKey = "client-zUdXdSTygXJdzoE0sWTkP8GKTVsUMF2IRM7ShVO2JAG"

	ClaudeAndroidUA      = "Claude com.anthropic.claude/1.261023.20 (Android 30) Claude/1.261023.20"
	ClaudePlatformHeader = "android"

	FastToken = "YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm"

	SpotifySignupKey = "142b583129b2df829de3656f9eb484e6"
	SpotifyClientID  = "9a8d2f0ce77a4e248bb71fefcb557637"

	DisneyPlusAPIKey = "ZGlzbmV5JmFuZHJvaWQmMS4wLjA.bkeb0m230uUhv8qrAXuNu39tbE_mD5EEhM_NAcohjyA"
	DisneyPlusQuery  = `{"query":"mutation registerDevice($registerDevice: RegisterDeviceInput!) { registerDevice(registerDevice: $registerDevice) { __typename } }","variables":{"registerDevice":{"applicationRuntime":"android","attributes":{"operatingSystem":"Android","operatingSystemVersion":"13"},"deviceFamily":"android","deviceLanguage":"en","deviceProfile":"phone","devicePlatformId":"android"}},"operationName":"registerDevice"}`

	YouTubePremiumQuery = `{"context":{"client":{"clientName":"MWEB","clientVersion":"2.20261020.00.00","hl":"en","gl":"US"}},"browseId":"SPunlimited"}`

	DAZNStartupBody = `{"Version":"2","LandingPageKey":"generic","Languages":"en-US","Platform":"web","Manufacturer":"","PromoCode":"","PlatformAttributes":{}}`
)
