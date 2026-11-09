package clientids

const (
	NowEVodBody   = `{"contentId":"202310181863841","contentType":"Vod","pin":"","deviceName":"Browser","deviceId":"w-678913af-3998-3998-3998-39983998","deviceType":"WEB","secureCookie":null,"callerReferenceNo":"W17370372345461425","profileId":null,"mupId":null,"trackId":"738296446.226.1737037103860.2","sessionId":"c39f03e6-9e74-4d24-a82f-e0d0f328bb70"}`
	ViuTVLiveBody = `{"callerReferenceNo":"20210726112323","contentId":"099","contentType":"Channel","channelno":"099","mode":"prod","deviceId":"29b3cb117a635d5b56","deviceType":"ANDROID_WEB"}`

	LiTVURLsBodyFormat = `{"AssetId":"vod70810-000001M001_1500K","MediaType":"vod","puid":"%s"}`
	LineTVTWAppID      = "062097f1b1f34e11e7f82aag22000aee"
	CatchPlayBasicAuth = "NTQ3MzM0NDgtYTU3Yi00MjU2LWE4MTEtMzdlYzNkNjJmM2E0Ok90QzR3elJRR2hLQ01sSDc2VEoy"

	WavveStreamingQuery   = "device=pc&partner=pooq&apikey=E5F3E0D30947AA5440556471321BB6D9&credential=none&service=wavve&pooqzone=none&region=kor&drm=pr&targetage=all&contentid=MV_C3001_C300000012559&contenttype=movie&hdr=sdr&videocodec=avc&audiocodec=ac3&issurround=n&format=normal&withinsubtitle=n&action=dash&protocol=dash&quality=auto&deviceModelId=Windows%2010&guid=1a8e9c88-6a3b-11ed-8584-eed06ef80652&lastplayid=none&authtype=cookie&isabr=y&ishevc=n"
	TvingAPIKey           = "1e7952d0917d6aab1f0293a063697610"
	SpotvNowBrightcoveKey = "BCpkADawqM0U3mi_PT566m5lvtapzMq3Uy7ICGGjGB6v4Ske7ZX_ynzj8ePedQJhH36nym_5mbvSYeyyHOOdUsZovyg2XlhV6rRspyYPw_USVNLaR0fB_AAL2HSQlfuetIPiEzbUs1tpNF9NtQxt3BAPvXdOAsvy1ltLPWMVzJHiw9slpLRgI2NUufc"

	DMMTVStreamingBody   = `{"player_name":"dmmtv_browser","player_version":"0.0.0","content_type_detail":"VOD_SVOD","content_id":"11uvjcm4fw2wdu7drtd1epnvz","purchase_product_id":null}`
	TelasaDeviceID       = "d36f8e6b-e344-4f5e-9a55-90aeb3403799"
	UNextPlaylistQuery   = `{"operationName":"cosmo_getPlaylistUrl","variables":{"code":"ED00479780","playMode":"caption","bitrateLow":192,"bitrateHigh":null,"validationOnly":false},"query":"query cosmo_getPlaylistUrl($code: String, $playMode: String, $bitrateLow: Int, $bitrateHigh: Int, $validationOnly: Boolean) {\n  webfront_playlistUrl(\n    code: $code\n    playMode: $playMode\n    bitrateLow: $bitrateLow\n    bitrateHigh: $bitrateHigh\n    validationOnly: $validationOnly\n  ) {\n    resultStatus\n    result {\n      errorCode\n      errorMessage\n      __typename\n    }\n    __typename\n  }\n}\n"}`
	LeminoServiceToken   = "f365771afd91452fa279863f240c233d"
	LeminoTraceID        = "556db33f-d739-4a82-84df-dd509a8aa179"
	LeminoWatchReadyBody = `{"inflow_flows":[null,"crid://plala.iptvf.jp/group/b100ce3"],"play_type":1,"key_download_only":null,"quality":null,"groupcast":null,"avail_status":"1","terminal_type":3,"test_account":0,"content_list":[{"kind":"main","service_id":null,"cid":"00lm78dz30","lid":"a0lsa6kum1","crid":"crid://plala.iptvf.jp/vod/0000000000_00lm78dymn","preview":0,"trailer":0,"auto_play":0,"stop_position":0}]}`
	AnimeFestaTrackingID = "yEZr4P_U7JEdBucZOkv1Y"

	KonosubaFDUserAgent     = "pj0007/212 CFNetwork/1240.0.4 Darwin/20.6.0"
	ProjectSekaiUserAgent   = "pjsekai/48 CFNetwork/1240.0.4 Darwin/20.6.0"
	ProjectSekaiVersionPath = "1.8.1/3ed70b6a-8352-4532-b819-108837926ff5"
)
