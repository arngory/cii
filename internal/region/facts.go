package region

import (
	"encoding/json"

	"github.com/arngory/cii/internal/probe"
)

func withFacts(c probe.Check, facts func(body []byte) *probe.Facts) probe.Check {
	eval := c.Eval
	c.Eval = func(rs []*probe.Response) []probe.Result {
		out := eval(rs)
		if len(out) == 1 && out[0].Status == probe.OK {
			out[0].Facts = facts(rs[0].Body).OrNil()
		}
		return out
	}
	return c
}

func ipqueryFacts(body []byte) *probe.Facts {
	var d struct {
		Risk *struct {
			IsMobile     *bool    `json:"is_mobile"`
			IsVPN        *bool    `json:"is_vpn"`
			IsTor        *bool    `json:"is_tor"`
			IsProxy      *bool    `json:"is_proxy"`
			IsDatacenter *bool    `json:"is_datacenter"`
			RiskScore    *float64 `json:"risk_score"`
		} `json:"risk"`
	}
	if json.Unmarshal(body, &d) != nil || d.Risk == nil {
		return nil
	}
	r := d.Risk
	f := &probe.Facts{}
	f.SetIf(probe.Proxy, r.IsProxy)
	f.SetIf(probe.VPN, r.IsVPN)
	f.SetIf(probe.Tor, r.IsTor)
	f.SetIf(probe.Hosting, r.IsDatacenter)
	if r.IsMobile != nil && *r.IsMobile {
		f.Usage = "mobile"
	}
	if r.RiskScore != nil {
		f.SetScore(*r.RiskScore)
	}
	return f
}

func ip2locationFacts(body []byte) *probe.Facts {
	var d struct {
		IsProxy *bool `json:"is_proxy"`
	}
	if json.Unmarshal(body, &d) != nil {
		return nil
	}
	f := &probe.Facts{}
	f.SetIf(probe.Proxy, d.IsProxy)
	return f
}

func ipAPIFacts(body []byte) *probe.Facts {
	var d struct {
		Proxy   *bool `json:"proxy"`
		Hosting *bool `json:"hosting"`
		Mobile  *bool `json:"mobile"`
	}
	if json.Unmarshal(body, &d) != nil {
		return nil
	}
	f := &probe.Facts{}
	f.SetIf(probe.Proxy, d.Proxy)
	f.SetIf(probe.Hosting, d.Hosting)
	if d.Mobile != nil && *d.Mobile {
		f.Usage = "mobile"
	}
	return f
}

func ipregistryFacts(body []byte) *probe.Facts {
	var d struct {
		Connection *struct {
			Type string `json:"type"`
		} `json:"connection"`
		Company *struct {
			Type string `json:"type"`
		} `json:"company"`
		Security *struct {
			IsAbuser        *bool `json:"is_abuser"`
			IsAttacker      *bool `json:"is_attacker"`
			IsCloudProvider *bool `json:"is_cloud_provider"`
			IsProxy         *bool `json:"is_proxy"`
			IsTor           *bool `json:"is_tor"`
			IsTorExit       *bool `json:"is_tor_exit"`
			IsVPN           *bool `json:"is_vpn"`
		} `json:"security"`
	}
	if json.Unmarshal(body, &d) != nil {
		return nil
	}
	f := &probe.Facts{}
	if d.Connection != nil {
		f.SetUsage(d.Connection.Type)
	}
	if d.Company != nil {
		f.SetCompany(d.Company.Type)
	}
	if s := d.Security; s != nil {
		f.SetIf(probe.Proxy, s.IsProxy)
		f.SetIf(probe.VPN, s.IsVPN)
		f.SetIf(probe.Tor, s.IsTor)
		f.SetIf(probe.Tor, s.IsTorExit)
		f.SetIf(probe.Hosting, s.IsCloudProvider)
		f.SetIf(probe.Abuser, s.IsAbuser)
		f.SetIf(probe.Abuser, s.IsAttacker)
	}
	return f
}
