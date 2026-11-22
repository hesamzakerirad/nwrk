package community

// Disclosure is the text that nw shows before any measurement. It must match
// the public privacy notice.
var Disclosure = []string{
	"Contributing is optional. It happens only when you run this command and agree.",
	"nw runs the checks of the profile on this machine, then shows you the exact result. Nothing is uploaded unless you agree after you see it.",
	"The upload holds, for each service: the check type (DNS, TCP, TLS or HTTP), the IP version, success or failure, the time in milliseconds, and sometimes an HTTP status code, the number of DNS answers or an error code. It also holds the nw version and the profile name.",
	"The upload never holds your addresses, your DNS resolver addresses, the addresses of the services, certificates, headers, URLs, your computer name or any device or installation ID.",
	"The server sees the address your connection comes from. It uses it, in memory only, to look up your country and network (ASN), and it stores the country and the ASN with your results. It does not store the address.",
	"The server is hosted in Iran. Anyone with legal or technical access to the server, including the hosting provider and authorities, can read what it stores. If this is a risk for you, use --dry-run, which never contacts the server.",
	"Your internet provider can see that your connection goes to the NWRK server, and when. It cannot read the upload.",
	"Results are kept without a set limit for now. Nothing links a result to a person, so one person's result cannot be found and deleted later.",
	"If you use a VPN or a proxy, the server sees the address of the VPN or proxy. Results from outside Iran are not stored.",
}
