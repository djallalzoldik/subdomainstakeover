package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
	"bufio"
	"os"
	"github.com/fatih/color"
)

type provider struct {
	Name        string
	Fingerprint *regexp.Regexp
}

var knownProviders = []provider{
	{
		Name:        "Amazon S3",
		Fingerprint: regexp.MustCompile(`<Code>NoSuchBucket</Code>`),
	},
	{
		Name:        "Heroku",
		Fingerprint: regexp.MustCompile(`There's nothing here.`),
	},
	{
		Name:        "GitHub Pages",
		Fingerprint: regexp.MustCompile(`There isn't a GitHub Pages site here.`),
	},
	{
		Name:        "GitLab Pages",
		Fingerprint: regexp.MustCompile(`<title>.* - GitLab Pages</title>`),
	},
	{
		Name:        "Microsoft Azure",
		Fingerprint: regexp.MustCompile(`The resource you are looking for has been removed, had its name changed, or is temporarily unavailable.`),
	},
	{
		Name:        "Fastly",
		Fingerprint: regexp.MustCompile(`Fastly error: unknown domain:`),
	},
	{
		Name:        "WordPress.com",
		Fingerprint: regexp.MustCompile(`Do you want to register .*`),
	},
	{
		Name:        "Tilda",
		Fingerprint: regexp.MustCompile(`<title>.* – is this your website\\?</title>`),
	},
	{
		Name:        "Shopify",
		Fingerprint: regexp.MustCompile(`Sorry, this shop is currently unavailable.`),
	},
	{
		Name:        "Netlify",
		Fingerprint: regexp.MustCompile(`<title>Site Not Found</title>`),
	},
	{
		Name:        "Pantheon",
		Fingerprint: regexp.MustCompile(`<title>.* is parked on Pantheon</title>`),
	},
	{
		Name:        "Tumblr",
		Fingerprint: regexp.MustCompile(`There's nothing here\\. <a href="https://www.tumblr.com">Whatever you were looking for doesn't currently exist at this address\\.</a>`),
	},
	{
		Name:        "Cloudflare",
		Fingerprint: regexp.MustCompile(`Error 1001 \\| DNS resolution error`),
	},
	{
		Name:        "Fly",
		Fingerprint: regexp.MustCompile(`404 Site .*fly.dev is not served on this interface`),
	},
	{
		Name:        "Cargo",
		Fingerprint: regexp.MustCompile(`<title>404 Page Not Found \\| Cargo</title>`),
	},
	{
		Name:        "Unbounce",
		Fingerprint: regexp.MustCompile(`<title>.* - Unbounce</title>`),
	},
	{
		Name:        "Surge",
		Fingerprint: regexp.MustCompile(`project not found`),
	},
	{
		Name:        "Webflow",
		Fingerprint: regexp.MustCompile(`The page you are looking for doesn't exist or has been moved.`),
	},
	{
		Name:        "Read the Docs",
		Fingerprint: regexp.MustCompile(`This domain is not served by Read the Docs`),
	},
	{
		Name:        "Hatena Blog",
		Fingerprint: regexp.MustCompile(`The page you were looking for doesn't exist \\(404\\)`),
	},
	{
		Name:        "Help Scout",
		Fingerprint: regexp.MustCompile(`No settings were found for this company:`),
	},
	{
		Name:        "Zendesk",
		Fingerprint: regexp.MustCompile(`Help Center Closed`),
	},
	{
		Name:        "Kinsta",
		Fingerprint: regexp.MustCompile(`No Site For Domain`),
	},
	{
		Name:        "Ghost",
		Fingerprint: regexp.MustCompile(`<title>Ghost \\| Sign in</title>`),
	},
	{
		Name:        "Acquia",
		Fingerprint: regexp.MustCompile(`Site not found · Acquia`),
	},
	{
		Name:        "Big Cartel",
		Fingerprint: regexp.MustCompile(`This shop is not available`),
	},
	{
		Name:        "Bitbucket",
		Fingerprint: regexp.MustCompile(`Repository not found`),
	},
	{
		Name:        "Brightcove",
		Fingerprint: regexp.MustCompile(`The page you have requested has been removed or is temporarily unavailable.`),
	},
	{
		Name:        "Campaign Monitor",
		Fingerprint: regexp.MustCompile(`double-check that the domain is correctly configured`),
	},
	{
		Name:        "Cargo Collective",
		Fingerprint: regexp.MustCompile(`You have reached a domain that is pending ICANN verification`),
	},
	{
		Name:        "Desk",
		Fingerprint: regexp.MustCompile(`Please try again or try Desk.com free for 14 days`),
	},
	{
		Name:        "Distil Networks",
		Fingerprint: regexp.MustCompile(`The requested URL was not found on this server.`),
	},
	{
		Name:        "Freshdesk",
		Fingerprint: regexp.MustCompile(`The page you're looking for is currently unavailable`),
	},
	{
		Name:        "G Suite",
		Fingerprint: regexp.MustCompile(`Sorry, this page is not available`),
	},
	{
		Name:        "Intercom",
		Fingerprint: regexp.MustCompile(`This page is no longer available`),
	},
	{
		Name:        "Launchrock",
		Fingerprint: regexp.MustCompile(`It looks like you may have taken a wrong turn somewhere. Don't worry...it happens to all of us.`),
	},
	{
		Name:        "Mashery",
		Fingerprint: regexp.MustCompile(`Unrecognized domain`),
	},
	{
		Name:        "StatusPage",
		Fingerprint: regexp.MustCompile(`You've Discovered A Missing Link`),
	},
	{
		Name:        "Strikingly",
		Fingerprint: regexp.MustCompile(`Looks like you've accessed a page that doesn't exist`),
	},
	{
		Name:        "Thinkific",
		Fingerprint: regexp.MustCompile(`You may have mistyped the address or the page may have moved`),
	},
	{
		Name:        "Tictail",
		Fingerprint: regexp.MustCompile(`There's nothing here... yet`),
	},
	{
		Name:        "Uptime Robot",
		Fingerprint: regexp.MustCompile(`This domain is no longer being monitored`),
	},
	{
		Name:        "Uservoice",
		Fingerprint: regexp.MustCompile(`This UserVoice subdomain is currently available!`),
	},
	{
		Name:        "Wishpond",
		Fingerprint: regexp.MustCompile(`This account has been deactivated`),
	},
	{
		Name:        "Wix",
		Fingerprint: regexp.MustCompile(`Looks like this domain isn't connected to a website yet!`),
	},
	{
		Name:        "Wordpress",
		Fingerprint: regexp.MustCompile(`Do you want to register this domain and start building your website?`),
	},
	{
		Name:        "Worksites",
		Fingerprint: regexp.MustCompile(`Sorry, we couldn't find the page you're looking for`),
	},
	
	
}




func resolveSubdomain(subdomain string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resolver := net.Resolver{}

	ips, err := resolver.LookupIPAddr(ctx, subdomain)
	if err != nil {
		return "", err
	}

	return ips[0].String(), nil
}


func sendRequest(subdomain string) (*http.Response, error) {
	client := http.Client{
		Timeout: 5 * time.Second,
	}

	response, err := client.Get("http://" + subdomain)
	if err != nil {
		return nil, err
	}

	return response, nil
}

func checkSubdomainTakeover(response *http.Response) (bool, string) {
	defer response.Body.Close()

	body, _ := ioutil.ReadAll(response.Body)

	for _, provider := range knownProviders {
		if provider.Fingerprint.Match(body) {
			return true, provider.Name
		}
	}

	return false, ""
}

func scanSubdomain(subdomain string, wg *sync.WaitGroup) {
	defer wg.Done()

	ip, err := resolveSubdomain(subdomain)
	if err != nil {
		fmt.Println("Error resolving subdomain:", err)
		return
	}

	response, err := sendRequest(subdomain)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}

	takeover, provider := checkSubdomainTakeover(response)
	if takeover {
		fmt.Println(color.RedString("Subdomain takeover detected:"), subdomain, "by", provider, "at IP", ip)
	} else {
		fmt.Println(color.GreenString("No takeover detected:"), subdomain, "at IP", ip)
	}
}

func main() {
	scanner := bufio.NewScanner(os.Stdin)
	var subdomains []string

	for scanner.Scan() {
		subdomain := strings.TrimSpace(scanner.Text())
		if subdomain != "" {
			subdomains = append(subdomains, subdomain)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading subdomains: %v\n", err)
		os.Exit(1)
	}

	var wg sync.WaitGroup
	wg.Add(len(subdomains))

	for _, subdomain := range subdomains {
		go scanSubdomain(subdomain, &wg)
	}

	wg.Wait()
}


