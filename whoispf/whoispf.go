package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/likexian/whois"
	"github.com/olekukonko/tablewriter"
)

type WhoisInfo struct {
	Target   string
	NetOrg   string
	Location string
	Country  string
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] target1 [target2 ...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Targets can be IP addresses, CIDR ranges (only the first IP is used), or file paths containing a list of targets.\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -spf string    Domain to fetch SPF allowed IPs recursively.\n")
		fmt.Fprintf(os.Stderr, "  -plain         Disable fancy mode and use plain text output.\n")
		fmt.Fprintf(os.Stderr, "  -verbose       Enable verbose output of operations.\n")
	}
	spfDomain := flag.String("spf", "", "Domain to fetch SPF allowed IPs recursively")
	plainMode := flag.Bool("plain", false, "Disable fancy mode and use plain text output")
	verboseMode := flag.Bool("verbose", false, "Enable verbose output of operations")
	flag.Parse()

	var targets []string
	if *spfDomain != "" {
		if *verboseMode {
			fmt.Printf("Fetching SPF IPs for domain: %s\n", *spfDomain)
		}
		spfIPs, err := getSPFIPs(*spfDomain)
		if err != nil {
			log.Printf("Error fetching SPF IPs for domain %s: %v", *spfDomain, err)
		} else {
			targets = append(targets, spfIPs...)
		}
	}
	for _, arg := range flag.Args() {
		if fileInfo, err := os.Stat(arg); err == nil && !fileInfo.IsDir() {
			if *verboseMode {
				fmt.Printf("Reading targets from file: %s\n", arg)
			}
			fileTargets, err := readTargetsFromFile(arg)
			if err != nil {
				log.Printf("Error reading file %s: %v", arg, err)
				continue
			}
			targets = append(targets, fileTargets...)
		} else {
			targets = append(targets, arg)
		}
	}
	if len(targets) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	var results []WhoisInfo
	for _, target := range targets {
		if *verboseMode {
			fmt.Printf("Processing target: %s\n", target)
		}
		normTarget := normalizeTarget(target)
		if *verboseMode {
			fmt.Printf("Normalized target: %s\n", normTarget)
		}
		whoisData, err := getWhois(normTarget)
		if err != nil {
			log.Printf("Error retrieving whois for %s: %v", normTarget, err)
			continue
		}
		if *verboseMode {
			fmt.Printf("Retrieved whois data for %s\n", normTarget)
		}
		netname, orgname, location, country := parseWhois(whoisData)
		netorg := netname
		if orgname != "" {
			if netorg != "" {
				netorg = netorg + " / " + orgname
			} else {
				netorg = orgname
			}
		}
		results = append(results, WhoisInfo{
			Target:   target,
			NetOrg:   netorg,
			Location: location,
			Country:  country,
		})
	}
	if *plainMode {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "IP/CIDR\tNetName / OrgName\tLocation\tCountry/TLD")
		fmt.Fprintln(w, "-------\t-----------------\t--------\t-----------")
		for _, info := range results {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", info.Target, info.NetOrg, info.Location, info.Country)
		}
		w.Flush()
	} else {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"IP/CIDR", "NetName / OrgName", "Location", "Country/TLD"})
		table.SetBorder(true)
		table.SetRowLine(true)
		table.SetHeaderColor(
			tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiBlueColor},
			tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiBlueColor},
			tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiBlueColor},
			tablewriter.Colors{tablewriter.Bold, tablewriter.FgHiBlueColor},
		)
		table.SetColumnAlignment([]int{
			tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT, tablewriter.ALIGN_LEFT,
		})
		for _, info := range results {
			table.Append([]string{info.Target, info.NetOrg, info.Location, info.Country})
		}
		table.Render()
	}
}

func readTargetsFromFile(filePath string) ([]string, error) {
	var targets []string
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return targets, nil
}

func getWhois(target string) (string, error) {
	return whois.Whois(target)
}

func parseWhois(data string) (netname, orgname, location, country string) {
	netname = extractField(data, `(?i)netname:\s*(.+)`)
	orgname = extractField(data, `(?i)(?:org[-]?name|organization|owner):\s*(.+)`)
	location = extractField(data, `(?i)location:\s*(.+)`)
	if location == "" {
		location = extractField(data, `(?i)address:\s*(.+)`)
	}
	country = extractField(data, `(?i)country:\s*(.+)`)
	return strings.TrimSpace(netname), strings.TrimSpace(orgname), strings.TrimSpace(location), strings.TrimSpace(country)
}

func extractField(data, pattern string) string {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(data)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

func getSPFIPs(domain string) ([]string, error) {
	visited := make(map[string]bool)
	return getSPFIPsRecursive(domain, visited)
}

func getSPFIPsRecursive(domain string, visited map[string]bool) ([]string, error) {
	if visited[domain] {
		return nil, nil
	}
	visited[domain] = true
	txts, err := net.LookupTXT(domain)
	if err != nil {
		return nil, err
	}
	var spfRecord string
	for _, txt := range txts {
		if strings.HasPrefix(txt, "v=spf1") {
			spfRecord = txt
			break
		}
	}
	if spfRecord == "" {
		return nil, fmt.Errorf("no SPF record found for domain %s", domain)
	}
	tokens := strings.Fields(spfRecord)
	var ips []string
	for _, token := range tokens {
		token = strings.TrimLeft(token, "+-~?")
		switch {
		case strings.HasPrefix(token, "ip4:"):
			ip := strings.TrimPrefix(token, "ip4:")
			ips = append(ips, ip)
		case strings.HasPrefix(token, "ip6:"):
			ip := strings.TrimPrefix(token, "ip6:")
			ips = append(ips, ip)
		case strings.HasPrefix(token, "include:"):
			includeDomain := strings.TrimPrefix(token, "include:")
			subIPs, err := getSPFIPsRecursive(includeDomain, visited)
			if err != nil {
				log.Printf("Error fetching SPF for include domain %s: %v", includeDomain, err)
			} else {
				ips = append(ips, subIPs...)
			}
		case strings.HasPrefix(token, "redirect="):
			redirectDomain := strings.TrimPrefix(token, "redirect=")
			subIPs, err := getSPFIPsRecursive(redirectDomain, visited)
			if err != nil {
				log.Printf("Error fetching SPF for redirect domain %s: %v", redirectDomain, err)
			} else {
				ips = append(ips, subIPs...)
			}
		}
	}
	return ips, nil
}

func normalizeTarget(target string) string {
	if ip, _, err := net.ParseCIDR(target); err == nil {
		return ip.String()
	}
	return target
}
