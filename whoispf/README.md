# whoispf

A go snippet tool that retrieves WHOIS data for IP addresses, CIDR ranges (using the first IP), or targets listed in a file.
It supports recursive SPF record lookup (using the -spf flag)

```
go run whoispf.go -spf example.com
```
