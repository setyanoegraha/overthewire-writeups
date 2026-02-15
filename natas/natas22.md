# Natas Level 22: The Redirect That Never Stopped

## The Setup
| Level | Username | Target URL |
| :--- | :--- | :--- |
| Level 22 | natas22 | http://natas22.natas.labs.overthewire.org |

**Introduction:** Level 22 teaches a subtle but critical lesson about HTTP redirects and PHP execution flow. It's the kind of vulnerability that looks secure at first glance but falls apart the moment you understand how web servers and browsers actually communicate. This challenge is a perfect reminder that security through browser behavior is no security at all.

---

## Hunting for Clues

When I first loaded the page, I was greeted with an almost empty interface.

![](image-53.png)

The page displays a black header with "NATAS22" in white text. Below that is a large white content area that's completely blank except for a blue "View sourcecode" link in the lower right corner. There's also a WeChall submit token button in the top right. The minimalist design immediately told me that the real action was going to be in the source code.

I clicked on the "View sourcecode" link to see what was happening behind the scenes:

```php
<?php
session_start();

if(array_key_exists("revelio", $_GET)) {
    // only admins can reveal the password
    if(!($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1)) {
    header("Location: /");
    }
}
?>
```

And further down in the HTML:

```php
<?php
    if(array_key_exists("revelio", $_GET)) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas23\n";
    print "Password: <censored></pre>";
    }
?>
```

At first, this code looked secure. Let me walk through the logic:

1. If the URL contains a `?revelio` parameter, the code checks whether you're an admin
2. If you're NOT an admin (which I'm not), it sends a redirect header to send you back to the homepage
3. Further down, if `?revelio` is present, it prints the password

The developer's intention was clear: only admins can see the password. Non admins get redirected away before they can see anything. But there's a critical flaw in this implementation.

### The Fatal Mistake

The vulnerability is right here:

```php
if(!($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1)) {
    header("Location: /");
}
```

Do you see what's missing? There's no `exit()` or `die()` call after the `header()` function.

This is a huge mistake. The `header("Location: /")` function in PHP doesn't stop script execution. It merely sends an HTTP header to the browser telling it to redirect to a different page. But the PHP interpreter keeps running and continues to execute all the code that follows.

So here's what actually happens when a non admin visits `?revelio`:

1. PHP checks if you're an admin (you're not)
2. PHP sends a `Location: /` header to your browser
3. **PHP continues executing the rest of the script**
4. PHP prints the admin credentials to the response body
5. The response (with both the redirect header AND the password) is sent to the browser
6. The browser sees the `Location` header and immediately redirects, never showing you the response body

The password is right there in the response, but browsers dutifully follow redirects and never display it. This is security through client side behavior, which is no security at all.

## Breaking In

The attack strategy was simple: I needed to make a request with the `?revelio` parameter but using a tool that doesn't automatically follow redirects. This would let me see the full response body before any redirect happens.

Curl is perfect for this. By default, curl doesn't follow redirects unless you explicitly tell it to with the `-L` flag. Without that flag, curl will show me the entire response, including the password that gets printed before the redirect.

I crafted my request:

```bash
┌──(ouba㉿CLIENT-DESKTOP)-[/tmp/natas]
└─$ curl -u natas22:d8r[REDACTED] "http://natas22.natas.labs.overthewire.org/index.php?revelio"


<html>
<head>
<!-- This stuff in the header has nothing to do with the level -->
<link rel="stylesheet" type="text/css" href="http://natas.labs.overthewire.org/css/level.css">
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/jquery-ui.css" />
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/wechall.css" />
<script src="http://natas.labs.overthewire.org/js/jquery-1.9.1.js"></script>
<script src="http://natas.labs.overthewire.org/js/jquery-ui.js"></script>
<script src=http://natas.labs.overthewire.org/js/wechall-data.js></script><script src="http://natas.labs.overthewire.org/js/wechall.js"></script>
<script>var wechallinfo = { "level": "natas22", "pass": "d8r[REDACTED]" };</script></head>
<body>
<h1>natas22</h1>
<div id="content">

You are an admin. The credentials for the next level are:<br><pre>Username: natas23
Password: dIU[REDACTED]</pre>
<div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
</div>
</body>
</html>
```

Perfect! The response body contains the full HTML page, including the admin credentials. The message "You are an admin. The credentials for the next level are:" is right there, followed by the username natas23 and the password.

If I had used a browser to visit this URL, the browser would have received this exact same response, but it would have immediately processed the `Location: /` header and redirected me before displaying any of the content. Using curl allowed me to bypass this client side behavior and see the raw server response.

### Understanding the Execution Flow

Let me clarify exactly what happens when PHP executes this code:

1. **Request arrives**: `GET /index.php?revelio`
2. **Session check**: No admin session exists
3. **Header sent**: `header("Location: /")` adds a redirect header to the response
4. **Script continues**: No `exit()` was called, so PHP keeps running
5. **Password printed**: The second PHP block executes and adds credentials to the response body
6. **Response sent**: Browser receives headers (including redirect) and body (including password)
7. **Browser behavior**: Browser sees `Location` header and redirects immediately
8. **Curl behavior**: Curl shows the full response without following the redirect

The key insight is that `header()` doesn't send the response immediately. It just queues up a header to be sent when the script finishes or when output begins. The response body is built up alongside the headers, and everything is sent together at the end.

### Why This Matters

This isn't just a CTF trick. This vulnerability pattern appears in real world applications all the time. Developers often assume that calling `header("Location: ...")` will stop execution, but it doesn't. They think the redirect provides security, but it only provides UX.

Common real world scenarios where this bug appears:

- **Authorization checks**: Redirecting unauthorized users but continuing to process sensitive operations
- **Payment validation**: Redirecting users who haven't paid but still generating premium content
- **Access control**: Redirecting based on user roles but still exposing protected data in the response
- **API endpoints**: Sending redirect responses but including sensitive data in the body that API clients can access

Any automated tool, API client, or even browser developer tools can capture the full response before the redirect happens.

### The Correct Implementation

The fix is simple. Always call `exit()` or `die()` immediately after a security relevant redirect:

```php
if(!($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1)) {
    header("Location: /");
    exit(); // CRITICAL: Stop execution immediately
}
```

With `exit()`, the script terminates as soon as the redirect header is set. No further code executes, no password is printed, and the response body is empty.

Even better, you could use a helper function that combines both operations:

```php
function redirect_and_exit($location) {
    header("Location: $location");
    exit();
}

// Usage
if(!is_admin()) {
    redirect_and_exit("/");
}
```

This makes it impossible to forget the `exit()` call.

### Additional Security Best Practices

Beyond fixing the missing `exit()`, here are other important considerations:

1. **Don't Print Sensitive Data Before Checking Authorization**: Structure your code so that sensitive operations only happen after all security checks pass. Don't rely on redirects to hide output that's already been generated.

2. **Use Proper HTTP Status Codes**: When redirecting for security reasons, use appropriate status codes like `303 See Other` or `401 Unauthorized` rather than just the default `302 Found`:
   ```php
   header("HTTP/1.1 401 Unauthorized");
   header("Location: /login");
   exit();
   ```

3. **Defense in Depth**: Even with proper redirects, implement authorization checks at multiple layers. Check permissions before querying data, before rendering output, and before performing actions.

4. **Server Side Validation**: Never trust client side behavior for security. Always validate and enforce security rules on the server, assuming the client might be malicious or compromised.

5. **Security Audits**: Use automated tools and manual code review to find patterns like `header("Location:` without a following `exit()`. This is an easy pattern to search for in codebases.

6. **Testing with Non Browser Clients**: Include tests that use curl, wget, or HTTP libraries to verify that your application doesn't leak data to clients that don't follow redirects.

7. **Framework Protection**: Modern frameworks like Laravel, Django, and Express often have helper methods that automatically terminate execution after redirects. Use these instead of raw `header()` calls:
   ```php
   // Laravel
   return redirect('/');
   
   // Symfony
   return $this->redirectToRoute('homepage');
   ```

8. **Logging and Monitoring**: Log failed authorization attempts, especially when they involve sensitive operations. This can help detect exploitation attempts.

9. **Principle of Least Privilege**: Don't expose admin only endpoints to non admin users at all. Use routing and middleware to enforce access control before the request reaches vulnerable code.

10. **Education**: Make sure all developers on your team understand that HTTP headers don't control program flow. This is a fundamental concept that prevents many security issues.

The core lesson is simple but critical: **redirects are for browsers, not security**. If you need to stop execution for security reasons, you must explicitly terminate the script. HTTP headers are instructions to the client, not commands to the server.

---

## The Loot

**Next Level Password:** dIU[REDACTED]

**Quick Recap:** Missing exit() call after a security redirect allowed the script to continue executing and leak admin credentials in the response body, which curl captured before the redirect could take effect.
