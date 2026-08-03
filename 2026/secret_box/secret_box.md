# Secret Box-PicoCTF-2026

---

### Web Exploit - Medium - (Source code)

---

#### Description:

#### This secret box is designed to conceal your secrets.

#### It's perfectly secure—only you can see what's inside.

#### Or can you? Try uncovering the admin's secret.

---

- I’m presented with 2 buttons when accessing the challenge, let’s see what they do.
    
    ![image.png](images/image.png)
    
- Observing the error message of the login form, this error message can prevent user enumeration, I tried using single quote to test for SQLi but it seems secure either. Nothing I can do here for now.
    
    ![image.png](images/image%201.png)
    
- Moving to the sign up from, I enter `admin` as the username and it displays `already exists` , meaning there’s an administrator account named `admin`.
    
    ![image.png](images/image%202.png)
    
- After that, I register an account `test:test` and login, now I have a button to create a secret to myself.
    
    ![image.png](images/image%203.png)
    
- So I create one.
    
    ![image.png](images/image%204.png)
    
- And it shows here, just like that.
    
    ![image.png](images/image%205.png)
    
- Then I create a new one and add a single quote here.
    
    ![image.png](images/image%206.png)
    
- It displays an error contain the query using in this function - An INSERT statement. Normally, INSERT statement can be injected to serve the purpose of capturing someone else secret and send it to where attacker can read.
    
    ![image.png](images/image%207.png)
    
- I decide to read the source code from this moment to get clearer context. In `src/server.js` , user input is directly used to query DB, making this route vulnerable while all other routes using prepared statement.
    
    ![image.png](images/image%208.png)
    
- In `src/db.js` , I see that the flag is hidden inside that ID’s secret, it probably is the ID of admin account, from here I can either:
    - Send the admin’s password to me, then login and read the flag.
    - Send the flag directly to me (I choose this)
        
        ![image.png](images/image%209.png)
        
- Here is what the table secret looks like.
    
    ![image.png](images/image%2010.png)
    
- The final step is to craft a working payload, since this application uses PostgreSQL, the syntax will be almost the same as MySQL, just slightly different in more complex queries that I’m not going to use here:
- Original query statement:
    - `INSERT INTO secrets(owner_id, content) VALUES ('${userId}', '${content}')`
- Based on what I did earlier, I notice that I can only control the `content` field, by inserting `test');--` , I’ve escaped the original query and I can place my payload in the middle like this:
    - `INSERT INTO secrets(owner_id, content) VALUES ('${userId}', 'test');[payload]--')`
        
        ![image.png](images/image%2011.png)
        
- Then I try changing the payload to `test'); update secrets set content = 'abc'--` , the query turns to this and overwrite all the secret’s content as following:
    - `INSERT INTO secrets(owner_id, content) VALUES ('${userId}', 'test'); update secrets set content = 'abc'--')`
        
        ![image.png](images/image%2012.png)
        
        ![image.png](images/image%2013.png)
        
- Now I just need to overwrite it one more time, but with the content of the flag, this query will return the content of the flag that lies in admin’s secret:
    - `select content from secrets where owner_id = 'e2a66f7d-2ce6-4861-b4aa-be8e069601cb'`
- Just need to replace the `abc` to the query above, the complete payload becomes `test'); update secrets set content = (select content from secrets where owner_id = 'e2a66f7d-2ce6-4861-b4aa-be8e069601cb')--` , here is what happens in the back end:
    - `INSERT INTO secrets(owner_id, content) VALUES ('${userId}', 'test'); update secrets set content = (select content from secrets where owner_id = 'e2a66f7d-2ce6-4861-b4aa-be8e069601cb')--')`
        
        ![image.png](images/image%2014.png)
        
- And I…MUST HAVE HAD THE FLAG ??? What happened here, why is it showing `abc` instead of the flag ??!#$@#%!
    
    ![image.png](images/image%2015.png)
    
- W…HA….T
- ….’S
- WR…..O…..N..G…?
- WH……A..T
- HA…..PPE….NED….?

---

- Explanation:
- I made a big mistake, when used `update secrets set content = 'abc'` , I accidentally overwrote `content` for every row in table `secrets` including the actual flag to `abc` , because I didn’t use `WHERE clause` to specify which user should be overwritten.
- So because this is just a lab, just need to reset the instance, and everything will be alright, (BUT DON’T MAKE THIS MISTAKE IN REAL LIFE)
- I should have used this `test'); update secrets set content = 'abc' where owner_id = 'MY-ID'--` for testing purpose (`owner_id` has been leaked in the error message before)
- Or I can just use the complete payload directly to get the flag after resetting the instance.
- `test'); update secrets set content = (select content from secrets where owner_id = 'e2a66f7d-2ce6-4861-b4aa-be8e069601cb')--`
    
    ![image.png](images/image%2016.png)
    
- Root cause:
    - SQL Injection via unparameterized query: route /secrets/create builds
    the INSERT statement using raw string interpolation (`${userId}`, `${content}`)
    instead of a parameterized query, while every other route in the app correctly
    uses prepared statements, so this single endpoint lets user-controlled `content`
    break out of the string literal and inject arbitrary SQL.
    - Missing input validation on `content` : the field accepts any length/charset
    with no sanitization, so a value like `test');` is enough to close the original
    statement and open a new one, turning a "note content" field into a full SQL
    execution point.
    - Stacked query execution enabled by db.raw(): node-postgres normally blocks
    multiple statements per call when queries go through parameterized placeholders,
    but building the query as a raw string removes that protection, so the attacker
    isn't limited to modifying the INSERT — they can append entirely new statements
    (UPDATE, SELECT subqueries) that run in the same request.
    - Combined effect: no parameterization + no input validation + stacked-query-capable
    raw execution reduces this to an authenticated attacker having near-arbitrary write
    access to the `secrets` table, not just the ability to read the admin's row —
    demonstrated firsthand when the missing WHERE clause overwrote every row's content,
    including the flag.
    
    Takeaway: SQLi severity isn't just "can I read another user's data": when the
    injection point allows stacked queries, an attacker can write/delete anywhere the
    DB user has permission, which is exactly what turned a "leak the flag" bug into
    a "destroy the flag" mistake here.
