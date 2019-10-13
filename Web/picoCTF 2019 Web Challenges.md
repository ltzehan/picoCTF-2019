---
typora-copy-images-to: ipic
---

# picoCTF 2019 Web Challenges

---

## Inspector(50)

### Problem

> Kishor Balan tipped us off that the following code may need inspection: `https://2019shell1.picoctf.com/problem/61676/` ([link](https://2019shell1.picoctf.com/problem/61676/)) or http://2019shell1.picoctf.com:61676

### Hints

> How do you inspect web code on a browser?
>
> There's 3 parts

### Solution

Visiting the website, we right click and choose to view source code, getting the first third of the flag, included as a html comment:

```html
<!-- Html is neat. Anyways have 1/3 of the flag: picoCTF{tru3_d3 -->
```

The second part of the flag comes from the referenced CSS file [mycss.cs](https://2019shell1.picoctf.com/problem/61676/mycss.css):

```CSS
/* You need CSS to make pretty pages. Here's part 2/3 of the flag: t3ct1ve_0r_ju5t */
```

The last part comes from the Javascript scipt [myjs.js](https://2019shell1.picoctf.com/problem/61676/myjs.js):

```javascript
/* Javascript sure is neat. Anyways part 3/3 of the flag: _lucky?1638dbe7} */
```

Hence combining the 3 parts gives the flag:

`picoCTF{tru3_d3t3ct1ve_0r_ju5t_lucky?1638dbe7}` 



## dont-use-client-side(100)

### Problem

> Can you break into this super secure portal? `https://2019shell1.picoctf.com/problem/49886/` ([link](https://2019shell1.picoctf.com/problem/49886/)) or http://2019shell1.picoctf.com:49886

### Hints

> Never trust the client

### Solution

Opening the website greets us with a 'login' page, requiring credentials. As referenced by the problem name, we assume that the check for the validity of the credentials is checked locally, and hence can be reversed to obtain the correct password. Checking the html source code gives us:

```html
<script type="text/javascript">
  function verify() {
    checkpass = document.getElementById("pass").value;
    split = 4;
    if (checkpass.substring(0, split) == 'pico') {
      if (checkpass.substring(split*6, split*7) == 'e2f2') {
        if (checkpass.substring(split, split*2) == 'CTF{') {
         if (checkpass.substring(split*4, split*5) == 'ts_p') {
          if (checkpass.substring(split*3, split*4) == 'lien') {
            if (checkpass.substring(split*5, split*6) == 'lz_e') {
              if (checkpass.substring(split*2, split*3) == 'no_c') {
                if (checkpass.substring(split*7, split*8) == '4}') {
                  alert("Password Verified")
                  }
                }
              }
      
            }
          }
        }
      }
    }
    else {
      alert("Incorrect password");
    }
    
  }
</script>
```

The checkpass variable holds our input, and the each substring method in this case gets us *split*(set to 4) number of characters starting from the first argument to the method. We assemble the credentials, and hence the flag, accordingly:

`picoCTF{no_clients_plz_ee2f24}` 



## logon(100)

### Problem

> The factory is hiding things from all of its users. Can you login as logon and find what they've been looking at? `https://2019shell1.picoctf.com/problem/32270/` ([link](https://2019shell1.picoctf.com/problem/32270/)) or http://2019shell1.picoctf.com:32270

### Hints

> Hmm it doesn't seem to check anyone's password, except for {{name}}'s?

### Solution

No matter what credentials we use for the login, it successfully logs us in but doesn't give us the flag. This suggests that a cookie might be used to store a separate variable that might be preventing us from seeing the flag. Sure enough, we notice an admin cookie set to `False`. Changing this to `True` and refreshing the page gives us the flag:

`picoCTF{th3_c0nsp1r4cy_l1v3s_a03e3590}` 



## where are the robots(100)

### Problem

> Can you find the robots? `https://2019shell1.picoctf.com/problem/21868/` ([link](https://2019shell1.picoctf.com/problem/21868/)) or http://2019shell1.picoctf.com:21868

### Hints

> What part of the website could tell you where the creator doesn't want you to look?

### Solution

This challenge references [a file that gives instructions to web crawlers](https://www.robotstxt.org/robotstxt.html), called robots.txt. Visiting https://2019shell1.picoctf.com/problem/21868/robots.txt, we see

```html
User-agent: *
Disallow: /e0779.html
```

Visiting https://2019shell1.picoctf.com/problem/21868/e0779.html now, we get our flag:

`picoCTF{ca1cu1at1ng_Mach1n3s_e0779}` 



## Client-side-again(200)

### Problem

> Can you break into this super secure portal? `https://2019shell1.picoctf.com/problem/37886/` ([link](https://2019shell1.picoctf.com/problem/37886/)) or http://2019shell1.picoctf.com:37886

### Hints

> What is obfuscation?

### Solution

Visiting the website, we are greeted by a page similar to [dont-use-client-side](#dont-use-client-side(100)). We thus check the source code of the website again, getting an obfuscation Javascript script:

```html
<script type="text/javascript">
  var _0x5a46=['9d025}','_again_3','this','Password\x20Verified','Incorrect\x20password','getElementById','value','substring','picoCTF{','not_this'];(function(_0x4bd822,_0x2bd6f7){var _0xb4bdb3=function(_0x1d68f6){while(--_0x1d68f6){_0x4bd822['push'](_0x4bd822['shift']());}};_0xb4bdb3(++_0x2bd6f7);}(_0x5a46,0x1b3));var _0x4b5b=function(_0x2d8f05,_0x4b81bb){_0x2d8f05=_0x2d8f05-0x0;var _0x4d74cb=_0x5a46[_0x2d8f05];return _0x4d74cb;};function verify(){checkpass=document[_0x4b5b('0x0')]('pass')[_0x4b5b('0x1')];split=0x4;if(checkpass[_0x4b5b('0x2')](0x0,split*0x2)==_0x4b5b('0x3')){if(checkpass[_0x4b5b('0x2')](0x7,0x9)=='{n'){if(checkpass[_0x4b5b('0x2')](split*0x2,split*0x2*0x2)==_0x4b5b('0x4')){if(checkpass[_0x4b5b('0x2')](0x3,0x6)=='oCT'){if(checkpass[_0x4b5b('0x2')](split*0x3*0x2,split*0x4*0x2)==_0x4b5b('0x5')){if(checkpass['substring'](0x6,0xb)=='F{not'){if(checkpass[_0x4b5b('0x2')](split*0x2*0x2,split*0x3*0x2)==_0x4b5b('0x6')){if(checkpass[_0x4b5b('0x2')](0xc,0x10)==_0x4b5b('0x7')){alert(_0x4b5b('0x8'));}}}}}}}}else{alert(_0x4b5b('0x9'));}}
</script>
```

We however, notice the array at the very start, containg a few strings, including some that might be a part of the flag, such as `'picoCTF'` and `'not_this'`. Excluding the error.success/html strings, we are left with `'picoCTF{'`, `'not_this'`, `'_again_3'`, and `'9d025}'`. We try assembling these pieces, we get the flag.

`picoCTF{not_this_again_39d025}` 



## Open-to-admins(200)

### Problem

> This secure website allows users to access the flag only if they are **admin** and if the **time** is exactly 1400. `https://2019shell1.picoctf.com/problem/21882/` ([link](https://2019shell1.picoctf.com/problem/21882/)) or http://2019shell1.picoctf.com:21882

### Hints

> Can cookies help you to get the flag?

Visiting the website and clicking `Flag` tells us that we are not the admin, or it;s the incorrect time. From the challenge prompt, we know we need to be admin, and the time needs to be 1400. As hinted, we make a cookie named `Admin` with the value `True`, as seen in [logon](#logon(100)), and make a `Time` cookie with the value `1400`. Now clicking `Flag` gives us the flag:

 `picoCTF{0p3n_t0_adm1n5_b6ea8359}` 



## picobrowser(200)

### Problem

> This website can be rendered only by **picobrowser**, go and catch the flag! `https://2019shell1.picoctf.com/problem/37829/` ([link](https://2019shell1.picoctf.com/problem/37829/)) or http://2019shell1.picoctf.com:37829

### Hints

> You dont need to download a new web browser

### Solution

Clicking `Flag` tells us that we are not picobrowser, and then gives us our current [user agent](https://www.wikiwand.com/en/User_agent):

![image-20191013130144946](https://tva1.sinaimg.cn/large/006y8mN6gy1g7wqvt1ermj3130044js9.jpg)

We can use an extension such as [User-Agent Switcher](https://chrome.google.com/webstore/detail/user-agent-switcher/lkmofgnohbedopheiphabfhfjgkhfcgf) on Google Chrome, to manually input our desired user agent. We use picobrowser as suggested and get the flag:

`picoCTF{p1c0_s3cr3t_ag3nt_7e9c671a}`



## Irish-Name-Repo 1(300)

### Problem

> There is a website running at `https://2019shell1.picoctf.com/problem/47253/` ([link](https://2019shell1.picoctf.com/problem/47253/)) or http://2019shell1.picoctf.com:47253. Do you think you can log us in? Try to see if you can login!

### Hints

> There doesn't seem to be many ways to interact with this, I wonder if the users are kept in a database?
>
> Try to think about how does the website verify your login?

### Solution

The hint seems to suggest the use of [SQL injection](https://www.owasp.org/index.php/SQL_Injection), hence we start off by trying simple payloads:

```
username: admin' --
password: password(this field does not matter as it is commented out)
```

This gives us the flag:

`picoCTF{s0m3_SQL_93e76603}`



## Irish-Name-Repo 2(350)

### Problem

> There is a website running at `https://2019shell1.picoctf.com/problem/60775/` ([link](https://2019shell1.picoctf.com/problem/60775/)). Someone has bypassed the login before, and now it's being strengthened. Try to see if you can still login! or http://2019shell1.picoctf.com:60775

### Hints

> The password is being filtered.

We start off by trying the same input as [Irish Name Repo 1](#irish-name-repo-1(300)):

```
username: admin' --
password: password(this field does not matter as it is commented out)
```

This surprisingly gives us the flag as well! 

`picoCTF{m0R3_SQL_plz_015815e2}`

With the hint to this challenge, I assume that Repo 1 was meant to be solved with an OR injection or something of the *like*.



## Irish-Name-Repo 3(400)

### Problem

> There is a secure website running at `https://2019shell1.picoctf.com/problem/47247/` ([link](https://2019shell1.picoctf.com/problem/47247/)) or http://2019shell1.picoctf.com:47247. Try to see if you can login as admin!

### Hints

> Seems like the password is encrypted.

Since the password is hinted to be encrypted, we first check the page source for any signs of encryption to the input, however, do not see any. This means the encryption must be taking place server side. 

We want to leak the encryption method somehow, so we open [BurpSuite](https://portswigger.net/burp/communitydownload) to monitor the requests made to the site. We input some string(i.e. `abcdefghijklmnopqrstuvwxyz`) and submit the request. In BurpSuite, we notice a `debug` parameter, originally set to `0`.

![image-20191013133255579](https://tva1.sinaimg.cn/large/006y8mN6gy1g7wqv38rhfj30gw00ojrh.jpg)

 We change this to a `1`, and forward the request. Now in addition to the `Login failed` page, we get some debug info:

![image-20191013133400879](/Users/arnav/Library/Application Support/typora-user-images/image-20191013133400879.png)

The 'encryption' method used is just [ROT13](https://www.wikiwand.com/en/ROT13)! We can thus craft our payloads normally, just running it through a ROT13 converter before sending it through. 

We utilise a simple payload that escapes the string and always evaluates to true:

`' OR 1=1 --`

'Encrypting' it, we get:

`' BE 1=1 --`

Submitting this as the input, we get our flag:

`picoCTF{3v3n_m0r3_SQL_c2c37f5e}`



## Empire 1(400)

### Problem

> Psst, Agent 513, now that you're an employee of Evil Empire Co., try to get their secrets off the company website. `https://2019shell1.picoctf.com/problem/4155/` ([link](https://2019shell1.picoctf.com/problem/4155/)) Can you first find the secret code they assigned to you? or http://2019shell1.picoctf.com:4155

### Hints

> Pay attention to the feedback you get
>
> There is *very* limited filtering in place - this to stop you from breaking the challenge for yourself, not for you to bypass.
>
> The database gets reverted every 2 hours if you do break it, just come back later

### Solution

*TODO*



## JaWT Scratchpad(400)

### Problem

> Check the admin scratchpad! `https://2019shell1.picoctf.com/problem/45158/` or http://2019shell1.picoctf.com:45158

### Hints

> What is that cookie?
>
> Have you heard of JWT?

We first enter the website with some username, and notice that we have been issued a `jwt` cookie. This is a [JSON Web Token](https://jwt.io/introduction/). We can also [decode](https://jwt.io/#debugger) our token, where we see the payload to be:

```javascript
{
  "user": "john"
}
```

We would obviously like to change the user to admin, however, to encode this, require the secret key. Under the section `Register with your name!`, a hyperlink linking to the JohnTheRipper tool's GitHub page suggests a brute force method is required. Instead of using JohnTheRipper, I chose to use this [jwt-cracker](https://github.com/lmammino/jwt-cracker). Letting it run for a while, I get the secret, `ilovepico`. Using the debugger tool on [jwt.io](jwt.io), we get the cookie to be injected:

`eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.gtqDl4jVDvNbEe_JYEZTN19Vx6X9NNZtRVbKPBkhO-s` 

Injecting this as the cookie and refreshing the page gives us the flag:

`picoCTF{jawt_was_just_what_you_thought_d571d8aa3163f61c144f6d505ef2919b}`



## Java Script Kiddie(400)

### Problem

> The image link appears broken... https://2019shell1.picoctf.com/problem/10188 or http://2019shell1.picoctf.com:10188

### Hints

> This is only a JavaScript problem.

### Solution

Looking at the source code of the website, we see a script that seems to be constructing our image by manipulating some values in an array named "bytes", and our input, otherwise called key in the code.

![image-20191013142822951](https://tva1.sinaimg.cn/large/006y8mN6gy1g7wqva1nu2j31qk0mk42z.jpg)

We get the bytes array through the browser console: 

![image-20191013143022717](https://tva1.sinaimg.cn/large/006y8mN6gy1g7wqvd281zj30tu0puajk.jpg)

The script seems to be doing

> 1. Use the input as the key
> 2. For each number in the key, convert the string to the actual number(char()-48), store it in variable `i`
> 3. Get the byte value for the resultant PNG at position (i , j),  by the following formula:

```javascript
for(var j = 0; j < (bytes.length / LEN); j ++){
	result[(j * LEN) + i] = bytes[(((j + shifter) * LEN) % bytes.length) + i]
}
```

> 4. Remove all trailing zeros from the file
> 5. Use the result as the source for the PNG displayed on the page

Looking at the [file signature](https://www.garykessler.net/library/file_sigs.html) for a PNG file, we see that the first 8 bytes of the file have to be `89 50 4E 47 0D 0A 1A 0A`, and the trailing 8 bytes have to be `49 45 4E 44 AE 42 60 82`. We can thus write a python script to find us possible values for the first 8 digits of the key using the header, and the last 8 digits using the trailer, giving us the final key.

For the first 8 digits:

```python
byte_list = [61,180,159,7,201,26,191,...]
png_header = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
print 'First 8 digits:'
for head in range(8):
	for i in xrange(len(byte_list)):
	  if byte_list[i] == png_header[head]:
	    if (i-head)%16 ==0:
	    	print (i-head)/16,
```

This gives us the first 8 digits - `74478291`. 

For the last 8 digits, the actual result might include a bunch of 0s at the end, instead of the actual trailer, as we see that the javascript script actually does work to remove these just before the image is used as a source. We thus try our luck with the ending being `00 00 00 00 00 00 00 00` first, as we notice multiple 0s in the bytes array, leading us to believe that some of these might actually be at the end. We get a list of possible numbers for the last 8 digits of the key with this script:

```python
count = 0
png_trailer = [0,0,0,0,0,0,0,0]
print ''
print 'Possibilities for the last 8 digits:'
for head in range(8):
	for i in xrange(len(byte_list)):
	  if byte_list[i] == png_trailer[head]:
	    if (i-head-8)%16 ==0 and (i-head-8)/16<10:
	    	print (i-head+1)/16,
	print 'Digit '+ str(count)
  count += 1
```

We then use the following to iterate through the combination possibilities:

```python
first = ['0']
second = ['8','9']
third = ['0','1','2']
fourth = ['1','3','4']
fifth = ['3','5','6']
sixth = ['2','4']
seventh = ['9']
eighth = ['6']
arr =[first,second,third,fourth,fifth,sixth, seventh,eighth]
trailer_combi = list(itertools.product(*arr))

header = '74478291'
count=0

print '\n\nPossible keys, check output files:'
for possible_tail in trailer_combi:
	key = header+''.join(possible_tail)
	result=[0]*688
	for i in xrange(16):
	 	shifter = int(key[i])
	 	for j in xrange(43):
	 		result[(j * 16) + i] = byte_list[(((j + shifter) * 16) % 688) + i]
	while not result[-1]:
		result.pop()
	if result[-8:] == png_trailer:
		print key
		f = open('output'+str(count), 'wb')
		f.write(bytearray(result))
		count +=1
```

We use the command `pngcheck output*`, and notice that `output0` gives OK. We open it and see a qr code, whcih we use `zbarimg` to decode to get the flag:

`picoCTF{9e627a851b332d57435b6c32d7c2d4af}`



## Empire2(450)

### Problem

> Well done, Agent 513! Our sources say Evil Empire Co is passing secrets around when you log in: `https://2019shell1.picoctf.com/problem/39830/` ([link](https://2019shell1.picoctf.com/problem/39830/)), can you help us find it? or http://2019shell1.picoctf.com:39830

### Hints

> Pay attention to the feedback you get
>
> There is *very* limited filtering in place - this to stop you from breaking the challenge for yourself, not for you to bypass.
>
> The database gets reverted every 2 hours if you do break it, just come back later

### Solution

We create an account and log in, noticing that there is a flask session cookie. [Decoding](https://www.kirsle.net/wizards/flask-session.cgi) the cookie gives us:

```javascript
{
    "_fresh": true,
    "_id": "8cd7ed88b8f2634ebe13cbb6c321c3090c11254effbb99924bf9037639c9fda127643b8e1c4ba5257fce7a193639ae2f5e2911ece327e48e43b386ef65618709",
    "csrf_token": "bf1d1303f409590730443f12541c77cdb97811e8",
    "dark_secret": "picoCTF{its_a_me_your_flag3f43252e}",
    "user_id": "3"
}
```

The cookie includes the flag:

`picoCTF{its_a_me_your_flag3f43252e}`



## Java Script Kiddie 2(450)

### Problem

> The image link appears broken... twice as badly... https://2019shell1.picoctf.com/problem/21890 or http://2019shell1.picoctf.com:21890

### Hints

> This is only a JavaScript problem.

### Solution

*TODO* but extremely similar to [JS Kiddie](#java-script-kiddie(400)). It is now a 32 digit key, however, only alternate digits matter so code similar to [JS Kiddie](#java-script-kiddie(400)) can be used here to get the results QR code. Decoding it gives the flag:

`picoCTF{e1f443bfe40e958050e0d74aec4daa48}` 



## cereal hacker 1(450)

### Problem

> Login as admin. https://2019shell1.picoctf.com/problem/47283/ or http://2019shell1.picoctf.com:47283

### Solution

*TODO*, but is a simple cookie SQLi, with initial login as guest/guest.



## Empire3(500)

### Problem

> Agent 513! One of your dastardly colleagues is laughing very sinisterly! Can you access his todo list and discover his nefarious plans? `https://2019shell1.picoctf.com/problem/47271/` ([link](https://2019shell1.picoctf.com/problem/47271/)) or http://2019shell1.picoctf.com:47271

### Hints

> Pay attention to the feedback you get
>
> There is *very* limited filtering in place - this to stop you from breaking the challenge for yourself, not for you to bypass.
>
> The database gets reverted every 2 hours if you do break it, just come back later

### Solution

Similarly to [Empire2](#empire2(450)), we can decode the cookie, and we see that we now need to edit the cookie to user id 1 or 2, both of which seem to be admin. However, to encrypt the data back into a usable cookie, we need to sign it with a secret. 

Going into the `Add a Todo` page and inputting `{{config}}`, we can see all the items under the flask configuration of the website. This utilises a [Server Side Template Injection(SSTI)]([https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server Side Template Injection)), specifically a vulnerability in the Jinja2 template that Flask uses. 

Now viewing `Your Todos`, we get the `secret_key`, `'11e524344575850af46c19681f9baa0d'`. 

Now we can use a [flask cookie encoder](https://github.com/Paradoxis/Flask-Unsign) to generate our desired cookie.

```shell
flask-unsign --sign --cookie "{'_fresh': True, '_id': 'da00c2f44206c588ee050cd3e467e96d1ccfbd7f121c497442c70e7e7ad0cd08c1f7c8e967301b5beb1740d0c35dc5cc9ff421d0c0914a30a91364c5e35bc294', 'csrf_token': 'ab946d3f256cc7eafed0821f8a70aa18c63f620b', 'user_id': '2'}" --secret '11e524344575850af46c19681f9baa0d'
```

Injecting the output as the cookie and going into `Your Todos`, we get the flag:

`picoCTF{cookies_are_a_sometimes_food_404e643b}`

## cereal hacker 2(500)

### Problem

>Get the admin's password. https://2019shell1.picoctf.com/problem/62195/ or http://2019shell1.picoctf.com:62195

### Solution

*TODO*, but was essentially using a PHP filter wrapper to leak source code, get credentials to a mySQL server running on the picoCTF shell localhost, logging in, and doing a blind SQLi to get admin's password, which was also the flag

Flag:

`picoCTF{c9f6ad462c6bb64a53c6e7a6452a6eb7}`



