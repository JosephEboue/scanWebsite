from XssClass import XssClass

webites=["https://sudo.co.il/xss/level4.php","https://alf.nu/alert1?world=alert&level=alert0","http://testphp.vulnweb.com/signup.php","https://web.archive.org/web/20190617111911/https://polyglot.innerht.ml/"]
for website in webites:
    print(f"Scanning {website}")
    XssClass.xss_scan(website)
    print("---------------------")