from scanner import Scanner

webites=["https://despegar.asesoresram.com/api/user/authenticate"]

for website in webites:
    print(f"Scanning {website} for SQL injection")
    Scanner.test_sql_injection(website, "OR 1=1")
    print("---------------------")
