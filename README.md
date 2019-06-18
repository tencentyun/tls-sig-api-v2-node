## npm 集成
```shell 
npm install tls-sig-api-v2
```

## 源码集成
将文件 `TLSSigAPI.js` 放置于需要的路径下即可。

## 接口调用
```javascript
var TLSSigAPI = require('tls-sig-api-v2');
// var TLSSigAPI = require('./TLSSigAPI'); // 源码集成需要使用相对路径

var api = new TLSSigAPI.Api(1400000000, "5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e");
var sig = api.genSig("xiaojun", 86400*180);
console.log(sig);
```
