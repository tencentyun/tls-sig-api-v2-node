var TLSSigAPI = require('./TLSSigAPI');

var api = new TLSSigAPI.Api(1400000000, "5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e");
var sig = api.genSig("xiaojun", 86400*180);
console.log(sig);