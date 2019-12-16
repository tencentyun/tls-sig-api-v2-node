var TLSSigAPIv2 = require('./TLSSigAPIv2');

var api = new TLSSigAPIv2.Api(1400000000, "5bd2850fff3ecb11d7c805251c51ee463a25727bddc2385f3fa8bfee1bb93b5e");
var sig = api.genSig("xiaojun", 86400*180);
console.log("sig " + sig);
var userbuf = api._getUserbuf("xiaojun",10000,86400*180,255,0);
console.log(userbuf);
var sig = api.genSigWithUserbuf("xiaojun", 86400*180, userbuf);
console.log("sig with userbuf " + sig);
