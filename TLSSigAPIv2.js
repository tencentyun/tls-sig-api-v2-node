var crypto = require('crypto');
var zlib = require('zlib');

var base64url = {};

var newBuffer = function (fill, encoding) {
    return Buffer.from ? Buffer.from(fill, encoding) : new Buffer(fill, encoding)
};

base64url.unescape = function unescape(str) {
    return (str + Array(5 - str.length % 4))
        .replace(/_/g, '=')
        .replace(/\-/g, '/')
        .replace(/\*/g, '+');
};

base64url.escape = function escape(str) {
    return str.replace(/\+/g, '*')
        .replace(/\//g, '-')
        .replace(/=/g, '_');
};

base64url.encode = function encode (str) {
    return this.escape(newBuffer(str).toString('base64'));
};

base64url.decode = function decode (str) {
    return newBuffer(this.unescape(str), 'base64').toString();
};

function base64encode(str) {
    return newBuffer(str).toString('base64')
}
function base64decode(str) {
    return newBuffer(str, 'base64').toString()
}

var Api = function(sdkappid, key) {
    this.sdkappid  = sdkappid;
    this.key = key;
};
/**用于生成实时音视频(TRTC)业务进房权限加密串,具体用途用法参考TRTC文档：https://cloud.tencent.com/document/product/647/32240 
* TRTC业务进房权限加密串需使用用户定义的userbuf
* @brief 生成 userbuf
* @param account 用户名
* @param dwSdkappid sdkappid
* @param dwAuthID  数字房间号
* @param dwExpTime 过期时间：该权限加密串的过期时间，建议300秒，300秒内拿到该签名，并且发起进房间操作
* @param dwPrivilegeMap 用户权限，255表示所有权限
* @param dwAccountType 用户类型,默认为0
* @return userbuf  {string}  返回的userbuf
*/
Api.prototype._getUserbuf = function (account, dwAuthID, dwExpTime,
    dwPrivilegeMap, dwAccountType){

    let accountLength = account.length;
    let offset = 0;
    let userBuf = new Buffer(1+2+accountLength+4+4+4+4+4);

    //cVer
    userBuf[offset++] = 0;

    //wAccountLen
    userBuf[offset++] = (accountLength & 0xFF00) >> 8;
    userBuf[offset++] = accountLength & 0x00FF;
    
    //buffAccount
    for (; offset < 3 + accountLength; ++offset) {
        userBuf[offset] = account.charCodeAt(offset - 3);
    }

    //dwSdkAppid
    userBuf[offset++] = (this.sdkappid & 0xFF000000) >> 24;
    userBuf[offset++] = (this.sdkappid & 0x00FF0000) >> 16;
    userBuf[offset++] = (this.sdkappid & 0x0000FF00) >> 8;
    userBuf[offset++] = this.sdkappid & 0x000000FF;
    
    //dwAuthId
    userBuf[offset++] = (dwAuthID & 0xFF000000) >> 24;
    userBuf[offset++] = (dwAuthID & 0x00FF0000) >> 16;
    userBuf[offset++] = (dwAuthID & 0x0000FF00) >> 8;
    userBuf[offset++] = dwAuthID & 0x000000FF;
    
    //dwExpTime
    userBuf[offset++] = (dwExpTime & 0xFF000000) >> 24;
    userBuf[offset++] = (dwExpTime & 0x00FF0000) >> 16;
    userBuf[offset++] = (dwExpTime & 0x0000FF00) >> 8;
    userBuf[offset++] = dwExpTime & 0x000000FF;
    
    //dwPrivilegeMap
    userBuf[offset++] = (dwPrivilegeMap & 0xFF000000) >> 24;
    userBuf[offset++] = (dwPrivilegeMap & 0x00FF0000) >> 16;
    userBuf[offset++] = (dwPrivilegeMap & 0x0000FF00) >> 8;
    userBuf[offset++] = dwPrivilegeMap & 0x000000FF;
    
    //dwAccountType
    userBuf[offset++] = (dwAccountType & 0xFF000000) >> 24;
    userBuf[offset++] = (dwAccountType & 0x00FF0000) >> 16;
    userBuf[offset++] = (dwAccountType & 0x0000FF00) >> 8;
    userBuf[offset++] = dwAccountType & 0x000000FF;

    return userBuf;
}
/**
 * 通过传入参数生成 base64 的 hmac 值
 * @param identifier
 * @param currTime
 * @param expire
 * @returns {string}
 * @private
 */
Api.prototype._hmacsha256 = function(identifier, currTime, expire, base64UserBuf){
    var contentToBeSigned = "TLS.identifier:" + identifier + "\n";
    contentToBeSigned += "TLS.sdkappid:"+ this.sdkappid + "\n";
    contentToBeSigned += "TLS.time:" + currTime + "\n";
    contentToBeSigned += "TLS.expire:" + expire + "\n";
    if (null != base64UserBuf) {
        contentToBeSigned += "TLS.userbuf:" + base64UserBuf + "\n";
    }
    const hmac = crypto.createHmac("sha256", this.key);
    return hmac.update(contentToBeSigned).digest('base64');
};

/**
 * 生成 usersig
 * @param string $identifier 用户名
 * @return string 生成的失败时为false
 */
/**
 * 生成 usersig
 * @param identifier 用户账号
 * @param expire 有效期，单位秒
 * @returns {string} 返回的 sig 值
 */
Api.prototype.genSig = function(identifier, expire){
    return this.genSigWithUserbuf(identifier, expire, null);
};

/**
 * 生成带 userbuf 的 usersig
 * @param identifier  用户账号
 * @param expire 有效期，单位秒
 * @param userBuf 用户数据
 * @returns {string} 返回的 sig 值
 */
Api.prototype.genSigWithUserbuf = function(identifier, expire, userBuf){

    var currTime = Math.floor(Date.now()/1000);

    var sigDoc = {
        'TLS.ver': "2.0",
        'TLS.identifier': ""+identifier,
        'TLS.sdkappid': Number(this.sdkappid),
        'TLS.time': Number(currTime),
        'TLS.expire': Number(expire)
    };

    var sig = '';
    if (null != userBuf) {
        var base64UserBuf = base64encode(userBuf);
        sigDoc['TLS.userbuf'] = base64UserBuf;
        sig = this._hmacsha256(identifier, currTime, expire, base64UserBuf);
    } else {
        sig = this._hmacsha256(identifier, currTime, expire, null);
    }
    sigDoc['TLS.sig'] = sig;

    var compressed = zlib.deflateSync(newBuffer(JSON.stringify(sigDoc))).toString('base64');
    return base64url.escape(compressed);
};

exports.Api = Api;
