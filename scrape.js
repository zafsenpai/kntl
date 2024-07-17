const fs = require('fs');

const proxies = [];
const output_file = 'proxy.txt';

if (fs.existsSync(output_file)) {
  fs.unlinkSync(output_file);
  console.log(`'${output_file}' telah dihapus.`);
}

const raw_proxy_sites = [
"https://api.proxyscrape.com/v3/free-proxy-list/get?request=displayproxies&proxy_format=ipport&format=text&protocol=http",
];

async function fetchProxies() {
  for (const site of raw_proxy_sites) {
    try {
      const response = await fetch(site);
      if (response.ok) {
        console.log(`success: ${site}`);
        const data = await response.text();
        const lines = data.split('\n');
        for (const line of lines) {
          if (line.includes(':')) {
            const [ip, port] = line.split(':', 2);
            proxies.push(`${ip}:${port}`);
          }
        }
      } else {
        console.log(`skip: ${site}`);
      }
    } catch (error) {
      console.error(`skip: ${site}`);
    }
  }

  fs.writeFileSync(output_file, proxies.join('\n'));
  fs.readFile(output_file, 'utf8', (err, data) => {
    if (err) {
      console.error('Gagal membaca file:', err);
      return;
    }
    const proxies = data.trim().split('\n');
    const totalProxies = proxies.length;
    console.log(`success scraping ${totalProxies} proxy`);
  });
}

fetchProxies();
