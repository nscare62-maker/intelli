const http = require('http');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const mimeTypes = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.csv': 'text/csv'
};

const server = http.createServer((req, res) => {
  let filePath = path.join(__dirname, req.url === '/' ? 'index.html' : req.url.split('?')[0]);
  const ext = path.extname(filePath).toLowerCase();
  const contentType = mimeTypes[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404);
      res.end('Not found');
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content, 'utf-8');
    }
  });
});

server.listen(8092, async () => {
  console.log('Server running on 8092');

  const chromePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  const chrome = spawn(chromePath, [
    '--headless=new',
    '--remote-debugging-port=9224',
    '--disable-gpu',
    '--no-sandbox',
    'http://localhost:8092/'
  ]);

  await new Promise(r => setTimeout(r, 1500));

  try {
    const tabsRes = await fetch('http://127.0.0.1:9224/json');
    const tabs = await tabsRes.json();
    const pageTab = tabs.find(t => t.url.includes('localhost:8092'));

    const ws = new WebSocket(pageTab.webSocketDebuggerUrl);
    let msgId = 1;
    const pending = new Map();

    function send(method, params = {}) {
      return new Promise((resolve) => {
        const id = msgId++;
        pending.set(id, resolve);
        ws.send(JSON.stringify({ id, method, params }));
      });
    }

    const errors = [];
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.id && pending.has(data.id)) {
        const resolve = pending.get(data.id);
        pending.delete(data.id);
        resolve(data.result);
      }
      if (data.method === 'Runtime.exceptionThrown') {
        errors.push(data.params.exceptionDetails.exception?.description || data.params.exceptionDetails.text);
      }
    };

    await new Promise(r => ws.onopen = r);
    await send('Runtime.enable');

    console.log('\n--- 1. Testing Attacks with Staged User Dataset ---');
    // First stage a user dataset
    await send('Runtime.evaluate', {
      expression: `
        processUploadedDataset(JSON.stringify({
          datasetName: "Telemetry_Network_Alpha",
          nodes: [
            { id: "IOT-MTR-01", name: "Substation Meter 01", type: "Smart Meter", protocol: "MQTT", trustScore: 98, status: "Verified" },
            { id: "IOT-VALV-02", name: "Emergency Hydraulic Valve", type: "Industrial Actuator", protocol: "CoAP", trustScore: 95, status: "Verified" }
          ]
        }), "Telemetry_Network_Alpha.json", false);
      `,
      awaitPromise: true
    });

    // Switch to tab-simulator
    await send('Runtime.evaluate', { expression: `switchTab('tab-simulator')` });

    // Test 1: DDoS Attack
    console.log('\nTesting simDDoSBtn (Test DDoS Flood)...');
    const ddosRes = await send('Runtime.evaluate', {
      expression: `
        (async function() {
          const btn = document.getElementById('simDDoSBtn');
          btn.click();
          await new Promise(r => setTimeout(r, 1000));
          const targetNode = State.nodes.find(n => n.id === 'IOT-MTR-01');
          return {
            status: targetNode.status,
            trustScore: targetNode.trustScore,
            intrusionsBlocked: State.totalIntrusionsBlocked,
            ddosTraffic: State.trafficStats.ddos,
            pipeScore: document.getElementById('pipeAnomalyScore').textContent,
            pipeDecision: document.getElementById('pipeDecision').textContent,
            pipeBadge: document.getElementById('pipelineStatusBadge').textContent
          };
        })()
      `,
      awaitPromise: true,
      returnByValue: true
    });
    console.log('DDoS Flood Result:', ddosRes.result.value);

    // Test 2: MAC Spoofing Attack
    console.log('\nTesting simSpoofBtn (Test Spoofing)...');
    const spoofRes = await send('Runtime.evaluate', {
      expression: `
        (async function() {
          const btn = document.getElementById('simSpoofBtn');
          btn.click();
          await new Promise(r => setTimeout(r, 1000));
          return {
            intrusionsBlocked: State.totalIntrusionsBlocked,
            spoofTraffic: State.trafficStats.spoof,
            pipeScore: document.getElementById('pipeAnomalyScore').textContent,
            pipeDecision: document.getElementById('pipeDecision').textContent,
            pipeBadge: document.getElementById('pipelineStatusBadge').textContent,
            terminalHasSpoof: document.getElementById('liveTerminalFeed').innerHTML.includes('ROGUE-NODE')
          };
        })()
      `,
      awaitPromise: true,
      returnByValue: true
    });
    console.log('MAC Spoofing Result:', spoofRes.result.value);

    // Test 3: MITM Tampering Attack
    console.log('\nTesting simTamperBtn (Test Tampering)...');
    const tamperRes = await send('Runtime.evaluate', {
      expression: `
        (async function() {
          const btn = document.getElementById('simTamperBtn');
          btn.click();
          await new Promise(r => setTimeout(r, 1000));
          return {
            intrusionsBlocked: State.totalIntrusionsBlocked,
            tamperTraffic: State.trafficStats.tamper,
            pipeScore: document.getElementById('pipeAnomalyScore').textContent,
            pipeDecision: document.getElementById('pipeDecision').textContent,
            pipeBadge: document.getElementById('pipelineStatusBadge').textContent,
            terminalHasTamper: document.getElementById('liveTerminalFeed').innerHTML.includes('tampered_temp')
          };
        })()
      `,
      awaitPromise: true,
      returnByValue: true
    });
    console.log('MITM Tampering Result:', tamperRes.result.value);

    console.log('\nTotal Uncaught Exceptions:', errors.length ? errors : 'None! (0 errors)');

    ws.close();
  } catch (err) {
    console.error('Test error:', err);
  } finally {
    chrome.kill();
    server.close();
    process.exit(0);
  }
});

