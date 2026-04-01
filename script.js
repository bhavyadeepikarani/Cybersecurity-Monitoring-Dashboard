// Data Simulation Variables
let activeThreats = 14;
let networkTraffic = 4.2;
let blockedIPs = 1024;
let systemHealth = 98.5;

// Elements
const elActiveThreats = document.getElementById('active-threats');
const elNetworkTraffic = document.getElementById('network-traffic');
const elBlockedIPs = document.getElementById('blocked-ips');
const elSystemHealth = document.getElementById('system-health');
const elThreatLogBody = document.getElementById('threat-log-body');
const elHistoricalLogBody = document.getElementById('historical-log-body');

// ----------------------------------------------------
// SPA Routing Logic
// ----------------------------------------------------
const navLinks = document.querySelectorAll('.nav-menu a');
const viewSections = document.querySelectorAll('.view-section');

navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        
        navLinks.forEach(l => l.classList.remove('active'));
        link.classList.add('active');
        
        viewSections.forEach(sec => sec.classList.remove('active'));
        
        const targetId = link.getAttribute('data-target');
        const targetSection = document.getElementById(targetId);
        if (targetSection) {
            targetSection.classList.add('active');
            // Trigger resize to fix canvas sizing issues on display:none
            window.dispatchEvent(new Event('resize'));
        }
    });
});

// ----------------------------------------------------
// Dashboard KPI Updates
// ----------------------------------------------------
function updateKPIs() {
    if(Math.random() > 0.7) {
        activeThreats += Math.floor(Math.random() * 3) - 1;
        if(activeThreats < 0) activeThreats = 0;
        if(elActiveThreats) {
            elActiveThreats.innerText = activeThreats;
            elActiveThreats.style.textShadow = '0 0 20px rgba(255, 51, 51, 0.8)';
            setTimeout(() => elActiveThreats.style.textShadow = '', 300);
        }
    }
    networkTraffic = Math.max(1.5, Math.min(8.0, networkTraffic + (Math.random() * 0.4 - 0.2)));
    if(elNetworkTraffic) elNetworkTraffic.innerText = networkTraffic.toFixed(1) + ' TB/s';
    
    if(Math.random() > 0.8) {
        blockedIPs += Math.floor(Math.random() * 5);
        if(elBlockedIPs) elBlockedIPs.innerText = blockedIPs.toLocaleString();
    }
    
    systemHealth = Math.max(90.0, Math.min(100.0, systemHealth + (Math.random() * 0.2 - 0.1)));
    if(elSystemHealth) {
        elSystemHealth.innerText = systemHealth.toFixed(1) + '%';
        if (systemHealth < 95) {
            elSystemHealth.className = 'kpi-value warning glow-warning';
        } else {
            elSystemHealth.className = 'kpi-value text-green glow-green';
        }
    }
}
setInterval(updateKPIs, 2000); 

// ----------------------------------------------------
// Core Canvas Drawing Resizer
// ----------------------------------------------------
let charts = [];
function resizeCanvases() {
    charts.forEach(chart => {
        const parent = chart.canvas.parentElement;
        if(parent.clientWidth > 0 && parent.clientHeight > 0) {
            chart.canvas.width = parent.clientWidth;
            chart.canvas.height = parent.clientHeight;
            chart.width = chart.canvas.width;
            chart.height = chart.canvas.height;
            if(chart.draw) chart.draw();
        }
    });
}
window.addEventListener('resize', resizeCanvases);
setTimeout(resizeCanvases, 100);

// ----------------------------------------------------
// Main Traffic Chart (Dashboard)
// ----------------------------------------------------
const tCtx = document.getElementById('trafficChart');
if(tCtx) {
    const trafficChartObj = {
        canvas: tCtx,
        ctx: tCtx.getContext('2d'),
        width: 0, height: 0,
        dataIn: Array(40).fill(0).map(() => 50 + Math.random() * 30),
        dataOut: Array(40).fill(0).map(() => 30 + Math.random() * 20),
        draw: function() {
            const ctx = this.ctx;
            if (!ctx) return;
            ctx.clearRect(0, 0, this.width, this.height);
            
            ctx.strokeStyle = '#1f2235';
            ctx.lineWidth = 1;
            ctx.beginPath();
            for(let i=0; i<this.height; i+=40) { ctx.moveTo(0, i); ctx.lineTo(this.width, i); }
            for(let i=0; i<this.width; i+=60) { ctx.moveTo(i, 0); ctx.lineTo(i, this.height); }
            ctx.stroke();

            const drawLine = (data, color, fillOpacity) => {
                const step = this.width / (data.length - 1);
                ctx.beginPath();
                ctx.moveTo(0, this.height - data[0]);
                for(let i = 1; i < data.length; i++) {
                    const x_prev = (i - 1) * step, y_prev = this.height - data[i - 1];
                    const x_curr = i * step, y_curr = this.height - data[i];
                    const xc = (x_prev + x_curr) / 2;
                    ctx.quadraticCurveTo(x_prev, y_prev, xc, (y_prev + y_curr) / 2);
                    ctx.quadraticCurveTo(xc, (y_prev + y_curr) / 2, x_curr, y_curr);
                }
                ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.stroke();
                ctx.lineTo(this.width, this.height); ctx.lineTo(0, this.height); ctx.closePath();
                
                const gradient = ctx.createLinearGradient(0, 0, 0, this.height);
                gradient.addColorStop(0, `${color.replace(')', `, ${fillOpacity})`).replace('rgb', 'rgba')}`);
                gradient.addColorStop(1, 'rgba(13, 14, 21, 0)');
                ctx.fillStyle = gradient; ctx.fill();
            };

            drawLine(this.dataIn, '#00f3ff', 0.2); // Cyan Ingress
            drawLine(this.dataOut, '#00ff66', 0.2); // Green Egress
        }
    };
    charts.push(trafficChartObj);

    setInterval(() => {
        if(trafficChartObj.canvas.offsetParent === null) return; 
        
        trafficChartObj.dataIn.shift();
        trafficChartObj.dataOut.shift();
        const lastIn = trafficChartObj.dataIn[trafficChartObj.dataIn.length - 1];
        const lastOut = trafficChartObj.dataOut[trafficChartObj.dataOut.length - 1];
        trafficChartObj.dataIn.push(Math.max(20, Math.min(150, lastIn + (Math.random() * 40 - 20))));
        trafficChartObj.dataOut.push(Math.max(10, Math.min(100, lastOut + (Math.random() * 30 - 15))));
        trafficChartObj.draw();
    }, 1000);
}

// ----------------------------------------------------
// Threat Map Simulation
// ----------------------------------------------------
const tmCtx = document.getElementById('threatMapChart');
if(tmCtx) {
    const threatMapObj = {
        canvas: tmCtx,
        ctx: tmCtx.getContext('2d'),
        width: 0, height: 0,
        nodes: [],
        init: function() {
            for(let i=0; i<30; i++) {
                this.nodes.push({
                    x: Math.random(), 
                    y: Math.random(),
                    radius: Math.random() * 3 + 1,
                    alpha: Math.random(),
                    pulseDir: Math.random() > 0.5 ? 0.05 : -0.05,
                    isThreat: Math.random() > 0.8
                });
            }
        },
        draw: function() {
            const ctx = this.ctx;
            if (!ctx) return;
            ctx.clearRect(0, 0, this.width, this.height);
            
            ctx.lineWidth = 1;
            for(let i=0; i<this.nodes.length; i++) {
                for(let j=i+1; j<this.nodes.length; j++) {
                    const dist = Math.hypot(this.nodes[i].x - this.nodes[j].x, this.nodes[i].y - this.nodes[j].y);
                    if(dist < 0.2) { 
                        ctx.beginPath();
                        ctx.moveTo(this.nodes[i].x * this.width, this.nodes[i].y * this.height);
                        ctx.lineTo(this.nodes[j].x * this.width, this.nodes[j].y * this.height);
                        ctx.strokeStyle = `rgba(0, 243, 255, ${0.2 - dist})`;
                        ctx.stroke();
                    }
                }
            }

            let threatsActive = 0;
            this.nodes.forEach(node => {
                ctx.beginPath();
                ctx.arc(node.x * this.width, node.y * this.height, node.radius, 0, Math.PI * 2);
                if(node.isThreat) {
                    ctx.fillStyle = `rgba(255, 51, 51, ${node.alpha})`;
                    ctx.shadowBlur = 10;
                    ctx.shadowColor = 'red';
                    threatsActive++;
                } else {
                    ctx.fillStyle = `rgba(0, 243, 255, ${node.alpha})`;
                    ctx.shadowBlur = 5;
                    ctx.shadowColor = 'cyan';
                }
                ctx.fill();
                ctx.shadowBlur = 0; 
                
                node.alpha += node.pulseDir;
                if(node.alpha >= 1) { node.alpha = 1; node.pulseDir = -0.02; }
                if(node.alpha <= 0.2) { node.alpha = 0.2; node.pulseDir = 0.02; }
            });
            
            const scanNode = document.getElementById('nodes-scanning');
            if(scanNode) scanNode.innerText = threatsActive;
        }
    };
    threatMapObj.init();
    charts.push(threatMapObj);

    setInterval(() => {
        if(threatMapObj.canvas.offsetParent !== null) {
            if(Math.random() > 0.9 && threatMapObj.nodes.length > 0) {
                const idx = Math.floor(Math.random() * threatMapObj.nodes.length);
                threatMapObj.nodes[idx].isThreat = !threatMapObj.nodes[idx].isThreat;
            }
            threatMapObj.draw();
        }
    }, 50); 
}

// ----------------------------------------------------
// Protocol Traffic Chart
// ----------------------------------------------------
const pCtx = document.getElementById('protocolTrafficChart');
if(pCtx) {
    const protocolChartObj = {
        canvas: pCtx,
        ctx: pCtx.getContext('2d'),
        width: 0, height: 0,
        data: [70, 20, 5, 2, 3],
        labels: ['HTTPS', 'SSH', 'DNS', 'ICMP', 'OTHER'],
        draw: function() {
            const ctx = this.ctx;
            if (!ctx) return;
            ctx.clearRect(0, 0, this.width, this.height);
            
            const barWidth = (this.width / this.data.length) - 20;
            const maxH = this.height - 40;
            
            for(let i=0; i<this.data.length; i++) {
                const barH = (this.data[i] / 100) * maxH;
                const x = i * (barWidth + 20) + 10;
                const y = maxH - barH + 20;
                
                const gradient = ctx.createLinearGradient(0, y, 0, this.height);
                gradient.addColorStop(0, 'rgba(0, 243, 255, 0.8)');
                gradient.addColorStop(1, 'rgba(0, 243, 255, 0.1)');
                ctx.fillStyle = gradient;
                ctx.fillRect(x, y, barWidth, barH);
                
                ctx.fillStyle = '#8e8e9e';
                ctx.font = '12px "Share Tech Mono"';
                ctx.textAlign = 'center';
                ctx.fillText(this.labels[i], x + barWidth/2, this.height - 5);
                
                ctx.fillStyle = '#fff';
                ctx.fillText(this.data[i] + '%', x + barWidth/2, y - 10);
            }
        }
    };
    charts.push(protocolChartObj);

    setInterval(() => {
        if(protocolChartObj.canvas.offsetParent !== null) {
            protocolChartObj.data = protocolChartObj.data.map((val) => {
                return Math.max(1, val + (Math.random() * 4 - 2));
            });
            const sum = protocolChartObj.data.reduce((a, b) => a + b, 0);
            protocolChartObj.data = protocolChartObj.data.map(v => Math.round((v/sum)*100));
            protocolChartObj.draw();
        }
    }, 3000);
}

// ----------------------------------------------------
// Threat Logs Generation (Table)
// ----------------------------------------------------
const threatTypes = ['DDoS Attempt', 'SQL Injection', 'Brute Force SSH', 'Malware Payload', 'Port Scan', 'Cross-Site Scripting'];
const severities = [
    { label: 'SEVERE', class: 'badge-severe' },
    { label: 'WARNING', class: 'badge-warning' },
    { label: 'INFO', class: 'badge-info' }
];
const statuses = [
    { label: 'Blocked', class: 'status-dot status-blocked', text: 'Blocked' },
    { label: 'Investigating', class: 'status-dot status-investigating', text: 'Investigating' },
    { label: 'Active', class: 'status-dot status-active', text: 'Active Threat' }
];

function getRandomItem(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function getRandomIP() { return `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`; }

let logs = [];

function generateLog(withId = false) {
    const r = Math.random();
    let sev = severities[2];
    if (r < 0.1) sev = severities[0];
    else if (r < 0.4) sev = severities[1];

    const isSevere = sev.label === 'SEVERE';
    const status = isSevere ? statuses[2] : statuses[Math.floor(Math.random()*statuses.length)];

    const now = new Date();
    const timeString = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`;
    
    let idStr = '';
    if(withId) {
        const id = 'INC-' + Math.floor(Math.random() * 90000 + 10000);
        idStr = `<td class="text-cyan">${id}</td>`;
    }

    return `
        <tr>
            ${idStr}
            <td>${timeString}</td>
            <td><span class="${sev.class}">${sev.label}</span></td>
            <td>${getRandomIP()}</td>
            ${!withId ? `<td>10.0.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}</td>` : ''}
            <td>${getRandomItem(threatTypes)}</td>
            <td>
                <div style="display: flex; align-items: center;">
                    <span class="${status.class}"></span> ${status.text}
                </div>
            </td>
        </tr>
    `;
}

// Initial populate
for(let i=0; i<6; i++) {
    const d = new Date(Date.now() - (6-i)*60000);
    const tm = `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}:00`;
    logs.push(generateLog(false).replace(/\d{2}:\d{2}:\d{2}/, tm));
}
if(elThreatLogBody) elThreatLogBody.innerHTML = logs.join('');

let historicalLogs = [];
for(let i=0; i<15; i++) {
    historicalLogs.push(generateLog(true));
}
if(elHistoricalLogBody) elHistoricalLogBody.innerHTML = historicalLogs.join('');

setInterval(() => {
    if(Math.random() > 0.5) return;
    
    if(elThreatLogBody) {
        const newLog = generateLog(false);
        logs.unshift(newLog);
        if(logs.length > 8) logs.pop();
        
        const parser = new DOMParser();
        const rowNode = parser.parseFromString(newLog, "text/html").querySelector('tr');
        rowNode.style.backgroundColor = 'rgba(0, 243, 255, 0.2)';
        rowNode.style.transition = 'background-color 1s ease';
        
        elThreatLogBody.innerHTML = '';
        elThreatLogBody.appendChild(rowNode);
        setTimeout(() => { rowNode.style.backgroundColor = ''; }, 100);

        const restNode = parser.parseFromString(`<table><tbody>${logs.slice(1).join('')}</tbody></table>`, "text/html").querySelector('tbody');
        while(restNode.firstChild) { elThreatLogBody.appendChild(restNode.firstChild); }
    }
    
    if(elHistoricalLogBody) {
        const newHistLog = generateLog(true);
        const parser = new DOMParser();
        const histNode = parser.parseFromString(newHistLog, "text/html").querySelector('tr');
        elHistoricalLogBody.insertBefore(histNode, elHistoricalLogBody.firstChild);
        if(elHistoricalLogBody.childNodes.length > 25) {
            elHistoricalLogBody.removeChild(elHistoricalLogBody.lastChild);
        }
    }
}, 3500);

// Initialize all charts layout
setTimeout(() => { 
    window.dispatchEvent(new Event('resize')); 
}, 500);

// ----------------------------------------------------
// Interactivity & Polish Logic (Search & User)
// ----------------------------------------------------

// 1. Profile Dropdown Logic
const profileBtn = document.getElementById('profile-btn');
const profileDropdown = document.getElementById('profile-dropdown');

if(profileBtn && profileDropdown) {
    profileBtn.addEventListener('click', (e) => {
        profileDropdown.classList.toggle('show');
        e.stopPropagation();
    });

    document.addEventListener('click', (e) => {
        if (!profileBtn.contains(e.target)) {
            profileDropdown.classList.remove('show');
        }
    });
}

// 2. Global Search Logic
const globalSearchInput = document.getElementById('global-search-input');
if(globalSearchInput) {
    const alertDiv = document.createElement('div');
    alertDiv.className = 'global-alert';
    document.body.appendChild(alertDiv);

    globalSearchInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            const query = globalSearchInput.value.trim();
            if(query) {
                alertDiv.innerHTML = `<span class="material-icons-sharp" style="vertical-align: middle; color: var(--accent-cyan); margin-right: 8px;">search</span> Searching databases for <b>"${query}"</b>...`;
                alertDiv.classList.add('show');
                
                setTimeout(() => {
                    alertDiv.innerHTML = `<span class="material-icons-sharp" style="vertical-align: middle; color: var(--accent-green); margin-right: 8px;">check_circle</span> 0 Threats found for <b>"${query}"</b>.`;
                    setTimeout(() => alertDiv.classList.remove('show'), 2500);
                }, 1500);
                
                globalSearchInput.value = '';
                globalSearchInput.blur();
            }
        }
    });
}

// 3. Incident Logs Filtering
const incidentSearchInput = document.getElementById('incident-search-input');
if(incidentSearchInput) {
    incidentSearchInput.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase();
        const rows = document.querySelectorAll('#historical-log-body tr');
        rows.forEach(row => {
            if(row.innerText.toLowerCase().includes(query)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    });
}
