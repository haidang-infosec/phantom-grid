document.addEventListener('DOMContentLoaded', () => {
    // --- Navigation ---
    const navItems = document.querySelectorAll('.nav-item');
    const viewSections = document.querySelectorAll('.view-section');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const targetId = item.getAttribute('data-target');
            
            navItems.forEach(nav => nav.classList.remove('active'));
            item.classList.add('active');

            viewSections.forEach(section => {
                if (section.id === targetId) {
                    section.classList.add('active');
                    // Re-render map/charts to fix resize bugs when switching tabs
                    if(targetId === 'view-dashboard') {
                        setTimeout(() => window.dispatchEvent(new Event('resize')), 50);
                    }
                } else {
                    section.classList.remove('active');
                }
            });
        });
    });

    // --- Vector Map (Geo-IP) ---
    const map = new jsVectorMap({
        selector: '#world-map',
        map: 'world',
        backgroundColor: 'transparent',
        regionStyle: {
            initial: { fill: '#1f232b', stroke: '#272b35', strokeWidth: 0.5 },
            hover: { fill: '#2a2f3a' }
        },
        zoomButtons: false,
        zoomOnScroll: false,
        markers: [
            // Dummy initial markers
            { name: "Node-Alpha (Local)", coords: [38.9072, -77.0369], style: { fill: '#5e6ad2' } }
        ],
        markerStyle: {
            initial: { r: 4, fill: '#ef4444', stroke: '#000', strokeWidth: 1 }
        }
    });

    // --- Chart.js Setup ---
    Chart.defaults.color = '#888';
    Chart.defaults.font.family = 'Inter';

    // Traffic Line Chart
    const trafficCtx = document.getElementById('trafficChart').getContext('2d');
    const trafficGradient = trafficCtx.createLinearGradient(0, 0, 0, 300);
    trafficGradient.addColorStop(0, 'rgba(94, 106, 210, 0.4)');
    trafficGradient.addColorStop(1, 'rgba(94, 106, 210, 0.0)');

    const trafficChart = new Chart(trafficCtx, {
        type: 'line',
        data: {
            labels: Array(30).fill(''),
            datasets: [{
                label: 'Events/sec',
                data: Array(30).fill(0),
                borderColor: '#5e6ad2',
                backgroundColor: trafficGradient,
                borderWidth: 2,
                pointRadius: 0,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' } },
                x: { grid: { display: false } }
            },
            animation: { duration: 0 }
        }
    });

    // Mitigation Gauge
    const mitigationCtx = document.getElementById('mitigationGauge').getContext('2d');
    const mitigationChart = new Chart(mitigationCtx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [99.9, 0.1],
                backgroundColor: ['#5e6ad2', 'rgba(255,255,255,0.05)'],
                borderWidth: 0,
                circumference: 270,
                rotation: 225
            }]
        },
        options: { cutout: '80%', plugins: { tooltip: { enabled: false } }, animation: false }
    });

    // Load Gauge
    const loadCtx = document.getElementById('loadGauge').getContext('2d');
    const loadChart = new Chart(loadCtx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: [12, 88],
                backgroundColor: ['#2ecc71', 'rgba(255,255,255,0.05)'],
                borderWidth: 0,
                circumference: 270,
                rotation: 225
            }]
        },
        options: { cutout: '80%', plugins: { tooltip: { enabled: false } }, animation: false }
    });

    // --- State & SSE logic ---
    let bootTime = Date.now();
    let currentEventCount = 0;

    const els = {
        uptime: document.getElementById('system-uptime'),
        dropped: document.getElementById('stat-dropped'),
        authSuccess: document.getElementById('stat-auth-success'),
        authFailed: document.getElementById('stat-auth-failed'),
        cpuVal: document.getElementById('cpu-load-val'),
        logTable: document.getElementById('log-table-body'),
        clearLogs: document.getElementById('clear-logs')
    };

    let lastDropped = 0;
    let lastSuccess = 0;
    let lastFailed = 0;

    // Animated Counter function
    function animateValue(obj, start, end, duration) {
        if(!obj) return;
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            obj.innerHTML = Math.floor(progress * (end - start) + start).toLocaleString();
            if (progress < 1) { window.requestAnimationFrame(step); }
        };
        window.requestAnimationFrame(step);
    }

    // Uptime & Load Simulation
    setInterval(() => {
        const diff = Math.floor((Date.now() - bootTime) / 1000);
        const h = String(Math.floor(diff / 3600)).padStart(2, '0');
        const m = String(Math.floor((diff % 3600) / 60)).padStart(2, '0');
        const s = String(diff % 60).padStart(2, '0');
        els.uptime.innerText = `Uptime: ${h}:${m}:${s}`;

        // Fluctuate CPU gauge
        const cpu = 10 + Math.floor(Math.random() * 15);
        els.cpuVal.innerText = cpu + '%';
        loadChart.data.datasets[0].data = [cpu, 100 - cpu];
        loadChart.update();
    }, 1000);

    // Traffic Chart Update
    setInterval(() => {
        const data = trafficChart.data.datasets[0].data;
        data.push(currentEventCount);
        data.shift();
        trafficChart.update();
        currentEventCount = 0;
    }, 1000);

    // Poll actual eBPF stats
    let lastDropped = 0, lastSuccess = 0, lastFailed = 0;
    setInterval(async () => {
        try {
            const res = await fetch('/api/stats');
            if (res.ok) {
                const data = await res.json();
                if (data.dropped_packets !== undefined && data.dropped_packets !== lastDropped) {
                    animateValue(els.dropped, lastDropped, data.dropped_packets, 500);
                    lastDropped = data.dropped_packets;
                }
                if (data.auth_success !== undefined && data.auth_success !== lastSuccess) {
                    animateValue(els.authSuccess, lastSuccess, data.auth_success, 500);
                    lastSuccess = data.auth_success;
                }
                if (data.auth_failed !== undefined && data.auth_failed !== lastFailed) {
                    animateValue(els.authFailed, lastFailed, data.auth_failed, 500);
                    lastFailed = data.auth_failed;
                }
            }
        } catch (e) {
            console.error('Stats poll error:', e);
        }
    }, 2000);

    // SSE Logs
    const logSource = new EventSource('/api/logs');
    logSource.onmessage = function(event) {
        currentEventCount++;
        const msg = event.data;
        appendLog(msg);
        addMapMarker(msg);
    };

    function appendLog(rawMsg) {
        let timeStr = new Date().toLocaleTimeString();
        let ip = '-';
        let severityClass = 'badge-info';
        let severityText = 'INFO';
        let action = rawMsg;
        let target = 'System';

        const timeMatch = rawMsg.match(/^\[(.*?)\]/);
        if (timeMatch) { action = rawMsg.substring(timeMatch[0].length).trim(); }

        const ipMatch = action.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/);
        if (ipMatch) { ip = ipMatch[0]; }

        if (action.includes('TRAP HIT') || action.includes('COMMAND') || action.includes('Failed auth')) {
            severityClass = 'badge-danger'; severityText = 'CRITICAL'; target = 'Honeypot';
        } else if (action.includes('Successful auth')) {
            severityClass = 'badge-success'; severityText = 'AUTH OK'; target = 'SPA Engine';
        } else if (action.includes('stealth')) {
            severityClass = 'badge-warning'; severityText = 'DROPPED'; target = 'XDP Filter';
        }

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${escapeHTML(timeStr)}</td>
            <td>${escapeHTML(ip)}</td>
            <td>${escapeHTML(target)}</td>
            <td>${escapeHTML(action)}</td>
            <td><span class="badge ${severityClass}">${severityText}</span></td>
        `;

        els.logTable.insertBefore(tr, els.logTable.firstChild);
        if (els.logTable.children.length > 50) els.logTable.removeChild(els.logTable.lastChild);
    }

    // Map Marker Generator (Random locations for visual WOW factor)
    function addMapMarker(msg) {
        if (!msg.includes('TRAP') && !msg.includes('connection')) return;
        
        // Random coords for visual effect
        const lat = (Math.random() * 120 - 60).toFixed(4); // -60 to 60
        const lng = (Math.random() * 360 - 180).toFixed(4); // -180 to 180
        
        const markerObj = { name: "Threat Source", coords: [lat, lng] };
        map.addMarker(Date.now().toString(), markerObj);
        
        // Keep only last 10 markers to avoid clutter
        if(Object.keys(map.markers).length > 10) {
            const firstKey = Object.keys(map.markers)[0];
            // JSVectorMap doesn't have a direct removeMarker by index, so this is a hack.
            // Ideally we'd remove it, but for now we just let it accumulate or reset map.
        }
    }

    els.clearLogs.addEventListener('click', () => { els.logTable.innerHTML = ''; });
    
    function escapeHTML(str) {
        const p = document.createElement('p'); p.appendChild(document.createTextNode(str)); return p.innerHTML;
    }

    // --- Authentication & RBAC ---
    let currentUser = null;
    
    async function initAuth() {
        try {
            const res = await fetch('/api/auth/me');
            if (res.status === 401) {
                window.location.href = '/login';
                return;
            }
            if (res.ok) {
                currentUser = await res.json();
                document.getElementById('username-display').innerText = currentUser.username;
                document.getElementById('user-avatar').src = `https://ui-avatars.com/api/?name=${currentUser.username}&background=2563eb&color=fff&rounded=true&bold=true`;
                
                // RBAC UI Restrictions
                if (currentUser.role !== 'admin') {
                    document.getElementById('save-settings').disabled = true;
                    document.getElementById('save-settings').style.opacity = '0.5';
                    document.getElementById('save-settings').title = 'Admin privilege required';
                    
                    document.getElementById('btn-change-pass').disabled = true;
                    document.getElementById('btn-change-pass').style.opacity = '0.5';
                }
            }
        } catch(e) {
            console.error('Auth error:', e);
        }
    }
    
    async function fetchStats() {
        const agentSelect = document.getElementById('agent-select');
        let url = '/api/stats';
        if (agentSelect && agentSelect.value) {
            url += '?agent=' + encodeURIComponent(agentSelect.value);
        }

        try {
            const res = await fetch(url);
            if (!res.ok) return;
            const data = await res.json();
            
            if (data.dropped_packets !== undefined && data.dropped_packets !== lastDropped) {
                animateValue(els.dropped, lastDropped, data.dropped_packets, 500);
                lastDropped = data.dropped_packets;
            }
            if (data.auth_success !== undefined && data.auth_success !== lastSuccess) {
                animateValue(els.authSuccess, lastSuccess, data.auth_success, 500);
                lastSuccess = data.auth_success;
            }
            if (data.auth_failed !== undefined && data.auth_failed !== lastFailed) {
                animateValue(els.authFailed, lastFailed, data.auth_failed, 500);
                lastFailed = data.auth_failed;
            }
        } catch (error) {
            console.error("Error fetching stats:", error);
        }
    }
    
    async function fetchSettings() {
        try {
            const res = await fetch('/api/settings');
            if(res.ok) {
                const s = await res.json();
                document.getElementById('set-agent-id').value = s.agent_identifier;
                document.getElementById('set-mirage').checked = s.mirage_enabled;
                document.getElementById('set-log-rot').value = s.log_rotation;
                document.getElementById('set-stealth').checked = s.stealth_mode;
                document.getElementById('set-ebpf-timeout').value = s.ebpf_timeout_sec;
                document.getElementById('set-spa-port').value = s.spa_trigger_port;
                document.getElementById('set-spa-ttl').value = s.spa_whitelist_sec;
                document.getElementById('set-spa-skew').value = s.spa_clock_skew_sec;
            }
        } catch(e) {
            console.error('Settings load error:', e);
        }
    }
    
    async function fetchAgents() {
        try {
            const res = await fetch('/api/fleet/agents');
            if(res.ok) {
                const agents = await res.json();
                const select = document.getElementById('agent-select');
                if(!select) return;
                
                // Keep the first option (Local Agent), add new ones
                select.innerHTML = '<option value="">Local Agent (Default)</option>';
                if(agents) {
                    agents.forEach(a => {
                        const opt = document.createElement('option');
                        opt.value = a.agent_id;
                        opt.textContent = `${a.agent_id} (${a.ip})`;
                        select.appendChild(opt);
                    });
                }
            }
        } catch(e) {
            // fleet API might 404 if not running fleet, ignore
        }
    }
    
    initAuth().then(() => {
        fetchSettings();
        fetchAgents();
    });

    // Refresh stats when agent changes
    const agentSelect = document.getElementById('agent-select');
    if (agentSelect) {
        agentSelect.addEventListener('change', fetchStats);
    }

    // Logout
    document.getElementById('btn-logout').addEventListener('click', async () => {
        await fetch('/api/auth/logout', { method: 'POST' });
        window.location.href = '/login';
    });

    // Change Password
    document.getElementById('btn-change-pass').addEventListener('click', async () => {
        const oldP = document.getElementById('old-pass').value;
        const newP = document.getElementById('new-pass').value;
        
        if(!oldP || !newP) {
            showToast('Please enter both passwords.', 'danger');
            return;
        }

        try {
            const res = await fetch('/api/auth/password', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({old_password: oldP, new_password: newP})
            });
            if(res.ok) {
                showToast('Password changed successfully.', 'success');
                document.getElementById('old-pass').value = '';
                document.getElementById('new-pass').value = '';
            } else {
                showToast('Failed to change password.', 'danger');
            }
        } catch(e) {
            showToast('Network error.', 'danger');
        }
    });

    // --- Settings Toast ---
    document.getElementById('save-settings').addEventListener('click', async () => {
        if(currentUser && currentUser.role !== 'admin') return;

        const payload = {
            agent_identifier: document.getElementById('set-agent-id').value,
            mirage_enabled: document.getElementById('set-mirage').checked,
            log_rotation: document.getElementById('set-log-rot').value,
            protected_if: document.getElementById('set-interface').value,
            stealth_mode: document.getElementById('set-stealth').checked,
            ebpf_timeout_sec: parseInt(document.getElementById('set-ebpf-timeout').value, 10),
            spa_trigger_port: parseInt(document.getElementById('set-spa-port').value, 10),
            spa_whitelist_sec: parseInt(document.getElementById('set-spa-ttl').value, 10),
            spa_clock_skew_sec: parseInt(document.getElementById('set-spa-skew').value, 10)
        };

        try {
            const res = await fetch('/api/settings', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(payload)
            });
            
            if(res.ok) {
                showToast('<strong>Configuration Applied</strong><br>Settings updated successfully.', 'success');
            } else {
                showToast('Failed to save settings.', 'danger');
            }
        } catch(e) {
            showToast('Network error while saving.', 'danger');
        }
    });

    function showToast(htmlMsg, type = 'success') {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = 'toast';
        if (type === 'danger') {
            toast.style.borderLeftColor = '#e74c3c';
        }
        toast.innerHTML = htmlMsg;
        container.appendChild(toast);
        
        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    // --- Notification Dropdown Logic ---
    const notifBtn = document.getElementById('notif-btn');
    const notifDropdown = document.getElementById('notif-dropdown');

    if (notifBtn && notifDropdown) {
        notifBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            notifDropdown.classList.toggle('show');
        });

        document.addEventListener('click', (e) => {
            if (!notifDropdown.contains(e.target) && e.target !== notifBtn) {
                notifDropdown.classList.remove('show');
            }
        });
    }
});
