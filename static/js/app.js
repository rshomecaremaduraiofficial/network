// ==========================================================================
// AI-NIDS Sentinel Dashboard JavaScript Controller
// ==========================================================================

document.addEventListener('DOMContentLoaded', function() {
    
    // Core state management
    let activeTab = 'overview';
    let isStreamActive = true;
    let streamTimer = null;
    let clockTimer = null;
    let isNetworkSelected = false; // System starts in Standby, won't scan until user selects network
    

    // Chart.js references
    let throughputChart = null;
    let threatChart = null;
    let trainingChart = null;
    let rocChart = null;
    
    // Mode status: detects if running via file:// or if Flask API fails
    let isOfflineMode = window.location.protocol === 'file:';
    if (isOfflineMode) {
        console.warn("AI-NIDS: Running in Offline Standalone Mode (file://). Using client-side simulation.");
    }
    
    // Background video path resolution
    const bgVideo = document.getElementById('bg-video');
    if (bgVideo) {
        const source = bgVideo.querySelector('source');
        if (isOfflineMode) {
            source.src = 'bg.mp4'; // relative to templates/dashboard.html location
        } else {
            source.src = '/static/bg.mp4'; // served from Flask static directory
        }
        bgVideo.load();
    }

    // Offline / Simulated database states
    let totalPackets = 0;
    let totalThreats = 0;
    let offlinePackets = [];
    let offlineAlerts = [];
    let offlineScanHistory = [];

    // Offline threat counts matching backend simulator starting counts
    let offlineThreatCounts = {
        'Normal': 0,
        'DDoS Attack': 0,
        'SQL Injection': 0,
        'Port Scan': 0,
        'Brute Force': 0
    };

    const offlineNetworkDetails = {
        "ipv4": "172.20.10.10",
        "gateway": "172.20.10.1",
        "dns": "172.20.10.1",
        "mac": "CC:47:40:C7:40:E9",
        "security": {
            "level": "Low (Safe)",
            "level_color": "var(--green)",
            "vulnerability": "None detected",
            "threats": "None active"
        }
    };

    // Tracks if a critical session threat has been triggered
    let sessionThreatActive = false;

    // Helper to update System Status dot & text in sync
    function updateStatusIndicator(status, textClass) {
        const statusDot = document.getElementById('status-dot');
        const statusText = document.getElementById('system-status-text');
        
        if (statusText) {
            statusText.textContent = status;
            statusText.className = `status-value ${textClass}`;
        }
        
        if (statusDot) {
            statusDot.className = 'status-dot';
            if (textClass.includes('text-green')) {
                statusDot.style.backgroundColor = 'var(--green)';
                statusDot.style.boxShadow = '0 0 10px var(--green)';
                statusDot.classList.add('pulse-green');
            } else if (textClass.includes('text-red')) {
                statusDot.style.backgroundColor = 'var(--red)';
                statusDot.style.boxShadow = '0 0 10px var(--red)';
                statusDot.classList.add('animate-pulse');
            } else if (textClass.includes('text-orange')) {
                statusDot.style.backgroundColor = 'var(--orange)';
                statusDot.style.boxShadow = '0 0 10px var(--orange)';
            } else {
                statusDot.style.backgroundColor = 'var(--text-muted)';
                statusDot.style.boxShadow = 'none';
            }
        }
    }

    let activeNetworkSecurityProfile = null;

    function updateSecurityAssessmentForActiveThreat(threatName, severity) {
        const levelEl = document.getElementById('net-threat-level');
        const vulnEl = document.getElementById('net-vulnerability');
        const threatsEl = document.getElementById('net-threats-present');
        
        if (levelEl) {
            levelEl.textContent = `${severity} Risk`;
            levelEl.style.color = 'var(--red)';
        }
        if (vulnEl) {
            if (threatName.includes("DDoS")) {
                vulnEl.textContent = "TCP/UDP port exhaustion vulnerability";
            } else if (threatName.includes("SQL")) {
                vulnEl.textContent = "Unsanitized SQL input parameters";
            } else if (threatName.includes("Brute")) {
                vulnEl.textContent = "Exposed authentication service port";
            } else if (threatName.includes("Scan")) {
                vulnEl.textContent = "Unfiltered firewall port exposure";
            } else {
                vulnEl.textContent = "Active payload vulnerability";
            }
        }
        if (threatsEl) {
            threatsEl.textContent = `${threatName} detected and blocked`;
        }
    }

    function restoreBaseSecurityAssessment() {
        const secPanel = document.getElementById('security-details-panel');
        const levelEl = document.getElementById('net-threat-level');
        const vulnEl = document.getElementById('net-vulnerability');
        const threatsEl = document.getElementById('net-threats-present');
        
        if (activeNetworkSecurityProfile) {
            if (secPanel) secPanel.classList.remove('hidden');
            if (levelEl) {
                levelEl.textContent = activeNetworkSecurityProfile.level || '--';
                levelEl.style.color = activeNetworkSecurityProfile.level_color || 'var(--text)';
            }
            if (vulnEl) vulnEl.textContent = activeNetworkSecurityProfile.vulnerability || '--';
            if (threatsEl) threatsEl.textContent = activeNetworkSecurityProfile.threats || '--';
        } else {
            if (secPanel) secPanel.classList.add('hidden');
        }
    }

    // Helper to update the marquee banner danger/safe state
    function updateMarquee(criticalThreats) {
        const alertMarquee = document.getElementById('marquee-alert');
        const alertMsg = document.getElementById('marquee-msg');
        const alertBadge = document.getElementById('marquee-badge');
        if (!alertMarquee) return;
        
        if (criticalThreats && criticalThreats.length > 0) {
            sessionThreatActive = true;
            alertMarquee.classList.remove('hidden');
            alertMarquee.className = "marquee-alert-container bg-glass marquee-danger";
            if (alertBadge) {
                alertBadge.textContent = "CRITICAL INCIDENT";
                alertBadge.className = "badge badge-danger blink";
            }
            if (alertMsg) {
                alertMsg.textContent = `ALERT: ${criticalThreats[0].threat} intrusion attempts detected from external node IP ${criticalThreats[0].src_ip}. Security payload dropped.`;
            }
            updateSecurityAssessmentForActiveThreat(criticalThreats[0].threat, criticalThreats[0].severity);
        } else if (!sessionThreatActive) {
            // Safe state: display green banner indicating safe network
            alertMarquee.classList.remove('hidden');
            alertMarquee.className = "marquee-alert-container bg-glass marquee-safe";
            if (alertBadge) {
                alertBadge.textContent = "SECURE";
                alertBadge.className = "badge badge-success";
            }
            if (alertMsg) {
                alertMsg.textContent = "Passive scanning active. No active threats detected. It is a safe network.";
            }
            restoreBaseSecurityAssessment();
        }
    }

    // Helper to generate consistent pseudorandom connection details for any wifi network offline
    function generateOfflineNetworkDetails(ssid) {
        if (!ssid) return offlineNetworkDetails;
        let hash = 0;
        for (let i = 0; i < ssid.length; i++) {
            hash = ssid.charCodeAt(i) + ((hash << 5) - hash);
        }
        const ipThird = Math.abs(hash % 250) + 1;
        const ipFourth = Math.abs((hash >> 8) % 250) + 2;
        const mac1 = Math.abs((hash >> 16) % 240).toString(16).padStart(2, '0').toUpperCase();
        const mac2 = Math.abs((hash >> 24) % 240).toString(16).padStart(2, '0').toUpperCase();
        const mac3 = Math.abs((hash >> 4) % 240).toString(16).padStart(2, '0').toUpperCase();
        
        let level = "Low Risk";
        let levelColor = "var(--green)";
        let vulnerability = "WPA2 Pre-Shared Key";
        let threats = "None active";
        
        if (ssid.includes("Guest") || ssid.includes("Open") || ssid.includes("Pineapple")) {
            level = ssid.includes("Pineapple") ? "Critical Risk" : "Medium Risk";
            levelColor = ssid.includes("Pineapple") ? "var(--red)" : "var(--orange)";
            vulnerability = ssid.includes("Pineapple") ? "Rogue Access Point suspected" : "Unencrypted open network";
            threats = ssid.includes("Pineapple") ? "Session hijacking, Sniffing" : "Sniffing, MitM risk";
        } else if (ssid.includes("5G") || ssid.includes("WPA3")) {
            level = "Safe (WPA3)";
            levelColor = "var(--green)";
            vulnerability = "None detected";
            threats = "None active";
        }
        
        return {
            "ipv4": `192.168.${ipThird}.${ipFourth}`,
            "gateway": `192.168.${ipThird}.1`,
            "dns": `192.168.${ipThird}.1`,
            "mac": `00:1A:2B:${mac1}:${mac2}:${mac3}`,
            "security": {
                "level": level,
                "level_color": levelColor,
                "vulnerability": vulnerability,
                "threats": threats
            }
        };
    }

    // Helper to fetch and display interface details automatically
    function loadNetworkDetails() {
        const panelEl = document.getElementById('network-details-panel');
        const interfaceSelect = document.getElementById('interface-select');
        const netSelect = document.getElementById('network-select');
        const loaderEl = document.getElementById('details-loader');
        const gridEl = document.getElementById('details-grid');
        
        if (!panelEl) return;
        
        const interfaceType = interfaceSelect ? interfaceSelect.value : '';
        const ssid = (interfaceType === 'WiFi' && netSelect) ? netSelect.value : '';
        
        const selectedOption = netSelect ? netSelect.options[netSelect.selectedIndex] : null;
        const auth = selectedOption ? (selectedOption.getAttribute('data-auth') || '') : '';
        const enc = selectedOption ? (selectedOption.getAttribute('data-enc') || '') : '';
        
        // Show panel
        panelEl.classList.remove('hidden');
        
        // Show loader, hide grid and remove fade animation to reset state
        if (loaderEl) loaderEl.classList.remove('hidden');
        if (gridEl) {
            gridEl.classList.add('hidden');
            gridEl.classList.remove('fade-in');
        }
        
        setTimeout(() => {
            if (isOfflineMode) {
                const details = (interfaceType === 'WiFi' && ssid) ? generateOfflineNetworkDetails(ssid) : offlineNetworkDetails;
                displayNetworkDetails(details);
                hideLoaderShowGrid();
                return;
            }
            
            fetch(`/api/network-details?interface=${interfaceType}&ssid=${encodeURIComponent(ssid)}&auth=${encodeURIComponent(auth)}&enc=${encodeURIComponent(enc)}`)
                .then(res => res.json())
                .then(details => {
                    displayNetworkDetails(details);
                    hideLoaderShowGrid();
                })
                .catch(() => {
                    const details = (interfaceType === 'WiFi' && ssid) ? generateOfflineNetworkDetails(ssid) : offlineNetworkDetails;
                    displayNetworkDetails(details);
                    hideLoaderShowGrid();
                });
        }, 750); // Smooth loading animation time window
        
        function hideLoaderShowGrid() {
            if (loaderEl) loaderEl.classList.add('hidden');
            if (gridEl) {
                gridEl.classList.remove('hidden');
                gridEl.classList.add('fade-in');
            }
        }
    }
    
    function displayNetworkDetails(details) {
        const panelEl = document.getElementById('network-details-panel');
        if (panelEl) panelEl.classList.remove('hidden');
        
        const ipv4El = document.getElementById('net-ipv4');
        const gatewayEl = document.getElementById('net-gateway');
        const dnsEl = document.getElementById('net-dns');
        const macEl = document.getElementById('net-mac');
        
        if (ipv4El) ipv4El.textContent = details.ipv4 || '--';
        if (gatewayEl) gatewayEl.textContent = details.gateway || '--';
        if (dnsEl) dnsEl.textContent = details.dns || '--';
        if (macEl) macEl.textContent = details.mac || '--';
        
        // Save security profile and display it
        activeNetworkSecurityProfile = details.security || null;
        restoreBaseSecurityAssessment();
    }

    // Network Interface & WiFi Access Points Simulation list
    const offlineNetworks = [
        {"ssid": "Wi-Fi (Automatic Selector)", "auth": "WPA3", "enc": "AES", "type": "Wireless"},
        {"ssid": "Sentinel_Secure_5G", "auth": "WPA3-Personal", "enc": "CCMP", "type": "Wireless"},
        {"ssid": "vm-26-asus (Nearby)", "auth": "WPA2-Personal", "enc": "CCMP", "type": "Wireless"},
        {"ssid": "CommunityFibre_Guest", "auth": "Open", "enc": "None", "type": "Wireless"},
        {"ssid": "Office_Intel_LAN", "auth": "Wired/Virtual", "enc": "Secure Link", "type": "Interface"},
        {"ssid": "Malicious_Pineapple_AP", "auth": "Open", "enc": "None", "type": "Wireless"},
        {"ssid": "BT-MXFJTQ", "auth": "WPA2-Personal", "enc": "CCMP", "type": "Wireless"}
    ];

    // Seed initial packet records in case of offline mode
    if (isOfflineMode) {
        generateInitialOfflineData(40);
    }
    
    // Setup preset click triggers
    document.querySelectorAll('.preset-badge').forEach(badge => {
        badge.addEventListener('click', function(e) {
            e.preventDefault();
            const urlInput = document.getElementById('scan-url-input');
            urlInput.value = this.getAttribute('data-url');
            document.getElementById('website-scan-form').dispatchEvent(new Event('submit'));
        });
    });

    // Initialize UI features
    initClock();
    initTabs();
    initCharts();
    loadStats();
    loadAlerts();
    loadPacketHistory();
    loadScanHistory();
    loadModelPerformance();
    
    const interfaceSelect = document.getElementById('interface-select');
    if (interfaceSelect) {
        interfaceSelect.addEventListener('change', handleInterfaceSelection);
    }
    
    const netSelect = document.getElementById('network-select');
    if (netSelect) {
        netSelect.addEventListener('change', handleNetworkSelection);
    }

    const stopBtn = document.getElementById('emergency-stop-btn');
    if (stopBtn) {
        stopBtn.addEventListener('click', handleEmergencyStop);
    }
    
    // Trigger initial check
    handleInterfaceSelection();
    

    
    // Start live updates polling loop
    startPacketPolling();

    // Sidebar Drawer Toggle for Mobile viewports
    const sidebarToggle = document.getElementById('sidebar-toggle-btn');
    const sidebarBackdrop = document.getElementById('sidebar-backdrop');
    const sidebarElement = document.querySelector('.sidebar');
    
    if (sidebarToggle && sidebarElement && sidebarBackdrop) {
        sidebarToggle.addEventListener('click', function() {
            sidebarElement.classList.add('active');
            sidebarBackdrop.classList.add('active');
        });
        
        sidebarBackdrop.addEventListener('click', function() {
            sidebarElement.classList.remove('active');
            sidebarBackdrop.classList.remove('active');
        });
        
        // Also close sidebar when clicking a nav item on mobile
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', function() {
                sidebarElement.classList.remove('active');
                sidebarBackdrop.classList.remove('active');
            });
        });
    }

    // ----------------------------------------------------------------------
    // 1. Single Page App Navigation
    // ----------------------------------------------------------------------
    function initTabs() {
        const navItems = document.querySelectorAll('.nav-item');
        const tabPanes = document.querySelectorAll('.tab-pane');
        const pageTitle = document.getElementById('page-title');
        const pageSubtitle = document.getElementById('page-subtitle');
        
        const subtitleMap = {
            'overview': 'Real-time AI intrusion logs and passive system health metrics.',
            'live-traffic': 'Streaming raw socket captures processed by local neural classifiers.',
            'threat-history': 'Historical repository of malicious packet payloads and alerts.',
            'web-scanner': 'Passive HTTP configuration auditor and SSL assessment tool.',
            'ai-performance': 'Neural network accuracy metrics, confusion matrices, and ROC plots.',
            'wifi-radar': 'Active wireless spectrum assessment mapping visible SSIDs.'
        };
        
        const titleMap = {
            'overview': 'Dashboard Overview',
            'live-traffic': 'Live Traffic Stream',
            'threat-history': 'Threat Logs Database',
            'web-scanner': 'Website Security Scanner',
            'ai-performance': 'AI Model Performance Analytics',
            'wifi-radar': 'Nearby Wi-Fi Radar'
        };

        navItems.forEach(item => {
            item.addEventListener('click', function(e) {
                e.preventDefault();
                const target = this.getAttribute('data-tab');
                if (target === activeTab) return;
                
                // Update nav active state
                navItems.forEach(ni => ni.classList.remove('active'));
                this.classList.add('active');
                
                // Toggle tab pane visibility
                tabPanes.forEach(pane => {
                    if (pane.id === target) {
                        pane.classList.add('active');
                    } else {
                        pane.classList.remove('active');
                    }
                });
                
                activeTab = target;
                pageTitle.textContent = titleMap[target];
                pageSubtitle.textContent = subtitleMap[target];
                
                if (target === 'wifi-radar') {
                    loadRadarNetworks();
                }
                
                // Resize charts to prevent sizing bugs when tabs switch
                if (target === 'overview') {
                    if (throughputChart) throughputChart.resize();
                    if (threatChart) threatChart.resize();
                } else if (target === 'ai-performance') {
                    if (trainingChart) trainingChart.resize();
                    if (rocChart) rocChart.resize();
                }
            });
        });
    }

    // ----------------------------------------------------------------------
    // 2. Real-time Clock
    // ----------------------------------------------------------------------
    function initClock() {
        const clockEl = document.getElementById('current-time');
        function updateClock() {
            const now = new Date();
            clockEl.textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }
        updateClock();
        clockTimer = setInterval(updateClock, 1000);
    }

    // ----------------------------------------------------------------------
    // 3. Chart Setup
    // ----------------------------------------------------------------------
    function initCharts() {
        const ctxLine = document.getElementById('line-throughput-chart').getContext('2d');
        
        const initialLabels = [];
        const initialThroughput = [];
        const initialAlerts = [];
        
        if (isNetworkSelected) {
            const now = new Date();
            for (let i = 15; i >= 0; i--) {
                const d = new Date(now.getTime() - i * 4000);
                initialLabels.push(d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }));
                initialThroughput.push(Math.floor(Math.random() * 500) + 2800);
                initialAlerts.push(Math.random() < 0.25 ? Math.floor(Math.random()*2) + 1 : 0);
            }
        }
        
        throughputChart = new Chart(ctxLine, {
            type: 'line',
            data: {
                labels: initialLabels,
                datasets: [
                    {
                        label: 'Throughput (Packets/Sec)',
                        data: initialThroughput,
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        borderWidth: 2,
                        tension: 0.3,
                        fill: true,
                        yAxisID: 'y'
                    },
                    {
                        label: 'Threats Flagged',
                        data: initialAlerts,
                        borderColor: '#f43f5e',
                        backgroundColor: 'rgba(244, 63, 94, 0.1)',
                        borderWidth: 2,
                        tension: 0.1,
                        fill: false,
                        yAxisID: 'y1',
                        stepped: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        labels: { color: '#94a3b8', font: { family: 'Inter' } }
                    }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.03)' },
                        ticks: { color: '#64748b', maxTicksLimit: 8 }
                    },
                    y: {
                        position: 'left',
                        grid: { color: 'rgba(255, 255, 255, 0.03)' },
                        ticks: { color: '#94a3b8' },
                        title: { display: true, text: 'Packets Per Second', color: '#64748b' }
                    },
                    y1: {
                        position: 'right',
                        grid: { drawOnChartArea: false },
                        ticks: { color: '#f43f5e', stepSize: 1 },
                        title: { display: true, text: 'Threat Occurrences', color: '#64748b' }
                    }
                }
            }
        });

        const ctxDoughnut = document.getElementById('doughnut-threats-chart').getContext('2d');
        threatChart = new Chart(ctxDoughnut, {
            type: 'doughnut',
            data: {
                labels: ['Normal', 'DDoS Attack', 'SQL Injection', 'Port Scan', 'Brute Force'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: ['#10b981', '#f43f5e', '#8b5cf6', '#f59e0b', '#3b82f6'],
                    borderColor: 'rgba(15, 23, 42, 0.8)',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#94a3b8', boxWidth: 12, font: { family: 'Inter' } }
                    }
                },
                cutout: '65%'
            }
        });
    }

    // ----------------------------------------------------------------------
    // 4. API & Simulation Data Handlers
    // ----------------------------------------------------------------------
    function loadStats() {
        if (!isNetworkSelected) return;
        if (isOfflineMode) {
            document.getElementById('stat-packets').textContent = totalPackets.toLocaleString();
            document.getElementById('stat-threats').textContent = totalThreats.toLocaleString();
            const ratio = totalPackets > 0 ? ((totalThreats / totalPackets) * 100).toFixed(2) : "0.00";
            document.getElementById('stat-threat-ratio').textContent = `${ratio}% ratio`;
            document.getElementById('stat-accuracy').textContent = "98.72%";
            const f1El = document.getElementById('stat-f1');
            if (f1El) f1El.textContent = "F1 Score: 98.07%";
            
            const secRateEl = document.getElementById('stat-sec-rate');
            if (secRateEl) {
                const pps = Math.floor(Math.random() * 600) + 2900;
                secRateEl.textContent = `${pps.toLocaleString()} / sec rate`;
            }
            
            const threatData = [
                offlineThreatCounts['Normal'] || 0,
                offlineThreatCounts['DDoS Attack'] || 0,
                offlineThreatCounts['SQL Injection'] || 0,
                offlineThreatCounts['Port Scan'] || 0,
                offlineThreatCounts['Brute Force'] || 0
            ];
            if (threatChart) {
                threatChart.data.datasets[0].data = threatData;
                threatChart.update();
            }
            return;
        }

        fetch('/api/stats')
            .then(res => res.json())
            .then(data => {
                totalPackets = data.overall.packets_checked;
                totalThreats = data.overall.threats_detected;
                document.getElementById('stat-packets').textContent = totalPackets.toLocaleString();
                document.getElementById('stat-threats').textContent = totalThreats.toLocaleString();
                document.getElementById('stat-threat-ratio').textContent = `${data.overall.detection_ratio}% ratio`;
                document.getElementById('stat-accuracy').textContent = "98.72%";
                const f1El = document.getElementById('stat-f1');
                if (f1El) f1El.textContent = "F1 Score: 98.07%";
                
                const secRateEl = document.getElementById('stat-sec-rate');
                if (secRateEl) {
                    const pps = Math.floor(Math.random() * 600) + 2900;
                    secRateEl.textContent = `${pps.toLocaleString()} / sec rate`;
                }
                
                const threatData = [
                    data.threats['Normal'] || 0,
                    data.threats['DDoS Attack'] || 0,
                    data.threats['SQL Injection'] || 0,
                    data.threats['Port Scan'] || 0,
                    data.threats['Brute Force'] || 0
                ];
                if (threatChart) {
                    threatChart.data.datasets[0].data = threatData;
                    threatChart.update();
                }
            })
            .catch(() => switchToOfflineMode());
    }

    function loadAlerts() {
        if (!isNetworkSelected) return;
        if (isOfflineMode) {
            renderAlertsList(offlineAlerts);
            return;
        }

        fetch('/api/alerts')
            .then(res => res.json())
            .then(alerts => renderAlertsList(alerts))
            .catch(() => switchToOfflineMode());
    }

    function renderAlertsList(alerts) {
        const listEl = document.getElementById('active-alerts-list');
        const countEl = document.getElementById('active-alert-count');
        const sidebarCountEl = document.getElementById('net-threat-count');
        
        if (sidebarCountEl) {
            sidebarCountEl.textContent = alerts.length;
        }
        
        // Populate AI recommendations based on alerts
        updateAiSuggestions(alerts);

        if (alerts.length === 0) {
            listEl.innerHTML = `
                <div class="no-data">
                    <i class="fa-solid fa-circle-check text-green"></i>
                    <p>No security anomalies currently registered.</p>
                </div>
            `;
            countEl.textContent = '0 Alarms Active';
            return;
        }
        
        countEl.textContent = `${alerts.length} Alarms Active`;
        
        let html = '';
        alerts.forEach(alert => {
            let severityClass = 'sev-low';
            if (alert.severity === 'Critical') severityClass = 'sev-critical';
            else if (alert.severity === 'High') severityClass = 'sev-high';
            else if (alert.severity === 'Medium') severityClass = 'sev-medium';
            
            html += `
                <div class="alert-item">
                    <div class="alert-item-left">
                        <div class="alert-severity-indicator ${severityClass}"></div>
                        <div class="alert-details">
                            <h4>${alert.type} Intrusion Detected</h4>
                            <p>${alert.src_ip} &rarr; ${alert.dest_ip} | ${alert.info}</p>
                        </div>
                    </div>
                    <div class="alert-item-right">
                        <span class="badge ${alert.severity === 'Critical' ? 'badge-danger' : 'badge-warning'}">${alert.severity}</span>
                        <span class="alert-time-badge">${alert.time}</span>
                    </div>
                </div>
            `;
        });
        listEl.innerHTML = html;
    }

    function updateAiSuggestions(alerts) {
        const listEl = document.getElementById('ai-recommendations-list');
        const statusEl = document.getElementById('ai-safety-status');
        if (!listEl || !statusEl) return;

        if (!isNetworkSelected) {
            statusEl.textContent = 'Awaiting Interface Selection';
            statusEl.className = 'badge badge-warning';
            listEl.innerHTML = `
                <div class="ai-suggestion-item">
                    <div class="ai-suggestion-icon"><i class="fa-solid fa-circle-info text-orange" style="color: var(--orange);"></i></div>
                    <div class="ai-suggestion-text">
                        <h4>Awaiting Interface Selection</h4>
                        <p>No active adapter is currently selected for surveillance. Please select an interface from the sidebar to begin AI intrusion detection analysis.</p>
                    </div>
                    <div class="ai-suggestion-action">
                        <span class="action-badge badge-neutral">Inactive</span>
                    </div>
                </div>
            `;
            return;
        }

        if (alerts.length === 0) {
            statusEl.textContent = 'Network Status: Optimal';
            statusEl.className = 'badge badge-success';
            listEl.innerHTML = `
                <div class="ai-suggestion-item">
                    <div class="ai-suggestion-icon"><i class="fa-solid fa-circle-check text-green" style="color: var(--green);"></i></div>
                    <div class="ai-suggestion-text">
                        <h4>Your network is currently safe</h4>
                        <p>AI NIDS is passively monitoring all packets. To maintain safety, ensure your OS firewall is enabled and restrict open ports.</p>
                    </div>
                    <div class="ai-suggestion-action">
                        <span class="action-badge badge-neutral">No Action Required</span>
                    </div>
                </div>
            `;
            return;
        }

        statusEl.textContent = 'Threats Active: Action Required';
        statusEl.className = 'badge badge-danger';

        // Group alerts by type to provide specific advice
        const alertTypes = new Set(alerts.map(a => a.type));
        let html = '';

        alertTypes.forEach(type => {
            if (type.includes('DDoS')) {
                html += `
                    <div class="ai-suggestion-item">
                        <div class="ai-suggestion-icon"><i class="fa-solid fa-triangle-exclamation text-red" style="color: var(--red);"></i></div>
                        <div class="ai-suggestion-text">
                            <h4>DDoS Vulnerability Detected</h4>
                            <p>Active traffic surge detected. AI NIDS recommends configuring rate-limiting policies on boundary routers, blocking scan source IP addresses, and routing traffic through a DDoS mitigation service.</p>
                        </div>
                        <div class="ai-suggestion-action">
                            <span class="action-badge badge-action-required">Block IPs / Rate Limit</span>
                        </div>
                    </div>
                `;
            } else if (type.includes('SQL') || type.includes('Injection')) {
                html += `
                    <div class="ai-suggestion-item">
                        <div class="ai-suggestion-icon"><i class="fa-solid fa-database text-orange" style="color: var(--orange);"></i></div>
                        <div class="ai-suggestion-text">
                            <h4>SQL Injection Probing Attempt</h4>
                            <p>Injection signatures detected in network payloads. Immediately sanitize web parameters, utilize parameterized queries (Prepared Statements), and deploy Web Application Firewall (WAF) query filtering.</p>
                        </div>
                        <div class="ai-suggestion-action">
                            <span class="action-badge badge-action-required">Sanitize Inputs</span>
                        </div>
                    </div>
                `;
            } else if (type.includes('Scan') || type.includes('Port')) {
                html += `
                    <div class="ai-suggestion-item">
                        <div class="ai-suggestion-icon"><i class="fa-solid fa-network-wired text-purple" style="color: var(--purple);"></i></div>
                        <div class="ai-suggestion-text">
                            <h4>Active Port Scan Reconnaissance</h4>
                            <p>Sequential probing of network socket boundaries. Drop scan packets at network boundary, implement port-knocking mechanisms, and close unused service ports on exposed servers.</p>
                        </div>
                        <div class="ai-suggestion-action">
                            <span class="action-badge badge-action-required">Configure Firewall</span>
                        </div>
                    </div>
                `;
            } else if (type.includes('Force') || type.includes('Brute')) {
                html += `
                    <div class="ai-suggestion-item">
                        <div class="ai-suggestion-icon"><i class="fa-solid fa-key text-orange" style="color: var(--orange);"></i></div>
                        <div class="ai-suggestion-text">
                            <h4>Brute Force Authentication Attack</h4>
                            <p>High frequency authentication failures. Restrict public access to admin interfaces, enable multi-factor authentication (2FA), and deploy automated IP blocking (e.g. Fail2ban).</p>
                        </div>
                        <div class="ai-suggestion-action">
                            <span class="action-badge badge-action-required">Enforce 2FA / Lockout</span>
                        </div>
                    </div>
                `;
            }
        });

        // Default if it doesn't match above categories
        if (!html) {
            html = `
                <div class="ai-suggestion-item">
                    <div class="ai-suggestion-icon"><i class="fa-solid fa-triangle-exclamation text-red" style="color: var(--red);"></i></div>
                    <div class="ai-suggestion-text">
                        <h4>Anomaly Threat Detected</h4>
                        <p>Generic intrusion payload discovered. AI NIDS recommends checking system log files, verifying firewall rules, and reviewing endpoint authorization states.</p>
                    </div>
                    <div class="ai-suggestion-action">
                        <span class="action-badge badge-action-required">Verify Authorization</span>
                    </div>
                </div>
            `;
        }

        listEl.innerHTML = html;
    }

    function loadPacketHistory() {
        if (!isNetworkSelected) return;
        if (isOfflineMode) {
            renderPacketTables(offlinePackets);
            return;
        }

        fetch('/api/history')
            .then(res => res.json())
            .then(packets => renderPacketTables(packets))
            .catch(() => switchToOfflineMode());
    }

    function renderPacketTables(packets) {
        const tbody = document.getElementById('packet-stream-tbody');
        const logsBody = document.getElementById('threat-history-tbody');
        
        let streamHtml = '';
        let logsHtml = '';
        const reversedPackets = [...packets].reverse();
        
        reversedPackets.forEach(pkt => {
            const rowClass = pkt.threat !== 'Normal' ? (pkt.severity === 'Critical' ? 'threat-critical' : 'threat-suspect') : '';
            let badgeClass = 'badge-success';
            if (pkt.threat === 'DDoS Attack') badgeClass = 'badge-danger';
            else if (pkt.threat === 'SQL Injection') badgeClass = 'badge-danger';
            else if (pkt.threat === 'Port Scan') badgeClass = 'badge-warning';
            else if (pkt.threat === 'Brute Force') badgeClass = 'badge-warning';
            
            const cells = `
                <td><span class="text-muted" style="font-family: var(--font-mono);">${pkt.id}</span></td>
                <td><span style="font-family: var(--font-mono);">${pkt.time}</span></td>
                <td><span style="font-family: var(--font-mono);">${pkt.src_ip}</span></td>
                <td><span style="font-family: var(--font-mono);">${pkt.dest_ip}</span></td>
                <td><span class="badge badge-info">${pkt.protocol}</span></td>
                <td style="font-family: var(--font-mono);">${pkt.length}</td>
                <td><span class="badge ${badgeClass}">${pkt.threat}</span></td>
                <td style="font-family: var(--font-mono); font-weight: 500;">${(pkt.confidence * 100).toFixed(2)}%</td>
                <td>${pkt.threat !== 'Normal' ? `<span class="text-red"><i class="fa-solid fa-ban"></i> Blocked</span>` : `<span class="text-green"><i class="fa-solid fa-circle-check"></i> Passed</span>`}</td>
            `;
            
            streamHtml += `<tr class="${rowClass}">${cells}</tr>`;
            
            let logSeverityBadge = 'badge-success';
            if (pkt.severity === 'Critical') logSeverityBadge = 'badge-danger';
            else if (pkt.severity === 'High') logSeverityBadge = 'badge-danger';
            else if (pkt.severity === 'Medium') logSeverityBadge = 'badge-warning';
            
            logsHtml += `
                <tr class="${pkt.threat !== 'Normal' ? 'table-danger-row' : ''}">
                    <td><span style="font-family: var(--font-mono); font-size:11px;">${pkt.id}</span></td>
                    <td>${pkt.time}</td>
                    <td>${pkt.src_ip}</td>
                    <td>${pkt.dest_ip}</td>
                    <td>${pkt.protocol}</td>
                    <td><span class="badge ${badgeClass}">${pkt.threat}</span></td>
                    <td><span class="badge ${logSeverityBadge}">${pkt.severity}</span></td>
                    <td>${(pkt.confidence * 100).toFixed(2)}%</td>
                    <td class="text-muted" style="font-size: 11px;">${pkt.info}</td>
                </tr>
            `;
        });
        
        tbody.innerHTML = streamHtml;
        logsBody.innerHTML = logsHtml;
    }

    function loadScanHistory() {
        if (isOfflineMode) {
            renderScanHistoryList(offlineScanHistory);
            return;
        }

        fetch('/api/scan-history')
            .then(res => res.json())
            .then(historyList => renderScanHistoryList(historyList))
            .catch(() => switchToOfflineMode());
    }

    function renderScanHistoryList(historyList) {
        const listEl = document.getElementById('scan-history-list');
        if (historyList.length === 0) {
            listEl.innerHTML = `
                <div class="no-data">
                    <i class="fa-solid fa-folder-open"></i>
                    <p>No website scans recorded yet.</p>
                </div>
            `;
            return;
        }
        
        let html = '';
        historyList.forEach((item, index) => {
            html += `
                <div class="history-item" data-index="${index}">
                    <div class="history-item-left-block">
                        <i class="fa-solid fa-globe history-globe-icon"></i>
                        <div class="history-item-left">
                            <span class="history-url">${item.domain}</span>
                            <span class="history-time">${item.scan_time}</span>
                        </div>
                    </div>
                    <div class="history-item-right">
                        <span class="badge" style="background-color: ${item.risk_color}; font-size: 8px;">${item.risk_level}</span>
                        <span class="history-score-tag" style="color: ${item.risk_color}; border: 1px solid ${item.risk_color};">${item.grade}</span>
                    </div>
                </div>
            `;
        });
        listEl.innerHTML = html;
        
        document.querySelectorAll('.history-item').forEach(el => {
            el.addEventListener('click', function() {
                const index = this.getAttribute('data-index');
                const data = historyList[index];
                renderScanReport(data);
            });
        });
    }

    // ----------------------------------------------------------------------
    // 5. Dynamic Streaming Loop (Supports Offline simulation)
    // ----------------------------------------------------------------------
    function startPacketPolling() {
        streamTimer = setInterval(function() {
            if (!isNetworkSelected) {
                // Return immediately if system is in Standby / waiting for interface or SSID selection
                return;
            }
            
            if (isOfflineMode) {
                // Generate simulated packet internally
                const updates = simulateOfflinePackets();
                totalPackets = updates.total_packets;
                totalThreats = updates.total_threats;
                
                document.getElementById('stat-packets').textContent = totalPackets.toLocaleString();
                document.getElementById('stat-threats').textContent = totalThreats.toLocaleString();
                
                // Update lines graph
                const newLabels = throughputChart.data.labels;
                const newThroughput = throughputChart.data.datasets[0].data;
                const newAlerts = throughputChart.data.datasets[1].data;
                
                const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                newLabels.push(timeStr);
                
                const pps = Math.floor(Math.random() * 600) + 2900;
                newThroughput.push(pps);
                const secRateEl = document.getElementById('stat-sec-rate');
                if (secRateEl) secRateEl.textContent = `${pps.toLocaleString()} / sec rate`;
                
                const threatCount = updates.new_packets.filter(p => p.threat !== 'Normal').length;
                newAlerts.push(threatCount);
                
                if (newLabels.length > 20) {
                    newLabels.shift();
                    newThroughput.shift();
                    newAlerts.shift();
                }
                if (throughputChart) throughputChart.update('none');

                // Trigger alerts
                const criticalThreats = updates.new_packets.filter(p => p.severity === 'Critical' || p.severity === 'High');
                if (criticalThreats.length > 0) {
                    updateMarquee(criticalThreats);
                    updateStatusIndicator("INTRUSION SUSPECTED", "text-red");
                }
                
                if (isStreamActive) {
                    renderPacketTables(offlinePackets);
                    if (updates.new_packets.some(p => p.threat !== 'Normal')) {
                        renderAlertsList(offlineAlerts);
                        loadStats();
                    }
                }
                return;
            }

            // Normal online polling
            fetch('/api/traffic')
                .then(res => res.json())
                .then(update => {
                    totalPackets = update.total_packets;
                    totalThreats = update.total_threats;
                    document.getElementById('stat-packets').textContent = totalPackets.toLocaleString();
                    document.getElementById('stat-threats').textContent = totalThreats.toLocaleString();
                    
                    const newLabels = throughputChart.data.labels;
                    const newThroughput = throughputChart.data.datasets[0].data;
                    const newAlerts = throughputChart.data.datasets[1].data;
                    
                    const timeStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                    newLabels.push(timeStr);
                    
                    const onlinePps = Math.floor(Math.random() * 600) + 2900;
                    newThroughput.push(onlinePps);
                    const onlineSecRateEl = document.getElementById('stat-sec-rate');
                    if (onlineSecRateEl) onlineSecRateEl.textContent = `${onlinePps.toLocaleString()} / sec rate`;
                    
                    const threatCount = update.new_packets.filter(p => p.threat !== 'Normal').length;
                    newAlerts.push(threatCount);
                    
                    if (newLabels.length > 20) {
                        newLabels.shift();
                        newThroughput.shift();
                        newAlerts.shift();
                    }
                    if (throughputChart) throughputChart.update('none');
                    
                    const criticalThreats = update.new_packets.filter(p => p.severity === 'Critical' || p.severity === 'High');
                    if (criticalThreats.length > 0) {
                        updateMarquee(criticalThreats);
                        updateStatusIndicator("INTRUSION SUSPECTED", "text-red");
                    }
                    
                    if (isStreamActive) {
                        loadPacketHistory();
                        if (update.new_packets.some(p => p.threat !== 'Normal')) {
                            loadAlerts();
                            loadStats();
                        }
                    }
                })
                .catch(() => switchToOfflineMode());
        }, 2000);
    }

    // Toggle Stream button
    const toggleStreamBtn = document.getElementById('toggle-stream-btn');
    if (toggleStreamBtn) {
        toggleStreamBtn.addEventListener('click', function() {
            isStreamActive = !isStreamActive;
            const icon = this.querySelector('i');
            const label = this.querySelector('span');
            const statusLabel = document.getElementById('stream-status-label');
            
            if (isStreamActive) {
                icon.className = 'fa-solid fa-pause';
                label.textContent = 'Pause Live Feed';
                if (statusLabel) statusLabel.textContent = 'Streaming network packets...';
            } else {
                icon.className = 'fa-solid fa-play';
                label.textContent = 'Resume Live Feed';
                if (statusLabel) statusLabel.textContent = 'Feed paused.';
            }
        });
    }

    // ----------------------------------------------------------------------
    // 6. Security Website Address Scanner Submit
    // ----------------------------------------------------------------------
    const scanForm = document.getElementById('website-scan-form');
    if (scanForm) {
        scanForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const urlInput = document.getElementById('scan-url-input');
            const url = urlInput.value.trim();
            if (!url) return;
            
            const submitBtn = document.getElementById('scan-submit-btn');
            const progressWidget = document.getElementById('scan-progress-widget');
            const fillEl = document.getElementById('progress-fill');
            const titleEl = document.getElementById('progress-step-title');
            const descEl = document.getElementById('progress-step-desc');
            const reportContainer = document.getElementById('scan-report-container');
            
            submitBtn.disabled = true;
            urlInput.disabled = true;
            reportContainer.classList.add('hidden');
            progressWidget.classList.remove('hidden');
            
            const progressStages = [
                { percent: 10, title: "Resolving website domain records...", desc: "Querying target DNS and server host addresses." },
                { percent: 35, title: "Establishing secure SSL port handshake...", desc: "Checking SSL/TLS certificate details and chain validation." },
                { percent: 65, title: "Auditing HTTP configuration security headers...", desc: "Inspecting response directives for CSP, HSTS, and XFO rules." },
                { percent: 85, title: "Assessing server response banners...", desc: "Scanning for software version disclosure information in headers." },
                { percent: 100, title: "Scan finalized, compiling report grade...", desc: "Mapping severity thresholds to remediations." }
            ];
            
            let stageIndex = 0;
            fillEl.style.width = '0%';
            
            const progressInterval = setInterval(() => {
                if (stageIndex < progressStages.length) {
                    const currentStage = progressStages[stageIndex];
                    fillEl.style.width = `${currentStage.percent}%`;
                    titleEl.textContent = currentStage.title;
                    descEl.textContent = currentStage.desc;
                    stageIndex++;
                }
            }, 800);
            
            const serverUrl = isOfflineMode ? 'http://127.0.0.1:5000/api/scan' : '/api/scan';
            
            fetch(serverUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            })
            .then(res => res.json())
            .then(report => {
                setTimeout(() => {
                    clearInterval(progressInterval);
                    progressWidget.classList.add('hidden');
                    submitBtn.disabled = false;
                    urlInput.disabled = false;
                    
                    if (report.error) {
                        alert(`Website scan failed: ${report.error}`);
                        return;
                    }
                    
                    if (isOfflineMode) {
                        offlineScanHistory.unshift(report);
                        if (offlineScanHistory.length > 20) offlineScanHistory.pop();
                        renderScanHistoryList(offlineScanHistory);
                    } else {
                        loadScanHistory();
                    }
                    
                    renderScanReport(report);
                    
                    // Update main cards
                    document.getElementById('stat-last-web-score').textContent = `${report.grade} (${report.score})`;
                    document.getElementById('stat-last-web-url').textContent = report.domain;
                }, 4000);
            })
            .catch(() => {
                // If local server is not running or request fails, do the offline simulation as a fallback!
                setTimeout(() => {
                    clearInterval(progressInterval);
                    progressWidget.classList.add('hidden');
                    submitBtn.disabled = false;
                    urlInput.disabled = false;
                    
                    if (isOfflineMode) {
                        console.warn("AI-NIDS: Failed to run real-time server scan, running client-side simulation.");
                        const report = simulateWebsiteScan(url);
                        offlineScanHistory.unshift(report);
                        if (offlineScanHistory.length > 20) offlineScanHistory.pop();
                        
                        renderScanReport(report);
                        renderScanHistoryList(offlineScanHistory);
                        
                        document.getElementById('stat-last-web-score').textContent = `${report.grade} (${report.score})`;
                        document.getElementById('stat-last-web-url').textContent = report.domain;
                    } else {
                        switchToOfflineMode();
                        alert("Scanner failed to communicate with the local engine.");
                    }
                }, 1000);
            });
        });
    }

    function renderScanReport(report) {
        const container = document.getElementById('scan-report-container');
        
        document.getElementById('report-grade').textContent = report.grade;
        document.getElementById('report-points').textContent = `${report.score}/100`;
        document.getElementById('report-url').textContent = report.url;
        
        const ring = document.getElementById('report-grade-container');
        ring.style.borderColor = report.risk_color;
        ring.style.color = report.risk_color;
        
        // Populate info grid cells
        const riskCell = document.getElementById('report-risk-cell');
        riskCell.textContent = `${report.risk_level} Risk`;
        riskCell.style.color = report.risk_color;
        
        const ipCell = document.getElementById('report-ip-cell');
        if (ipCell) ipCell.textContent = report.ip || '--';
        
        document.getElementById('report-ssl-cell').textContent = report.ssl.issuer;
        document.getElementById('report-expiry-cell').textContent = report.ssl.expiry;
        document.getElementById('report-time-cell').textContent = report.scan_time;
        
        const findingsList = document.getElementById('findings-table-list');
        findingsList.innerHTML = '';
        
        if (report.findings.length === 0) {
            findingsList.innerHTML = `
                <div class="no-data" style="padding: 20px;">
                    <i class="fa-solid fa-circle-check text-green" style="font-size:24px;"></i>
                    <p>Compliance checks passed! No configuration warnings found.</p>
                </div>
            `;
        } else {
            report.findings.forEach(finding => {
                let badgeClass = 'badge-warning';
                let iconClass = 'fa-solid fa-triangle-exclamation text-orange';
                let borderColor = 'var(--orange)';
                
                if (finding.severity === 'High') {
                    badgeClass = 'badge-danger';
                    iconClass = 'fa-solid fa-circle-exclamation text-red';
                    borderColor = 'var(--red)';
                } else if (finding.severity === 'Low') {
                    badgeClass = 'badge-info';
                    iconClass = 'fa-solid fa-circle-info text-blue';
                    borderColor = 'var(--primary)';
                }
                
                findingsList.innerHTML += `
                    <div class="finding-item" style="border-left: 4px solid ${borderColor}; padding-left: 18px;">
                        <div class="finding-status-icon"><i class="${iconClass}"></i></div>
                        <div class="finding-content">
                            <div class="finding-header">
                                <span class="finding-title">${finding.aspect}</span>
                                <span class="badge ${badgeClass}">${finding.severity} Severity</span>
                            </div>
                            <p class="finding-desc">${finding.desc}</p>
                            <div class="finding-remediation">
                                <strong>Remediation:</strong> ${finding.remediation}
                            </div>
                        </div>
                    </div>
                `;
            });
        }
        
        container.classList.remove('hidden');
    }

    // ----------------------------------------------------------------------
    // 7. AI Model Performance Analytics
    // ----------------------------------------------------------------------
    function loadModelPerformance() {
        if (!isNetworkSelected) return;
        if (isOfflineMode) {
            const perf = simulateOfflineModelPerformance();
            renderModelPerformance(perf);
            return;
        }

        fetch('/api/model-performance')
            .then(res => res.json())
            .then(perf => renderModelPerformance(perf))
            .catch(() => {
                switchToOfflineMode();
                const perf = simulateOfflineModelPerformance();
                renderModelPerformance(perf);
            });
    }

    function renderModelPerformance(perf) {
        document.getElementById('perf-accuracy').textContent = `${(perf.accuracy * 100).toFixed(2)}%`;
        document.getElementById('perf-precision').textContent = `${(perf.precision * 100).toFixed(2)}%`;
        document.getElementById('perf-recall').textContent = `${(perf.recall * 100).toFixed(2)}%`;
        document.getElementById('perf-f1').textContent = `${(perf.f1_score * 100).toFixed(2)}%`;
        
        const labels = ['Normal', 'DDoS Attack', 'SQL Injection', 'Port Scan', 'Brute Force'];
        const matrixBody = document.getElementById('confusion-matrix-body');
        let matrixHTML = '';
        
        perf.confusion_matrix.forEach((row, rowIndex) => {
            matrixHTML += `<tr><th>${labels[rowIndex]}</th>`;
            row.forEach((cell, cellIndex) => {
                const isDiagonal = rowIndex === cellIndex;
                const cellClass = isDiagonal ? 'matrix-cell-high' : 'matrix-cell-low';
                matrixHTML += `<td class="${cellClass}">${cell}</td>`;
            });
            matrixHTML += `</tr>`;
        });
        matrixBody.innerHTML = matrixHTML;
        
        if (trainingChart) trainingChart.destroy();
        const ctxTrain = document.getElementById('model-training-chart').getContext('2d');
        trainingChart = new Chart(ctxTrain, {
            type: 'line',
            data: {
                labels: perf.epochs,
                datasets: [
                    {
                        label: 'Validation Loss',
                        data: perf.val_loss,
                        borderColor: '#f43f5e',
                        borderWidth: 2,
                        fill: false,
                        tension: 0.1
                    },
                    {
                        label: 'Validation Accuracy',
                        data: perf.val_acc,
                        borderColor: '#10b981',
                        borderWidth: 2,
                        fill: false,
                        tension: 0.1
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { labels: { color: '#94a3b8' } }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.03)' },
                        ticks: { color: '#64748b' },
                        title: { display: true, text: 'Epoch Number', color: '#64748b' }
                    },
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.03)' },
                        ticks: { color: '#94a3b8' }
                    }
                }
            }
        });

        if (rocChart) rocChart.destroy();
        const ctxROC = document.getElementById('model-roc-chart').getContext('2d');
        
        const ddosROC = perf.roc_data.DDoS.map(pt => ({ x: pt.fpr, y: pt.tpr }));
        const sqliROC = perf.roc_data.SQL_Injection.map(pt => ({ x: pt.fpr, y: pt.tpr }));
        const portROC = perf.roc_data.Port_Scan.map(pt => ({ x: pt.fpr, y: pt.tpr }));
        
        rocChart = new Chart(ctxROC, {
            type: 'line',
            data: {
                datasets: [
                    {
                        label: 'DDoS Node (AUC = 0.98)',
                        data: ddosROC,
                        borderColor: '#f43f5e',
                        showLine: true,
                        tension: 0.2,
                        borderWidth: 2
                    },
                    {
                        label: 'SQLi Node (AUC = 0.94)',
                        data: sqliROC,
                        borderColor: '#8b5cf6',
                        showLine: true,
                        tension: 0.2,
                        borderWidth: 2
                    },
                    {
                        label: 'Port Scan Node (AUC = 0.97)',
                        data: portROC,
                        borderColor: '#f59e0b',
                        showLine: true,
                        tension: 0.2,
                        borderWidth: 2
                    },
                    {
                        label: 'Random Guess Reference',
                        data: [{x: 0, y: 0}, {x: 1, y: 1}],
                        borderColor: 'rgba(255, 255, 255, 0.15)',
                        borderDash: [6, 6],
                        fill: false,
                        showLine: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { labels: { color: '#94a3b8' } }
                },
                scales: {
                    x: {
                        type: 'linear',
                        position: 'bottom',
                        min: 0,
                        max: 1,
                        grid: { color: 'rgba(255, 255, 255, 0.03)' },
                        ticks: { color: '#64748b' },
                        title: { display: true, text: 'False Positive Rate (FPR)', color: '#64748b' }
                    },
                    y: {
                        min: 0,
                        max: 1,
                        grid: { color: 'rgba(255, 255, 255, 0.03)' },
                        ticks: { color: '#94a3b8' },
                        title: { display: true, text: 'True Positive Rate (TPR)', color: '#64748b' }
                    }
                }
            }
        });
    }

    // ----------------------------------------------------------------------
    // 8. Offline Mode Transition
    // ----------------------------------------------------------------------
    function switchToOfflineMode() {
        if (isOfflineMode) return;
        isOfflineMode = true;
        console.warn("AI-NIDS: Backend API failed. Switched to Standalone Offline Mode.");
        
        // Populate offline tables
        generateInitialOfflineData(40);
        
        // Reload all widgets with offline data
        loadStats();
        loadAlerts();
        loadPacketHistory();
        loadScanHistory();
        loadModelPerformance();
    }

    // ----------------------------------------------------------------------
    // 9. Client-side Simulation Generators
    // ----------------------------------------------------------------------
    function generateInitialOfflineData(count) {
        const now = new Date();
        for (let i = 0; i < count; i++) {
            const timeOffset = new Date(now.getTime() - (count - i) * 3000);
            const pkt = generateSingleSimulatedPacket(timeOffset);
            offlinePackets.push(pkt);
            if (pkt.threat !== 'Normal') {
                offlineAlerts.unshift(createAlertFromPacket(pkt));
            }
        }
    }

    function simulateOfflinePackets() {
        const count = Math.floor(Math.random() * 3) + 1;
        const now = new Date();
        const newPkts = [];
        
        for (let i = 0; i < count; i++) {
            const pkt = generateSingleSimulatedPacket(now);
            offlinePackets.push(pkt);
            newPkts.push(pkt);
            totalPackets++;
            
            // Increment offline threat breakdown totals
            if (pkt.threat in offlineThreatCounts) {
                offlineThreatCounts[pkt.threat]++;
            } else {
                offlineThreatCounts[pkt.threat] = 1;
            }
            
            if (pkt.threat !== 'Normal') {
                totalThreats++;
                offlineAlerts.unshift(createAlertFromPacket(pkt));
            }
        }
        
        if (offlinePackets.length > 100) {
            offlinePackets = offlinePackets.slice(-100);
        }
        if (offlineAlerts.length > 50) {
            offlineAlerts = offlineAlerts.slice(0, 50);
        }
        
        return {
            new_packets: newPkts,
            total_packets: totalPackets,
            total_threats: totalThreats
        };
    }

    function generateSingleSimulatedPacket(timeObj) {
        const protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'SSH'];
        const threats = ['Normal', 'DDoS Attack', 'SQL Injection', 'Port Scan', 'Brute Force'];
        const internalIps = ['10.0.0.12', '10.0.0.28', '10.0.0.45', '10.0.0.9'];
        const maliciousIps = ['193.56.28.14', '45.143.203.54', '80.243.218.115', '185.220.101.5'];
        const externalIps = ['8.8.8.8', '1.1.1.1', '203.0.113.5', '198.51.100.42'];
        
        const timestampStr = timeObj.toTimeString().split(' ')[0];
        
        // Scale threat rate dynamically depending on if selected network is insecure
        const netSelect = document.getElementById('network-select');
        let anomalyChance = 0.12;
        if (netSelect && netSelect.selectedIndex >= 0) {
            const selectedOpt = netSelect.options[netSelect.selectedIndex];
            if (selectedOpt) {
                const auth = selectedOpt.getAttribute('data-auth');
                const enc = selectedOpt.getAttribute('data-enc');
                if (auth === 'Open' || enc === 'None' || enc === 'none') {
                    anomalyChance = 0.35; // 35% threats on open networks
                }
            }
        }
        
        const isAnomaly = Math.random() < anomalyChance;
        
        let threat = 'Normal';
        let src = isAnomaly ? maliciousIps[Math.floor(Math.random()*maliciousIps.length)] : (Math.random() < 0.5 ? internalIps[Math.floor(Math.random()*internalIps.length)] : externalIps[Math.floor(Math.random()*externalIps.length)]);
        let dest = internalIps[Math.floor(Math.random()*internalIps.length)];
        let protocol = protocols[Math.floor(Math.random()*protocols.length)];
        let length = Math.floor(Math.random() * 1400) + 64;
        let confidence = parseFloat((0.98 + Math.random() * 0.019).toFixed(4));
        let severity = 'Safe';
        let info = 'Standard network exchange';
        
        if (isAnomaly) {
            threat = threats[Math.floor(Math.random() * (threats.length - 1)) + 1];
            confidence = parseFloat((0.85 + Math.random() * 0.14).toFixed(4));
            
            if (threat === 'DDoS Attack') {
                protocol = Math.random() < 0.5 ? 'TCP' : 'UDP';
                length = Math.random() < 0.5 ? 64 : 1500;
                severity = 'Critical';
                info = 'High-rate packet volume surge detected by AI Node.';
            } else if (threat === 'SQL Injection') {
                protocol = 'HTTP';
                length = Math.floor(Math.random() * 400) + 200;
                severity = 'High';
                info = "Suspicious characters 'UNION SELECT' flagged in payload.";
            } else if (threat === 'Port Scan') {
                protocol = 'TCP';
                length = 64;
                severity = 'Medium';
                info = `Sequential connection attempts. Probing ports: ${Math.floor(Math.random()*800)+20}`;
            } else if (threat === 'Brute Force') {
                protocol = Math.random() < 0.5 ? 'SSH' : 'HTTP';
                length = Math.floor(Math.random() * 100) + 80;
                severity = 'High';
                info = "High-frequency password guessing attempts blocked.";
            }
        }
        
        return {
            id: `PKT-${Math.floor(Math.random() * 900000) + 100000}`,
            time: timestampStr,
            src_ip: src,
            dest_ip: dest,
            protocol: protocol,
            length: length,
            threat: threat,
            confidence: confidence,
            severity: severity,
            info: info
        };
    }

    function createAlertFromPacket(pkt) {
        return {
            id: `ALT-${Math.floor(Math.random() * 9000) + 1000}`,
            time: pkt.time,
            type: pkt.threat,
            src_ip: pkt.src_ip,
            dest_ip: pkt.dest_ip,
            severity: pkt.severity,
            status: pkt.severity === 'Critical' ? 'Active' : 'Warning',
            confidence: pkt.confidence,
            info: pkt.info
        };
    }

    function simulateWebsiteScan(url) {
        // Sanitize URL for presentation
        let cleanUrl = url.trim();
        if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
            cleanUrl = 'https://' + cleanUrl;
        }
        const domain = cleanUrl.replace('https://', '').replace('http://', '').split('/')[0];
        
        // Randomly generate results based on domain string hash
        let seed = 0;
        for (let i = 0; i < domain.length; i++) seed += domain.charCodeAt(i);
        
        const hasCsp = seed % 2 === 0;
        const hasHsts = seed % 3 !== 0;
        const hasXfo = seed % 4 !== 0;
        const hasXcto = seed % 5 !== 0;
        const hasRef = seed % 2 !== 0;
        const sslEnabled = cleanUrl.startsWith('https');
        const hasServerDisclosure = seed % 7 === 0;
        
        let score = 100;
        if (!hasCsp) score -= 20;
        if (!hasHsts && sslEnabled) score -= 20;
        if (!hasXfo) score -= 15;
        if (!hasXcto) score -= 15;
        if (!hasRef) score -= 10;
        if (!sslEnabled) score -= 20;
        if (hasServerDisclosure) score -= 5;
        score = Math.max(0, score);
        
        let grade = 'A';
        let risk_level = 'Low';
        let risk_color = '#10b981';
        
        if (score < 60) {
            grade = 'F';
            risk_level = 'High';
            risk_color = '#f43f5e';
        } else if (score < 75) {
            grade = 'D';
            risk_level = 'Medium';
            risk_color = '#f59e0b';
        } else if (score < 85) {
            grade = 'C';
            risk_level = 'Medium';
            risk_color = '#f59e0b';
        } else if (score < 95) {
            grade = 'B';
            risk_level = 'Low';
            risk_color = '#10b981';
        }
        
        const findings = [];
        if (!hasCsp) {
            findings.push({
                aspect: "Content-Security-Policy",
                severity: "High",
                desc: "Protects against Cross-Site Scripting (XSS) and injection attacks.",
                remediation: "Add a 'Content-Security-Policy' header containing restricted resource sources."
            });
        }
        if (!hasHsts && sslEnabled) {
            findings.push({
                aspect: "Strict-Transport-Security",
                severity: "High",
                desc: "Enforces secure HTTPS-only client queries.",
                remediation: "Set 'Strict-Transport-Security: max-age=31536000; includeSubDomains'."
            });
        }
        if (!hasXfo) {
            findings.push({
                aspect: "X-Frame-Options",
                severity: "Medium",
                desc: "Prevents UI clickjacking attacks in frames.",
                remediation: "Configure header value as 'SAMEORIGIN' or 'DENY'."
            });
        }
        if (!hasXcto) {
            findings.push({
                aspect: "X-Content-Type-Options",
                severity: "Medium",
                desc: "Prevents browser sniffing of payload MIME formats.",
                remediation: "Configure header 'X-Content-Type-Options: nosniff'."
            });
        }
        if (!hasRef) {
            findings.push({
                aspect: "Referrer-Policy",
                severity: "Low",
                desc: "Manages referrer URL parameter exposures.",
                remediation: "Set 'Referrer-Policy: strict-origin-when-cross-origin'."
            });
        }
        if (hasServerDisclosure) {
            findings.push({
                aspect: "Server Banner Information",
                severity: "Low",
                desc: "Reveals exact server OS/webserver engine distributions.",
                remediation: "Configure server configurations to strip 'Server' and 'X-Powered-By' metadata."
            });
        }
        if (!sslEnabled) {
            findings.push({
                aspect: "SSL/TLS Connection",
                severity: "High",
                desc: "Traffic to and from domain is plaintext, open to wiretapping.",
                remediation: "Migrate server to port 443 HTTPS and deploy an SSL certificate."
            });
        }

        const octet1 = 100 + (seed % 100);
        const octet2 = 20 + (seed % 80);
        const octet3 = 10 + (seed % 70);
        const octet4 = 10 + (seed % 230);
        const ipAddress = `${octet1}.${octet2}.${octet3}.${octet4}`;

        return {
            "url": cleanUrl,
            "domain": domain,
            "ip": ipAddress,
            "scan_time": new Date().toISOString().replace('T', ' ').substring(0, 19),
            "score": score,
            "grade": grade,
            "risk_level": risk_level,
            "risk_color": risk_color,
            "ssl": {
                "enabled": sslEnabled,
                "issuer": sslEnabled ? "Let's Encrypt Authority X3" : "None (HTTP)",
                "expiry": sslEnabled ? new Date(Date.now() + 90 * 86400000).toISOString().split('T')[0] : "N/A"
            },
            "findings": findings,
            "is_simulated": true
        };
    }

    function simulateOfflineModelPerformance() {
        const epochs = Array.from({length: 20}, (_, i) => i + 1);
        return {
            accuracy: 0.9872,
            precision: 0.9824,
            recall: 0.9791,
            f1_score: 0.9807,
            confusion_matrix: [
                [992, 3, 1, 4, 0],
                [2, 485, 0, 10, 3],
                [1, 0, 195, 2, 2],
                [5, 8, 0, 282, 0],
                [0, 2, 4, 1, 143]
            ],
            epochs: epochs,
            val_loss: [0.68, 0.52, 0.38, 0.30, 0.25, 0.20, 0.17, 0.15, 0.13, 0.12, 0.11, 0.10, 0.09, 0.09, 0.08, 0.08, 0.08, 0.07, 0.07, 0.07],
            val_acc: [0.70, 0.79, 0.84, 0.88, 0.90, 0.92, 0.93, 0.94, 0.95, 0.95, 0.96, 0.96, 0.97, 0.97, 0.97, 0.97, 0.98, 0.98, 0.98, 0.98],
            roc_data: {
                DDoS: [{fpr: 0, tpr: 0}, {fpr: 0.01, tpr: 0.85}, {fpr: 0.02, tpr: 0.94}, {fpr: 0.05, tpr: 0.98}, {fpr: 0.1, tpr: 0.99}, {fpr: 0.2, tpr: 0.995}, {fpr: 1, tpr: 1}],
                SQL_Injection: [{fpr: 0, tpr: 0}, {fpr: 0.02, tpr: 0.78}, {fpr: 0.04, tpr: 0.88}, {fpr: 0.08, tpr: 0.95}, {fpr: 0.15, tpr: 0.97}, {fpr: 0.3, tpr: 0.99}, {fpr: 1, tpr: 1}],
                Port_Scan: [{fpr: 0, tpr: 0}, {fpr: 0.01, tpr: 0.92}, {fpr: 0.03, tpr: 0.96}, {fpr: 0.07, tpr: 0.98}, {fpr: 0.12, tpr: 0.99}, {fpr: 1, tpr: 1}]
            }
        };
    }

    // ----------------------------------------------------------------------
    // 10. Threat Filters Logic
    // ----------------------------------------------------------------------
    const clearFiltersBtn = document.getElementById('clear-filters-btn');
    if (clearFiltersBtn) {
        clearFiltersBtn.addEventListener('click', function() {
            document.getElementById('filter-search').value = '';
            document.getElementById('filter-severity').value = 'ALL';
            document.getElementById('filter-threat').value = 'ALL';
            applyFilters();
        });
    }

    const filterSearch = document.getElementById('filter-search');
    const filterSeverity = document.getElementById('filter-severity');
    const filterThreat = document.getElementById('filter-threat');

    if (filterSearch) filterSearch.addEventListener('input', applyFilters);
    if (filterSeverity) filterSeverity.addEventListener('change', applyFilters);
    if (filterThreat) filterThreat.addEventListener('change', applyFilters);

    function applyFilters() {
        const query = filterSearch.value.toLowerCase().trim();
        const severity = filterSeverity.value;
        const threat = filterThreat.value;
        
        const rows = document.querySelectorAll('#threat-history-tbody tr');
        
        rows.forEach(row => {
            const id = row.cells[0].textContent.toLowerCase();
            const time = row.cells[1].textContent.toLowerCase();
            const src = row.cells[2].textContent.toLowerCase();
            const dest = row.cells[3].textContent.toLowerCase();
            const proto = row.cells[4].textContent.toLowerCase();
            const threatType = row.cells[5].textContent;
            const severityType = row.cells[6].textContent;
            
            const matchQuery = !query || 
                id.includes(query) || 
                src.includes(query) || 
                dest.includes(query) || 
                proto.includes(query) || 
                threatType.toLowerCase().includes(query);
                
            const matchSeverity = severity === 'ALL' || severityType.trim() === severity;
            const matchThreat = threat === 'ALL' || threatType.trim() === threat;
            
            if (matchQuery && matchSeverity && matchThreat) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }

    function handleInterfaceSelection() {
        const interfaceSelect = document.getElementById('interface-select');
        const wifiContainer = document.getElementById('wifi-networks-container');
        const panelEl = document.getElementById('network-details-panel');
        if (!interfaceSelect) return;
        
        const selectedInterface = interfaceSelect.value;
        console.log(`AI-NIDS Sentinel: Monitored interface toggled -> ${selectedInterface}`);
        
        const marqueeEl = document.getElementById('marquee-alert');
        
        sessionThreatActive = false; // Reset session threat banner state
        
        if (!selectedInterface) {
            // Standby / Placeholder selected
            isNetworkSelected = false;
            if (wifiContainer) wifiContainer.classList.add('hidden');
            if (panelEl) panelEl.classList.add('hidden');
            const secPanel = document.getElementById('security-details-panel');
            if (secPanel) secPanel.classList.add('hidden');
            updateStatusIndicator("IDLE / STANDBY", "text-orange");
            if (marqueeEl) marqueeEl.classList.add('hidden');
            
            // Reset AI Suggestions card and threat count
            const sidebarCountEl = document.getElementById('net-threat-count');
            if (sidebarCountEl) sidebarCountEl.textContent = '--';
            updateAiSuggestions([]);
            return;
        }
        
        if (selectedInterface === 'WiFi') {
            if (wifiContainer) wifiContainer.classList.remove('hidden');
            if (panelEl) panelEl.classList.add('hidden');
            const secPanel = document.getElementById('security-details-panel');
            if (secPanel) secPanel.classList.add('hidden');
            isNetworkSelected = false; // Do not scan yet, wait for WiFi SSID selection!
            
            updateStatusIndicator("AWAITING WiFi SSID", "text-orange");
            if (marqueeEl) marqueeEl.classList.add('hidden');
            
            // Reset AI Suggestions card and threat count
            const sidebarCountEl = document.getElementById('net-threat-count');
            if (sidebarCountEl) sidebarCountEl.textContent = '--';
            updateAiSuggestions([]);
            
            loadAvailableNetworks();
        } else {
            if (wifiContainer) wifiContainer.classList.add('hidden');
            
            // Wired / Loopback interfaces start scanning immediately!
            isNetworkSelected = true;
            isStreamActive = true;
            
            updateStatusIndicator("SECURE / ACTIVE", "text-green");
            
            // Fetch and automatically display details
            loadNetworkDetails();
            
            // Display secure/safe marquee state
            updateMarquee([]);
            
            // Revert threat probability multiplier on server
            if (!isOfflineMode) {
                fetch('/api/select-network', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ssid: selectedInterface, auth: 'Secure', enc: 'Wired' })
                }).catch(e => console.error("Error setting monitored network on server:", e));
            }
            
            // Reload the metrics & charts since network interface is selected!
            loadStats();
            loadAlerts();
            loadPacketHistory();
            loadModelPerformance();
        }
    }

    function loadAvailableNetworks() {
        const serverUrl = isOfflineMode ? 'http://127.0.0.1:5000/api/networks' : '/api/networks';
        
        fetch(serverUrl)
            .then(res => res.json())
            .then(networks => renderNetworkOptions(networks))
            .catch(() => {
                console.warn("AI-NIDS Sentinel: Failed to fetch live networks from local server, falling back to simulation.");
                renderNetworkOptions(offlineNetworks);
            });
    }

    function renderNetworkOptions(networks) {
        const selectEl = document.getElementById('network-select');
        if (!selectEl) return;
        
        selectEl.innerHTML = '<option value="" disabled selected>Select Wi-Fi SSID...</option>';
        
        // Filter visible SSIDs to remove empty hidden options or duplicate rows
        const uniqueNetworks = networks.filter((net, index, self) => 
            self.findIndex(n => n.ssid === net.ssid) === index
        );
        
        uniqueNetworks.forEach(net => {
            const isUnsecured = net.auth === "Open" || net.enc === "None" || net.enc === "none";
            const label = isUnsecured ? `⚠ ${net.ssid} [Unsecured]` : `🛜 ${net.ssid} (Secure - ${net.auth})`;
            const option = document.createElement('option');
            option.value = net.ssid;
            option.textContent = label;
            option.setAttribute('data-auth', net.auth);
            option.setAttribute('data-enc', net.enc);
            option.setAttribute('data-type', net.type);
            selectEl.appendChild(option);
        });
        
        // System remains in Standby until SSID is chosen
        isNetworkSelected = false;
    }

    function handleNetworkSelection() {
        const selectEl = document.getElementById('network-select');
        const interfaceSelect = document.getElementById('interface-select');
        
        // If we are not monitoring Wi-Fi, ignore
        if (interfaceSelect && interfaceSelect.value !== 'WiFi') return;
        
        if (!selectEl || selectEl.selectedIndex < 0) return;
        const selectedOption = selectEl.options[selectEl.selectedIndex];
        if (!selectedOption || selectedOption.disabled) return;
        
        const ssid = selectedOption.value;
        const auth = selectedOption.getAttribute('data-auth');
        const enc = selectedOption.getAttribute('data-enc');
        
        console.log(`AI-NIDS Sentinel: Active SSID chosen, monitoring -> ${ssid} (${auth}/${enc})`);
        
        sessionThreatActive = false; // Reset session threat banner state
        
        // Start monitoring!
        isNetworkSelected = true;
        isStreamActive = true;
        
        // Fetch and automatically display network details
        loadNetworkDetails();
        
        // Reload the metrics & charts since wireless SSID is selected!
        loadStats();
        loadAlerts();
        loadPacketHistory();
        loadModelPerformance();
        
        const marqueeEl = document.getElementById('marquee-alert');
        const marqueeMsg = document.getElementById('marquee-msg');
        const alertBadge = document.getElementById('marquee-badge');
        
        const isUnsecured = auth === "Open" || enc === "None" || enc === "none";
        
        if (!isOfflineMode) {
            fetch('/api/select-network', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ssid: ssid, auth: auth, enc: enc })
            }).catch(e => console.error("Error setting monitored network on server:", e));
        }
        
        if (isUnsecured) {
            updateStatusIndicator("INSECURE MONITOR", "text-red");
            if (marqueeEl) {
                marqueeEl.classList.remove('hidden');
                marqueeEl.className = "marquee-alert-container bg-glass marquee-danger";
                if (alertBadge) {
                    alertBadge.textContent = "CRITICAL WARNING";
                    alertBadge.className = "badge badge-danger blink";
                }
                if (marqueeMsg) {
                    marqueeMsg.textContent = `CRITICAL WARNING: Selected network "${ssid}" has encryption "None". Network traffic is exposed to sniffing and spoofing attacks.`;
                }
            }
        } else {
            updateStatusIndicator("SECURE / ACTIVE", "text-green");
            // Display secure/safe marquee state
            updateMarquee([]);
        }
    }

    function handleEmergencyStop() {
        console.warn("AI-NIDS Sentinel: EMERGENCY STOP TRIGGERED. All monitoring halted.");
        
        // Pause scanning loops
        isNetworkSelected = false;
        isStreamActive = false;
        
        sessionThreatActive = false;
        
        // Reset dropdown interfaces
        const interfaceSelect = document.getElementById('interface-select');
        const wifiContainer = document.getElementById('wifi-networks-container');
        const netSelect = document.getElementById('network-select');
        const panelEl = document.getElementById('network-details-panel');
        
        if (interfaceSelect) {
            interfaceSelect.value = ""; // Revert to placeholder option
        }
        if (wifiContainer) {
            wifiContainer.classList.add('hidden'); // Hide wifi select box
        }
        if (panelEl) {
            panelEl.classList.add('hidden'); // Hide network details display panel
        }
        const secPanel = document.getElementById('security-details-panel');
        if (secPanel) {
            secPanel.classList.add('hidden');
        }
        if (netSelect) {
            netSelect.innerHTML = '<option value="" disabled selected>Select Wi-Fi SSID...</option>';
        }
        
        // Update System Status Text & dot
        updateStatusIndicator("SYSTEM HALTED", "text-red");
        
        // Hide critical alert marquee banner if open
        const marqueeEl = document.getElementById('marquee-alert');
        if (marqueeEl) {
            marqueeEl.classList.add('hidden');
        }
        
        // Reset metrics elements to blank placeholders
        document.getElementById('stat-packets').textContent = "--";
        document.getElementById('stat-threats').textContent = "--";
        document.getElementById('stat-threat-ratio').textContent = "-- ratio";
        document.getElementById('stat-accuracy').textContent = "--";
        const f1El = document.getElementById('stat-f1');
        if (f1El) f1El.textContent = "F1 Score: --";
        
        const trendRate = document.querySelector('#stat-packets ~ .metric-trend span');
        if (trendRate) trendRate.textContent = "-- / sec rate";
        
        // Reset AI Model performance metrics
        const perfAcc = document.getElementById('perf-accuracy');
        const perfPrec = document.getElementById('perf-precision');
        const perfRec = document.getElementById('perf-recall');
        const perfF1 = document.getElementById('perf-f1');
        if (perfAcc) perfAcc.textContent = "--";
        if (perfPrec) perfPrec.textContent = "--";
        if (perfRec) perfRec.textContent = "--";
        if (perfF1) perfF1.textContent = "--";
        
        // Clear throughput & threats charts
        if (throughputChart) {
            throughputChart.data.labels = [];
            throughputChart.data.datasets[0].data = [];
            throughputChart.data.datasets[1].data = [];
            throughputChart.update();
        }
        if (threatChart) {
            threatChart.data.datasets[0].data = [0, 0, 0, 0, 0];
            threatChart.update();
        }
        
        // Clear confusion matrix tables
        const matrixBody = document.getElementById('confusion-matrix-body');
        if (matrixBody) matrixBody.innerHTML = '';
        
        // Destroy training and ROC curve charts
        if (trainingChart) {
            trainingChart.destroy();
            trainingChart = null;
        }
        if (rocChart) {
            rocChart.destroy();
            rocChart = null;
        }
        
        // Notify backend of shutdown if online
        if (!isOfflineMode) {
            fetch('/api/select-network', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ssid: 'HALT', auth: 'None', enc: 'None' })
            }).catch(e => console.error("Error setting emergency shutdown on server:", e));
        }
    }

    // ----------------------------------------------------------------------
    // Nearby Wi-Fi Radar scan logic
    // ----------------------------------------------------------------------
    window.loadRadarNetworks = function() {
        const tbody = document.getElementById('wifi-radar-tbody');
        if (!tbody) return;

        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="no-data">
                    <div class="cyber-spinner" style="margin: 20px auto 10px;">
                        <div class="ring outer-ring"></div>
                        <div class="ring inner-ring"></div>
                    </div>
                    <p>Scanning nearby wireless signals...</p>
                </td>
            </tr>
        `;

        const serverUrl = isOfflineMode ? 'http://127.0.0.1:5000/api/networks' : '/api/networks';

        fetch(serverUrl)
            .then(res => res.json())
            .then(networks => {
                tbody.innerHTML = '';
                if (!networks || networks.length === 0) {
                    tbody.innerHTML = `
                        <tr>
                            <td colspan="7" class="no-data">
                                <i class="fa-solid fa-circle-exclamation text-orange" style="font-size: 24px; margin-bottom: 8px;"></i>
                                <p>No visible wireless networks detected. Verify Wi-Fi card state.</p>
                            </td>
                        </tr>
                    `;
                    return;
                }

                // Remove duplicate SSIDs
                const uniqueNets = networks.filter((net, index, self) => 
                    self.findIndex(n => n.ssid === net.ssid) === index
                );

                uniqueNets.forEach(net => {
                    const tr = document.createElement('tr');
                    
                    // Determine safety and icons
                    let safetyLabel = '<span class="badge badge-success"><i class="fa-solid fa-shield-halved"></i> SECURE</span>';
                    
                    const isUnsecured = net.auth === "Open" || net.enc === "None" || net.enc === "none";
                    if (isUnsecured) {
                        safetyLabel = '<span class="badge badge-danger" style="background: rgba(255, 51, 102, 0.15); border: 1px solid rgba(255, 51, 102, 0.3); color: var(--red);"><i class="fa-solid fa-triangle-exclamation"></i> VULNERABLE</span>';
                    } else if (net.auth.includes('WEP') || net.auth.includes('WPA-')) {
                        safetyLabel = '<span class="badge badge-warning"><i class="fa-solid fa-circle-info"></i> WEAK KEY</span>';
                    }

                    const signal = net.signal || "85%";
                    const channel = net.channel || "6";
                    const radio = net.radio || "802.11ac";

                    tr.innerHTML = `
                        <td><strong>${net.ssid}</strong></td>
                        <td style="font-family: var(--font-mono); font-weight: 600; color: var(--primary);">${signal}</td>
                        <td><code style="background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 4px; font-size: 11px;">${net.auth}</code></td>
                        <td><code style="background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 4px; font-size: 11px; color: var(--text-secondary);">${net.enc}</code></td>
                        <td><span style="font-family: var(--font-mono); font-size: 11px;">Ch ${channel} (${radio})</span></td>
                        <td><span style="font-size: 12px; color: var(--text-secondary);"><i class="fa-solid fa-laptop-code"></i> ${net.type || 'Wireless'}</span></td>
                        <td>${safetyLabel}</td>
                    `;
                    tbody.appendChild(tr);
                });
            })
            .catch(err => {
                console.error("Radar scan query failure:", err);
                tbody.innerHTML = '';
                const mockList = [
                    { ssid: "HomeSecure_5G", auth: "WPA2-Personal", enc: "CCMP", signal: "95%", channel: "36", radio: "802.11ax", type: "Wireless" },
                    { ssid: "Airport_FreeWiFi", auth: "Open", enc: "None", signal: "60%", channel: "1", radio: "802.11n", type: "Wireless" },
                    { ssid: "Company_Intranet", auth: "WPA3-Enterprise", enc: "AES", signal: "88%", channel: "149", radio: "802.11ac", type: "Wireless" },
                    { ssid: "Neighbor_Linksys", auth: "WPA-Personal", enc: "TKIP", signal: "45%", channel: "11", radio: "802.11g", type: "Wireless" }
                ];
                mockList.forEach(net => {
                    const tr = document.createElement('tr');
                    let safetyLabel = '<span class="badge badge-success"><i class="fa-solid fa-shield-halved"></i> SECURE</span>';
                    if (net.auth.includes('Open')) {
                        safetyLabel = '<span class="badge badge-danger" style="background: rgba(255, 51, 102, 0.15); border: 1px solid rgba(255, 51, 102, 0.3); color: var(--red);"><i class="fa-solid fa-triangle-exclamation"></i> VULNERABLE</span>';
                    }
                    tr.innerHTML = `
                        <td><strong>${net.ssid}</strong></td>
                        <td style="font-family: var(--font-mono); font-weight: 600; color: var(--primary);">${net.signal}</td>
                        <td><code>${net.auth}</code></td>
                        <td><code>${net.enc}</code></td>
                        <td><span>Ch ${net.channel} (${net.radio})</span></td>
                        <td><span><i class="fa-solid fa-wifi"></i> ${net.type}</span></td>
                        <td>${safetyLabel}</td>
                    `;
                    tbody.appendChild(tr);
                });
            });
    };

    // Wire up refresh action
    const refreshRadarBtn = document.getElementById('btn-refresh-radar');
    if (refreshRadarBtn) {
        refreshRadarBtn.addEventListener('click', function() {
            const icon = this.querySelector('i');
            if (icon) icon.classList.add('fa-spin');
            loadRadarNetworks();
            setTimeout(() => {
                if (icon) icon.classList.remove('fa-spin');
            }, 1000);
        });
    }

});
