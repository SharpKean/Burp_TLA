package burp;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import javax.swing.*;

import ui.Config;
import ui.MainUI;

public class BurpExtender implements IBurpExtender, ITab, IContextMenuFactory, IHttpListener {
    public static IBurpExtenderCallbacks callbacks;
    private PrintWriter stdout;
    private MainUI mainUI;
    private final ExecutorService executor = Executors.newFixedThreadPool(4);

    private final Set<String> domainUrls = ConcurrentHashMap.newKeySet();
    private final Set<String> routeUrls = ConcurrentHashMap.newKeySet();

    List<String> payloads = Arrays.asList("aaaaa''", "aaaaa\"\"", "aaaaa%27%27", "aaaaa%22%22");

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName("TLA Watcher");
        this.stdout = new PrintWriter(callbacks.getStdout(), true);

        this.stdout.println("===============================");
        this.stdout.println("TLA Watcher V1.3 (Refactored) Loaded Successfully!!!!\n");
        this.stdout.println("Project URL: https://github.com/SharpKean/Brup_TLA");
        this.stdout.println("Author: SharpKean");
        this.stdout.println("===============================");

        this.mainUI = new MainUI();
        callbacks.customizeUiComponent(this.mainUI.root);
        callbacks.addSuiteTab(this);
        callbacks.registerContextMenuFactory(this);
        callbacks.registerHttpListener(this);
    }


    private int getGlobalThreadNum() {
        try {
            String threadStr = Config.getDBFile("thread_num");
            if (threadStr != null && !threadStr.trim().isEmpty()) {
                return Integer.parseInt(threadStr.trim());
            }
        } catch (Exception e) {
            stdout.println("[!] Failed to parse thread_num, using default 4");
        }
        return 4;
    }

    private String getGlobalFilterUrls() {
        String filter = Config.getDBFile("filter_url");
        return filter != null ? filter : "";
    }

    private boolean isDomainFiltered(String host) {
        if (host == null) return false;
        String globalFilter = getGlobalFilterUrls();
        if (globalFilter.isEmpty()) return false;

        String key;
        int dotCount = host.split("\\.").length - 1;
        if (dotCount <= 1) {
            key = host.replaceAll("^(.*?\\d*:?\\d*\\/\\/)?([^:\\/]*).*$", "$2");
        } else {
            key = host.replaceAll("^(.*?\\.)?([^:\\/]*).*$", "$2");
        }
        return globalFilter.contains(key);
    }

    @Override
    public String getTabCaption() {
        return "TLA Watcher";
    }

    @Override
    public Component getUiComponent() {
        return this.mainUI.root;
    }

    public static IMessageEditor createMessageEditor(boolean isRequest) {
        return callbacks.createMessageEditor(null, isRequest);
    }

    // ========== HTTP Listener ==========
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (toolFlag != IBurpExtenderCallbacks.TOOL_PROXY) {
            return;
        }

        IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(messageInfo);
        String host = requestInfo.getUrl().getHost();

        if (isDomainFiltered(host)) {
            return;
        }

        if (!messageIsRequest) {
            String xssScan = Config.getDBFile("xss_enable");
            if ("true".equals(xssScan)) {
                executor.submit(() -> {
                    try {
                        IExtensionHelpers helpers = callbacks.getHelpers();
                        IResponseInfo responseInfo = helpers.analyzeResponse(messageInfo.getResponse());
                        int statusCode = responseInfo.getStatusCode();
                        if (statusCode == 404) return;

                        boolean containsTextHtml = false;
                        for (String header : responseInfo.getHeaders()) {
                            if (header != null && header.toLowerCase().startsWith("content-type:") &&
                                    header.toLowerCase().contains("text/html")) {
                                containsTextHtml = true;
                                break;
                            }
                        }
                        if (!containsTextHtml) return;

                        byte[] responseBodyBytes = messageInfo.getResponse();
                        int bodyOffset = responseInfo.getBodyOffset();
                        byte[] bodyBytes = Arrays.copyOfRange(responseBodyBytes, bodyOffset, responseBodyBytes.length);
                        String responseBody = new String(bodyBytes, StandardCharsets.UTF_8);

                        List<IParameter> parameters = requestInfo.getParameters();
                        for (IParameter param : parameters) {
                            if (param.getType() == IParameter.PARAM_COOKIE) continue;
                            if (param.getValue() != null && param.getValue().length() > 150) continue;

                            String decodedValue = URLDecoder.decode(param.getValue(), StandardCharsets.UTF_8.name());
                            if (decodedValue != null && !decodedValue.trim().isEmpty() && responseBody.contains(decodedValue)) {
                                final IParameter finalParam = param;
                                final String finalUrl = requestInfo.getUrl().toString();
                                final String finalMethod = requestInfo.getMethod();
                                sendXssTestRequests(messageInfo, finalParam, finalUrl, finalMethod);
                            }
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });
            }
        }

        if (messageIsRequest) {
            int typeScanTemp = 1;
            try {
                String typeScanStr = Config.getDBFile("type_scan");
                typeScanTemp = Integer.parseInt(typeScanStr != null ? typeScanStr.trim() : "1");
            } catch (Exception ignored) {
            }
            final int typeScan = typeScanTemp;
            if (typeScan == 3) return;

            Thread scanThread = new Thread(() -> {
                performDirectoryScan(messageInfo, requestInfo, typeScan);
            });
            scanThread.start();
        }
    }

    private void performDirectoryScan(IHttpRequestResponse messageInfo, IRequestInfo requestInfo, int typeScan) {
        String dicsStr = mainUI.getRightPanel().getFileContentList().toString()
                .replace("[", "").replace("]", "");
        if (dicsStr.trim().isEmpty()) return;

        String[] dictionary = dicsStr.split(",");
        String urlString = requestInfo.getUrl().toString();
        String[] parts = urlString.split("\\?", 2);
        String path = parts[0];
        String[] pathParts = path.split("/");
        if (pathParts.length < 3) return;

        String protocol = pathParts[0];
        String domain = protocol + "//" + pathParts[2];

        int threadNum = getGlobalThreadNum();
        List<CompletableFuture<Void>> futures = new ArrayList<>();

        for (int c = 0; c < threadNum; c++) {
            CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                if (typeScan == 2) {
                    String currentPath = domain;
                    for (int i = 3; i < pathParts.length; i++) {
                        if (routeUrls.add(currentPath)) {
                            for (String word : dictionary) {
                                String trimmed = word.trim();
                                if (!trimmed.isEmpty()) {
                                    sendDirectoryRequest(messageInfo, requestInfo, currentPath + trimmed);
                                }
                            }
                        }
                        currentPath += "/" + pathParts[i];
                    }
                } else {
                    if (domainUrls.add(domain)) {
                        for (String word : dictionary) {
                            String trimmed = word.trim();
                            if (!trimmed.isEmpty()) {
                                sendDirectoryRequest(messageInfo, requestInfo, domain + trimmed);
                            }
                        }
                    }
                }
            }, executor);
            futures.add(future);
        }
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();
    }

    private void sendDirectoryRequest(IHttpRequestResponse originalMessage, IRequestInfo originalRequestInfo, String targetUrl) {
        try {
            IExtensionHelpers helpers = callbacks.getHelpers();
            List<String> headers = new ArrayList<>(originalRequestInfo.getHeaders());
            if (!headers.isEmpty()) {
                String firstLine = headers.get(0);
                int firstSpace = firstLine.indexOf(' ');
                int secondSpace = firstLine.indexOf(' ', firstSpace + 1);
                if (firstSpace != -1 && secondSpace != -1) {
                    String method = firstLine.substring(0, firstSpace);
                    String version = firstLine.substring(secondSpace + 1);
                    headers.set(0, method + " " + targetUrl + " " + version);
                }
            }

            byte[] body = Arrays.copyOfRange(
                    originalMessage.getRequest(),
                    originalRequestInfo.getBodyOffset(),
                    originalMessage.getRequest().length
            );

            byte[] newRequest = helpers.buildHttpMessage(headers, body);
            IHttpRequestResponse resp = callbacks.makeHttpRequest(originalMessage.getHttpService(), newRequest);

            if (resp == null || resp.getResponse() == null) return;

            IResponseInfo respInfo = helpers.analyzeResponse(resp.getResponse());
            short code = respInfo.getStatusCode();
            int len = resp.getResponse().length;

            if (code == 200 || code == 403 || (code >= 300 && code < 400)) {
                mainUI.getRightDownPanel().addResult(targetUrl, String.valueOf(code), len);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void sendXssTestRequests(IHttpRequestResponse originalRequestResponse, IParameter param, String xss_url, String xss_method) {
        class XssTestResult {
            final List<String> payloads = new ArrayList<>();
            final List<String> encodedValues = new ArrayList<>();
            final List<byte[]> requests = new ArrayList<>();
            final List<Integer> statusCodes = new ArrayList<>();
            final List<Integer> bodyLengths = new ArrayList<>();
            final AtomicInteger completedCount = new AtomicInteger(0);
            final AtomicInteger hitCount = new AtomicInteger(0);
        }

        XssTestResult resultGroup = new XssTestResult();
        resultGroup.payloads.addAll(payloads);

        for (String payload : payloads) {
            CompletableFuture.runAsync(() -> {
                try {
                    byte[] originalRequestBytes = originalRequestResponse.getRequest();
                    IExtensionHelpers helpers = callbacks.getHelpers();
                    IParameter newParam = helpers.buildParameter(param.getName(), payload, param.getType());
                    byte[] modifiedRequestBytes = helpers.updateParameter(originalRequestBytes, newParam);
                    IHttpRequestResponse testResp = callbacks.makeHttpRequest(
                            originalRequestResponse.getHttpService(),
                            modifiedRequestBytes
                    );

                    if (testResp.getResponse() == null) return;
                    IResponseInfo respInfo = helpers.analyzeResponse(testResp.getResponse());
                    int bodyOffset = respInfo.getBodyOffset();
                    byte[] bodyBytes = Arrays.copyOfRange(testResp.getResponse(), bodyOffset, testResp.getResponse().length);
                    String responseBody = new String(bodyBytes, StandardCharsets.UTF_8);
                    String decodedPayload = URLDecoder.decode(payload, StandardCharsets.UTF_8.name());

                    boolean isHit = decodedPayload != null && !decodedPayload.trim().isEmpty() && responseBody.contains(decodedPayload);

                    synchronized (resultGroup) {
                        if (isHit) {
                            resultGroup.hitCount.incrementAndGet();
                            resultGroup.encodedValues.add(param.getName() + "=" + payload);
                            resultGroup.requests.add(modifiedRequestBytes);
                            resultGroup.statusCodes.add((int) respInfo.getStatusCode());
                            resultGroup.bodyLengths.add(bodyBytes.length);
                        }

                        int completed = resultGroup.completedCount.incrementAndGet();
                        if (completed == payloads.size() && resultGroup.hitCount.get() > 0) {
                            double rate = ((double) resultGroup.hitCount.get() / payloads.size()) * 100;
                            String vulnName = String.format("存在XSS漏洞(%.0f%%)", rate);
                            Random rand = new Random();
                            int idx = rand.nextInt(resultGroup.hitCount.get());

                            mainUI.getRightDownPanel().addBugResult(
                                    vulnName,
                                    resultGroup.encodedValues.get(idx),
                                    xss_url,
                                    xss_method,
                                    String.valueOf(resultGroup.statusCodes.get(idx)),
                                    resultGroup.bodyLengths.get(idx),
                                    resultGroup.requests.get(idx)
                            );
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }, executor);
        }
    }
    @Override
    public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
        JMenuItem menuItem = new JMenuItem("Save TLA Watcher");
        menuItem.addActionListener(e -> {
            IHttpRequestResponse[] messages = invocation.getSelectedMessages();
            if (messages == null || messages.length == 0) return;

            IHttpRequestResponse msg = messages[0];
            IRequestInfo reqInfo = callbacks.getHelpers().analyzeRequest(msg);
            URL urlObj = reqInfo.getUrl();
            String url = urlObj.getProtocol() + "://" + urlObj.getHost();
            int port = urlObj.getPort();
            if (port == -1) port = urlObj.getDefaultPort();
            String method = reqInfo.getMethod();
            String route = urlObj.getFile();
            String remarks = JOptionPane.showInputDialog(null, "请输入注释信息", "备忘录", JOptionPane.PLAIN_MESSAGE);
            String request = new String(msg.getRequest(), StandardCharsets.UTF_8);
            String response = msg.getResponse() != null ?
                    new String(msg.getResponse(), StandardCharsets.UTF_8) : "";

            mainUI.insertDataToDatabase(url, port, method, route, request, response, remarks);
        });
        return Collections.singletonList(menuItem);
    }
}