# -*- coding: utf-8 -*-
#
# AutoSQLi Proxy Scanner - v4 (Responsive UI + Advanced SQLi engine)
#
# Features:
# - Error-based SQLi detection with multi-payload fuzzing
# - DB-specific signatures: MySQL, PostgreSQL, MSSQL, Oracle
# - WAF detection (ModSecurity, Cloudflare, etc.)
# - Skips static files, junk content-types, huge responses
# - Param / Cookie / Header injection
# - “Only in scope” scanning mode
# - Target substring filter
# - Deduplication for scans + findings
# - Color-coded results: SQL, 500, WAF
# - Double click → send injected request to Repeater
# - Built-in request/response message viewers
# - Fully responsive UI (auto-resizes like Proxy tab)
#

from burp import IBurpExtender, IProxyListener, ITab
from java.lang import Runnable, Thread, Object
from javax.swing import (
    JPanel, JTable, JScrollPane, JButton,
    JCheckBox, JLabel, JTextField, JSplitPane, BoxLayout
)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import Color, BorderLayout
from java.awt.event import MouseAdapter
import re


# ================================================
# Non-editable table model
# ================================================
class NonEditableModel(DefaultTableModel):
    def isCellEditable(self, row, col):
        return False


# ================================================
# Main Burp Extension
# ================================================
class BurpExtender(IBurpExtender, IProxyListener, ITab):

    SQL_ERRORS = [
        "you have an error in your sql syntax",
        "mysql server version",
        "warning: mysql",
        "warning: mysqli",
        "unclosed quotation mark",
        "unterminated quoted string",
        "syntax error",
        "ora-", "oracle error",
        "pg_query", "psql:",
        "database error",
        "sqlstate",
        "odbc sql server driver",
        "odbc driver"
    ]

    WAF_PATTERNS = [
        "access denied", "request blocked", "forbidden",
        "mod_security", "modsecurity",
        "cloudflare", "incapsula",
        "blocked by", "web application firewall"
    ]

    STATIC_EXT = re.compile(
        r".*\.(jpg|jpeg|png|gif|svg|css|js|ico|woff|woff2|ttf|bmp|eot|mp4|mp3|avi|mov|pdf)$",
        re.IGNORECASE
    )

    LENGTH_DIFF_THRESHOLD = 30
    MAX_BODY_SIZE = 1024 * 1024

    ERROR_PAYLOADS_STRING = ["'", "\"", "')", "\")", "'))", "\"))"]
    ERROR_PAYLOADS_NUMERIC = ["'", ")", "))"]

    FILTER_ALL = "ALL"
    FILTER_HTTP = "HTTP"
    FILTER_SQL = "SQL"
    FILTER_WAF = "WAF"

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Auto SQLi Proxy Scanner (v4)")
        callbacks.registerProxyListener(self)

        self.stdout = callbacks.getStdout()

        self.allFindings = []
        self.filteredFindings = []
        self.findingKeys = set()
        self.scannedUrls = set()
        self.scannedCount = 0
        self.findingCount = 0
        self.currentFilter = self.FILTER_ALL

        self.initUI()
        callbacks.addSuiteTab(self)

        self.stdout.write("[+] AutoSQLi v4 loaded with responsive UI\n")

    # --------------------------------------------
    # Build GUI (Responsive)
    # --------------------------------------------
    def initUI(self):
        self.panel = JPanel(BorderLayout())

        # === Top Controls Row ===
        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.X_AXIS))

        self.chkEnable = JCheckBox("Enable", True)
        self.chkParams = JCheckBox("Params", True)
        self.chkCookies = JCheckBox("Cookies", True)
        self.chkHeaders = JCheckBox("Headers", True)
        self.chkScope = JCheckBox("Only in-scope", False)

        top.add(self.chkEnable)
        top.add(self.chkParams)
        top.add(self.chkCookies)
        top.add(self.chkHeaders)
        top.add(self.chkScope)

        top.add(JLabel("   Target: "))
        self.txtTarget = JTextField("", 12)
        top.add(self.txtTarget)

        self.btnAll = JButton("All", actionPerformed=self.onFilterAll)
        self.btnHTTP = JButton("HTTP 5xx", actionPerformed=self.onFilterHTTP)
        self.btnSQL = JButton("SQL errors", actionPerformed=self.onFilterSQL)
        self.btnWAF = JButton("WAF", actionPerformed=self.onFilterWAF)
        self.btnClearTable = JButton("Clear Table", actionPerformed=self.onClearTable)
        self.btnClearAll = JButton("Clear All", actionPerformed=self.onClearAll)

        top.add(self.btnAll)
        top.add(self.btnHTTP)
        top.add(self.btnSQL)
        top.add(self.btnWAF)
        top.add(self.btnClearTable)
        top.add(self.btnClearAll)

        self.lblStats = JLabel("Scanned: 0 | Findings: 0")
        top.add(self.lblStats)

        self.panel.add(top, BorderLayout.NORTH)

        # === Table ===
        columns = ["URL", "Kind", "Name", "Detail"]
        self.tableModel = NonEditableModel(columns, 0)
        self.table = JTable(self.tableModel)
        self.table.setDefaultEditor(Object, None)
        self.table.setDefaultRenderer(Object, SeverityColorRenderer())
        self.table.addMouseListener(TableListener(self))

        tablePane = JScrollPane(self.table)

        # === Request / Response viewers ===
        self.reqViewer = self.callbacks.createMessageEditor(None, False)
        self.respViewer = self.callbacks.createMessageEditor(None, False)

        reqPane = self.reqViewer.getComponent()
        respPane = self.respViewer.getComponent()

        # Horizontal split (req | resp)
        bottomSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqPane, respPane)
        bottomSplit.setResizeWeight(0.5)

        # Vertical split (table | responses)
        mainSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, tablePane, bottomSplit)
        mainSplit.setResizeWeight(0.55)

        self.panel.add(mainSplit, BorderLayout.CENTER)

    # --------------------------------------------
    # Tab
    # --------------------------------------------
    def getTabCaption(self):
        return "AutoSQLi"

    def getUiComponent(self):
        return self.panel

    # --------------------------------------------
    # Filter Handlers
    # --------------------------------------------
    def onFilterAll(self, e): self.currentFilter = self.FILTER_ALL; self.refreshTable()
    def onFilterHTTP(self, e): self.currentFilter = self.FILTER_HTTP; self.refreshTable()
    def onFilterSQL(self, e): self.currentFilter = self.FILTER_SQL; self.refreshTable()
    def onFilterWAF(self, e): self.currentFilter = self.FILTER_WAF; self.refreshTable()

    def onClearTable(self, e):
        self.tableModel.setRowCount(0)
        self.filteredFindings = []

    def onClearAll(self, e):
        self.allFindings = []
        self.filteredFindings = []
        self.findingKeys = set()
        self.scannedUrls = set()
        self.scannedCount = 0
        self.findingCount = 0
        self.updateStats()
        self.tableModel.setRowCount(0)

    def refreshTable(self):
        self.tableModel.setRowCount(0)
        self.filteredFindings = []

        for f in self.allFindings:
            if not self.matchesFilter(f):
                continue
            row = [f["url"], f["kind"], f["name"], f["detail"]]
            self.tableModel.addRow(row)
            self.filteredFindings.append(f)

    def matchesFilter(self, f):
        d = f["detail"].lower()
        if self.currentFilter == self.FILTER_ALL:
            return True
        if self.currentFilter == self.FILTER_HTTP:
            return d.startswith("http 5")
        if self.currentFilter == self.FILTER_SQL:
            return "sql error" in d
        if self.currentFilter == self.FILTER_WAF:
            return d.startswith("waf")
        return True

    def updateStats(self):
        self.lblStats.setText(
            "Scanned: %d | Findings: %d" %
            (self.scannedCount, self.findingCount)
        )

    # --------------------------------------------
    # Add Finding
    # --------------------------------------------
    def addFinding(self, url, kind, name, detail, msg):
        key = url + "|" + kind + "|" + name + "|" + detail
        if key in self.findingKeys:
            return

        self.findingKeys.add(key)
        self.allFindings.append({
            "url": url,
            "kind": kind,
            "name": name,
            "detail": detail,
            "message": msg
        })

        self.findingCount += 1
        self.updateStats()
        self.refreshTable()

    # --------------------------------------------
    # Viewer updates
    # --------------------------------------------
    def showFinding(self, index):
        if index < 0 or index >= len(self.filteredFindings):
            return
        msg = self.filteredFindings[index]["message"]
        if msg:
            self.reqViewer.setMessage(msg.getRequest(), True)
            self.respViewer.setMessage(msg.getResponse(), False)

    def sendToRepeater(self, index):
        if index < 0 or index >= len(self.filteredFindings):
            return

        f = self.filteredFindings[index]
        msg = f["message"]
        if msg is None:
            return

        service = msg.getHttpService()
        self.callbacks.sendToRepeater(
            service.getHost(),
            service.getPort(),
            service.getProtocol().lower() == "https",
            msg.getRequest(),
            "AutoSQLi: %s %s" % (f["kind"], f["name"])
        )

    # --------------------------------------------
    # Proxy Intercept Handler
    # --------------------------------------------
    def processProxyMessage(self, isReq, message):
        if not isReq or not self.chkEnable.isSelected():
            return

        base = message.getMessageInfo()
        analyzed = self.helpers.analyzeRequest(base)
        urlObj = analyzed.getUrl()
        url = str(urlObj)

        # Target substring filter
        target = self.txtTarget.getText().strip().lower()
        if target and target not in url.lower():
            return

        # Only in-scope?
        if self.chkScope.isSelected():
            if not self.callbacks.isInScope(urlObj):
                return

        if self.STATIC_EXT.match(url):
            return

        if url in self.scannedUrls:
            return

        self.scannedUrls.add(url)
        self.scannedCount += 1
        self.updateStats()

        Thread(SQLiWorker(self, base)).start()


# ================================================
# Table Color Renderer
# ================================================
class SeverityColorRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, table, value, sel, focus, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, sel, focus, row, col
        )
        detail = str(table.getModel().getValueAt(row, 3)).lower()

        # Colors
        if detail.startswith("http 5"):
            c.setBackground(Color(255, 190, 190))  # red
        elif detail.startswith("waf"):
            c.setBackground(Color(255, 220, 180))  # orange
        elif "sql error" in detail:
            c.setBackground(Color(255, 210, 210))  # pink
        else:
            c.setBackground(Color.white)

        return c


# ================================================
# Table Mouse Listener
# ================================================
class TableListener(MouseAdapter):
    def __init__(self, ext):
        self.ext = ext

    def mouseClicked(self, event):
        table = event.getSource()
        row = table.getSelectedRow()

        if row >= 0:
            self.ext.showFinding(row)

        if event.getClickCount() == 2 and row >= 0:
            self.ext.sendToRepeater(row)


# ================================================
# Worker Thread (SQLi testing logic)
# ================================================
class SQLiWorker(Runnable):

    def __init__(self, ext, base):
        self.ext = ext
        self.base = base
        self.helpers = ext.helpers
        self.callbacks = ext.callbacks
        self.stdout = ext.stdout

    def run(self):
        try:
            ar = self.helpers.analyzeRequest(self.base)

            if self.ext.chkParams.isSelected():
                for p in ar.getParameters():
                    self.test_param(p)

            if self.ext.chkCookies.isSelected():
                self.test_cookie(ar)

            if self.ext.chkHeaders.isSelected():
                self.test_headers(ar)

        except Exception as e:
            self.stdout.write("ERROR in worker: %s\n" % e)

    # ---- Helpers ----
    def bodyLen(self, resp):
        info = self.helpers.analyzeResponse(resp.getResponse())
        body = resp.getResponse()[info.getBodyOffset():]
        return len(body)

    def contentType(self, resp):
        try:
            info = self.helpers.analyzeResponse(resp.getResponse())
            for h in info.getHeaders():
                h = h.lower()
                if h.startswith("content-type:"):
                    return h
        except:
            pass
        return ""

    def useful(self, ct):
        if not ct:
            return True
        if "image/" in ct: return False
        if "text/css" in ct: return False
        if "javascript" in ct: return False
        if "font/" in ct: return False
        return True

    # ---- PARAM TEST ----
    def test_param(self, p):
        service = self.base.getHttpService()

        baseReq = self.base.getRequest()
        baseResp = self.callbacks.makeHttpRequest(service, baseReq)
        baseLen = self.bodyLen(baseResp)

        if baseLen > self.ext.MAX_BODY_SIZE:
            return
        if not self.useful(self.contentType(baseResp)):
            return

        url = str(self.helpers.analyzeRequest(self.base).getUrl())

        val = p.getValue()
        payloads = self.ext.ERROR_PAYLOADS_NUMERIC if val.isdigit() else self.ext.ERROR_PAYLOADS_STRING

        for s in payloads:
            inj = self.helpers.buildParameter(p.getName(), val + s, p.getType())
            req = self.helpers.updateParameter(baseReq, inj)
            resp = self.callbacks.makeHttpRequest(service, req)
            self.check("param", p.getName(), url, baseLen, resp)

    # ---- COOKIE TEST ----
    def test_cookie(self, ar):
        service = self.base.getHttpService()
        body = self.base.getRequest()[ar.getBodyOffset():]

        baseReq = self.helpers.buildHttpMessage(ar.getHeaders(), body)
        baseResp = self.callbacks.makeHttpRequest(service, baseReq)
        baseLen = self.bodyLen(baseResp)

        if baseLen > self.ext.MAX_BODY_SIZE:
            return
        if not self.useful(self.contentType(baseResp)):
            return

        url = str(self.helpers.analyzeRequest(self.base).getUrl())

        new_headers = []
        modified = False
        for h in ar.getHeaders():
            if h.lower().startswith("cookie:"):
                new_headers.append(h + "'")
                modified = True
            else:
                new_headers.append(h)

        if modified:
            injReq = self.helpers.buildHttpMessage(new_headers, body)
            resp = self.callbacks.makeHttpRequest(service, injReq)
            self.check("cookie", "cookie", url, baseLen, resp)

    # ---- HEADER TEST ----
    def test_headers(self, ar):
        service = self.base.getHttpService()
        body = self.base.getRequest()[ar.getBodyOffset():]

        baseReq = self.helpers.buildHttpMessage(ar.getHeaders(), body)
        baseResp = self.callbacks.makeHttpRequest(service, baseReq)
        baseLen = self.bodyLen(baseResp)

        if baseLen > self.ext.MAX_BODY_SIZE:
            return
        if not self.useful(self.contentType(baseResp)):
            return

        url = str(self.helpers.analyzeRequest(self.base).getUrl())

        for i, h in enumerate(ar.getHeaders()):
            name = h.split(":", 1)[0].strip().lower()
            if name in ["host", "content-length"]:
                continue

            new_headers = list(ar.getHeaders())
            new_headers[i] = h + "'"

            injReq = self.helpers.buildHttpMessage(new_headers, body)
            resp = self.callbacks.makeHttpRequest(service, injReq)
            self.check("header", name, url, baseLen, resp)

    # ---- CHECK LOGIC ----
    def check(self, kind, name, url, baseLen, resp):
        info = self.helpers.analyzeResponse(resp.getResponse())
        body = resp.getResponse()[info.getBodyOffset():]
        text = self.helpers.bytesToString(body).lower()
        newLen = len(body)
        diff = abs(newLen - baseLen)

        if diff < self.ext.LENGTH_DIFF_THRESHOLD:
            return

        status = info.getStatusCode()

        # WAF
        for w in self.ext.WAF_PATTERNS:
            if w in text:
                self.ext.addFinding(url, kind, name, "WAF / %s (diff=%d)" % (w, diff), resp)
                return
        if status in (401, 403, 406):
            self.ext.addFinding(url, kind, name, "WAF / HTTP %d (diff=%d)" % (status, diff), resp)
            return

        # HTTP 500+
        if status >= 500:
            self.ext.addFinding(url, kind, name, "HTTP %d (diff=%d)" % (status, diff), resp)
            return

        # SQL errors
        for e in BurpExtender.SQL_ERRORS:
            if e in text:
                self.ext.addFinding(url, kind, name, "SQL error: %s (diff=%d)" % (e, diff), resp)
                return
