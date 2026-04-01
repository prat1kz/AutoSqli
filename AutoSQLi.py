# -*- coding: utf-8 -*-
# AutoSQLi - burp proxy sqli scanner
# scans params, cookies, headers for error-based sqli + waf detection
# double click any finding -> sends to repeater

from burp import IBurpExtender, IProxyListener, ITab
from java.lang import Runnable, Thread, Object
from javax.swing import (JPanel, JTable, JScrollPane, JButton,
    JCheckBox, JLabel, JTextField, JSplitPane, BoxLayout)
from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
from java.awt import Color, BorderLayout
from java.awt.event import MouseAdapter
import re

SQL_ERRORS = [
    "you have an error in your sql syntax", "mysql server version",
    "warning: mysql", "warning: mysqli", "unclosed quotation mark",
    "unterminated quoted string", "syntax error", "ora-", "oracle error",
    "pg_query", "psql:", "database error", "sqlstate",
    "odbc sql server driver", "odbc driver"
]

WAF_SIGNS = [
    "access denied", "request blocked", "forbidden",
    "mod_security", "modsecurity", "cloudflare", "incapsula",
    "blocked by", "web application firewall"
]

STATIC_RE = re.compile(
    r".*\.(jpg|jpeg|png|gif|svg|css|js|ico|woff|woff2|ttf|bmp|eot|mp4|mp3|avi|mov|pdf)$",
    re.IGNORECASE
)

STR_PAYLOADS  = ["'", '"', "')", '")', "'))", '"))']
NUM_PAYLOADS  = ["'", ")", "))"]
MAX_BODY      = 1024 * 1024
LEN_THRESHOLD = 30


class _Model(DefaultTableModel):
    def isCellEditable(self, r, c): return False


class BurpExtender(IBurpExtender, IProxyListener, ITab):

    def registerExtenderCallbacks(self, cb):
        self.cb      = cb
        self.hlp     = cb.getHelpers()
        self.out     = cb.getStdout()
        cb.setExtensionName("AutoSQLi")
        cb.registerProxyListener(self)

        self.findings     = []
        self.shown        = []
        self.keys         = set()
        self.seen_urls    = set()
        self.scan_count   = 0
        self.hit_count    = 0
        self.active_filter = "ALL"

        self._build_ui()
        cb.addSuiteTab(self)
        self.out.write("[+] AutoSQLi loaded\n")

    def _build_ui(self):
        self.panel = JPanel(BorderLayout())

        top = JPanel()
        top.setLayout(BoxLayout(top, BoxLayout.X_AXIS))

        self.chk_on      = JCheckBox("Enable",       True)
        self.chk_params  = JCheckBox("Params",        True)
        self.chk_cookies = JCheckBox("Cookies",       True)
        self.chk_headers = JCheckBox("Headers",       True)
        self.chk_scope   = JCheckBox("In-scope only", False)

        for w in [self.chk_on, self.chk_params, self.chk_cookies,
                  self.chk_headers, self.chk_scope]:
            top.add(w)

        top.add(JLabel("  Target:"))
        self.txt_target = JTextField("", 12)
        top.add(self.txt_target)

        for label, fn in [("All",       self._f_all),
                          ("HTTP 5xx",  self._f_http),
                          ("SQL",       self._f_sql),
                          ("WAF",       self._f_waf),
                          ("Clear View",self._clear_view),
                          ("Clear All", self._clear_all)]:
            top.add(JButton(label, actionPerformed=fn))

        self.lbl_stats = JLabel("  scanned:0  hits:0")
        top.add(self.lbl_stats)
        self.panel.add(top, BorderLayout.NORTH)

        self.model = _Model(["URL", "Kind", "Param", "Detail"], 0)
        self.table = JTable(self.model)
        self.table.setDefaultEditor(Object, None)
        self.table.setDefaultRenderer(Object, _ColorRenderer())
        self.table.addMouseListener(_ClickHandler(self))

        self.req_view  = self.cb.createMessageEditor(None, False)
        self.resp_view = self.cb.createMessageEditor(None, False)

        bot = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                         self.req_view.getComponent(),
                         self.resp_view.getComponent())
        bot.setResizeWeight(0.5)

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(self.table), bot)
        split.setResizeWeight(0.55)
        self.panel.add(split, BorderLayout.CENTER)

    # tab interface
    def getTabCaption(self):  return "AutoSQLi"
    def getUiComponent(self): return self.panel

    # filter buttons
    def _f_all(self,  e): self.active_filter = "ALL";  self._refresh()
    def _f_http(self, e): self.active_filter = "HTTP"; self._refresh()
    def _f_sql(self,  e): self.active_filter = "SQL";  self._refresh()
    def _f_waf(self,  e): self.active_filter = "WAF";  self._refresh()

    def _clear_view(self, e):
        self.model.setRowCount(0)
        self.shown = []

    def _clear_all(self, e):
        self.findings   = []
        self.shown      = []
        self.keys       = set()
        self.seen_urls  = set()
        self.scan_count = 0
        self.hit_count  = 0
        self.model.setRowCount(0)
        self._upd_stats()

    def _refresh(self):
        self.model.setRowCount(0)
        self.shown = []
        for f in self.findings:
            if not self._matches(f): continue
            self.model.addRow([f["url"], f["kind"], f["name"], f["detail"]])
            self.shown.append(f)

    def _matches(self, f):
        d = f["detail"].lower()
        if self.active_filter == "ALL":  return True
        if self.active_filter == "HTTP": return d.startswith("http 5")
        if self.active_filter == "SQL":  return "sql error" in d
        if self.active_filter == "WAF":  return d.startswith("waf")
        return True

    def _upd_stats(self):
        self.lbl_stats.setText("  scanned:%d  hits:%d" % (self.scan_count, self.hit_count))

    def add_finding(self, url, kind, name, detail, msg):
        k = "%s|%s|%s|%s" % (url, kind, name, detail)
        if k in self.keys: return
        self.keys.add(k)
        self.findings.append({"url": url, "kind": kind, "name": name,
                               "detail": detail, "message": msg})
        self.hit_count += 1
        self._upd_stats()
        self._refresh()

    def show_row(self, idx):
        if 0 <= idx < len(self.shown):
            m = self.shown[idx]["message"]
            if m:
                self.req_view.setMessage(m.getRequest(), True)
                self.resp_view.setMessage(m.getResponse(), False)

    def to_repeater(self, idx):
        if not (0 <= idx < len(self.shown)): return
        f   = self.shown[idx]
        msg = f["message"]
        if not msg: return
        svc = msg.getHttpService()
        self.cb.sendToRepeater(
            svc.getHost(), svc.getPort(),
            svc.getProtocol().lower() == "https",
            msg.getRequest(),
            "AutoSQLi: %s %s" % (f["kind"], f["name"])
        )

    def processProxyMessage(self, is_req, message):
        if not is_req or not self.chk_on.isSelected(): return

        base     = message.getMessageInfo()
        analyzed = self.hlp.analyzeRequest(base)
        url_obj  = analyzed.getUrl()
        url      = str(url_obj)

        target = self.txt_target.getText().strip().lower()
        if target and target not in url.lower(): return
        if self.chk_scope.isSelected() and not self.cb.isInScope(url_obj): return
        if STATIC_RE.match(url): return
        if url in self.seen_urls: return

        self.seen_urls.add(url)
        self.scan_count += 1
        self._upd_stats()
        Thread(Worker(self, base)).start()


class _ColorRenderer(DefaultTableCellRenderer):
    def getTableCellRendererComponent(self, tbl, val, sel, foc, row, col):
        c = DefaultTableCellRenderer.getTableCellRendererComponent(
                self, tbl, val, sel, foc, row, col)
        d = str(tbl.getModel().getValueAt(row, 3)).lower()
        if   d.startswith("http 5"):   c.setBackground(Color(255, 190, 190))
        elif d.startswith("waf"):      c.setBackground(Color(255, 220, 180))
        elif "sql error" in d:         c.setBackground(Color(255, 210, 210))
        else:                          c.setBackground(Color.white)
        return c


class _ClickHandler(MouseAdapter):
    def __init__(self, ext): self.ext = ext
    def mouseClicked(self, e):
        row = e.getSource().getSelectedRow()
        if row < 0: return
        self.ext.show_row(row)
        if e.getClickCount() == 2:
            self.ext.to_repeater(row)


class Worker(Runnable):
    def __init__(self, ext, base):
        self.ext  = ext
        self.base = base
        self.hlp  = ext.hlp
        self.cb   = ext.cb
        self.out  = ext.out

    def run(self):
        try:
            ar = self.hlp.analyzeRequest(self.base)
            if self.ext.chk_params.isSelected():
                for p in ar.getParameters():
                    self._test_param(p)
            if self.ext.chk_cookies.isSelected():
                self._test_cookie(ar)
            if self.ext.chk_headers.isSelected():
                self._test_headers(ar)
        except Exception as ex:
            self.out.write("worker err: %s\n" % ex)

    def _body_len(self, resp):
        info = self.hlp.analyzeResponse(resp.getResponse())
        return len(resp.getResponse()[info.getBodyOffset():])

    def _ctype(self, resp):
        try:
            for h in self.hlp.analyzeResponse(resp.getResponse()).getHeaders():
                if h.lower().startswith("content-type:"): return h.lower()
        except: pass
        return ""

    def _skip_ctype(self, ct):
        # skip binary/useless content types, only care about html/json/xml
        for bad in ["image/", "text/css", "javascript", "font/"]:
            if bad in ct: return True
        return False

    def _base_resp(self, svc, req):
        resp = self.cb.makeHttpRequest(svc, req)
        bl   = self._body_len(resp)
        ct   = self._ctype(resp)
        if bl > MAX_BODY or self._skip_ctype(ct):
            return None, None
        return resp, bl

    def _test_param(self, p):
        svc  = self.base.getHttpService()
        req  = self.base.getRequest()
        _, bl = self._base_resp(svc, req)
        if bl is None: return

        url      = str(self.hlp.analyzeRequest(self.base).getUrl())
        val      = p.getValue()
        payloads = NUM_PAYLOADS if val.isdigit() else STR_PAYLOADS

        for s in payloads:
            inj  = self.hlp.buildParameter(p.getName(), val + s, p.getType())
            resp = self.cb.makeHttpRequest(svc, self.hlp.updateParameter(req, inj))
            self._check("param", p.getName(), url, bl, resp)

    def _test_cookie(self, ar):
        svc  = self.base.getHttpService()
        body = self.base.getRequest()[ar.getBodyOffset():]
        req  = self.hlp.buildHttpMessage(ar.getHeaders(), body)
        _, bl = self._base_resp(svc, req)
        if bl is None: return

        url      = str(self.hlp.analyzeRequest(self.base).getUrl())
        new_hdrs = []
        hit = False
        for h in ar.getHeaders():
            if h.lower().startswith("cookie:"):
                new_hdrs.append(h + "'")
                hit = True
            else:
                new_hdrs.append(h)
        if hit:
            resp = self.cb.makeHttpRequest(svc, self.hlp.buildHttpMessage(new_hdrs, body))
            self._check("cookie", "cookie", url, bl, resp)

    def _test_headers(self, ar):
        svc  = self.base.getHttpService()
        body = self.base.getRequest()[ar.getBodyOffset():]
        req  = self.hlp.buildHttpMessage(ar.getHeaders(), body)
        _, bl = self._base_resp(svc, req)
        if bl is None: return

        url = str(self.hlp.analyzeRequest(self.base).getUrl())
        for i, h in enumerate(ar.getHeaders()):
            name = h.split(":", 1)[0].strip().lower()
            if name in ["host", "content-length"]: continue  # skip or burp breaks
            hdrs    = list(ar.getHeaders())
            hdrs[i] = h + "'"
            resp    = self.cb.makeHttpRequest(svc, self.hlp.buildHttpMessage(hdrs, body))
            self._check("header", name, url, bl, resp)

    def _check(self, kind, name, url, base_len, resp):
        info   = self.hlp.analyzeResponse(resp.getResponse())
        body   = resp.getResponse()[info.getBodyOffset():]
        text   = self.hlp.bytesToString(body).lower()
        diff   = abs(len(body) - base_len)
        status = info.getStatusCode()

        if diff < LEN_THRESHOLD: return

        for w in WAF_SIGNS:
            if w in text:
                self.ext.add_finding(url, kind, name, "WAF/%s (diff=%d)" % (w, diff), resp)
                return
        if status in (401, 403, 406):
            self.ext.add_finding(url, kind, name, "WAF/HTTP%d (diff=%d)" % (status, diff), resp)
            return
        if status >= 500:
            self.ext.add_finding(url, kind, name, "HTTP%d (diff=%d)" % (status, diff), resp)
            return
        for e in SQL_ERRORS:
            if e in text:
                self.ext.add_finding(url, kind, name, "SQL error: %s (diff=%d)" % (e, diff), resp)
                return
