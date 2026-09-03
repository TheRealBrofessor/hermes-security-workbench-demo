/**
 * Hermes Security Workbench — reporting dashboard.
 *
 * Plain IIFE using the host dashboard SDK; no build step is required. The
 * backend remains the source of truth for filtering and redaction.
 */
(function () {
  "use strict";

  const SDK = window.__HERMES_PLUGIN_SDK__;
  if (!SDK) return;

  const { React } = SDK;
  const h = React.createElement;
  const { useCallback, useEffect, useState } = SDK.hooks;
  const Button = SDK.components.Button;
  const API = "/api/plugins/hermes-security-workbench";

  function apiError(error) {
    const raw = error && error.message ? String(error.message) : String(error);
    const match = raw.match(/^\d{3}:\s*(.*)$/s);
    const body = match ? match[1] : raw;
    try {
      const parsed = JSON.parse(body);
      return typeof parsed.detail === "string" ? parsed.detail : body;
    } catch (_error) {
      return body;
    }
  }

  function queryFor(caseId) {
    return caseId ? "?case_id=" + encodeURIComponent(caseId) : "";
  }

  function Breakdown(props) {
    const entries = Object.entries(props.values || {});
    return h("div", { className: "hsw-breakdown" },
      h("h3", null, props.title),
      entries.length
        ? h("ul", null, entries.map(function (entry) {
            return h("li", { key: entry[0] },
              h("span", null, entry[0]),
              h("strong", null, String(entry[1]))
            );
          }))
        : h("p", { className: "hsw-muted" }, "No matching records")
    );
  }

  function Summary(props) {
    if (!props.summary) return null;
    const counts = props.summary.counts;
    return h(React.Fragment, null,
      h("div", { className: "hsw-counts" },
        ["cases", "jobs", "findings"].map(function (name) {
          return h("div", { className: "hsw-count", key: name },
            h("strong", null, String(counts[name])),
            h("span", null, name)
          );
        })
      ),
      h("div", { className: "hsw-breakdowns" },
        h(Breakdown, {
          title: "Jobs by status",
          values: props.summary.jobs_by_status,
        }),
        h(Breakdown, {
          title: "Findings by severity",
          values: props.summary.findings_by_severity,
        })
      )
    );
  }

  function WorkbenchPage() {
    const [cases, setCases] = useState([]);
    const [caseId, setCaseId] = useState("");
    const [summary, setSummary] = useState(null);
    const [loading, setLoading] = useState(true);
    const [downloading, setDownloading] = useState("");
    const [error, setError] = useState("");

    const loadSummary = useCallback(function (selectedCase) {
      setLoading(true);
      setError("");
      return SDK.fetchJSON(API + "/reports/summary" + queryFor(selectedCase))
        .then(setSummary)
        .catch(function (err) {
          setSummary(null);
          setError(apiError(err));
        })
        .finally(function () { setLoading(false); });
    }, []);

    useEffect(function () {
      SDK.fetchJSON(API + "/cases")
        .then(function (rows) { setCases(Array.isArray(rows) ? rows : []); })
        .catch(function (err) { setError(apiError(err)); });
    }, []);

    useEffect(function () {
      loadSummary(caseId);
    }, [caseId, loadSummary]);

    function download(format) {
      setDownloading(format);
      setError("");
      SDK.authedFetch(API + "/reports/" + format + queryFor(caseId))
        .then(async function (response) {
          if (!response.ok) {
            throw new Error(response.status + ": " + await response.text());
          }
          const blob = await response.blob();
          const disposition = response.headers.get("content-disposition") || "";
          const match = disposition.match(/filename="?([^";]+)"?/i);
          const filename = match ? match[1] : "workbench-report." + format;
          const url = URL.createObjectURL(blob);
          const anchor = document.createElement("a");
          anchor.href = url;
          anchor.download = filename;
          document.body.appendChild(anchor);
          anchor.click();
          anchor.remove();
          URL.revokeObjectURL(url);
        })
        .catch(function (err) { setError(apiError(err)); })
        .finally(function () { setDownloading(""); });
    }

    return h("main", { className: "hsw-page" },
      h("header", { className: "hsw-header" },
        h("div", null,
          h("p", { className: "hsw-eyebrow" }, "Security Workbench"),
          h("h1", null, "Reports and exports"),
          h("p", { className: "hsw-subtitle" },
            "Review active records and export a redacted snapshot. Archived records and operational job output are excluded."
          )
        ),
        h("label", { className: "hsw-case-filter" },
          h("span", null, "Report scope"),
          h("select", {
            value: caseId,
            onChange: function (event) { setCaseId(event.target.value); },
          },
            h("option", { value: "" }, "All active cases"),
            cases.map(function (item) {
              return h("option", { key: item.id, value: item.id }, item.name);
            })
          )
        )
      ),
      error ? h("div", { className: "hsw-error", role: "alert" }, error) : null,
      loading
        ? h("p", { className: "hsw-muted" }, "Loading report summary…")
        : h(Summary, { summary: summary }),
      h("section", { className: "hsw-export" },
        h("div", null,
          h("h2", null, "Download report"),
          h("p", { className: "hsw-muted" },
            "JSON includes the full safe report contract. CSV contains findings. Markdown is presentation-ready."
          )
        ),
        h("div", { className: "hsw-actions" },
          ["json", "csv", "markdown"].map(function (format) {
            return h(Button, {
              key: format,
              disabled: !!downloading || loading || !summary,
              onClick: function () { download(format); },
            }, downloading === format
              ? "Preparing…"
              : "Export " + (format === "markdown" ? "Markdown" : format.toUpperCase()));
          })
        )
      )
    );
  }

  if (window.__HERMES_PLUGINS__ &&
      typeof window.__HERMES_PLUGINS__.register === "function") {
    window.__HERMES_PLUGINS__.register(
      "hermes-security-workbench",
      WorkbenchPage
    );
  }
})();
