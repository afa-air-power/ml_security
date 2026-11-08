const checkList = document.querySelector("#checks");
const messageEl = document.querySelector("#message");
const presetSelect = document.querySelector("#preset-select");
const refreshBtn = document.querySelector("#refresh-btn");
const seedVulnBtn = document.querySelector("#seed-vuln-btn");
const seedCleanBtn = document.querySelector("#seed-clean-btn");
const seedClearBtn = document.querySelector("#seed-clear-btn");
const uploadJsonInput = document.querySelector("#upload-json");
const exportMdBtn = document.querySelector("#export-md-btn");
const rawJsonLink = document.querySelector("#raw-json-link");

const gateBanner = document.querySelector("#gate-banner");
const gateBadge = document.querySelector("#gate-badge");
const gateTitle = document.querySelector("#gate-title");
const reportTimestamp = document.querySelector("#report-timestamp");

const metricTotal = document.querySelector("#metric-total");
const metricCritical = document.querySelector("#metric-critical");
const metricHigh = document.querySelector("#metric-high");
const metricMediumLow = document.querySelector("#metric-medium-low");
const metricBlocking = document.querySelector("#metric-blocking");

const filterContour = document.querySelector("#filter-contour");
const filterSeverity = document.querySelector("#filter-severity");
const filterStatus = document.querySelector("#filter-status");
const filterSearch = document.querySelector("#filter-search");
const findingsList = document.querySelector("#findings-list");
const findingsEmpty = document.querySelector("#findings-empty");

const contourTitles = {
  model: "Контур 1 · ML-модель (веса, сериализация, CVE)",
  wrapper: "Контур 2 · Код-обёртка (SAST)",
  api: "Обёртка · API", cache: "Обёртка · Cache",
  executor: "Обёртка · Executor", llm: "Обёртка · LLM",
};

const triageStatusLabels = {
  true_positive: "Подтверждено",
  accepted_risk: "Принятый риск",
  unresolved: "Без решения",
  confirmed: "Подтверждено",
  needs_review: "Требует проверки",
  false_positive: "Ложное срабатывание",
  fixed: "Исправлено",
};

let currentReport = null;
const pointSelect = document.querySelector("#evidence-point");
const evidenceRoute = document.querySelector("#evidence-route");
const evidenceMetrics = document.querySelector("#evidence-metrics");
const evidenceImpact = document.querySelector("#evidence-impact");
const warningBox = document.querySelector("#evidence-warning-box");
const warningTitle = document.querySelector("#evidence-warning-title");
const warningList = document.querySelector("#evidence-warnings");

const pointKinds = {
  peak: "Пиковый вес", row_norm: "Норма строки", bias: "Смещение класса",
  nonfinite: "Нечисловое значение", prompt_marker: "Маркер инструкции",
};
const metricNames = {
  ratio: "Отношение к медиане норм", z_score: "Z-score", z_score_max: "Максимальный Z-score",
  robust_z: "Робастный Z-score", kurtosis: "Эксцесс", ratio_to_p99: "Отношение к p99",
  mad: "Медианное отклонение", median_row_norm: "Медиана норм строк",
  row_norm: "Норма строки", abs_peak: "Модуль пикового веса", delta: "Сдвиг к среднему",
  peer_mean: "Среднее соседних значений", sample_size: "Проверено значений",
  count: "Количество", bytes_inspected: "Проверено байт",
};
const triggerLabels = {
  classic_peak: "пик по Z-score", heavy_tail: "эксцесс и амплитуда", robust_peak: "робастный пик",
};
const cacheStates = { hit: "Из кэша", miss: "Новый скан", bypass: "Без кэша" };
const metricNumber = new Intl.NumberFormat("ru-RU", { maximumSignificantDigits: 5 });

function showNotice(text, isError = false) {
  messageEl.hidden = false;
  messageEl.textContent = text;
  messageEl.style.background = isError ? "#fef2f2" : "#eff6ff";
  messageEl.style.borderColor = isError ? "#f87171" : "#93c5fd";
  messageEl.style.color = isError ? "#991b1b" : "#1e3a8a";
}

function hideNotice() {
  messageEl.hidden = true;
}

function getContourBadgeInfo(check) {
  const count = (check.findings || []).length;
  switch (check.status) {
    case "ok":
      if (count === 0) {
        return { text: "Успешно · Без находок", cls: "badge-ok-clean" };
      }
      return { text: `Проверено · Находок: ${count}`, cls: "badge-ok-findings" };
    case "skipped":
      return { text: "Пропущено · Нет входных файлов", cls: "badge-skipped" };
    case "not_configured":
      return { text: "Не настроен", cls: "badge-skipped" };
    case "unsupported_format":
      return { text: "Неподдерживаемый формат", cls: "badge-medium" };
    case "error":
      return { text: "Ошибка сканера", cls: "badge-error" };
    default:
      return { text: check.status, cls: "badge-skipped" };
  }
}

function renderGateBanner(report) {
  const summary = report.summary || {};
  const overall = summary.overall_status || "passed";
  gateBanner.className = "gate-banner";

  if (overall === "blocked") {
    gateBanner.classList.add("gate-blocked");
    gateBadge.className = "badge badge-critical";
    gateBadge.textContent = "CI GATE: БЛОКИРОВАН";
  } else if (overall === "error") {
    gateBanner.classList.add("gate-error");
    gateBadge.className = "badge badge-error";
    gateBadge.textContent = "CI GATE: СБОЙ ИНСТРУМЕНТА";
  } else if (overall === "warning" || overall === "skipped") {
    gateBanner.classList.add("gate-warning");
    gateBadge.className = "badge badge-medium";
    gateBadge.textContent = summary.gate_passed
      ? "CI GATE: ПРЕДУПРЕЖДЕНИЕ"
      : "CI GATE: НЕПОЛНАЯ ПРОВЕРКА";
  } else {
    gateBanner.classList.add("gate-passed");
    gateBadge.className = "badge badge-ok-clean";
    gateBadge.textContent = report.profile === "sfs" ? "ТРИАЖ ЗАВЕРШЁН" : "CI GATE: ПРОЙДЕН";
  }

  gateTitle.textContent = summary.gate_reason || "Отчёт сформирован.";
  if (report.generated_at) {
    reportTimestamp.textContent = `Сформирован: ${new Date(report.generated_at).toLocaleString("ru-RU")}`;
  } else {
    reportTimestamp.textContent = "";
  }

  const bySev = summary.by_severity || {};
  metricTotal.textContent = String(summary.total_findings ?? 0);
  metricCritical.textContent = String(bySev.critical ?? 0);
  metricHigh.textContent = String(bySev.high ?? 0);
  metricMediumLow.textContent = String((bySev.medium ?? 0) + (bySev.low ?? 0));
  metricBlocking.textContent = String(summary.blocking_findings_count ?? 0);
}

function renderContours(report) {
  checkList.innerHTML = "";
  for (const check of report.checks || []) {
    const li = document.createElement("li");
    li.className = "contour-card";

    const top = document.createElement("div");
    top.className = "contour-top";

    const title = document.createElement("strong");
    title.className = "contour-title";
    title.textContent = contourTitles[check.id] ?? check.id;

    const badgeInfo = getContourBadgeInfo(check);
    const badge = document.createElement("span");
    badge.className = `badge ${badgeInfo.cls}`;
    badge.textContent = badgeInfo.text;

    top.append(title, badge);
    const cacheState = check.execution?.cache;
    if (cacheStates[cacheState]) {
      const cacheBadge = document.createElement("span");
      cacheBadge.className = "badge badge-skipped";
      cacheBadge.textContent = cacheStates[cacheState];
      cacheBadge.title = check.execution.fingerprint || cacheBadge.textContent;
      top.append(cacheBadge);
    }
    li.append(top);

    if (check.message) {
      const msg = document.createElement("p");
      msg.className = "contour-msg";
      msg.textContent = check.message;
      li.append(msg);
    }

    if (Array.isArray(check.scanned_files) && check.scanned_files.length > 0) {
      const filesBox = document.createElement("div");
      filesBox.className = "contour-files";
      for (const f of check.scanned_files) {
        const pill = document.createElement("span");
        pill.className = "file-pill";
        pill.textContent = f;
        filesBox.append(pill);
      }
      li.append(filesBox);
    }

    checkList.append(li);
  }
}

function getAllFindings(report) {
  const result = [];
  for (const check of report.checks || []) {
    for (const f of check.findings || []) {
      result.push({
        ...f,
        contour: f.contour || check.id,
      });
    }
  }
  return result;
}

function renderFindings(report) {
  findingsList.innerHTML = "";
  const all = getAllFindings(report);

  const cFilter = filterContour.value;
  const sFilter = filterSeverity.value;
  const stFilter = filterStatus.value;
  const q = filterSearch.value.trim().toLowerCase();

  const filtered = all.filter((f) => {
    if (cFilter !== "all" && f.contour !== cFilter) return false;
    if (sFilter !== "all" && f.severity !== sFilter) return false;
    if (stFilter !== "all" && f.status !== stFilter) return false;
    if (q) {
      const hay = `${f.id} ${f.object} ${f.evidence} ${f.decision} ${f.category || ""}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  if (filtered.length === 0) {
    findingsEmpty.hidden = false;
    const anyError = (report.checks || []).some((c) => c.status === "error");
    const allSkipped = (report.checks || []).every((c) => c.status === "skipped" || c.status === "not_configured");
    if (anyError) {
      findingsEmpty.textContent = "Сканирование завершилось ошибкой инструмента. Проверьте диагностическое сообщение контура выше.";
    } else if (allSkipped) {
      findingsEmpty.textContent = "Проверка пропущена: в папках model/ и wrapper/ пока нет файлов. Нажмите «Заполнить model/ + wrapper/» сверху или переключите режим просмотра.";
    } else if (all.length === 0) {
      findingsEmpty.textContent = "Оба контура отработали штатно: уязвимостей, закладок и небезопасной сериализации не обнаружено.";
    } else {
      findingsEmpty.textContent = "По выбранным фильтрам находок не найдено.";
    }
    return;
  }

  findingsEmpty.hidden = true;

  for (const f of filtered) {
    const card = document.createElement("article");
    const sev = f.severity || "medium";
    card.className = `finding-card sev-border-${sev}`;

    const header = document.createElement("div");
    header.className = "finding-header";

    const idGroup = document.createElement("div");
    idGroup.className = "finding-id-group";

    const idEl = document.createElement("span");
    idEl.className = "finding-id";
    idEl.textContent = f.id;

    const contourBadge = document.createElement("span");
    contourBadge.className = "badge badge-skipped";
    contourBadge.textContent = f.contour === "model" ? "Контур: Модель" : "Контур: Обёртка";

    const sevBadge = document.createElement("span");
    sevBadge.className = `badge badge-${sev}`;
    sevBadge.textContent = `Серьёзность: ${sev.toUpperCase()}`;

    const stBadge = document.createElement("span");
    stBadge.className = f.status === "false_positive" || f.status === "fixed" ? "badge badge-ok-clean" : "badge badge-high";
    stBadge.textContent = `Статус: ${triageStatusLabels[f.status] || f.status}`;

    idGroup.append(idEl, contourBadge, sevBadge, stBadge);
    header.append(idGroup);
    card.append(header);

    const grid = document.createElement("div");
    grid.className = "triage-grid";

    const fields = [
      ["ID и контур", `${f.id} (${f.contour})`],
      ["Объект", f.object],
      ["Доказательство", f.evidence],
      ["Серьёзность", sev.toUpperCase()],
      ["Статус", `${triageStatusLabels[f.status] || f.status} (${f.status})`],
      ["Решение", f.decision || "—"],
      ...(f.cwe ? [["CWE", f.cwe]] : []),
      ...(f.comment ? [["Комментарий триажа", f.comment]] : []),
    ];

    for (const [label, val] of fields) {
      const lDiv = document.createElement("div");
      lDiv.className = "triage-label";
      lDiv.textContent = label;

      const vDiv = document.createElement("div");
      vDiv.className = "triage-val";
      vDiv.textContent = val;

      grid.append(lDiv, vDiv);
    }
    card.append(grid);

    if (report.profile === "sfs") {
      findingsList.append(card);
      continue;
    }

    const editor = document.createElement("div");
    editor.className = "triage-editor";

    const statusSelect = document.createElement("select");
    for (const [code, label] of Object.entries(triageStatusLabels)) {
      const opt = document.createElement("option");
      opt.value = code;
      opt.textContent = label;
      if (code === f.status) opt.selected = true;
      statusSelect.append(opt);
    }

    const decisionInput = document.createElement("input");
    decisionInput.type = "text";
    decisionInput.value = f.decision || "";
    decisionInput.placeholder = "Обоснование статуса и следующий шаг…";

    const saveBtn = document.createElement("button");
    saveBtn.type = "button";
    saveBtn.className = "btn btn-sm btn-primary";
    saveBtn.textContent = "Сохранить триаж";

    saveBtn.addEventListener("click", async () => {
      const key = f.key || `${f.id}::${f.object}`;
      saveBtn.disabled = true;
      saveBtn.textContent = "Сохраняем…";
      try {
        const res = await fetch("/api/triage", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            key,
            status: statusSelect.value,
            decision: decisionInput.value,
          }),
        });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        showNotice(`Решение триажа для ${f.id} сохранено в triage.json.`);
        await loadReport();
      } catch (err) {
        showNotice(`Ошибка сохранения триажа: ${err.message}`, true);
      } finally {
        saveBtn.disabled = false;
        saveBtn.textContent = "Сохранить триаж";
      }
    });

    editor.append(statusSelect, decisionInput, saveBtn);
    card.append(editor);
    findingsList.append(card);
  }
}

function evidenceNode(label, title, detail, state) {
  const item = document.createElement("li");
  item.className = "evidence-node";
  item.dataset.state = state;
  const caption = document.createElement("small");
  const name = document.createElement("strong");
  const description = document.createElement("span");
  caption.textContent = label;
  name.textContent = title;
  description.textContent = detail;
  item.append(caption, name, description);
  return item;
}

function renderEvidencePath(report) {
  evidenceRoute.replaceChildren();
  evidenceMetrics.replaceChildren();
  const graph = report.decision_graph;
  const point = graph?.nodes?.find(node => node.type === "point" && node.id === pointSelect.value);
  const edge = graph?.edges?.find(link => link.from === point?.id && link.type === "evidence");
  const finding = edge && graph.nodes.find(node => node.id === edge.to && node.type === "finding");

  if (!point || !finding) {
    evidenceImpact.textContent = graph
      ? "В этом отчёте нет точек интереса в весах. Покрытие проверок указано ниже."
      : "Для этого отчёта карта недоступна. Запустите проверку обновлённым сканером.";
    return;
  }

  const data = point.data;
  const coordinates = Array.isArray(data.coordinates) ? `[${data.coordinates.join(", ")}]` : `смещение ${data.index}`;
  const observed = typeof data.value === "number" ? metricNumber.format(data.value) : String(data.value);
  const blockers = graph.edges.filter(link => link.to === "gate" && link.type === "blocks");
  const blocks = blockers.some(link => link.from === finding.id);
  const verdict = report.summary?.gate_passed ? "Проходит" : "Блокирует";
  const effect = blocks ? "Эта находка влияет на решение." : "Эта находка сама по себе не блокирует.";
  evidenceRoute.append(
    evidenceNode("Измерение", data.tensor, `${coordinates} · ${observed}`, "point"),
    evidenceNode("Находка", finding.rule, triageStatusLabels[finding.status] || finding.status, "finding"),
    evidenceNode("CI Gate", verdict, effect, report.summary?.gate_passed ? "pass" : "block"),
  );

  for (const [key, value] of Object.entries(data.metrics || {})) {
    if (!Number.isFinite(value)) continue;
    const threshold = data.thresholds?.[key];
    const row = document.createElement("div");
    row.className = "evidence-measure";
    const label = document.createElement("span");
    label.textContent = `${metricNames[key] || key} · ${metricNumber.format(value)}`;
    row.append(label);
    if (Number.isFinite(threshold) && threshold > 0) {
      const meter = document.createElement("meter");
      meter.min = 0;
      meter.max = Math.max(threshold * 2, value);
      meter.low = threshold;
      meter.high = threshold;
      meter.optimum = 0;
      meter.value = Math.max(0, value);
      meter.setAttribute("aria-label", `${metricNames[key] || key}, порог ${metricNumber.format(threshold)}`);
      label.textContent += ` / порог ${metricNumber.format(threshold)}`;
      row.append(meter);
    }
    evidenceMetrics.append(row);
  }
  if (Array.isArray(data.triggered_rules)) {
    const rule = document.createElement("p");
    rule.className = "muted-meta";
    rule.textContent = `Сработали критерии: ${data.triggered_rules.map(key => triggerLabels[key] || key).join(", ")}.`;
    evidenceMetrics.append(rule);
  }

  const remaining = blockers.filter(link => link.from !== finding.id).length;
  evidenceImpact.textContent = blocks
    ? (remaining ? `Без этой находки осталось бы блокирующих причин: ${remaining}.` : "Если эту находку подтвердят как ложное срабатывание, блокирующих причин не останется.")
    : effect;
}

function renderEvidence(report) {
  const previous = pointSelect.value;
  const graph = report.decision_graph;
  const points = graph?.nodes?.filter(node => node.type === "point") || [];
  pointSelect.replaceChildren();
  for (const point of points) {
    const option = document.createElement("option");
    option.value = point.id;
    option.textContent = `${pointKinds[point.data.kind] || point.data.kind} · ${point.data.tensor}`;
    pointSelect.append(option);
  }
  if (points.some(point => point.id === previous)) pointSelect.value = previous;
  pointSelect.hidden = points.length === 0;
  document.querySelector("#point-label").hidden = points.length === 0;

  warningList.replaceChildren();
  const warnings = Array.isArray(report.warnings) ? report.warnings : [];
  warningBox.hidden = warnings.length === 0;
  warningTitle.textContent = `Предупреждения · ${warnings.length}`;
  for (const warning of warnings) {
    const item = document.createElement("li");
    item.textContent = `${warning.contour} · ${warning.blocking ? "Влияет на CI" : "Для сведения"} · ${warning.message}`;
    warningList.append(item);
  }
  renderEvidencePath(report);
  const paths = document.querySelector("#sfs-paths");
  paths.replaceChildren();
  paths.hidden = report.profile !== "sfs";
  if (report.profile === "sfs") {
    const weight = report.provenance?.weights;
    if (weight?.file) {
      const message = document.createElement("p");
      message.textContent = weight.matches_reference
        ? "SHA-256 весов совпадает с опубликованным эталоном SmolLM2."
        : "SHA-256 весов расходится с опубликованным эталоном.";
      paths.append(message);
    }
    for (const path of report.attack_paths || []) {
      const heading = document.createElement("h3");
      heading.textContent = path.title;
      const steps = document.createElement("ol");
      for (const step of path.steps) {
        const item = document.createElement("li");
        item.textContent = step;
        steps.append(item);
      }
      paths.append(heading, steps);
    }
  }
}

pointSelect.addEventListener("change", () => {
  if (currentReport) renderEvidencePath(currentReport);
});

function renderReport(report) {
  currentReport = report;
  document.querySelector("#triage-mode").textContent = report.profile === "sfs"
    ? "Конкурсный отчёт. Решения хранятся в triage-sfs.json и проверяются в CI."
    : "В демонстрационном режиме карточки можно редактировать прямо в интерфейсе.";
  renderGateBanner(report);
  renderContours(report);
  renderEvidence(report);
  renderFindings(report);
}

async function loadReport() {
  const preset = presetSelect.value || "workspace";
  rawJsonLink.href = `/api/report?preset=${encodeURIComponent(preset)}`;
  try {
    const response = await fetch(`/api/report?preset=${encodeURIComponent(preset)}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const report = await response.json();
    renderReport(report);
  } catch {
    showNotice("Не удалось загрузить отчёт. Проверьте, запущен ли локальный сервер (python3 -m backend.app).", true);
  }
}

async function updateWorkspacePreset(preset, noticeText) {
  try {
    const res = await fetch("/api/workspace", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ preset }),
    });
    if (!res.ok) {
      const error = await res.json();
      throw new Error(error.error || `HTTP ${res.status}`);
    }
    presetSelect.value = "workspace";
    showNotice(noticeText);
    await loadReport();
  } catch (err) {
    showNotice(`Не удалось обновить рабочие папки: ${err.message}`, true);
  }
}

presetSelect.addEventListener("change", () => {
  hideNotice();
  loadReport();
});

refreshBtn.addEventListener("click", () => {
  hideNotice();
  loadReport();
});

seedVulnBtn.addEventListener("click", () =>
  updateWorkspacePreset(
    "vulnerable",
    "В папки model/ и wrapper/ скопирован демонстрационный набор с уязвимостями (закладка в весах, RCE в Pickle, CVE и уязвимая обёртка)."
  )
);

seedCleanBtn.addEventListener("click", () =>
  updateWorkspacePreset(
    "clean",
    "В папки model/ и wrapper/ скопирован чистый эталонный набор (SafeTensors + безопасная обёртка)."
  )
);

seedClearBtn.addEventListener("click", () =>
  updateWorkspacePreset(
    "empty",
    "Папки model/ и wrapper/ очищены (оставлены только шаблонные README.md)."
  )
);

for (const el of [filterContour, filterSeverity, filterStatus, filterSearch]) {
  el.addEventListener("input", () => {
    if (currentReport) renderFindings(currentReport);
  });
}

uploadJsonInput.addEventListener("change", async (e) => {
  const file = e.target.files?.[0];
  if (!file) return;
  try {
    const text = await file.text();
    const parsed = JSON.parse(text);
    renderReport(parsed);
    showNotice(`Загружен локальный отчёт из файла ${file.name}.`);
  } catch (err) {
    showNotice(`Не удалось прочитать JSON-файл: ${err.message}`, true);
  }
});

exportMdBtn.addEventListener("click", () => {
  if (!currentReport) return;
  const findings = getAllFindings(currentReport);
  const lines = [
    "# Отчёт триажа находок ML Security Pipeline",
    "",
    "| ID и контур | Объект | Доказательство | Серьёзность | Статус | Решение |",
    "| --- | --- | --- | --- | --- | --- |",
  ];
  for (const f of findings) {
    const row = [
      `\`${f.id}\` (${f.contour})`,
      `\`${f.object}\``,
      (f.evidence || "").replace(/\|/g, "\\|"),
      (f.severity || "").toUpperCase(),
      `${triageStatusLabels[f.status] || f.status} (\`${f.status}\`)`,
      ([f.decision, f.comment].filter(Boolean).join(" ")).replace(/\|/g, "\\|"),
    ];
    lines.push(`| ${row.join(" | ")} |`);
  }
  const blob = new Blob([lines.join("\n") + "\n"], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "triage-report.md";
  a.click();
  URL.revokeObjectURL(url);
});

loadReport();
