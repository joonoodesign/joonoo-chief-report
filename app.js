/* 주누디자인 대표님 전용 총괄 업무보고서 · 달력 · AES-256 암호화 금고 (v1.0.0) */
(() => {
  "use strict";

  const APP_VERSION = "v1.0.0";
  const STORAGE_GAS_URL = "joonoo_chief_gas_url_v1";
  const SESSION_TOKEN_KEY = "joonoo_chief_token_v1";
  const SESSION_VKEY_KEY = "joonoo_chief_vkey_v1";
  const AUTO_LOCK_SEC = 300; // 5분 무입력 자동 잠금

  // 기본 GAS URL (배포 완료된 주누디자인 대표님 전용 백엔드)
  const DEFAULT_GAS_URL = "https://script.google.com/macros/s/AKfycbwTHnguDDA8UtnTClDr7F_ZqagzHzpVmyj6hmYglYVBZyaDyZ_kjcD22bbXvWjIJTEe9w/exec";

  const DEPTS = [
    { key: "chief", label: "총괄매니저", short: "총괄", color: "#1B365D" },
    { key: "market", label: "① 마켓·정산·CS", short: "①마켓", color: "#0284C7" },
    { key: "ads", label: "② 광고·SEO", short: "②광고", color: "#EA580C" },
    { key: "cafe24", label: "③ 자사몰(카페24)", short: "③자사몰", color: "#7C3AED" },
    { key: "design", label: "④ 어도비 디자인", short: "④디자인", color: "#DB2777" },
    { key: "blog", label: "⑤ 블로그·마케팅", short: "⑤블로그", color: "#16A34A" },
    { key: "youtube", label: "⑥ 유튜브·영상", short: "⑥유튜브", color: "#DC2626" },
    { key: "tax", label: "⑦ 세무·회계·노무", short: "⑦세무", color: "#0D9488" },
  ];

  const DEPT_MAP = Object.fromEntries(DEPTS.map((d) => [d.key, d]));

  // 대한민국 고정 양력 공휴일 (MM-DD) — 세무 마감일 주말·공휴일 순연 계산용
  const FIXED_HOLIDAYS = new Set([
    "01-01", "03-01", "05-05", "06-06", "08-15", "10-03", "10-09", "12-25",
  ]);

  const state = {
    pinBuf: "",
    busyLogin: false,
    token: "",
    vaultCryptoKey: null,
    currentView: "report",
    currentMonth: todayStr().slice(0, 7),
    selectedDate: todayStr(),
    selectedDept: "ALL",
    compactMode: false,
    monthCache: {},
    carryovers: [],
    vaultItems: [],
    revealedVaultIds: new Set(),
    lastActivityAt: Date.now(),
    timerId: null,
  };

  /* ==================== DOM 헬퍼 (XSS 차단: textContent 전용) ==================== */
  const $ = (id) => document.getElementById(id);

  function el(tag, attrs, text) {
    const node = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (k === "class") node.className = v;
        else if (k === "style" && typeof v === "object") Object.assign(node.style, v);
        else if (k.startsWith("data-")) node.setAttribute(k, String(v));
        else if (v !== undefined && v !== null) node.setAttribute(k, String(v));
      }
    }
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function clearEl(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function isSafeHttpUrl(url) {
    return typeof url === "string" && /^https?:\/\/[^\s]+$/i.test(url.trim());
  }

  let toastTimer = null;
  function showToast(msg) {
    const t = $("toast");
    t.textContent = msg;
    t.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => t.classList.remove("show"), 2600);
  }

  function todayStr() {
    const now = new Date();
    const y = now.getFullYear();
    const m = String(now.getMonth() + 1).padStart(2, "0");
    const d = String(now.getDate()).padStart(2, "0");
    return `${y}-${m}-${d}`;
  }

  function formatKoreanDate(dateStr) {
    if (!dateStr) return "";
    const [y, m, d] = dateStr.split("-").map(Number);
    const dt = new Date(y, m - 1, d);
    const w = ["일", "월", "화", "수", "목", "금", "토"][dt.getDay()];
    return `${y}년 ${m}월 ${d}일 (${w})`;
  }

  function getGasUrl() {
    const saved = (localStorage.getItem(STORAGE_GAS_URL) || "").trim();
    return saved || DEFAULT_GAS_URL;
  }

  /* ==================== AES-256-GCM 브라우저 종단간 암호화 ==================== */
  function b64ToBytes(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function bytesToB64(bytes) {
    let bin = "";
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
    return btoa(bin);
  }

  async function importVaultKey(rawKeyB64) {
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error("이 브라우저는 Web Crypto AES-256 암호화를 지원하지 않습니다(HTTPS 접속 필요).");
    }
    const rawBytes = b64ToBytes(rawKeyB64);
    return window.crypto.subtle.importKey("raw", rawBytes, { name: "AES-GCM" }, false, [
      "encrypt",
      "decrypt",
    ]);
  }

  async function encryptField(plainText, cryptoKey) {
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(String(plainText || ""));
    const cipherBuf = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      encoded
    );
    return `enc1:${bytesToB64(iv)}:${bytesToB64(new Uint8Array(cipherBuf))}`;
  }

  async function decryptField(blob, cryptoKey) {
    if (!blob) return "";
    if (!blob.startsWith("enc1:")) return "[암호화 형식 오류]";
    const parts = blob.split(":");
    if (parts.length !== 3) return "[복호화 불가]";
    try {
      const iv = b64ToBytes(parts[1]);
      const cipherBytes = b64ToBytes(parts[2]);
      const plainBuf = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        cryptoKey,
        cipherBytes
      );
      return new TextDecoder().decode(plainBuf);
    } catch {
      return "[복호화 오류]";
    }
  }

  /* ==================== GAS 서버 통신 ==================== */
  async function apiCall(action, payload = {}, skipAuth = false) {
    const url = getGasUrl();
    if (!url) {
      throw new Error("구글 서버(GAS) 주소가 설정되지 않았습니다. 하단 [구글 서버 주소 연결 설정]을 먼저 입력해 주세요.");
    }
    const body = Object.assign({ action }, payload);
    if (!skipAuth && state.token) {
      body.token = state.token;
    }

    const resp = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "text/plain;charset=utf-8" },
      body: JSON.stringify(body),
      redirect: "follow",
    });

    if (!resp.ok) {
      throw new Error(`서버 응답 오류 (HTTP ${resp.status})`);
    }
    const data = await resp.json();
    if (!data.ok && data.code === "UNAUTHORIZED" && !skipAuth) {
      lockApp("세션이 만료되어 자동으로 잠겼습니다. 다시 로그인해 주세요.");
      throw new Error(data.error || "인증 만료");
    }
    return data;
  }

  /* ==================== ⑦ 법정 세무·노무 일정 자동 계산 ==================== */
  function adjustBusinessDay(year, month, day) {
    const dt = new Date(year, month - 1, day);
    while (true) {
      const wd = dt.getDay();
      const mmdd = `${String(dt.getMonth() + 1).padStart(2, "0")}-${String(dt.getDate()).padStart(2, "0")}`;
      if (wd !== 0 && wd !== 6 && !FIXED_HOLIDAYS.has(mmdd)) break;
      dt.setDate(dt.getDate() + 1);
    }
    return `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, "0")}-${String(dt.getDate()).padStart(2, "0")}`;
  }

  function getTaxEventsForMonth(ym) {
    const [y, m] = ym.split("-").map(Number);
    const events = [];

    events.push({
      date: adjustBusinessDay(y, m, 10),
      short: "원천세·4대보험",
      title: "매월 10일 법정 마감 — 원천세 신고·납부 / 4대보험 납부 / 전월 전자세금계산서 발급 마감",
    });
    events.push({
      date: adjustBusinessDay(y, m, 15),
      short: "급여지급일",
      title: "매월 15일 — 직원 급여 지급 및 급여명세서 교부 확인 (금액 미표시 보안 적용)",
    });

    if (m === 1 || m === 7) {
      events.push({
        date: adjustBusinessDay(y, m, 25),
        short: "부가세신고",
        title: `${m === 1 ? "2기" : "1기"} 부가가치세 확정신고 마감 — 사업용 카드 불공제(PG 5곳·주유 등) 점검`,
      });
    }
    if (m === 5) {
      events.push({
        date: adjustBusinessDay(y, m, 31),
        short: "종소세마감",
        title: "종합소득세 확정신고 마감 (간편장부대상자 — 세무대리인 자료 전달 확인)",
      });
    }
    return events;
  }

  function getUpcomingTaxEvent() {
    const today = todayStr();
    const [y, m] = today.split("-").map(Number);
    const nextM = m === 12 ? `${y + 1}-01` : `${y}-${String(m + 1).padStart(2, "0")}`;
    const list = [...getTaxEventsForMonth(`${y}-${String(m).padStart(2, "0")}`), ...getTaxEventsForMonth(nextM)]
      .filter((e) => e.date >= today)
      .sort((a, b) => a.date.localeCompare(b.date));
    return list[0] || null;
  }

  function daysDiff(fromStr, toStr) {
    const [y1, m1, d1] = fromStr.split("-").map(Number);
    const [y2, m2, d2] = toStr.split("-").map(Number);
    return Math.round((new Date(y2, m2 - 1, d2) - new Date(y1, m1 - 1, d1)) / 86400000);
  }

  /* ==================== 로그인 / 잠금 / 자동잠금 ==================== */
  function renderPinDots(isError = false) {
    const dots = $("pinDots").children;
    for (let i = 0; i < dots.length; i++) {
      dots[i].classList.toggle("filled", i < state.pinBuf.length);
      dots[i].classList.toggle("error", isError);
    }
  }

  function setLockMsg(text, isOk = false) {
    const box = $("lockMsg");
    box.textContent = text || "";
    box.classList.toggle("ok", isOk);
  }

  async function submitPin() {
    if (state.busyLogin || state.pinBuf.length !== 6) return;
    state.busyLogin = true;
    const pin = state.pinBuf;
    setLockMsg("서버 보안 인증 중...", true);

    try {
      const res = await apiCall("login", { pin }, true);
      if (!res.ok) {
        renderPinDots(true);
        setLockMsg(res.error || "비밀번호가 일치하지 않습니다.");
        setTimeout(() => {
          state.pinBuf = "";
          renderPinDots(false);
        }, 420);
        return;
      }

      const cryptoKey = await importVaultKey(res.vaultKey);
      state.token = res.token;
      state.vaultCryptoKey = cryptoKey;
      sessionStorage.setItem(SESSION_TOKEN_KEY, res.token);
      sessionStorage.setItem(SESSION_VKEY_KEY, res.vaultKey);

      state.pinBuf = "";
      renderPinDots(false);
      setLockMsg("");
      enterApp();
    } catch (err) {
      renderPinDots(true);
      setLockMsg(err.message || "연결 오류가 발생했습니다.");
      state.pinBuf = "";
      setTimeout(() => renderPinDots(false), 500);
    } finally {
      state.busyLogin = false;
    }
  }

  function enterApp() {
    $("lockScreen").classList.add("hidden");
    $("appShell").classList.remove("hidden");
    $("appVerTag").textContent = APP_VERSION;
    touchActivity();
    startAutoLockLoop();
    loadMonth(state.currentMonth, true);
  }

  async function lockApp(reasonMsg) {
    const prevToken = state.token;
    state.token = "";
    state.vaultCryptoKey = null;
    state.vaultItems = [];
    state.revealedVaultIds.clear();
    state.monthCache = {};
    sessionStorage.removeItem(SESSION_TOKEN_KEY);
    sessionStorage.removeItem(SESSION_VKEY_KEY);
    clearInterval(state.timerId);
    state.timerId = null;

    $("appShell").classList.add("hidden");
    $("lockScreen").classList.remove("hidden");
    state.pinBuf = "";
    renderPinDots(false);
    setLockMsg(reasonMsg || "안전하게 잠겼습니다.", !reasonMsg);

    if (prevToken && getGasUrl()) {
      apiCall("logout", { token: prevToken }, true).catch(() => {});
    }
  }

  function touchActivity() {
    state.lastActivityAt = Date.now();
  }

  function startAutoLockLoop() {
    clearInterval(state.timerId);
    state.timerId = setInterval(() => {
      if (!state.token) return;
      const elapsed = Math.floor((Date.now() - state.lastActivityAt) / 1000);
      const remain = Math.max(0, AUTO_LOCK_SEC - elapsed);
      const mm = String(Math.floor(remain / 60)).padStart(2, "0");
      const ss = String(remain % 60).padStart(2, "0");
      $("autoLockTimer").textContent = `자동잠금 ${mm}:${ss}`;
      if (remain <= 0) {
        lockApp("5분간 입력이 없어 자동으로 잠겼습니다.");
      }
    }, 1000);
  }

  /* ==================== 월간 데이터 로딩 & 달력 렌더링 ==================== */
  async function loadMonth(ym, force = false) {
    state.currentMonth = ym;
    const [y, m] = ym.split("-").map(Number);
    $("calMonthLabel").textContent = `${y}년 ${m}월`;

    if (!force && state.monthCache[ym]) {
      renderAllReportPanels();
      return;
    }

    try {
      const res = await apiCall("getMonthData", { month: ym });
      if (!res.ok) throw new Error(res.error || "데이터 조회 실패");
      state.monthCache[ym] = res;
      state.carryovers = res.carryovers || [];

      // 선택 날짜가 해당 월에 없으면 기록 있는 최신 날짜 또는 오늘로 이동
      if (!state.selectedDate.startsWith(ym)) {
        const dates = [...new Set((res.logs || []).map((l) => l.date))].sort();
        state.selectedDate = dates.length ? dates[dates.length - 1] : `${ym}-01`;
      }
      renderAllReportPanels();
    } catch (err) {
      showToast(err.message || "월간 데이터를 불러오지 못했습니다.");
    }
  }

  function renderAllReportPanels() {
    renderStats();
    renderCalendar();
    renderCarryovers();
    renderSelectedDayReport();
  }

  function renderStats() {
    const data = state.monthCache[state.currentMonth] || { logs: [], approvals: {} };
    const logs = data.logs || [];
    const activeDates = new Set(logs.map((l) => l.date));
    const approvedCount = Object.values(data.approvals || {}).filter((a) => a && a.approvedAt).length;
    const openCarry = (state.carryovers || []).filter((c) => c.status !== "DONE").length;

    $("statMonthLogs").textContent = `${logs.length}건`;
    $("statActiveDays").textContent = `기록된 날짜 ${activeDates.size}일 (전체 누적 ${data.totalLogCountAll || logs.length}건)`;
    $("statApproved").textContent = `${approvedCount}일`;
    $("statApprovedSub").textContent = activeDates.size ? `기록일 대비 ${Math.round((approvedCount / activeDates.size) * 100)}% 결재` : "결재 대기";
    $("statCarryOpen").textContent = `${openCarry}건`;

    const nextTax = getUpcomingTaxEvent();
    if (nextTax) {
      const d = daysDiff(todayStr(), nextTax.date);
      $("statNextTax").textContent = `${nextTax.short} (${d === 0 ? "D-Day" : "D-" + d})`;
      $("statNextTaxSub").textContent = `${nextTax.date} 마감`;
    }
  }

  function renderCalendar() {
    const grid = $("calendarGrid");
    clearEl(grid);

    const data = state.monthCache[state.currentMonth] || { logs: [], approvals: {} };
    const logsByDate = {};
    for (const item of data.logs || []) {
      if (!logsByDate[item.date]) logsByDate[item.date] = [];
      logsByDate[item.date].push(item);
    }

    const taxEvents = getTaxEventsForMonth(state.currentMonth);
    const taxByDate = {};
    for (const ev of taxEvents) {
      if (!taxByDate[ev.date]) taxByDate[ev.date] = [];
      taxByDate[ev.date].push(ev);
    }

    const [year, month] = state.currentMonth.split("-").map(Number);
    const firstDay = new Date(year, month - 1, 1);
    const startOffset = firstDay.getDay();
    const lastDate = new Date(year, month, 0).getDate();
    const prevLastDate = new Date(year, month - 1, 0).getDate();
    const today = todayStr();

    const totalCells = Math.ceil((startOffset + lastDate) / 7) * 7;

    for (let idx = 0; idx < totalCells; idx++) {
      let cellDate = "";
      let dayNum = 0;
      let isOther = false;

      if (idx < startOffset) {
        dayNum = prevLastDate - startOffset + idx + 1;
        isOther = true;
      } else if (idx >= startOffset + lastDate) {
        dayNum = idx - (startOffset + lastDate) + 1;
        isOther = true;
      } else {
        dayNum = idx - startOffset + 1;
        cellDate = `${year}-${String(month).padStart(2, "0")}-${String(dayNum).padStart(2, "0")}`;
      }

      const wd = idx % 7;
      const cls = ["cal-cell"];
      if (isOther) cls.push("other");
      if (wd === 0) cls.push("sun");
      if (wd === 6) cls.push("sat");
      if (cellDate === today) cls.push("today");
      if (cellDate === state.selectedDate) cls.push("selected");

      const cell = el("button", { type: "button", class: cls.join(" ") });
      const topRow = el("div", { class: "cal-day-row" });
      topRow.appendChild(el("span", { class: "cal-day-num" }, dayNum));

      if (cellDate && data.approvals && data.approvals[cellDate] && data.approvals[cellDate].approvedAt) {
        topRow.appendChild(el("span", { class: "cal-approved", title: "대표님 결재 완료" }, "✅"));
      }
      cell.appendChild(topRow);

      if (cellDate && taxByDate[cellDate]) {
        for (const ev of taxByDate[cellDate]) {
          const diff = daysDiff(today, cellDate);
          const tagCls = diff >= 0 && diff <= 3 ? "cal-tax-tag urgent" : "cal-tax-tag";
          cell.appendChild(el("div", { class: tagCls, title: ev.title }, ev.short));
        }
      }

      if (cellDate && logsByDate[cellDate]) {
        const dayLogs = logsByDate[cellDate];
        const dotsWrap = el("div", { class: "cal-dots" });
        const seenDepts = new Set();
        for (const lg of dayLogs) {
          const dk = lg.deptKey === "all" ? "chief" : lg.deptKey;
          if (!seenDepts.has(dk) && DEPT_MAP[dk]) {
            seenDepts.add(dk);
            dotsWrap.appendChild(
              el("span", {
                class: "dot",
                style: { backgroundColor: DEPT_MAP[dk].color },
                title: DEPT_MAP[dk].label,
              })
            );
          }
        }
        dotsWrap.appendChild(el("span", { class: "cal-count" }, `${dayLogs.length}`));
        cell.appendChild(dotsWrap);
      }

      if (cellDate) {
        cell.addEventListener("click", () => {
          state.selectedDate = cellDate;
          state.selectedDept = "ALL";
          renderCalendar();
          renderSelectedDayReport();
          if (window.innerWidth <= 1024) {
            $("reportPanel").scrollIntoView({ behavior: "smooth", block: "start" });
          }
        });
      } else {
        cell.disabled = true;
      }
      grid.appendChild(cell);
    }
  }

  function renderDeptLegend() {
    const wrap = $("deptLegend");
    clearEl(wrap);
    for (const d of DEPTS) {
      const item = el("span", { class: "legend-item" });
      item.appendChild(el("span", { class: "dot", style: { backgroundColor: d.color } }));
      item.appendChild(el("span", null, d.short));
      wrap.appendChild(item);
    }
  }

  /* ==================== 선택일 보고서 & 매니저별 일지 ==================== */
  function renderSelectedDayReport() {
    const dateStr = state.selectedDate;
    const data = state.monthCache[state.currentMonth] || { logs: [], approvals: {} };
    const dayLogs = (data.logs || []).filter((l) => l.date === dateStr);
    const approval = (data.approvals && data.approvals[dateStr]) || {
      date: dateStr,
      approvedAt: "",
      approver: "",
      chiefNote: "",
      deptNotes: {},
    };

    $("reportDocTitle").textContent = `주누디자인 일일 총괄 업무보고서 — ${formatKoreanDate(dateStr)}`;
    $("reportDocMeta").textContent = `기록 건수: ${dayLogs.length}건 · 통합 허브: Google Sheets(일일_업무일지) 실시간 연동`;

    // 결재 도장 영역
    const stampCeo = $("stampCeo");
    clearEl(stampCeo);
    if (approval.approvedAt) {
      stampCeo.appendChild(el("div", { class: "stamp-approved" }, "승 인"));
      stampCeo.appendChild(el("div", { class: "stamp-date" }, approval.approvedAt.slice(5, 16)));
      $("approveBtn").textContent = "✅ 결재 승인됨 (재저장)";
    } else {
      stampCeo.appendChild(el("span", null, "결재 대기"));
      $("approveBtn").textContent = "✅ 대표님 결재 승인";
    }

    // 세무 일정 배너
    const taxBanner = $("dayTaxBanner");
    const taxEvents = getTaxEventsForMonth(dateStr.slice(0, 7)).filter((e) => e.date === dateStr);
    if (taxEvents.length) {
      taxBanner.textContent = "🗓️ " + taxEvents.map((e) => e.title).join(" / ");
      taxBanner.classList.remove("hidden");
    } else {
      taxBanner.classList.add("hidden");
    }

    // 부서별 그룹핑
    const grouped = {};
    for (const d of DEPTS) grouped[d.key] = [];
    for (const lg of dayLogs) {
      const k = lg.deptKey === "all" ? "chief" : (DEPT_MAP[lg.deptKey] ? lg.deptKey : "chief");
      grouped[k].push(lg);
    }

    // 부서 필터 탭
    const tabsWrap = $("deptTabs");
    clearEl(tabsWrap);
    const allTab = el("button", {
      type: "button",
      class: `dept-tab ${state.selectedDept === "ALL" ? "active" : ""}`,
    });
    allTab.appendChild(el("span", null, "전체 부서"));
    allTab.appendChild(el("span", { class: "cnt" }, `(${dayLogs.length})`));
    allTab.addEventListener("click", () => {
      state.selectedDept = "ALL";
      renderSelectedDayReport();
    });
    tabsWrap.appendChild(allTab);

    for (const d of DEPTS) {
      const cnt = grouped[d.key].length;
      const tab = el("button", {
        type: "button",
        class: `dept-tab ${state.selectedDept === d.key ? "active" : ""}`,
      });
      tab.appendChild(el("span", { class: "dot", style: { backgroundColor: d.color } }));
      tab.appendChild(el("span", null, d.short));
      tab.appendChild(el("span", { class: "cnt" }, `(${cnt})`));
      tab.addEventListener("click", () => {
        state.selectedDept = d.key;
        renderSelectedDayReport();
      });
      tabsWrap.appendChild(tab);
    }

    // 부서 카드 출력
    const cardsWrap = $("deptCards");
    clearEl(cardsWrap);

    const targetDepts = state.selectedDept === "ALL" ? DEPTS : DEPTS.filter((d) => d.key === state.selectedDept);
    let renderedCount = 0;

    for (const d of targetDepts) {
      const items = grouped[d.key];
      if (state.selectedDept === "ALL" && items.length === 0) continue;
      renderedCount++;

      const card = el("article", {
        class: "dept-card",
        style: { borderLeftColor: d.color },
      });

      const head = el("div", { class: "dept-card-head" });
      head.appendChild(el("span", { class: "dept-name" }, d.label));
      head.appendChild(el("span", { class: "dept-pill" }, `${items.length}건 기록`));
      card.appendChild(head);

      if (items.length === 0) {
        const empty = el("div", { style: { padding: "12px 14px", fontSize: "12.5px", color: "#64748B" } }, "이 날짜에는 해당 부서의 기록이 없습니다.");
        card.appendChild(empty);
      } else {
        const ul = el("ul", { class: "log-list" });
        for (const lg of items) {
          const li = el("li", { class: "log-row" });
          li.appendChild(el("span", { class: "log-time" }, lg.time || "--:--"));

          const body = el("div", { style: { flex: "1", minWidth: "0" } });
          if (lg.category) body.appendChild(el("span", { class: "log-cat" }, lg.category));

          const displayText = state.compactMode && lg.content.length > 90
            ? lg.content.slice(0, 90) + "…"
            : lg.content;
          body.appendChild(el("span", null, displayText));

          if (!state.compactMode && lg.pc) {
            body.appendChild(el("span", { class: "log-pc" }, `[${lg.pc}]`));
          }
          li.appendChild(body);
          ul.appendChild(li);
        }
        card.appendChild(ul);
      }

      // 부서별 대표님 개별 지시 메모
      const noteBar = el("div", { class: "dept-note-bar no-print" });
      const noteInput = el("input", {
        type: "text",
        "data-dept-note": d.key,
        placeholder: `${d.short} 담당 매니저에게 남길 지시 메모...`,
        value: (approval.deptNotes && approval.deptNotes[d.key]) || "",
      });
      noteBar.appendChild(noteInput);
      card.appendChild(noteBar);

      cardsWrap.appendChild(card);
    }

    if (renderedCount === 0) {
      const emptyBox = el("div", {
        style: {
          textAlign: "center",
          padding: "36px 16px",
          color: "#64748B",
          fontSize: "13.5px",
          border: "1px dashed #CBD5E1",
          borderRadius: "10px",
        },
      }, "이 날짜에는 아직 기록된 업무일지가 없습니다. 달력에서 점(●)이 표시된 날짜를 클릭해 보세요.");
      cardsWrap.appendChild(emptyBox);
    }

    $("chiefNoteInput").value = approval.chiefNote || "";
    $("approvalStatusText").textContent = approval.updatedAt
      ? `마지막 저장: ${approval.updatedAt}`
      : "저장 시 구글 시트(대표님_결재및지시)에 즉시 기록됩니다.";
  }

  function collectDeptNotesFromDom() {
    const notes = {};
    document.querySelectorAll("input[data-dept-note]").forEach((inp) => {
      const val = inp.value.trim();
      if (val) notes[inp.getAttribute("data-dept-note")] = val;
    });
    return notes;
  }

  async function saveApprovalOrNote(approveFlag) {
    const dateStr = state.selectedDate;
    const chiefNote = $("chiefNoteInput").value.trim();
    const deptNotes = collectDeptNotesFromDom();
    try {
      const res = await apiCall("saveApproval", {
        date: dateStr,
        approve: approveFlag,
        chiefNote,
        deptNotes,
      });
      if (!res.ok) throw new Error(res.error || "저장 실패");
      if (!state.monthCache[state.currentMonth]) state.monthCache[state.currentMonth] = { logs: [], approvals: {} };
      state.monthCache[state.currentMonth].approvals[dateStr] = res.approval;
      renderStats();
      renderCalendar();
      renderSelectedDayReport();
      showToast(approveFlag ? "✅ 대표님 전자결재가 승인되었습니다." : "💾 지시 메모가 저장되었습니다.");
    } catch (err) {
      showToast(err.message || "저장에 실패했습니다.");
    }
  }

  /* ==================== 이월 할 일 ==================== */
  function renderCarryovers() {
    const listWrap = $("carryoverList");
    clearEl(listWrap);
    const showDone = $("showDoneCarryChk").checked;
    const items = (state.carryovers || []).filter((c) => showDone || c.status !== "DONE");

    if (!items.length) {
      listWrap.appendChild(
        el("div", { style: { fontSize: "12.5px", color: "#64748B", padding: "8px 2px" } }, "미완료 이월 할 일이 없습니다.")
      );
      return;
    }

    for (const item of items) {
      const row = el("div", { class: `co-item ${item.status === "DONE" ? "done" : ""}` });
      const chk = el("input", { type: "checkbox" });
      chk.checked = item.status === "DONE";
      chk.addEventListener("change", async () => {
        try {
          const res = await apiCall("toggleCarryover", { id: item.id });
          if (!res.ok) throw new Error(res.error);
          state.carryovers = res.carryovers || [];
          renderStats();
          renderCarryovers();
        } catch (err) {
          showToast(err.message || "상태 변경 실패");
        }
      });

      const body = el("div", { class: "co-body" });
      body.appendChild(el("div", { class: "co-title" }, item.title));
      body.appendChild(
        el("div", { class: "co-meta" }, `${item.dept} · 등록일 ${item.sourceDate || "-"}${item.doneAt ? " · 완료 " + item.doneAt.slice(5, 16) : ""}`)
      );

      const delBtn = el("button", { type: "button", class: "btn btn-sm btn-danger", title: "삭제" }, "✕");
      delBtn.addEventListener("click", async () => {
        if (!confirm("이 이월 할 일을 삭제할까요?")) return;
        try {
          const res = await apiCall("deleteCarryover", { id: item.id });
          if (!res.ok) throw new Error(res.error);
          state.carryovers = res.carryovers || [];
          renderStats();
          renderCarryovers();
        } catch (err) {
          showToast(err.message || "삭제 실패");
        }
      });

      row.appendChild(chk);
      row.appendChild(body);
      row.appendChild(delBtn);
      listWrap.appendChild(row);
    }
  }

  /* ==================== 전체 기간 키워드 검색 ==================== */
  async function runSearch() {
    const query = $("searchQueryInput").value.trim();
    const dept = $("searchDeptSelect").value;
    if (!query && dept === "ALL") {
      showToast("검색어를 입력하거나 부서를 선택해 주세요.");
      return;
    }
    try {
      const res = await apiCall("searchLogs", { query, dept });
      if (!res.ok) throw new Error(res.error || "검색 실패");
      const box = $("searchResultsBox");
      clearEl(box);

      box.appendChild(
        el("div", { style: { fontWeight: "800", marginBottom: "8px", color: "#1B365D", fontSize: "13.5px" } },
          `🔍 검색 결과 ${res.count}건 (클릭하면 해당 날짜 보고서로 이동합니다)`)
      );

      if (!res.results.length) {
        box.appendChild(el("div", { style: { fontSize: "12.5px", color: "#64748B" } }, "일치하는 기록이 없습니다."));
      } else {
        for (const item of res.results) {
          const row = el("div", { class: "sr-item" });
          row.appendChild(
            el("div", { style: { fontSize: "12px", fontWeight: "700", color: "#1B365D" } },
              `${item.date} ${item.time || ""} · ${item.manager} ${item.category ? "[" + item.category + "]" : ""}`)
          );
          row.appendChild(el("div", { style: { fontSize: "12.5px", marginTop: "2px" } }, item.content));
          row.addEventListener("click", async () => {
            const targetYm = item.date.slice(0, 7);
            state.selectedDate = item.date;
            state.selectedDept = "ALL";
            await loadMonth(targetYm, false);
            box.classList.add("hidden");
            $("clearSearchBtn").classList.add("hidden");
          });
          box.appendChild(row);
        }
      }
      box.classList.remove("hidden");
      $("clearSearchBtn").classList.remove("hidden");
    } catch (err) {
      showToast(err.message || "검색 중 오류가 발생했습니다.");
    }
  }

  /* ==================== 대표님 전용 암호화 금고 (AES-256-GCM) ==================== */
  async function loadVault() {
    if (!state.vaultCryptoKey) return;
    try {
      const res = await apiCall("listVault");
      if (!res.ok) throw new Error(res.error || "금고 조회 실패");

      const decrypted = [];
      for (const raw of res.items || []) {
        decrypted.push({
          id: raw.id,
          category: raw.category || "기타",
          site: await decryptField(raw.siteEnc, state.vaultCryptoKey),
          url: raw.urlEnc ? await decryptField(raw.urlEnc, state.vaultCryptoKey) : "",
          user: await decryptField(raw.userEnc, state.vaultCryptoKey),
          pass: await decryptField(raw.passEnc, state.vaultCryptoKey),
          memo: raw.memoEnc ? await decryptField(raw.memoEnc, state.vaultCryptoKey) : "",
          updatedAt: raw.updatedAt || "",
        });
      }
      state.vaultItems = decrypted;
      renderVaultList();
    } catch (err) {
      showToast(err.message || "금고 복호화/조회 중 오류");
    }
  }

  function renderVaultList() {
    const wrap = $("vaultCards");
    clearEl(wrap);
    const cat = $("vaultFilterCat").value;
    const q = $("vaultSearchInput").value.trim().toLowerCase();

    const filtered = state.vaultItems.filter((it) => {
      if (cat !== "ALL" && it.category !== cat) return false;
      if (q) {
        const hay = `${it.site} ${it.user} ${it.memo} ${it.url}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    $("vaultCount").textContent = String(filtered.length);

    if (!filtered.length) {
      wrap.appendChild(
        el("div", { style: { fontSize: "13px", color: "#64748B", padding: "20px 6px" } },
          "보관된 계정이 없습니다. 왼쪽 폼에서 자주 쓰시는 아이디·비밀번호를 암호화해 저장해 보세요.")
      );
      return;
    }

    for (const item of filtered) {
      const card = el("article", { class: "vault-card" });

      const head = el("div", { class: "vault-card-head" });
      head.appendChild(el("span", { class: "vault-site" }, item.site));
      head.appendChild(el("span", { class: "vault-cat" }, item.category));
      card.appendChild(head);

      if (item.url && isSafeHttpUrl(item.url)) {
        const a = el("a", {
          class: "vault-link",
          href: item.url,
          target: "_blank",
          rel: "noopener noreferrer",
        }, `🔗 ${item.url}`);
        card.appendChild(a);
      }

      // 아이디 행
      const uRow = el("div", { class: "vault-row" });
      uRow.appendChild(el("span", { style: { fontSize: "11px", color: "#64748B", fontWeight: "700" } }, "ID"));
      uRow.appendChild(el("span", { class: "vault-val" }, item.user));
      const copyUBtn = el("button", { type: "button", class: "btn btn-sm" }, "복사");
      copyUBtn.addEventListener("click", () => copySecret(item.user, "아이디"));
      uRow.appendChild(copyUBtn);
      card.appendChild(uRow);

      // 비밀번호 행 (기본 마스킹)
      const isShown = state.revealedVaultIds.has(item.id);
      const pRow = el("div", { class: "vault-row" });
      pRow.appendChild(el("span", { style: { fontSize: "11px", color: "#64748B", fontWeight: "700" } }, "PW"));
      pRow.appendChild(el("span", { class: "vault-val" }, isShown ? item.pass : "••••••••••"));

      const eyeBtn = el("button", { type: "button", class: "btn btn-sm", title: "비밀번호 보기/숨기기" }, isShown ? "숨김" : "보기");
      eyeBtn.addEventListener("click", () => {
        if (state.revealedVaultIds.has(item.id)) state.revealedVaultIds.delete(item.id);
        else state.revealedVaultIds.add(item.id);
        renderVaultList();
      });

      const copyPBtn = el("button", { type: "button", class: "btn btn-sm btn-primary" }, "복사");
      copyPBtn.addEventListener("click", () => copySecret(item.pass, "비밀번호"));

      pRow.appendChild(eyeBtn);
      pRow.appendChild(copyPBtn);
      card.appendChild(pRow);

      if (item.memo) {
        card.appendChild(el("div", { class: "vault-memo" }, item.memo));
      }

      const actions = el("div", { class: "vault-actions" });
      const editBtn = el("button", { type: "button", class: "btn btn-sm" }, "수정");
      editBtn.addEventListener("click", () => startEditVault(item));

      const delBtn = el("button", { type: "button", class: "btn btn-sm btn-danger" }, "삭제");
      delBtn.addEventListener("click", () => deleteVault(item));

      actions.appendChild(editBtn);
      actions.appendChild(delBtn);
      card.appendChild(actions);

      wrap.appendChild(card);
    }
  }

  async function copySecret(value, label) {
    try {
      await navigator.clipboard.writeText(value);
      showToast(`📋 ${label} 복사 완료! (보안을 위해 사용 후 클립보드 주의)`);
    } catch {
      showToast("클립보드 복사에 실패했습니다.");
    }
  }

  function startEditVault(item) {
    $("vaultEditId").value = item.id;
    $("vaultCategory").value = item.category;
    $("vaultSite").value = item.site;
    $("vaultUrl").value = item.url;
    $("vaultUser").value = item.user;
    $("vaultPass").value = item.pass;
    $("vaultMemo").value = item.memo;
    $("vaultFormTitle").textContent = "계정 정보 수정";
    $("vaultSaveBtn").textContent = "🔐 암호화하여 수정 저장";
    $("vaultResetBtn").classList.remove("hidden");
    $("vaultSite").focus();
  }

  function resetVaultForm() {
    $("vaultForm").reset();
    $("vaultEditId").value = "";
    $("vaultPass").type = "password";
    $("vaultFormTitle").textContent = "새 계정 안전 등록";
    $("vaultSaveBtn").textContent = "🔐 암호화하여 저장";
    $("vaultResetBtn").classList.add("hidden");
  }

  async function handleVaultSubmit(e) {
    e.preventDefault();
    if (!state.vaultCryptoKey) return;

    const id = $("vaultEditId").value.trim();
    const category = $("vaultCategory").value;
    const site = $("vaultSite").value.trim();
    const url = $("vaultUrl").value.trim();
    const user = $("vaultUser").value.trim();
    const pass = $("vaultPass").value;
    const memo = $("vaultMemo").value.trim();

    if (!site || !user || !pass) {
      showToast("사이트명, 아이디, 비밀번호는 필수입니다.");
      return;
    }
    if (url && !isSafeHttpUrl(url)) {
      showToast("접속 주소는 http:// 또는 https:// 로 시작해야 합니다.");
      return;
    }

    try {
      const encItem = {
        id,
        category,
        siteEnc: await encryptField(site, state.vaultCryptoKey),
        urlEnc: url ? await encryptField(url, state.vaultCryptoKey) : "",
        userEnc: await encryptField(user, state.vaultCryptoKey),
        passEnc: await encryptField(pass, state.vaultCryptoKey),
        memoEnc: memo ? await encryptField(memo, state.vaultCryptoKey) : "",
      };
      const res = await apiCall("saveVaultItem", { item: encItem });
      if (!res.ok) throw new Error(res.error || "금고 저장 실패");
      resetVaultForm();
      await loadVault();
      showToast("🔐 AES-256 암호화되어 안전하게 저장되었습니다.");
    } catch (err) {
      showToast(err.message || "금고 저장 중 오류가 발생했습니다.");
    }
  }

  async function deleteVault(item) {
    if (!confirm(`[${item.site}] 계정 정보를 금고에서 영구 삭제할까요?`)) return;
    try {
      const res = await apiCall("deleteVaultItem", { id: item.id });
      if (!res.ok) throw new Error(res.error || "삭제 실패");
      state.revealedVaultIds.delete(item.id);
      await loadVault();
      showToast("삭제되었습니다.");
    } catch (err) {
      showToast(err.message || "삭제 중 오류");
    }
  }

  /* ==================== 이벤트 바인딩 ==================== */
  function bindEvents() {
    // 키패드 입력
    $("keypad").addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-key]");
      if (!btn || state.busyLogin) return;
      const key = btn.getAttribute("data-key");
      if (key === "clear") state.pinBuf = "";
      else if (key === "back") state.pinBuf = state.pinBuf.slice(0, -1);
      else if (/^\d$/.test(key) && state.pinBuf.length < 6) state.pinBuf += key;
      renderPinDots(false);
      if (state.pinBuf.length === 6) submitPin();
    });

    // 키보드 숫자 입력 지원 (잠금 화면일 때만)
    document.addEventListener("keydown", (e) => {
      if ($("lockScreen").classList.contains("hidden")) {
        touchActivity();
        return;
      }
      if (document.activeElement && document.activeElement.tagName === "INPUT") return;
      if (/^\d$/.test(e.key) && state.pinBuf.length < 6) {
        state.pinBuf += e.key;
        renderPinDots(false);
        if (state.pinBuf.length === 6) submitPin();
      } else if (e.key === "Backspace") {
        state.pinBuf = state.pinBuf.slice(0, -1);
        renderPinDots(false);
      } else if (e.key === "Escape") {
        state.pinBuf = "";
        renderPinDots(false);
      }
    });

    // 활동 감지 (자동 잠금 리셋)
    ["click", "mousemove", "touchstart", "scroll"].forEach((evt) => {
      document.addEventListener(evt, touchActivity, { passive: true });
    });

    // GAS 서버 URL 설정창
    $("toggleServerBtn").addEventListener("click", () => {
      $("serverForm").classList.toggle("hidden");
      $("gasUrlInput").value = getGasUrl();
    });

    $("saveGasUrlBtn").addEventListener("click", async () => {
      const url = $("gasUrlInput").value.trim();
      if (!/^https:\/\/script\.google\.com\/macros\/s\/.+\/exec$/i.test(url)) {
        $("serverStatusText").textContent = "⚠️ https://script.google.com/macros/s/.../exec 형식의 URL을 입력해 주세요.";
        return;
      }
      localStorage.setItem(STORAGE_GAS_URL, url);
      $("serverStatusText").textContent = "연결 테스트 중...";
      try {
        const res = await apiCall("ping", {}, true);
        if (res.ok) {
          $("serverStatusText").textContent = `✅ 연결 성공! (서버 v${res.version} · 초기보안설정: ${res.configured ? "완료" : "미실행"})`;
          setLockMsg("서버 연결이 완료되었습니다. 6자리 비밀번호를 입력해 주세요.", true);
        } else {
          $("serverStatusText").textContent = "⚠️ 응답 확인 실패";
        }
      } catch (err) {
        $("serverStatusText").textContent = `❌ 연결 실패: ${err.message}`;
      }
    });

    // 상단 메뉴 탭 전환
    document.querySelectorAll(".nav-tab").forEach((btn) => {
      btn.addEventListener("click", () => {
        const view = btn.getAttribute("data-view");
        state.currentView = view;
        document.querySelectorAll(".nav-tab").forEach((b) => b.classList.toggle("active", b === btn));
        $("reportView").classList.toggle("hidden", view !== "report");
        $("vaultView").classList.toggle("hidden", view !== "vault");
        if (view === "vault") loadVault();
      });
    });

    $("refreshBtn").addEventListener("click", () => {
      if (state.currentView === "report") loadMonth(state.currentMonth, true);
      else loadVault();
      showToast("최신 데이터로 새로고침했습니다.");
    });

    $("lockNowBtn").addEventListener("click", () => lockApp("대표님이 화면을 잠갔습니다."));

    // 달력 월 이동
    $("prevMonthBtn").addEventListener("click", () => {
      const [y, m] = state.currentMonth.split("-").map(Number);
      const next = m === 1 ? `${y - 1}-12` : `${y}-${String(m - 1).padStart(2, "0")}`;
      loadMonth(next, false);
    });
    $("nextMonthBtn").addEventListener("click", () => {
      const [y, m] = state.currentMonth.split("-").map(Number);
      const next = m === 12 ? `${y + 1}-01` : `${y}-${String(m + 1).padStart(2, "0")}`;
      loadMonth(next, false);
    });
    $("todayBtn").addEventListener("click", () => {
      const t = todayStr();
      state.selectedDate = t;
      loadMonth(t.slice(0, 7), false);
    });

    // 보고서 툴바
    $("toggleCompactBtn").addEventListener("click", () => {
      state.compactMode = !state.compactMode;
      $("toggleCompactBtn").textContent = state.compactMode ? "전체 상세 보기" : "핵심 요약 모드";
      renderSelectedDayReport();
    });
    $("approveBtn").addEventListener("click", () => saveApprovalOrNote(true));
    $("saveNoteBtn").addEventListener("click", () => saveApprovalOrNote(false));
    $("printReportBtn").addEventListener("click", () => {
      // 인쇄 직전 금고 뷰 강제 비노출 보장
      if (state.currentView !== "report") {
        showToast("업무보고서 화면에서만 A4 인쇄가 가능합니다.");
        return;
      }
      window.print();
    });

    // 이월 할 일 추가
    $("carryoverForm").addEventListener("submit", async (e) => {
      e.preventDefault();
      const title = $("coTitleInput").value.trim();
      const dept = $("coDeptSelect").value;
      if (!title) return;
      try {
        const res = await apiCall("upsertCarryover", {
          sourceDate: state.selectedDate,
          dept,
          title,
          status: "OPEN",
        });
        if (!res.ok) throw new Error(res.error);
        $("coTitleInput").value = "";
        state.carryovers = res.carryovers || [];
        renderStats();
        renderCarryovers();
        showToast("📌 이월 할 일이 등록되었습니다.");
      } catch (err) {
        showToast(err.message || "등록 실패");
      }
    });
    $("showDoneCarryChk").addEventListener("change", renderCarryovers);

    // 통합 검색
    $("searchBtn").addEventListener("click", runSearch);
    $("searchQueryInput").addEventListener("keydown", (e) => {
      if (e.key === "Enter") runSearch();
    });
    $("clearSearchBtn").addEventListener("click", () => {
      $("searchResultsBox").classList.add("hidden");
      $("clearSearchBtn").classList.add("hidden");
    });

    // 암호화 금고 폼 & 필터
    $("vaultForm").addEventListener("submit", handleVaultSubmit);
    $("vaultResetBtn").addEventListener("click", resetVaultForm);
    $("toggleFormPassBtn").addEventListener("click", () => {
      const inp = $("vaultPass");
      inp.type = inp.type === "password" ? "text" : "password";
    });
    $("vaultFilterCat").addEventListener("change", renderVaultList);
    $("vaultSearchInput").addEventListener("input", renderVaultList);
  }

  /* ==================== 초기화 ==================== */
  async function init() {
    renderDeptLegend();
    bindEvents();

    if (!getGasUrl()) {
      $("serverForm").classList.remove("hidden");
      setLockMsg("최초 1회: 아래에 구글 서버(GAS) 웹앱 주소를 저장해 주세요.", true);
    }

    // 동일 탭 새로고침 시 세션 유지 (창 닫으면 자동 소멸)
    const savedToken = sessionStorage.getItem(SESSION_TOKEN_KEY);
    const savedVkey = sessionStorage.getItem(SESSION_VKEY_KEY);
    if (savedToken && savedVkey && getGasUrl()) {
      try {
        state.vaultCryptoKey = await importVaultKey(savedVkey);
        state.token = savedToken;
        enterApp();
      } catch {
        sessionStorage.removeItem(SESSION_TOKEN_KEY);
        sessionStorage.removeItem(SESSION_VKEY_KEY);
      }
    }
  }

  init();
})();
