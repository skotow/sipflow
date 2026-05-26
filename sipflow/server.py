from __future__ import annotations

import argparse
import hmac
import json
import os
import queue
import secrets
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from .capture import CaptureConfig, PacketCapture, list_interfaces
from .pcap import PcapImportConfig, import_pcap
from .rtp import RtpPacket
from .sip import CallStore, SipMessage


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SIPFLOW</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f7f8fa;
      --panel: #ffffff;
      --panel-2: #f1f4f8;
      --text: #172033;
      --muted: #657085;
      --line: #d8dee8;
      --accent: #007c89;
      --accent-2: #2357c5;
      --good: #087f5b;
      --warn: #a35f00;
      --bad: #c92a2a;
      --shadow: 0 8px 24px rgba(22, 32, 51, .08);
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 14px;
    }

    button, input, select {
      font: inherit;
    }

    button {
      border: 1px solid var(--line);
      border-radius: 6px;
      background: var(--panel);
      color: var(--text);
      min-height: 34px;
      padding: 0 12px;
      cursor: pointer;
    }

    button.primary {
      background: var(--accent);
      border-color: var(--accent);
      color: #fff;
    }

    button.danger {
      border-color: #f0b8b8;
      color: var(--bad);
    }

    button:disabled {
      cursor: not-allowed;
      opacity: .55;
    }

    input, select {
      width: 100%;
      min-height: 34px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--text);
      padding: 0 10px;
    }

    input[type="file"] {
      display: none;
    }

    .app {
      min-height: 100vh;
      display: grid;
      grid-template-rows: auto 1fr;
    }

    .topbar {
      display: grid;
      grid-template-columns: auto 1fr auto;
      gap: 16px;
      align-items: center;
      min-height: 64px;
      padding: 12px 18px;
      background: var(--panel);
      border-bottom: 1px solid var(--line);
      position: sticky;
      top: 0;
      z-index: 5;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
      min-width: 132px;
    }

    .brand-mark {
      width: 32px;
      height: 32px;
      border-radius: 7px;
      background: linear-gradient(135deg, #007c89, #3c78d8);
      display: grid;
      place-items: center;
      color: #fff;
      font-weight: 800;
    }

    .brand-title {
      font-size: 18px;
      font-weight: 760;
      letter-spacing: 0;
    }

    .capture-form {
      display: grid;
      grid-template-columns: minmax(180px, 260px) 110px minmax(260px, 1fr) repeat(4, auto);
      gap: 10px;
      align-items: center;
    }

    .ignore-group {
      display: flex;
      align-items: center;
      gap: 6px;
      min-height: 34px;
      overflow-x: auto;
      white-space: nowrap;
    }

    .check {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      min-height: 30px;
      color: var(--muted);
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 0 10px 0 8px;
      white-space: nowrap;
    }

    .check input {
      width: 16px;
      min-height: 16px;
    }

    .status-strip {
      display: flex;
      align-items: center;
      gap: 8px;
      color: var(--muted);
      justify-self: end;
      white-space: nowrap;
    }

    .dot {
      width: 9px;
      height: 9px;
      border-radius: 99px;
      background: var(--muted);
    }

    .dot.on { background: var(--good); }
    .dot.err { background: var(--bad); }

    .workspace {
      display: grid;
      grid-template-columns: minmax(380px, 44%) 1fr;
      gap: 14px;
      padding: 14px;
      min-height: 0;
    }

    .pane {
      min-height: 0;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }

    .pane-head {
      display: grid;
      grid-template-columns: 1fr auto;
      gap: 12px;
      align-items: center;
      min-height: 54px;
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
      background: #fbfcfe;
    }

    .pane-title {
      font-size: 15px;
      font-weight: 740;
    }

    .metric-row {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      border-bottom: 1px solid var(--line);
      background: var(--panel-2);
    }

    .metric {
      padding: 10px 12px;
      border-right: 1px solid var(--line);
    }

    .metric:last-child { border-right: 0; }

    .metric-value {
      font-size: 20px;
      line-height: 1.1;
      font-weight: 760;
    }

    .metric-label {
      margin-top: 3px;
      color: var(--muted);
      font-size: 12px;
    }

    .filters {
      display: grid;
      grid-template-columns: 1fr 150px;
      gap: 8px;
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
    }

    .table-wrap {
      overflow: auto;
      min-height: 0;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      table-layout: fixed;
    }

    th {
      position: sticky;
      top: 0;
      z-index: 1;
      background: #f8fafc;
      color: var(--muted);
      text-align: left;
      font-size: 12px;
      font-weight: 650;
      border-bottom: 1px solid var(--line);
      padding: 9px 10px;
    }

    td {
      border-bottom: 1px solid #edf0f5;
      padding: 10px;
      vertical-align: top;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    tr.call-row {
      cursor: pointer;
    }

    tr.call-row:hover {
      background: #f4f8fb;
    }

    tr.call-row.selected {
      background: #e9f7f8;
      box-shadow: inset 3px 0 0 var(--accent);
    }

    .pill {
      display: inline-flex;
      align-items: center;
      min-height: 22px;
      border-radius: 999px;
      padding: 0 8px;
      background: #edf2f7;
      color: #334155;
      font-size: 12px;
      font-weight: 680;
      white-space: nowrap;
    }

    .pill.good { background: #dff5ec; color: var(--good); }
    .pill.warn { background: #fff0d6; color: var(--warn); }
    .pill.bad { background: #ffe3e3; color: var(--bad); }
    .pill.info { background: #e1efff; color: var(--accent-2); }

    .small {
      color: var(--muted);
      font-size: 12px;
    }

    .detail-empty {
      display: grid;
      place-items: center;
      min-height: 240px;
      color: var(--muted);
      padding: 24px;
      text-align: center;
    }

    .detail-body {
      overflow: auto;
      min-height: 0;
      padding: 12px;
      display: grid;
      gap: 12px;
    }

    .summary-grid {
      display: grid;
      grid-template-columns: repeat(3, minmax(0, 1fr));
      gap: 10px;
    }

    .summary-item {
      border: 1px solid var(--line);
      border-radius: 7px;
      padding: 9px 10px;
      background: #fff;
      min-width: 0;
    }

    .summary-label {
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 4px;
    }

    .summary-value {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-weight: 650;
    }

    .ladder {
      border: 1px solid var(--line);
      border-radius: 7px;
      background: #fff;
      overflow: auto;
    }

    .ladder-head, .ladder-row {
      display: grid;
      grid-template-columns: 150px minmax(140px, 1fr) minmax(160px, 1.2fr) minmax(140px, 1fr);
      align-items: center;
      min-width: 760px;
    }

    .ladder-head {
      background: #f8fafc;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      border-bottom: 1px solid var(--line);
    }

    .ladder-head div, .ladder-row div {
      padding: 8px 10px;
    }

    .ladder-row {
      border-bottom: 1px solid #edf0f5;
      cursor: pointer;
    }

    .ladder-row:last-child { border-bottom: 0; }
    .ladder-row:hover { background: #f4f8fb; }
    .ladder-row.selected { background: #e9f7f8; }

    .arrow {
      display: grid;
      grid-template-columns: 1fr auto 1fr;
      align-items: center;
      gap: 8px;
      color: var(--accent-2);
      font-weight: 760;
      white-space: nowrap;
    }

    .arrow::before, .arrow::after {
      content: "";
      height: 1px;
      background: #9ab1d9;
    }

    .sip-ladder {
      border: 1px solid var(--line);
      border-radius: 7px;
      background: #fff;
      overflow: auto;
    }

    .sip-ladder-head, .sip-ladder-row {
      display: grid;
      grid-template-columns: 112px minmax(160px, 1fr) minmax(220px, 1.5fr) minmax(160px, 1fr);
      align-items: center;
      min-width: 820px;
    }

    .sip-ladder-head {
      background: #f8fafc;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      border-bottom: 1px solid var(--line);
    }

    .sip-ladder-head div, .sip-ladder-row div {
      padding: 8px 10px;
    }

    .sip-ladder-row {
      border-bottom: 1px solid #edf0f5;
      cursor: pointer;
    }

    .sip-ladder-row:last-child { border-bottom: 0; }
    .sip-ladder-row:hover { background: #f4f8fb; }
    .sip-ladder-row.selected { background: #e9f7f8; }

    .endpoint-cell {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      color: #26364f;
    }

    .endpoint-cell.active {
      color: var(--text);
      font-weight: 720;
    }

    .flow-arrow {
      display: grid;
      grid-template-columns: 1fr auto 1fr;
      align-items: center;
      gap: 8px;
      color: var(--accent-2);
      font-weight: 760;
      white-space: nowrap;
      min-width: 0;
    }

    .flow-arrow::before,
    .flow-arrow::after {
      content: "";
      height: 1px;
      background: #9ab1d9;
    }

    .flow-arrow span {
      justify-self: center;
      overflow: hidden;
      text-overflow: ellipsis;
      text-align: center;
    }

    .inspector {
      border: 1px solid var(--line);
      border-radius: 7px;
      overflow: hidden;
      background: #fff;
    }

    .inspector-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 9px 10px;
      border-bottom: 1px solid var(--line);
      background: #f8fafc;
    }

    pre {
      margin: 0;
      padding: 12px;
      overflow: auto;
      color: #152033;
      background: #fbfcfe;
      font: 12px/1.5 Consolas, "Cascadia Mono", ui-monospace, monospace;
      white-space: pre-wrap;
      word-break: break-word;
      max-height: 340px;
    }

    audio {
      width: min(260px, 100%);
      height: 32px;
      display: block;
    }

    .notice {
      color: var(--bad);
      min-height: 18px;
      font-size: 12px;
      padding: 0 2px;
    }

    @media (max-width: 1040px) {
      .topbar {
        grid-template-columns: 1fr;
      }

      .capture-form {
        grid-template-columns: 1fr 100px;
      }

      .ignore-group {
        grid-column: 1 / -1;
      }

      .status-strip {
        justify-self: start;
      }

      .workspace {
        grid-template-columns: 1fr;
      }
    }

    @media (max-width: 640px) {
      .capture-form,
      .filters,
      .summary-grid,
      .metric-row {
        grid-template-columns: 1fr;
      }

      .metric {
        border-right: 0;
        border-bottom: 1px solid var(--line);
      }

      .metric:last-child { border-bottom: 0; }
      .workspace { padding: 8px; }
      .pane { border-radius: 6px; }
    }
  </style>
</head>
<body>
  <div class="app">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark">SF</div>
        <div>
          <div class="brand-title">SIPFLOW</div>
          <div class="small">Live SIP capture</div>
        </div>
      </div>

      <form class="capture-form" id="captureForm">
        <select id="interfaceSelect" aria-label="Capture interface"></select>
        <input id="portsInput" aria-label="SIP ports" value="5060" />
        <div class="ignore-group" aria-label="Ignored SIP methods">
          <label class="check"><input class="ignore-method" type="checkbox" value="OPTIONS" checked /> OPTIONS</label>
          <label class="check"><input class="ignore-method" type="checkbox" value="REGISTER" /> REGISTER</label>
          <label class="check"><input class="ignore-method" type="checkbox" value="SUBSCRIBE" /> SUBSCRIBE</label>
          <label class="check"><input class="ignore-method" type="checkbox" value="NOTIFY" /> NOTIFY</label>
          <label class="check"><input class="ignore-method" type="checkbox" value="MESSAGE" /> MESSAGE</label>
        </div>
        <label class="check" title="Records G.711 RTP payloads for browser playback. Off by default."><input id="recordAudio" type="checkbox" /> Record audio</label>
        <button class="primary" id="startButton" type="submit">Start</button>
        <button class="danger" id="stopButton" type="button">Stop</button>
        <button id="clearButton" type="button">Clear</button>
        <button id="importButton" type="button">Import PCAP</button>
        <input id="pcapInput" type="file" accept=".pcap,.pcapng,.cap,.pcap.gz,application/vnd.tcpdump.pcap" />
        <button id="logoutButton" type="button">Logout</button>
        <div class="notice" id="notice"></div>
      </form>

      <div class="status-strip">
        <span class="dot" id="statusDot"></span>
        <span id="statusText">Connecting</span>
      </div>
    </header>

    <main class="workspace">
      <section class="pane">
        <div class="pane-head">
          <div>
            <div class="pane-title">Calls</div>
            <div class="small" id="eventStatus">Event stream idle</div>
          </div>
          <button id="refreshButton" type="button">Refresh</button>
        </div>

        <div class="metric-row">
          <div class="metric"><div class="metric-value" id="totalMetric">0</div><div class="metric-label">Total</div></div>
          <div class="metric"><div class="metric-value" id="activeMetric">0</div><div class="metric-label">Active</div></div>
          <div class="metric"><div class="metric-value" id="failedMetric">0</div><div class="metric-label">Failed</div></div>
          <div class="metric"><div class="metric-value" id="keepaliveMetric">0</div><div class="metric-label">Keepalive</div></div>
        </div>

        <div class="filters">
          <input id="searchInput" placeholder="Search caller, callee, IP, Call-ID" />
          <select id="stateFilter">
            <option value="">All states</option>
            <option value="calling">Calling</option>
            <option value="ringing">Ringing</option>
            <option value="answered">Answered</option>
            <option value="confirmed">Confirmed</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="keepalive">Keepalive</option>
            <option value="registration">Registration</option>
            <option value="registered">Registered</option>
          </select>
        </div>

        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th style="width: 88px;">State</th>
                <th style="width: 86px;">Method</th>
                <th>Caller</th>
                <th>Callee</th>
                <th style="width: 76px;">Msgs</th>
              </tr>
            </thead>
            <tbody id="callsTable"></tbody>
          </table>
        </div>
      </section>

      <section class="pane">
        <div class="pane-head">
          <div>
            <div class="pane-title" id="detailTitle">Call detail</div>
            <div class="small" id="detailSubtitle">Select a call from the list</div>
          </div>
          <span class="pill" id="detailState">Idle</span>
        </div>
        <div id="detail"></div>
      </section>
    </main>
  </div>

  <script>
    const state = {
      calls: new Map(),
      selectedCallId: null,
      selectedMessageIndex: 0,
      eventSource: null,
      renderTimer: null,
      capture: { running: false, status: 'unknown', error: null }
    };

    const els = {
      interfaceSelect: document.querySelector('#interfaceSelect'),
      portsInput: document.querySelector('#portsInput'),
      ignoreMethods: document.querySelectorAll('.ignore-method'),
      recordAudio: document.querySelector('#recordAudio'),
      captureForm: document.querySelector('#captureForm'),
      startButton: document.querySelector('#startButton'),
      stopButton: document.querySelector('#stopButton'),
      clearButton: document.querySelector('#clearButton'),
      importButton: document.querySelector('#importButton'),
      pcapInput: document.querySelector('#pcapInput'),
      logoutButton: document.querySelector('#logoutButton'),
      refreshButton: document.querySelector('#refreshButton'),
      notice: document.querySelector('#notice'),
      statusDot: document.querySelector('#statusDot'),
      statusText: document.querySelector('#statusText'),
      eventStatus: document.querySelector('#eventStatus'),
      searchInput: document.querySelector('#searchInput'),
      stateFilter: document.querySelector('#stateFilter'),
      callsTable: document.querySelector('#callsTable'),
      detail: document.querySelector('#detail'),
      detailTitle: document.querySelector('#detailTitle'),
      detailSubtitle: document.querySelector('#detailSubtitle'),
      detailState: document.querySelector('#detailState'),
      totalMetric: document.querySelector('#totalMetric'),
      activeMetric: document.querySelector('#activeMetric'),
      failedMetric: document.querySelector('#failedMetric'),
      keepaliveMetric: document.querySelector('#keepaliveMetric')
    };

    function escapeHtml(value) {
      return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
      }[char]));
    }

    function shortSip(value) {
      if (!value) return '';
      const match = String(value).match(/sip:([^@>;]+)/i);
      return match ? match[1] : String(value).replace(/[<>]/g, '');
    }

    function stateClass(value) {
      if (['answered', 'confirmed', 'completed', 'registered'].includes(value)) return 'good';
      if (['failed', 'canceled'].includes(value)) return 'bad';
      if (['calling', 'ringing'].includes(value)) return 'warn';
      if (['keepalive', 'registration'].includes(value)) return 'info';
      return '';
    }

    function messageLabel(message) {
      if (!message) return '';
      if (message.method) return message.method;
      const suffix = message.cseqMethod ? ` ${message.cseqMethod}` : '';
      return `${message.statusCode || ''} ${message.reason || ''}${suffix}`.trim();
    }

    function formatTime(value) {
      if (!value) return '';
      try {
        return new Date(value).toLocaleTimeString();
      } catch {
        return value;
      }
    }

    function endpointHost(value) {
      return String(value || '').split(':')[0];
    }

    function callColumns(messages) {
      const counts = new Map();
      messages.forEach(message => {
        [message.src, message.dst].forEach(endpoint => {
          counts.set(endpoint, (counts.get(endpoint) || 0) + 1);
        });
      });
      return Array.from(counts.entries())
        .sort((a, b) => b[1] - a[1])
        .map(item => item[0])
        .slice(0, 2);
    }

    function flowDirection(message, leftEndpoint, rightEndpoint) {
      if (message.src === leftEndpoint && message.dst === rightEndpoint) return 'right';
      if (message.src === rightEndpoint && message.dst === leftEndpoint) return 'left';

      const srcHost = endpointHost(message.src);
      const dstHost = endpointHost(message.dst);
      if (srcHost === endpointHost(leftEndpoint) && dstHost === endpointHost(rightEndpoint)) return 'right';
      if (srcHost === endpointHost(rightEndpoint) && dstHost === endpointHost(leftEndpoint)) return 'left';
      return 'right';
    }

    function flowLabel(message, direction) {
      return direction === 'left'
        ? `← ${messageLabel(message)}`
        : `${messageLabel(message)} →`;
    }

    function searchable(call) {
      return [
        call.id,
        call.state,
        call.initialMethod,
        call.caller,
        call.callee,
        call.lastSummary,
        ...(call.participants || [])
      ].join(' ').toLowerCase();
    }

    function selectedIgnoredMethods() {
      return Array.from(els.ignoreMethods)
        .filter(item => item.checked)
        .map(item => item.value);
    }

    function callMethod(call) {
      return String(call.initialMethod || '').toUpperCase();
    }

    function isCallIgnoredInView(call) {
      const ignored = new Set(selectedIgnoredMethods());
      if (ignored.has(callMethod(call))) {
        return true;
      }
      if (call.state === 'keepalive' && ignored.has('OPTIONS')) {
        return true;
      }
      return false;
    }

    async function api(path, options = {}) {
      const response = await fetch(path, {
        headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
        ...options
      });
      const text = await response.text();
      const data = text ? JSON.parse(text) : {};
      if (!response.ok) {
        throw new Error(data.error || response.statusText);
      }
      return data;
    }

    async function loadInterfaces() {
      const data = await api('/api/interfaces');
      els.interfaceSelect.innerHTML = data.interfaces.map(item =>
        `<option value="${escapeHtml(item.ip)}">${escapeHtml(item.name)} (${escapeHtml(item.ip)})</option>`
      ).join('');
    }

    async function loadStatus() {
      state.capture = await api('/api/capture/status');
      renderStatus();
    }

    async function loadCalls() {
      const data = await api('/api/calls');
      state.calls = new Map(data.calls.map(call => [call.id, call]));
      if (state.selectedCallId && !state.calls.has(state.selectedCallId)) {
        state.selectedCallId = null;
      }
      render();
    }

    function connectEvents() {
      if (state.eventSource) {
        state.eventSource.close();
      }
      const source = new EventSource('/api/events');
      state.eventSource = source;
      source.onopen = () => {
        els.eventStatus.textContent = 'Event stream connected';
      };
      source.onerror = () => {
        els.eventStatus.textContent = 'Event stream reconnecting';
      };
      source.onmessage = event => {
        const data = JSON.parse(event.data);
        if ((data.type === 'sip_message' || data.type === 'rtp_packet') && data.call) {
          state.calls.set(data.call.id, data.call);
          if (!state.selectedCallId) {
            state.selectedCallId = data.call.id;
          }
          scheduleRender(data.type === 'rtp_packet');
        }
        if (data.type === 'calls_cleared') {
          state.calls.clear();
          state.selectedCallId = null;
          render();
        }
      };
    }

    function renderStatus() {
      els.statusDot.className = 'dot';
      if (state.capture.running) {
        els.statusDot.classList.add('on');
      }
      if (state.capture.status === 'error') {
        els.statusDot.classList.add('err');
      }
      els.statusText.textContent = state.capture.running ? 'Capture running' : state.capture.status || 'Stopped';
      els.startButton.disabled = state.capture.running;
      els.stopButton.disabled = !state.capture.running;
      els.notice.textContent = state.capture.error || '';
    }

    function renderMetrics(calls) {
      els.totalMetric.textContent = calls.length;
      els.activeMetric.textContent = calls.filter(call => ['calling', 'ringing', 'answered', 'confirmed'].includes(call.state)).length;
      els.failedMetric.textContent = calls.filter(call => call.state === 'failed').length;
      els.keepaliveMetric.textContent = calls.filter(call => call.state === 'keepalive').length;
    }

    function renderCalls() {
      const query = els.searchInput.value.trim().toLowerCase();
      const filter = els.stateFilter.value;
      const calls = Array.from(state.calls.values());

      const visible = calls.filter(call => {
        if (isCallIgnoredInView(call)) return false;
        if (filter && call.state !== filter) return false;
        if (query && !searchable(call).includes(query)) return false;
        return true;
      }).sort((a, b) => new Date(b.lastSeenAt || 0) - new Date(a.lastSeenAt || 0));

      if (state.selectedCallId && !visible.some(call => call.id === state.selectedCallId)) {
        state.selectedCallId = visible[0]?.id || null;
        state.selectedMessageIndex = 0;
      }

      renderMetrics(visible);

      els.callsTable.innerHTML = visible.map(call => `
        <tr class="call-row ${call.id === state.selectedCallId ? 'selected' : ''}" data-call-id="${escapeHtml(call.id)}">
          <td><span class="pill ${stateClass(call.state)}">${escapeHtml(call.state || 'unknown')}</span></td>
          <td>${escapeHtml(call.initialMethod || '')}<div class="small">${escapeHtml(call.lastSummary || '')}</div></td>
          <td title="${escapeHtml(call.caller || '')}">${escapeHtml(shortSip(call.caller) || '-')}</td>
          <td title="${escapeHtml(call.callee || '')}">${escapeHtml(shortSip(call.callee) || '-')}<div class="small">${escapeHtml(formatTime(call.lastSeenAt))}</div></td>
          <td>${escapeHtml(call.messageCount || 0)}</td>
        </tr>
      `).join('');

      document.querySelectorAll('.call-row').forEach(row => {
        row.addEventListener('click', () => {
          state.selectedCallId = row.dataset.callId;
          state.selectedMessageIndex = 0;
          render();
        });
      });
    }

    function renderDetail() {
      const call = state.selectedCallId ? state.calls.get(state.selectedCallId) : null;
      if (!call) {
        els.detailTitle.textContent = 'Call detail';
        els.detailSubtitle.textContent = 'Select a call from the list';
        els.detailState.textContent = 'Idle';
        els.detailState.className = 'pill';
        els.detail.innerHTML = '<div class="detail-empty">Captured SIP dialogs will appear here as soon as traffic is seen.</div>';
        return;
      }

      const messages = call.messages || [];
      const selected = messages[state.selectedMessageIndex] || messages[0];
      const participants = call.participants || [];
      const media = call.media || {};
      const mediaDiagnostics = media.diagnostics || [];
      const mediaEndpoints = media.endpoints || [];
      const mediaStreams = media.streams || [];
      const columns = callColumns(messages);
      const leftEndpoint = columns[0] || 'Source';
      const rightEndpoint = columns[1] || 'Destination';
      els.detailTitle.textContent = shortSip(call.caller) && shortSip(call.callee)
        ? `${shortSip(call.caller)} to ${shortSip(call.callee)}`
        : call.id;
      els.detailSubtitle.textContent = call.id;
      els.detailState.textContent = call.state || 'unknown';
      els.detailState.className = `pill ${stateClass(call.state)}`;

      els.detail.innerHTML = `
        <div class="detail-body">
          <div class="summary-grid">
            <div class="summary-item"><div class="summary-label">Caller</div><div class="summary-value" title="${escapeHtml(call.caller || '')}">${escapeHtml(shortSip(call.caller) || '-')}</div></div>
            <div class="summary-item"><div class="summary-label">Callee</div><div class="summary-value" title="${escapeHtml(call.callee || '')}">${escapeHtml(shortSip(call.callee) || '-')}</div></div>
            <div class="summary-item"><div class="summary-label">Last status</div><div class="summary-value">${escapeHtml(call.lastStatusCode || call.lastSummary || '-')}</div></div>
            <div class="summary-item"><div class="summary-label">Started</div><div class="summary-value">${escapeHtml(formatTime(call.startedAt))}</div></div>
            <div class="summary-item"><div class="summary-label">Last seen</div><div class="summary-value">${escapeHtml(formatTime(call.lastSeenAt))}</div></div>
            <div class="summary-item"><div class="summary-label">Participants</div><div class="summary-value" title="${escapeHtml(participants.join(', '))}">${escapeHtml(participants.length)}</div></div>
            <div class="summary-item"><div class="summary-label">RTP packets</div><div class="summary-value">${escapeHtml(media.packetCount || 0)}</div></div>
            <div class="summary-item"><div class="summary-label">Codecs</div><div class="summary-value" title="${escapeHtml((media.codecs || []).join(', '))}">${escapeHtml((media.codecs || []).join(', ') || '-')}</div></div>
            <div class="summary-item"><div class="summary-label">RTP status</div><div class="summary-value">${escapeHtml(media.rtpFlowing ? 'flowing' : 'not seen')}</div></div>
          </div>

          <div class="inspector">
            <div class="inspector-head">
              <strong>Media</strong>
              <span class="small">${escapeHtml(media.streamCount || 0)} RTP streams</span>
            </div>
            <div style="padding: 10px; display: grid; gap: 10px;">
              ${mediaDiagnostics.length ? mediaDiagnostics.map(item => `
                <div class="pill ${item.level === 'warning' ? 'warn' : 'info'}">${escapeHtml(item.message)}</div>
              `).join('') : '<div class="small">No media warnings.</div>'}
              <div class="ladder">
                <div class="ladder-head">
                  <div>SDP IP:Port</div>
                  <div>Codecs</div>
                  <div>Private IP</div>
                  <div>Seen</div>
                </div>
                ${mediaEndpoints.length ? mediaEndpoints.map(endpoint => `
                  <div class="ladder-row">
                    <div>${escapeHtml(endpoint.key)}</div>
                    <div>${escapeHtml(Object.values(endpoint.codecs || {}).join(', ') || '-')}</div>
                    <div>${escapeHtml(endpoint.isPrivateIp ? 'yes' : 'no')}</div>
                    <div>${escapeHtml(mediaStreams.some(stream => stream.src === endpoint.key || stream.dst === endpoint.key) ? 'yes' : 'no')}</div>
                  </div>
                `).join('') : '<div class="detail-empty" style="min-height: 72px;">No SDP audio endpoints found.</div>'}
              </div>
              <div class="ladder">
                <div class="ladder-head">
                  <div>RTP Source</div>
                  <div>RTP Destination</div>
                  <div>Stats</div>
                  <div>Codec</div>
                </div>
                ${mediaStreams.length ? mediaStreams.map(stream => `
                  <div class="ladder-row">
                    <div>${escapeHtml(stream.src)}</div>
                    <div>${escapeHtml(stream.dst)}</div>
                    <div>${escapeHtml(`${stream.packetCount} pkts, ${stream.jitterMs} ms jitter, ${stream.lossPercent}% loss, ${stream.durationSeconds}s`)}</div>
                    <div>
                      ${escapeHtml(stream.codec || `PT ${stream.payloadType}`)}
                      ${stream.audioUrl ? `<div style="margin-top: 6px;"><audio controls preload="none" src="${escapeHtml(stream.audioUrl)}"></audio></div>` : ''}
                      ${stream.audioNote ? `<div class="small" style="margin-top: 6px;">${escapeHtml(stream.audioNote)}</div>` : ''}
                    </div>
                  </div>
                `).join('') : '<div class="detail-empty" style="min-height: 72px;">No RTP packets matched this call yet.</div>'}
              </div>
            </div>
          </div>

          <div class="sip-ladder">
            <div class="sip-ladder-head">
              <div>Time</div>
              <div title="${escapeHtml(leftEndpoint)}">${escapeHtml(leftEndpoint)}</div>
              <div>Message</div>
              <div title="${escapeHtml(rightEndpoint)}">${escapeHtml(rightEndpoint)}</div>
            </div>
            ${messages.map((message, index) => {
              const direction = flowDirection(message, leftEndpoint, rightEndpoint);
              const leftText = direction === 'right' ? message.src : message.dst;
              const rightText = direction === 'right' ? message.dst : message.src;
              return `
              <div class="sip-ladder-row ${index === state.selectedMessageIndex ? 'selected' : ''}" data-message-index="${index}">
                <div>${escapeHtml(formatTime(message.timestamp))}</div>
                <div class="endpoint-cell ${message.src === leftEndpoint || message.dst === leftEndpoint ? 'active' : ''}" title="${escapeHtml(leftText)}">${escapeHtml(leftText)}</div>
                <div class="flow-arrow ${direction}"><span title="${escapeHtml(`${message.src} to ${message.dst}`)}">${escapeHtml(flowLabel(message, direction))}</span></div>
                <div class="endpoint-cell ${message.src === rightEndpoint || message.dst === rightEndpoint ? 'active' : ''}" title="${escapeHtml(rightText)}">${escapeHtml(rightText)}</div>
              </div>
            `}).join('')}
          </div>

          <div class="inspector">
            <div class="inspector-head">
              <strong>${escapeHtml(messageLabel(selected))}</strong>
              <span class="small">${escapeHtml(selected ? `${selected.transport} ${selected.src} -> ${selected.dst}` : '')}</span>
            </div>
            <pre>${escapeHtml(selected ? selected.raw : '')}</pre>
          </div>
        </div>
      `;

      document.querySelectorAll('.sip-ladder-row').forEach(row => {
        row.addEventListener('click', () => {
          state.selectedMessageIndex = Number(row.dataset.messageIndex || 0);
          renderDetail();
        });
      });
    }

    function render() {
      if (state.renderTimer) {
        clearTimeout(state.renderTimer);
        state.renderTimer = null;
      }
      renderStatus();
      renderCalls();
      renderDetail();
    }

    function scheduleRender(deferred = false) {
      if (!deferred) {
        render();
        return;
      }
      if (state.renderTimer) {
        return;
      }
      state.renderTimer = setTimeout(render, 500);
    }

    els.captureForm.addEventListener('submit', async event => {
      event.preventDefault();
      els.notice.textContent = '';
      const ports = els.portsInput.value.split(',').map(item => Number(item.trim())).filter(Boolean);
      const ignoreMethods = selectedIgnoredMethods();
      try {
        await api('/api/capture/start', {
          method: 'POST',
          body: JSON.stringify({
            interface_ip: els.interfaceSelect.value,
            ports,
            ignore_methods: ignoreMethods,
            record_audio: els.recordAudio.checked
          })
        });
        await loadStatus();
      } catch (error) {
        els.notice.textContent = error.message;
        await loadStatus().catch(() => {});
      }
    });

    els.stopButton.addEventListener('click', async () => {
      await api('/api/capture/stop', { method: 'POST', body: '{}' }).catch(error => {
        els.notice.textContent = error.message;
      });
      await loadStatus();
    });

    els.clearButton.addEventListener('click', async () => {
      await api('/api/calls/clear', { method: 'POST', body: '{}' });
      state.calls.clear();
      state.selectedCallId = null;
      render();
    });

    els.importButton.addEventListener('click', () => {
      els.pcapInput.click();
    });

    els.pcapInput.addEventListener('change', async () => {
      const file = els.pcapInput.files && els.pcapInput.files[0];
      if (!file) return;
      els.notice.textContent = '';
      const form = new FormData();
      form.append('pcap', file);
      form.append('ports', els.portsInput.value);
      form.append('ignore_methods', selectedIgnoredMethods().join(','));
      form.append('record_audio', els.recordAudio.checked ? '1' : '0');
      try {
        const response = await fetch('/api/pcap/upload', { method: 'POST', body: form });
        const data = await response.json();
        if (!response.ok) {
          throw new Error(data.error || 'PCAP import failed');
        }
        els.notice.textContent = `Imported ${data.stats.sipMessages} SIP messages from ${data.stats.packets} packets`;
        await loadCalls();
      } catch (error) {
        els.notice.textContent = error.message;
      } finally {
        els.pcapInput.value = '';
      }
    });

    els.logoutButton.addEventListener('click', async () => {
      await api('/api/logout', { method: 'POST', body: '{}' }).catch(() => {});
      window.location.href = '/login';
    });

    els.refreshButton.addEventListener('click', loadCalls);
    els.searchInput.addEventListener('input', renderCalls);
    els.stateFilter.addEventListener('change', renderCalls);
    els.ignoreMethods.forEach(item => item.addEventListener('change', render));

    async function boot() {
      try {
        await loadInterfaces();
        await loadStatus();
        await loadCalls();
        connectEvents();
        render();
        setInterval(loadStatus, 2000);
      } catch (error) {
        els.notice.textContent = error.message;
      }
    }

    boot();
  </script>
</body>
</html>
"""


LOGIN_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>SIPFLOW Login</title>
  <style>
    :root {
      --bg: #f7f8fa;
      --panel: #ffffff;
      --text: #172033;
      --muted: #657085;
      --line: #d8dee8;
      --accent: #007c89;
      --bad: #c92a2a;
      --shadow: 0 16px 44px rgba(22, 32, 51, .12);
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      background: var(--bg);
      color: var(--text);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }

    .shell {
      width: min(420px, calc(100vw - 32px));
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: var(--shadow);
      padding: 28px;
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 24px;
    }

    .mark {
      width: 38px;
      height: 38px;
      border-radius: 7px;
      background: linear-gradient(135deg, #007c89, #3c78d8);
      display: grid;
      place-items: center;
      color: #fff;
      font-weight: 800;
    }

    h1 {
      margin: 0;
      font-size: 22px;
      letter-spacing: 0;
    }

    .sub {
      margin-top: 2px;
      color: var(--muted);
      font-size: 13px;
    }

    label {
      display: grid;
      gap: 6px;
      margin-top: 14px;
      color: var(--muted);
      font-size: 13px;
      font-weight: 650;
    }

    input {
      width: 100%;
      min-height: 42px;
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 0 12px;
      color: var(--text);
      font: inherit;
    }

    button {
      width: 100%;
      min-height: 42px;
      margin-top: 20px;
      border: 1px solid var(--accent);
      border-radius: 6px;
      background: var(--accent);
      color: #fff;
      font: inherit;
      font-weight: 720;
      cursor: pointer;
    }

    .error {
      min-height: 18px;
      margin-top: 12px;
      color: var(--bad);
      font-size: 13px;
    }
  </style>
</head>
<body>
  <main class="shell">
    <div class="brand">
      <div class="mark">SF</div>
      <div>
        <h1>SIPFLOW</h1>
        <div class="sub">Sign in to view live SIP traffic</div>
      </div>
    </div>

    <form id="loginForm">
      <label>
        Username
        <input id="username" name="username" autocomplete="username" autofocus />
      </label>
      <label>
        Password
        <input id="password" name="password" type="password" autocomplete="current-password" />
      </label>
      <button type="submit">Sign In</button>
      <div class="error" id="error"></div>
    </form>
  </main>

  <script>
    const form = document.querySelector('#loginForm');
    const error = document.querySelector('#error');

    form.addEventListener('submit', async event => {
      event.preventDefault();
      error.textContent = '';
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: document.querySelector('#username').value,
          password: document.querySelector('#password').value
        })
      });

      if (response.ok) {
        window.location.href = '/';
        return;
      }

      const data = await response.json().catch(() => ({}));
      error.textContent = data.error || 'Login failed';
    });
  </script>
</body>
</html>
"""


class EventHub:
    def __init__(self) -> None:
        self._subscribers: set[queue.Queue[dict[str, Any]]] = set()
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue[dict[str, Any]]:
        subscriber: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=500)
        with self._lock:
            self._subscribers.add(subscriber)
        return subscriber

    def unsubscribe(self, subscriber: queue.Queue[dict[str, Any]]) -> None:
        with self._lock:
            self._subscribers.discard(subscriber)

    def publish(self, event: dict[str, Any]) -> None:
        with self._lock:
            subscribers = list(self._subscribers)
        for subscriber in subscribers:
            try:
                subscriber.put_nowait(event)
            except queue.Full:
                pass


class AppState:
    def __init__(self, auth_username: str | None = None, auth_password: str | None = None) -> None:
        self.calls = CallStore()
        self.events = EventHub()
        self.capture = PacketCapture(self.on_sip_message, self.on_rtp_packet)
        self.auth_username = auth_username
        self.auth_password = auth_password
        self.sessions: set[str] = set()
        self.sessions_lock = threading.Lock()
        self.last_rtp_publish_by_call: dict[str, float] = {}
        self.rtp_publish_interval = 0.5

    def on_sip_message(self, message: SipMessage) -> None:
        call = self.calls.add(message)
        self.events.publish(
            {
                "type": "sip_message",
                "callId": message.call_id,
                "message": message.to_dict(),
                "call": call.to_dict() if call else None,
            }
        )

    def on_rtp_packet(self, packet: RtpPacket) -> None:
        call = self.calls.add_rtp_packet(packet)
        if call and self.should_publish_rtp(call.id):
            self.events.publish(
                {
                    "type": "rtp_packet",
                    "callId": call.id,
                    "call": call.to_dict(),
                }
            )

    def should_publish_rtp(self, call_id: str) -> bool:
        now = time.monotonic()
        last = self.last_rtp_publish_by_call.get(call_id, 0)
        if now - last < self.rtp_publish_interval:
            return False
        self.last_rtp_publish_by_call[call_id] = now
        return True

    @property
    def auth_enabled(self) -> bool:
        return bool(self.auth_username and self.auth_password)

    def create_session(self) -> str:
        token = secrets.token_urlsafe(32)
        with self.sessions_lock:
            self.sessions.add(token)
        return token

    def has_session(self, token: str | None) -> bool:
        if not token:
            return False
        with self.sessions_lock:
            return token in self.sessions

    def delete_session(self, token: str | None) -> None:
        if not token:
            return
        with self.sessions_lock:
            self.sessions.discard(token)


class SipflowHandler(BaseHTTPRequestHandler):
    state: AppState

    def do_GET(self) -> None:
        parsed_path = urlparse(self.path)
        path = parsed_path.path
        if path == "/login":
            if self.is_authenticated():
                self.redirect("/")
                return
            self.send_bytes(LOGIN_HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if not self.require_session():
            return
        if path == "/" or path == "/index.html":
            self.send_bytes(INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/api/interfaces":
            self.send_json({"interfaces": [item.__dict__ for item in list_interfaces()]})
            return
        if path == "/api/capture/status":
            self.send_json(self.state.capture.status())
            return
        if path == "/api/calls":
            self.send_json({"calls": self.state.calls.list()})
            return
        if path == "/api/audio":
            self.send_audio(parsed_path.query)
            return
        if path == "/api/events":
            self.stream_events()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if self.path == "/api/login":
            self.login()
            return
        if not self.require_session():
            return
        if self.path == "/api/logout":
            self.logout()
            return
        if self.path == "/api/capture/start":
            self.start_capture()
            return
        if self.path == "/api/capture/stop":
            self.state.capture.stop()
            self.state.events.publish({"type": "capture_stopped"})
            self.send_json(self.state.capture.status())
            return
        if self.path == "/api/calls/clear":
            self.state.calls.clear()
            self.state.events.publish({"type": "calls_cleared"})
            self.send_json({"ok": True})
            return
        if self.path == "/api/pcap/upload":
            self.upload_pcap()
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def send_audio(self, query: str) -> None:
        params = parse_qs(query)
        call_id = params.get("call_id", [""])[0]
        stream_id = params.get("stream_id", [""])[0]
        audio = self.state.calls.audio_wav(call_id, stream_id)
        if not audio:
            self.send_json({"error": "audio not found"}, status=HTTPStatus.NOT_FOUND)
            return
        self.send_bytes(audio, "audio/wav")

    def upload_pcap(self) -> None:
        try:
            fields = self.read_multipart_form()
            pcap_data = fields.get("pcap", b"")
            ports_text = fields.get("ports", b"5060").decode("utf-8", errors="replace")
            ignore_text = fields.get("ignore_methods", b"").decode("utf-8", errors="replace")
            record_audio = fields.get("record_audio", b"0") == b"1"
            ports = {int(port.strip()) for port in ports_text.split(",") if port.strip()}
            ignore_methods = {method.strip().upper() for method in ignore_text.split(",") if method.strip()}
            if not ports:
                ports = {5060}
            stats = import_pcap(
                pcap_data,
                PcapImportConfig(ports=ports, ignore_methods=ignore_methods, record_audio=record_audio),
                self.state.on_sip_message,
                self.state.on_rtp_packet,
            )
            self.state.events.publish({"type": "pcap_imported", "stats": stats.to_dict()})
            self.send_json({"ok": True, "stats": stats.to_dict()})
        except Exception as exc:
            self.send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.add_cors_headers()
        self.end_headers()

    def is_authenticated(self) -> bool:
        if not self.state.auth_enabled:
            return True
        return self.state.has_session(self.get_cookie("sipflow_session"))

    def require_session(self) -> bool:
        if self.is_authenticated():
            return True

        if self.path.startswith("/api/"):
            self.send_json({"error": "authentication required"}, status=HTTPStatus.UNAUTHORIZED)
        else:
            self.redirect("/login")
        return False

    def login(self) -> None:
        if not self.state.auth_enabled:
            self.send_json({"ok": True})
            return

        try:
            body = self.read_json()
        except Exception:
            self.send_json({"error": "invalid login request"}, status=HTTPStatus.BAD_REQUEST)
            return

        username = str(body.get("username") or "")
        password = str(body.get("password") or "")
        if (
            hmac.compare_digest(username, self.state.auth_username or "")
            and hmac.compare_digest(password, self.state.auth_password or "")
        ):
            token = self.state.create_session()
            self.send_json(
                {"ok": True},
                extra_headers=[
                    (
                        "Set-Cookie",
                        f"sipflow_session={token}; Path=/; HttpOnly; SameSite=Lax",
                    )
                ],
            )
            return

        self.send_json({"error": "invalid username or password"}, status=HTTPStatus.UNAUTHORIZED)

    def logout(self) -> None:
        self.state.delete_session(self.get_cookie("sipflow_session"))
        self.send_json(
            {"ok": True},
            extra_headers=[
                (
                    "Set-Cookie",
                    "sipflow_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
                )
            ],
        )

    def get_cookie(self, name: str) -> str | None:
        header = self.headers.get("Cookie", "")
        for part in header.split(";"):
            cookie_name, separator, value = part.strip().partition("=")
            if separator and cookie_name == name:
                return value
        return None

    def redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.FOUND)
        self.add_cors_headers()
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def start_capture(self) -> None:
        try:
            body = self.read_json()
            interface_ip = str(body.get("interface_ip") or "")
            ports = [int(port) for port in body.get("ports", [5060])]
            ignore_methods = {str(method).upper() for method in body.get("ignore_methods", [])}
            record_audio = bool(body.get("record_audio", False))
            if not interface_ip:
                interfaces = list_interfaces()
                interface_ip = interfaces[0].ip
            self.state.capture.start(
                CaptureConfig(
                    interface_ip=interface_ip,
                    ports=ports,
                    ignore_methods=ignore_methods,
                    record_audio=record_audio,
                )
            )
            self.state.events.publish(
                {
                    "type": "capture_started",
                    "interfaceIp": interface_ip,
                    "ports": ports,
                    "ignoreMethods": sorted(ignore_methods),
                    "recordAudio": record_audio,
                }
            )
            self.send_json(self.state.capture.status())
        except Exception as exc:
            self.send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)

    def stream_events(self) -> None:
        subscriber = self.state.events.subscribe()
        self.send_response(HTTPStatus.OK)
        self.add_cors_headers()
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        self.wfile.write(b": connected\n\n")
        self.wfile.flush()

        try:
            while True:
                try:
                    event = subscriber.get(timeout=20)
                    data = json.dumps(event, separators=(",", ":")).encode("utf-8")
                    self.wfile.write(b"data: " + data + b"\n\n")
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionAbortedError, ConnectionResetError):
            pass
        finally:
            self.state.events.unsubscribe(subscriber)

    def read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def read_multipart_form(self) -> dict[str, bytes]:
        content_type = self.headers.get("Content-Type", "")
        marker = "boundary="
        if marker not in content_type:
            raise ValueError("multipart/form-data upload is required")

        boundary = content_type.split(marker, 1)[1].split(";", 1)[0].strip().strip('"')
        if not boundary:
            raise ValueError("missing multipart boundary")

        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            raise ValueError("empty upload")
        if length > 100 * 1024 * 1024:
            raise ValueError("PCAP upload is limited to 100 MB")

        body = self.rfile.read(length)
        delimiter = b"--" + boundary.encode("utf-8")
        fields: dict[str, bytes] = {}
        for part in body.split(delimiter):
            part = part.strip()
            if not part or part == b"--":
                continue
            if part.endswith(b"--"):
                part = part[:-2].strip()
            header_blob, separator, value = part.partition(b"\r\n\r\n")
            if not separator:
                continue
            name = multipart_name(header_blob.decode("utf-8", errors="replace"))
            if not name:
                continue
            if value.endswith(b"\r\n"):
                value = value[:-2]
            fields[name] = value

        if "pcap" not in fields:
            raise ValueError("missing pcap file")
        return fields

    def send_json(
        self,
        payload: dict[str, Any],
        status: HTTPStatus = HTTPStatus.OK,
        extra_headers: list[tuple[str, str]] | None = None,
    ) -> None:
        self.send_bytes(
            json.dumps(payload, indent=2).encode("utf-8"),
            "application/json; charset=utf-8",
            status,
            extra_headers,
        )

    def send_bytes(
        self,
        payload: bytes,
        content_type: str,
        status: HTTPStatus = HTTPStatus.OK,
        extra_headers: list[tuple[str, str]] | None = None,
    ) -> None:
        self.send_response(status)
        self.add_cors_headers()
        self.send_header("Content-Type", content_type)
        for name, value in extra_headers or []:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def add_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def log_message(self, format: str, *args: Any) -> None:
        print(f"{self.address_string()} - {format % args}")


def multipart_name(header_blob: str) -> str | None:
    for line in header_blob.splitlines():
        if not line.lower().startswith("content-disposition:"):
            continue
        for item in line.split(";"):
            key, separator, value = item.strip().partition("=")
            if separator and key.lower() == "name":
                return value.strip().strip('"')
    return None


def create_server(
    host: str,
    port: int,
    auth_username: str | None = None,
    auth_password: str | None = None,
) -> ThreadingHTTPServer:
    state = AppState(auth_username=auth_username, auth_password=auth_password)

    class Handler(SipflowHandler):
        pass

    Handler.state = state
    return ThreadingHTTPServer((host, port), Handler)


def main() -> None:
    parser = argparse.ArgumentParser(description="SIPFLOW capture server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8080, type=int)
    parser.add_argument("--auth-user", default=os.environ.get("SIPFLOW_AUTH_USER"))
    parser.add_argument("--auth-password", default=os.environ.get("SIPFLOW_AUTH_PASSWORD"))
    args = parser.parse_args()

    if bool(args.auth_user) != bool(args.auth_password):
        parser.error("--auth-user and --auth-password must be set together")

    server = create_server(args.host, args.port, args.auth_user, args.auth_password)
    print(f"SIPFLOW server listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
