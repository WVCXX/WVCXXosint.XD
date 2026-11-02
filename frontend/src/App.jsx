import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  useEdgesState,
  useNodesState,
} from 'reactflow';
import 'reactflow/dist/style.css';
import dagre from '@dagrejs/dagre';
import { Command, RotateCcw, ScanSearch, Search, Square } from 'lucide-react';
import NodeCard from './components/NodeCard';
import CommandPalette from './components/CommandPalette';
import ApiKeySettings from './components/ApiKeySettings';
import Inspector from './components/Inspector';
import Timeline, { CategoryFeed } from './components/Timeline';
import SidebarRail from './components/SidebarRail';
import MonitoringView from './components/MonitoringView';
import { ExifCard } from './components/ExifCard';
import {
  LanguageContext,
  ToastContext,
  categoryLabel,
  localizeTool,
  queryTypeLabel,
  statusLabel,
  toolStatusLabel,
} from './i18n';
import './App.css';

const NODE_WIDTH = 300;
const HISTORY_KEY = 'wvcxxosint.history.v1';
const QUERY_TYPES = [
  ['auto', 'Auto detect', 'Автоопределение'],
  ['email', 'Email', 'Электронная почта'],
  ['username', 'Username', 'Имя пользователя'],
  ['domain', 'Domain', 'Домен'],
  ['ip', 'IP address', 'IP-адрес'],
  ['url', 'URL', 'URL'],
  ['phone', 'Phone number', 'Телефон'],
  ['organization', 'Organization', 'Организация'],
];
const NAV_ITEMS = [
  ['investigation', 'Расследование', 'Investigation'],
  ['tools', 'Инструменты', 'Tools'],
  ['monitoring', 'Мониторинг', 'Monitoring'],
  ['history', 'История', 'History'],
  ['reports', 'Отчёты', 'Reports'],
  ['settings', 'Настройки', 'Settings'],
  ['about', 'О платформе', 'About'],
];
const nodeTypes = { custom: NodeCard };
const edgeTypes = {};

const TEXT = {
  ru: {
    search: 'Поиск по открытым данным',
    placeholder: 'Введите идентификатор для проверки',
    analyze: 'Начать анализ',
    analyzing: 'Анализ…',
    cancelScan: 'Остановить',
    retryFailed: 'Повторить ошибки',
    depth: 'Глубина',
    emptyTitle: 'Начните новое расследование',
    emptyText: 'Выберите тип запроса и запустите независимые проверки по публичным источникам.',
    graph: 'Граф',
    timeline: 'Лента',
    center: 'Центрировать',
    export: 'Экспорт',
    searchGraph: 'Найти в графе',
    allStatuses: 'Все статусы',
    allCategories: 'Все категории',
    modules: 'проверок',
    findings: 'результатов',
    language: 'Язык',
    configureKey: 'Ключи API',
    keySaved: 'Ключ сохранён',
    keyPartiallySaved: 'Сохранена часть ключа',
    keyMissing: 'Ключ не задан',
    keyOptional: 'Ключ необязателен',
    sourceDocs: 'Документация источника ↗',
    targetTitle: 'Объект анализа',
    edgeLabel: 'проверка',
    noResults: 'Проверки завершены — ни одна из них не вернула результаты.',
    detailTarget: 'ЗАПРОС',
    detailModule: 'OSINT МОДУЛЬ',
    copy: 'Копировать',
    deepDive: 'Продолжить исследование значения',
    palettePlaceholder: 'Команда или новый запрос…',
    paletteRunScan: 'Enter — проверить как новый запрос (автоопределение)',
    diffAgainst: 'Диф с выбранным исследованием',
    diffAdded: 'новых',
    diffChanged: 'изменённых',
    diffRemoved: 'удалённых',
    diffAddedTitle: 'Новые узлы',
    diffChangedTitle: 'Изменённые статусы',
    diffRemovedTitle: 'Пропавшие узлы',
    diffButton: 'Сравнить',
    monitoringTitle: 'Мониторинг по расписанию',
    monitoringDetail: 'Периодическая перепроверка на сервере: новые и изменившиеся результаты копятся в дифе.',
    watchQuery: 'Запрос',
    watchType: 'Тип',
    watchDepth: 'Глубина',
    watchInterval: 'Интервал',
    watchCreate: 'Добавить наблюдение',
    watchEmptyTitle: 'Наблюдений нет',
    watchEmptyText: 'Добавьте запрос, и сервер будет перепроверять его по расписанию.',
    watchLast: 'Прошлая проверка',
    watchNext: 'Следующая',
    watchPending: 'Ожидает первой проверки',
    watchRunNow: 'Проверить сейчас',
    watchDelete: 'Удалить',
    exifTitle: 'ExifTool',
    confidenceHigh: 'Высокое доверие',
    confidenceMedium: 'Среднее доверие',
    confidenceLow: 'Низкое доверие',
  },
  en: {
    search: 'Open-source research',
    placeholder: 'Enter an identifier to investigate',
    analyze: 'Start investigation',
    analyzing: 'Analyzing…',
    cancelScan: 'Stop scan',
    retryFailed: 'Retry failed checks',
    depth: 'Depth',
    emptyTitle: 'Start a new investigation',
    emptyText: 'Choose a query type and run independent checks against public sources.',
    graph: 'Graph',
    timeline: 'Timeline',
    center: 'Center graph',
    export: 'Export',
    searchGraph: 'Search graph',
    allStatuses: 'All statuses',
    allCategories: 'All categories',
    modules: 'checks',
    findings: 'results',
    language: 'Language',
    configureKey: 'API keys',
    keySaved: 'Key saved',
    keyPartiallySaved: 'Credential incomplete',
    keyMissing: 'Key not configured',
    keyOptional: 'Optional key',
    sourceDocs: 'Source documentation ↗',
    targetTitle: 'Investigation target',
    edgeLabel: 'check',
    noResults: 'Checks completed — none of them returned results.',
    detailTarget: 'SEARCH QUERY',
    detailModule: 'OSINT MODULE',
    copy: 'Copy',
    deepDive: 'Continue investigation with this value',
    palettePlaceholder: 'Command or a new query…',
    paletteRunScan: 'Enter — run as a new query (auto detect)',
    diffAgainst: 'Diff against selected investigation',
    diffAdded: 'added',
    diffChanged: 'changed',
    diffRemoved: 'removed',
    diffAddedTitle: 'New nodes',
    diffChangedTitle: 'Status changes',
    diffRemovedTitle: 'Missing nodes',
    diffButton: 'Compare',
    monitoringTitle: 'Scheduled monitoring',
    monitoringDetail: 'Server-side periodic re-scan: new and changed results accumulate in a diff.',
    watchQuery: 'Query',
    watchType: 'Type',
    watchDepth: 'Depth',
    watchInterval: 'Interval',
    watchCreate: 'Add watch',
    watchEmptyTitle: 'No watches yet',
    watchEmptyText: 'Add a query and the server will re-check it on a schedule.',
    watchLast: 'Last run',
    watchNext: 'Next',
    watchPending: 'Awaiting first run',
    watchRunNow: 'Check now',
    watchDelete: 'Delete',
    exifTitle: 'ExifTool',
    confidenceHigh: 'High confidence',
    confidenceMedium: 'Medium confidence',
    confidenceLow: 'Low confidence',
  },
};

function readHistory() {
  try {
    const stored = window.localStorage.getItem(HISTORY_KEY);
    const parsed = stored ? JSON.parse(stored) : [];
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    console.error('Could not read local investigation history', error);
    return [];
  }
}

function readLanguage() {
  try {
    return window.localStorage.getItem('wvcxxosint.language') === 'en' ? 'en' : 'ru';
  } catch (error) {
    console.error('Could not read language preference', error);
    return 'ru';
  }
}

function readTheme() {
  try {
    const stored = window.localStorage.getItem('wvcxxosint.theme');
    if (stored === 'light' || stored === 'dark') return stored;
  } catch (error) {
    console.error('Could not read theme preference', error);
  }
  return window.matchMedia?.('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

function saveHistory(history) {
  try {
    window.localStorage.setItem(HISTORY_KEY, JSON.stringify(history));
    return true;
  } catch (error) {
    console.error('Could not save local investigation history', error);
    return false;
  }
}

function estimateNodeHeight(node) {
  if (node.data.isRoot) return 92;
  if (node.data.isCategory) return 58;
  const fields = node.data.fields || [];
  const contentHeight = fields.reduce((height, field) => {
    const valueLength = String(field.value ?? '').length;
    return height + 32 + Math.min(4, Math.max(1, Math.ceil(valueLength / 38))) * 16;
  }, 0);
  return Math.max(100, 58 + contentHeight);
}

function getLayoutedElements(nodes, edges) {
  const graph = new dagre.graphlib.Graph().setDefaultEdgeLabel(() => ({}));
  graph.setGraph({ rankdir: 'TB', nodesep: 68, ranksep: 90, marginx: 40, marginy: 40 });
  nodes.forEach((node) => graph.setNode(node.id, { width: NODE_WIDTH, height: estimateNodeHeight(node) }));
  edges.forEach((edge) => graph.setEdge(edge.source, edge.target));
  dagre.layout(graph);

  return {
    nodes: nodes.map((node) => {
      const position = graph.node(node.id);
      return {
        ...node,
        sourcePosition: 'bottom',
        targetPosition: 'top',
        position: {
          x: position.x - NODE_WIDTH / 2,
          y: position.y - estimateNodeHeight(node) / 2,
        },
      };
    }),
    edges,
  };
}

function makeGraphNode(id, data) {
  return {
    id,
    type: 'custom',
    data,
    position: { x: 0, y: 0 },
    style: { width: NODE_WIDTH },
  };
}

function downloadFile(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function csvValue(value) {
  return `"${String(value ?? '').replaceAll('"', '""')}"`;
}

function xmlValue(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;');
}

function buildMarkdown(query, nodes, language, queryType) {
  const groups = new Map();
  for (const node of nodes) {
    if (node.data.isRoot || node.data.isCategory) continue;
    const key = node.data.category || 'other';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(node);
  }
  const exportedAt = new Date().toISOString();
  const lines = [
    `# OSINT Spider — ${query}`,
    '',
    `- ${language === 'ru' ? 'Тип запроса' : 'Query type'}: ${queryType}`,
    `- ${language === 'ru' ? 'Экспортировано' : 'Exported'}: ${exportedAt}`,
    '',
  ];
  for (const [key, items] of groups.entries()) {
    lines.push(`## ${categoryLabel(key, language) || key}`, '');
    for (const item of items) {
      lines.push(`### ${item.data.title} — ${statusLabel(item.data.state || item.data.status, language)}`);
      if (item.data.check_title) lines.push(`Check: ${item.data.check_title}`);
      if (item.data.source_url) lines.push(`Source: ${item.data.source_url}`);
      if (item.data.received_at) lines.push(`Received: ${item.data.received_at}`);
      if (item.data.confidence) lines.push(`Confidence: ${item.data.confidence}`);
      if (item.data.evidence_type) lines.push(`Evidence: ${item.data.evidence_type}`);
      lines.push('');
      for (const field of item.data.fields || []) {
        lines.push(`- **${field.label}:** ${field.value}`);
      }
      for (const limitation of item.data.limitations || []) lines.push(`- Limitation: ${limitation}`);
      for (const error of item.data.errors || []) lines.push(`- Error: ${error}`);
      lines.push('');
    }
  }
  return lines.join('\n');
}

function buildReportHtml(query, nodes, edgesCount, queryType) {
  const groups = new Map();
  for (const node of nodes) {
    if (node.data.isRoot || node.data.isCategory) continue;
    const key = node.data.category || 'other';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(node);
  }
  const sections = [...groups.entries()].map(([key, items]) => {
    const cards = items.map((item) => {
      const rows = (item.data.fields || []).map((field) => `
        <tr><th>${xmlValue(field.label)}</th><td>${xmlValue(field.value)}</td></tr>`).join('');
      const link = item.data.source_url
        ? `<p class="src">Источник: <a href="${xmlValue(item.data.source_url)}">${xmlValue(item.data.source_url)}</a></p>`
        : '';
      const metadata = [
        item.data.check_title ? `Проверка: ${item.data.check_title}` : '',
        item.data.received_at ? `Получено: ${item.data.received_at}` : '',
        item.data.confidence ? `Доверие: ${item.data.confidence}` : '',
        item.data.evidence_type ? `Тип доказательства: ${item.data.evidence_type}` : '',
        ...(item.data.limitations || []).map((value) => `Ограничение: ${value}`),
        ...(item.data.errors || []).map((value) => `Ошибка: ${value}`),
      ].filter(Boolean).map((value) => `<li>${xmlValue(value)}</li>`).join('');
      return `<div class="card">
        <div class="card-head"><b>${xmlValue(item.data.title)}</b><span class="state">${xmlValue(item.data.state || '')}</span></div>
        <table>${rows}</table>${metadata ? `<ul class="meta-list">${metadata}</ul>` : ''}${link}</div>`;
    }).join('');
    return `<h2>${xmlValue(categoryLabel(key, 'ru') || key)}</h2>${cards}`;
  }).join('');
  return `<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>OSINT Spider — ${xmlValue(query)}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 32px; color: #111; }
    h1 { font-size: 20px; } h2 { font-size: 14px; margin-top: 28px; color: #333; }
    .meta { color: #666; font-size: 11px; }
    .card { border: 1px solid #ddd; border-radius: 6px; padding: 10px 12px; margin-bottom: 10px; }
    .card-head { display: flex; justify-content: space-between; }
    .state { font-size: 10px; color: #666; }
    table { width: 100%; border-collapse: collapse; font-size: 11px; }
    th { text-align: left; color: #555; width: 160px; padding: 3px 6px; vertical-align: top; }
    td { padding: 3px 6px; word-break: break-all; }
    .src { font-size: 10px; color: #666; }
    .meta-list { padding-left: 18px; color: #555; font-size: 10px; }
  </style></head><body>
  <h1>OSINT Spider — отчёт</h1>
  <p class="meta">Запрос: <b>${xmlValue(query)}</b> · тип: ${xmlValue(queryType)} · узлов: ${nodes.length} · связей: ${edgesCount} · ${new Date().toLocaleString('ru-RU')}</p>
  ${sections}
  <script>window.onload = () => window.print();</script>
  </body></html>`;
}

function printReport(html) {
  const iframe = document.createElement('iframe');
  iframe.style.position = 'fixed';
  iframe.style.right = '0';
  iframe.style.bottom = '0';
  iframe.style.width = '0';
  iframe.style.height = '0';
  iframe.style.border = '0';
  document.body.appendChild(iframe);
  const doc = iframe.contentWindow?.document;
  if (!doc) return;
  doc.open();
  doc.write(html);
  doc.close();
  window.setTimeout(() => iframe.remove(), 3000);
}

function buildSvg(nodes, edges, query) {
  const margin = 48;
  const positions = new Map(nodes.map((node) => [node.id, node]));
  const minX = Math.min(0, ...nodes.map((node) => node.position.x));
  const minY = Math.min(0, ...nodes.map((node) => node.position.y));
  const maxX = Math.max(800, ...nodes.map((node) => node.position.x + NODE_WIDTH));
  const maxY = Math.max(450, ...nodes.map((node) => node.position.y + estimateNodeHeight(node)));
  const width = maxX - minX + margin * 2;
  const height = maxY - minY + margin * 2;
  const edgeMarkup = edges.map((edge) => {
    const source = positions.get(edge.source);
    const target = positions.get(edge.target);
    if (!source || !target) return '';
    const x1 = source.position.x - minX + margin + NODE_WIDTH / 2;
    const y1 = source.position.y - minY + margin + estimateNodeHeight(source);
    const x2 = target.position.x - minX + margin + NODE_WIDTH / 2;
    const y2 = target.position.y - minY + margin;
    return `<path d="M ${x1} ${y1} C ${x1} ${y1 + 34}, ${x2} ${y2 - 34}, ${x2} ${y2}" fill="none" stroke="#343941" stroke-width="1.5"/><text x="${(x1 + x2) / 2 + 6}" y="${(y1 + y2) / 2}" fill="#9298a3" font-size="11">checked by</text>`;
  }).join('');
  const nodeMarkup = nodes.map((node) => {
    const x = node.position.x - minX + margin;
    const y = node.position.y - minY + margin;
    const nodeHeight = estimateNodeHeight(node);
    const status = node.data.state || node.data.status;
    const color = status === 'completed' || status === 'ok' ? '#38c987'
      : status === 'failed' || status === 'error' ? '#f16b73'
        : status === 'not_configured' ? '#9298a3' : '#e8b45a';
    return `<g><rect x="${x}" y="${y}" width="${NODE_WIDTH}" height="${nodeHeight}" rx="8" fill="#191b1f" stroke="#343941"/><rect x="${x}" y="${y}" width="3" height="${nodeHeight}" rx="2" fill="${color}"/><text x="${x + 16}" y="${y + 24}" fill="#f2f4f7" font-size="14" font-family="Inter,Arial,sans-serif">${xmlValue(node.data.title)}</text><text x="${x + 16}" y="${y + 44}" fill="${color}" font-size="11" font-family="Inter,Arial,sans-serif">${xmlValue(status)}</text></g>`;
  }).join('');
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}"><rect width="100%" height="100%" fill="#08090b"/><text x="${margin}" y="25" fill="#9298a3" font-size="12" font-family="Inter,Arial,sans-serif">${xmlValue(query)}</text>${edgeMarkup}${nodeMarkup}</svg>`;
}

function getApiBase() {
  return `${window.location.protocol === 'https:' ? 'https:' : 'http:'}//${window.location.hostname || '127.0.0.1'}:8000`;
}

function App() {
  const [language, setLanguage] = useState(readLanguage);
  const [theme, setTheme] = useState(readTheme);
  const t = TEXT[language] || TEXT.ru;
  const [view, setView] = useState('investigation');
  const [query, setQuery] = useState('');
  const [queryType, setQueryType] = useState('auto');
  const [depth, setDepth] = useState(1);
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState({ completed: 0, total: 0, results: 0 });
  const [error, setError] = useState('');
  const [connectionStatus, setConnectionStatus] = useState('');
  const [noteDraftState, setNoteDraftState] = useState({ key: null, value: '' });
  const [history, setHistory] = useState(readHistory);
  const [historySearch, setHistorySearch] = useState('');
  const [tools, setTools] = useState([]);
  const [toolsError, setToolsError] = useState('');
  const [toolsSearch, setToolsSearch] = useState('');
  const [toolsTypeFilter, setToolsTypeFilter] = useState('');
  const [toolsCategoryFilter, setToolsCategoryFilter] = useState('');
  const [toolsStatusFilter, setToolsStatusFilter] = useState('');
  const [toolsApiFilter, setToolsApiFilter] = useState('');
  const [graphSearch, setGraphSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [nodeTypeFilter] = useState('');
  const [selectedNode, setSelectedNode] = useState(null);
  const [timelineMode, setTimelineMode] = useState('graph');
  const [collapsedCategories, setCollapsedCategories] = useState(() => new Set());
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [toast, setToast] = useState('');
  const [diffPanel, setDiffPanel] = useState(null);
  const [watches, setWatches] = useState([]);
  const [watchesError, setWatchesError] = useState('');
  const [watchLoading, setWatchLoading] = useState(false);
  const [watchForm, setWatchForm] = useState({ query: '', queryType: 'domain', depth: 1, intervalMinutes: 60 });
  const [exifResults, setExifResults] = useState([]);
  const wsRef = useRef(null);
  const flowInstanceRef = useRef(null);
  const retryTimerRef = useRef(null);
  const generationRef = useRef(0);
  const activeScanRef = useRef(null);
  const nodeCounterRef = useRef(0);
  const graphNodesRef = useRef([]);
  const graphEdgesRef = useRef([]);
  const scanContextRef = useRef(null);
  const categoryNodeIdsRef = useRef(new Map());

  const pushToast = useCallback((message) => {
    if (!message) return;
    setToast(message);
    window.setTimeout(() => setToast((current) => (current === message ? '' : current)), 1600);
  }, []);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      window.localStorage.setItem('wvcxxosint.theme', theme);
    } catch (storageError) {
      console.error('Could not save theme preference', storageError);
    }
  }, [theme]);

  const applyLayout = useCallback((nextNodes, nextEdges) => {
    const layout = getLayoutedElements(nextNodes, nextEdges);
    graphNodesRef.current = layout.nodes;
    graphEdgesRef.current = layout.edges;
    setNodes(layout.nodes);
    setEdges(layout.edges);
    const flow = flowInstanceRef.current;
    if (flow) {
      window.requestAnimationFrame(() => {
        if (flowInstanceRef.current === flow) flow.fitView({ padding: 0.16, maxZoom: 1, duration: 250 });
      });
    }
  }, [setEdges, setNodes]);

  useEffect(() => {
    graphNodesRef.current = nodes;
    graphEdgesRef.current = edges;
  }, [edges, nodes]);

  useEffect(() => {
    const controller = new AbortController();
    fetch(`${getApiBase()}/api/tools`, { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error(`Backend returned HTTP ${response.status}`);
        return response.json();
      })
      .then((payload) => {
        if (!Array.isArray(payload.tools)) throw new Error('Backend returned an invalid tools catalogue');
        setTools(payload.tools);
        setToolsError('');
      })
      .catch((fetchError) => {
        if (fetchError.name !== 'AbortError') {
          console.error('Could not load tools catalogue', fetchError);
          setToolsError('Не удалось загрузить реестр модулей. Проверьте backend.');
        }
      });
    return () => controller.abort();
  }, []);

  useEffect(() => {
    const refreshTools = async () => {
      try {
        const response = await fetch(`${getApiBase()}/api/tools`);
        if (!response.ok) throw new Error(`Backend returned HTTP ${response.status}`);
        const payload = await response.json();
        if (Array.isArray(payload.tools)) setTools(payload.tools);
      } catch (refreshError) {
        console.error('Could not refresh tools catalogue', refreshError);
      }
    };
    window.addEventListener('osint-tools-updated', refreshTools);
    return () => window.removeEventListener('osint-tools-updated', refreshTools);
  }, []);

  useEffect(() => {
    try {
      window.localStorage.setItem('wvcxxosint.language', language);
    } catch (storageError) {
      console.error('Could not save language preference', storageError);
    }
  }, [language]);

  // Command palette: Ctrl+K / Cmd+K.
  useEffect(() => {
    const handler = (event) => {
      if ((event.ctrlKey || event.metaKey) && String(event.key).toLowerCase() === 'k') {
        event.preventDefault();
        setPaletteOpen(true);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, []);

  const saveInvestigation = useCallback((scan, resultNodes, resultEdges) => {
    const saved = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      query: scan.query,
      label: scan.query,
      tags: [],
      inputType: scan.queryType,
      depth: scan.depth,
      createdAt: new Date().toISOString(),
      nodes: resultNodes,
      edges: resultEdges,
    };
    setHistory((previous) => {
      const next = [saved, ...previous].slice(0, 50);
      if (!saveHistory(next)) setError('Исследование готово, но браузер не смог сохранить его в историю.');
      return next;
    });
    return saved;
  }, []);

  const connectScan = useCallback(function connectScan(scan, generation, retryCount, overrideType) {
    if (generationRef.current !== generation) return;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.hostname || '127.0.0.1';
    const socket = new WebSocket(`${protocol}//${host}:8000/ws/scan`);
    wsRef.current = socket;
    let receivedDone = false;

    socket.onopen = () => {
      if (generationRef.current !== generation) {
        socket.close();
        return;
      }
      setConnectionStatus('');
      socket.send(JSON.stringify({
        query: scan.query,
        query_type: scan.queryType ?? overrideType,
        depth: scan.depth,
        ...(scan.retryTitles?.length ? { retry_titles: scan.retryTitles } : {}),
      }));
    };

    socket.onmessage = (event) => {
      if (generationRef.current !== generation) return;
      let message;
      try {
        message = JSON.parse(event.data);
      } catch (parseError) {
        console.error('Backend sent an invalid WebSocket message', parseError);
        setError('Сервер прислал некорректный ответ.');
        setLoading(false);
        activeScanRef.current = null;
        socket.close();
        return;
      }

      if (message.error) {
        setError(message.error);
        setLoading(false);
        activeScanRef.current = null;
        scanContextRef.current = null;
        socket.close();
        return;
      }

      if (message.type === 'root') {
        if (!scan.retryTitles?.length) {
          nodeCounterRef.current = 0;
          categoryNodeIdsRef.current = new Map();
        }
        scan.queryType = message.data.input_type;
        setQueryType(message.data.input_type);
        setProgress({ completed: 0, total: 0, results: 0 });
        setCollapsedCategories(new Set());
        setDiffPanel(null);
        const root = makeGraphNode('root', {
          title: t.targetTitle,
          status: 'root',
          state: 'root',
          isRoot: true,
          query: message.data.query,
          inputType: message.data.input_type,
          fields: [],
        });
        if (!scan.retryTitles?.length) applyLayout([root], []);
        return;
      }

      if (message.type === 'loading' || message.type === 'node') {
        const isPlaceholder = message.type === 'loading';
        const data = isPlaceholder
          ? { ...message.data, status: 'loading', state: 'loading', fields: [] }
          : { ...message.data, fields: Array.isArray(message.data.fields) ? message.data.fields : [] };
        let nextNodes = [...graphNodesRef.current];
        let nextEdges = [...graphEdgesRef.current];

        // Категория: создаём узел группы один раз.
        let categoryNodeId = 'root';
        if (data.category) {
          const existing = categoryNodeIdsRef.current.get(data.category);
          if (!existing) {
            categoryNodeId = `category-${data.category}`;
            categoryNodeIdsRef.current.set(data.category, categoryNodeId);
            nextNodes.push(makeGraphNode(categoryNodeId, {
              title: categoryLabel(data.category, language) || data.category,
              status: 'info',
              state: 'info',
              isCategory: true,
              category: data.category,
              count: 0,
              fields: [],
            }));
            nextEdges.push({
              id: `edge-root-${categoryNodeId}`,
              source: 'root',
              target: categoryNodeId,
              type: 'smoothstep',
              className: 'relationship-edge',
              style: { stroke: '#343941', strokeWidth: 1 },
            });
          } else {
            categoryNodeId = existing;
          }
        }

        let targetNodeId;
        if (!isPlaceholder) {
          const checkId = data.check_id ? `check-${data.check_id}` : null;
          const placeholderIndex = checkId ? nextNodes.findIndex((node) => node.id === checkId) : -1;
          if (placeholderIndex >= 0 && (data.check_index || 0) === 0) {
            const replacement = { ...nextNodes[placeholderIndex], data: { ...nextNodes[placeholderIndex].data, ...data } };
            nextNodes[placeholderIndex] = replacement;
            targetNodeId = checkId;
          } else {
            const id = `result-${++nodeCounterRef.current}`;
            nextNodes.push(makeGraphNode(id, data));
            const edge = {
              id: `edge-${categoryNodeId}-${id}`,
              source: categoryNodeId,
              target: id,
              type: 'smoothstep',
              label: language === 'ru' ? 'проверка' : 'check',
              className: 'relationship-edge',
              style: { stroke: '#343941', strokeWidth: 1.5 },
              labelStyle: { fill: '#9298a3', fontSize: 10 },
            };
            nextEdges.push(edge);
            targetNodeId = id;
          }
          // Обновляем счётчик карточек у категории.
          if (data.category) {
            const catIndex = nextNodes.findIndex((node) => node.id === categoryNodeId);
            if (catIndex >= 0) {
              nextNodes[catIndex] = {
                ...nextNodes[catIndex],
                data: { ...nextNodes[catIndex].data, count: (nextNodes[catIndex].data.count || 0) + 1 },
              };
            }
          }
        } else {
          const id = `check-${data.check_id}`;
          nextNodes.push(makeGraphNode(id, data));
          nextEdges.push({
            id: `edge-${categoryNodeId}-${id}`,
            source: categoryNodeId,
            target: id,
            type: 'smoothstep',
            className: 'relationship-edge',
            style: { stroke: '#343941', strokeWidth: 1.5 },
            labelStyle: { fill: '#9298a3', fontSize: 10 },
          });
          targetNodeId = id;
        }

        applyLayout(nextNodes, nextEdges);
        window.requestAnimationFrame(() => {
          const found = graphNodesRef.current.find((node) => node.id === targetNodeId);
          if (found && !isPlaceholder) setSelectedNode(found);
        });
        return;
      }

      if (message.type === 'progress') {
        setProgress(message.data);
        return;
      }

      if (message.type === 'done') {
        receivedDone = true;
        activeScanRef.current = null;
        scanContextRef.current = null;
        setLoading(false);
        setConnectionStatus('');
        saveInvestigation(scan, graphNodesRef.current, graphEdgesRef.current);
        socket.close();
      }
    };

    socket.onerror = () => {
      if (generationRef.current === generation) setConnectionStatus('Связь с backend прервана…');
    };

    socket.onclose = () => {
      if (generationRef.current !== generation || activeScanRef.current !== generation || receivedDone) return;
      if (retryCount < 2) {
        const delay = 500 * (2 ** retryCount);
        setConnectionStatus(`Переподключение ${retryCount + 1}/2…`);
        retryTimerRef.current = window.setTimeout(() => {
          if (generationRef.current !== generation) return;
          graphNodesRef.current = [];
          graphEdgesRef.current = [];
          setNodes([]);
          setEdges([]);
          setProgress({ completed: 0, total: 0, results: 0 });
          connectScan(scan, generation, retryCount + 1, overrideType);
        }, delay);
        return;
      }
      activeScanRef.current = null;
      setLoading(false);
      setConnectionStatus('');
      setError('Не удалось подключиться к серверу. Проверьте, что backend запущен.');
    };
  }, [applyLayout, saveInvestigation, setEdges, setNodes, language, t.targetTitle]);

  const depthEnabled = ['email', 'domain', 'url'].includes(queryType)
    || (queryType === 'auto' && (
      query.includes('@')
      || query.includes('.')
      || query.toLowerCase().startsWith('http://')
      || query.toLowerCase().startsWith('https://')
    ));

  const startScan = useCallback(function startScan(scanQuery, scanType, scanDepth, retryTitles = []) {
    const scanQueryTrimmed = String(scanQuery || '').trim();
    if (!scanQueryTrimmed) return;
    const retrySet = new Set(retryTitles);
    const scan = {
      query: scanQueryTrimmed,
      queryType: scanType,
      depth: Number(scanDepth) || 1,
      retryTitles: [...retrySet],
    };
    generationRef.current += 1;
    const generation = generationRef.current;
    activeScanRef.current = generation;
    scanContextRef.current = scan;
    window.clearTimeout(retryTimerRef.current);
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.close();
    }
    if (retrySet.size) {
      const removedIds = new Set(graphNodesRef.current
        .filter((node) => retrySet.has(node.data.check_title || node.data.title))
        .map((node) => node.id));
      const retainedNodes = graphNodesRef.current.filter((node) => !removedIds.has(node.id));
      const retainedEdges = graphEdgesRef.current.filter((edge) => (
        !removedIds.has(edge.source) && !removedIds.has(edge.target)
      ));
      const categoryCounts = new Map();
      retainedNodes.forEach((node) => {
        if (!node.data.isRoot && !node.data.isCategory && node.data.category) {
          categoryCounts.set(node.data.category, (categoryCounts.get(node.data.category) || 0) + 1);
        }
      });
      graphNodesRef.current = retainedNodes.map((node) => (node.data.isCategory
        ? { ...node, data: { ...node.data, count: categoryCounts.get(node.data.category) || 0 } }
        : node));
      graphEdgesRef.current = retainedEdges;
      setNodes(graphNodesRef.current);
      setEdges(retainedEdges);
      nodeCounterRef.current = retainedNodes.reduce((largest, node) => {
        const match = /^result-(\d+)$/.exec(node.id);
        return match ? Math.max(largest, Number(match[1])) : largest;
      }, 0);
      categoryNodeIdsRef.current = new Map(retainedNodes
        .filter((node) => node.data.isCategory && node.data.category)
        .map((node) => [node.data.category, node.id]));
    } else {
      nodeCounterRef.current = 0;
      categoryNodeIdsRef.current = new Map();
      graphNodesRef.current = [];
      graphEdgesRef.current = [];
      setNodes([]);
      setEdges([]);
    }
    setSelectedNode(null);
    setNoteDraftState({ key: null, value: '' });
    setError('');
    setConnectionStatus('Подключение к анализаторам…');
    setLoading(true);
    setView('investigation');
    setTimelineMode('graph');
    connectScan(scan, generation, 0);
  }, [connectScan, setEdges, setNodes, setNoteDraftState]);

  const cancelScan = useCallback(() => {
    generationRef.current += 1;
    activeScanRef.current = null;
    window.clearTimeout(retryTimerRef.current);
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.onerror = null;
      wsRef.current.close(1000, 'Scan cancelled by user');
      wsRef.current = null;
    }
    const retainedNodes = graphNodesRef.current.filter((node) => node.data.state !== 'loading');
    const retainedIds = new Set(retainedNodes.map((node) => node.id));
    const retainedEdges = graphEdgesRef.current.filter((edge) => (
      retainedIds.has(edge.source) && retainedIds.has(edge.target)
    ));
    const categoryCounts = new Map();
    retainedNodes.forEach((node) => {
      if (!node.data.isRoot && !node.data.isCategory && node.data.category) {
        categoryCounts.set(node.data.category, (categoryCounts.get(node.data.category) || 0) + 1);
      }
    });
    const nextNodes = retainedNodes.map((node) => (node.data.isCategory
      ? { ...node, data: { ...node.data, count: categoryCounts.get(node.data.category) || 0 } }
      : node));
    const scan = scanContextRef.current;
    graphNodesRef.current = nextNodes;
    graphEdgesRef.current = retainedEdges;
    applyLayout(nextNodes, retainedEdges);
    setLoading(false);
    setConnectionStatus('');
    scanContextRef.current = null;
    if (scan && nextNodes.some((node) => !node.data.isRoot && !node.data.isCategory)) {
      saveInvestigation(scan, nextNodes, retainedEdges);
    }
    pushToast(language === 'ru' ? 'Проверка остановлена; готовые результаты сохранены.' : 'Scan stopped; completed results were saved.');
  }, [applyLayout, language, pushToast, saveInvestigation]);

  const handleSearch = useCallback((event) => {
    event.preventDefault();
    startScan(query, queryType, depthEnabled ? depth : 1);
  }, [depth, depthEnabled, query, queryType, startScan]);

  useEffect(() => () => {
    generationRef.current += 1;
    activeScanRef.current = null;
    window.clearTimeout(retryTimerRef.current);
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.close();
    }
  }, []);

  // Заметки: локальное хранилище, привязанное к стабильному id проверки.
  const selectedNoteKey = useMemo(() => (
    selectedNode ? `wvcxxosint.note.${selectedNode.data.id || selectedNode.id}` : null
  ), [selectedNode]);

  // Загрузка заметки при смене узла (без эффектов — паттерн «состояние во время рендера»).
  if (selectedNoteKey !== noteDraftState.key) {
    let nextNoteValue = '';
    if (selectedNoteKey) {
      try {
        nextNoteValue = window.localStorage.getItem(selectedNoteKey) || '';
      } catch (storageError) {
        console.error('Could not read note', storageError);
        nextNoteValue = '';
      }
    }
    setNoteDraftState({ key: selectedNoteKey, value: nextNoteValue });
  }
  const noteDraft = noteDraftState.value;

  const saveNote = useCallback((value) => {
    setNoteDraftState({ key: selectedNoteKey, value });
    if (!selectedNoteKey) return;
    try {
      if (value) {
        window.localStorage.setItem(selectedNoteKey, value);
      } else {
        window.localStorage.removeItem(selectedNoteKey);
      }
    } catch (storageError) {
      console.error('Could not save note', storageError);
    }
  }, [selectedNoteKey, setNoteDraftState]);

  const visibleNodes = useMemo(() => nodes.filter((node) => {
    if (node.data.isRoot) return true;
    if (node.data.isCategory) return !categoryFilter || node.data.category === categoryFilter;
    if (node.data.category && collapsedCategories.has(node.data.category)) return false;
    const searchMatch = !graphSearch
      || `${node.data.title} ${node.data.query || ''} ${(node.data.fields || []).map((field) => field.value).join(' ')}`
        .toLocaleLowerCase().includes(graphSearch.toLocaleLowerCase());
    const currentStatus = node.data.state || node.data.status;
    const statusMatch = !statusFilter || currentStatus === statusFilter;
    const categoryMatch = !categoryFilter || node.data.category === categoryFilter;
    const sourceMatch = !sourceFilter || node.data.tool === sourceFilter;
    const typeMatch = !nodeTypeFilter || node.data.entityType === nodeTypeFilter;
    return searchMatch && statusMatch && categoryMatch && sourceMatch && typeMatch;
  }), [categoryFilter, collapsedCategories, graphSearch, nodeTypeFilter, nodes, sourceFilter, statusFilter]);
  const visibleNodeIds = useMemo(() => new Set(visibleNodes.map((node) => node.id)), [visibleNodes]);
  const visibleEdges = useMemo(() => edges.filter((edge) => (
    visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target)
  )), [edges, visibleNodeIds]);
  const resultNodes = nodes.filter((node) => !node.data.isRoot && !node.data.isCategory);
  const retryableTitles = [...new Set(resultNodes
    .filter((node) => ['failed', 'rate_limited'].includes(node.data.state || node.data.status))
    .map((node) => node.data.check_title || node.data.tool || node.data.title))];
  const progressPercent = progress.total ? Math.round((progress.completed / progress.total) * 100) : 0;
  const availableSources = [...new Set(resultNodes.map((node) => node.data.tool || node.data.title))];
  const availableCategories = [...new Set(resultNodes.map((node) => node.data.category).filter(Boolean))];

  const toggleCategoryCollapse = useCallback((categoryKey) => {
    setCollapsedCategories((previous) => {
      const next = new Set(previous);
      if (next.has(categoryKey)) {
        next.delete(categoryKey);
      } else {
        next.add(categoryKey);
      }
      return next;
    });
  }, []);

  const hideSelectedBranch = useCallback(() => {
    if (!selectedNode || selectedNode.id === 'root') return;
    const hidden = new Set([selectedNode.id]);
    let changed = true;
    while (changed) {
      changed = false;
      edges.forEach((edge) => {
        if (hidden.has(edge.source) && !hidden.has(edge.target)) {
          hidden.add(edge.target);
          changed = true;
        }
      });
    }
    const nextNodes = nodes.filter((node) => !hidden.has(node.id));
    const nextEdges = edges.filter((edge) => !hidden.has(edge.source) && !hidden.has(edge.target));
    graphNodesRef.current = nextNodes;
    graphEdgesRef.current = nextEdges;
    setNodes(nextNodes);
    setEdges(nextEdges);
    setSelectedNode(null);
  }, [edges, nodes, selectedNode, setEdges, setNodes]);

  const updateHistoryMetadata = (id, field, value) => {
    setHistory((previous) => {
      const next = previous.map((item) => (item.id === id ? { ...item, [field]: value } : item));
      if (!saveHistory(next)) setError('Не удалось сохранить метаданные истории в браузере.');
      return next;
    });
  };

  const openHistoryItem = (item) => {
    graphNodesRef.current = item.nodes;
    graphEdgesRef.current = item.edges;
    const categories = new Map();
    for (const node of item.nodes || []) {
      if (node?.data?.isCategory && node.data.category) {
        categories.set(node.data.category, node.id);
      }
    }
    categoryNodeIdsRef.current = new Map(categories);
    setNodes(item.nodes);
    setEdges(item.edges);
    setQuery(item.query);
    setQueryType(item.inputType || 'email');
    setDepth(item.depth || 1);
    setSelectedNode(null);
    setError('');
    setDiffPanel(null);
    setView('investigation');
    window.requestAnimationFrame(() => flowInstanceRef.current?.fitView({ padding: 0.16, maxZoom: 1 }));
  };

  const computeDiffAgainst = (baseItem) => {
    const current = resultNodes;
    const previous = (baseItem.nodes || []).filter((node) => !node.data.isRoot && !node.data.isCategory);
    const previousByTitle = new Map(previous.map((node) => [String(node.data.title || ''), node]));
    const added = [];
    const changed = [];
    const removed = [];
    const currentTitles = new Set();
    for (const node of current) {
      const title = String(node.data.title || '');
      currentTitles.add(title);
      const old = previousByTitle.get(title);
      if (!old) {
        added.push({ title, state: node.data.state });
      } else if (old.data.state !== node.data.state) {
        changed.push({ title, from: old.data.state, to: node.data.state });
      }
    }
    for (const node of previous) {
      const title = String(node.data.title || '');
      if (!currentTitles.has(title)) removed.push(title);
    }
    setDiffPanel({ baseId: baseItem.id, added, changed, removed });
    setView('investigation');
  };

  const exportResults = useCallback((format) => {
    if (!nodes.length) {
      setError('Нет результатов для экспорта.');
      return;
    }
    const filename = `osint-spider-${new Date().toISOString().replaceAll(':', '-')}`;
    if (format === 'json') {
      downloadFile(`${filename}.json`, JSON.stringify({
        query,
        queryType,
        exportedAt: new Date().toISOString(),
        nodes,
        edges,
      }, null, 2), 'application/json');
    } else if (format === 'csv') {
      const rows = [['id', 'entity_type', 'category', 'query', 'tool', 'check_title', 'state', 'confidence', 'evidence_type', 'received_at', 'source_url', 'errors', 'limitations', 'field', 'value']];
      nodes.filter((node) => !node.data.isRoot).forEach((node) => {
        const data = node.data;
        const fields = data.fields?.length ? data.fields : [{ label: '', value: '' }];
        fields.forEach((field) => rows.push([
          node.id, data.entityType || 'OSINT Module', data.category || '', data.query, data.tool || data.title,
          data.check_title || '', data.state || data.status, data.confidence || '', data.evidence_type || '',
          data.received_at || '', data.source_url || '', (data.errors || []).join('; '), (data.limitations || []).join('; '),
          field.label, field.value,
        ]));
      });
      downloadFile(`${filename}.csv`, rows.map((row) => row.map(csvValue).join(',')).join('\r\n'), 'text/csv;charset=utf-8');
    } else if (format === 'svg') {
      downloadFile(`${filename}.svg`, buildSvg(nodes, edges, query), 'image/svg+xml;charset=utf-8');
    } else if (format === 'md') {
      downloadFile(`${filename}.md`, buildMarkdown(query, nodes, language, queryType), 'text/markdown;charset=utf-8');
    } else if (format === 'pdf') {
      printReport(buildReportHtml(query, nodes, edges.length, queryType));
    }
    setError('');
  }, [edges, language, nodes, query, queryType]);

  const visibleTools = tools.filter((tool) => {
    const localized = localizeTool(tool, language);
    const searchText = `${tool.name} ${tool.category} ${tool.description} ${localized.name} ${localized.category} ${localized.description}`;
    return (!toolsSearch || searchText.toLowerCase().includes(toolsSearch.toLowerCase()))
      && (!toolsTypeFilter || tool.input_types.includes(toolsTypeFilter))
      && (!toolsCategoryFilter || tool.category === toolsCategoryFilter)
      && (!toolsStatusFilter || (toolsStatusFilter === 'adapter_unavailable'
        ? tool.adapter_implemented === false
        : tool.status === toolsStatusFilter))
      && (!toolsApiFilter || String(Boolean(tool.requires_api_key || tool.optional_api_key)) === toolsApiFilter);
  });
  const toolCategories = [...new Set(tools.map((tool) => tool.category))].sort();
  const filteredHistory = history.filter((item) => (
    !historySearch || `${item.query} ${item.label || ''} ${(item.tags || []).join(' ')} ${item.inputType}`
      .toLowerCase().includes(historySearch.toLowerCase())
  ));

  // Опрос и управление наблюдениями мониторинга.
  useEffect(() => {
    if (view !== 'monitoring') return undefined;
    let cancelled = false;
    const load = async () => {
      try {
        const response = await fetch(`${getApiBase()}/api/watch`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const payload = await response.json();
        if (!cancelled) {
          setWatches(Array.isArray(payload.watches) ? payload.watches : []);
          setWatchesError('');
        }
      } catch (loadError) {
        if (!cancelled) {
          console.error(loadError);
          setWatchesError(language === 'ru' ? 'Не удалось загрузить список наблюдений.' : 'Could not load watches.');
        }
      }
    };
    load();
    const timer = window.setInterval(load, 15000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [language, view]);

  const createWatch = async () => {
    setWatchLoading(true);
    try {
      const response = await fetch(`${getApiBase()}/api/watch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: watchForm.query.trim(),
          query_type: watchForm.queryType,
          depth: Number(watchForm.depth),
          interval_minutes: Number(watchForm.intervalMinutes),
        }),
      });
      const payload = await response.json();
      if (payload.error) {
        setWatchesError(payload.error);
      } else {
        setWatchesError('');
        setWatchForm((form) => ({ ...form, query: '' }));
        setView('monitoring');
      }
    } catch (createError) {
      console.error(createError);
      setWatchesError(language === 'ru' ? 'Backend недоступен.' : 'Backend is unavailable.');
    } finally {
      setWatchLoading(false);
    }
  };

  const deleteWatch = async (id) => {
    try {
      await fetch(`${getApiBase()}/api/watch/${id}`, { method: 'DELETE' });
      setWatches((previous) => previous.filter((item) => item.id !== id));
    } catch (deleteError) {
      console.error(deleteError);
    }
  };

  const paletteActions = useMemo(() => ([
    { id: 'scan-current', label: language === 'ru' ? 'Проверить текущий запрос' : 'Run current query', hint: query || undefined, run: () => startScan(query, 'auto', 1) },
    { id: 'nav-investigation', label: language === 'ru' ? 'Перейти: Расследование' : 'Go: Investigation', run: () => setView('investigation') },
    { id: 'nav-tools', label: language === 'ru' ? 'Перейти: Инструменты' : 'Go: Tools', run: () => setView('tools') },
    { id: 'nav-monitoring', label: language === 'ru' ? 'Перейти: Мониторинг' : 'Go: Monitoring', run: () => setView('monitoring') },
    { id: 'nav-history', label: language === 'ru' ? 'Перейти: История' : 'Go: History', run: () => setView('history') },
    { id: 'nav-reports', label: language === 'ru' ? 'Перейти: Отчёты' : 'Go: Reports', run: () => setView('reports') },
    { id: 'center', label: language === 'ru' ? 'Центрировать граф' : 'Center graph', run: () => flowInstanceRef.current?.fitView({ padding: 0.16, maxZoom: 1 }) },
    { id: 'theme', label: theme === 'light' ? (language === 'ru' ? 'Тёмная тема' : 'Dark theme') : (language === 'ru' ? 'Светлая тема' : 'Light theme'), run: () => setTheme(theme === 'light' ? 'dark' : 'light') },
    { id: 'language', label: language === 'ru' ? 'Интерфейс: English' : 'Interface: Русский', run: () => setLanguage(language === 'ru' ? 'en' : 'ru') },
    { id: 'export-json', label: language === 'ru' ? 'Экспорт JSON' : 'Export JSON', run: () => exportResults('json') },
    { id: 'export-csv', label: language === 'ru' ? 'Экспорт CSV' : 'Export CSV', run: () => exportResults('csv') },
    { id: 'export-svg', label: language === 'ru' ? 'Экспорт SVG' : 'Export SVG', run: () => exportResults('svg') },
    { id: 'export-md', label: language === 'ru' ? 'Экспорт Markdown' : 'Export Markdown', run: () => exportResults('md') },
    { id: 'export-pdf', label: language === 'ru' ? 'Экспорт PDF (печать)' : 'Export PDF (print)', run: () => exportResults('pdf') },
  ]), [exportResults, language, query, startScan, theme]);

  const inspectorNode = useMemo(() => {
    if (selectedNode) {
      const fresh = nodes.find((node) => node.id === selectedNode.id);
      return fresh || selectedNode;
    }
    return null;
  }, [nodes, selectedNode]);

  return (
    <LanguageContext.Provider value={language}>
      <ToastContext.Provider value={pushToast}>
        <SidebarRail
          items={NAV_ITEMS}
          activeView={view}
          theme={theme}
          onToggleTheme={() => setTheme(theme === 'light' ? 'dark' : 'light')}
          onSelect={(id) => {
            if (id === '__toggle-language') {
              setLanguage(language === 'ru' ? 'en' : 'ru');
              return;
            }
            setView(id);
          }}
        />
        <div className="app-frame">
          <header className="top-bar">
            <a className="brand" href="/" aria-label="OSINT Spider — главная" onClick={(event) => { event.preventDefault(); setView('investigation'); }}>
              <span className="brand-mark" aria-hidden="true">S</span>
              <span className="brand-copy"><strong>OSINT Spider</strong><span>Open-source intelligence</span></span>
            </a>
            <button
              className="palette-trigger"
              onClick={() => setPaletteOpen(true)}
              type="button"
              aria-label={language === 'ru' ? 'Командная палитра' : 'Command palette'}
            >
              <Command className="palette-trigger-icon" aria-hidden="true" />
              {language === 'ru' ? 'Команды' : 'Commands'} <kbd>Ctrl K</kbd>
            </button>
          </header>

      {view === 'investigation' ? (
        <section className="invest-grid">
          <div className="canvas-column">
            <form className="query-toolbar" onSubmit={handleSearch}>
              <label className="query-type">
                <span>{language === 'ru' ? 'Тип' : 'Type'}</span>
                <select value={queryType} onChange={(event) => setQueryType(event.target.value)}>
                  {QUERY_TYPES.map(([value, english, russian]) => <option key={value} value={value}>{language === 'ru' ? russian : english}</option>)}
                </select>
              </label>
              <label className="query-input">
                <Search className="search-icon" aria-hidden="true" />
                <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t.placeholder} aria-label={t.search} maxLength={255} />
              </label>
              <label className="depth-select">
                <span>{t.depth}</span>
                <select value={depth} disabled={!depthEnabled} onChange={(event) => setDepth(Number(event.target.value))}>
                  <option value={1}>1</option><option value={2}>2</option><option value={3}>3</option>
                </select>
              </label>
              {loading ? (
                <button className="scan-button scan-cancel-button" type="button" onClick={cancelScan}>
                  <Square aria-hidden="true" />{t.cancelScan}
                </button>
              ) : (
                <button className="scan-button" type="submit" disabled={!query.trim()}>{t.analyze}</button>
              )}
            </form>

            <div className="graph-toolbar">
              <label className="graph-search">
                <Search className="search-icon" aria-hidden="true" />
                <input value={graphSearch} onChange={(event) => setGraphSearch(event.target.value)} placeholder={t.searchGraph} />
              </label>
              <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)} aria-label={t.allStatuses}>
                <option value="">{t.allStatuses}</option>
                <option value="completed">{language === 'ru' ? 'Завершено' : 'Completed'}</option>
                <option value="partial">{language === 'ru' ? 'Частично' : 'Partial'}</option>
                <option value="no_results">{language === 'ru' ? 'Нет результатов' : 'No results'}</option>
                <option value="failed">{language === 'ru' ? 'Ошибка' : 'Failed'}</option>
                <option value="rate_limited">{language === 'ru' ? 'Лимит запросов' : 'Rate limited'}</option>
                <option value="not_configured">{language === 'ru' ? 'Не подключено' : 'Not configured'}</option>
              </select>
              <select value={categoryFilter} onChange={(event) => setCategoryFilter(event.target.value)} aria-label={t.allCategories}>
                <option value="">{t.allCategories}</option>
                {availableCategories.map((category) => <option key={category} value={category}>{categoryLabel(category, language)}</option>)}
              </select>
              {availableCategories.length ? (
                <div className="category-chips" role="group" aria-label={t.allCategories}>
                  <button className={`category-chip${!categoryFilter ? ' is-active' : ''}`} onClick={() => setCategoryFilter('')} type="button">{t.allCategories}</button>
                  {availableCategories.map((category) => (
                    <button
                      key={category}
                      className={`category-chip${categoryFilter === category ? ' is-active' : ''}`}
                      onClick={() => setCategoryFilter(categoryFilter === category ? '' : category)}
                      type="button"
                    >
                      {categoryLabel(category, language)}
                    </button>
                  ))}
                </div>
              ) : null}
              <select value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value)} aria-label={language === 'ru' ? 'Источник' : 'Source'}>
                <option value="">{language === 'ru' ? 'Все источники' : 'All sources'}</option>
                {availableSources.map((source) => <option key={source} value={source}>{source}</option>)}
              </select>
              <div className="view-mode-toggle">
                <button className={timelineMode === 'graph' ? 'is-active' : ''} onClick={() => setTimelineMode('graph')} type="button">{t.graph}</button>
                <button className={timelineMode === 'timeline' ? 'is-active' : ''} onClick={() => setTimelineMode('timeline')} type="button">{t.timeline}</button>
              </div>
              {retryableTitles.length && !loading ? (
                <button className="secondary-button retry-failed-button" type="button" onClick={() => startScan(query, queryType, depth, retryableTitles)}>
                  <RotateCcw aria-hidden="true" />{t.retryFailed} · {retryableTitles.length}
                </button>
              ) : null}
              <details className="export-menu">
                <summary>{t.export}</summary>
                <div className="export-menu-items">
                  <button type="button" onClick={() => { exportResults('json'); setPaletteOpen(false); }}>JSON</button>
                  <button type="button" onClick={() => exportResults('csv')}>CSV</button>
                  <button type="button" onClick={() => exportResults('svg')}>SVG</button>
                  <button type="button" onClick={() => exportResults('md')}>Markdown</button>
                  <button type="button" onClick={() => exportResults('pdf')}>PDF</button>
                </div>
              </details>
              <button className="secondary-button" type="button" onClick={() => flowInstanceRef.current?.fitView({ padding: 0.16, maxZoom: 1 })}>{t.center}</button>
            </div>

            <div className="graph-frame">
              {nodes.length === 0 && !loading ? (
                <div className="empty-state">
                  <div className="empty-mark" aria-hidden="true"><ScanSearch /></div>
                  <h2>{t.emptyTitle}</h2>
                  <p>{t.emptyText}</p>
                  <p className="empty-hint">{language === 'ru' ? 'Ctrl+K — быстрая команда' : 'Ctrl+K — quick command'}</p>
                  <div className="empty-samples">
                    <button type="button" onClick={() => { setQueryType('domain'); setQuery('example.com'); }}>example.com</button>
                    <button type="button" onClick={() => { setQueryType('email'); setQuery('analyst@example.com'); }}>analyst@example.com</button>
                  </div>
                </div>
              ) : null}
              {connectionStatus ? <div className="connection-banner" role="status">{connectionStatus}</div> : null}
              {!loading && !connectionStatus && nodes.length > 0 && resultNodes.length === 0 && !error ? (
                <div className="no-results-banner" role="status">{t.noResults}</div>
              ) : null}
              {error ? <div className="error-banner" role="alert">{error}<button onClick={() => setError('')} aria-label="Закрыть">×</button></div> : null}

              <div className={`graph-canvas${timelineMode === 'timeline' ? ' is-hidden' : ''}`}>
                <ReactFlow
                  nodes={visibleNodes}
                  edges={visibleEdges}
                  nodeTypes={nodeTypes}
                  edgeTypes={edgeTypes}
                  onInit={(instance) => { flowInstanceRef.current = instance; }}
                  onNodesChange={onNodesChange}
                  onEdgesChange={onEdgesChange}
                  onNodeClick={(_, node) => {
                    if (node?.data?.isCategory && node.data.category) {
                      toggleCategoryCollapse(node.data.category);
                    }
                    setSelectedNode(node);
                  }}
                  fitView
                  fitViewOptions={{ padding: 0.16, maxZoom: 1 }}
                  minZoom={0.15}
                  maxZoom={1.5}
                  proOptions={{ hideAttribution: true }}
                >
                  <Background color={theme === 'light' ? '#c9d6d2' : '#2b373a'} gap={24} size={1} />
                  <MiniMap className="graph-minimap" nodeColor={(node) => {
                    const status = node.data.state || node.data.status;
                    return status === 'completed' || status === 'ok' ? '#41b985'
                      : status === 'failed' || status === 'error' ? '#e77378'
                        : status === 'not_configured' ? '#a1aeae' : '#35ae9d';
                  }} maskColor={theme === 'light' ? 'rgba(239, 243, 242, 0.8)' : 'rgba(14, 18, 20, 0.75)'} />
                  <Controls />
                </ReactFlow>
              </div>
              {timelineMode === 'timeline' ? (
                <div className="timeline-wrap">
                  <Timeline
                    nodes={resultNodes}
                    selectedId={selectedNode?.id}
                    onSelect={(node) => setSelectedNode(node)}
                  />
                </div>
              ) : null}
              <CategoryFeed
                nodes={resultNodes}
                selectedId={selectedNode?.id}
                onSelect={(node) => setSelectedNode(node)}
              />
            </div>

            <footer className="analysis-footer">
              <span><i className={`status-dot${loading ? ' is-working' : ''}`} />{loading ? (language === 'ru' ? 'Проверки выполняются' : 'Checks running') : (language === 'ru' ? 'Состояние исследования' : 'Investigation status')}</span>
              <span className="analysis-progress">
                <span className="progress-track"><i style={{ width: `${progressPercent}%` }} /></span>
                <span>{language === 'ru' ? 'Проверки' : 'Checks'} {progress.completed}/{progress.total}</span>
              </span>
              <span>{resultNodes.length} {t.findings}</span>
              <span>{tools.filter((tool) => tool.status === 'available').length} {language === 'ru' ? 'модулей доступно' : 'modules available'}</span>
              <span>{history.length} {language === 'ru' ? 'сохранено локально' : 'saved locally'}</span>
            </footer>
          </div>

          <aside className="inspector-column">
            <Inspector
              node={inspectorNode}
              language={language}
              t={t}
              summary={{ query, results: resultNodes }}
              diffPanel={diffPanel}
              onCloseDiff={() => setDiffPanel(null)}
              onHideBranch={hideSelectedBranch}
              onDeepDive={(value) => startScan(value, 'auto', 1)}
              noteValue={noteDraft}
              onNoteChange={saveNote}
            />
          </aside>
        </section>
      ) : null}

      {view === 'tools' ? (
        <section className="page-content">
          <PageHeading eyebrow="CATALOG" title={language === 'ru' ? 'Каталог инструментов' : 'Tools catalogue'} detail={`${tools.length} ${language === 'ru' ? 'модулей в реестре backend' : 'modules registered by backend'}`} />
          {toolsError ? <div className="error-banner inline-error">{toolsError}</div> : null}
          <div className="catalog-filters">
            <input value={toolsSearch} onChange={(event) => setToolsSearch(event.target.value)} placeholder={language === 'ru' ? 'Поиск инструмента' : 'Search tools'} />
            <select value={toolsTypeFilter} onChange={(event) => setToolsTypeFilter(event.target.value)}>
              <option value="">{language === 'ru' ? 'Все типы запросов' : 'All query types'}</option>
              {QUERY_TYPES.filter(([value]) => value !== 'auto').map(([value]) => <option key={value} value={value}>{queryTypeLabel(value, language)}</option>)}
            </select>
            <select value={toolsCategoryFilter} onChange={(event) => setToolsCategoryFilter(event.target.value)}>
              <option value="">{language === 'ru' ? 'Все категории' : 'All categories'}</option>
              {toolCategories.map((category) => <option key={category} value={category}>{localizeTool({ id: '', name: '', description: '', category }, language).category}</option>)}
            </select>
            <select value={toolsStatusFilter} onChange={(event) => setToolsStatusFilter(event.target.value)}>
              <option value="">{language === 'ru' ? 'Любой статус' : 'Any status'}</option>
              <option value="available">{language === 'ru' ? 'Доступен' : 'Available'}</option>
              <option value="not_configured">{language === 'ru' ? 'Не подключён' : 'Not configured'}</option>
              <option value="adapter_unavailable">{language === 'ru' ? 'Адаптер не реализован' : 'Adapter not implemented'}</option>
            </select>
            <select value={toolsApiFilter} onChange={(event) => setToolsApiFilter(event.target.value)}>
              <option value="">{language === 'ru' ? 'Любое требование API' : 'Any API requirement'}</option>
              <option value="true">{language === 'ru' ? 'Нужен API-ключ' : 'API key required'}</option>
              <option value="false">{language === 'ru' ? 'Без API-ключа' : 'No API key'}</option>
            </select>
          </div>
          <div className="tools-grid">
            {visibleTools.map((tool) => {
              const localized = localizeTool(tool, language);
              const hasApiKey = tool.requires_api_key || tool.optional_api_key;
              const keyLabel = tool.api_key_configured
                ? t.keySaved
                : tool.api_key_any_configured
                  ? t.keyPartiallySaved
                  : tool.optional_api_key
                    ? t.keyOptional
                    : t.keyMissing;
              return (
                <article className="tool-card" key={tool.id}>
                  <div className="tool-card-top"><span>{localized.category}</span><b className={`tool-status tool-${tool.adapter_implemented === false ? 'not_configured' : tool.status}`}>{toolStatusLabel(tool, language)}</b></div>
                  <h2>{localized.name}</h2><p>{localized.description}</p>
                  <div className="tool-tags">{tool.input_types.map((type) => <span key={type}>{queryTypeLabel(type, language)}</span>)}</div>
                  {hasApiKey ? (
                    <div className="tool-key-actions">
                      <small className={tool.api_key_configured ? 'is-configured' : ''}>{keyLabel}</small>
                      <button type="button" className="tool-configure-button" onClick={() => setView('settings')}>{t.configureKey}</button>
                    </div>
                  ) : null}
                  {tool.source_url ? <a href={tool.source_url} target="_blank" rel="noreferrer">{t.sourceDocs}</a> : null}
                </article>
              );
            })}
            <ExifCard apiBase={getApiBase()} results={exifResults} setResults={setExifResults} />
          </div>
        </section>
      ) : null}

      {view === 'monitoring' ? (
        <MonitoringView
          t={t}
          language={language}
          watches={watches}
          watchesError={watchesError}
          watchLoading={watchLoading}
          form={watchForm}
          onFormChange={setWatchForm}
          onCreate={createWatch}
          onDelete={deleteWatch}
          onWatch={(queryValue) => startScan(queryValue, 'auto', 1)}
        />
      ) : null}

      {view === 'history' ? (
        <section className="page-content">
          <PageHeading eyebrow="LOCAL STORAGE" title={language === 'ru' ? 'История исследований' : 'Investigation history'} detail={language === 'ru' ? 'Хранится только в этом браузере; серверная база данных не настроена.' : 'Stored in this browser only.'} />
          <div className="history-toolbar"><input value={historySearch} onChange={(event) => setHistorySearch(event.target.value)} placeholder={language === 'ru' ? 'Поиск по запросу' : 'Search investigations'} /><button className="secondary-button danger-button" onClick={() => { if (saveHistory([])) setHistory([]); else setError('Не удалось удалить историю браузера.'); }}>{language === 'ru' ? 'Удалить всю историю' : 'Delete all history'}</button></div>
          {filteredHistory.length ? <div className="history-list">{filteredHistory.map((item) => (
            <article className="history-item" key={item.id}>
              <div className="history-item-details">
                <span className="type-label">{item.inputType}</span>
                <input className="history-name-input" aria-label={language === 'ru' ? 'Название исследования' : 'Investigation name'} value={item.label ?? item.query} onChange={(event) => updateHistoryMetadata(item.id, 'label', event.target.value)} />
                <input className="history-tags-input" aria-label={language === 'ru' ? 'Метки через запятую' : 'Comma-separated tags'} placeholder={language === 'ru' ? 'Добавить метки через запятую' : 'Add comma-separated tags'} value={(item.tags || []).join(', ')} onChange={(event) => updateHistoryMetadata(item.id, 'tags', event.target.value.split(',').map((tag) => tag.trim()).filter(Boolean).slice(0, 8))} />
                <small>{new Date(item.createdAt).toLocaleString(language === 'ru' ? 'ru-RU' : 'en-US')} · {item.nodes.filter((node) => !node.data?.isRoot && !node.data?.isCategory).length} {t.findings}</small>
              </div>
              <div className="history-actions">
                <button className="secondary-button" onClick={() => openHistoryItem(item)}>{language === 'ru' ? 'Открыть граф' : 'Open graph'}</button>
                <button className="secondary-button" onClick={() => { openHistoryItem(item); window.setTimeout(() => computeDiffAgainst(item), 60); }}>{t.diffButton}</button>
                <button className="icon-button danger-button" onClick={() => setHistory((previous) => {
                  const next = previous.filter((row) => row.id !== item.id);
                  if (!saveHistory(next)) setError('Не удалось обновить историю в локальном хранилище браузера.');
                  return next;
                })} aria-label="Удалить">×</button>
              </div>
            </article>
          ))}</div> : <EmptyPanel title={language === 'ru' ? 'История пуста' : 'No investigations saved'} description={language === 'ru' ? 'Завершённые проверки будут сохраняться локально в браузере.' : 'Completed checks will be stored locally in this browser.'} />}
        </section>
      ) : null}

      {view === 'reports' ? (
        <section className="page-content">
          <PageHeading eyebrow="EXPORT" title={language === 'ru' ? 'Отчёты и экспорт' : 'Reports & export'} detail={language === 'ru' ? 'Экспортирует текущий граф; содержимое секретов и API-ключи не добавляются.' : 'Exports the current graph; secrets and API keys are not included.'} />
          {nodes.length ? <div className="export-grid">
            <ExportCard title="JSON" description={language === 'ru' ? 'Узлы, связи, источники, статусы и временные отметки.' : 'Nodes, relationships, sources, statuses, and timestamps.'} action={() => exportResults('json')} />
            <ExportCard title="CSV" description={language === 'ru' ? 'Плоская таблица результатов для анализа.' : 'Flat results table for analysis.'} action={() => exportResults('csv')} />
            <ExportCard title="SVG" description={language === 'ru' ? 'Векторный снимок текущего графа.' : 'Vector snapshot of the current graph.'} action={() => exportResults('svg')} />
            <ExportCard title="MD" description={language === 'ru' ? 'Markdown-сводка по категориям для заметок и репозиториев.' : 'Markdown summary grouped by category.'} action={() => exportResults('md')} />
            <ExportCard title="PDF" description={language === 'ru' ? 'Печатная форма отчёта: браузер сохранит её в PDF (Ctrl+P → Сохранить как PDF).' : 'Print form: the browser will save it as PDF.'} action={() => exportResults('pdf')} />
          </div> : (
            <EmptyPanel title={language === 'ru' ? 'Нет текущего исследования' : 'No current investigation'} description={language === 'ru' ? 'Запустите проверку или откройте исследование из истории.' : 'Run a check or reopen an investigation from History.'} />
          )}
          <p className="notice-text">{language === 'ru' ? 'Локальная история и заметки не синхронизируются между устройствами.' : 'Local history and notes are not synchronized between devices.'}</p>
        </section>
      ) : null}

      {view === 'settings' ? (
        <section className="page-content">
          <PageHeading eyebrow="PREFERENCES" title={language === 'ru' ? 'Настройки' : 'Settings'} detail={language === 'ru' ? 'Настройте подключение и поведение локальной установки.' : 'Configure connections and behavior for this local installation.'} />
          <div className="settings-grid">
            <article className="settings-card"><h2>{language === 'ru' ? 'Язык интерфейса' : 'Interface language'}</h2><p>{language === 'ru' ? 'Выберите язык интерфейса.' : 'Choose the interface language.'}</p><button className="secondary-button" onClick={() => setLanguage(language === 'ru' ? 'en' : 'ru')}>{language === 'ru' ? 'Русский / English' : 'English / Русский'}</button></article>
            <article className="settings-card"><h2>{language === 'ru' ? 'Тема' : 'Theme'}</h2><p>{language === 'ru' ? 'Светлая тема применяется ко всему интерфейсу, включая граф.' : 'Light theme applies to the whole interface, including the graph.'}</p><button className="secondary-button" onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}>{theme === 'light' ? (language === 'ru' ? 'Переключить на тёмную' : 'Switch to dark') : (language === 'ru' ? 'Переключить на светлую' : 'Switch to light')}</button></article>
            <article className="settings-card settings-keys-card"><h2>{language === 'ru' ? 'Подключения источников' : 'Source configuration'}</h2><ApiKeySettings language={language} apiBase={getApiBase()} /></article>
            <article className="settings-card"><h2>{language === 'ru' ? 'Хранение' : 'Storage'}</h2><p>{language === 'ru' ? 'История сохраняется в localStorage этого браузера (максимум 50 исследований).' : 'History is stored in this browser localStorage (up to 50 investigations).'}</p><button className="secondary-button danger-button" onClick={() => { if (saveHistory([])) setHistory([]); }}>{language === 'ru' ? 'Удалить сохранённую историю' : 'Delete saved history'}</button></article>
          </div>
        </section>
      ) : null}

      {view === 'about' ? (
        <section className="page-content">
          <PageHeading eyebrow="ABOUT" title="OSINT Spider" detail={language === 'ru' ? 'Платформа первичного анализа общедоступных источников.' : 'A first-pass platform for public-source research.'} />
          <div className="about-copy">
            <h2>{language === 'ru' ? 'Ограничения и корректность' : 'Scope and limitations'}</h2>
            <p>{language === 'ru' ? 'Результаты показывают только выполненные проверки и ответы источников. Совпадение имени пользователя не подтверждается по одному HTTP-ответу. «Нет результатов» не доказывает отсутствие связи или аккаунта.' : 'Results report only executed checks and source responses. A username match is not confirmed from an HTTP response alone.'}</p>
            <p>{language === 'ru' ? 'Проверки сайтов ограничены публичными hostname, безопасным DNS-разрешением и запросом без автоматического перехода по редиректам. Частные IP и нестандартные порты не принимаются.' : 'Website checks are limited to public hostnames, safe DNS resolution, and requests without automatic redirects.'}</p>
            <p>{language === 'ru' ? 'Подключены: DNS/SPF/DMARC, WHOIS, RDAP, crt.sh, GitHub, Gravatar, PGP, HIBP, Shodan, theHarvester, Internet Archive, WhatsMyName (датасет), Wikidata/GitHub Organizations, ExifTool и мониторинг по расписанию. Не подключены: Google metadata, Blackbird, Sherlock, Maigret, Epieos, VirusTotal и urlscan.' : 'Connected: DNS/SPF/DMARC, WHOIS, RDAP, crt.sh, GitHub, Gravatar, PGP, HIBP, Shodan, theHarvester, Internet Archive, WhatsMyName (dataset), Wikidata/GitHub Organizations, ExifTool and scheduled monitoring. Not connected: Google metadata, Blackbird, Sherlock, Maigret, Epieos, VirusTotal and urlscan.'}</p>
          </div>
        </section>
      ) : null}

        </div>
        <CommandPalette
          open={paletteOpen}
          onClose={() => setPaletteOpen(false)}
          actions={paletteActions}
          onSubmitQuery={(text) => startScan(text, 'auto', 1)}
          t={t}
        />
        {toast ? <div className="toast" role="status">{toast}</div> : null}
      </ToastContext.Provider>
    </LanguageContext.Provider>
  );
}

function PageHeading({ eyebrow, title, detail }) {
  return <div className="page-heading"><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p>{detail}</p></div>;
}

function EmptyPanel({ title, description }) {
  return <div className="empty-panel"><h2>{title}</h2><p>{description}</p></div>;
}

function ExportCard({ title, description, action }) {
  return <article className="export-card"><span className="export-icon">{title.slice(0, 1)}</span><h2>{title}</h2><p>{description}</p><button className="secondary-button" onClick={action}>Export {title}</button></article>;
}

export default App;
