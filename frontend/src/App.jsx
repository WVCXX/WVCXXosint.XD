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
import NodeCard from './components/NodeCard';
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
    depth: 'Глубина',
    emptyTitle: 'Начните новое расследование',
    emptyText: 'Выберите тип запроса и запустите независимые проверки по публичным источникам.',
    graph: 'Граф',
    cards: 'Результаты',
    center: 'Центрировать',
    export: 'Экспорт',
    searchGraph: 'Найти в графе',
    allStatuses: 'Все статусы',
    modules: 'проверок',
    findings: 'результатов',
    language: 'Язык',
  },
  en: {
    search: 'Open-source research',
    placeholder: 'Enter an identifier to investigate',
    analyze: 'Start investigation',
    analyzing: 'Analyzing…',
    depth: 'Depth',
    emptyTitle: 'Start a new investigation',
    emptyText: 'Choose a query type and run independent checks against public sources.',
    graph: 'Graph',
    cards: 'Results',
    center: 'Center graph',
    export: 'Export',
    searchGraph: 'Search graph',
    allStatuses: 'All statuses',
    modules: 'checks',
    findings: 'results',
    language: 'Language',
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
  const [sourceFilter, setSourceFilter] = useState('');
  const [nodeTypeFilter, setNodeTypeFilter] = useState('');
  const [selectedNode, setSelectedNode] = useState(null);
  const [mobileView, setMobileView] = useState('graph');
  const wsRef = useRef(null);
  const flowInstanceRef = useRef(null);
  const retryTimerRef = useRef(null);
  const generationRef = useRef(0);
  const activeScanRef = useRef(null);
  const nodeCounterRef = useRef(0);
  const graphNodesRef = useRef([]);
  const graphEdgesRef = useRef([]);

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
    try {
      window.localStorage.setItem('wvcxxosint.language', language);
    } catch (storageError) {
      console.error('Could not save language preference', storageError);
    }
  }, [language]);

  const saveInvestigation = useCallback((scan, resultNodes, resultEdges) => {
    const saved = {
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      query: scan.query,
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
  }, []);

  const connectScan = useCallback(function connectScan(scan, generation, retryCount) {
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
      socket.send(JSON.stringify({ query: scan.query, query_type: scan.queryType, depth: scan.depth }));
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
        socket.close();
        return;
      }

      if (message.type === 'root') {
        nodeCounterRef.current = 0;
        scan.queryType = message.data.input_type;
        setQueryType(message.data.input_type);
        setProgress({ completed: 0, total: 0, results: 0 });
        const root = makeGraphNode('root', {
          title: 'Объект анализа',
          status: 'root',
          state: 'root',
          isRoot: true,
          query: message.data.query,
          inputType: message.data.input_type,
          fields: [],
        });
        applyLayout([root], []);
        return;
      }

      if (message.type === 'node') {
        const id = `result-${++nodeCounterRef.current}`;
        const data = {
          ...message.data,
          fields: Array.isArray(message.data.fields) ? message.data.fields : [],
          entityType: 'OSINT Module',
        };
        const resultNode = makeGraphNode(id, data);
        const edge = {
          id: `edge-root-${id}`,
          source: 'root',
          target: id,
          type: 'smoothstep',
          label: 'проверка',
          className: 'relationship-edge',
          style: { stroke: '#343941', strokeWidth: 1.5 },
          labelStyle: { fill: '#9298a3', fontSize: 10 },
        };
        applyLayout([...graphNodesRef.current, resultNode], [...graphEdgesRef.current, edge]);
        return;
      }

      if (message.type === 'progress') {
        setProgress(message.data);
        return;
      }

      if (message.type === 'done') {
        receivedDone = true;
        activeScanRef.current = null;
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
          connectScan(scan, generation, retryCount + 1);
        }, delay);
        return;
      }
      activeScanRef.current = null;
      setLoading(false);
      setConnectionStatus('');
      setError('Не удалось подключиться к серверу. Проверьте, что backend запущен.');
    };
  }, [applyLayout, saveInvestigation, setEdges, setNodes]);

  const depthEnabled = ['email', 'domain', 'url'].includes(queryType)
    || (queryType === 'auto' && (
      query.includes('@')
      || query.includes('.')
      || query.toLowerCase().startsWith('http://')
      || query.toLowerCase().startsWith('https://')
    ));

  const handleSearch = useCallback((event) => {
    event.preventDefault();
    const scanQuery = query.trim();
    if (!scanQuery) return;
    const scan = { query: scanQuery, queryType, depth: depthEnabled ? Number(depth) : 1 };
    generationRef.current += 1;
    const generation = generationRef.current;
    activeScanRef.current = generation;
    window.clearTimeout(retryTimerRef.current);
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.close();
    }
    nodeCounterRef.current = 0;
    graphNodesRef.current = [];
    graphEdgesRef.current = [];
    setNodes([]);
    setEdges([]);
    setSelectedNode(null);
    setError('');
    setConnectionStatus('Подключение к анализаторам…');
    setLoading(true);
    setView('investigation');
    setMobileView('graph');
    connectScan(scan, generation, 0);
  }, [connectScan, depth, depthEnabled, query, queryType, setEdges, setNodes]);

  useEffect(() => () => {
    generationRef.current += 1;
    activeScanRef.current = null;
    window.clearTimeout(retryTimerRef.current);
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.close();
    }
  }, []);

  const visibleNodes = useMemo(() => nodes.filter((node) => {
    if (node.data.isRoot) return true;
    const searchMatch = !graphSearch
      || `${node.data.title} ${node.data.query || ''} ${(node.data.fields || []).map((field) => field.value).join(' ')}`
        .toLocaleLowerCase().includes(graphSearch.toLocaleLowerCase());
    const currentStatus = node.data.state || node.data.status;
    const statusMatch = !statusFilter || currentStatus === statusFilter;
    const sourceMatch = !sourceFilter || node.data.tool === sourceFilter;
    const typeMatch = !nodeTypeFilter || node.data.entityType === nodeTypeFilter;
    return searchMatch && statusMatch && sourceMatch && typeMatch;
  }), [graphSearch, nodeTypeFilter, nodes, sourceFilter, statusFilter]);
  const visibleNodeIds = useMemo(() => new Set(visibleNodes.map((node) => node.id)), [visibleNodes]);
  const visibleEdges = useMemo(() => edges.filter((edge) => (
    visibleNodeIds.has(edge.source) && visibleNodeIds.has(edge.target)
  )), [edges, visibleNodeIds]);
  const resultNodes = nodes.filter((node) => !node.data.isRoot);
  const progressPercent = progress.total ? Math.round((progress.completed / progress.total) * 100) : 0;
  const availableSources = [...new Set(resultNodes.map((node) => node.data.tool || node.data.title))];
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

  const openHistoryItem = (item) => {
    graphNodesRef.current = item.nodes;
    graphEdgesRef.current = item.edges;
    setNodes(item.nodes);
    setEdges(item.edges);
    setQuery(item.query);
    setQueryType(item.inputType || 'email');
    setDepth(item.depth || 1);
    setSelectedNode(null);
    setError('');
    setView('investigation');
    window.requestAnimationFrame(() => flowInstanceRef.current?.fitView({ padding: 0.16, maxZoom: 1 }));
  };

  const removeHistoryItem = (id) => {
    setHistory((previous) => {
      const next = previous.filter((item) => item.id !== id);
      if (!saveHistory(next)) setError('Не удалось обновить историю в локальном хранилище браузера.');
      return next;
    });
  };

  const exportResults = (format) => {
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
      const rows = [['id', 'entity_type', 'query', 'tool', 'state', 'received_at', 'source_url', 'field', 'value']];
      nodes.filter((node) => !node.data.isRoot).forEach((node) => {
        const data = node.data;
        const fields = data.fields?.length ? data.fields : [{ label: '', value: '' }];
        fields.forEach((field) => rows.push([
          node.id, data.entityType || 'OSINT Module', data.query, data.tool || data.title,
          data.state || data.status, data.received_at, data.source_url, field.label, field.value,
        ]));
      });
      downloadFile(`${filename}.csv`, rows.map((row) => row.map(csvValue).join(',')).join('\r\n'), 'text/csv;charset=utf-8');
    } else if (format === 'svg') {
      downloadFile(`${filename}.svg`, buildSvg(nodes, edges, query), 'image/svg+xml;charset=utf-8');
    }
    setError('');
  };

  const visibleTools = tools.filter((tool) => (
    (!toolsSearch || `${tool.name} ${tool.category} ${tool.description}`.toLowerCase().includes(toolsSearch.toLowerCase()))
    && (!toolsTypeFilter || tool.input_types.includes(toolsTypeFilter))
    && (!toolsCategoryFilter || tool.category === toolsCategoryFilter)
    && (!toolsStatusFilter || tool.status === toolsStatusFilter)
    && (!toolsApiFilter || String(Boolean(tool.requires_api_key || tool.optional_api_key)) === toolsApiFilter)
  ));
  const toolCategories = [...new Set(tools.map((tool) => tool.category))].sort();
  const filteredHistory = history.filter((item) => (
    !historySearch || `${item.query} ${item.inputType}`.toLowerCase().includes(historySearch.toLowerCase())
  ));

  return (
    <main className="app-shell">
      <header className="top-bar">
        <a className="brand" href="/" aria-label="OSINT Spider — главная" onClick={(event) => { event.preventDefault(); setView('investigation'); }}>
          <span className="brand-mark" aria-hidden="true">S</span>
          <span className="brand-copy"><strong>OSINT Spider</strong><span>Open-source intelligence</span></span>
        </a>
        <nav className="main-nav" aria-label="Основная навигация">
          {NAV_ITEMS.map(([id, russian, english]) => (
            <button className={`nav-button${view === id ? ' is-active' : ''}`} key={id} onClick={() => setView(id)}>
              {language === 'ru' ? russian : english}
            </button>
          ))}
        </nav>
        <button className="language-button" onClick={() => setLanguage(language === 'ru' ? 'en' : 'ru')} aria-label={t.language}>
          {language.toUpperCase()}
        </button>
      </header>

      {view === 'investigation' ? (
        <>
          <form className="query-toolbar" onSubmit={handleSearch}>
            <label className="query-type">
              <span>{language === 'ru' ? 'Тип' : 'Type'}</span>
              <select value={queryType} onChange={(event) => setQueryType(event.target.value)}>
                {QUERY_TYPES.map(([value, english, russian]) => <option key={value} value={value}>{language === 'ru' ? russian : english}</option>)}
              </select>
            </label>
            <label className="query-input">
              <span className="search-icon" aria-hidden="true">⌕</span>
              <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t.placeholder} aria-label={t.search} maxLength={255} />
            </label>
            <label className="depth-select">
              <span>{t.depth}</span>
              <select value={depth} disabled={!depthEnabled} onChange={(event) => setDepth(Number(event.target.value))}>
                <option value={1}>1</option><option value={2}>2</option><option value={3}>3</option>
              </select>
            </label>
            <button className="scan-button" type="submit" disabled={loading || !query.trim()}>
              {loading ? <span className="button-spinner" aria-hidden="true" /> : null}
              {loading ? t.analyzing : t.analyze}
            </button>
          </form>

          <section className="workspace">
            <div className="workspace-heading">
              <div>
                <p className="eyebrow">{language === 'ru' ? 'ИССЛЕДОВАНИЕ' : 'INVESTIGATION'}</p>
                <h1>{t.search}</h1>
              </div>
              <div className="heading-meta">
                <span className="result-count">{resultNodes.length} {t.findings}</span>
                <span className="live-status"><i className={`status-dot${loading ? ' is-working' : ''}`} />{loading ? (language === 'ru' ? 'Выполняются проверки' : 'Checks running') : (language === 'ru' ? 'Готов к анализу' : 'Ready')}</span>
              </div>
            </div>

            <div className="graph-toolbar">
              <label className="graph-search">
                <span aria-hidden="true">⌕</span>
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
              <select value={nodeTypeFilter} onChange={(event) => setNodeTypeFilter(event.target.value)} aria-label={language === 'ru' ? 'Тип узла' : 'Node type'}>
                <option value="">{language === 'ru' ? 'Все типы узлов' : 'All node types'}</option>
                <option value="OSINT Module">OSINT Module</option>
              </select>
              <select value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value)} aria-label={language === 'ru' ? 'Источник' : 'Source'}>
                <option value="">{language === 'ru' ? 'Все источники' : 'All sources'}</option>
                {availableSources.map((source) => <option key={source} value={source}>{source}</option>)}
              </select>
              <button className="secondary-button" type="button" onClick={() => flowInstanceRef.current?.fitView({ padding: 0.16, maxZoom: 1 })}>{t.center}</button>
              <button className="secondary-button" type="button" onClick={() => exportResults('json')}>{t.export} JSON</button>
              <div className="mobile-view-toggle">
                <button className={mobileView === 'graph' ? 'is-active' : ''} onClick={() => setMobileView('graph')} type="button">{t.graph}</button>
                <button className={mobileView === 'cards' ? 'is-active' : ''} onClick={() => setMobileView('cards')} type="button">{t.cards}</button>
              </div>
            </div>

            <div className={`graph-frame${mobileView === 'cards' ? ' mobile-cards' : ''}`}>
              {nodes.length === 0 && !loading ? (
                <div className="empty-state">
                  <div className="empty-mark" aria-hidden="true">◎</div>
                  <h2>{t.emptyTitle}</h2>
                  <p>{t.emptyText}</p>
                </div>
              ) : null}
              {connectionStatus ? <div className="connection-banner" role="status">{connectionStatus}</div> : null}
              {error ? <div className="error-banner" role="alert">{error}<button onClick={() => setError('')} aria-label="Закрыть">×</button></div> : null}
              <div className="graph-canvas">
                <ReactFlow
                  nodes={visibleNodes}
                  edges={visibleEdges}
                  nodeTypes={nodeTypes}
                  edgeTypes={edgeTypes}
                  onInit={(instance) => { flowInstanceRef.current = instance; }}
                  onNodesChange={onNodesChange}
                  onEdgesChange={onEdgesChange}
                  onNodeClick={(_, node) => setSelectedNode(node)}
                  fitView
                  fitViewOptions={{ padding: 0.16, maxZoom: 1 }}
                  minZoom={0.15}
                  maxZoom={1.5}
                  proOptions={{ hideAttribution: true }}
                >
                  <Background color="#292d33" gap={24} size={1} />
                  <MiniMap className="graph-minimap" nodeColor={(node) => (
                    node.data.state === 'completed' || node.data.status === 'ok' ? '#38c987'
                      : node.data.state === 'failed' || node.data.status === 'error' ? '#f16b73'
                        : node.data.state === 'not_configured' ? '#9298a3' : '#3988ff'
                  )} maskColor="rgba(8, 9, 11, 0.75)" />
                  <Controls />
                </ReactFlow>
              </div>
              {mobileView === 'cards' ? (
                <div className="mobile-result-list">
                  {resultNodes.map((node) => (
                    <button key={node.id} className="result-list-card" onClick={() => setSelectedNode(node)}>
                      <span className={`result-status status-${node.data.state || node.data.status}`} />
                      <span><strong>{node.data.title}</strong><small>{node.data.state || node.data.status}</small></span>
                      <span aria-hidden="true">›</span>
                    </button>
                  ))}
                </div>
              ) : null}
              {selectedNode ? (
                <aside className="detail-panel">
                  <button className="detail-close" onClick={() => setSelectedNode(null)} aria-label="Закрыть детали">×</button>
                  <p className="eyebrow">{selectedNode.data.entityType || (selectedNode.data.isRoot ? 'SEARCH QUERY' : 'OSINT MODULE')}</p>
                  <h2>{selectedNode.data.title}</h2>
                  <span className={`detail-status status-${selectedNode.data.state || selectedNode.data.status}`}>{selectedNode.data.state || selectedNode.data.status}</span>
                  {selectedNode.data.fields?.map((field, index) => (
                    <div className="detail-field" key={`${field.label}-${index}`}><small>{field.label}</small><span>{field.value}</span></div>
                  ))}
                  {selectedNode.data.source_url ? <a className="source-link" href={selectedNode.data.source_url} target="_blank" rel="noreferrer">{language === 'ru' ? 'Открыть источник ↗' : 'Open source ↗'}</a> : null}
                  {selectedNode.id !== 'root' ? <button className="secondary-button full-width" onClick={hideSelectedBranch}>{language === 'ru' ? 'Скрыть ветвь' : 'Hide branch'}</button> : null}
                </aside>
              ) : null}
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
          </section>
        </>
      ) : null}

      {view === 'tools' ? (
        <section className="page-content">
          <PageHeading eyebrow="CATALOG" title={language === 'ru' ? 'Каталог инструментов' : 'Tools catalogue'} detail={`${tools.length} ${language === 'ru' ? 'модулей в реестре backend' : 'modules registered by backend'}`} />
          {toolsError ? <div className="error-banner inline-error">{toolsError}</div> : null}
          <div className="catalog-filters">
            <input value={toolsSearch} onChange={(event) => setToolsSearch(event.target.value)} placeholder={language === 'ru' ? 'Поиск инструмента' : 'Search tools'} />
            <select value={toolsTypeFilter} onChange={(event) => setToolsTypeFilter(event.target.value)}>
              <option value="">{language === 'ru' ? 'Все типы запросов' : 'All query types'}</option>
              {QUERY_TYPES.filter(([value]) => value !== 'auto').map(([value, english, russian]) => <option key={value} value={value}>{language === 'ru' ? russian : english}</option>)}
            </select>
            <select value={toolsCategoryFilter} onChange={(event) => setToolsCategoryFilter(event.target.value)}>
              <option value="">{language === 'ru' ? 'Все категории' : 'All categories'}</option>
              {toolCategories.map((category) => <option key={category} value={category}>{category}</option>)}
            </select>
            <select value={toolsStatusFilter} onChange={(event) => setToolsStatusFilter(event.target.value)}>
              <option value="">{language === 'ru' ? 'Любой статус' : 'Any status'}</option>
              <option value="available">{language === 'ru' ? 'Доступен' : 'Available'}</option>
              <option value="not_configured">{language === 'ru' ? 'Не подключён' : 'Not configured'}</option>
            </select>
            <select value={toolsApiFilter} onChange={(event) => setToolsApiFilter(event.target.value)}>
              <option value="">{language === 'ru' ? 'Любое требование API' : 'Any API requirement'}</option>
              <option value="true">{language === 'ru' ? 'Нужен API-ключ' : 'API key required'}</option>
              <option value="false">{language === 'ru' ? 'Без API-ключа' : 'No API key'}</option>
            </select>
          </div>
          <div className="tools-grid">
            {visibleTools.map((tool) => (
              <article className="tool-card" key={tool.id}>
                <div className="tool-card-top"><span>{tool.category}</span><b className={`tool-status tool-${tool.status}`}>{tool.status === 'available' ? (language === 'ru' ? 'Доступен' : 'Available') : (language === 'ru' ? 'Не подключён' : 'Not configured')}</b></div>
                <h2>{tool.name}</h2><p>{tool.description}</p>
                <div className="tool-tags">{tool.input_types.map((type) => <span key={type}>{type}</span>)}</div>
                {tool.requires_api_key || tool.optional_api_key ? <small>{language === 'ru' ? 'Ключ сервера:' : 'Server key:'} {tool.api_key_env || tool.optional_api_key}</small> : null}
                {tool.source_url ? <a href={tool.source_url} target="_blank" rel="noreferrer">{language === 'ru' ? 'Документация источника ↗' : 'Source documentation ↗'}</a> : null}
              </article>
            ))}
          </div>
        </section>
      ) : null}

      {view === 'history' ? (
        <section className="page-content">
          <PageHeading eyebrow="LOCAL STORAGE" title={language === 'ru' ? 'История исследований' : 'Investigation history'} detail={language === 'ru' ? 'Хранится только в этом браузере; серверная база данных не настроена.' : 'Stored in this browser only; no server database is configured.'} />
          <div className="history-toolbar"><input value={historySearch} onChange={(event) => setHistorySearch(event.target.value)} placeholder={language === 'ru' ? 'Поиск по запросу' : 'Search investigations'} /><button className="secondary-button danger-button" onClick={() => { if (saveHistory([])) setHistory([]); else setError('Не удалось удалить историю браузера.'); }}>{language === 'ru' ? 'Удалить всю историю' : 'Delete all history'}</button></div>
          {filteredHistory.length ? <div className="history-list">{filteredHistory.map((item) => (
            <article className="history-item" key={item.id}>
              <div><span className="type-label">{item.inputType}</span><h2>{item.query}</h2><small>{new Date(item.createdAt).toLocaleString(language === 'ru' ? 'ru-RU' : 'en-US')} · {Math.max(0, item.nodes.length - 1)} {t.findings}</small></div>
              <div className="history-actions"><button className="secondary-button" onClick={() => openHistoryItem(item)}>{language === 'ru' ? 'Открыть граф' : 'Open graph'}</button><button className="icon-button danger-button" onClick={() => removeHistoryItem(item.id)} aria-label="Удалить">×</button></div>
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
          </div> : <EmptyPanel title={language === 'ru' ? 'Нет текущего исследования' : 'No current investigation'} description={language === 'ru' ? 'Запустите проверку или откройте исследование из истории.' : 'Run a check or reopen an investigation from History.'} />}
          <p className="notice-text">{language === 'ru' ? 'PDF-отчёт пока не реализован. Локальная история не синхронизируется между устройствами.' : 'PDF reports are not implemented yet. Local history is not synchronized between devices.'}</p>
        </section>
      ) : null}

      {view === 'settings' ? (
        <section className="page-content">
          <PageHeading eyebrow="PREFERENCES" title={language === 'ru' ? 'Настройки' : 'Settings'} detail={language === 'ru' ? 'Секреты хранятся только на backend в переменных окружения.' : 'Secrets are stored server-side in environment variables only.'} />
          <div className="settings-grid">
            <article className="settings-card"><h2>{language === 'ru' ? 'Язык интерфейса' : 'Interface language'}</h2><p>{language === 'ru' ? 'Выберите язык интерфейса.' : 'Choose the interface language.'}</p><button className="secondary-button" onClick={() => setLanguage(language === 'ru' ? 'en' : 'ru')}>{language === 'ru' ? 'Русский / English' : 'English / Русский'}</button></article>
            <article className="settings-card"><h2>{language === 'ru' ? 'Подключения источников' : 'Source configuration'}</h2><p>{language === 'ru' ? 'Значения ключей недоступны в интерфейсе; отображается только состояние настройки.' : 'Key values are never exposed to the UI; only configuration status is shown.'}</p><div className="key-status-list">{tools.filter((tool) => tool.requires_api_key || tool.optional_api_key).map((tool) => <div key={tool.id}><span>{tool.api_key_env || tool.optional_api_key}</span><b className={`tool-status tool-${tool.status}`}>{tool.status === 'available' ? (language === 'ru' ? 'Настроен' : 'Configured') : (language === 'ru' ? 'Не настроен' : 'Not configured')}</b></div>)}</div></article>
            <article className="settings-card"><h2>{language === 'ru' ? 'Хранение' : 'Storage'}</h2><p>{language === 'ru' ? 'История сохраняется в localStorage этого браузера (максимум 50 исследований).' : 'History is stored in this browser localStorage (up to 50 investigations).'}</p><button className="secondary-button danger-button" onClick={() => { if (saveHistory([])) setHistory([]); }}>{language === 'ru' ? 'Удалить сохранённую историю' : 'Delete saved history'}</button></article>
          </div>
        </section>
      ) : null}

      {view === 'about' ? (
        <section className="page-content">
          <PageHeading eyebrow="ABOUT" title="OSINT Spider" detail={language === 'ru' ? 'Платформа первичного анализа общедоступных источников.' : 'A first-pass platform for public-source research.'} />
          <div className="about-copy">
            <h2>{language === 'ru' ? 'Ограничения и корректность' : 'Scope and limitations'}</h2>
            <p>{language === 'ru' ? 'Результаты показывают только выполненные проверки и ответы источников. Совпадение имени пользователя не подтверждается по одному HTTP-ответу. «Нет результатов» не доказывает отсутствие связи или аккаунта.' : 'Results report only executed checks and source responses. A username match is not confirmed from an HTTP response alone. “No results” does not prove an account or relationship does not exist.'}</p>
            <p>{language === 'ru' ? 'Проверки сайтов ограничены публичными hostname, безопасным DNS-разрешением и запросом без автоматического перехода по редиректам. Частные IP и нестандартные порты не принимаются.' : 'Website checks are limited to public hostnames, safe DNS resolution, and requests without automatic redirects. Private IPs and non-standard ports are rejected.'}</p>
            <p>{language === 'ru' ? 'Не подключены: Google metadata, Blackbird, поиск по организациям и PDF. Их наличие явно обозначается в каталоге; демонстрационные данные не создаются.' : 'Not connected: Google metadata, Blackbird, organization search, and PDF reports. The catalogue marks these explicitly; no demo results are generated.'}</p>
          </div>
        </section>
      ) : null}
    </main>
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
