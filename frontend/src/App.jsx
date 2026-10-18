import { useCallback, useEffect, useRef, useState } from 'react';
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

const NODE_WIDTH = 286;
const ROOT_HEIGHT = 96;
const CATEGORY_HEIGHT = 82;
const MAX_RECONNECTS = 2;
const nodeTypes = { custom: NodeCard };
const edgeTypes = {};

function estimateNodeHeight(node) {
  if (node.data.isRoot) return ROOT_HEIGHT;
  if (node.data.isCategory) return CATEGORY_HEIGHT;

  const fields = node.data.fields || [];
  const contentHeight = fields.reduce((height, field) => {
    const valueLength = String(field.value ?? '').length;
    const estimatedLines = Math.max(1, Math.ceil(valueLength / 34));
    return height + 34 + Math.min(estimatedLines, 4) * 17;
  }, 0);
  return Math.max(88, 54 + contentHeight);
}

function getLayoutedElements(nodes, edges) {
  const graph = new dagre.graphlib.Graph().setDefaultEdgeLabel(() => ({}));
  graph.setGraph({ rankdir: 'TB', nodesep: 80, ranksep: 120, marginx: 50, marginy: 50 });

  nodes.forEach((node) => {
    graph.setNode(node.id, {
      width: NODE_WIDTH,
      height: estimateNodeHeight(node),
    });
  });
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

function getCategory(title = '') {
  const normalizedTitle = title.toLocaleLowerCase();
  if (['smtp', 'домен', 'ip', 'whois'].some((term) => normalizedTitle.includes(term.toLocaleLowerCase()))) {
    return 'Инфраструктура';
  }
  if (['утечки', 'hibp', 'blackbird'].some((term) => normalizedTitle.includes(term))) {
    return 'Утечки данных';
  }
  if (['профили', 'github', 'reddit', 'twitter'].some((term) => normalizedTitle.includes(term))) {
    return 'Соцсети';
  }
  if (['google', 'gravatar'].some((term) => normalizedTitle.includes(term))) {
    return 'Сервисы';
  }
  return 'Прочее';
}

function App() {
  const [query, setQuery] = useState('');
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [connectionStatus, setConnectionStatus] = useState('');
  const wsRef = useRef(null);
  const flowInstanceRef = useRef(null);
  const retryTimerRef = useRef(null);
  const generationRef = useRef(0);
  const activeScanRef = useRef(null);
  const nodeCounterRef = useRef(0);
  const categoriesRef = useRef({});
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
        window.requestAnimationFrame(() => {
          if (flowInstanceRef.current === flow) {
            flow.fitView({ padding: 0.2, maxZoom: 1, duration: 420 });
          }
        });
      });
    }
  }, [setEdges, setNodes]);

  const handleFlowInit = useCallback((instance) => {
    flowInstanceRef.current = instance;
  }, []);

  const connectScan = useCallback(function connectScan(scanQuery, generation, retryCount) {
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
      socket.send(JSON.stringify({ query: scanQuery }));
    };

    socket.onmessage = (event) => {
      if (generationRef.current !== generation) return;

      let message;
      try {
        message = JSON.parse(event.data);
      } catch {
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
        categoriesRef.current = {};
        nodeCounterRef.current = 0;
        const root = makeGraphNode('root', {
          title: 'Объект анализа',
          status: 'root',
          isRoot: true,
          query: message.data.query,
          inputType: message.data.input_type,
          fields: [],
        });
        applyLayout([root], []);
        return;
      }

      if (message.type === 'node') {
        const category = getCategory(message.data.title);
        let categoryId = categoriesRef.current[category];
        let nextNodes = [...graphNodesRef.current];
        let nextEdges = [...graphEdgesRef.current];

        if (!categoryId) {
          categoryId = `category-${Object.keys(categoriesRef.current).length}`;
          categoriesRef.current[category] = categoryId;
          nextNodes.push(makeGraphNode(categoryId, {
            title: category,
            status: 'category',
            isCategory: true,
            count: 0,
            fields: [],
          }));
          nextEdges.push({
            id: `edge-root-${categoryId}`,
            source: 'root',
            target: categoryId,
            type: 'smoothstep',
            animated: true,
            className: 'animated-edge',
            style: { stroke: '#6676d9', strokeWidth: 1.7 },
          });
        }

        const id = `result-${++nodeCounterRef.current}`;
        const resultNode = makeGraphNode(id, {
          ...message.data,
          fields: Array.isArray(message.data.fields) ? message.data.fields : [],
        });
        const edge = {
          id: `edge-${categoryId}-${id}`,
          source: categoryId,
          target: id,
          type: 'smoothstep',
          animated: true,
          className: 'animated-edge',
          style: { stroke: '#4b67ed', strokeWidth: 1.5 },
        };
        nextNodes = nextNodes.map((node) => (
          node.id === categoryId
            ? { ...node, data: { ...node.data, count: node.data.count + 1 } }
            : node
        ));
        nextNodes.push(resultNode);
        nextEdges.push(edge);
        applyLayout(nextNodes, nextEdges);
        return;
      }

      if (message.type === 'done') {
        receivedDone = true;
        activeScanRef.current = null;
        setLoading(false);
        setConnectionStatus('');
        socket.close();
      }
    };

    socket.onerror = () => {
      if (generationRef.current === generation) {
        setConnectionStatus('Связь прервана. Проверяю соединение…');
      }
    };

    socket.onclose = () => {
      if (
        generationRef.current !== generation
        || activeScanRef.current !== generation
        || receivedDone
      ) {
        return;
      }

      if (retryCount < MAX_RECONNECTS) {
        const delay = 500 * (2 ** retryCount);
        setConnectionStatus(`Переподключение ${retryCount + 1}/${MAX_RECONNECTS}…`);
        retryTimerRef.current = window.setTimeout(() => {
          if (generationRef.current !== generation) return;
          nodeCounterRef.current = 0;
          categoriesRef.current = {};
          graphNodesRef.current = [];
          graphEdgesRef.current = [];
          setNodes([]);
          setEdges([]);
          connectScan(scanQuery, generation, retryCount + 1);
        }, delay);
        return;
      }

      activeScanRef.current = null;
      setLoading(false);
      setConnectionStatus('');
      setError('Не удалось подключиться к серверу. Проверьте, что backend запущен.');
    };
  }, [applyLayout, setEdges, setNodes]);

  const handleSearch = useCallback((event) => {
    event.preventDefault();
    const scanQuery = query.trim();
    if (!scanQuery) return;

    generationRef.current += 1;
    const generation = generationRef.current;
    activeScanRef.current = generation;
    window.clearTimeout(retryTimerRef.current);

    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.close();
    }

    nodeCounterRef.current = 0;
    categoriesRef.current = {};
    graphNodesRef.current = [];
    graphEdgesRef.current = [];
    setNodes([]);
    setEdges([]);
    setError('');
    setConnectionStatus('Подключение к сканеру…');
    setLoading(true);
    connectScan(scanQuery, generation, 0);
  }, [connectScan, query, setEdges, setNodes]);

  useEffect(() => () => {
    generationRef.current += 1;
    activeScanRef.current = null;
    window.clearTimeout(retryTimerRef.current);
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.close();
    }
  }, []);

  return (
    <main className="app-shell">
      <header className="top-bar">
        <a className="brand" href="/" aria-label="OSINT Spider — главная">
          <span className="brand-mark" aria-hidden="true">S</span>
          <span className="brand-copy">
            <strong>OSINT Spider</strong>
            <span>Relationship intelligence</span>
          </span>
        </a>

        <form className="search-form" onSubmit={handleSearch}>
          <label className="search-field">
            <span className="search-icon" aria-hidden="true">⌕</span>
            <input
              type="text"
              placeholder="Email, домен, телефон или никнейм"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              aria-label="Email, домен, телефон или никнейм"
            />
          </label>
          <button className="scan-button" type="submit" disabled={loading || !query.trim()}>
            {loading ? <span className="button-spinner" aria-hidden="true" /> : null}
            {loading ? 'Анализ…' : 'Начать анализ'}
          </button>
        </form>
      </header>

      <section className="workspace">
        <div className="workspace-heading">
          <div>
            <p className="eyebrow">ГРАФ РАССЛЕДОВАНИЯ</p>
            <h1>Связи и цифровые следы</h1>
          </div>
          <div className="live-status">
            <span className={loading ? 'status-dot is-working' : 'status-dot'} />
            {loading ? 'Сканирование' : 'Готов к анализу'}
          </div>
        </div>

        <div className="graph-frame">
          {nodes.length === 0 && !loading ? (
            <div className="empty-state">
              <div className="empty-orbit" aria-hidden="true">
                <span />
                <span />
                <span />
                <b>◎</b>
              </div>
              <h2>Начните новое расследование</h2>
              <p>Введите объект поиска — результаты и связи появятся здесь.</p>
            </div>
          ) : null}

          {connectionStatus ? (
            <div className="connection-banner" role="status">{connectionStatus}</div>
          ) : null}
          {error ? <div className="error-banner" role="alert">{error}</div> : null}

          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            onInit={handleFlowInit}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            fitView
            fitViewOptions={{ padding: 0.2, maxZoom: 1 }}
            minZoom={0.15}
            maxZoom={1.5}
            proOptions={{ hideAttribution: true }}
          >
            <Background color="#333a52" gap={28} size={1} />
            <MiniMap
              className="graph-minimap"
              nodeColor={(node) => {
                if (node.data.status === 'ok') return '#43d9a3';
                if (node.data.status === 'error') return '#ff647c';
                return '#6582ff';
              }}
              maskColor="rgba(8, 10, 17, 0.72)"
            />
            <Controls />
          </ReactFlow>
        </div>
      </section>
    </main>
  );
}

export default App;
