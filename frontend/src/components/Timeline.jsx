import { useContext } from 'react';
import {
  CATEGORY_LABELS,
  LanguageContext,
  categoryLabel as categoryLabelFn,
  statusLabel,
  timeAgo,
} from '../i18n';

export default function Timeline({ nodes, selectedId, onSelect }) {
  const language = useContext(LanguageContext);
  const sorted = [...nodes].sort((a, b) => String(a.data.received_at || '').localeCompare(String(b.data.received_at || '')));

  return (
    <div className="timeline" role="list">
      {sorted.length === 0 ? (
        <p className="timeline-empty">{language === 'ru' ? 'Проверки появятся здесь по мере выполнения.' : 'Checks will appear here as they complete.'}</p>
      ) : null}
      {sorted.map((node) => {
        const state = node.data.state || node.data.status;
        return (
          <button
            key={node.id}
            role="listitem"
            className={`timeline-item${node.id === selectedId ? ' is-selected' : ''}`}
            onClick={() => onSelect(node)}
            title={node.data.received_at ? new Date(String(node.data.received_at)).toLocaleString(language === 'en' ? 'en-US' : 'ru-RU') : undefined}
            type="button"
          >
            <span className={`timeline-dot status-${state}`} />
            <span className="timeline-body">
              <strong>{node.data.title}</strong>
              <small>
                {statusLabel(state, language)}
                {node.data.category ? ` · ${categoryLabelFn(node.data.category, language)}` : ''}
                {node.data.received_at ? ` · ${timeAgo(node.data.received_at, language)}` : ''}
              </small>
            </span>
            <span className={`timeline-confidence confidence-${node.data.confidence || 'none'}`}>
              {node.data.confidence ? { medium: '◐', high: '●', low: '○' }[node.data.confidence] || '' : ''}
            </span>
          </button>
        );
      })}
    </div>
  );
}

export function CategoryFeed({ nodes, selectedId, onSelect }) {
  const language = useContext(LanguageContext);
  const groups = new Map();
  for (const node of nodes) {
    const key = node.data.category || 'other';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(node);
  }
  const labels = CATEGORY_LABELS[language === 'en' ? 'en' : 'ru'] || CATEGORY_LABELS.ru;

  return (
    <div className="mobile-feed">
      {[...groups.entries()].map(([key, items]) => (
        <details key={key} className="feed-group" open>
          <summary>
            {categoryLabelFn(key, language) || labels[key] || key}
            <span>{items.length}</span>
          </summary>
          <div className="feed-items">
            {items.map((node) => {
              const state = node.data.state || node.data.status;
              return (
                <button
                  key={node.id}
                  className={`feed-item${node.id === selectedId ? ' is-selected' : ''}`}
                  onClick={() => onSelect(node)}
                  title={node.data.received_at ? new Date(String(node.data.received_at)).toLocaleString(language === 'en' ? 'en-US' : 'ru-RU') : undefined}
                  type="button"
                >
                  <span className={`timeline-dot status-${state}`} />
                  <strong>{node.data.title}</strong>
                  <small>{statusLabel(state, language)}</small>
                </button>
              );
            })}
          </div>
        </details>
      ))}
    </div>
  );
}
