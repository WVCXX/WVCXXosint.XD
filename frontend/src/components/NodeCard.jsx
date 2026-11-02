import { Handle, Position } from 'reactflow';
import { useContext, useMemo } from 'react';
import { ExternalLink } from 'lucide-react';
import {
  LanguageContext,
  ToastContext,
  categoryLabel,
  statusLabel,
  timeAgo,
} from '../i18n';

function SkeletonFields() {
  return (
    <div className="node-skeleton" aria-label="Загрузка данных">
      <span className="skeleton-line skeleton-line-wide" />
      <span className="skeleton-line" />
      <span className="skeleton-line skeleton-line-short" />
    </div>
  );
}

function ConfidenceBar({ level, language }) {
  const widthByLevel = { high: '100%', medium: '66%', low: '33%' };
  const classByLevel = { high: 'confidence-high', medium: 'confidence-medium', low: 'confidence-low' };
  if (!level) return null;
  return (
    <span
      className={`node-confidence ${classByLevel[level] || 'confidence-medium'}`}
      title={level === 'high'
        ? (language === 'ru' ? 'Высокое доверие' : 'High confidence')
        : level === 'low'
          ? (language === 'ru' ? 'Низкое доверие' : 'Low confidence')
          : (language === 'ru' ? 'Среднее доверие' : 'Medium confidence')}
    >
      <i style={{ width: widthByLevel[level] || '66%' }} />
    </span>
  );
}

export default function NodeCard({ data }) {
  const language = useContext(LanguageContext);
  const pushToast = useContext(ToastContext);
  const {
    title = 'Результат проверки',
    status = 'info',
    fields = [],
    isRoot = false,
    isCategory = false,
    count = 0,
    query = '',
    inputType = '',
  } = data || {};
  const displayStatus = data?.state || status;
  const confidence = data?.confidence;
  const category = data?.category;
  const sourceUrl = data?.source_url;
  const receivedAt = data?.received_at;

  const countLabel = useMemo(() => {
    if (language === 'en') {
      return count === 1 ? 'card' : 'cards';
    }
    if (count % 10 === 1 && count % 100 !== 11) return 'карточка';
    if (count % 10 >= 2 && count % 10 <= 4 && (count % 100 < 12 || count % 100 > 14)) return 'карточки';
    return 'карточек';
  }, [count, language]);

  const copyValue = (event, value) => {
    event.stopPropagation();
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(String(value)).catch(() => {});
    }
    pushToast(language === 'ru' ? 'Скопировано' : 'Copied');
  };

  return (
    <article className={`node-card status-${displayStatus}${isRoot ? ' node-card-root' : ''}${isCategory ? ' node-card-category' : ''}`}>
      <Handle type="target" position={Position.Top} isConnectable={false} />
      <div className="node-status-rail" />
      <div className="node-card-content">
        <header className="node-card-header">
          <h3>{title}</h3>
          {!isRoot && !isCategory ? (
            <span className="node-status-label">{statusLabel(displayStatus, language)}</span>
          ) : !isRoot && isCategory ? null : null}
          {!isRoot && !isCategory ? <ConfidenceBar level={confidence} language={language} /> : null}
        </header>

        {isRoot ? (
          <div className="node-root-meta">
            <span>{query}</span>
            <span className="node-type-pill">{inputType}</span>
          </div>
        ) : isCategory ? (
          <div className="node-category-meta">
            <span>{categoryLabel(category, language) || ''}</span>
            <span className="node-category-count">{count} {countLabel}</span>
          </div>
        ) : displayStatus === 'loading' ? (
          <SkeletonFields />
        ) : (
          <div className="node-fields">
            {fields.map((field, index) => {
              const value = String(field.value ?? '');
              const isLink = /^https?:\/\//i.test(value);
              return (
                <div className="node-field" key={`${field.label}-${index}`}>
                  <span className="node-field-label">{field.label}</span>
                  {isLink ? (
                    <a
                      className="node-field-value is-link"
                      href={value}
                      target="_blank"
                      rel="noreferrer"
                      onClick={(event) => event.stopPropagation()}
                    >
                      {value.replace(/^https?:\/\//i, '')}
                    </a>
                  ) : (
                    <button
                      type="button"
                      className="node-field-value copyable"
                      title={`${field.label}: ${value} — ${language === 'ru' ? 'клик — скопировать' : 'click — copy'}`}
                      onClick={(event) => copyValue(event, value)}
                    >
                      {value}
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        )}
        {!isRoot && !isCategory && (sourceUrl || receivedAt) ? (
          <div className="node-proof-meta">
            {sourceUrl ? (
              <a
                className="node-source-link"
                href={sourceUrl}
                target="_blank"
                rel="noreferrer"
                onClick={(event) => event.stopPropagation()}
              >
                <ExternalLink aria-hidden="true" />
                {language === 'ru' ? 'Источник' : 'Source'}
              </a>
            ) : null}
            {receivedAt ? <time dateTime={receivedAt}>{timeAgo(receivedAt, language)}</time> : null}
          </div>
        ) : null}
      </div>
      <Handle type="source" position={Position.Bottom} isConnectable={false} />
    </article>
  );
}
