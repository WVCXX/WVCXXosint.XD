import { useContext, useMemo, useState } from 'react';
import {
  ToastContext,
  categoryLabel,
  inferType,
  statusLabel,
  timeAgo,
} from '../i18n';

function findDeepDives(fields) {
  const found = [];
  for (const field of fields || []) {
    const type = inferType(field.value);
    if (type && type !== 'username') {
      found.push({ value: String(field.value), type });
    }
  }
  const uniq = [];
  for (const item of found) {
    if (!uniq.some((existing) => existing.value === item.value)) uniq.push(item);
  }
  return uniq.slice(0, 4);
}

export default function Inspector({
  node,
  language,
  t,
  summary,
  diffPanel,
  onCloseDiff,
  onHideBranch,
  onDeepDive,
  noteValue,
  onNoteChange,
}) {
  const pushToast = useContext(ToastContext);
  const [openNote, setOpenNote] = useState(false);
  const [openNoteKey, setOpenNoteKey] = useState(null);
  const currentNoteKey = node?.data?.id ?? node?.id ?? null;

  // Сброс открытой заметки при смене узла (без эффектов — паттерн «состояние во время рендера»).
  if (currentNoteKey !== openNoteKey) {
    setOpenNoteKey(currentNoteKey);
    setOpenNote(false);
  }

  const statusBreakdown = useMemo(() => {
    const counts = {};
    for (const item of summary.results) {
      const state = item.data.state || item.data.status;
      counts[state] = (counts[state] || 0) + 1;
    }
    return Object.entries(counts);
  }, [summary.results]);

  const copyValue = (value) => {
    if (navigator.clipboard?.writeText) {
      navigator.clipboard.writeText(String(value)).catch(() => {});
    }
    pushToast(language === 'ru' ? 'Скопировано' : 'Copied');
  };

  const deepDives = node && !node.data.isRoot ? findDeepDives(node.data.fields) : [];
  const receivedAt = node?.data?.received_at;

  if (!node) {
    return (
      <aside className="inspector">
        <div className="inspector-head">
          <p className="eyebrow">{language === 'ru' ? 'СВОДКА' : 'SUMMARY'}</p>
          <h2>{summary.query || (language === 'ru' ? 'Нет активного узла' : 'No node selected')}</h2>
        </div>
        {diffPanel ? (
          <div className="diff-panel">
            <div className="diff-head">
              <span>{t.diffAgainst}</span>
              <button className="icon-button" onClick={onCloseDiff} aria-label={t.close}>×</button>
            </div>
            <div className="diff-counts">
              <span className="diff-added">+{diffPanel.added.length} {t.diffAdded}</span>
              <span className="diff-changed">≈{diffPanel.changed.length} {t.diffChanged}</span>
              <span className="diff-removed">−{diffPanel.removed.length} {t.diffRemoved}</span>
            </div>
            {['added', 'changed', 'removed'].map((bucket) => (
              diffPanel[bucket].length ? (
                <div className="diff-section" key={bucket}>
                  <small>{t[`diff${bucket.charAt(0).toUpperCase()}${bucket.slice(1)}`] || bucket}</small>
                  <ul>
                    {diffPanel[bucket].map((entry, index) => {
                      const title = typeof entry === 'string' ? entry : entry.title;
                      const note = typeof entry === 'string' ? '' : ` (${entry.from} → ${entry.to})`;
                      return <li key={`${bucket}-${index}`}>{title}{note}</li>;
                    })}
                  </ul>
                </div>
              ) : null
            ))}
          </div>
        ) : null}
        <p className="inspector-empty">
          {language === 'ru'
            ? 'Выберите узел в графе или ленте, чтобы увидеть поля, заметки и связанные данные.'
            : 'Select a node in the graph or timeline to see fields, notes and related data.'}
        </p>
        <div className="inspector-tally">
          <small>{language === 'ru' ? 'Статусы' : 'Statuses'}</small>
          {statusBreakdown.length === 0 ? <span>—</span> : null}
          {statusBreakdown.map(([state, count]) => (
            <span className={`tally-chip status-${state}`} key={state}>{statusLabel(state, language)}: {count}</span>
          ))}
        </div>
      </aside>
    );
  }

  return (
    <aside className="inspector">
      <div className="inspector-head">
        <p className="eyebrow">
          {node.data.isRoot
            ? t.detailTarget
            : node.data.isCategory
              ? (language === 'ru' ? 'ГРУППА' : 'GROUP')
              : (node.data.entityType || t.detailModule)}
        </p>
        <h2>{node.data.title}</h2>
        <div className="inspector-meta">
          <span className={`detail-status status-${node.data.state || node.data.status}`}>
            {statusLabel(node.data.state || node.data.status, language)}
          </span>
          {node.data.category && !node.data.isRoot ? (
            <span className="meta-chip">{categoryLabel(node.data.category, language)}</span>
          ) : null}
          <span className={`meta-chip confidence status-${node.data.confidence}`}>
            {node.data.confidence ? t[`confidence${node.data.confidence.charAt(0).toUpperCase()}${node.data.confidence.slice(1)}`] : ''}
          </span>
          {receivedAt ? (
            <span className="meta-chip" title={new Date(Date.parse(receivedAt)).toLocaleString()}>
              {timeAgo(receivedAt, language)}
            </span>
          ) : null}
          {node.data.tool && !node.data.isRoot ? <span className="meta-chip">{node.data.tool}</span> : null}
        </div>
      </div>

      {node.data.fields?.length ? (
        <div className="detail-fields">
          {node.data.fields.map((field, index) => (
            <div className="detail-field" key={`${field.label}-${index}`}>
              <small>{field.label}</small>
              <span className="detail-field-value">{String(field.value ?? '')}</span>
              <button
                className="field-icon"
                onClick={() => copyValue(field.value)}
                aria-label={t.copy}
                title={t.copy}
              >⧉</button>
            </div>
          ))}
        </div>
      ) : (
        <p className="inspector-empty">{node.data.isRoot ? (language === 'ru' ? 'Корневой узел исследования.' : 'Root node of the investigation.') : (language === 'ru' ? 'Полей нет.' : 'No fields.')}</p>
      )}

      {deepDives.length ? (
        <div className="deep-dives">
          <small>{t.deepDive}</small>
          {deepDives.map((item) => (
            <button className="deep-dive-button" key={item.value} onClick={() => onDeepDive(item.value)} type="button">
              ⤷ {item.value.length > 42 ? `${item.value.slice(0, 42)}…` : item.value}
            </button>
          ))}
        </div>
      ) : null}

      {node.data.source_url ? (
        <a className="source-link" href={node.data.source_url} target="_blank" rel="noreferrer">
          {language === 'ru' ? 'Открыть источник ↗' : 'Open source ↗'}
        </a>
      ) : null}

      <div className="notes-block">
        <button className="notes-toggle" onClick={() => setOpenNote((open) => !open)} type="button">
          {language === 'ru' ? 'Заметки' : 'Notes'} {(noteValue ? '•' : '')}
        </button>
        {openNote ? (
          <textarea
            value={noteValue}
            onChange={(event) => onNoteChange(event.target.value)}
            placeholder={language === 'ru' ? 'Свободная заметка сохраняется локально в браузере.' : 'Free-form note stored locally in the browser.'}
            rows={5}
          />
        ) : null}
      </div>

      {!node.data.isRoot ? (
        <button className="secondary-button full-width hide-branch-button" onClick={onHideBranch}>
          {language === 'ru' ? 'Скрыть ветвь' : 'Hide branch'}
        </button>
      ) : null}
    </aside>
  );
}
