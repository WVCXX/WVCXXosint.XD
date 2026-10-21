import { Handle, Position } from 'reactflow';

function SkeletonFields() {
  return (
    <div className="node-skeleton" aria-label="Загрузка данных">
      <span className="skeleton-line skeleton-line-wide" />
      <span className="skeleton-line" />
      <span className="skeleton-line skeleton-line-short" />
    </div>
  );
}

export default function NodeCard({ data }) {
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
  const statusLabels = {
    ok: 'Подтверждено',
    completed: 'Завершено',
    error: 'Ошибка',
    failed: 'Ошибка',
    info: 'Информация',
    partial: 'Частичный результат',
    no_results: 'Нет результатов',
    rate_limited: 'Лимит запросов',
    not_configured: 'Не подключено',
    loading: 'Загрузка',
    root: 'Объект',
  };
  const countLabel = count % 10 === 1 && count % 100 !== 11
    ? 'карточка'
    : count % 10 >= 2 && count % 10 <= 4 && (count % 100 < 12 || count % 100 > 14)
      ? 'карточки'
      : 'карточек';

  return (
    <article className={`node-card status-${displayStatus}${isRoot ? ' node-card-root' : ''}${isCategory ? ' node-card-category' : ''}`}>
      <Handle type="target" position={Position.Top} isConnectable={false} />
      <div className="node-status-rail" />
      <div className="node-card-content">
        <header className="node-card-header">
          <h3>{title}</h3>
          {!isRoot && !isCategory ? (
            <span className="node-status-label">{statusLabels[displayStatus] || statusLabels.info}</span>
          ) : null}
        </header>

        {isRoot ? (
          <div className="node-root-meta">
            <span>{query}</span>
            <span className="node-type-pill">{inputType}</span>
          </div>
        ) : isCategory ? (
          <div className="node-category-meta">
            <span>ГРУППА РЕЗУЛЬТАТОВ</span>
            <span>{count} {countLabel}</span>
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
                    <a href={value} target="_blank" rel="noreferrer">
                      {value.replace(/^https?:\/\//i, '')}
                    </a>
                  ) : (
                    <span className="node-field-value">{value}</span>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
      <Handle type="source" position={Position.Bottom} isConnectable={false} />
    </article>
  );
}
