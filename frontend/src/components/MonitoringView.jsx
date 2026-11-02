import { statusLabel, timeAgo } from '../i18n';

const QUERY_TYPES = ['email', 'username', 'domain', 'ip', 'url', 'phone', 'organization'];
const TYPE_LABELS = {
  ru: { email: 'Email', username: 'Имя пользователя', domain: 'Домен', ip: 'IP-адрес', url: 'URL', phone: 'Телефон', organization: 'Организация' },
  en: { email: 'Email', username: 'Username', domain: 'Domain', ip: 'IP address', url: 'URL', phone: 'Phone', organization: 'Organization' },
};

export default function MonitoringView({
  t,
  language,
  watches,
  watchesError,
  watchLoading,
  form,
  onFormChange,
  onCreate,
  onDelete,
  onWatch,
}) {
  const lang = language === 'en' ? 'en' : 'ru';

  return (
    <section className="page-content">
      <div className="page-heading">
        <p className="eyebrow">MONITORING</p>
        <h1>{t.monitoringTitle}</h1>
        <p>{t.monitoringDetail}</p>
      </div>

      <form className="watch-form" onSubmit={(event) => { event.preventDefault(); onCreate(); }}>
        <label>
          <span>{t.watchQuery}</span>
          <input value={form.query} onChange={(event) => onFormChange({ ...form, query: event.target.value })} maxLength={255} />
        </label>
        <label>
          <span>{t.watchType}</span>
          <select value={form.queryType} onChange={(event) => onFormChange({ ...form, queryType: event.target.value })}>
            {QUERY_TYPES.map((type) => <option key={type} value={type}>{TYPE_LABELS[lang][type]}</option>)}
          </select>
        </label>
        <label>
          <span>{t.watchDepth}</span>
          <select value={form.depth} onChange={(event) => onFormChange({ ...form, depth: Number(event.target.value) })}>
            <option value={1}>1</option><option value={2}>2</option><option value={3}>3</option>
          </select>
        </label>
        <label>
          <span>{t.watchInterval}</span>
          <select value={form.intervalMinutes} onChange={(event) => onFormChange({ ...form, intervalMinutes: Number(event.target.value) })}>
            <option value={15}>15 {lang === 'ru' ? 'мин' : 'min'}</option>
            <option value={60}>60 {lang === 'ru' ? 'мин' : 'min'}</option>
            <option value={360}>360 {lang === 'ru' ? 'мин' : 'min'}</option>
            <option value={1440}>24 {lang === 'ru' ? 'ч' : 'h'}</option>
          </select>
        </label>
        <button className="primary-button" type="submit" disabled={watchLoading || !form.query.trim()}>
          {watchLoading ? t.analyzing : t.watchCreate}
        </button>
      </form>

      {watchesError ? <div className="error-banner inline-error">{watchesError}</div> : null}

      {watches.length === 0 && !watchLoading ? (
        <div className="empty-panel">
          <h2>{t.watchEmptyTitle}</h2>
          <p>{t.watchEmptyText}</p>
        </div>
      ) : (
        <div className="watch-list">
          {watches.map((watch) => (
            <article className="watch-item" key={watch.id}>
              <div className="watch-item-head">
                <span className="type-label">{TYPE_LABELS[lang][watch.query_type] || watch.query_type}{watch.depth > 1 ? ` · d${watch.depth}` : ''}</span>
                <h2>{watch.query}</h2>
                <small>
                  {watch.last_run_at ? `${t.watchLast}: ${timeAgo(watch.last_run_at, lang)} · ` : ''}
                  {watch.next_run_in_minutes != null ? `${t.watchNext}: ${watch.next_run_in_minutes} ${lang === 'ru' ? 'мин' : 'min'}` : t.watchPending}
                  {' · '}{watch.results} {t.findings}
                </small>
              </div>
              {watch.diff ? (
                <div className="diff-counts small">
                  <span className="diff-added">+{(watch.diff.added || []).length}</span>
                  <span className="diff-changed">≈{(watch.diff.changed || []).length}</span>
                  <span className="diff-removed">−{(watch.diff.removed || []).length}</span>
                </div>
              ) : null}
              {watch.diff && (watch.diff.added?.length || watch.diff.changed?.length) ? (
                <ul className="watch-changes">
                  {(watch.diff.added || []).slice(0, 4).map((title) => <li key={`a-${title}`} className="diff-added">+ {title}</li>)}
                  {(watch.diff.changed || []).slice(0, 4).map((entry) => (
                    <li key={`c-${entry.title}`} className="diff-changed">≈ {entry.title} ({statusLabel(entry.from, lang)} → {statusLabel(entry.to, lang)})</li>
                  ))}
                </ul>
              ) : null}
              <div className="history-actions">
                <button className="secondary-button" onClick={() => onWatch(watch.query)} type="button">{t.watchRunNow}</button>
                <button className="icon-button danger-button" onClick={() => onDelete(watch.id)} aria-label={t.watchDelete} type="button">×</button>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
