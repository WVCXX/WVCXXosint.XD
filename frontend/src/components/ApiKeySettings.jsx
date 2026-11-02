import { useEffect, useState } from 'react';
import { CircleCheck, CircleX, Eye, EyeOff, RefreshCw, Save, ShieldCheck, Trash2 } from 'lucide-react';

const PROVIDERS = [
  { id: 'github', nameRu: 'GitHub', nameEn: 'GitHub', adapterImplemented: true, hintRu: 'Повышает лимит GitHub API для публичных данных.', hintEn: 'Raises the GitHub API rate limit for public data.' },
  { id: 'hibp', nameRu: 'Have I Been Pwned', nameEn: 'Have I Been Pwned', adapterImplemented: true, hintRu: 'Используется для проверки адресов электронной почты.', hintEn: 'Used for email breach checks.' },
  { id: 'shodan', nameRu: 'Shodan', nameEn: 'Shodan', adapterImplemented: true, hintRu: 'Используется для проверки публичных IP-адресов.', hintEn: 'Used for public IP address lookups.' },
  { id: 'virustotal', nameRu: 'VirusTotal', nameEn: 'VirusTotal', adapterImplemented: false, hintRu: 'Ключ сохранится, но проверка не заработает до реализации адаптера.', hintEn: 'The key is stored, but lookups remain unavailable until an adapter is implemented.' },
  { id: 'abuseipdb', nameRu: 'AbuseIPDB', nameEn: 'AbuseIPDB', adapterImplemented: false, hintRu: 'Ключ сохранится, но проверка не заработает до реализации адаптера.', hintEn: 'The key is stored, but lookups remain unavailable until an adapter is implemented.' },
  { id: 'censys_id', nameRu: 'Идентификатор API Censys', nameEn: 'Censys API ID', adapterImplemented: false, hintRu: 'Одна из двух учётных частей Censys. Адаптер пока не реализован.', hintEn: 'One part of the Censys credentials. The adapter is not implemented yet.' },
  { id: 'censys_secret', nameRu: 'Секрет API Censys', nameEn: 'Censys API secret', adapterImplemented: false, hintRu: 'Одна из двух учётных частей Censys. Адаптер пока не реализован.', hintEn: 'One part of the Censys credentials. The adapter is not implemented yet.' },
  { id: 'urlscan', nameRu: 'urlscan.io', nameEn: 'urlscan.io', adapterImplemented: false, hintRu: 'Ключ сохранится, но сканирование не отправляется: адаптер не реализован.', hintEn: 'The key is stored, but scans are not submitted until an adapter is implemented.' },
  { id: 'search', nameRu: 'API поискового сервиса', nameEn: 'Search API', adapterImplemented: false, hintRu: 'Ключ сохранится, но провайдер поиска ещё не подключён.', hintEn: 'The key is stored, but no search provider is connected yet.' },
];

export default function ApiKeySettings({ language, apiBase }) {
  const isEnglish = language === 'en';
  const [keys, setKeys] = useState([]);
  const [health, setHealth] = useState(null);
  const [drafts, setDrafts] = useState({});
  const [visible, setVisible] = useState({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  useEffect(() => {
    const controller = new AbortController();
    const load = async () => {
      try {
        const [keysResponse, healthResponse] = await Promise.all([
          fetch(`${apiBase}/api/settings/keys`, { signal: controller.signal }),
          fetch(`${apiBase}/api/health`, { signal: controller.signal }),
        ]);
        if (!keysResponse.ok) throw new Error(`HTTP ${keysResponse.status}`);
        if (!healthResponse.ok) throw new Error(`HTTP ${healthResponse.status}`);
        const [keysPayload, healthPayload] = await Promise.all([
          keysResponse.json(),
          healthResponse.json(),
        ]);
        setKeys(Array.isArray(keysPayload.keys) ? keysPayload.keys : []);
        setHealth(healthPayload);
        setError('');
      } catch (loadError) {
        if (loadError.name !== 'AbortError') {
          setError(isEnglish ? 'Could not load backend settings.' : 'Не удалось загрузить настройки backend.');
        }
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    };
    load();
    return () => controller.abort();
  }, [apiBase, isEnglish]);

  const refresh = async () => {
    setLoading(true);
    setError('');
    try {
      const [keysResponse, healthResponse] = await Promise.all([
        fetch(`${apiBase}/api/settings/keys`),
        fetch(`${apiBase}/api/health`),
      ]);
      if (!keysResponse.ok || !healthResponse.ok) throw new Error('Backend is unavailable');
      const [keysPayload, healthPayload] = await Promise.all([
        keysResponse.json(),
        healthResponse.json(),
      ]);
      setKeys(Array.isArray(keysPayload.keys) ? keysPayload.keys : []);
      setHealth(healthPayload);
    } catch {
      setError(isEnglish ? 'Could not connect to backend.' : 'Не удалось подключиться к backend.');
    } finally {
      setLoading(false);
    }
  };

  const saveKey = async (event, provider) => {
    event.preventDefault();
    const value = String(drafts[provider] || '').trim();
    if (!value) return;
    setSaving(provider);
    setError('');
    setNotice('');
    try {
      const response = await fetch(`${apiBase}/api/settings/keys/${provider}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ value }),
      });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail || `HTTP ${response.status}`);
      setKeys(payload.keys || []);
      window.dispatchEvent(new Event('osint-tools-updated'));
      setDrafts((previous) => ({ ...previous, [provider]: '' }));
      setVisible((previous) => ({ ...previous, [provider]: false }));
      setNotice(isEnglish ? 'API key saved on the backend.' : 'API-ключ сохранён на backend.');
    } catch (saveError) {
      setError(saveError.message || (isEnglish ? 'Could not save API key.' : 'Не удалось сохранить API-ключ.'));
    } finally {
      setSaving('');
    }
  };

  const removeKey = async (provider) => {
    setSaving(provider);
    setError('');
    setNotice('');
    try {
      const response = await fetch(`${apiBase}/api/settings/keys/${provider}`, { method: 'DELETE' });
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.detail || `HTTP ${response.status}`);
      setKeys(payload.keys || []);
      window.dispatchEvent(new Event('osint-tools-updated'));
      setNotice(isEnglish ? 'Application key removed.' : 'Ключ приложения удалён.');
    } catch (removeError) {
      setError(removeError.message || (isEnglish ? 'Could not remove API key.' : 'Не удалось удалить API-ключ.'));
    } finally {
      setSaving('');
    }
  };

  return (
    <div className="api-settings">
      <div className="backend-health" role="status" aria-live="polite">
        {health?.status === 'ok'
          ? <CircleCheck className="health-icon is-online" aria-hidden="true" />
          : <CircleX className="health-icon is-offline" aria-hidden="true" />}
        <div>
          <strong>{health?.status === 'ok' ? (isEnglish ? 'Backend connected' : 'Backend подключён') : (isEnglish ? 'Backend unavailable' : 'Backend недоступен')}</strong>
          <span>{health?.module_count ?? 0} {isEnglish ? 'modules registered' : 'модулей в реестре'}</span>
        </div>
        <button className="icon-button" type="button" title={isEnglish ? 'Refresh status' : 'Обновить статус'} aria-label={isEnglish ? 'Refresh status' : 'Обновить статус'} onClick={refresh} disabled={loading}>
          <RefreshCw className={loading ? 'is-spinning' : ''} aria-hidden="true" />
        </button>
      </div>

      {error ? <div className="api-settings-message is-error" role="alert">{error}</div> : null}
      {notice ? <div className="api-settings-message is-success" role="status">{notice}</div> : null}

      <div className="api-key-list">
        {PROVIDERS.map((provider) => {
          const status = keys.find((item) => item.provider === provider.id);
          const configured = Boolean(status?.configured);
          const source = status?.source || 'none';
          const adapterImplemented = status?.adapter_implemented ?? provider.adapterImplemented;
          const providerName = isEnglish ? provider.nameEn : provider.nameRu;
          return (
            <form className="api-key-row" key={provider.id} onSubmit={(event) => saveKey(event, provider.id)}>
              <div className="api-key-copy">
                <div className="api-key-heading">
                  <h3>{providerName}</h3>
                  <span className={`api-key-status ${configured ? 'is-configured' : 'is-missing'}`}>
                    {configured && adapterImplemented
                      ? (isEnglish ? 'Configured' : 'Настроен')
                      : configured
                        ? (isEnglish ? 'Key saved · adapter unavailable' : 'Ключ сохранён · адаптер недоступен')
                        : (isEnglish ? 'Not configured' : 'Не настроен')}
                  </span>
                </div>
                <p>{isEnglish ? provider.hintEn : provider.hintRu}</p>
                {configured ? (
                  <small className="api-key-source">
                    {source === 'application'
                      ? (isEnglish ? 'Stored by this app' : 'Сохранён приложением')
                      : (isEnglish ? 'Provided by backend environment' : 'Задан в окружении backend')}
                  </small>
                ) : null}
              </div>
              <label className="api-key-input-wrap">
                <span className="sr-only">{isEnglish ? `${providerName} API key` : `API-ключ ${providerName}`}</span>
                <input
                  type={visible[provider.id] ? 'text' : 'password'}
                  autoComplete="new-password"
                  spellCheck="false"
                  value={drafts[provider.id] || ''}
                  placeholder={isEnglish ? 'Paste a new key' : 'Вставьте ключ'}
                  onChange={(event) => setDrafts((previous) => ({ ...previous, [provider.id]: event.target.value }))}
                  maxLength={4096}
                />
                <button className="icon-button" type="button" title={visible[provider.id] ? (isEnglish ? 'Hide key' : 'Скрыть ключ') : (isEnglish ? 'Show while editing' : 'Показать при вводе')} aria-label={visible[provider.id] ? (isEnglish ? 'Hide key' : 'Скрыть ключ') : (isEnglish ? 'Show key' : 'Показать ключ')} onClick={() => setVisible((previous) => ({ ...previous, [provider.id]: !previous[provider.id] }))}>
                  {visible[provider.id] ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
                </button>
              </label>
              <div className="api-key-actions">
                <button className="secondary-button api-key-save" type="submit" disabled={!String(drafts[provider.id] || '').trim() || Boolean(saving)}>
                  <Save aria-hidden="true" />
                  {saving === provider.id ? (isEnglish ? 'Saving…' : 'Сохранение…') : (isEnglish ? 'Save key' : 'Сохранить')}
                </button>
                {source === 'application' ? (
                  <button className="icon-button danger-button" type="button" title={isEnglish ? 'Remove stored key' : 'Удалить сохранённый ключ'} aria-label={isEnglish ? `Remove ${providerName} key` : `Удалить ключ ${providerName}`} onClick={() => removeKey(provider.id)} disabled={Boolean(saving)}>
                    <Trash2 aria-hidden="true" />
                  </button>
                ) : null}
              </div>
            </form>
          );
        })}
      </div>

      <p className="api-key-notice">
        <ShieldCheck aria-hidden="true" />
        {isEnglish
          ? 'Keys are stored in a backend-only file with owner-only permissions (not encrypted at rest). Values are never sent back to this page.'
          : 'Ключи хранятся в backend-файле с правами только для владельца (без шифрования на диске). Значения не отправляются обратно в браузер.'}
      </p>
    </div>
  );
}