import { useContext, useRef, useState } from 'react';
import { LanguageContext, ToastContext, statusLabel } from '../i18n';

const MAX_BYTES = 25 * 1024 * 1024;

export function ExifCard({ apiBase, results, setResults }) {
  const language = useContext(LanguageContext);
  const pushToast = useContext(ToastContext);
  const [dragOver, setDragOver] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const inputRef = useRef(null);

  const upload = async (file) => {
    if (!file) return;
    if (file.size > MAX_BYTES) {
      setError(language === 'ru' ? 'Файл больше 25 МБ.' : 'File is larger than 25 MB.');
      return;
    }
    setBusy(true);
    setError('');
    try {
      const response = await fetch(`${apiBase}/api/exif`, {
        method: 'POST',
        headers: { 'x-file-name': file.name.slice(0, 100) },
        body: file,
      });
      const payload = await response.json();
      if (payload.error) {
        setError(payload.error);
      } else {
        setResults((previous) => [{ id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`, filename: file.name, ...payload }, ...previous].slice(0, 12));
        pushToast(language === 'ru' ? 'Метаданные извлечены' : 'Metadata extracted');
      }
    } catch (uploadError) {
      console.error(uploadError);
      setError(language === 'ru' ? 'Не удалось отправить файл в backend.' : 'Could not upload the file to backend.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <article className="exif-card">
      <div className="tool-card-top"><span>Metadata</span><b className="tool-status tool-available">{language === 'ru' ? 'Локально на сервере' : 'Runs on the server'}</b></div>
      <h2>{language === 'ru' ? 'ExifTool — метаданные файла' : 'ExifTool — file metadata'}</h2>
      <p>{language === 'ru' ? 'Перетащите файл или выберите вручную. Файл обрабатывается локальным ExifTool на backend и не хранится.' : 'Drag a file in or pick one manually. The file is processed by the local ExifTool binary on backend and is not stored.'}</p>
      <div
        className={`dropzone${dragOver ? ' is-dragover' : ''}`}
        onClick={() => inputRef.current?.click()}
        onDragOver={(event) => { event.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragOver(false);
          upload(event.dataTransfer.files?.[0]);
        }}
        role="button"
        tabIndex={0}
        onKeyDown={(event) => { if (event.key === 'Enter') inputRef.current?.click(); }}
      >
        {busy ? (language === 'ru' ? 'Обработка…' : 'Processing…') : (language === 'ru' ? '⬇ Перетащите файл сюда' : '⬇ Drop a file here')}
      </div>
      <input
        ref={inputRef}
        type="file"
        hidden
        onChange={(event) => upload(event.target.files?.[0])}
      />
      {error ? <div className="error-banner inline-error">{error}</div> : null}
      {results.map((item) => (
        <div className="exif-result" key={item.id}>
          <div className="tool-card-top">
            <span>{item.filename}</span>
            <b className={`tool-status tool-${item.status === 'available' ? 'available' : item.status === 'completed' ? 'available' : item.status}`}>
              {statusLabel(item.status, language)}
            </b>
          </div>
          {item.fields?.map((field, index) => (
            <div className="detail-field" key={`${field.label}-${index}`}>
              <small>{field.label}</small>
              <span>{field.value}</span>
            </div>
          ))}
        </div>
      ))}
    </article>
  );
}
