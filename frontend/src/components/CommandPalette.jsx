import { useEffect, useMemo, useRef, useState } from 'react';
import { Search } from 'lucide-react';

export default function CommandPalette({ open, onClose, actions, onSubmitQuery, t }) {
  const [text, setText] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);
  const [lastOpen, setLastOpen] = useState(open);
  const inputRef = useRef(null);

  // Сброс состояния при открытии (без эффектов — паттерн «состояние во время рендера»).
  if (open !== lastOpen) {
    setLastOpen(open);
    if (open) {
      setText('');
      setActiveIndex(0);
    }
  }

  useEffect(() => {
    if (open) {
      window.setTimeout(() => inputRef.current?.focus(), 30);
    }
  }, [open]);

  const filteredActions = useMemo(() => {
    const needle = text.trim().toLowerCase();
    if (!needle) return actions.slice(0, 12);
    return actions.filter((action) => action.label.toLowerCase().includes(needle)).slice(0, 12);
  }, [actions, text]);

  if (!open) return null;

  const commit = () => {
    const query = text.trim();
    if (filteredActions.length > 0 && query && filteredActions[activeIndex]) {
      filteredActions[activeIndex].run();
      onClose();
      return;
    }
    if (query) {
      onSubmitQuery(query);
      onClose();
      return;
    }
    if (!query && filteredActions[activeIndex]) {
      filteredActions[activeIndex].run();
      onClose();
    }
  };

  return (
    <div className="palette-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
      <div className="palette" role="dialog" aria-label="Command palette">
        <div className="palette-input-row">
          <Search className="palette-search-icon" aria-hidden="true" />
          <input
            ref={inputRef}
            value={text}
            placeholder={t.palettePlaceholder}
            onChange={(event) => { setText(event.target.value); setActiveIndex(0); }}
            onKeyDown={(event) => {
              if (event.key === 'Escape') onClose();
              if (event.key === 'Enter') { event.preventDefault(); commit(); }
              if (event.key === 'ArrowDown') { event.preventDefault(); setActiveIndex((i) => Math.min(i + 1, Math.max(0, filteredActions.length - 1))); }
              if (event.key === 'ArrowUp') { event.preventDefault(); setActiveIndex((i) => Math.max(i - 1, 0)); }
            }}
            spellCheck="false"
          />
          <kbd>Esc</kbd>
        </div>
        <ul className="palette-list">
          {filteredActions.map((action, index) => (
            <li key={action.id}>
              <button
                className={index === activeIndex ? 'is-active' : ''}
                onMouseEnter={() => setActiveIndex(index)}
                onClick={() => { action.run(); onClose(); }}
                type="button"
              >
                <span>{action.label}</span>
                {action.hint ? <small>{action.hint}</small> : null}
              </button>
            </li>
          ))}
          {filteredActions.length === 0 && text.trim() ? (
            <li className="palette-hint">{t.paletteRunScan}</li>
          ) : null}
        </ul>
      </div>
    </div>
  );
}
