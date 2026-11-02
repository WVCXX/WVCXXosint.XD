import { useContext, useState } from 'react';
import { Activity, CircleHelp, FileText, History, Languages, Moon, ScanSearch, Settings2, Sun, Wrench } from 'lucide-react';
import { LanguageContext } from '../i18n';

const NAV_ICONS = {
  investigation: ScanSearch,
  tools: Wrench,
  monitoring: Activity,
  history: History,
  reports: FileText,
  settings: Settings2,
  about: CircleHelp,
};

export default function SidebarRail({ items, activeView, onSelect, theme, onToggleTheme }) {
  const language = useContext(LanguageContext);
  const [hovered, setHovered] = useState(null);

  return (
    <nav className="side-rail" aria-label={language === 'ru' ? 'Основная навигация' : 'Main navigation'}>
      <div className="rail-brand" aria-hidden="true">S</div>
      <div className="rail-items">
        {items.map(([id, russian, english]) => {
          const Icon = NAV_ICONS[id];
          return (
            <button
              key={id}
              className={`rail-button${activeView === id ? ' is-active' : ''}`}
              onClick={() => onSelect(id)}
              onMouseEnter={() => setHovered(id)}
              onMouseLeave={() => setHovered(null)}
              type="button"
              aria-pressed={activeView === id}
              title={language === 'ru' ? russian : english}
            >
              <Icon className="rail-icon" aria-hidden="true" />
              <span className={`rail-label${hovered === id ? ' is-visible' : ''}`}>
                {language === 'ru' ? russian : english}
              </span>
            </button>
          );
        })}
      </div>
      <div className="rail-footer">
        <button
          className="rail-button"
          onClick={onToggleTheme}
          onMouseEnter={() => setHovered('theme')}
          onMouseLeave={() => setHovered(null)}
          type="button"
        >
          {theme === 'light'
            ? <Moon className="rail-icon" aria-hidden="true" />
            : <Sun className="rail-icon" aria-hidden="true" />}
          <span className={`rail-label${hovered === 'theme' ? ' is-visible' : ''}`}>
            {theme === 'light' ? (language === 'ru' ? 'Тёмная тема' : 'Dark theme') : (language === 'ru' ? 'Светлая тема' : 'Light theme')}
          </span>
        </button>
        <button
          className="rail-button"
          onClick={() => onSelect('__toggle-language')}
          type="button"
        >
          <Languages className="rail-icon" aria-hidden="true" />
          <span className="rail-label">{language.toUpperCase()}</span>
        </button>
      </div>
    </nav>
  );
}
