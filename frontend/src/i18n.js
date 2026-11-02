import { createContext } from 'react';

export const LanguageContext = createContext('ru');
export const ToastContext = createContext(() => {});

export const STATUS_LABELS = {
  ru: {
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
  },
  en: {
    ok: 'Confirmed',
    completed: 'Completed',
    error: 'Error',
    failed: 'Failed',
    info: 'Info',
    partial: 'Partial result',
    no_results: 'No results',
    rate_limited: 'Rate limited',
    not_configured: 'Not configured',
    loading: 'Loading',
    root: 'Target',
  },
};

export function statusLabel(status, language) {
  const labels = STATUS_LABELS[language === 'en' ? 'en' : 'ru'] || STATUS_LABELS.ru;
  return labels[status] || labels.info || String(status);
}

export const CATEGORY_LABELS = {
  ru: {
    mail: 'Почта и DNS',
    dns: 'Инфраструктура и DNS',
    web: 'Веб и сертификаты',
    whois: 'Регистрация',
    search: 'Поиск',
    profiles: 'Профили',
    reputation: 'Репутация',
    leaks: 'Утечки',
    phone: 'Телефон',
    org: 'Организации',
  },
  en: {
    mail: 'Mail & DNS',
    dns: 'Infrastructure & DNS',
    web: 'Web & certificates',
    whois: 'Registration',
    search: 'Search',
    profiles: 'Public profiles',
    reputation: 'Reputation',
    leaks: 'Breach data',
    phone: 'Phone',
    org: 'Organizations',
  },
};

export function categoryLabel(category, language) {
  if (!category) return null;
  const map = CATEGORY_LABELS[language === 'en' ? 'en' : 'ru'] || CATEGORY_LABELS.ru;
  return map[category] || category;
}

const TOOL_TRANSLATIONS_RU = {
  dns: ['DNS-записи', 'Публичные записи MX, SPF и DMARC, полученные через DNS.'],
  rdap: ['RDAP / WHOIS', 'Публичные регистрационные данные; состав полей зависит от реестра.'],
  website: ['Метаданные сайта', 'Один ограниченный HTTPS-запрос к публичному адресу; редиректы не выполняются.'],
  'certificate-transparency': ['Прозрачность сертификатов (crt.sh)', 'Публичные имена сертификатов с глубиной, ограниченной настройкой поиска.'],
  phone: ['Данные телефонного номера', 'Локальный разбор номера; регион и оператор относятся к плану нумерации, а не к владельцу.'],
  github: ['Публичные коммиты GitHub', 'Поиск по публичным данным коммитов; токен повышает лимит GitHub API.'],
  gravatar: ['Gravatar', 'Проверяет публичный аватар по точному хешу адреса электронной почты.'],
  openpgp: ['keys.openpgp.org', 'Ищет опубликованный публичный ключ; приватные ключи не запрашиваются.'],
  hibp: ['Have I Been Pwned', 'Показывает названия утечек; содержимое утечек и пароли не загружаются.'],
  shodan: ['Shodan', 'Проверка публичного IP через Shodan API.'],
  theharvester: ['theHarvester', 'Необязательная локальная программа; доступность зависит от установленного бинарного файла.'],
  'username-sites': ['Проверка профилей GitHub', 'Профиль подтверждается только ответом публичного GitHub API.'],
  'google-metadata': ['Публичные метаданные Google', 'Совместимый разрешённый адаптер не настроен; наличие аккаунта не предполагается.'],
  blackbird: ['Blackbird', 'Не установлен и не запускается; демонстрационные ссылки не считаются результатами.'],
  sherlock: ['Sherlock', 'Не установлен и не запускается; одного HTTP-статуса недостаточно для подтверждения профиля.'],
  maigret: ['Maigret', 'Не установлен и не запускается; предположительные профили не создаются.'],
  whatsmyname: ['WhatsMyName', 'Публичный датасет; профиль подтверждается точным совпадением маркера ответа.'],
  epieos: ['Epieos', 'Совместимый разрешённый адаптер не настроен.'],
  virustotal: ['VirusTotal', 'Адаптер пока не реализован; сохранение ключа не включает проверку.'],
  abuseipdb: ['AbuseIPDB', 'Адаптер пока не реализован; сохранение ключа не включает проверку.'],
  censys: ['Censys', 'Адаптер пока не реализован.'],
  urlscan: ['urlscan.io', 'Адаптер не реализован; отправка сканов не выполняется.'],
  'search-api': ['Публичные поисковые API', 'Провайдер поиска не подключён; ссылки и шаблоны не считаются результатами.'],
  exiftool: ['ExifTool', 'Метаданные загруженного файла обрабатываются локальной программой на backend.'],
  'organization-registers': ['Реестры организаций', 'Публичный API GitHub и поиск сущностей Wikidata; доступные поля зависят от источника.'],
  wayback: ['Internet Archive', 'Публичный API сообщает ближайший архивный снимок и URL.'],
};

const TOOL_CATEGORIES_RU = {
  Infrastructure: 'Инфраструктура',
  Identity: 'Идентичность',
  'Public profiles': 'Публичные профили',
  Reputation: 'Репутация',
  Search: 'Поиск',
  Website: 'Веб-сайты',
  Metadata: 'Метаданные',
  Organization: 'Организации',
};

const QUERY_TYPE_LABELS = {
  email: { ru: 'Электронная почта', en: 'Email' },
  username: { ru: 'Имя пользователя', en: 'Username' },
  domain: { ru: 'Домен', en: 'Domain' },
  ip: { ru: 'IP-адрес', en: 'IP address' },
  url: { ru: 'URL', en: 'URL' },
  phone: { ru: 'Телефон', en: 'Phone' },
  organization: { ru: 'Организация', en: 'Organization' },
  file: { ru: 'Файл', en: 'File' },
};

export function queryTypeLabel(type, language) {
  const locale = language === 'en' ? 'en' : 'ru';
  return QUERY_TYPE_LABELS[type]?.[locale] || type;
}

export function localizeTool(tool, language) {
  if (language === 'en') return tool;
  const translation = TOOL_TRANSLATIONS_RU[tool.id];
  return {
    ...tool,
    name: translation?.[0] || tool.name,
    description: translation?.[1] || tool.description,
    category: TOOL_CATEGORIES_RU[tool.category] || tool.category,
  };
}

export function toolStatusLabel(tool, language) {
  if (tool.adapter_implemented === false) {
    return language === 'en' ? 'Adapter not implemented' : 'Адаптер не реализован';
  }
  return tool.status === 'available'
    ? (language === 'en' ? 'Available' : 'Доступен')
    : (language === 'en' ? 'Not connected' : 'Не подключён');
}

export const CONFIDENCE_LABELS = {
  ru: {
    high: 'Высокое доверие',
    medium: 'Среднее доверие',
    low: 'Низкое доверие',
  },
  en: {
    high: 'High confidence',
    medium: 'Medium confidence',
    low: 'Low confidence',
  },
};

export function timeAgo(isoValue, language) {
  const timestamp = Date.parse(String(isoValue || ''));
  if (Number.isNaN(timestamp)) return '';
  const seconds = Math.max(0, Math.round((Date.now() - timestamp) / 1000));
  const ru = language !== 'en';
  const table = [
    [60, ru ? 'только что' : 'just now', 1],
    [3600, ru ? '{n} мин назад' : '{n} min ago', 60],
    [86400, ru ? '{n} ч назад' : '{n} h ago', 3600],
    [2592000, ru ? '{n} дн назад' : '{n} d ago', 86400],
  ];
  for (const [limit, template, divisor] of table) {
    if (seconds < limit) {
      if (divisor === 1) return template;
      const value = Math.max(1, Math.floor(seconds / divisor));
      return template.replace('{n}', String(value));
    }
  }
  return new Date(timestamp).toLocaleDateString(ru ? 'ru-RU' : 'en-US');
}

/** Определяет тип идентификатора для глубокого исследования значений. */
export function inferType(value) {
  const text = String(value || '').trim();
  if (!text || text.length > 255) return null;
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(text)) return 'email';
  if (/^https?:\/\/\S+$/i.test(text.toLowerCase())) return 'url';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(text) || /^[0-9a-f:]+:[0-9a-f:]+$/i.test(text)) return 'ip';
  if (/^\+?[0-9\s().-]{10,18}$/.test(text) && (text.match(/\d/g) || []).length >= 10) return 'phone';
  if (text.includes('.') && /^[a-z0-9.-]+$/i.test(text) && !/\/|@|:/.test(text)) return 'domain';
  if (!/[\s/\\@:]/.test(text)) return 'username';
  return null;
}
