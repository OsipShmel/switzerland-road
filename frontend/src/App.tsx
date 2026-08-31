import {
  type FormEvent,
  type KeyboardEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import { streamDemoEvents } from "./services/securityGate";
import type {
  CorrelationMode,
  ScanConfiguration,
  Severity,
  VulnerabilitySummary,
} from "./types";

type Phase =
  | "idle"
  | "repository"
  | "mode"
  | "configured"
  | "running"
  | "complete";

type MessageRole = "assistant" | "user" | "system";

type MessagePayload =
  | { kind: "text"; text: string }
  | { kind: "mode"; repositoryUrl: string }
  | { kind: "configuration"; configuration: ScanConfiguration }
  | { kind: "progress"; stage: string; details: string; progress: number }
  | { kind: "findings"; findings: VulnerabilitySummary[] };

type ChatMessage = {
  id: number;
  role: MessageRole;
  timestamp: string;
} & MessagePayload;

type ChatMessageDraft = {
  role: MessageRole;
} & MessagePayload;

const INITIAL_MESSAGE: ChatMessage = {
  id: 1,
  role: "assistant",
  kind: "text",
  text: "Готов настроить анализ репозитория. Введите /start, чтобы начать.",
  timestamp: formatTime(),
};

const MODE_LABELS: Record<CorrelationMode, string> = {
  correlated: "С корреляцией · тестовая функция",
  separate: "Без корреляции · DAST отдельно",
};

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "Критическая",
  high: "Высокая",
  medium: "Средняя",
  low: "Низкая",
};

function formatTime(): string {
  return new Intl.DateTimeFormat("ru-RU", {
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date());
}

function isRepositoryUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return (
      (url.protocol === "https:" || url.protocol === "http:") &&
      url.hostname.length > 0 &&
      url.pathname !== "/"
    );
  } catch {
    return false;
  }
}

function shortRepositoryName(repositoryUrl: string): string {
  try {
    const url = new URL(repositoryUrl);
    return `${url.hostname}${url.pathname.replace(/\/$/, "")}`;
  } catch {
    return repositoryUrl;
  }
}

function App() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [messages, setMessages] = useState<ChatMessage[]>([INITIAL_MESSAGE]);
  const [input, setInput] = useState("");
  const [repositoryUrl, setRepositoryUrl] = useState("");
  const [configuration, setConfiguration] =
    useState<ScanConfiguration | null>(null);
  const [findings, setFindings] = useState<VulnerabilitySummary[]>([]);

  const nextMessageId = useRef(2);
  const streamCleanup = useRef<(() => void) | null>(null);
  const chatEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const appendMessage = useCallback(
    (message: ChatMessageDraft) => {
      setMessages((current) => [
        ...current,
        {
          ...message,
          id: nextMessageId.current++,
          timestamp: formatTime(),
        } as ChatMessage,
      ]);
    },
    [],
  );

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  useEffect(() => {
    return () => streamCleanup.current?.();
  }, []);

  const resetChat = useCallback(() => {
    streamCleanup.current?.();
    streamCleanup.current = null;
    nextMessageId.current = 2;
    setPhase("idle");
    setMessages([
      {
        ...INITIAL_MESSAGE,
        timestamp: formatTime(),
      },
    ]);
    setInput("");
    setRepositoryUrl("");
    setConfiguration(null);
    setFindings([]);
    window.setTimeout(() => inputRef.current?.focus(), 0);
  }, []);

  const chooseMode = useCallback(
    (mode: CorrelationMode, showSelection = true) => {
      if (phase !== "mode") return;

      const nextConfiguration: ScanConfiguration = {
        repositoryUrl,
        correlationMode: mode,
      };
      setConfiguration(nextConfiguration);
      setPhase("configured");
      if (showSelection) {
        appendMessage({
          role: "user",
          kind: "text",
          text: MODE_LABELS[mode],
        });
      }
      appendMessage({
        role: "assistant",
        kind: "configuration",
        configuration: nextConfiguration,
      });
    },
    [appendMessage, phase, repositoryUrl],
  );

  const startDemo = useCallback(() => {
    if (!configuration || phase === "running") return;

    streamCleanup.current?.();
    setFindings([]);
    setPhase("running");
    appendMessage({
      role: "system",
      kind: "text",
      text: "Запущена демонстрация потока логов. Реальный Security Gate не вызывается.",
    });

    const collectedFindings: VulnerabilitySummary[] = [];
    streamCleanup.current = streamDemoEvents(configuration, (event) => {
      if (event.type === "progress") {
        appendMessage({
          role: "assistant",
          kind: "progress",
          stage: event.stage,
          details: event.details,
          progress: event.progress,
        });
        return;
      }

      if (event.type === "finding") {
        collectedFindings.push(event.finding);
        setFindings([...collectedFindings]);
        return;
      }

      if (event.type === "error") {
        setPhase("configured");
        appendMessage({
          role: "assistant",
          kind: "text",
          text: `Ошибка выполнения: ${event.message}`,
        });
        return;
      }

      setPhase("complete");
      appendMessage({
        role: "assistant",
        kind: "findings",
        findings: [...collectedFindings],
      });
    });
  }, [appendMessage, configuration, phase]);

  const processInput = useCallback(
    (rawValue: string) => {
      const value = rawValue.trim();
      if (!value) return;

      appendMessage({ role: "user", kind: "text", text: value });
      setInput("");

      if (value === "/reset") {
        window.setTimeout(resetChat, 120);
        return;
      }

      if (value === "/help") {
        appendMessage({
          role: "assistant",
          kind: "text",
          text: "Доступные команды: /start — новая настройка, /demo — показать поток логов, /reset — очистить чат.",
        });
        return;
      }

      if (value === "/start") {
        streamCleanup.current?.();
        setConfiguration(null);
        setFindings([]);
        setRepositoryUrl("");
        setPhase("repository");
        appendMessage({
          role: "assistant",
          kind: "text",
          text: "Пришлите HTTPS-ссылку на репозиторий, который нужно проверить.",
        });
        return;
      }

      if (value === "/demo") {
        if (configuration && (phase === "configured" || phase === "complete")) {
          startDemo();
        } else {
          appendMessage({
            role: "assistant",
            kind: "text",
            text: "Сначала завершите настройку через /start.",
          });
        }
        return;
      }

      if (phase === "repository") {
        if (!isRepositoryUrl(value)) {
          appendMessage({
            role: "assistant",
            kind: "text",
            text: "Ссылка не похожа на адрес репозитория. Используйте полный URL, например https://github.com/team/project.",
          });
          return;
        }
        setRepositoryUrl(value);
        setPhase("mode");
        appendMessage({
          role: "assistant",
          kind: "mode",
          repositoryUrl: value,
        });
        return;
      }

      if (phase === "mode") {
        if (value === "1" || value === "/correlation") {
          chooseMode("correlated", false);
          return;
        }
        if (value === "2" || value === "/separate") {
          chooseMode("separate", false);
          return;
        }
        appendMessage({
          role: "assistant",
          kind: "text",
          text: "Выберите один из вариантов кнопкой ниже или отправьте 1 либо 2.",
        });
        return;
      }

      if (phase === "running") {
        appendMessage({
          role: "assistant",
          kind: "text",
          text: "Демонстрация выполняется. Для остановки и очистки используйте /reset.",
        });
        return;
      }

      appendMessage({
        role: "assistant",
        kind: "text",
        text: "Не понял сообщение. Введите /start для новой проверки или /help для списка команд.",
      });
    },
    [
      appendMessage,
      chooseMode,
      configuration,
      phase,
      resetChat,
      startDemo,
    ],
  );

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault();
    processInput(input);
  };

  const handleInputKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      processInput(input);
    }
  };

  const statusLabel =
    phase === "running"
      ? "демо выполняется"
      : phase === "complete"
        ? "демо завершено"
        : "готов к работе";

  return (
    <main className="app-shell">
      <section className="chat-window" aria-label="Security Gate chat">
        <header className="chat-header">
          <div className="brand-mark" aria-hidden="true">
            <ShieldIcon />
          </div>
          <div className="brand-copy">
            <h1>Security Gate</h1>
            <div className="status-line">
              <span
                className={`status-dot ${phase === "running" ? "status-dot--active" : ""}`}
              />
              {statusLabel}
            </div>
          </div>
          <button className="reset-button" type="button" onClick={resetChat}>
            Новый чат
          </button>
        </header>

        <div className="messages" aria-live="polite">
          <div className="day-divider"><span>Сегодня</span></div>
          {messages.map((message) => (
            <MessageBubble
              key={message.id}
              message={message}
              phase={phase}
              onModeSelect={chooseMode}
              onDemoStart={startDemo}
            />
          ))}

          {phase === "running" && (
            <div className="typing-indicator" aria-label="Анализ выполняется">
              <span />
              <span />
              <span />
            </div>
          )}
          <div ref={chatEndRef} />
        </div>

        <footer className="composer-area">
          {phase === "idle" && (
            <button
              type="button"
              className="command-chip"
              onClick={() => processInput("/start")}
            >
              /start
            </button>
          )}
          {(phase === "configured" || phase === "complete") && (
            <button
              type="button"
              className="command-chip"
              onClick={startDemo}
            >
              /demo логов
            </button>
          )}
          <form className="composer" onSubmit={handleSubmit}>
            <textarea
              ref={inputRef}
              value={input}
              onChange={(event) => setInput(event.target.value)}
              onKeyDown={handleInputKeyDown}
              rows={1}
              placeholder={
                phase === "repository"
                  ? "https://github.com/team/repository"
                  : "Введите сообщение или команду"
              }
              aria-label="Сообщение"
            />
            <button
              className="send-button"
              type="submit"
              disabled={!input.trim()}
              aria-label="Отправить"
            >
              <SendIcon />
            </button>
          </form>
          <p className="composer-hint">
            Enter — отправить · Shift + Enter — новая строка
          </p>
        </footer>
      </section>
      {findings.length > 0 && phase === "running" && (
        <div className="sr-only">Найдено уязвимостей: {findings.length}</div>
      )}
    </main>
  );
}

interface MessageBubbleProps {
  message: ChatMessage;
  phase: Phase;
  onModeSelect: (mode: CorrelationMode) => void;
  onDemoStart: () => void;
}

function MessageBubble({
  message,
  phase,
  onModeSelect,
  onDemoStart,
}: MessageBubbleProps) {
  return (
    <article className={`message message--${message.role}`}>
      {message.role !== "user" && (
        <div className="message-avatar" aria-hidden="true">
          {message.role === "system" ? <TerminalIcon /> : <ShieldIcon />}
        </div>
      )}
      <div className="message-column">
        <div className="message-meta">
          <span>{message.role === "user" ? "Вы" : "Gate"}</span>
          <time>{message.timestamp}</time>
        </div>
        <div className={`bubble bubble--${message.kind}`}>
          {message.kind === "text" && <p>{message.text}</p>}
          {message.kind === "mode" && (
            <ModeSelection
              repositoryUrl={message.repositoryUrl}
              disabled={phase !== "mode"}
              onSelect={onModeSelect}
            />
          )}
          {message.kind === "configuration" && (
            <ConfigurationCard
              configuration={message.configuration}
              canRunDemo={phase === "configured" || phase === "complete"}
              onDemoStart={onDemoStart}
            />
          )}
          {message.kind === "progress" && (
            <ProgressCard
              stage={message.stage}
              details={message.details}
              progress={message.progress}
            />
          )}
          {message.kind === "findings" && (
            <FindingsList findings={message.findings} />
          )}
        </div>
      </div>
    </article>
  );
}

function ModeSelection({
  repositoryUrl,
  disabled,
  onSelect,
}: {
  repositoryUrl: string;
  disabled: boolean;
  onSelect: (mode: CorrelationMode) => void;
}) {
  return (
    <div className="mode-selection">
      <p>
        Репозиторий принят: <strong>{shortRepositoryName(repositoryUrl)}</strong>
      </p>
      <p className="muted">Выберите режим обработки результатов:</p>
      <div className="mode-options">
        <button
          type="button"
          className="mode-option mode-option--accent"
          disabled={disabled}
          onClick={() => onSelect("correlated")}
        >
          <span className="mode-number">01</span>
          <span className="mode-copy">
            <strong>Включить корреляцию</strong>
            <small>SAST и DAST будут связаны в VLS Registry</small>
          </span>
          <span className="test-badge">Тестовая функция</span>
        </button>
        <button
          type="button"
          className="mode-option"
          disabled={disabled}
          onClick={() => onSelect("separate")}
        >
          <span className="mode-number">02</span>
          <span className="mode-copy">
            <strong>Без корреляции</strong>
            <small>Отчет DAST будет сохранен отдельным логом</small>
          </span>
        </button>
      </div>
    </div>
  );
}

function ConfigurationCard({
  configuration,
  canRunDemo,
  onDemoStart,
}: {
  configuration: ScanConfiguration;
  canRunDemo: boolean;
  onDemoStart: () => void;
}) {
  return (
    <div className="configuration-card">
      <div className="card-heading">
        <span className="success-icon"><CheckIcon /></span>
        <div>
          <strong>Конфигурация готова</strong>
          <p>Данные сохранены только в интерфейсе</p>
        </div>
      </div>
      <dl className="configuration-grid">
        <div>
          <dt>Репозиторий</dt>
          <dd>{shortRepositoryName(configuration.repositoryUrl)}</dd>
        </div>
        <div>
          <dt>Режим</dt>
          <dd>{MODE_LABELS[configuration.correlationMode]}</dd>
        </div>
      </dl>
      <div className="notice">
        <InfoIcon />
        <span>
          Security Gate пока не подключен — запрос никуда не отправляется.
        </span>
      </div>
      {canRunDemo && (
        <button className="demo-button" type="button" onClick={onDemoStart}>
          Показать demo выполнения
          <ArrowIcon />
        </button>
      )}
    </div>
  );
}

function ProgressCard({
  stage,
  details,
  progress,
}: {
  stage: string;
  details: string;
  progress: number;
}) {
  return (
    <div className="progress-card">
      <div className="progress-heading">
        <strong>{stage}</strong>
        <span>{progress}%</span>
      </div>
      <p>{details}</p>
      <div
        className="progress-track"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={progress}
      >
        <span style={{ width: `${progress}%` }} />
      </div>
    </div>
  );
}

function FindingsList({ findings }: { findings: VulnerabilitySummary[] }) {
  return (
    <div className="findings-card">
      <div className="findings-heading">
        <div>
          <strong>Проверка завершена</strong>
          <p>Демонстрационный результат · {findings.length} находки</p>
        </div>
        <span className="finding-count">{findings.length}</span>
      </div>
      <div className="findings-list">
        {findings.length === 0 ? (
          <p className="empty-state">Уязвимости не найдены</p>
        ) : (
          findings.map((finding) => (
            <div className="finding-item" key={finding.id}>
              <span className={`severity severity--${finding.severity}`}>
                {SEVERITY_LABELS[finding.severity]}
              </span>
              <div className="finding-content">
                <strong>{finding.title}</strong>
                <span>{finding.location}</span>
              </div>
              <div className="finding-source">{finding.source}</div>
            </div>
          ))
        )}
      </div>
      <p className="demo-disclaimer">
        Эти данные нужны только для демонстрации будущего чтения логов.
      </p>
    </div>
  );
}

function ShieldIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 3 5.5 5.7v5.1c0 4.4 2.7 8.2 6.5 9.7 3.8-1.5 6.5-5.3 6.5-9.7V5.7L12 3Z" />
      <path d="m9.4 11.8 1.7 1.7 3.7-4" />
    </svg>
  );
}

function SendIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="m4 4 16 8-16 8 3-8-3-8Z" />
      <path d="M7 12h13" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="m6 12.5 4 4L18 8" />
    </svg>
  );
}

function InfoIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="12" cy="12" r="9" />
      <path d="M12 11v5M12 8h.01" />
    </svg>
  );
}

function ArrowIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M5 12h14M14 7l5 5-5 5" />
    </svg>
  );
}

function TerminalIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="m5 7 4 4-4 4M11 17h7" />
    </svg>
  );
}

export default App;
