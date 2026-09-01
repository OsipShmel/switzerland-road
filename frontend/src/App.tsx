import {
  type FormEvent,
  type KeyboardEvent,
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import { securityGateClient } from "./services/securityGate";
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
  | "submitting"
  | "running"
  | "complete"
  | "failed";

type MessageRole = "assistant" | "user" | "system";

type MessagePayload =
  | { kind: "text"; text: string }
  | { kind: "mode"; repositoryUrl: string }
  | {
      kind: "configuration";
      configuration: ScanConfiguration;
      scanId: string;
    }
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
  const [findings, setFindings] = useState<VulnerabilitySummary[]>([]);

  const nextMessageId = useRef(2);
  const submissionVersion = useRef(0);
  const streamCleanup = useRef<(() => void) | null>(null);
  const findingsRef = useRef<VulnerabilitySummary[]>([]);
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
    submissionVersion.current += 1;
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
    setFindings([]);
    findingsRef.current = [];
    window.setTimeout(() => inputRef.current?.focus(), 0);
  }, []);

  const chooseMode = useCallback(
    async (mode: CorrelationMode, showSelection = true) => {
      if (phase !== "mode") return;

      const nextConfiguration: ScanConfiguration = {
        repositoryUrl,
        correlationMode: mode,
      };
      if (showSelection) {
        appendMessage({
          role: "user",
          kind: "text",
          text: MODE_LABELS[mode],
        });
      }
      setPhase("submitting");
      const currentSubmission = ++submissionVersion.current;

      try {
        const receipt = await securityGateClient.startScan(nextConfiguration);
        if (currentSubmission !== submissionVersion.current) return;

        findingsRef.current = [];
        setFindings([]);
        setPhase("running");
        appendMessage({
          role: "assistant",
          kind: "configuration",
          configuration: nextConfiguration,
          scanId: receipt.scanId,
        });
        streamCleanup.current = securityGateClient.subscribe(
          receipt.scanId,
          (event) => {
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
              const current = findingsRef.current;
              const existingIndex = current.findIndex(
                (finding) => finding.id === event.finding.id,
              );
              const updated = [...current];
              if (existingIndex >= 0) {
                updated[existingIndex] = event.finding;
              } else {
                updated.push(event.finding);
              }
              findingsRef.current = updated;
              setFindings(updated);
              return;
            }

            streamCleanup.current?.();
            streamCleanup.current = null;
            if (event.type === "error") {
              setPhase("failed");
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
              kind: "text",
              text: event.summary,
            });
            appendMessage({
              role: "assistant",
              kind: "findings",
              findings: findingsRef.current,
            });
          },
        );
      } catch (error) {
        if (currentSubmission !== submissionVersion.current) return;

        setPhase("mode");
        appendMessage({
          role: "assistant",
          kind: "text",
          text:
            error instanceof Error
              ? error.message
              : "Не удалось отправить заявку в Security Gate.",
        });
      }
    },
    [appendMessage, phase, repositoryUrl],
  );

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
          text: "Доступные команды: /start — новая проверка, /reset — очистить чат.",
        });
        return;
      }

      if (value === "/start") {
        streamCleanup.current?.();
        setFindings([]);
        findingsRef.current = [];
        setRepositoryUrl("");
        setPhase("repository");
        appendMessage({
          role: "assistant",
          kind: "text",
          text: "Пришлите HTTPS-ссылку на репозиторий, который нужно проверить.",
        });
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
          text: "Проверка выполняется. Новые этапы и результаты появятся здесь автоматически.",
        });
        return;
      }

      appendMessage({
        role: "assistant",
        kind: "text",
        text: "Не понял сообщение. Введите /start для новой проверки или /help для списка команд.",
      });
    },
    [appendMessage, chooseMode, phase, resetChat],
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
      ? "проверка выполняется"
      : phase === "submitting"
        ? "отправка заявки"
        : phase === "complete"
          ? "проверка завершена"
          : phase === "failed"
            ? "ошибка проверки"
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
            />
          ))}

          {phase === "running" && (
            <div className="typing-indicator" aria-label="Анализ выполняется">
              <span />
              <span />
              <span />
            </div>
          )}
          {phase === "submitting" && (
            <div className="typing-indicator" aria-label="Заявка отправляется">
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
}

function MessageBubble({
  message,
  phase,
  onModeSelect,
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
              scanId={message.scanId}
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
  scanId,
}: {
  configuration: ScanConfiguration;
  scanId: string;
}) {
  return (
    <div className="configuration-card">
      <div className="card-heading">
        <span className="success-icon"><CheckIcon /></span>
        <div>
          <strong>Конфигурация готова</strong>
          <p>Заявка принята Security Gate</p>
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
        <div>
          <dt>Scan ID</dt>
          <dd>{scanId}</dd>
        </div>
      </dl>
      <div className="notice">
        <InfoIcon />
        <span>
          Supervisor скачивает репозиторий, запускает pipeline и передает результат
          в песочницу. Состояние приходит в этот чат автоматически.
        </span>
      </div>
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
          <p>VLS Registry · найдено записей: {findings.length}</p>
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

function TerminalIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="m5 7 4 4-4 4M11 17h7" />
    </svg>
  );
}

export default App;
