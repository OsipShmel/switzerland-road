import type { ScanConfiguration, ScanEvent } from "../types";

export interface SecurityGateClient {
  startScan(configuration: ScanConfiguration): Promise<ScanReceipt>;
  subscribe(
    scanId: string,
    onEvent: (event: ScanEvent) => void,
  ): () => void;
}

export interface ScanReceipt {
  scanId: string;
  status:
    | "accepted"
    | "running"
    | "sandbox_starting"
    | "agent_running"
    | "completed"
    | "failed";
  repositoryUrl: string;
  correlationEnabled: boolean;
  semgrepConfig: "p/sql-injection" | "p/default" | "auto";
  findingCount?: number;
  error?: string;
}

const SECURITY_GATE_URL = (
  import.meta.env.VITE_SECURITY_GATE_URL ?? "http://127.0.0.1:8000"
).replace(/\/$/, "");

const SEMGREP_CONFIGS = {
  "sql-injection": "p/sql-injection",
  default: "p/default",
  auto: "auto",
} as const;

export const securityGateClient: SecurityGateClient = {
  async startScan(configuration) {
    const response = await fetch(`${SECURITY_GATE_URL}/api/security-gate/scans`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        repositoryUrl: configuration.repositoryUrl,
        correlationEnabled: configuration.correlationMode === "correlated",
        semgrepConfig: SEMGREP_CONFIGS[configuration.semgrepProfile],
      }),
    });

    if (!response.ok) {
      let details = `HTTP ${response.status}`;
      try {
        const body = (await response.json()) as { detail?: string };
        details = body.detail ?? details;
      } catch {
        // сервер может вернуть ответ без json
      }
      throw new Error(`Security Gate отклонил заявку: ${details}`);
    }

    return (await response.json()) as ScanReceipt;
  },
  subscribe(scanId, onEvent) {
    const eventSource = new EventSource(
      `${SECURITY_GATE_URL}/api/security-gate/scans/${encodeURIComponent(scanId)}/events`,
    );
    let connectionWarningShown = false;
    eventSource.onopen = () => {
      connectionWarningShown = false;
    };
    eventSource.onmessage = (message) => {
      try {
        onEvent(JSON.parse(message.data) as ScanEvent);
      } catch {
        onEvent({
          type: "error",
          message: "Security Gate вернул некорректное событие.",
        });
      }
    };
    eventSource.onerror = () => {
      if (connectionWarningShown) return;
      connectionWarningShown = true;
      onEvent({
        type: "progress",
        stage: "Связь с Security Gate",
        details: "Поток событий прерван, выполняется переподключение",
        progress: 0,
      });
    };

    return () => eventSource.close();
  },
};
