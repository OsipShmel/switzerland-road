import type { ScanConfiguration, ScanEvent } from "../types";

export interface SecurityGateClient {
  startScan(configuration: ScanConfiguration): Promise<{ scanId: string }>;
  subscribe(
    scanId: string,
    onEvent: (event: ScanEvent) => void,
  ): () => void;
}

// контракт готов, реальное api будет подключено позже
export const securityGateClient: SecurityGateClient = {
  async startScan() {
    throw new Error("Security Gate API пока не подключен");
  },
  subscribe() {
    return () => undefined;
  },
};

export function streamDemoEvents(
  configuration: ScanConfiguration,
  onEvent: (event: ScanEvent) => void,
): () => void {
  const dastDetails =
    configuration.correlationMode === "correlated"
      ? "ZAP проверяет найденные endpoint, затем сверяется runtime-трасса"
      : "ZAP запускается отдельно, исходный отчет будет сохранен в logs/dast-report.json";

  const events: ScanEvent[] = [
    {
      type: "progress",
      stage: "Подготовка",
      details: "Репозиторий принят, параметры запуска проверены",
      progress: 8,
    },
    {
      type: "progress",
      stage: "SAST",
      details: "Semgrep анализирует исходный код",
      progress: 28,
    },
    {
      type: "progress",
      stage: "Endpoint locator",
      details: "Найденные строки сопоставляются с HTTP-маршрутами",
      progress: 46,
    },
    {
      type: "progress",
      stage: "Scoring",
      details: "Находки сортируются с учетом кода и топологии",
      progress: 62,
    },
    {
      type: "finding",
      finding: {
        id: "VLS-1024",
        title: "Возможная SQL-инъекция",
        severity: "high",
        source: "SAST",
        location: "routes/search.ts:23",
        status: "unconfirmed",
      },
    },
    {
      type: "progress",
      stage: "DAST",
      details: dastDetails,
      progress: 78,
    },
    {
      type: "finding",
      finding: {
        id: "VLS-1041",
        title: "Небезопасные атрибуты cookie",
        severity: "medium",
        source: "DAST",
        location: "/rest/user/login",
        status: "unconfirmed",
      },
    },
    {
      type: "progress",
      stage: "Сборка отчета",
      details: "VLS Registry готовится к передаче следующему компоненту",
      progress: 94,
    },
    {
      type: "complete",
      summary: "Демонстрационный анализ завершен",
    },
  ];

  const timers = events.map((event, index) =>
    window.setTimeout(() => onEvent(event), 450 * (index + 1)),
  );

  return () => timers.forEach((timer) => window.clearTimeout(timer));
}
