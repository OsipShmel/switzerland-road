export type CorrelationMode = "correlated" | "separate";
export type SemgrepProfile = "sql-injection" | "default" | "auto";

export interface ScanConfiguration {
  repositoryUrl: string;
  correlationMode: CorrelationMode;
  semgrepProfile: SemgrepProfile;
}

export type Severity = "critical" | "high" | "medium" | "low";

export interface VulnerabilitySummary {
  id: string;
  title: string;
  severity: Severity;
  source: "SAST" | "DAST" | "SAST + DAST";
  location: string;
  status: "confirmed" | "unconfirmed";
}

export type ScanEvent =
  | {
      type: "progress";
      stage: string;
      details: string;
      progress: number;
    }
  | {
      type: "finding";
      finding: VulnerabilitySummary;
    }
  | {
      type: "complete";
      summary: string;
    }
  | {
      type: "error";
      message: string;
    };
