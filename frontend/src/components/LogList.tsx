import { useState, useEffect } from "react";
import type { LogEntry } from "./LogDetail";

interface LogListProps {
  logDataVersion: number;
  initialLogs?: { files: LogEntry[] };
  onLogSelect: (log: LogEntry) => void;
  onUploadClick: () => void;
}

function formatFilename(filename: string): string {
  const parts = filename.split("_");
  return parts.length > 2 ? parts.slice(2).join("_") : filename;
}

export default function LogList({ logDataVersion, initialLogs, onLogSelect, onUploadClick }: LogListProps) {
  const [logs, setLogs] = useState<LogEntry[]>(initialLogs?.files || []);
  const [loading, setLoading] = useState(!initialLogs);
  const [error, setError] = useState<string | null>(null);

  const fetchLogs = async () => {
    try {
      setLoading(true);
      const response = await fetch("/api/logs/list", {
        credentials: "include",
      });
      if (!response.ok) {
        throw new Error("Failed to fetch logs");
      }
      const data = await response.json();
      setLogs(data.files || []);
    } catch (err) {
      setError("Could not load logs");
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, [logDataVersion]);

  if (loading) return <div>Loading logs...</div>;
  if (error) return <div>{error}</div>;

  return (
    <div className="log-list-container">
      <div className="log-list-header">
        <h2>Uploaded Logs</h2>
        <button className="action-button" onClick={onUploadClick}>
          Upload Log
        </button>
      </div>
      {logs.length === 0 ? (
        <p>No logs found.</p>
      ) : (
        <ul>
          {logs.map((log) => (
            <li key={log.id} onClick={() => onLogSelect(log)} style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span>{formatFilename(log.filename)}</span>
              <span
                style={{
                  fontSize: "0.75rem",
                  fontWeight: 600,
                  color: log.processed ? "#22c55e" : "#f59e0b",
                }}
              >
                {log.processed ? "Processed" : "Processing"}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
