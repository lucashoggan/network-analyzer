import { useState, useEffect } from "react";

interface LogListProps {
  logDataVersion: number;
}

export default function LogList({ logDataVersion }: LogListProps) {
  const [logs, setLogs] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
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
      <h2>Uploaded Logs</h2>
      {logs.length === 0 ? (
        <p>No logs found.</p>
      ) : (
        <ul>
          {logs.map((filename) => (
            <li key={filename}>{filename}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
