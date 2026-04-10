import { useState, useEffect } from "react";

export interface LogEntry {
  id: number;
  filename: string;
  processed: boolean;
  uploaded_at: string | null;
}

interface MapPoint {
  x: number;
  y: number;
  outlier_score: number;
  start_packet_number: number;
  end_packet_number: number;
}

function formatFilename(filename: string): string {
  const parts = filename.split("_");
  return parts.length > 2 ? parts.slice(2).join("_") : filename;
}

/** Interpolates green → amber → red based on a 0–1 outlier score. */
function outlierColor(score: number): string {
  const green  = [34,  197,  94];
  const amber  = [245, 158,  11];
  const red    = [239,  68,  68];
  const [from, to, t] = score < 0.5
    ? [green, amber, score * 2]
    : [amber, red,   (score - 0.5) * 2];
  return `rgb(${[0,1,2].map(i => Math.round(from[i] + (to[i] - from[i]) * t)).join(",")})`;
}

function outlierLabel(score: number): string {
  if (score < 0.33) return "Normal";
  if (score < 0.66) return "Unusual";
  return "Anomalous";
}

interface LogDetailProps {
  log: LogEntry;
  onBack: () => void;
}

export default function LogDetail({ log, onBack }: LogDetailProps) {
  const [mapPoints, setMapPoints] = useState<MapPoint[] | null>(null);
  const [mapLoading, setMapLoading] = useState(false);
  const [selectedPoint, setSelectedPoint] = useState<MapPoint | null>(null);
  const displayName = formatFilename(log.filename);
  const uploadedDate = log.uploaded_at
    ? new Date(log.uploaded_at).toLocaleString()
    : "Unknown";

  useEffect(() => {
    if (!log.processed) return;
    setMapLoading(true);
    fetch(`/api/logs/${log.id}/map`, { credentials: "include" })
      .then((r) => r.json())
      .then((d) => setMapPoints(d.points || []))
      .catch((err) => console.error("Failed to fetch map:", err))
      .finally(() => setMapLoading(false));
  }, [log.id, log.processed]);

  const handlePointClick = (point: MapPoint) => {
    setSelectedPoint((prev) => (prev === point ? null : point));
  };

  return (
    <div className="log-detail-container">
      <button className="log-detail-back" onClick={onBack}>
        ← Back to logs
      </button>
      <h2>{displayName}</h2>
      <div className="log-detail-fields">
        <div className="log-detail-field">
          <label>Uploaded</label>
          <span>{uploadedDate}</span>
        </div>
        <div className="log-detail-field">
          <label>Status</label>
          <span style={{ color: log.processed ? "#22c55e" : "#f59e0b", fontWeight: 600 }}>
            {log.processed ? "Processed" : "Processing"}
          </span>
        </div>
      </div>

      {log.processed && (
        <div className="log-map-container">
          <label style={{ display: "block", marginBottom: "0.5rem", fontSize: "0.75rem", color: "var(--text)" }}>
            Section Distance Map (t-SNE) — colour indicates outlier severity
          </label>
          {mapLoading ? (
            <div style={{ textAlign: "center", padding: "2rem", color: "var(--text)" }}>
              Loading map...
            </div>
          ) : mapPoints && mapPoints.length > 0 ? (
            <>
              <svg
                viewBox="0 0 400 400"
                style={{ width: "100%", border: "1px solid var(--border)", borderRadius: "4px", display: "block" }}
              >
                <rect width="400" height="400" fill="var(--code-bg)" />
                {mapPoints.map((point, idx) => {
                  const x = point.x * 380 + 10;
                  const y = point.y * 380 + 10;
                  const color = outlierColor(point.outlier_score);
                  const isSelected = selectedPoint === point;
                  return (
                    <circle
                      key={idx}
                      cx={x}
                      cy={y}
                      r={isSelected ? 7 : 5}
                      fill={color}
                      opacity={isSelected ? 1 : 0.8}
                      stroke={isSelected ? "var(--text-h)" : "none"}
                      strokeWidth={isSelected ? 1.5 : 0}
                      style={{ cursor: "pointer" }}
                      onClick={() => handlePointClick(point)}
                    >
                      <title>
                        {outlierLabel(point.outlier_score)} — Packets {point.start_packet_number} – {point.end_packet_number}
                      </title>
                    </circle>
                  );
                })}
              </svg>

              <div style={{ display: "flex", gap: "1rem", marginTop: "0.5rem", fontSize: "0.7rem", color: "var(--text)" }}>
                <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                  <span style={{ width: 10, height: 10, borderRadius: "50%", background: outlierColor(0), display: "inline-block" }} />
                  Normal
                </span>
                <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                  <span style={{ width: 10, height: 10, borderRadius: "50%", background: outlierColor(0.5), display: "inline-block" }} />
                  Unusual
                </span>
                <span style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                  <span style={{ width: 10, height: 10, borderRadius: "50%", background: outlierColor(1), display: "inline-block" }} />
                  Anomalous
                </span>
              </div>

              {selectedPoint && (
                <div className="section-info-panel">
                  <h3>Section</h3>
                  <div className="section-info-fields">
                    <div className="section-info-field">
                      <label>Start Packet</label>
                      <span>{selectedPoint.start_packet_number.toLocaleString()}</span>
                    </div>
                    <div className="section-info-field">
                      <label>End Packet</label>
                      <span>{selectedPoint.end_packet_number.toLocaleString()}</span>
                    </div>
                    <div className="section-info-field">
                      <label>Packet Count</label>
                      <span>{(selectedPoint.end_packet_number - selectedPoint.start_packet_number + 1).toLocaleString()}</span>
                    </div>
                    <div className="section-info-field">
                      <label>Outlier Score</label>
                      <span style={{ color: outlierColor(selectedPoint.outlier_score), fontWeight: 600 }}>
                        {outlierLabel(selectedPoint.outlier_score)} ({(selectedPoint.outlier_score * 100).toFixed(0)}%)
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </>
          ) : (
            <div style={{ color: "var(--text)", fontStyle: "italic" }}>No map data available yet</div>
          )}
        </div>
      )}
    </div>
  );
}
