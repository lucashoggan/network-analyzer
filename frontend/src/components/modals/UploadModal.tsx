import { useState } from "react";
import NotificationModal from "./NotificationModal";

type ProcessingMethod = "batch" | "timeframe";

interface UploadModalProps {
  handleClose: () => void;
  onUploadSuccess: () => void;
}

export default function UploadModal({
  handleClose,
  onUploadSuccess,
}: UploadModalProps) {
  const [file, setFile] = useState<File | null>(null);
  const [processingMethod, setProcessingMethod] = useState<ProcessingMethod>("batch");
  const [processingValue, setProcessingValue] = useState<number>(5);
  const [notification, setNotification] = useState<{
    message: string;
    type: "success" | "error";
  } | null>(null);

  const handleMethodChange = (method: ProcessingMethod) => {
    setProcessingMethod(method);
    setProcessingValue(method === "batch" ? 5 : 600);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;

    const formData = new FormData();
    formData.append("file", file);
    formData.append("processing_method", processingMethod);
    formData.append("processing_value", String(processingValue));

    try {
      const response = await fetch("/api/logs/upload", {
        method: "POST",
        body: formData,
        credentials: "include",
      });

      if (response.ok) {
        setNotification({
          message: "File uploaded successfully",
          type: "success",
        });
        onUploadSuccess();
      } else {
        setNotification({
          message: "Upload failed",
          type: "error",
        });
      }
    } catch (error) {
      setNotification({
        message:
          "Error during upload: " +
          (error instanceof Error ? error.message : "Unknown error"),
        type: "error",
      });
    }
  };

  if (notification) {
    return (
      <NotificationModal
        message={notification.message}
        type={notification.type}
        onClose={handleClose}
      />
    );
  }

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <h2>Upload Log File</h2>
        <form onSubmit={handleSubmit} className="modal-form">
          <input
            type="file"
            className="modal-input"
            required
            onChange={(e) => setFile(e.target.files?.[0] || null)}
            style={{ border: "none", padding: "10px 0" }}
          />

          <div className="modal-field">
            <label>Processing Method</label>
            <div style={{ display: "flex", gap: "16px", marginTop: "6px" }}>
              {(["batch", "timeframe"] as ProcessingMethod[]).map((method) => (
                <label key={method} style={{ display: "flex", alignItems: "center", gap: "6px", cursor: "pointer" }}>
                  <input
                    type="radio"
                    name="processingMethod"
                    value={method}
                    checked={processingMethod === method}
                    onChange={() => handleMethodChange(method)}
                  />
                  {method === "batch" ? "Request Count" : "Timeframe"}
                </label>
              ))}
            </div>
          </div>

          <div className="modal-field">
            <label>
              {processingMethod === "batch" ? "Requests per batch" : "Timeframe (seconds)"}
            </label>
            <input
              type="number"
              className="modal-input"
              min={1}
              required
              value={processingValue}
              onChange={(e) => setProcessingValue(Number(e.target.value))}
            />
          </div>

          <div className="modal-actions">
            <button type="button" onClick={handleClose} className="btn-cancel">
              Cancel
            </button>
            <button type="submit" className="btn-submit">
              Upload
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
