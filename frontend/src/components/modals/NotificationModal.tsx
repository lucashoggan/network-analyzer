interface NotificationModalProps {
  message: string;
  type: "success" | "error";
  onClose: () => void;
}

export default function NotificationModal({ message, type, onClose }: NotificationModalProps) {
  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <h2 style={{ color: type === "success" ? "var(--accent)" : "#ff4d4f" }}>
          {type === "success" ? "Success" : "Error"}
        </h2>
        <p>{message}</p>
        <div className="modal-actions">
          <button type="button" onClick={onClose} className="btn-submit">
            OK
          </button>
        </div>
      </div>
    </div>
  );
}
