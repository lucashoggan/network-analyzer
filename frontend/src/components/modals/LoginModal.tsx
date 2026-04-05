import type { FormEvent } from "react";

interface LoginModalProps {
  password: string;
  setPassword: (password: string) => void;
  handleSubmit: (e: FormEvent) => void;
  handleClose: () => void;
}

export default function LoginModal({
  password,
  setPassword,
  handleSubmit,
  handleClose,
}: LoginModalProps) {
  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <h2>Enter Password</h2>
        <form onSubmit={handleSubmit} className="modal-form">
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Password..."
            autoFocus
            className="modal-input"
          />
          <div className="modal-actions">
            <button
              type="button"
              onClick={handleClose}
              className="btn-cancel"
            >
              Cancel
            </button>
            <button type="submit" className="btn-submit">
              Submit
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
