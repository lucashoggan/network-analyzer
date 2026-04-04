import { useState, FormEvent } from "react";
import { generateSHA256 } from "./functions";
import "./App.css";

function App() {
  const [isModalOpen, setIsModalOpen] = useState(true);
  const [password, setPassword] = useState("");

  const handleOpenModal = () => setIsModalOpen(true);
  const handleCloseModal = () => {
    setIsModalOpen(false);
    setPassword("");
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const hash = await generateSHA256(password);
      const response = await fetch("http://127.0.0.1:8000/user/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(hash),
        credentials: "include",
      });

      if (response.ok) {
        console.log("Logged in successfully");
        handleCloseModal();
      } else {
        console.error("Login failed");
      }
    } catch (error) {
      console.error("Error during login:", error);
    }
  };

  return (
    <div className="app-container">
      {isModalOpen && (
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
                  onClick={handleCloseModal}
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
      )}
    </div>
  );
}

export default App;
