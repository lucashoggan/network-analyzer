import { useState, useEffect } from "react";
import Navbar from "./components/navbar";
import type { FormEvent } from "react";
import { generateSHA256 } from "./functions";
import LogList from "./components/LogList";
import LogDetail from "./components/LogDetail";
import type { LogEntry } from "./components/LogDetail";
import LoginModal from "./components/modals/LoginModal";
import UploadModal from "./components/modals/UploadModal";
import { useLogData } from "./hooks/useLogRefresh";
import "./App.css";

type ModalType = "login" | "upload" | null;

interface LogsResponse {
  files: LogEntry[];
}

function App() {
  const [modalType, setModalType] = useState<ModalType>(null);
  const [password, setPassword] = useState("");
  const [authed, setAuthed] = useState(false);
  const [authChecked, setAuthChecked] = useState(false);
  const [initialLogs, setInitialLogs] = useState<LogsResponse | null>(null);
  const [selectedLog, setSelectedLog] = useState<LogEntry | null>(null);
  const { logDataVersion, notifyLogDataChanged } = useLogData();

  useEffect(() => {
    fetch("/api/logs/list", { credentials: "include" })
      .then((res) => {
        if (res.ok) {
          return res.json().then((data) => {
            setInitialLogs(data);
            setAuthed(true);
          });
        } else {
          setModalType("login");
        }
      })
      .catch(() => setModalType("login"))
      .finally(() => setAuthChecked(true));
  }, []);

  const handleCloseModal = () => {
    setModalType(null);
    setPassword("");
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (modalType === "login") {
      try {
        const hash = await generateSHA256(password);
        const response = await fetch("/api/users/login", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(hash),
          credentials: "include",
        });

        if (response.ok) {
          setAuthed(true);
          handleCloseModal();
        } else {
          console.error("Login failed");
        }
      } catch (error) {
        console.error("Error during login:", error);
      }
    }
  };

  const renderModal = () => {
    switch (modalType) {
      case "login":
        return (
          <LoginModal
            password={password}
            setPassword={setPassword}
            handleSubmit={handleSubmit}
            handleClose={handleCloseModal}
          />
        );
      case "upload":
        return (
          <UploadModal
            handleClose={handleCloseModal}
            onUploadSuccess={notifyLogDataChanged}
          />
        );
      default:
        return null;
    }
  };

  if (!authChecked) return null;

  return (
    <main>
      <Navbar authed={authed} onLoginClick={() => setModalType("login")} />

      {authed && (
        <div className="app-container">
          {selectedLog ? (
            <LogDetail log={selectedLog} onBack={() => setSelectedLog(null)} />
          ) : (
            <LogList
              logDataVersion={logDataVersion}
              initialLogs={initialLogs ?? undefined}
              onLogSelect={setSelectedLog}
              onUploadClick={() => setModalType("upload")}
            />
          )}
        </div>
      )}

      {renderModal()}
    </main>
  );
}

export default App;
