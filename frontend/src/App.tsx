import { useState } from "react";
import Navbar from "./components/navbar";
import type { FormEvent } from "react";
import { generateSHA256 } from "./functions";
import LogList from "./components/LogList";
import LoginModal from "./components/modals/LoginModal";
import UploadModal from "./components/modals/UploadModal";
import { useLogData } from "./hooks/useLogRefresh";
import "./App.css";

type ModalType = "login" | "upload" | null;

function App() {
  const [modalType, setModalType] = useState<ModalType>(null);
  const [password, setPassword] = useState("");
  const [authed, setAuthed] = useState(false);
  const { logDataVersion, notifyLogDataChanged } = useLogData();

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
          console.log("Logged in successfully");
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

  return (
    <main>
      <Navbar
        authed={authed}
        onLoginClick={() => setModalType("login")}
        onUploadClick={() => setModalType("upload")}
      />

      {authed && (
        <div className="app-container">
          <LogList logDataVersion={logDataVersion} />
        </div>
      )}

      {renderModal()}
    </main>
  );
}

export default App;
