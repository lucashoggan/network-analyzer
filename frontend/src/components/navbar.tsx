export default function Navbar({
  authed,
  onLoginClick,
  onUploadClick,
}: {
  authed: boolean;
  onLoginClick: () => void;
  onUploadClick: () => void;
}) {
  return (
    <nav className="navbar">
      <h2>Network Analyzer</h2>
      <div className="navbar-actions">
        {!authed ? (
          <button className="action-button" onClick={onLoginClick}>
            Login
          </button>
        ) : (
          <button className="action-button" onClick={onUploadClick}>
            Upload Log
          </button>
        )}
      </div>
    </nav>
  );
}
