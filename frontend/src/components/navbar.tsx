export default function Navbar({
  authed,
  onLoginClick,
}: {
  authed: boolean;
  onLoginClick: () => void;
}) {
  return (
    <nav className="navbar">
      <h2>Network Analyzer</h2>
      <div className="navbar-actions">
        {!authed && (
          <button className="action-button" onClick={onLoginClick}>
            Login
          </button>
        )}
      </div>
    </nav>
  );
}
