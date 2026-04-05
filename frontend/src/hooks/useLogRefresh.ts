import { useState, useCallback } from "react";

/**
 * A hook to manage the state and refresh trigger for log data.
 * It provides a version number that can be used as a dependency in useEffect
 * to trigger re-fetches when logs are modified, uploaded, or deleted.
 */
export function useLogData() {
  const [logDataVersion, setLogDataVersion] = useState(0);

  const notifyLogDataChanged = useCallback(() => {
    setLogDataVersion((prev) => prev + 1);
  }, []);

  return {
    logDataVersion,
    notifyLogDataChanged,
  };
}
