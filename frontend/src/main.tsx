// Ensure our IndexedDB-backed async storage is initialized on startup so
// AuthProvider and other modules can access `window.storage` immediately.
import "./lib/windowStorage";

import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import "./index.css";

createRoot(document.getElementById("root")!).render(<App />);
