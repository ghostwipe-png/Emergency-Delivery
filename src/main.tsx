import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { AppProvider } from "./context/AppContext";
import "./index.css";

/**
 * Top-level ErrorBoundary.
 * Guarantees a visible, readable error screen (never a blank window)
 * if any component throws during render. Uses inline styles so it
 * works even if the CSS bundle fails to load.
 */
class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { error: Error | null }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("Emergency Delivery crashed:", error, info);
  }

  render() {
    if (this.state.error) {
      return (
        <div
          style={{
            minHeight: "100vh",
            background: "#0b141a",
            color: "#e9edef",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            justifyContent: "center",
            padding: "24px",
            fontFamily: "system-ui, sans-serif",
            textAlign: "center",
          }}
        >
          <div style={{ fontSize: "40px", marginBottom: "12px" }}>⚠️</div>
          <h1 style={{ fontSize: "20px", fontWeight: 700, marginBottom: "8px" }}>
            Something went wrong
          </h1>
          <pre
            style={{
              maxWidth: "640px",
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
              background: "#202c33",
              color: "#ff7b72",
              padding: "12px 16px",
              borderRadius: "12px",
              fontSize: "12px",
            }}
          >
            {String(this.state.error?.message ?? this.state.error)}
          </pre>
          <button
            onClick={() => window.location.reload()}
            style={{
              marginTop: "16px",
              background: "#00a884",
              color: "#ffffff",
              border: "none",
              borderRadius: "12px",
              padding: "10px 24px",
              fontWeight: 700,
              cursor: "pointer",
            }}
          >
            Reload App
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

const rootElement = document.getElementById("root");

if (!rootElement) {
  throw new Error('Root element "#root" not found in index.html');
}

ReactDOM.createRoot(rootElement).render(
  <React.StrictMode>
    <ErrorBoundary>
      <AppProvider>
        <App />
      </AppProvider>
    </ErrorBoundary>
  </React.StrictMode>,
);