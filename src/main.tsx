import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';

window.addEventListener('error', (e) => {
  document.body.innerHTML = `<pre style="color:red;padding:20px;white-space:pre-wrap">Unhandled error: ${e.message}\n${e.filename}:${e.lineno}:${e.colno}\n${e.error?.stack ?? ''}</pre>`;
});

window.addEventListener('unhandledrejection', (e) => {
  const reason = e.reason instanceof Error ? `${e.reason.message}\n${e.reason.stack}` : String(e.reason);
  document.body.innerHTML = `<pre style="color:red;padding:20px;white-space:pre-wrap">Unhandled promise rejection: ${reason}</pre>`;
});

const root = document.getElementById('root');
if (!root) {
  document.body.innerHTML = '<pre style="color:red;padding:20px">FATAL: #root element not found in index.html</pre>';
  throw new Error('Missing #root element in index.html');
}

ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
