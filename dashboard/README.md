# NetWatch Dashboard

React + Vite frontend for NetWatch network monitoring system.

## Overview

The dashboard provides a real-time web interface for:
- **Live Network Monitoring** - Real-time bandwidth, packet rates, and flow tracking
- **Interactive Visualizations** - Charts, maps, heatmaps, and network graphs
- **Security Alerts** - Real-time anomaly detection with detailed alert management
- **Analytics** - Historical trends, top hosts, top ports, and export capabilities
- **Configuration** - Runtime settings for thresholds, scanning, and monitoring behavior

## 🚀 Quick Start

### Prerequisites

- Node.js 18+
- npm or yarn
- NetWatch backend running (see main README)

### Installation & Development

```bash
cd dashboard
npm install
npm run dev
```

Open **http://localhost:5173** in your browser.

### Build for Production

```bash
npm run build
```

The optimized build will be in the `dist/` directory, ready to be served by Nginx.

## 📁 Project Structure

```
dashboard/
├── src/
│   ├── App.jsx           # Main application component (12 tabs)
│   ├── auth.jsx          # Authentication context and login screen
│   ├── i18n.jsx          # Internationalization system
│   ├── ConfigPanel.jsx   # Runtime configuration UI
│   ├── components/       # Reusable components
│   │   ├── Overview.jsx
│   │   ├── GeoMap.jsx
│   │   ├── NetworkGraph.jsx
│   │   ├── AlertPanel.jsx
│   │   └── ...
│   ├── styles/           # CSS modules
│   └── utils/            # Helper functions
├── public/               # Static assets
├── index.html
├── vite.config.js
└── package.json
```

## 🛠 Technology Stack

- **React 18** - UI library
- **Vite 5** - Build tool with HMR (hot module reload)
- **Recharts** - Chart library
- **Leaflet/Mapbox** - Geolocation mapping
- **SVG Canvas** - Network visualization
- **Axios** - HTTP client

## 🌍 Internationalization

The dashboard supports multiple languages via the i18n system.

### Switching Languages

Use the language selector in the dashboard UI or the `changeLang()` function:

```javascript
const { t, lang, changeLang } = useI18n()
changeLang('it')  // Switch to Italian
```

### Adding a New Language

Edit `dashboard/src/i18n.jsx` and add your translation block:

```javascript
const translations = {
  it: { /* Italian */ },
  en: { /* English */ },
  de: { /* German */ },  // ← Add here
}
```

Then add the option to the language selector component.

## 🔌 API Integration

The dashboard communicates with the NetWatch backend via:

- **REST API** - For one-time data fetches (config, history, exports)
- **Server-Sent Events (SSE)** - For real-time updates (bandwidth, alerts, flows)

Example:

```javascript
// REST API call
const snapshot = await axios.get('/api/snapshot', {
  headers: { Authorization: `Bearer ${token}` }
})

// SSE stream
const eventSource = new EventSource('/api/stream')
eventSource.onmessage = (event) => {
  const data = JSON.parse(event.data)
  updateDashboard(data)
}
```

## 🔐 Authentication

Authentication is handled by the `AuthProvider` context:

```javascript
import { useAuth } from './auth.jsx'

function MyComponent() {
  const { token, login, logout, isAuthenticated } = useAuth()
  // ...
}
```

Login credentials are checked against the backend JWT endpoint. Tokens are auto-refreshed before expiration.

## 🎨 Styling

The dashboard uses CSS modules for component scoping. Global styles are in `src/styles/global.css`.

### Theming

To customize colors, edit the CSS variables in `src/styles/global.css`:

```css
:root {
  --primary: #0066cc;
  --alert-high: #ff4444;
  --alert-medium: #ffaa00;
  --background: #0a0e27;
  /* ... */
}
```

## 🧪 Development Tips

### Hot Module Reload (HMR)

Changes to components are automatically reflected in the browser without full page reload.

### Debug Mode

Set `VITE_DEBUG=true` in `.env` for verbose logging:

```bash
echo "VITE_DEBUG=true" > .env.local
npm run dev
```

### Performance Profiling

Use React DevTools browser extension to profile component renders and identify bottlenecks.

## 📦 Build & Deploy

### Development

```bash
npm run dev
```

### Production Build

```bash
npm run build
```

Outputs to `dist/` — ready for Nginx or CDN deployment.

### Docker

The Dockerfile builds the dashboard and serves it via Nginx. See the main repository's `docker-compose.yml`.

## 🤝 Contributing

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Make changes and test: `npm run dev`
3. Build: `npm run build`
4. Commit and push: `git push origin feature/my-feature`
5. Open a Pull Request

## 📄 License

MIT License — see [LICENSE](../LICENSE) for details.
