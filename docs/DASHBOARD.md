# SOC Dashboard

The LogSentry SOC Dashboard (Sprint 6) provides a modern, responsive frontend application for security analysts to interact with the SIEM backend.

## Architecture
- **Framework**: React 18+ constructed via Vite for optimal build performance.
- **Language**: TypeScript for strong type safety matching backend Pydantic models.
- **Styling**: TailwindCSS configured with a custom dark theme (`bg-surface`, `bg-background`).
- **State Management**: TanStack React Query for efficient data fetching, caching, and background synchronization.
- **Routing**: React Router v6 mapping core pages (Dashboard, Alerts, Health, AI, Threat Intel).

## Component Hierarchy
- `App`: The root router component.
- `MainLayout`: Enforces the global layout grid (Sidebar on left, TopNav on top, Outlet for dynamic content).
- `Sidebar` & `TopNav`: Presentational navigation components using `lucide-react` for scalable SVG icons.
- `Pages` (e.g. `Dashboard`, `Alerts`, `SystemHealth`): Smart components that interact with TanStack query hooks to fetch and organize data.

## API Communication
The frontend is strictly decoupled from backend services. It relies purely on the REST endpoints provided by the FastAPI application. All HTTP traffic is channeled through centralized Axios instances in the `services/` directory:
- `api.ts`: Global Axios configuration setting standard headers and base URL.
- `alertService.ts`: Interacts with `/api/v1/alerts`.
- `healthService.ts`: Validates backend uptime via `/api/v1/health`.
- `aiService.ts` & `threatIntelService.ts`: Modular services corresponding to Sprints 4 & 5.

## State Management
We use `@tanstack/react-query` to abstract fetching logic away from components. This automatically handles:
- Loading states (rendering `isLoading` placeholders).
- Error boundaries (preventing white-screens on fetch failure).
- Caching (preventing redundant network calls when switching tabs).

## Future Roadmap
- Integration of `Chart.js` for "Alerts Over Time" visualizations.
- Detailed implementation of the Alert Details slide-over panel.
- Adding comprehensive end-to-end integration tests using Cypress or Playwright.
