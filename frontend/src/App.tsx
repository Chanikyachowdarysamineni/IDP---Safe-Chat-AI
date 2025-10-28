import { Toaster } from "./components/ui/toaster";
import { Toaster as Sonner } from "./components/ui/sonner";
import { TooltipProvider } from "./components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createBrowserRouter, RouterProvider, Outlet } from "react-router-dom";
import { AuthProvider } from "./hooks/useAuth";
import Landing from "./pages/Landing";
import Chat from "./pages/Chat";
import Auth from "./pages/Auth";
import Dashboard from "./pages/Dashboard";
import ModeratorPanel from "./pages/ModeratorPanel";
import AdminPanel from "./pages/AdminPanel";
import Profile from "./pages/Profile";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const routes = [
  {
    element: <AuthProvider><Outlet /></AuthProvider>,
    children: [
      { path: '/', element: <Landing /> },
      { path: '/chat', element: <Chat /> },
      { path: '/chat/:conversationId', element: <Chat /> },
      { path: '/auth', element: <Auth /> },
      { path: '/dashboard', element: <Dashboard /> },
      { path: '/moderator', element: <ModeratorPanel /> },
      { path: '/admin', element: <AdminPanel /> },
      { path: '/profile', element: <Profile /> },
      { path: '*', element: <NotFound /> },
    ],
  },
];

const routerOptions = { future: { v7_startTransition: true } } as any;
const router = createBrowserRouter(routes, routerOptions);

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <RouterProvider router={router} />
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
