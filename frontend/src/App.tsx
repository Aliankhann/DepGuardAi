import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import Index from "./pages/Index";
import Dashboard from "./pages/Dashboard";
import RepoDetail from "./pages/RepoDetail";
import AlertDetail from "./pages/AlertDetail";
import NotFound from "./pages/NotFound";
import { Auth0ProviderWithNavigate } from "./components/auth/Auth0ProviderWithNavigate";
import { AuthenticationGuard } from "./components/auth/AuthenticationGuard";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Auth0ProviderWithNavigate>
          <Routes>
            <Route path="/" element={<Index />} />
            <Route path="/dashboard" element={<AuthenticationGuard component={Dashboard} />} />
            <Route path="/repos/:repoId" element={<AuthenticationGuard component={RepoDetail} />} />
            <Route path="/alerts/:alertId" element={<AuthenticationGuard component={AlertDetail} />} />
            {/* ADD ALL CUSTOM ROUTES ABOVE THE CATCH-ALL "*" ROUTE */}
            <Route path="*" element={<NotFound />} />
          </Routes>
        </Auth0ProviderWithNavigate>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
