import { withAuthenticationRequired } from "@auth0/auth0-react";
import React from "react";

interface AuthenticationGuardProps {
  component: React.ComponentType<object>;
}

export const AuthenticationGuard: React.FC<AuthenticationGuardProps> = ({
  component,
}) => {
  const Component = withAuthenticationRequired(component, {
    onRedirecting: () => (
      <div className="flex items-center justify-center min-h-screen bg-background">
        <div className="text-primary font-mono animate-pulse">Loading...</div>
      </div>
    ),
  });

  return <Component />;
};
