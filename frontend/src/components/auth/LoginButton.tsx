import { useAuth0 } from "@auth0/auth0-react";

export const LoginButton = () => {
  const { loginWithRedirect } = useAuth0();

  return (
    <button
      onClick={() => loginWithRedirect()}
      className="px-5 py-2 bg-primary text-primary-foreground font-mono text-sm font-semibold rounded-md hover:shadow-[0_0_20px_hsl(142_72%_50%/0.25)] transition-all"
    >
      Log In
    </button>
  );
};
