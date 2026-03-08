import { useAuth0 } from "@auth0/auth0-react";

export const LogoutButton = () => {
  const { logout } = useAuth0();

  return (
    <button
      onClick={() => logout({ logoutParams: { returnTo: window.location.origin } })}
      className="px-5 py-2 border border-primary/50 text-foreground font-mono text-sm font-semibold rounded-md hover:bg-primary/10 transition-all"
    >
      Log Out
    </button>
  );
};
