import { LoginPage } from "@/src/console/LoginPage";

// The sign-in (WP-11): the password, then the TOTP code (with the
// enrolment QR at a first sign-in), through the BFF's /_bff/login.
export default function Login() {
  return <LoginPage />;
}
