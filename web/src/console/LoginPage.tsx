"use client";

// /<locale>/login: the two-step sign-in on the BFF's /_bff/login (the
// kit's contract, LoginResult). MFA is mandatory for every role (01 §4):
// the password goes once, the API answers a challenge that the BFF keeps
// sealed in its HttpOnly cookie, and the second request carries the
// username and the TOTP code. A first sign-in also carries the
// enrolment, which is shown here as a QR code of the API's otpauth URI
// and as the key itself (the kit's LoginForm shows the key only, so this
// page is its own form on the same route and the same bodies). The API's
// refusals are worded in the viewer's language by their slug; a 429
// counts its Retry-After down with the button disabled.
import { useEffect, useMemo, useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { BFF_LOGIN_PATH, type LoginResult } from "@rootxkit/uspace-ui/auth/client";
import { parseProblem, problemSlug, retryAfterSOf } from "@rootxkit/uspace-ui/api";
import { useLang, useT } from "@rootxkit/uspace-ui/i18n";
import { Button, Input, Label } from "@rootxkit/uspace-ui/ui";
import { encode } from "uqr";
import { qrPath, refusalKey } from "./login";

function QrCode({ text, label }: { text: string; label: string }) {
  const qr = useMemo(() => encode(text, { ecc: "M", border: 2 }), [text]);
  return (
    <svg
      role="img"
      aria-label={label}
      data-testid="enrolment-qr"
      viewBox={`0 0 ${qr.size} ${qr.size}`}
      width={qr.size * 5}
      height={qr.size * 5}
      shapeRendering="crispEdges"
    >
      <rect width={qr.size} height={qr.size} fill="#ffffff" />
      <path d={qrPath(qr.data)} fill="#000000" />
    </svg>
  );
}

interface Refusal {
  key: string;
  detail: string | null;
  retryAfterS: number | null;
}

async function refusalOf(res: Response): Promise<Refusal> {
  const problem = await parseProblem(res.clone());
  const slug = problem === null ? null : problemSlug(problem.type);
  return {
    key: refusalKey(slug, res.status),
    detail: problem?.detail ?? null,
    retryAfterS: retryAfterSOf(res.headers.get("Retry-After"), Date.now()),
  };
}

export function LoginPage() {
  const t = useT();
  const { lang } = useLang();
  const router = useRouter();
  const [step, setStep] = useState<"password" | "otp">("password");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [enrolment, setEnrolment] = useState<{ secret: string; otpauthUri: string } | null>(null);
  const [refusal, setRefusal] = useState<Refusal | null>(null);
  const [busy, setBusy] = useState(false);
  const [waitS, setWaitS] = useState(0);

  useEffect(() => {
    if (waitS <= 0) return;
    const id = setTimeout(() => setWaitS((s) => s - 1), 1000);
    return () => clearTimeout(id);
  }, [waitS]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setRefusal(null);
    try {
      const body = step === "password" ? { username, password } : { username, otp };
      const res = await fetch(BFF_LOGIN_PATH, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        credentials: "same-origin",
      });
      if (!res.ok) {
        const r = await refusalOf(res);
        setRefusal(r);
        if (r.retryAfterS !== null && r.retryAfterS > 0) setWaitS(Math.ceil(r.retryAfterS));
        if (step === "otp" && r.key === "ansp.login.problem.mfa_challenge_missing") {
          setStep("password");
          setOtp("");
          setEnrolment(null);
        }
        return;
      }
      const result = (await res.json()) as LoginResult;
      if (result.status === "mfa_required") {
        // The password crosses the network once: drop it from the page.
        setPassword("");
        setEnrolment(result.enrolment ?? null);
        setStep("otp");
        return;
      }
      router.replace(`/${lang}/restrictions`);
    } catch {
      setRefusal({ key: "ansp.login.problem.unavailable", detail: null, retryAfterS: null });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex flex-col gap-4 p-4">
      <p className="m-0 max-w-prose text-sm text-[var(--us-text-muted)]">{t("ansp.login.intro")}</p>
      <form onSubmit={(e) => void submit(e)} aria-labelledby="login-title" className="flex max-w-sm flex-col gap-3" data-testid="login-form">
        <h2 id="login-title" className="m-0 text-lg font-semibold">
          {t(step === "password" ? "ansp.login.title" : "ansp.login.title_otp")}
        </h2>
        {step === "password" ? (
          <>
            <div className="flex flex-col gap-1">
              <Label htmlFor="login-user">{t("ansp.login.username")}</Label>
              <Input id="login-user" name="username" autoComplete="username" required value={username} onChange={(e) => setUsername(e.target.value)} />
            </div>
            <div className="flex flex-col gap-1">
              <Label htmlFor="login-password">{t("ansp.login.password")}</Label>
              <Input
                id="login-password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
          </>
        ) : (
          <>
            {enrolment !== null && (
              <div className="flex flex-col gap-2 text-sm" data-testid="enrolment">
                <p className="m-0">{t("ansp.login.enrol")}</p>
                <QrCode text={enrolment.otpauthUri} label={t("ansp.login.enrol_qr")} />
                <p className="m-0">
                  {t("ansp.login.enrol_key")}: <code className="font-mono break-all">{enrolment.secret}</code>
                </p>
              </div>
            )}
            <div className="flex flex-col gap-1">
              <Label htmlFor="login-otp">{t("ansp.login.otp")}</Label>
              <Input
                id="login-otp"
                name="otp"
                autoComplete="one-time-code"
                inputMode="numeric"
                pattern="[0-9]{6}"
                required
                value={otp}
                onChange={(e) => setOtp(e.target.value)}
              />
            </div>
          </>
        )}
        {refusal !== null && (
          <div role="alert" data-testid="login-refusal" className="text-sm text-[var(--us-danger)]">
            <p className="m-0 font-semibold">{t(refusal.key)}</p>
            {refusal.detail !== null && refusal.detail !== "" && <p className="m-0">{refusal.detail}</p>}
          </div>
        )}
        {waitS > 0 && (
          <p role="status" className="m-0 text-sm">
            {t("ansp.login.wait", { seconds: waitS })}
          </p>
        )}
        <Button type="submit" disabled={busy || waitS > 0} data-testid="login-submit">
          {t(step === "password" ? "ansp.login.next" : "ansp.login.submit")}
        </Button>
      </form>
    </div>
  );
}
