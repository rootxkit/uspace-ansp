"use client";

// /<locale>/users: the console accounts, an administrator's (GET and
// POST /v1/users, POST /v1/users/{id}/reset-mfa and /disable are x-auth
// session:admin in api/openapi.yaml; 01 §4). The list as the API answers
// it; a new account with a username, a role and an initial password the
// administrator sets, which the page shows once with a copy button after
// the API created the account and then forgets (it is never stored,
// logged or sent anywhere but the API). The account enrols its TOTP at
// its first sign-in, as every account does. Resetting an account's MFA
// and disabling it are each confirmed first; the API ends the account's
// sessions. Any other role sees no form, and the API's 403 is shown as
// the refusal it is.
import { useState } from "react";
import { ConfirmDialog } from "@rootxkit/uspace-ui/form";
import { useT } from "@rootxkit/uspace-ui/i18n";
import { Button, cn, Input, Label, StatusBadge, TABLE_NOWRAP } from "@rootxkit/uspace-ui/ui";
import { failureOf, type CallFailure } from "../api/client";
import { useConsole, useLoad } from "./context";
import { mayAdminister } from "./roles";
import { ConsolePageHeader, Empty, Loading, ProblemNotice, Section, Time } from "./ui";
import { emptyNewUser, NEW_USER_ROLES, newUserBody, userActs, withUser, type ApiUser, type NewUserForm, type NewUserProblem } from "./users";

/** The account the API just created and the password the administrator set, until it is dismissed. */
interface Created {
  user: ApiUser;
  password: string;
}

function OneTimePassword({ created, onDone }: { created: Created; onDone(): void }) {
  const t = useT();
  const [copied, setCopied] = useState<"copied" | "failed" | null>(null);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(created.password);
      setCopied("copied");
    } catch {
      setCopied("failed");
    }
  };
  return (
    <div className="flex flex-col gap-2 rounded-lg border border-status-warning-border bg-status-warning-soft p-4 text-sm" data-testid="user-created" data-user={created.user.id}>
      <p className="m-0 font-semibold">{t("ansp.users.created", { username: created.user.username, role: t(`ansp.role.${created.user.role}`) })}</p>
      <p className="m-0">{t("ansp.users.password_once")}</p>
      <div className="flex flex-wrap items-center gap-2">
        <code className="rounded border border-border bg-card px-2 py-1 font-mono" data-testid="user-created-password" aria-label={t("ansp.users.password_label")}>
          {created.password}
        </code>
        <Button type="button" size="sm" variant="outline" onClick={() => void copy()} data-testid="user-created-copy">
          {t("ansp.users.copy")}
        </Button>
        <Button type="button" size="sm" onClick={onDone} data-testid="user-created-done">
          {t("ansp.users.password_done")}
        </Button>
      </div>
      {copied !== null && (
        <p role="status" className="m-0 text-xs">
          {t(copied === "copied" ? "ansp.users.copied" : "ansp.users.copy_failed")}
        </p>
      )}
      <p className="m-0 text-xs">{t("ansp.users.enrol_first")}</p>
    </div>
  );
}

function CreateForm({ onCreated }: { onCreated(c: Created): void }) {
  const t = useT();
  const { client } = useConsole();
  const [form, setForm] = useState<NewUserForm>(emptyNewUser);
  const [problems, setProblems] = useState<NewUserProblem[]>([]);
  const [failure, setFailure] = useState<CallFailure | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: keyof NewUserForm, v: string) => setForm((f) => ({ ...f, [k]: v }));
  const submit = async () => {
    setFailure(null);
    const built = newUserBody(form);
    if ("problems" in built) {
      setProblems(built.problems);
      return;
    }
    setProblems([]);
    setBusy(true);
    try {
      const { data } = await client.POST("/v1/users", { body: built.body });
      if (data !== undefined) {
        onCreated({ user: data, password: built.body.password });
        setForm(emptyNewUser());
      }
    } catch (err: unknown) {
      setFailure(failureOf(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form
      className="flex flex-col gap-3"
      data-testid="user-create"
      noValidate
      onSubmit={(e) => {
        e.preventDefault();
        void submit();
      }}
    >
      <div className="grid gap-3 md:grid-cols-3">
        <div className="flex flex-col gap-0.5">
          <Label htmlFor="user-username">{t("ansp.users.username")}</Label>
          <Input
            id="user-username"
            autoComplete="off"
            spellCheck={false}
            value={form.username}
            onChange={(e) => set("username", e.target.value)}
            data-testid="user-username"
            aria-invalid={problems.includes("username")}
          />
          {problems.includes("username") && <p className="m-0 text-xs text-status-critical">{t("ansp.users.problem.username")}</p>}
        </div>
        <div className="flex flex-col gap-0.5">
          <Label htmlFor="user-role">{t("ansp.users.role_field")}</Label>
          <select
            id="user-role"
            value={form.role}
            onChange={(e) => set("role", e.target.value)}
            className="h-9 rounded-md border border-border bg-card px-2 text-sm"
            data-testid="user-role"
          >
            {NEW_USER_ROLES.map((r) => (
              <option key={r} value={r}>
                {t(`ansp.role.${r}`)}
              </option>
            ))}
          </select>
          {problems.includes("role") && <p className="m-0 text-xs text-status-critical">{t("ansp.users.problem.role")}</p>}
        </div>
        <div className="flex flex-col gap-0.5">
          <Label htmlFor="user-password">{t("ansp.users.password")}</Label>
          <Input
            id="user-password"
            type="password"
            autoComplete="new-password"
            value={form.password}
            onChange={(e) => set("password", e.target.value)}
            data-testid="user-password"
            aria-invalid={problems.includes("password")}
          />
          {problems.includes("password") && <p className="m-0 text-xs text-status-critical">{t("ansp.users.problem.password")}</p>}
        </div>
      </div>
      <p className="m-0 text-xs text-muted-foreground">{t("ansp.users.create_hint")}</p>
      <div>
        <Button type="submit" size="sm" disabled={busy} data-testid="user-create-submit">
          {t("ansp.users.create")}
        </Button>
      </div>
      {failure !== null && <ProblemNotice failure={failure} />}
    </form>
  );
}

/** Each act's catalogue keys and test id. */
const ACTS = {
  reset_mfa: {
    label: "ansp.users.reset_mfa.label",
    title: "ansp.users.reset_mfa.title",
    body: "ansp.users.reset_mfa.body",
    confirm: "ansp.users.reset_mfa.confirm",
    done: "ansp.users.reset_mfa.done",
    testId: "reset-mfa",
  },
  disable: {
    label: "ansp.users.disable.label",
    title: "ansp.users.disable.title",
    body: "ansp.users.disable.body",
    confirm: "ansp.users.disable.confirm",
    done: "ansp.users.disable.done",
    testId: "disable",
  },
} as const;

/** One confirmed act on an account: the button, the kit's ConfirmDialog, then the call. */
function AccountAct(props: {
  user: ApiUser;
  act: keyof typeof ACTS;
  run(): Promise<ApiUser | undefined>;
  onDone(u: ApiUser): void;
  onFailure(f: CallFailure): void;
}) {
  const t = useT();
  const keys = ACTS[props.act];
  const [busy, setBusy] = useState(false);
  const go = async () => {
    setBusy(true);
    try {
      const u = await props.run();
      if (u !== undefined) props.onDone(u);
    } catch (err: unknown) {
      props.onFailure(failureOf(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <ConfirmDialog
      titleKey={keys.title}
      bodyKey={keys.body}
      confirmLabelKey={keys.confirm}
      vars={{ username: props.user.username }}
      destructive={props.act === "disable"}
      onConfirm={() => void go()}
      trigger={
        <Button type="button" size="sm" variant="outline" disabled={busy} data-testid={`user-${keys.testId}-${props.user.username}`}>
          {t(keys.label)}
        </Button>
      }
    />
  );
}

export function UsersPage() {
  const t = useT();
  const { client, role } = useConsole();
  const loaded = useLoad(async (c) => (await c.GET("/v1/users")).data?.users ?? [], "users");
  const [changed, setChanged] = useState<ApiUser[]>([]);
  const [created, setCreated] = useState<Created | null>(null);
  const [rowFailure, setRowFailure] = useState<{ id: string; failure: CallFailure } | null>(null);
  const [done, setDone] = useState<{ username: string; key: string } | null>(null);
  const admin = mayAdminister(role);
  const users = loaded.data === null ? null : changed.reduce((list, u) => withUser(list, u), loaded.data);
  const answered = (key: string) => (u: ApiUser) => {
    setRowFailure(null);
    setChanged((c) => withUser(c, u));
    setDone({ username: u.username, key });
  };

  return (
    <div className="flex flex-col gap-6">
      <ConsolePageHeader titleKey="ansp.users.title" descriptionKey="ansp.users.description" />
      {!admin && <Empty textKey="ansp.users.role" testId="users-role" />}
      {admin && (
        <Section titleKey="ansp.users.create_title">
          {created !== null && <OneTimePassword created={created} onDone={() => setCreated(null)} />}
          <CreateForm
            onCreated={(c) => {
              setDone(null);
              setCreated(c);
              setChanged((list) => withUser(list, c.user));
            }}
          />
        </Section>
      )}
      <Section titleKey="ansp.users.list_title">
        {loaded.failure !== null && <ProblemNotice failure={loaded.failure} />}
        {users === null && loaded.failure === null && <Loading />}
        {done !== null && (
          <p role="status" className="m-0 text-sm" data-testid="user-act-done">
            {t(done.key, { username: done.username })}
          </p>
        )}
        {users !== null && users.length === 0 && <Empty textKey="ansp.users.none" testId="users-none" />}
        {users !== null && users.length > 0 && (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-sm" data-testid="users-table">
              <thead>
                <tr className="border-b border-border bg-panel-header text-muted-foreground">
                  <th className="px-3 py-2 text-start font-semibold">{t("ansp.users.col.username")}</th>
                  <th className="px-3 py-2 text-start font-semibold">{t("ansp.users.col.role")}</th>
                  <th className="px-3 py-2 text-start font-semibold">{t("ansp.users.col.status")}</th>
                  <th className="px-3 py-2 text-start font-semibold">{t("ansp.users.col.created")}</th>
                  <th className="px-3 py-2 text-start font-semibold">{t("ansp.users.col.last_login")}</th>
                  <th className="px-3 py-2 text-start font-semibold">{t("ansp.users.col.acts")}</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => {
                  const acts = userActs(u);
                  return (
                    <tr key={u.id} className="border-b border-border align-top" data-testid="user-row" data-user={u.username} data-status={u.status} data-role={u.role}>
                      <td className={cn("px-3 py-2 font-mono", TABLE_NOWRAP)}>{u.username}</td>
                      <td className="px-3 py-2">{t(`ansp.role.${u.role}`)}</td>
                      <td className="px-3 py-2">
                        <StatusBadge tone={u.status === "active" ? "ok" : "neutral"}>{t(`ansp.users.status.${u.status}`)}</StatusBadge>
                      </td>
                      <td className="px-3 py-2">
                        <Time iso={u.created_at} />
                      </td>
                      <td className="px-3 py-2">{u.last_login_at === null ? t("ansp.users.never") : <Time iso={u.last_login_at} />}</td>
                      <td className="px-3 py-2">
                        <div className="flex flex-wrap gap-2">
                          {admin && acts.resetMfa && (
                            <AccountAct
                              user={u}
                              act="reset_mfa"
                              run={async () => (await client.POST("/v1/users/{id}/reset-mfa", { params: { path: { id: u.id } } })).data}
                              onDone={answered(ACTS.reset_mfa.done)}
                              onFailure={(failure) => setRowFailure({ id: u.id, failure })}
                            />
                          )}
                          {admin && acts.disable && (
                            <AccountAct
                              user={u}
                              act="disable"
                              run={async () => (await client.POST("/v1/users/{id}/disable", { params: { path: { id: u.id } } })).data}
                              onDone={answered(ACTS.disable.done)}
                              onFailure={(failure) => setRowFailure({ id: u.id, failure })}
                            />
                          )}
                        </div>
                        {rowFailure?.id === u.id && <ProblemNotice failure={rowFailure.failure} />}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </div>
  );
}
