// The users page's pure parts: the new account's body (sent when the form
// is complete, refused naming what is missing), the acts an account
// offers, and the list after an answer. Each refusal is paired with the
// case that passes (E-01).
import { describe, expect, it } from "vitest";
import { emptyNewUser, NEW_USER_ROLES, newUserBody, userActs, withUser, type ApiUser } from "./users";

function account(id: string, status: ApiUser["status"] = "active"): ApiUser {
  return { id, username: `u-${id}`, role: "viewer", status, created_at: "2026-10-01T08:00:00.000Z", last_login_at: null };
}

describe("new account body", () => {
  it("starts on a watch supervisor and offers the three console roles", () => {
    expect(emptyNewUser()).toEqual({ username: "", password: "", role: "watch_supervisor" });
    expect(NEW_USER_ROLES).toEqual(["watch_supervisor", "viewer", "admin"]);
  });

  it("sends the username trimmed, the password as typed and the role", () => {
    expect(newUserBody({ username: "  watch2 ", password: " a test password ", role: "watch_supervisor" })).toEqual({
      body: { username: "watch2", password: " a test password ", role: "watch_supervisor" },
    });
    for (const role of NEW_USER_ROLES) {
      expect(newUserBody({ username: "x", password: "y", role })).toEqual({ body: { username: "x", password: "y", role } });
    }
  });

  it("names every field that is missing or not a console role, and sends nothing", () => {
    expect(newUserBody({ username: "  ", password: "", role: "pilot" })).toEqual({ problems: ["username", "password", "role"] });
    expect(newUserBody({ username: "watch2", password: "", role: "viewer" })).toEqual({ problems: ["password"] });
    expect(newUserBody({ username: "watch2", password: "p", role: "" })).toEqual({ problems: ["role"] });
  });
});

describe("account acts", () => {
  it("offers reset-MFA and disable on an active account, neither on a disabled one", () => {
    expect(userActs(account("a"))).toEqual({ resetMfa: true, disable: true });
    expect(userActs(account("a", "disabled"))).toEqual({ resetMfa: false, disable: false });
  });

  it("puts the API's answer in place of the old row, or adds a new account", () => {
    const list = [account("a"), account("b")];
    expect(withUser(list, account("b", "disabled")).map((u) => [u.id, u.status])).toEqual([
      ["a", "active"],
      ["b", "disabled"],
    ]);
    expect(withUser(list, account("c")).map((u) => u.id)).toEqual(["a", "b", "c"]);
    expect(list.map((u) => u.status)).toEqual(["active", "active"]);
  });
});
