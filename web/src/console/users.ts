// The pure parts of the users page (GET and POST /v1/users, POST
// /v1/users/{id}/reset-mfa and /disable; every one x-auth session:admin):
// the new account's body and what the form lacks before it is sent. The
// console judges nothing the API judges (the username's shape, the
// password's length, a name already taken): it sends and shows the
// API's field errors. The initial password lives only in the form and in
// the one-time panel; nothing here keeps, logs or stores it.
import type { components } from "../api/types";
import { isRole, ROLES, type ConsoleRole } from "./roles";

export type ApiUser = components["schemas"]["User"];
export type ApiUserCreate = components["schemas"]["UserCreate"];

/** The roles a new account may be given, in the form's order. */
export const NEW_USER_ROLES: readonly ConsoleRole[] = ROLES;

/** The role the form starts on: the one the console is short of when it is first set up. */
export const DEFAULT_NEW_ROLE: ConsoleRole = "watch_supervisor";

export interface NewUserForm {
  username: string;
  password: string;
  role: string;
}

export type NewUserProblem = "username" | "password" | "role";

export function emptyNewUser(): NewUserForm {
  return { username: "", password: "", role: DEFAULT_NEW_ROLE };
}

/**
 * The body of POST /v1/users, or what is missing. The username is
 * trimmed; the password is sent exactly as typed (a space is part of it).
 */
export function newUserBody(form: NewUserForm): { body: ApiUserCreate } | { problems: NewUserProblem[] } {
  const problems: NewUserProblem[] = [];
  const username = form.username.trim();
  if (username === "") problems.push("username");
  if (form.password === "") problems.push("password");
  if (!isRole(form.role)) problems.push("role");
  if (problems.length > 0 || !isRole(form.role)) return { problems };
  return { body: { username, password: form.password, role: form.role } };
}

/** The acts an account offers: both on an active one, none on a disabled one (the API answers 409). */
export function userActs(u: Pick<ApiUser, "status">): { resetMfa: boolean; disable: boolean } {
  const active = u.status === "active";
  return { resetMfa: active, disable: active };
}

/** The list with an account the API just answered put in place of its old row, or added. */
export function withUser(list: readonly ApiUser[], u: ApiUser): ApiUser[] {
  const i = list.findIndex((x) => x.id === u.id);
  if (i === -1) return [...list, u];
  return list.map((x, j) => (j === i ? u : x));
}
