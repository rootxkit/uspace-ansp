import { describe, expect, it } from "vitest";
import { encode } from "uqr";
import { qrPath, refusalKey } from "./login";

describe("refusalKey", () => {
  it("words a known slug by its own key", () => {
    expect(refusalKey("invalid_credentials", 401)).toBe("ansp.login.problem.invalid_credentials");
    expect(refusalKey("mfa_challenge_missing", 401)).toBe("ansp.login.problem.mfa_challenge_missing");
  });

  it("words an unknown slug by its status", () => {
    expect(refusalKey("something_new", 400)).toBe("ansp.login.problem.other");
    expect(refusalKey(null, 502)).toBe("ansp.login.problem.unavailable");
  });
});

describe("qrPath", () => {
  it("draws one unit square per dark module and none for a light one", () => {
    expect(
      qrPath([
        [true, false],
        [false, true],
      ]),
    ).toBe("M0 0h1v1h-1zM1 1h1v1h-1z");
    expect(qrPath([[false]])).toBe("");
  });

  it("draws an otpauth URI as many squares as the code has dark modules", () => {
    const qr = encode("otpauth://totp/ANSP:super1?secret=JBSWY3DPEHPK3PXP&issuer=ANSP", { ecc: "M", border: 2 });
    const squares = qrPath(qr.data).split("z").length - 1;
    const dark = qr.data.flat().filter(Boolean).length;
    expect(squares).toBe(dark);
    expect(dark).toBeGreaterThan(100);
  });
});
