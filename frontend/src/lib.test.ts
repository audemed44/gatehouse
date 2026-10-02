import { describe, expect, it } from "vitest";
import { ago, certTone, formatHeaders, parseHeaders, splitList, statusTone } from "./lib";
import { parseRoute } from "./router";

describe("lib", () => {
  it("splits lists typed any way", () => {
    expect(splitList("a.example.com, b.example.com\nc.example.com  d")).toEqual([
      "a.example.com",
      "b.example.com",
      "c.example.com",
      "d",
    ]);
  });
  it("round-trips headers", () => {
    const h = parseHeaders("X-Frame-Options: SAMEORIGIN\nbad line\nX-A: b: c");
    expect(h).toEqual({ "X-Frame-Options": "SAMEORIGIN", "X-A": "b: c" });
    expect(formatHeaders(h)).toBe("X-Frame-Options: SAMEORIGIN\nX-A: b: c");
  });
  it("tones", () => {
    expect(certTone(3)).toBe("bad");
    expect(certTone(10)).toBe("warn");
    expect(certTone(60)).toBe("good");
    expect(statusTone(502)).toBe("bad");
    expect(statusTone(404)).toBe("warn");
    expect(statusTone(200)).toBe("good");
  });
  it("treats Go's zero time as unset", () => {
    expect(ago("0001-01-01T00:00:00Z")).toBe("");
  });
  it("parses routes", () => {
    expect(parseRoute("/logs", "?host=a.example.com")).toEqual({
      page: "logs",
      host: "a.example.com",
    });
    expect(parseRoute("/nope")).toEqual({ page: "hosts" });
  });
});
