import test from "node:test";
import assert from "node:assert/strict";
import { parseRoute, deviceRoute, routeUrl } from "../../web/navigation.mjs";
test("each sidebar section has a reloadable route", () => {
  for (const page of [
    "overview",
    "requests",
    "devices",
    "settings",
    "activity",
  ]) {
    assert.deepEqual(parseRoute(`#/${page}`), {
      page,
      search: "",
      pageNumber: 1,
    });
  }
});
test("empty or unknown routes safely select overview", () => {
  for (const hash of [
    "",
    "#",
    "#/",
    "#/unknown",
    "#/constructor",
    "#/__proto__",
  ]) {
    assert.deepEqual(parseRoute(hash), {
      page: "overview",
      search: "",
      pageNumber: 1,
    });
  }
});
test("device searches round-trip safely", () => {
  for (const search of [
    "",
    "Alice’s laptop",
    "a+b & c",
    "#/?q=x",
    "<script>",
    "é / 日本語",
  ]) {
    assert.deepEqual(parseRoute(deviceRoute(search)), {
      page: "devices",
      search,
      pageNumber: 1,
    });
  }
  assert.equal(deviceRoute(""), "#/devices");
  assert.deepEqual(parseRoute("#/settings?q=ignored"), {
    page: "settings",
    search: "",
    pageNumber: 1,
  });
});

test("pagination survives route round trips and keeps device search", () => {
  for (const page of ["devices", "requests", "activity"]) {
    assert.deepEqual(parseRoute(routeUrl(page, "owner laptop", 3)), {
      page,
      search: page === "devices" ? "owner laptop" : "",
      pageNumber: 3,
    });
  }
  assert.equal(deviceRoute("new search"), "#/devices?q=new+search");
  for (const n of ["0", "-1", "NaN", "1.5", "999999999999999999999"]) {
    assert.equal(parseRoute(`#/activity?page=${n}`).pageNumber, 1);
  }
});
