// URLs contain navigation and filters, never credentials or form drafts.
const pages = new Set([
  "overview",
  "requests",
  "devices",
  "settings",
  "activity",
]);
export function parseRoute(hash) {
  const [path, query = ""] = hash.replace(/^#\/?/, "").split("?", 2);
  const page = pages.has(path) ? path : "overview";
  const params = new URLSearchParams(query);
  const requested = Number(params.get("page") || 1);
  return {
    page,
    search: page === "devices" ? params.get("q") || "" : "",
    pageNumber:
      ["devices", "requests", "activity"].includes(page) &&
      Number.isSafeInteger(requested) &&
      requested > 0
        ? requested
        : 1,
  };
}
export function routeUrl(page, search = "", pageNumber = 1) {
  const params = new URLSearchParams();
  if (page === "devices" && search) params.set("q", search);
  if (pageNumber > 1) params.set("page", pageNumber);
  return `#/${page}${params.size ? `?${params}` : ""}`;
}
export function deviceRoute(search) {
  return routeUrl("devices", search);
}
