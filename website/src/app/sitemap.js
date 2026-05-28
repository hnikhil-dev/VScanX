export default function sitemap() {
  const baseUrl = "https://vscanx.vercel.app";

  const routes = [
    "",
    "/docs",
    "/docs/architecture",
    "/docs/canonical-findings",
    "/docs/cli",
    "/docs/core-concepts",
    "/docs/internals",
    "/docs/modules",
    "/docs/replay-diff",
    "/docs/verification-workflow",
    "/sandbox",
  ];

  return routes.map((route) => ({
    url: `${baseUrl}${route}`,
    lastModified: new Date().toISOString().split("T")[0],
    changeFrequency: route.startsWith("/docs") ? "weekly" : "daily",
    priority: route === "" ? 1.0 : route.startsWith("/docs") ? 0.8 : 0.5,
  }));
}
