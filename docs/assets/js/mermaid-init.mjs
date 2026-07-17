// Mermaid rendering for the shadcn theme.
//
// The shadcn theme has no built-in Mermaid support (it ships echarts and
// excalidraw instead), so the superfences `mermaid` custom fence lands in the
// page as `<pre class="mermaid">...graph source...</pre>`. This module turns
// those blocks into diagrams and keeps them in sync with the theme's
// light/dark toggle (which flips a `dark` class on <html>).
import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";

const isDark = () => document.documentElement.classList.contains("dark");

function blocks() {
  return document.querySelectorAll("pre.mermaid");
}

// Stash the raw graph source once so a theme switch can re-render from it.
function stashSources() {
  blocks().forEach((pre) => {
    if (pre.dataset.src === undefined) {
      pre.dataset.src = pre.textContent;
    }
  });
}

async function render() {
  stashSources();
  const nodes = blocks();
  nodes.forEach((pre) => {
    pre.removeAttribute("data-processed");
    pre.innerHTML = pre.dataset.src;
  });
  mermaid.initialize({
    startOnLoad: false,
    securityLevel: "strict",
    theme: isDark() ? "dark" : "default",
  });
  try {
    await mermaid.run({ nodes });
  } catch (err) {
    // Leave the source visible if a diagram fails to parse.
    console.error("mermaid render failed", err);
  }
}

render();

// Re-render only when the light/dark state actually changes.
let wasDark = isDark();
new MutationObserver(() => {
  const nowDark = isDark();
  if (nowDark !== wasDark) {
    wasDark = nowDark;
    render();
  }
}).observe(document.documentElement, { attributes: true, attributeFilter: ["class"] });
