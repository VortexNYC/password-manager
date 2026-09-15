// Chooser URL → tab. The action popup is its own Chrome window;
// currentWindow / lastFocusedWindow are not the checkout tab.
(function (root) {
  function usable(url) {
    return typeof url === "string" && (url.startsWith("https://") || url.startsWith("http://"));
  }
  function tabByURL(tabs, url) {
    if (!usable(url) || !tabs) {
      return null;
    }
    for (let i = 0; i < tabs.length; i++) {
      if (tabs[i] && tabs[i].url === url) {
        return tabs[i];
      }
    }
    return null;
  }
  root.veilTab = { usable: usable, tabByURL: tabByURL };
  if (typeof module !== "undefined" && module.exports) {
    module.exports = root.veilTab;
  }
})(typeof globalThis !== "undefined" ? globalThis : this);
