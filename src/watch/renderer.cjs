'use strict';
function rendererObserver(marker, OBSERVER_KEY, removable = false) {
  return `(() => { try {
      var KEY = ${JSON.stringify(OBSERVER_KEY)};
      if (window[KEY]) return 'exists';
      var events = [], seen = {}, cleanup = [];
      var push = function (e) { var k = e.type + '|' + (e.detail || '') + '|' + (e.live === undefined ? '' : e.live); if (seen[k]) return; seen[k] = 1; events.push(e); };
      var MARKER = ${JSON.stringify(marker || null)};
      var inspect = function (node) {
        if (!node || node.nodeType !== 1) return;
        if (node.tagName === 'SCRIPT' && (node.src || (node.textContent || '').trim())) push({ type: 'script', detail: node.src ? 'src' : 'inline' });
        var attrs = node.attributes || [];
        for (var i = 0; i < attrs.length; i++) {
          var a = attrs[i];
          // an event handler attribute: onclick, onerror... (not onboarding="true"): the element has a matching property
          if (/^on[a-z]+$/i.test(a.name) && (a.name.toLowerCase() in node)) push({ type: 'event-handler', detail: a.name });
          if (/^\\s*javascript:/i.test(a.value || '')) push({ type: 'javascript-url', detail: a.name });
        }
      };
      var scan = function (node) { inspect(node); if (node.querySelectorAll) { var all = node.querySelectorAll('*'); for (var i = 0; i < all.length; i++) inspect(all[i]); } };
      var mo = new MutationObserver(function (muts) {
        for (var i = 0; i < muts.length; i++) {
          var m = muts[i];
          if (m.type === 'attributes') inspect(m.target);
          var added = m.addedNodes || [];
          for (var j = 0; j < added.length; j++) scan(added[j]);
        }
      });
      var checkMarker = function () {
        if (!MARKER) return;
        try {
          var live = false, present = false;
          var els = document.getElementsByTagName('*');
          for (var i = 0; i < els.length; i++) {
            var el = els[i];
            if (el.tagName === 'SCRIPT' || el.tagName === 'STYLE') continue; // their text is source, not rendered markup
            var attrs = el.attributes || [];
            for (var j = 0; j < attrs.length; j++) {
              var name = attrs[j].name.toLowerCase(), value = attrs[j].value || '';
              // the marker shaped the markup: it became an attribute name, or landed in an event handler. Text in an
              // ordinary attribute value (an input's value, a title) is how safely displayed content looks.
              if (name.indexOf(MARKER.toLowerCase()) !== -1) { live = true; present = true; }
              else if (value.indexOf(MARKER) !== -1) { present = true; if (/^on/.test(name)) live = true; }
            }
            if (el.tagName && el.tagName.indexOf(MARKER.toUpperCase()) !== -1) { live = true; present = true; } // marker as a tag name
          }
          var shown = (document.body && (document.body.innerText || document.body.textContent)) || '';
          if (shown.indexOf(MARKER) !== -1) present = true; // marker visible as text (escaped, or alongside a live copy)
          if (present) push({ type: 'marker', detail: MARKER, live: live });
        } catch (e) {}
      };
      // HTML sinks: when a value carrying the marker is written as HTML, record the sink and the script location that
      // did it, so the static finding at that line can be confirmed. Only values holding the marker are looked at.
      var frames = function () {
        var list = [];
        String(new Error().stack || '').split('\\n').forEach(function (line) {
          var m = line.match(/([a-z][\\w+.-]*:\\/\\/[^\\s()]+):(\\d+):(\\d+)/i);
          if (m && list.length < 6) list.push({ url: m[1], line: Number(m[2]), column: Number(m[3]) });
        });
        return list;
      };
      var sinkSeen = {};
      var sink = function (name, value) {
        try {
          if (!MARKER || typeof value !== 'string' || value.indexOf(MARKER) === -1) return;
          var f = frames();
          var live = new RegExp('<[a-z][^>]*' + MARKER, 'i').test(value);
          var key = name + '|' + live + '|' + (f[0] ? f[0].url + ':' + f[0].line + ':' + f[0].column : '');
          if (sinkSeen[key]) return;
          sinkSeen[key] = 1;
          events.push({ type: 'sink', detail: name, live: live, frames: f });
        } catch (e) {}
      };
      if (MARKER) {
        try {
          ['innerHTML', 'outerHTML'].forEach(function (prop) {
            var d = Object.getOwnPropertyDescriptor(Element.prototype, prop);
            if (!d || !d.set || !d.configurable) return;
            var setter = function (v) { sink(prop, v); return d.set.call(this, v); };
            Object.defineProperty(Element.prototype, prop, { configurable: true, enumerable: d.enumerable, get: d.get, set: setter });
            cleanup.push(function () { var current = Object.getOwnPropertyDescriptor(Element.prototype, prop); if (current && current.set === setter) Object.defineProperty(Element.prototype, prop, d); });
          });
          var wrap = function (proto, name, argIndex) {
            var original = proto && proto[name];
            if (typeof original !== 'function') return;
            var wrapper = function () { sink(name, arguments[argIndex]); return original.apply(this, arguments); };
            proto[name] = wrapper;
            cleanup.push(function () { if (proto[name] === wrapper) proto[name] = original; });
          };
          wrap(Element.prototype, 'insertAdjacentHTML', 1);
          wrap(Document.prototype, 'write', 0);
          wrap(Document.prototype, 'writeln', 0);
          wrap(window.Range && Range.prototype, 'createContextualFragment', 0);
        } catch (e) {}
      }
      // a per-session name, hidden from enumeration and read-only, so pages don't trip over it or replace it
      Object.defineProperty(window, KEY, { value: Object.freeze({ drain: function () { checkMarker(); return events.splice(0); }, cleanup: function () { mo.disconnect(); for (var i = cleanup.length - 1; i >= 0; i--) { try { cleanup[i](); } catch (e) {} } delete window[KEY]; } }), enumerable: false, writable: false, configurable: ${removable} });
      // entry points the user exercised (for coverage): paste, drag and drop, file pickers. Only the kind is kept.
      var types = function (list) { try { return Array.prototype.slice.call(list || []); } catch (e) { return []; } };
      var listen = function (target, name, fn, capture) { target.addEventListener(name, fn, capture); cleanup.push(function () { target.removeEventListener(name, fn, capture); }); };
      listen(window, 'paste', function (e) { var t = types(e.clipboardData && e.clipboardData.types); push({ type: 'entry', detail: t.indexOf('text/html') !== -1 ? 'paste-html' : t.indexOf('Files') !== -1 ? 'paste-file' : 'paste-text' }); }, true);
      listen(window, 'drop', function (e) { var t = types(e.dataTransfer && e.dataTransfer.types); push({ type: 'entry', detail: t.indexOf('Files') !== -1 ? 'drop-file' : t.indexOf('text/html') !== -1 ? 'drop-html' : 'drop-text' }); }, true);
      listen(document, 'change', function (e) { if (e.target && e.target.type === 'file') push({ type: 'entry', detail: 'file-picker' }); }, true);
      var start = function () { try { mo.observe(document.documentElement, { childList: true, subtree: true, attributes: true }); } catch (e) {} scan(document.documentElement); checkMarker(); };
      if (document.documentElement) start(); else listen(document, 'DOMContentLoaded', start);
      return 'installed';
    } catch (e) { return 'error:' + (e && e.message); } })()`;
}

module.exports = { rendererObserver };
