// timers given functions are not code evaluation; only the string-built one is
function wait(resolve, ms) { setTimeout(resolve, ms); }
class Poller { start() { setInterval(this.tick.bind(this), 1000); window.setTimeout(this.handlers.flush, 0); } }
function later(name) { setTimeout("refresh('" + name + "')", 10); }
