(function () {
  function buildStats() {
    var bar = document.getElementById('stats-bar');
    if (!bar) return;
    var D = window.SPLUNK_DATA;
    var cmdCount = Object.keys(D.commands).length;
    var catCount = D.categories.length;
    var exCount = 0;
    Object.keys(D.commands).forEach(function (k) {
      var c = D.commands[k];
      if (c.syntax) exCount += c.syntax.length;
    });
    var tipCount = 0;
    Object.keys(D.commands).forEach(function (k) {
      var c = D.commands[k];
      if (c.tips) tipCount += c.tips.length;
    });
    var items = [
      { num: cmdCount,  label: 'Commands' },
      { num: catCount,  label: 'Categories' },
      { num: exCount,   label: 'Examples' },
      { num: tipCount,  label: 'Exam Tips' }
    ];
    bar.innerHTML = items.map(function (s) {
      return '<div class="stat-item"><span class="stat-num">' + s.num + '</span><span class="stat-label">' + s.label + '</span></div>';
    }).join('');
  }

  document.addEventListener('DOMContentLoaded', buildStats);
})();