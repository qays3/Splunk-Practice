(function () {
  function buildStats() {
    var bar = document.getElementById('stats-bar');
    if (!bar) return;
    var D = window.ADMIN_DATA;
    if (!D) return;
    var topicCount = Object.keys(D.topics).length;
    var catCount = D.categories ? D.categories.length : 0;
    var stanzaCount = 0;
    Object.keys(D.topics).forEach(function (k) {
      var t = D.topics[k];
      if (t.stanzas) stanzaCount += t.stanzas.length;
    });
    var tipCount = 0;
    Object.keys(D.topics).forEach(function (k) {
      var t = D.topics[k];
      if (t.tips) tipCount += t.tips.length;
    });
    var items = [
      { num: topicCount,  label: 'Topics' },
      { num: catCount,    label: 'Categories' },
      { num: stanzaCount, label: 'Stanzas' },
      { num: tipCount,    label: 'Exam Tips' }
    ];
    bar.innerHTML = items.map(function (s) {
      return '<div class="stat-item"><span class="stat-num">' + s.num + '</span><span class="stat-label">' + s.label + '</span></div>';
    }).join('');
  }

  document.addEventListener('DOMContentLoaded', buildStats);
})();