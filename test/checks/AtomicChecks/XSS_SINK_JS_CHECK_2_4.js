function render(name, data, res) {
  document.execCommand('insertHTML', false, window.userInput);   // execCommand insertHTML
  $('<div>' + name + '</div>').appendTo(document.body);          // jQuery HTML string
  angular.element(`<span>${data}</span>`).appendTo('#host');     // angular.element HTML string
  document.getElementById('out').innerHTML = res.data;          // server-fed innerHTML

  // safe: selectors, ready handler, non-HTML command, constant
  $('#existing').show();
  $(function () { ready(); });
  document.execCommand('bold');
  angular.element(document).ready(init);
}
