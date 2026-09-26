function load(ckeditor, quill, froalaEditor, response) {
  const html = document.getElementById('draft').value;
  ckeditor.setData(html);                                  // CKEditor
  tinymce.activeEditor.setContent(response.data);          // TinyMCE, server-fed
  quill.clipboard.dangerouslyPasteHTML(window.userHtml);   // Quill
  froalaEditor.html.set(response.body);                    // Froala
  $('#note').summernote('code', window.noteContent);       // Summernote

  // safe: constant markup
  ckeditor.setData('<p>welcome</p>');
}
