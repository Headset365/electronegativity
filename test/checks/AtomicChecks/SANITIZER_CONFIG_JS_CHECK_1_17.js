const clean = DOMPurify.sanitize(html, { ADD_ATTR: ['target', 'onclick'], ADD_TAGS: ['iframe'], ALLOWED_URI_REGEXP: /.*/ });
DOMPurify.addHook('uponSanitizeAttribute', (node, data) => { data.forceKeepAttr = true; });
DOMPurify.sanitize(html, { ADD_ATTR: ['target'], ALLOWED_URI_REGEXP: /^(?:https?|mailto):/i });
tinymce.init({ selector: '#ed', valid_elements: '*[*]', extended_valid_elements: 'a[href|target],script[src]', allow_script_urls: true });
tinymce.init({ selector: '#ok', valid_elements: 'p,b,i,a[href|target],ul,li' });
$scope.tinymceOptions = { verify_html: false, sandbox_iframes: false };
CKEDITOR.editorConfig = function (config) { config.allowedContent = true; config.extraAllowedContent = 'div(*)'; };
CKEDITOR.replace('ed', { extraAllowedContent: 'iframe[*]' });
new FroalaEditor('#f', { htmlRemoveTags: ['style'], htmlAllowedAttrs: ['.*'] });
angular.module('app', ['ngSanitize']).config(function ($sanitizeProvider, $compileProvider) {
  $sanitizeProvider.addValidAttrs(['style', 'onmouseover']);
  $sanitizeProvider.addValidElements({ htmlElements: ['iframe'] });
  $sanitizeProvider.enableSvg(true);
  $compileProvider.aHrefSanitizationTrustedUrlList(/^\s*(https?|javascript):/);
  $compileProvider.aHrefSanitizationTrustedUrlList(/^\s*(https?|mailto|app):/);
});
