session.defaultSession.setCertificateVerifyProc((request, callback) => {
  callback(PINNED.includes(request.certificate.fingerprint) ? 0 : -2);
});
