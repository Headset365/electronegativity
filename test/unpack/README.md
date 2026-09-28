# Installer and package fixtures

Small but real packages for the unpacking tests (`test/test_unpack.js`). They hold the deliberately insecure fixture
app from Electron-Dynamic (fake executables: nothing here runs).

- `insecure-fixture-app-64.7z`, `insecure-fixture-setup.exe`: from Electron-Dynamic's `tests/fixtures/bin`. The 7z is
  what electron-builder ships (LZMA2, BCJ2 for the .exe), stored in a zlib, non-solid NSIS installer.
- `nsis-*.exe`: built with makensis 3.09 around that 7z: `SetCompressor /SOLID lzma`, `SetCompressor lzma` (the 7z
  compressed as a block), `SetCompressor bzip2` with `SetCompress off` for the 7z, a zlib installer carrying an
  `app-32.7z` (x86 executable) and an `app-64.7z`, and a web installer that only names its package URL. Each registers
  the `tinyapp://` protocol and the `.tiny` file type.
- `squirrel-setup.exe`: a PE whose RCDATA resource is the zip Squirrel's Setup.exe embeds (the `.nupkg` and
  `RELEASES`); `InsecureFixture-1.2.3-full.nupkg` and `app.zip` are the same app as a NuGet package and a zipped build.
- `7z/*.7z`: the files in `7z/expected` archived by 7-Zip 16.02 (`7zip-bin`) with each coder: `-mx=9` (LZMA2 + BCJ2),
  `-m0=LZMA -mhc=on` (LZMA, compressed header), `-m0=Deflate`, `-m0=Copy`, `-mf=BCJ`, `-mf=Delta:4`, and `-pSECRET`
  (AES, refused). `expected/app.exe` is the start of an x86-64 library, so the branch converters have work to do.
