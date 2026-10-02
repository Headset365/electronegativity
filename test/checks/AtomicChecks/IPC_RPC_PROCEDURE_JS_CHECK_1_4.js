// electron-trpc routers: every procedure is an IPC handler the renderer can call
var import_fs9 = require("fs");
var import_promises3 = require("fs/promises");
var import_electron17 = require("electron");
var t3 = initTRPC.create();
var osIntegrationRouter = t3.router({
  zoomFactor: t3.procedure.query(() => config.zoomFactor),
  setZoomFactor: t3.procedure.input(z.number()).mutation(({ input: factor }) => { config.zoomFactor = factor; }),
  saveFile: t3.procedure.input(z.object({ data: z.string(), filePath: z.string() })).query(({ input }) => {
    (0, import_fs9.writeFileSync)(input.filePath, input.data);
  }),
  deleteFile: t3.procedure.input(z.string()).query(async ({ input }) => {
    await (0, import_promises3.rm)(input);
  }),
  openPath: t3.procedure.input(z.object({ link: z.string() })).query(({ input }) => import_electron17.shell.openPath(input.link)),
  decryptString: t3.procedure.input(z.string()).query(({ input }) => import_electron17.safeStorage.decryptString(Buffer.from(input, "base64")))
});
