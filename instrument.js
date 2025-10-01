// instrument.js  (puro ESM)
import * as Sentry from "@sentry/node";

Sentry.init({
  dsn: "https://72e47ddab7da7b355b65385a41e98031@o4510112830455808.ingest.de.sentry.io/4510112834912336",
  sendDefaultPii: true,
});

export default Sentry;