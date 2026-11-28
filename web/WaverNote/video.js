/* ============================================================
   WaverNote · videos
   Toma el audio de un video local, lo convierte a MP3 de 320 kbps
   y extrae un fotograma para usarlo como miniatura.

   Todo pasa en el dispositivo: el video no se sube a ningún lado.
   ============================================================ */

const WNVideo = (() => {
  const VIDEO_EXTENSIONS = new Set([
    "mp4",
    "m4v",
    "mov",
    "webm",
    "ogv",
    "3gp",
    "3g2",
    "mkv",
    "avi",
    "wmv",
    "flv"
  ]);

  const MAX_VIDEO_SECONDS = 10 * 60;
  const MAX_VIDEO_BYTES = 150 * 1024 * 1024;
  const MP3_BITRATE = 320;
  const SAMPLE_RATE = 44100;
  const THUMB_SIZE = 1000;
  const ENCODE_BLOCK = 1152;
  const PROGRESS_INTERVAL = 250;

  const extensionOf = (name) => {
    const clean = String(name || "").split(/[\\/]/).pop();
    const dot = clean.lastIndexOf(".");
    return dot > 0 ? clean.slice(dot + 1).toLowerCase() : "";
  };

  const isVideoFile = (file) => {
    const name = typeof file === "string" ? file : file?.name || "";
    const type = typeof file === "string" ? "" : file?.type || "";
    return /^video\//i.test(type) || VIDEO_EXTENSIONS.has(extensionOf(name));
  };

  const safeBaseName = (name) => {
    const base = String(name || "")
      .split(/[\\/]/)
      .pop()
      .replace(/\.[^.]+$/, "")
      .replace(/[\\/:*?"<>|\u0000-\u001f]+/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 100);
    return base || "Video";
  };

  const mp3FileName = (name) => `${safeBaseName(name)}.mp3`;
  const coverFileName = (name) => `${safeBaseName(name)}-miniatura.jpg`;

  const waitForEvent = (target, event, timeout, errorEvent = "error") =>
    new Promise((resolve, reject) => {
      let settled = false;

      const cleanup = () => {
        window.clearTimeout(timer);
        target.removeEventListener(event, onReady);
        target.removeEventListener(errorEvent, onError);
      };

      const finish = (error) => {
        if (settled) return;
        settled = true;
        cleanup();
        if (error) reject(error);
        else resolve();
      };

      const onReady = () => finish();
      const onError = () =>
        finish(new Error("No pudimos abrir ese video. Probá con un MP4 o un WEBM."));
      const timer = window.setTimeout(
        () => finish(new Error("El video tardó demasiado en responder. Probá con un archivo más chico.")),
        timeout
      );

      target.addEventListener(event, onReady, { once: true });
      target.addEventListener(errorEvent, onError, { once: true });
    });

  const withVideo = async (file, callback) => {
    const url = URL.createObjectURL(file);
    const video = document.createElement("video");
    video.preload = "metadata";
    video.muted = true;
    video.playsInline = true;
    video.src = url;

    try {
      await waitForEvent(video, "loadedmetadata", 15000);
      return await callback(video);
    } finally {
      try {
        video.pause();
      } catch (err) {
        /* noop */
      }
      video.removeAttribute("src");
      try {
        video.load();
      } catch (err) {
        /* noop */
      }
      URL.revokeObjectURL(url);
    }
  };

  const seekTo = (video, time) =>
    new Promise((resolve, reject) => {
      const duration = Number.isFinite(video.duration) ? video.duration : 0;
      const target = Math.max(0, Math.min(time, Math.max(0, duration - 0.05)));

      if (Math.abs((video.currentTime || 0) - target) < 0.02) {
        resolve();
        return;
      }

      let settled = false;
      const cleanup = () => {
        window.clearTimeout(timer);
        video.removeEventListener("seeked", onSeeked);
        video.removeEventListener("error", onError);
      };

      const finish = (error) => {
        if (settled) return;
        settled = true;
        cleanup();
        if (error) reject(error);
        else resolve();
      };

      const onSeeked = () => finish();
      const onError = () => finish(new Error("No pudimos leer ese fotograma del video."));
      const timer = window.setTimeout(
        () => finish(new Error("El video tardó demasiado en responder.")),
        8000
      );

      video.addEventListener("seeked", onSeeked, { once: true });
      video.addEventListener("error", onError, { once: true });
      video.currentTime = target;
    });

  const frameBrightness = (video) => {
    const size = 48;
    const canvas = document.createElement("canvas");
    canvas.width = size;
    canvas.height = size;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) return 0;

    try {
      context.drawImage(video, 0, 0, size, size);
      const pixels = context.getImageData(0, 0, size, size).data;
      let total = 0;
      for (let i = 0; i < pixels.length; i += 4) {
        total += 0.299 * pixels[i] + 0.587 * pixels[i + 1] + 0.114 * pixels[i + 2];
      }
      return total / (size * size);
    } catch (err) {
      return 0;
    }
  };

  const frameToFile = (video, name) =>
    new Promise((resolve) => {
      const source = Math.min(video.videoWidth || 0, video.videoHeight || 0);
      if (!source) {
        resolve(null);
        return;
      }

      const size = Math.max(1, Math.min(THUMB_SIZE, source));
      const canvas = document.createElement("canvas");
      canvas.width = size;
      canvas.height = size;
      const context = canvas.getContext("2d");
      if (!context) {
        resolve(null);
        return;
      }

      context.fillStyle = "#0a101c";
      context.fillRect(0, 0, size, size);
      context.drawImage(
        video,
        ((video.videoWidth || 0) - source) / 2,
        ((video.videoHeight || 0) - source) / 2,
        source,
        source,
        0,
        0,
        size,
        size
      );

      try {
        canvas.toBlob(
          (blob) => {
            if (!blob || !blob.size) {
              resolve(null);
              return;
            }
            resolve(new File([blob], coverFileName(name), { type: "image/jpeg" }));
          },
          "image/jpeg",
          0.92
        );
      } catch (err) {
        resolve(null);
      }
    });

  const readInfo = (file) =>
    withVideo(file, (video) => ({
      duration: Number.isFinite(video.duration) ? Number(video.duration) : 0,
      width: Number(video.videoWidth) || 0,
      height: Number(video.videoHeight) || 0
    }));

  // La miniatura queda centrada y cuadrada, que es como se ve la portada
  // en toda la app. Se prueban tres momentos para evitar intros a negro.
  const extractThumbnail = async (file) => {
    try {
      return await withVideo(file, async (video) => {
        const duration = Number.isFinite(video.duration) ? Number(video.duration) : 0;
        const candidates = duration
          ? [
              Math.min(3, Math.max(0.4, duration * 0.1)),
              Math.max(0.4, duration * 0.35),
              Math.max(0.4, duration * 0.65)
            ]
          : [0];

        let bestTime = candidates[0];
        let bestBrightness = -1;

        for (const time of candidates) {
          try {
            await seekTo(video, time);
            const brightness = frameBrightness(video);
            if (brightness > bestBrightness) {
              bestBrightness = brightness;
              bestTime = time;
            }
            if (brightness >= 28) break;
          } catch (err) {
            /* probamos con el siguiente momento */
          }
        }

        try {
          if (Math.abs((video.currentTime || 0) - bestTime) > 0.02) {
            await seekTo(video, bestTime);
          }
        } catch (err) {
          /* usamos el fotograma que quedó cargado */
        }

        return frameToFile(video, file.name);
      });
    } catch (err) {
      return null;
    }
  };

  const decodeAudio = async (file) => {
    const Context = window.AudioContext || window.webkitAudioContext;
    if (!Context) throw new Error("Este dispositivo no puede convertir videos.");

    let context;
    try {
      context = new Context({ sampleRate: SAMPLE_RATE });
    } catch (err) {
      context = new Context();
    }

    try {
      const data = await file.arrayBuffer();
      return await new Promise((resolve, reject) => {
        let settled = false;
        const finish = (error, buffer) => {
          if (settled) return;
          settled = true;
          if (error) reject(error);
          else resolve(buffer);
        };

        try {
          const result = context.decodeAudioData(
            data,
            (buffer) => finish(null, buffer),
            () => finish(new Error("No pudimos leer el audio de ese video. Probá con un MP4 o un WEBM que tenga sonido."))
          );
          if (result && typeof result.then === "function") {
            result.then((buffer) => finish(null, buffer), () =>
              finish(new Error("No pudimos leer el audio de ese video. Probá con un MP4 o un WEBM que tenga sonido."))
            );
          }
        } catch (err) {
          finish(new Error("No pudimos leer el audio de ese video. Probá con un MP4 o un WEBM que tenga sonido."));
        }
      });
    } finally {
      try {
        await context.close();
      } catch (err) {
        /* el contexto ya se cerró */
      }
    }
  };

  const toInt16 = (source, offset, length, target) => {
    for (let i = 0; i < length; i += 1) {
      const sample = Math.max(-1, Math.min(1, source[offset + i]));
      target[i] = sample < 0 ? sample * 0x8000 : sample * 0x7fff;
    }
  };

  const encodeMp3 = async (buffer, onProgress) => {
    if (typeof lamejs === "undefined" || typeof lamejs.Mp3Encoder !== "function") {
      throw new Error("No se pudo cargar el codificador MP3. Cerrá y volvé a abrir la app.");
    }

    const channels = 2;
    const rate = Number(buffer.sampleRate) || SAMPLE_RATE;
    const bitrate = rate >= 32000 ? MP3_BITRATE : 160;
    const encoder = new lamejs.Mp3Encoder(channels, rate, bitrate);
    const left = buffer.getChannelData(0);
    const right = buffer.numberOfChannels > 1 ? buffer.getChannelData(1) : left;
    const leftBlock = new Int16Array(ENCODE_BLOCK);
    const rightBlock = new Int16Array(ENCODE_BLOCK);
    const chunks = [];
    let lastReport = 0;

    for (let offset = 0; offset < buffer.length; offset += ENCODE_BLOCK) {
      const length = Math.min(ENCODE_BLOCK, buffer.length - offset);
      toInt16(left, offset, length, leftBlock);
      toInt16(right, offset, length, rightBlock);

      const chunk = encoder.encodeBuffer(
        leftBlock.subarray(0, length),
        rightBlock.subarray(0, length)
      );
      if (chunk && chunk.length) {
        chunks.push(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
      }

      const now = performance.now();
      if (onProgress && now - lastReport >= PROGRESS_INTERVAL) {
        lastReport = now;
        onProgress(Math.min(1, offset / buffer.length));
        // Se le devuelve el control al navegador para que la barra avance.
        await new Promise((resolve) => window.setTimeout(resolve, 0));
      }
    }

    const tail = encoder.flush();
    if (tail && tail.length) {
      chunks.push(new Uint8Array(tail.buffer, tail.byteOffset, tail.byteLength));
    }
    if (onProgress) onProgress(1);

    return new Blob(chunks, { type: "audio/mpeg" });
  };

  const convertToMp3 = async (file, { onProgress } = {}) => {
    if (!isVideoFile(file)) throw new Error("Ese archivo no es un video.");
    if (file.size > MAX_VIDEO_BYTES) {
      throw new Error(
        `El video supera los ${Math.round(MAX_VIDEO_BYTES / (1024 * 1024))} MB. Probá con uno más liviano.`
      );
    }

    let info = null;
    try {
      info = await readInfo(file);
    } catch (err) {
      info = null;
    }

    // Sin duración no hay forma de respetar el límite ni de anticipar cuánta
    // memoria va a ocupar la decodificación. Mejor pedir otro archivo.
    if (!info || !(info.duration > 0)) {
      throw new Error("No pudimos leer ese video. Probá con un MP4, MOV o WEBM.");
    }

    if (info.duration > MAX_VIDEO_SECONDS + 0.5) {
      throw new Error(
        `El video dura más de ${MAX_VIDEO_SECONDS / 60} minutos. Para convertirlo en la app, probá con uno más corto.`
      );
    }

    const buffer = await decodeAudio(file);
    if (!buffer || !buffer.length) {
      throw new Error("Ese video no tiene audio para convertir.");
    }
    if (buffer.duration > MAX_VIDEO_SECONDS + 0.5) {
      throw new Error(
        `El video dura más de ${MAX_VIDEO_SECONDS / 60} minutos. Para convertirlo en la app, probá con uno más corto.`
      );
    }

    const blob = await encodeMp3(buffer, onProgress);
    if (!blob.size) throw new Error("La conversión quedó vacía. Probá con otro video.");

    return {
      file: new File([blob], mp3FileName(file.name), { type: "audio/mpeg" }),
      duration: Math.round(buffer.duration) || (info?.duration ? Math.round(info.duration) : 0),
      size: blob.size
    };
  };

  return {
    isVideoFile,
    readInfo,
    extractThumbnail,
    convertToMp3,
    MAX_VIDEO_SECONDS,
    MAX_VIDEO_BYTES
  };
})();
