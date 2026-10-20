# =============================================================================
# WILDWEAPON MAYHEM - Generador de SFX de UI
#
# Sintetiza los sonidos de interfaz como WAV 16-bit mono 44.1 kHz. No dependen
# de assets externos.
#
# Los dos sonidos se arman por capas, como un sonido de verdad y no como un
# beep:
#
#   CLICK  - transitorio de ruido pasabanda (el "golpe"), cuerpo modal con
#            parciales inarmonicos (suena a placa de metal), cuerpo grave con
#            barrido de tono (peso), un tic mecanico 17 ms despues (como el
#            relay de un boton fisico) y una cola de aire filtrado.
#   HOVER  - tick de ruido muy corto (el "edge"), dos parciales agudos con
#            caida corta y una pizca de aire. Mas claro y mas corto que el
#            click, para que se distingan de un vistazo.
#
# Correr:  powershell -File tools\Generate-UI-Audio.ps1
# Salida:  Assets\_WildWeapon\Resources\WW\Audio\UI\*.wav
#
# Regenerar es barato y deterministico (semilla fija), asi que si un sonido
# molesta se ajusta el codigo de abajo y se vuelve a correr.
# =============================================================================

param(
    [string]$OutDir = (Join-Path $PSScriptRoot '..\Assets\_WildWeapon\Resources\WW\Audio\UI')
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- sintetizador
$csharp = @'
using System;
using System.IO;
using System.Text;

public static class Sfx
{
    const int RATE = 44100;

    // ---------------------------------------------------------------- salida
    public static void Write(string path, float[] s)
    {
        using (var fs = new FileStream(path, FileMode.Create))
        using (var w = new BinaryWriter(fs))
        {
            int n = s.Length;
            w.Write(Encoding.ASCII.GetBytes("RIFF"));
            w.Write(36 + n * 2);
            w.Write(Encoding.ASCII.GetBytes("WAVE"));
            w.Write(Encoding.ASCII.GetBytes("fmt "));
            w.Write(16);
            w.Write((short)1);          // PCM
            w.Write((short)1);          // mono
            w.Write(RATE);
            w.Write(RATE * 2);
            w.Write((short)2);          // block align
            w.Write((short)16);         // bits
            w.Write(Encoding.ASCII.GetBytes("data"));
            w.Write(n * 2);
            for (int i = 0; i < n; i++)
            {
                float v = s[i];
                if (v > 1f) v = 1f;
                if (v < -1f) v = -1f;
                w.Write((short)(v * 32767));
            }
        }
    }

    // ---------------------------------------------------------------- filtro
    // Biquad de RBJ (estable en cualquier frecuencia) con forma directa I.
    public sealed class Biquad
    {
        double b0, b1, b2, a1, a2;
        double x1, x2, y1, y2;

        // Pasabanda de ganancia constante en el pico (Q define el "diente").
        public void Bandpass(double fc, double q)
        {
            double w0 = 2.0 * Math.PI * fc / RATE;
            double alpha = Math.Sin(w0) / (2.0 * q);
            double a0 = 1.0 + alpha;
            b0 = alpha / a0;
            b1 = 0.0;
            b2 = -alpha / a0;
            a1 = -2.0 * Math.Cos(w0) / a0;
            a2 = (1.0 - alpha) / a0;
        }

        // Pasabajo de 2 polos.
        public void Lowpass(double fc, double q)
        {
            double w0 = 2.0 * Math.PI * fc / RATE;
            double alpha = Math.Sin(w0) / (2.0 * q);
            double a0 = 1.0 + alpha;
            b0 = (1.0 - Math.Cos(w0)) / 2.0 / a0;
            b1 = (1.0 - Math.Cos(w0)) / a0;
            b2 = b0;
            a1 = -2.0 * Math.Cos(w0) / a0;
            a2 = (1.0 - alpha) / a0;
        }

        public double Process(double x)
        {
            double y = b0 * x + b1 * x1 + b2 * x2 - a1 * y1 - a2 * y2;
            x2 = x1; x1 = x;
            y2 = y1; y1 = y;
            return y;
        }
    }

    // ------------------------------------------------------------- utilidades
    // Satura suave -> normaliza al pico -> fades de entrada/salida. Asi los
    // picos no suenan crudos y el WAV no tiene discontinuidades (nada de
    // chasquidos al empezar o cortar el sample).
    static float[] Shape(float[] s, double peak)
    {
        int n = s.Length;

        // 1) saturacion suave (el "calor" de la distortion)
        const double drive = 1.25;
        double norm = Math.Tanh(drive);
        for (int i = 0; i < n; i++)
            s[i] = (float)(Math.Tanh(s[i] * drive) / norm);

        // 2) normalizacion al pico pedido
        double mx = 0.0;
        for (int i = 0; i < n; i++) mx = Math.Max(mx, Math.Abs(s[i]));
        if (mx > 0.0)
            for (int i = 0; i < n; i++) s[i] = (float)(s[i] / mx * peak);

        // 3) fade de entrada (0.4 ms) y de salida (4 ms)
        int fin = Math.Max(1, (int)(0.0004 * RATE));
        int fout = Math.Min(n / 2, (int)(0.004 * RATE));
        for (int i = 0; i < fin; i++) s[i] *= (float)i / fin;
        for (int i = 0; i < fout; i++) s[n - 1 - i] *= (float)i / fout;

        return s;
    }

    // --- click: "clack" de placa de metal con peso y detalle mecanico ------
    public static float[] Click()
    {
        int n = (int)(RATE * 0.17);
        var s = new float[n];
        var rnd = new Random(2024);          // semilla fija: salida reproducible

        var golpe = new Biquad();  golpe.Bandpass(3600, 1.1);   // transitorio
        var relay = new Biquad();  relay.Bandpass(2450, 3.0);   // tic mecanico
        var aire = new Biquad();   aire.Lowpass(1700, 0.7);     // cola de aire

        // Modos de una placa golpeada: razones NO enteras (1 : 1.52 : 2.23 ...)
        // para que suene a metal y no a flauta.
        double[] modoF = { 1180, 1793, 2637, 3521, 4980, 6640 };
        double[] modoA = { 0.55, 0.42, 0.30, 0.20, 0.12, 0.07 };
        double[] modoD = { 0.055, 0.042, 0.030, 0.022, 0.015, 0.010 }; // decaimiento (s)

        for (int i = 0; i < n; i++)
        {
            double t = (double)i / RATE;
            double w = rnd.NextDouble() * 2.0 - 1.0;
            double v = 0.0;

            // A) transitorio: el "crack" del golpe
            double tr = golpe.Process(w) * Math.Exp(-t / 0.0035);
            if (t < 0.0004) tr *= t / 0.0004;      // ataque de 0.4 ms
            v += tr * 0.90;

            // B) cuerpo modal: parciales metalicos con leve caida de tono
            for (int k = 0; k < modoF.Length; k++)
            {
                double f = modoF[k] * (1.0 + 0.035 * Math.Exp(-t / 0.012));
                v += modoA[k] * Math.Sin(2.0 * Math.PI * f * t) * Math.Exp(-t / modoD[k]);
            }

            // C) peso: cuerpo grave con barrido de tono (como un golpe real)
            double fg = 190.0 - 60.0 * Math.Min(1.0, t / 0.05);
            v += 0.50 * Math.Sin(2.0 * Math.PI * fg * t) * Math.Exp(-t / 0.040);

            // D) detalle mecanico: el relay del boton, 17 ms despues
            double td = t - 0.017;
            if (td > 0.0)
                v += 0.22 * relay.Process(w) * Math.Exp(-td / 0.0025);

            // E) aire: cola de ruido filtrado (le da lugar al sonido)
            v += 0.10 * aire.Process(w) * Math.Exp(-t / 0.030);

            s[i] = (float)v;
        }
        return Shape(s, 0.90);
    }

    // --- hover: "tick" claro, mas agudo y mas corto que el click -----------
    public static float[] Hover()
    {
        int n = (int)(RATE * 0.085);
        var s = new float[n];
        var rnd = new Random(77);

        var tick = new Biquad();  tick.Bandpass(5200, 2.2);
        var aire = new Biquad();  aire.Lowpass(3000, 0.7);

        for (int i = 0; i < n; i++)
        {
            double t = (double)i / RATE;
            double w = rnd.NextDouble() * 2.0 - 1.0;
            double v = 0.0;

            // A) edge: un tic de ruido muy corto
            v += 0.45 * tick.Process(w) * Math.Exp(-t / 0.0022);

            // B) dos parciales agudos con caida corta
            double f1 = 2350.0 * (1.0 + 0.04 * Math.Exp(-t / 0.006));
            double f2 = 3160.0 * (1.0 + 0.06 * Math.Exp(-t / 0.004));
            v += 0.60 * Math.Sin(2.0 * Math.PI * f1 * t) * Math.Exp(-t / 0.020);
            v += 0.30 * Math.Sin(2.0 * Math.PI * f2 * t) * Math.Exp(-t / 0.014);

            // C) pizca de aire
            v += 0.08 * aire.Process(w) * Math.Exp(-t / 0.012);

            s[i] = (float)v;
        }
        return Shape(s, 0.55);
    }

    // ---------------------------------------------------------------- metricas
    public static double Peak(float[] s)
    {
        double mx = 0.0;
        for (int i = 0; i < s.Length; i++) mx = Math.Max(mx, Math.Abs(s[i]));
        return mx;
    }

    public static double Rms(float[] s)
    {
        double acc = 0.0;
        for (int i = 0; i < s.Length; i++) acc += (double)s[i] * s[i];
        return Math.Sqrt(acc / s.Length);
    }
}
'@

Add-Type -TypeDefinition $csharp -Language CSharp

# ---------------------------------------------------------------- generacion
$dir = [System.IO.Path]::GetFullPath($OutDir)
New-Item -ItemType Directory -Force -Path $dir | Out-Null

$clips = @{
    'ww_sfx_click' = { [Sfx]::Click() }
    'ww_sfx_hover' = { [Sfx]::Hover() }
}

foreach ($name in ($clips.Keys | Sort-Object)) {
    $path = Join-Path $dir "$name.wav"
    $data = & $clips[$name]
    [Sfx]::Write($path, $data)
    $kb = (Get-Item $path).Length / 1KB
    $sec = $data.Length / 44100.0
    $peak = [Sfx]::Peak($data)
    $rms = [Sfx]::Rms($data)
    "{0,-16} {1,6:N0} KB  {2,5:N3}s  pico={3:N3}  rms={4:N4}" -f $name, $kb, $sec, $peak, $rms
}
