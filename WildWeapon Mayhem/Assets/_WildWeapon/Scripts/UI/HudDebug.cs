using UnityEngine;

namespace WildWeapon
{
    /// <summary>
    /// HUD temporal de F0 con OnGUI (se reemplaza por UI Toolkit en F1).
    /// Muestra: ronda, reloj, Overdrive, scores, HP y arma activa por jugador.
    /// </summary>
    public class HudDebug : MonoBehaviour
    {
        private GUIStyle _stCenter;
        private GUIStyle _stLeft;
        private GUIStyle _stBig;
        private GUIStyle _stHint;
        private bool _init;

        private void Init()
        {
            if (_init) return;
            _stCenter = new GUIStyle(GUI.skin.label) { alignment = TextAnchor.MiddleCenter, fontSize = 18, fontStyle = FontStyle.Bold };
            _stLeft = new GUIStyle(GUI.skin.label) { alignment = TextAnchor.MiddleLeft, fontSize = 15 };
            _stBig = new GUIStyle(GUI.skin.label) { alignment = TextAnchor.MiddleCenter, fontSize = 40, fontStyle = FontStyle.Bold };
            _stHint = new GUIStyle(GUI.skin.label) { alignment = TextAnchor.MiddleCenter, fontSize = 13 };
            _init = true;
        }

        private void OnGUI()
        {
            var mgr = DuelManager.Instance;
            if (mgr == null) return;
            Init();

            int w = Screen.width;
            string clockText = $"{Mathf.FloorToInt(mgr.RoundTime / 60f):00}:{Mathf.FloorToInt(mgr.RoundTime % 60f):00}";

            // ---- Barra superior ----
            var top = new Rect(w * 0.5f - 170f, 10f, 340f, 34f);
            DrawRect(top, new Color(0f, 0f, 0f, 0.55f));
            _stCenter.normal.textColor = mgr.Overdrive ? new Color(1f, 0.4f, 0.35f) : Color.white;
            GUI.Label(top, $"RONDA {mgr.RoundNumber}     {clockText}", _stCenter);

            if (mgr.Overdrive && Mathf.PingPong(Time.unscaledTime * 2.5f, 1f) > 0.3f)
            {
                var od = new Rect(w * 0.5f - 220f, 48f, 440f, 30f);
                DrawRect(od, new Color(0.45f, 0f, 0f, 0.6f));
                var s = new GUIStyle(_stCenter) { fontSize = 20 };
                s.normal.textColor = new Color(1f, 0.55f, 0.45f);
                GUI.Label(od, "!OVERDRIVE!   DANO x1.5", s);
            }

            // ---- Paneles de jugador ----
            DrawPlayerPanel(mgr, 0, true);
            DrawPlayerPanel(mgr, 1, false);

            // ---- Estado central ----
            if (!string.IsNullOrEmpty(mgr.StatusText))
            {
                var mid = new Rect(w * 0.5f - 320f, Screen.height * 0.36f, 640f, 120f);
                DrawRect(mid, new Color(0f, 0f, 0f, 0.55f));
                _stBig.normal.textColor = Color.white;
                GUI.Label(mid, mgr.StatusText, _stBig);

                if (mgr.CurrentPhase == DuelManager.Phase.MatchEnd)
                {
                    var hint = new Rect(mid.x, mid.y + 78f, mid.width, 28f);
                    var hs = new GUIStyle(_stHint);
                    hs.normal.textColor = new Color(1f, 1f, 1f, 0.85f);
                    GUI.Label(hint, "R (teclado) o Start (mando) = revancha", hs);
                }
            }

            // ---- Pie ----
            var foot = new Rect(12f, Screen.height - 30f, Screen.width - 24f, 22f);
            _stHint.alignment = TextAnchor.MiddleLeft;
            _stHint.normal.textColor = new Color(1f, 1f, 1f, 0.45f);
            GUI.Label(foot, "F0 greybox - J1: WASD + mouse (click ataca, Shift/Space dash, X cambia arma) - J2: mando o flechas (',' ataca)", _stHint);
        }

        private void DrawPlayerPanel(DuelManager mgr, int index, bool leftSide)
        {
            var pc = mgr.Players != null && index < mgr.Players.Length ? mgr.Players[index] : null;
            const float panelW = 420f;
            var rect = new Rect(leftSide ? 16f : Screen.width - panelW - 16f, 16f, panelW, 104f);
            DrawRect(rect, new Color(0f, 0f, 0f, 0.5f));

            Color accent = leftSide ? new Color(0.55f, 0.75f, 1f) : new Color(1f, 0.6f, 0.55f);

            _stLeft.normal.textColor = accent;
            GUI.Label(new Rect(rect.x + 12f, rect.y + 6f, 220f, 24f), $"J{index + 1}", _stLeft);

            // marcas de ronda ganada (a 2)
            for (int i = 0; i < DuelRules.RoundsToWin; i++)
            {
                bool filled = mgr.Scores != null && index < mgr.Scores.Length && i < mgr.Scores[index];
                DrawRect(new Rect(rect.x + 58f + i * 22f, rect.y + 10f, 16f, 16f),
                         filled ? accent : new Color(1f, 1f, 1f, 0.15f));
            }

            // HP
            var hpBack = new Rect(rect.x + 12f, rect.y + 36f, panelW - 24f, 16f);
            DrawRect(hpBack, new Color(1f, 1f, 1f, 0.12f));
            if (pc != null && pc.Health != null)
            {
                var hpFill = new Rect(hpBack.x, hpBack.y, hpBack.width * pc.Health.Hp01, hpBack.height);
                DrawRect(hpFill, Color.Lerp(new Color(0.9f, 0.25f, 0.2f), new Color(0.35f, 0.85f, 0.4f), pc.Health.Hp01));
            }

            // armas (activa resaltada)
            string w1 = "-", w2 = "-";
            bool firstActive = true;
            if (pc != null && pc.Loadout != null && pc.Loadout.weapons != null)
            {
                var ws = pc.Loadout.weapons;
                if (ws.Length > 0 && ws[0] != null) w1 = ws[0].DisplayName;
                if (ws.Length > 1 && ws[1] != null) w2 = ws[1].DisplayName;
                firstActive = pc.Loadout.ActiveIndex == 0;
            }

            var wRow = new Rect(rect.x + 12f, rect.y + 62f, panelW - 24f, 30f);
            var wStyle = new GUIStyle(_stLeft) { fontSize = 14 };
            wStyle.normal.textColor = firstActive ? Color.white : new Color(1f, 1f, 1f, 0.45f);
            GUI.Label(new Rect(wRow.x, wRow.y, 200f, wRow.height), $"[1] {w1}", wStyle);
            wStyle.normal.textColor = firstActive ? new Color(1f, 1f, 1f, 0.45f) : Color.white;
            GUI.Label(new Rect(wRow.x + 200f, wRow.y, 200f, wRow.height), $"[2] {w2}", wStyle);
        }

        private static void DrawRect(Rect r, Color c)
        {
            Color prev = GUI.color;
            GUI.color = c;
            GUI.DrawTexture(r, Texture2D.whiteTexture);
            GUI.color = prev;
        }
    }
}
