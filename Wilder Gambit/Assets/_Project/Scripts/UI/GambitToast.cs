using UnityEngine;
using UnityEngine.UIElements;
using WilderGambit.Core;

namespace WilderGambit.UI
{
    /// <summary>
    /// Aviso flotante de Gambits: escucha GambitEconomy.OnEarned y muestra «+60 Gambits ·
    /// Partidas vs IA» en la esquina inferior derecha. También lo usan las recompensas
    /// que no pasan por un modal (misiones, logros, puzzles) y el propio menú para sus
    /// mensajes (método Show).
    /// </summary>
    public class GambitToast : MonoBehaviour
    {
        private const float VisibleSeconds = 2.6f;

        private VisualElement _toast;
        private Label _text;
        private Label _sub;
        private IVisualElementScheduledItem _hideItem;

        public void Initialize(VisualElement root)
        {
            if (root == null) return;

            _toast = root.Q<VisualElement>("gambit-toast");
            _text  = root.Q<Label>("gambit-toast-text");
            _sub   = root.Q<Label>("gambit-toast-sub");

            // Sprite del contenedor (si está generado; si no, queda el estilo USS)
            ProgressSprites.Apply(_toast, "toast");

            GambitEconomy.OnEarned += OnEarned;
            Debug.Log("[GambitToast] Escuchando recompensas de Gambits.");
        }

        private void OnDestroy()
        {
            GambitEconomy.OnEarned -= OnEarned;
        }

        private void OnEarned(GambitPayout payout)
        {
            if (!payout.Any) return;

            string source = GambitSources.Label(payout.source);
            string sub = payout.limited
                ? $"{source} · tope aplicado ({payout.limitReason})"
                : source;

            Show($"+{payout.granted:N0} Gambits", sub);
        }

        /// <summary>Muestra un mensaje libre (la cantidad va ya formateada).</summary>
        public void Show(string message, string subtitle = "")
        {
            if (_toast == null) return;

            if (_text != null) _text.text = message;
            if (_sub != null) _sub.text = subtitle ?? "";

            _toast.RemoveFromClassList("hidden");

            _hideItem?.Pause();
            _hideItem = _toast.schedule.Execute(() => _toast.AddToClassList("hidden"))
                .StartingIn((long)(VisibleSeconds * 1000f));
        }
    }
}
