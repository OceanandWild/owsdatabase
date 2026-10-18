using UnityEngine;
using UnityEngine.UI;

namespace WildWeapon.UI
{
    /// <summary>Fila de muestras de color para el cyborg de un jugador; actualiza la preview y lo guarda.</summary>
    public class MenuColorPicker : MonoBehaviour
    {
        public int playerIndex;
        public Button[] swatches;
        public RectTransform selector;
        public CharacterVisual preview;

        void Start()
        {
            for (int i = 0; i < swatches.Length; i++)
            {
                int idx = i;
                if (swatches[i] != null) swatches[i].onClick.AddListener(() => Select(idx));
            }
            Apply(GameSession.GetColorIndex(playerIndex));
        }

        public void Select(int index)
        {
            GameSession.SetColorIndex(playerIndex, index);
            Apply(index);
        }

        private void Apply(int index)
        {
            if (preview != null) preview.SetPaintColor(GameSession.Palette[index]);
            for (int i = 0; i < swatches.Length; i++)
                if (swatches[i] != null) swatches[i].transform.localScale = Vector3.one * (i == index ? 1.2f : 1f);
            if (selector != null && index < swatches.Length && swatches[index] != null)
            {
                selector.SetParent(swatches[index].transform, false);
                selector.anchoredPosition = Vector2.zero;
                selector.SetAsFirstSibling();
            }
        }
    }
}
