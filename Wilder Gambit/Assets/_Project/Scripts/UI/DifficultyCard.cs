using UnityEngine;
using UnityEngine.UI;
using WilderGambit.AI;

namespace WilderGambit.UI
{
    public class DifficultyCard : MonoBehaviour
    {
        [SerializeField] private DifficultyLevel level;
        [SerializeField] private Text titleText;
        [SerializeField] private Text descriptionText;
        [SerializeField] private Image bgImage;
        [SerializeField] private Outline cardOutline;

        private System.Action<DifficultyLevel> onSelectCallback;

        public void Setup(DifficultyLevel diffLevel, AIConfig config, System.Action<DifficultyLevel> callback)
        {
            level = diffLevel;
            onSelectCallback = callback;

            if (titleText != null) titleText.text = config.name;
            if (descriptionText != null) descriptionText.text = GetDescription(diffLevel);
            if (bgImage != null) bgImage.color = config.themeColor * 0.25f + new Color(0, 0, 0, 0.8f);
            if (cardOutline != null) cardOutline.effectColor = config.themeColor;

            Button btn = GetComponent<Button>();
            if (btn == null) btn = gameObject.AddComponent<Button>();
            if (bgImage == null) bgImage = GetComponent<Image>();
            btn.targetGraphic = bgImage;
            btn.onClick.RemoveAllListeners();
            btn.onClick.AddListener(() => onSelectCallback?.Invoke(level));

            // Hover + click. Sin esto caia en el ColorBlock por defecto de Unity
            // (hover casi blanco), que sobre una carta ya teñida por el tema no
            // se percibía. El hover tira hacia el color del nivel y el click
            // destella en dorado, igual que TributoModal / PromotionModal.
            Color baseColor = bgImage.color;
            UiFeedback.Apply(btn, baseColor,
                Color.Lerp(baseColor, config.themeColor, 0.55f),
                Color.Lerp(baseColor, new Color(1f, 0.85f, 0.35f), 0.35f));
        }

        private string GetDescription(DifficultyLevel lvl)
        {
            switch (lvl)
            {
                case DifficultyLevel.Novice: return "🟢 Principiante: Movimientos básicos con descuidos frecuentes. Ideal para calentamiento.";
                case DifficultyLevel.Apprentice: return "🔵 Aprendiz: Conoce el valor de las piezas y el enroque básico. Ocasionalmente descuida piezas.";
                case DifficultyLevel.Knight: return "🟡 Caballero: Aperturas agresivas y presión constante. Puede cometer pequeños deslices bajo presión.";
                case DifficultyLevel.Master: return "🔴 Maestro: Búsqueda profunda y ataques directos al Rey. 5% de vulnerabilidad de reina.";
                case DifficultyLevel.GrandMaster: default: return "🟣 Gran Maestro: Inflexible. 0% descuidos, sacrificios calculados, jaques trampa y anti-doble amenaza.";
            }
        }
    }
}
