using System;
using System.Collections;
using System.Collections.Generic;
using UnityEngine;
using UnityEngine.InputSystem;
using UnityEngine.InputSystem.UI;
using UnityEngine.EventSystems;
using UnityEngine.UI;
using WilderGambit.Core;
using WilderGambit.View;

namespace WilderGambit.UI
{
    /// <summary>
    /// Modal flotante de selección de Coronación de Peón (Pawn Promotion).
    /// Muestra las 4 opciones de piezas (Dama, Torre, Alfil, Caballo) con sprites y animación pop-in.
    /// Soporta eventos uGUI y fallback directo de New Input System.
    /// </summary>
    public class PromotionModal : MonoBehaviour
    {
        public static PromotionModal Instance { get; private set; }

        private GameObject _modalContainer;
        private Canvas _canvas;
        private Action<PieceType> _onSelectedCallback;
        private bool _isShowing = false;

        private List<(RectTransform rect, PieceType type)> _buttonRects = new List<(RectTransform, PieceType)>();

        private void Awake()
        {
            if (Instance != null && Instance != this)
            {
                Destroy(gameObject);
                return;
            }
            Instance = this;
            DontDestroyOnLoad(gameObject);

            EnsureEventSystem();
            CreateModalUI();
        }

        private void EnsureEventSystem()
        {
            EventSystem es = FindAnyObjectByType<EventSystem>();
            if (es == null)
            {
                GameObject esObj = new GameObject("EventSystem");
                es = esObj.AddComponent<EventSystem>();
                DontDestroyOnLoad(esObj);
            }

            var standalone = es.GetComponent<StandaloneInputModule>();
            if (standalone != null)
            {
                Destroy(standalone);
            }

            if (es.GetComponent<InputSystemUIInputModule>() == null)
            {
                es.gameObject.AddComponent<InputSystemUIInputModule>();
            }
        }

        private void CreateModalUI()
        {
            // 1. Crear Canvas si no existe
            GameObject canvasObj = new GameObject("Promotion_Canvas");
            canvasObj.transform.SetParent(transform);
            _canvas = canvasObj.AddComponent<Canvas>();
            _canvas.renderMode = RenderMode.ScreenSpaceOverlay;
            _canvas.sortingOrder = 999; // Siempre por encima de todo

            CanvasScaler scaler = canvasObj.AddComponent<CanvasScaler>();
            scaler.uiScaleMode = CanvasScaler.ScaleMode.ScaleWithScreenSize;
            scaler.referenceResolution = new Vector2(1920, 1080);
            UiResponsive.ApplyCanvasScaler(scaler);

            canvasObj.AddComponent<GraphicRaycaster>();

            // 2. Contenedor principal (Fondo oscurecido + Tarjeta central)
            _modalContainer = new GameObject("ModalContainer");
            _modalContainer.transform.SetParent(canvasObj.transform, false);

            RectTransform containerRect = _modalContainer.AddComponent<RectTransform>();
            containerRect.anchorMin = Vector2.zero;
            containerRect.anchorMax = Vector2.one;
            containerRect.sizeDelta = Vector2.zero;

            // Fondo semitransparente oscuro
            Image bgOverlay = _modalContainer.AddComponent<Image>();
            bgOverlay.color = new Color(0f, 0f, 0f, 0.65f);

            _modalContainer.SetActive(false);
        }

        public void Show(TeamColor team, Action<PieceType> onPieceSelected)
        {
            if (_isShowing) return;
            _isShowing = true;
            _onSelectedCallback = onPieceSelected;
            _buttonRects.Clear();

            EnsureEventSystem();

            if (_modalContainer == null)
            {
                CreateModalUI();
            }

            // Limpiar contenido previo de la ventana si lo hubiera
            Transform cardBox = _modalContainer.transform.Find("CardBox");
            if (cardBox != null)
            {
                Destroy(cardBox.gameObject);
            }

            // Crear la tarjeta central
            GameObject cardObj = new GameObject("CardBox");
            cardObj.transform.SetParent(_modalContainer.transform, false);

            RectTransform cardRect = cardObj.AddComponent<RectTransform>();
            cardRect.sizeDelta = new Vector2(620, 240);
            cardRect.anchorMin = new Vector2(0.5f, 0.5f);
            cardRect.anchorMax = new Vector2(0.5f, 0.5f);
            cardRect.pivot = new Vector2(0.5f, 0.5f);

            Image cardBg = cardObj.AddComponent<Image>();
            cardBg.color = new Color(0.12f, 0.14f, 0.18f, 0.95f);

            // Borde / sombra visual
            Outline outline = cardObj.AddComponent<Outline>();
            outline.effectColor = new Color(0.85f, 0.70f, 0.25f, 0.8f);
            outline.effectDistance = new Vector2(3, -3);

            // Título
            GameObject titleObj = new GameObject("TitleText");
            titleObj.transform.SetParent(cardObj.transform, false);
            RectTransform titleRect = titleObj.AddComponent<RectTransform>();
            titleRect.sizeDelta = new Vector2(580, 40);
            titleRect.anchoredPosition = new Vector2(0, 80);

            Text titleText = titleObj.AddComponent<Text>();
            titleText.text = "ELIGE PIEZA PARA CORONAR";
            titleText.fontSize = 22;
            titleText.fontStyle = FontStyle.Bold;
            titleText.alignment = TextAnchor.MiddleCenter;
            titleText.color = new Color(0.95f, 0.85f, 0.45f);
            titleText.font = Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");
            if (titleText.font == null) titleText.font = Font.CreateDynamicFontFromOSFont("Arial", 22);

            // Contenedor de Botones Horizontal
            GameObject buttonsRow = new GameObject("ButtonsRow");
            buttonsRow.transform.SetParent(cardObj.transform, false);
            RectTransform rowRect = buttonsRow.AddComponent<RectTransform>();
            rowRect.sizeDelta = new Vector2(560, 120);
            rowRect.anchoredPosition = new Vector2(0, -20);

            HorizontalLayoutGroup hlg = buttonsRow.AddComponent<HorizontalLayoutGroup>();
            hlg.spacing = 20;
            hlg.childAlignment = TextAnchor.MiddleCenter;
            hlg.childControlWidth = false;
            hlg.childControlHeight = false;

            // Las 4 opciones clásicas de coronación
            PieceType[] promotionPieces = new PieceType[]
            {
                PieceType.Queen,
                PieceType.Rook,
                PieceType.Bishop,
                PieceType.Knight
            };

            string[] pieceNames = new string[] { "Dama", "Torre", "Alfil", "Caballo" };

            for (int i = 0; i < promotionPieces.Length; i++)
            {
                PieceType pieceType = promotionPieces[i];
                string label = pieceNames[i];
                Sprite pieceSprite = BoardView.Instance != null ? BoardView.Instance.GetPieceSprite(pieceType, team) : null;

                RectTransform btnR = CreatePieceButton(buttonsRow.transform, pieceType, label, pieceSprite);
                _buttonRects.Add((btnR, pieceType));
            }

            _modalContainer.SetActive(true);
            StartCoroutine(AnimateModalPopIn(cardObj.transform));
        }

        private RectTransform CreatePieceButton(Transform parent, PieceType type, string label, Sprite sprite)
        {
            GameObject btnObj = new GameObject($"Btn_{type}");
            btnObj.transform.SetParent(parent, false);

            RectTransform btnRect = btnObj.AddComponent<RectTransform>();
            btnRect.sizeDelta = new Vector2(115, 115);

            Image btnBg = btnObj.AddComponent<Image>();
            Color baseColor = new Color(0.20f, 0.24f, 0.30f, 0.95f);

            Button btn = btnObj.AddComponent<Button>();
            // El Image.color y el ColorBlock se multiplican: el Image queda en
            // blanco y el color de verdad viaja por el ColorBlock. Ponerlo en los
            // dos lugares lo cebaba al cuadrado y apagaba el hover.
            btnBg.color = Color.white;
            UiFeedback.Apply(btn, baseColor,
                new Color(0.35f, 0.42f, 0.55f, 1f),
                new Color(0.85f, 0.70f, 0.25f, 1f));

            UiFeedback.AttachSounds(btn);

            btn.onClick.AddListener(() =>
            {
                OnPieceClicked(type);
            });

            // Icono de la pieza
            if (sprite != null)
            {
                GameObject iconObj = new GameObject("Icon");
                iconObj.transform.SetParent(btnObj.transform, false);
                RectTransform iconRect = iconObj.AddComponent<RectTransform>();
                iconRect.sizeDelta = new Vector2(75, 75);
                iconRect.anchoredPosition = new Vector2(0, 10);

                Image iconImg = iconObj.AddComponent<Image>();
                iconImg.sprite = sprite;
                iconImg.preserveAspect = true;
            }

            // Etiqueta de texto inferior
            GameObject labelObj = new GameObject("Label");
            labelObj.transform.SetParent(btnObj.transform, false);
            RectTransform labelRect = labelObj.AddComponent<RectTransform>();
            labelRect.sizeDelta = new Vector2(110, 25);
            labelRect.anchoredPosition = new Vector2(0, -42);

            Text labelText = labelObj.AddComponent<Text>();
            labelText.text = label;
            labelText.fontSize = 14;
            labelText.alignment = TextAnchor.MiddleCenter;
            labelText.color = Color.white;
            labelText.font = Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");
            if (labelText.font == null) labelText.font = Font.CreateDynamicFontFromOSFont("Arial", 14);

            return btnRect;
        }

        private void Update()
        {
            if (!_isShowing) return;

            var pointer = Pointer.current;
            if (pointer != null && pointer.press.wasPressedThisFrame)
            {
                Vector2 screenPos = pointer.position.ReadValue();

                foreach (var item in _buttonRects)
                {
                    if (item.rect != null && RectTransformUtility.RectangleContainsScreenPoint(item.rect, screenPos))
                    {
                        OnPieceClicked(item.type);
                        break;
                    }
                }
            }
        }

        private void OnPieceClicked(PieceType type)
        {
            if (!_isShowing) return;
            _isShowing = false;

            if (_modalContainer != null)
            {
                _modalContainer.SetActive(false);
            }

            var cb = _onSelectedCallback;
            _onSelectedCallback = null;
            cb?.Invoke(type);
        }

        private IEnumerator AnimateModalPopIn(Transform card)
        {
            if (card == null) yield break;

            Vector3 targetScale = Vector3.one;
            card.localScale = Vector3.zero;

            float elapsed = 0f;
            float duration = 0.22f;

            while (elapsed < duration)
            {
                if (card == null) yield break;
                elapsed += Time.unscaledDeltaTime;
                float progress = elapsed / duration;
                float scaleFactor = Mathf.Sin(progress * Mathf.PI * 0.5f) * (1f + 0.15f * Mathf.Sin(progress * Mathf.PI));
                card.localScale = targetScale * scaleFactor;
                yield return null;
            }

            card.localScale = targetScale;
        }

        public void Hide()
        {
            _isShowing = false;
            if (_modalContainer != null)
            {
                _modalContainer.SetActive(false);
            }
        }
    }
}
