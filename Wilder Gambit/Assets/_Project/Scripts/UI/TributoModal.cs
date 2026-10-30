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
    /// Modal flotante de decisión del Tributo (Sentencia de la Fragua).
    /// Cuando una Torre Fragua condena a una pieza tuya, elige entre:
    ///  - ENTREGAR: la pieza pelea 3 turnos para el condenador y vuelve a tu
    ///    ejército con inmunidad permanente (Indulto).
    ///  - DESAFIAR: la pieza queda sentenciada y arde al llegar la mecha a 0
    ///    (5 turnos de tu bando) si no cazas todas las torres condenadoras.
    /// Mismo patrón uGUI que PromotionModal (canvas overlay + fallback de
    /// New Input System) y pausa el juego vía IsGameActive en GameManager.
    /// </summary>
    public class TributoModal : MonoBehaviour
    {
        public static TributoModal Instance { get; private set; }

        private GameObject _modalContainer;
        private Canvas _canvas;
        private Action<bool> _onDecidedCallback;
        private bool _isShowing = false;

        private List<(RectTransform rect, bool accept)> _buttonRects = new List<(RectTransform, bool)>();

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
            // 1. Canvas siempre por encima de todo
            GameObject canvasObj = new GameObject("Tributo_Canvas");
            canvasObj.transform.SetParent(transform);
            _canvas = canvasObj.AddComponent<Canvas>();
            _canvas.renderMode = RenderMode.ScreenSpaceOverlay;
            _canvas.sortingOrder = 999;

            CanvasScaler scaler = canvasObj.AddComponent<CanvasScaler>();
            scaler.uiScaleMode = CanvasScaler.ScaleMode.ScaleWithScreenSize;
            scaler.referenceResolution = new Vector2(1920, 1080);
            UiResponsive.ApplyCanvasScaler(scaler);

            canvasObj.AddComponent<GraphicRaycaster>();

            // 2. Contenedor principal (fondo oscurecido)
            _modalContainer = new GameObject("ModalContainer");
            _modalContainer.transform.SetParent(canvasObj.transform, false);

            RectTransform containerRect = _modalContainer.AddComponent<RectTransform>();
            containerRect.anchorMin = Vector2.zero;
            containerRect.anchorMax = Vector2.one;
            containerRect.sizeDelta = Vector2.zero;

            Image bgOverlay = _modalContainer.AddComponent<Image>();
            bgOverlay.color = new Color(0f, 0f, 0f, 0.65f);

            _modalContainer.SetActive(false);
        }

        /// <summary>Muestra la decisión de Tributo al dueño de la pieza condenada.</summary>
        /// <param name="ownerTeam">Bando dueño de la pieza condenada.</param>
        /// <param name="pieceName">Nombre de la pieza (Dama, Torre…).</param>
        /// <param name="onDecided">true = ENTREGAR (Tributo), false = DESAFIAR (mecha).</param>
        public void Show(TeamColor ownerTeam, string pieceName, Action<bool> onDecided)
        {
            if (_isShowing) return;
            _isShowing = true;
            _onDecidedCallback = onDecided;
            _buttonRects.Clear();

            EnsureEventSystem();

            if (_modalContainer == null)
            {
                CreateModalUI();
            }

            Transform cardBox = _modalContainer.transform.Find("CardBox");
            if (cardBox != null)
            {
                Destroy(cardBox.gameObject);
            }

            // ── Tarjeta central ──
            GameObject cardObj = new GameObject("CardBox");
            cardObj.transform.SetParent(_modalContainer.transform, false);

            RectTransform cardRect = cardObj.AddComponent<RectTransform>();
            cardRect.sizeDelta = new Vector2(800, 360);
            cardRect.anchorMin = new Vector2(0.5f, 0.5f);
            cardRect.anchorMax = new Vector2(0.5f, 0.5f);
            cardRect.pivot = new Vector2(0.5f, 0.5f);

            Image cardBg = cardObj.AddComponent<Image>();
            cardBg.color = new Color(0.12f, 0.14f, 0.18f, 0.96f);

            Outline outline = cardObj.AddComponent<Outline>();
            outline.effectColor = new Color(1f, 0.55f, 0.1f, 0.85f); // borde ígneo de la Fragua
            outline.effectDistance = new Vector2(3, -3);

            // ── Título ──
            GameObject titleObj = new GameObject("TitleText");
            titleObj.transform.SetParent(cardObj.transform, false);
            RectTransform titleRect = titleObj.AddComponent<RectTransform>();
            titleRect.sizeDelta = new Vector2(760, 42);
            titleRect.anchoredPosition = new Vector2(0, 142);

            Text titleText = titleObj.AddComponent<Text>();
            titleText.text = "SENTENCIA DE LA FRAGUA";
            titleText.fontSize = 26;
            titleText.fontStyle = FontStyle.Bold;
            titleText.alignment = TextAnchor.MiddleCenter;
            titleText.color = new Color(1f, 0.62f, 0.15f);
            titleText.font = Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");
            if (titleText.font == null) titleText.font = Font.CreateDynamicFontFromOSFont("Arial", 26);

            // ── Subtítulo ──
            GameObject subObj = new GameObject("SubText");
            subObj.transform.SetParent(cardObj.transform, false);
            RectTransform subRect = subObj.AddComponent<RectTransform>();
            subRect.sizeDelta = new Vector2(760, 70);
            subRect.anchoredPosition = new Vector2(0, 84);

            Text subText = subObj.AddComponent<Text>();
            subText.text = $"Una Torre Fragua ha condenado a tu {pieceName}.\n" +
                           "¿Aceptas el Tributo o desafías la condena?";
            subText.fontSize = 18;
            subText.alignment = TextAnchor.MiddleCenter;
            subText.color = new Color(0.92f, 0.94f, 0.97f);
            subText.font = Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");
            if (subText.font == null) subText.font = Font.CreateDynamicFontFromOSFont("Arial", 18);

            // ── Fila de botones ──
            GameObject buttonsRow = new GameObject("ButtonsRow");
            buttonsRow.transform.SetParent(cardObj.transform, false);
            RectTransform rowRect = buttonsRow.AddComponent<RectTransform>();
            rowRect.sizeDelta = new Vector2(720, 150);
            rowRect.anchoredPosition = new Vector2(0, -32);

            HorizontalLayoutGroup hlg = buttonsRow.AddComponent<HorizontalLayoutGroup>();
            hlg.spacing = 40;
            hlg.childAlignment = TextAnchor.MiddleCenter;
            hlg.childControlWidth = false;
            hlg.childControlHeight = false;

            CreateDecisionButton(buttonsRow.transform, accept: true,
                "ENTREGAR · TRIBUTO",
                "Pelea 3 turnos para el rival\ny vuelve con INMUNIDAD");
            CreateDecisionButton(buttonsRow.transform, accept: false,
                "DESAFIAR · MECHA",
                "Arde en 5 turnos de tu bando\nsi no cazas la torre");

            // ── Nota al pie ──
            GameObject footObj = new GameObject("FootText");
            footObj.transform.SetParent(cardObj.transform, false);
            RectTransform footRect = footObj.AddComponent<RectTransform>();
            footRect.sizeDelta = new Vector2(760, 30);
            footRect.anchoredPosition = new Vector2(0, -155);

            Text footText = footObj.AddComponent<Text>();
            footText.text = "La condena ya cedió el turno: tu respuesta no gasta turno.";
            footText.fontSize = 14;
            footText.alignment = TextAnchor.MiddleCenter;
            footText.color = new Color(0.65f, 0.7f, 0.78f);
            footText.font = Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");
            if (footText.font == null) footText.font = Font.CreateDynamicFontFromOSFont("Arial", 14);

            _modalContainer.SetActive(true);
            StartCoroutine(AnimateModalPopIn(cardObj.transform));
        }

        private RectTransform CreateDecisionButton(Transform parent, bool accept, string title, string description)
        {
            GameObject btnObj = new GameObject(accept ? "Btn_Entregar" : "Btn_Desafiar");
            btnObj.transform.SetParent(parent, false);

            RectTransform btnRect = btnObj.AddComponent<RectTransform>();
            btnRect.sizeDelta = new Vector2(340, 150);

            Image btnBg = btnObj.AddComponent<Image>();
            Color baseColor = accept ? new Color(0.16f, 0.30f, 0.24f, 0.97f) : new Color(0.34f, 0.18f, 0.10f, 0.97f);

            Button btn = btnObj.AddComponent<Button>();
            // El Image.color y el ColorBlock se multiplican: el Image queda en
            // blanco y el color de verdad viaja por el ColorBlock. Ponerlo en los
            // dos lugares lo cebaba al cuadrado y apagaba el hover.
            btnBg.color = Color.white;
            UiFeedback.Apply(btn, baseColor,
                accept ? new Color(0.24f, 0.46f, 0.34f, 1f) : new Color(0.52f, 0.28f, 0.14f, 1f),
                new Color(0.95f, 0.75f, 0.25f, 1f));

            UiFeedback.AttachSounds(btn);

            bool acceptValue = accept;
            btn.onClick.AddListener(() => OnDecisionClicked(acceptValue));

            // Título del botón
            GameObject titleObj = new GameObject("Title");
            titleObj.transform.SetParent(btnObj.transform, false);
            RectTransform titleRect = titleObj.AddComponent<RectTransform>();
            titleRect.sizeDelta = new Vector2(330, 34);
            titleRect.anchoredPosition = new Vector2(0, 40);

            Text btnTitle = titleObj.AddComponent<Text>();
            btnTitle.text = title;
            btnTitle.fontSize = 20;
            btnTitle.fontStyle = FontStyle.Bold;
            btnTitle.alignment = TextAnchor.MiddleCenter;
            btnTitle.color = accept ? new Color(0.55f, 1f, 0.75f) : new Color(1f, 0.62f, 0.35f);
            btnTitle.font = Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");
            if (btnTitle.font == null) btnTitle.font = Font.CreateDynamicFontFromOSFont("Arial", 20);

            // Descripción del botón
            GameObject descObj = new GameObject("Desc");
            descObj.transform.SetParent(btnObj.transform, false);
            RectTransform descRect = descObj.AddComponent<RectTransform>();
            descRect.sizeDelta = new Vector2(330, 70);
            descRect.anchoredPosition = new Vector2(0, -22);

            Text btnDesc = descObj.AddComponent<Text>();
            btnDesc.text = description;
            btnDesc.fontSize = 15;
            btnDesc.alignment = TextAnchor.MiddleCenter;
            btnDesc.color = new Color(0.9f, 0.92f, 0.95f);
            btnDesc.font = Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");
            if (btnDesc.font == null) btnDesc.font = Font.CreateDynamicFontFromOSFont("Arial", 15);

            _buttonRects.Add((btnRect, accept));
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
                        OnDecisionClicked(item.accept);
                        break;
                    }
                }
            }
        }

        private void OnDecisionClicked(bool accept)
        {
            if (!_isShowing) return;
            _isShowing = false;

            if (_modalContainer != null)
            {
                _modalContainer.SetActive(false);
            }

            var cb = _onDecidedCallback;
            _onDecidedCallback = null;
            cb?.Invoke(accept);
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
