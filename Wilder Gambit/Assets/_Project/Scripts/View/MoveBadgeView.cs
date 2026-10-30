using System.Collections;
using System.IO;
using UnityEngine;
using WilderGambit.Core;
using WilderGambit.Engine;

namespace WilderGambit.View
{
    public class MoveBadgeView : MonoBehaviour
    {
        public static MoveBadgeView Instance { get; private set; }

        private GameObject _activeBadgeObj;
        private Coroutine _animCoroutine;

        private void Awake()
        {
            if (Instance != null && Instance != this)
            {
                Destroy(gameObject);
                return;
            }
            Instance = this;
        }

        public void DisplayBadge(Vector2IntCustom targetSquare, MoveClassification classification)
        {
            if (classification == MoveClassification.None) return;

            string textureName = MoveEvaluator.GetBadgeTextureName(classification);
            if (string.IsNullOrEmpty(textureName)) return;

            Sprite badgeSprite = LoadBadgeSprite(textureName);
            if (badgeSprite == null)
            {
                Debug.LogWarning($"[MoveBadgeView] No se pudo cargar el sprite para: {textureName}");
                return;
            }

            if (_activeBadgeObj != null)
            {
                Destroy(_activeBadgeObj);
            }

            _activeBadgeObj = new GameObject($"Badge_{classification}");
            _activeBadgeObj.transform.SetParent(transform);

            // Obtener la posición del centro de la casilla desde BoardView si está disponible
            Vector3 centerPos;
            float currentTileSize = 1.8f;

            BoardView boardView = FindAnyObjectByType<BoardView>();
            if (boardView != null)
            {
                centerPos = boardView.GetWorldPosition(targetSquare.Row, targetSquare.Col);
                // Extraer el tileSize real desde una casilla o estimarlo
                var tile = GameObject.Find($"Tile_{targetSquare.Row}_{targetSquare.Col}");
                if (tile != null)
                {
                    currentTileSize = tile.transform.localScale.x;
                }
            }
            else
            {
                float x = targetSquare.Col * currentTileSize - (Board.BOARD_SIZE * currentTileSize) / 2f + currentTileSize / 2f;
                float y = targetSquare.Row * currentTileSize - (Board.BOARD_SIZE * currentTileSize) / 2f + currentTileSize / 2f;
                centerPos = new Vector3(x, y, 0f);
            }

            // Anclar exactamente en la ESQUINA SUPERIOR DERECHA del cuadro (offset +X, +Y):
            // 0.35f del tamaño de casilla lo sitúa visible y elegante en la esquina sin tapar la pieza central
            float offsetX = currentTileSize * 0.34f;
            float offsetY = currentTileSize * 0.34f;
            _activeBadgeObj.transform.position = new Vector3(centerPos.x + offsetX, centerPos.y + offsetY, -3.5f);

            // Escalar el badge proporcional al tamaño de la casilla (aprox. 38% del tamaño del tile)
            float spriteWidth = badgeSprite.bounds.size.x;
            float targetScale = (currentTileSize * 0.38f) / (spriteWidth > 0 ? spriteWidth : 1f);

            SpriteRenderer sr = _activeBadgeObj.AddComponent<SpriteRenderer>();
            sr.sprite = badgeSprite;
            sr.sortingOrder = 30; // Muy por encima de las piezas y casillas

            if (_animCoroutine != null) StopCoroutine(_animCoroutine);
            _animCoroutine = StartCoroutine(AnimateBadgePopIn(_activeBadgeObj, targetScale));
        }

        private IEnumerator AnimateBadgePopIn(GameObject badgeObj, float targetScale)
        {
            if (badgeObj == null) yield break;

            Transform t = badgeObj.transform;
            Vector3 finalScale = new Vector3(targetScale, targetScale, 1f);
            t.localScale = Vector3.zero;

            float elapsed = 0f;
            float duration = 0.28f;

            // Elastic pop-in animation
            while (elapsed < duration)
            {
                if (badgeObj == null) yield break;
                elapsed += Time.deltaTime;
                float progress = elapsed / duration;
                // Overshoot bounce curve (1.25x bounce al inicio)
                float scaleFactor = Mathf.Sin(progress * Mathf.PI * 0.5f) * (1f + 0.25f * Mathf.Sin(progress * Mathf.PI));
                t.localScale = finalScale * scaleFactor;
                yield return null;
            }

            t.localScale = finalScale;
        }

        public void ClearBadge()
        {
            if (_activeBadgeObj != null)
            {
                Destroy(_activeBadgeObj);
                _activeBadgeObj = null;
            }
        }

        private Sprite LoadBadgeSprite(string name)
        {
            // 1. Fuente unica: StreamingAssets/Assets/Badges (funciona en Editor y build).
            string diskPath = Path.Combine(Application.streamingAssetsPath, "Badges", $"{name}.png");
            if (File.Exists(diskPath))
            {
                byte[] bytes = File.ReadAllBytes(diskPath);
                Texture2D tex = new Texture2D(2, 2, TextureFormat.RGBA32, false);
                tex.filterMode = FilterMode.Bilinear;
                if (tex.LoadImage(bytes))
                {
                    return Sprite.Create(tex, new Rect(0, 0, tex.width, tex.height), new Vector2(0.5f, 0.5f), 100f);
                }
            }

            return null;
        }
    }
}
