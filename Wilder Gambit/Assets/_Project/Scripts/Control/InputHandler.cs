using UnityEngine;
using UnityEngine.InputSystem;
using WilderGambit.Candy;
using WilderGambit.Core;
using WilderGambit.View;

namespace WilderGambit.Control
{
    public class InputHandler : MonoBehaviour
    {
        [SerializeField] private BoardView boardView;
        private Camera mainCamera;

        private void Awake()
        {
            mainCamera = Camera.main;
            if (boardView == null) boardView = FindAnyObjectByType<BoardView>();
        }

        private void Update()
        {
            // Si el juego no está activo o GameManager no existe (ej. en el menú principal), no procesar clicks en el tablero
            if (GameManager.Instance == null || !GameManager.Instance.IsGameActive) return;

            // La Cacería de Dulces monta su propio tablero UI: que el raycast 3D
            // no seleccione piezas de una partida clásica que quedó detrás.
            if (CandyModeController.Instance != null && CandyModeController.Instance.IsOpen) return;

            // Pointer cubre ratón, táctil y lápiz (Mouse.current es null en móvil)
            var pointer = Pointer.current;
            if (pointer == null) return;

            if (pointer.press.wasPressedThisFrame)
            {
                if (mainCamera == null) mainCamera = Camera.main;
                if (mainCamera == null) return;

                Vector2 screenPos = pointer.position.ReadValue();
                Vector3 mouseWorldPos = mainCamera.ScreenToWorldPoint(new Vector3(screenPos.x, screenPos.y, 0f));
                Vector2 mousePos2D = new Vector2(mouseWorldPos.x, mouseWorldPos.y);

                RaycastHit2D hit = Physics2D.Raycast(mousePos2D, Vector2.zero);
                if (hit.collider != null)
                {
                    string tileName = hit.collider.gameObject.name;
                    if (tileName.StartsWith("Tile_"))
                    {
                        string[] parts = tileName.Split('_');
                        if (parts.Length >= 3 && int.TryParse(parts[1], out int row) && int.TryParse(parts[2], out int col))
                        {
                            GameManager.Instance?.SelectSquare(new Vector2IntCustom(row, col));
                        }
                    }
                }
            }
        }
    }
}

