using UnityEngine;
using System;
using System.Collections;

namespace WilderGambit.View
{
    /// <summary>
    /// Componente que reproduce la animación Idle y de Ataque del Caballo Blanco transformado tras hacer un Fork.
    /// </summary>
    public class KnightForkAnimator : MonoBehaviour
    {
        private Sprite[] _idleFrames;
        private Sprite[] _attackFrames;
        private Sprite _staticSprite;
        private SpriteRenderer _sr;
        private Coroutine _currentRoutine;
        private float _fps = 24f;
        private float _tileSize = 1f;

        public void Initialize(Sprite[] idleFrames, Sprite[] attackFrames, Sprite staticSprite, float tileSize)
        {
            _idleFrames = idleFrames;
            _attackFrames = attackFrames;
            _staticSprite = staticSprite;
            _tileSize = tileSize;
            _sr = GetComponent<SpriteRenderer>();

            if (_sr == null)
                _sr = GetComponentInChildren<SpriteRenderer>();

            // Desactivar el Shadow child para que el aura de fuego translúcida se aprecie nítida
            Transform shadowT = transform.Find("Shadow");
            if (shadowT != null)
                shadowT.gameObject.SetActive(false);

            PlayIdle();
        }

        /// <summary>
        /// Detiene las animaciones y restaura el estado y sprite original del Caballo.
        /// </summary>
        public void Revert(Sprite staticSprite, float tileSize)
        {
            if (_currentRoutine != null)
            {
                StopCoroutine(_currentRoutine);
                _currentRoutine = null;
            }

            Sprite spriteToUse = staticSprite != null ? staticSprite : _staticSprite;

            if (_sr != null && spriteToUse != null)
            {
                _sr.sprite = spriteToUse;
            }

            Transform shadowT = transform.Find("Shadow");
            if (shadowT != null)
            {
                shadowT.gameObject.SetActive(true);
            }

            if (spriteToUse != null && spriteToUse.bounds.size.y > 0)
            {
                float targetHeight = tileSize * 0.82f;
                float scale = targetHeight / spriteToUse.bounds.size.y;
                transform.localScale = new Vector3(scale, scale, 1f);
            }
        }

        public void PlayIdle()
        {
            if (_currentRoutine != null)
                StopCoroutine(_currentRoutine);

            if (_idleFrames != null && _idleFrames.Length > 0)
            {
                if (_idleFrames[0] != null && _idleFrames[0].bounds.size.y > 0)
                {
                    float targetHeight = _tileSize * 0.82f;
                    float scale = targetHeight / _idleFrames[0].bounds.size.y;
                    transform.localScale = new Vector3(scale, scale, 1f);
                }
                _currentRoutine = StartCoroutine(IdleRoutine());
            }
            else if (_staticSprite != null && _sr != null)
            {
                _sr.sprite = _staticSprite;
                if (_staticSprite.bounds.size.y > 0)
                {
                    float targetHeight = _tileSize * 0.82f;
                    float scale = targetHeight / _staticSprite.bounds.size.y;
                    transform.localScale = new Vector3(scale, scale, 1f);
                }
            }
        }

        private IEnumerator IdleRoutine()
        {
            int currentFrame = 0;
            float interval = 1f / _fps;

            while (true)
            {
                if (_sr != null && _idleFrames != null && _idleFrames.Length > 0)
                {
                    _sr.sprite = _idleFrames[currentFrame];
                    currentFrame = (currentFrame + 1) % _idleFrames.Length;
                }

                yield return new WaitForSeconds(interval);
            }
        }

        /// <summary>
        /// Ejecuta la animación de ataque:
        /// 1) Frames 0..15: El caballo se desvanece en su casilla de origen.
        /// 2) Frame 16: El caballo desaparece de la casilla de origen y se traslada a la casilla objetivo antes del cometa.
        /// 3) Frames 16..26: El cometa rojo viaja y explota sobre la casilla objetivo.
        /// 4) Frame 27: Implosión en la casilla objetivo, se destruye la pieza enemiga.
        /// 5) Frames 27..71: Recomposición e implosión final del caballo, terminando en Idle en la casilla destino.
        /// </summary>
        public void PlayAttack(Vector3 targetWorldPos, Action onPieceDestroyed, Action onAnimationFinished)
        {
            if (_attackFrames == null || _attackFrames.Length == 0)
            {
                transform.position = targetWorldPos;
                onPieceDestroyed?.Invoke();
                onAnimationFinished?.Invoke();
                PlayIdle();
                return;
            }

            if (_currentRoutine != null)
                StopCoroutine(_currentRoutine);

            _currentRoutine = StartCoroutine(AttackRoutine(targetWorldPos, onPieceDestroyed, onAnimationFinished));
        }

        private IEnumerator AttackRoutine(Vector3 targetWorldPos, Action onPieceDestroyed, Action onAnimationFinished)
        {
            float interval = 1f / _fps;
            bool pieceDestroyedTriggered = false;

            for (int i = 0; i < _attackFrames.Length; i++)
            {
                // En el frame 16 (justo cuando desaparece la estela y surge el cometa),
                // movemos el Transform a la casilla destino para que el cometa y la explosión impacten allí.
                if (i == 16)
                {
                    transform.position = targetWorldPos;
                }

                // En el frame 27 (momento de máxima implosión / impacto), se destruye la pieza enemiga
                if (i >= 27 && !pieceDestroyedTriggered)
                {
                    pieceDestroyedTriggered = true;
                    onPieceDestroyed?.Invoke();
                }

                if (_sr != null && _attackFrames[i] != null)
                {
                    _sr.sprite = _attackFrames[i];
                }

                yield return new WaitForSeconds(interval);
            }

            if (!pieceDestroyedTriggered)
            {
                pieceDestroyedTriggered = true;
                onPieceDestroyed?.Invoke();
            }

            onAnimationFinished?.Invoke();

            // Reanudar el ciclo de Idle en la nueva posición
            PlayIdle();
        }
    }
}

