using System;
using UnityEngine;

namespace WilderGambit.View
{
    /// <summary>
    /// Smoothly animates a piece GameObject from one position to another.
    /// Attach dynamically when a move starts; self-destructs when done.
    /// </summary>
    public class PieceAnimator : MonoBehaviour
    {
        private Vector3 _startPos;
        private Vector3 _endPos;
        private float _duration;
        private float _elapsed;
        private Action _onComplete;
        private bool _isRunning;

        public bool IsAnimating => _isRunning;

        /// <summary>
        /// Starts a smooth movement from current position to target.
        /// </summary>
        /// <param name="target">World position to move to.</param>
        /// <param name="duration">Animation duration in seconds.</param>
        /// <param name="onComplete">Callback when animation finishes.</param>
        public void AnimateTo(Vector3 target, float duration, Action onComplete = null)
        {
            _startPos = transform.position;
            _endPos = target;
            _duration = Mathf.Max(duration, 0.01f);
            _elapsed = 0f;
            _onComplete = onComplete;
            _isRunning = true;
            enabled = true;
        }

        /// <summary>Instantly moves to target (no animation).</summary>
        public void SkipToEnd()
        {
            transform.position = _endPos;
            _isRunning = false;
            enabled = false;
            _onComplete?.Invoke();
            _onComplete = null;
        }

        private void Update()
        {
            if (!_isRunning) return;

            _elapsed += Time.deltaTime;
            float t = Mathf.Clamp01(_elapsed / _duration);

            // Ease-out cubic: fast start, slow end
            float eased = 1f - Mathf.Pow(1f - t, 3f);

            transform.position = Vector3.LerpUnclamped(_startPos, _endPos, eased);

            if (t >= 1f)
            {
                transform.position = _endPos;
                _isRunning = false;
                enabled = false;
                _onComplete?.Invoke();
                _onComplete = null;
            }
        }
    }
}
