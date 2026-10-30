using System.Collections;
using UnityEngine;

namespace WilderGambit.Candy
{
    /// <summary>
    /// Corredor persistente para las peticiones que deben sobrevivir al cierre
    /// de la pantalla o al reinicio de una partida (cancelar búsqueda, abandonar
    /// o reportar el resultado). Si corrieran en el controlador, el
    /// StopAllCoroutines del cierre las cortaría a mitad de camino y el rival
    /// quedaría esperando el timeout de abandono del servidor.
    /// </summary>
    public sealed class CandyNetworkRunner : MonoBehaviour
    {
        private static CandyNetworkRunner _runner;

        public static void Run(IEnumerator routine)
        {
            if (routine == null) return;

            if (_runner == null)
            {
                var go = new GameObject("CandyNetworkRunner");
                DontDestroyOnLoad(go);
                _runner = go.AddComponent<CandyNetworkRunner>();
            }

            _runner.StartCoroutine(routine);
        }

        private void OnDestroy()
        {
            if (_runner == this) _runner = null;
        }
    }
}
