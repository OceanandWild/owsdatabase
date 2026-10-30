#if UNITY_EDITOR
using UnityEditor;
using UnityEngine;
using WilderGambit.Core;
using WilderGambit.UI;

namespace WilderGambit.Editor
{
    /// <summary>
    /// Atajo para probar el cobro del cofre a mano, sin jugarse una semana perfecta.
    ///
    /// Deja la semana en 7/7 (incluidas las 3 misiones de hoy, para que el repintado no
    /// vacíe el día en curso y la deje en 6/7), abre PROGRESO y repinta sin lanzar la
    /// animación. El cofre queda cerrado, latiendo y con COBRAR COFRE habilitado: el cobro
    /// y la apertura se prueban pulsando el botón como un jugador real
    /// (<c>WeeklyProgress.ClaimChest()</c> + <c>ChestStage.Play</c>).
    /// No cobra nada por sí mismo: es solo preparación.
    /// </summary>
    public static class ChestAnimSetup
    {
        [MenuItem("Wilder Gambit/Probar la apertura del cofre")]
        public static void TestOpening()
        {
            var controller = Object.FindAnyObjectByType<MainMenuController>();
            if (controller == null)
            {
                Debug.LogWarning("[Cofre] No encuentro el MainMenuController: abre la escena del menú y entra en Play.");
                return;
            }

            var modal = Object.FindAnyObjectByType<ProgressModal>();
            if (modal == null)
            {
                Debug.LogWarning("[Cofre] El modal de PROGRESO todavía no está montado: espere a que " +
                                 "cargue el menú y vuelva a intentarlo.");
                return;
            }

            // Hoy también tiene que quedar perfecto: si no, SyncToday vacía el segmento del
            // día al repintar y la semana se queda en 6/7 con el botón bloqueado.
            DailyMissions.DebugCompleteToday();
            // Si el cofre ya se cobró esta semana, rellenar no basta: hay que desmarcarlo.
            WeeklyProgress.DebugResetChest();
            // Los 7 días perfectos son los que abren el cofre: así la fila queda como si
            // el jugador hubiera jugado la semana entera.
            GambitProgress.Debug.FillWeek(WeeklyProgress.SegmentCount);

            controller.OpenProgressModal();
            modal.DebugReadyChest();

            Debug.Log($"[Cofre] Semana lista para abrir a mano con {WeeklyProgress.ChestAmount}G. " +
                      "Pulsa COBRAR COFRE en la fila del cofre para probar el cobro y la animación.");
        }

        [MenuItem("Wilder Gambit/Probar la apertura del cofre", true)]
        private static bool TestOpeningEnabled() => Application.isPlaying;
    }
}
#endif
