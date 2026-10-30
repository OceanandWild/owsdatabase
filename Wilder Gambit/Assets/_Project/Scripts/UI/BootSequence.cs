using System.Collections;
using UnityEngine;
using UnityEngine.SceneManagement;
using UnityEngine.UIElements;

namespace WilderGambit.UI
{
    /// <summary>
    /// Escena de arranque: muestra el icono de OWS durante 3 segundos y carga el juego.
    ///
    /// Unity no deja ajustar la duracion del splash del motor (la decide el motor: un minimo fijo,
    /// o hasta que la primera escena este lista), asi que el tiempo visible se controla aca: esta
    /// escena es la escena[0] del build y el icono sale <see cref="holdSeconds"/> segundos antes de
    /// cargar la primera escena de juego. El splash del motor queda en color plano, sin arte y
    /// sin el logo de Unity, para que no haya dos pantallas distintas al arrancar.
    ///
    /// Requiere: UIDocument con PanelSettings. Sprite del icono y escena destino los asigna el menu
    /// Wilder Gambit &gt; Crear escena de splash (Boot).
    /// </summary>
    [RequireComponent(typeof(UIDocument))]
    public class BootSequence : MonoBehaviour
    {
        /// <summary>
        /// Color del fondo: azul verdoso profundo, del mismo tono que los bordes del arte del icono
        /// para que el cuadrado no se corte contra el fondo. Mismo valor que usan el splash del
        /// motor y la camara de la escena Boot.
        /// </summary>
        private static readonly Color Background = new Color(0.039f, 0.129f, 0.188f, 1f);

        [Header("Branding")]
        [SerializeField] private Sprite iconSprite;
        [SerializeField] private PanelSettings panelSettings;

        [Header("Tiempos")]
        [Min(0f)] [SerializeField] private float holdSeconds = 3f;

        [Header("Destino")]
        [SerializeField] private string nextSceneName = "SampleScene";

        private bool _leaving;

        private void Start()
        {
            // En Start, no en Awake: UIDocument crea rootVisualElement en su OnEnable, y el orden
            // entre componentes no esta garantizado durante el arranque.
            UIDocument document = GetComponent<UIDocument>();
            if (panelSettings != null) document.panelSettings = panelSettings;

            BuildStage(document);
            StartCoroutine(Run());
        }

        private void BuildStage(UIDocument document)
        {
            VisualElement root = document.rootVisualElement;
            root.Clear();
            root.pickingMode = PickingMode.Ignore;
            root.style.flexGrow = 1;
            root.style.backgroundColor = Background;

            if (iconSprite == null)
            {
                Debug.LogError("[Boot] No hay sprite de icono asignado. " +
                               "Ejecuta Wilder Gambit > Crear escena de splash (Boot).");
                return;
            }

            // El icono va centrado y con su proporcion intacta: la imagen es cuadrada y el panel es
            // 16:9, asi que se limita el alto y el ancho y ScaleToFit la deja proporcionada.
            root.style.alignItems = Align.Center;
            root.style.justifyContent = Justify.Center;

            var icon = new Image { name = "boot-icon", pickingMode = PickingMode.Ignore };
            icon.sprite = iconSprite;
            icon.scaleMode = ScaleMode.ScaleToFit;
            icon.style.width = Length.Percent(45f);
            icon.style.height = Length.Percent(70f);
            icon.style.flexShrink = 0f;

            root.Add(icon);
        }

        private IEnumerator Run()
        {
            for (float elapsed = 0f; elapsed < holdSeconds; elapsed += Time.unscaledDeltaTime)
            {
                yield return null;
            }

            Load();
        }

        private void Load()
        {
            if (_leaving) return;
            _leaving = true;

            if (string.IsNullOrEmpty(nextSceneName) ||
                Application.CanStreamedLevelBeLoaded(nextSceneName) == false)
            {
                Debug.LogError($"[Boot] La escena '{nextSceneName}' no esta en Build Settings. " +
                               "Ejecuta Wilder Gambit > Crear escena de splash (Boot).");
                return;
            }

            SceneManager.LoadScene(nextSceneName);
        }
    }
}
