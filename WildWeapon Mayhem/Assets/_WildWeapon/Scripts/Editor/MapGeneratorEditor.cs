using UnityEditor;
using UnityEditor.SceneManagement;
using UnityEngine;

namespace WildWeapon.EditorTools
{
    [CustomEditor(typeof(MapGenerator))]
    public class MapGeneratorEditor : Editor
    {
        public override void OnInspectorGUI()
        {
            DrawDefaultInspector();
            var gen = (MapGenerator)target;
            EditorGUILayout.Space();

            using (new EditorGUILayout.HorizontalScope())
            {
                if (GUILayout.Button("Generar mapa", GUILayout.Height(28)))
                    Run(gen, gen.map != null ? gen.map.seed : 0);
                if (GUILayout.Button("Semilla aleatoria", GUILayout.Height(28)))
                    Run(gen, Random.Range(1, 999999));
            }
            if (GUILayout.Button("Limpiar"))
            {
                gen.Clear();
                EditorSceneManager.MarkSceneDirty(gen.gameObject.scene);
            }
            EditorGUILayout.HelpBox("En Play la Arena regenera el mapa (semilla aleatoria si el MapDef lo indica).", MessageType.Info);
        }

        private static void Run(MapGenerator gen, int seed)
        {
            gen.Generate(seed, gen.mirrored);
            EditorSceneManager.MarkSceneDirty(gen.gameObject.scene);
        }
    }
}
