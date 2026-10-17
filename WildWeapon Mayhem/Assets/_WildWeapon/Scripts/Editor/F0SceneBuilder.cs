using System.IO;
using UnityEditor;
using UnityEditor.SceneManagement;
using UnityEngine;
using UnityEngine.Rendering.Universal;
using UnityEngine.SceneManagement;

namespace WildWeapon.EditorTools
{
    /// <summary>
    /// Genera la escena F0 (arena gris jugable) con menu:
    /// WildWeapon > F0 - Construir arena gris.
    /// Crea el sprite blanco greybox, los WeaponDef de la Katana y el Hacha Gris,
    /// la arena, los dos portadores, el DuelManager y el HUD.
    /// </summary>
    public static class F0SceneBuilder
    {
        private const string RootDir     = "Assets/_WildWeapon";
        private const string GreyboxDir  = RootDir + "/Art/Greybox";
        private const string WhiteSprite = GreyboxDir + "/white.png";
        private const string WeaponsDir  = RootDir + "/Data/Weapons";
        private const string KatanaPath  = WeaponsDir + "/katana.asset";
        private const string AxePath     = WeaponsDir + "/hacha_gris.asset";
        private const string ScenePath   = RootDir + "/Scenes/F0_Arena.unity";

        [MenuItem("WildWeapon/F0 - Construir arena gris")]
        public static void Build()
        {
            if (File.Exists(ScenePath))
            {
                bool overwrite = EditorUtility.DisplayDialog(
                    "WildWeapon F0",
                    "La escena F0_Arena ya existe. Volver a construirla desde cero?",
                    "Reconstruir", "Cancelar");
                if (!overwrite)
                {
                    EditorSceneManager.OpenScene(ScenePath);
                    return;
                }
            }

            if (!EditorSceneManager.SaveCurrentModifiedScenesIfUserWantsTo())
                return;

            EnsureFolders();
            var white = EnsureWhiteSprite();
            var katana = EnsureWeapon(KatanaPath, "Katana", 12f, 0.35f, 0.95f, 120f,
                new Color(0.85f, 0.87f, 0.95f), new Vector2(0.80f, 0.10f), 0.55f);
            var hacha = EnsureWeapon(AxePath, "Hacha Gris", 14f, 0.50f, 1.05f, 90f,
                new Color(0.62f, 0.65f, 0.70f), new Vector2(0.55f, 0.22f), 0.50f);

            var scene = EditorSceneManager.NewScene(NewSceneSetup.EmptyScene, NewSceneMode.Single);

            // ---- Luz global (URP 2D) ----
            var lightGo = new GameObject("Global Light 2D");
            var light = lightGo.AddComponent<Light2D>();
            light.lightType = Light2D.LightType.Global;
            light.color = Color.white;
            light.intensity = 1f;

            // ---- Camara ----
            var camGo = new GameObject("Main Camera");
            camGo.tag = "MainCamera";
            camGo.transform.position = new Vector3(0f, 0f, -10f);
            var cam = camGo.AddComponent<Camera>();
            cam.orthographic = true;
            cam.orthographicSize = 4.6f;
            cam.clearFlags = CameraClearFlags.SolidColor;
            cam.backgroundColor = new Color(0.05f, 0.05f, 0.07f);
            camGo.AddComponent<AudioListener>();

            // ---- Arena (jugable 15 x 8.5) ----
            CreateBlock("Piso", new Vector2(18f, 10.2f), Vector2.zero, new Color(0.16f, 0.16f, 0.18f), white, -10, false);
            var wallColor = new Color(0.07f, 0.07f, 0.09f);
            CreateBlock("Muro Norte", new Vector2(16.2f, 0.6f), new Vector2(0f, 4.55f), wallColor, white, -5, true);
            CreateBlock("Muro Sur", new Vector2(16.2f, 0.6f), new Vector2(0f, -4.55f), wallColor, white, -5, true);
            CreateBlock("Muro Este", new Vector2(0.6f, 9.7f), new Vector2(7.8f, 0f), wallColor, white, -5, true);
            CreateBlock("Muro Oeste", new Vector2(0.6f, 9.7f), new Vector2(-7.8f, 0f), wallColor, white, -5, true);

            // ---- Spawns espejados ----
            var spawn1 = new GameObject("SpawnP1");
            spawn1.transform.position = new Vector3(-4.2f, 0f, 0f);
            var spawn2 = new GameObject("SpawnP2");
            spawn2.transform.position = new Vector3(4.2f, 0f, 0f);

            // ---- Portadores ----
            var p1 = CreatePlayer("P1", white, new Color(0.30f, 0.58f, 0.95f), InputScheme.KeyboardMouse, katana, hacha);
            p1.transform.position = spawn1.transform.position;
            var p2 = CreatePlayer("P2", white, new Color(0.95f, 0.35f, 0.32f), InputScheme.Auto, katana, hacha);
            p2.transform.position = spawn2.transform.position;

            // ---- Director + HUD ----
            var mgrGo = new GameObject("DuelManager");
            var mgr = mgrGo.AddComponent<DuelManager>();
            mgr.players = new[] { p1, p2 };
            mgr.spawns = new[] { spawn1.transform, spawn2.transform };

            var hudGo = new GameObject("HUD");
            hudGo.AddComponent<HudDebug>();

            // ---- Guardar ----
            EditorSceneManager.SaveScene(scene, ScenePath);
            EditorBuildSettings.scenes = new[] { new EditorBuildSettingsScene(ScenePath, true) };
            AssetDatabase.SaveAssets();
            AssetDatabase.Refresh();

            EditorUtility.DisplayDialog("WildWeapon F0",
                "Arena lista.\n\n" +
                "J1: WASD + mouse (click ataca, Shift/Space dash, X cambia de arma)\n" +
                "J2: mando (stick izq mover, stick der apuntar, RT atacar, B dash, LT cambiar)\n" +
                "      o teclado: flechas + , ataca + . dash + / cambia\n\n" +
                "Dale Play.",
                "OK");
        }

        private static void EnsureFolders()
        {
            if (!AssetDatabase.IsValidFolder(RootDir)) AssetDatabase.CreateFolder("Assets", "_WildWeapon");
            if (!AssetDatabase.IsValidFolder(RootDir + "/Art")) AssetDatabase.CreateFolder(RootDir, "Art");
            if (!AssetDatabase.IsValidFolder(GreyboxDir)) AssetDatabase.CreateFolder(RootDir + "/Art", "Greybox");
            if (!AssetDatabase.IsValidFolder(RootDir + "/Data")) AssetDatabase.CreateFolder(RootDir, "Data");
            if (!AssetDatabase.IsValidFolder(WeaponsDir)) AssetDatabase.CreateFolder(RootDir + "/Data", "Weapons");
            if (!AssetDatabase.IsValidFolder(RootDir + "/Scenes")) AssetDatabase.CreateFolder(RootDir, "Scenes");
            AssetDatabase.Refresh();
        }

        private static Sprite EnsureWhiteSprite()
        {
            if (!File.Exists(WhiteSprite))
            {
                var tex = new Texture2D(64, 64, TextureFormat.RGBA32, false);
                var px = new Color32[64 * 64];
                for (int i = 0; i < px.Length; i++) px[i] = new Color32(255, 255, 255, 255);
                tex.SetPixels32(px);
                tex.Apply();
                File.WriteAllBytes(WhiteSprite, tex.EncodeToPNG());
                Object.DestroyImmediate(tex);

                AssetDatabase.ImportAsset(WhiteSprite, ImportAssetOptions.ForceUpdate);
                var imp = (TextureImporter)AssetImporter.GetAtPath(WhiteSprite);
                imp.textureType = TextureImporterType.Sprite;
                imp.spriteImportMode = SpriteImportMode.Single;
                imp.spritePixelsPerUnit = 64f;   // 64 px = 1 unidad
                imp.filterMode = FilterMode.Point;
                imp.mipmapEnabled = false;
                imp.alphaIsTransparency = true;
                imp.textureCompression = TextureImporterCompression.Uncompressed;
                imp.SaveAndReimport();
            }
            return AssetDatabase.LoadAssetAtPath<Sprite>(WhiteSprite);
        }

        private static WeaponDef EnsureWeapon(string path, string displayName, float damage, float cadence,
            float range, float arc, Color color, Vector2 bladeSize, float bladeOffset)
        {
            var def = AssetDatabase.LoadAssetAtPath<WeaponDef>(path);
            bool created = false;
            if (def == null)
            {
                def = ScriptableObject.CreateInstance<WeaponDef>();
                created = true;
            }

            def.displayName = displayName;
            def.damage = damage;
            def.cadence = cadence;
            def.range = range;
            def.arcDegrees = arc;
            def.color = color;
            def.bladeSize = bladeSize;
            def.bladeOffset = bladeOffset;

            if (created) AssetDatabase.CreateAsset(def, path);
            else EditorUtility.SetDirty(def);
            return def;
        }

        private static GameObject CreateBlock(string name, Vector2 size, Vector2 pos, Color color,
            Sprite sprite, int order, bool collider)
        {
            var go = new GameObject(name);
            go.transform.position = pos;
            go.transform.localScale = new Vector3(size.x, size.y, 1f);

            var sr = go.AddComponent<SpriteRenderer>();
            sr.sprite = sprite;
            sr.color = color;
            sr.sortingOrder = order;

            if (collider) go.AddComponent<BoxCollider2D>();
            return go;
        }

        private static PlayerController CreatePlayer(string name, Sprite white, Color bodyColor,
            InputScheme scheme, WeaponDef w1, WeaponDef w2)
        {
            var go = new GameObject(name);
            go.transform.localScale = new Vector3(0.85f, 0.85f, 1f);

            var sr = go.AddComponent<SpriteRenderer>();
            sr.sprite = white;
            sr.color = bodyColor;
            sr.sortingOrder = 2;

            var rb = go.AddComponent<Rigidbody2D>();
            rb.gravityScale = 0f;
            rb.freezeRotation = true;
            rb.linearDamping = 0f;
            rb.collisionDetectionMode = CollisionDetectionMode2D.Continuous;
            rb.interpolation = RigidbodyInterpolation2D.Interpolate;

            var col = go.AddComponent<CircleCollider2D>();
            col.radius = 0.5f;

            go.AddComponent<PlayerHealth>();
            var pc = go.AddComponent<PlayerController>();
            pc.scheme = scheme;
            pc.BodyRadius = 0.45f;

            var pivot = new GameObject("AimPivot");
            pivot.transform.SetParent(go.transform, false);
            pc.aimPivot = pivot.transform;

            AttachWeapon(pivot.transform, white, "Weapon_Katana", w1);
            AttachWeapon(pivot.transform, white, "Weapon_Hacha", w2);

            var loadout = go.AddComponent<WeaponLoadout>();
            loadout.weapons = go.GetComponentsInChildren<MeleeWeapon>(true);
            return pc;
        }

        private static void AttachWeapon(Transform pivot, Sprite white, string name, WeaponDef def)
        {
            var wgo = new GameObject(name);
            wgo.transform.SetParent(pivot, false);

            var mw = wgo.AddComponent<MeleeWeapon>();
            mw.def = def;

            var blade = new GameObject("Blade");
            blade.transform.SetParent(wgo.transform, false);
            var bsr = blade.AddComponent<SpriteRenderer>();
            bsr.sprite = white;
            bsr.sortingOrder = 3;
            bsr.color = def != null ? def.color : Color.white;

            mw.blade = blade.transform;
            mw.bladeRenderer = bsr;
            mw.ApplyBlade();
        }
    }
}
