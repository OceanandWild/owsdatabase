using System.Collections.Generic;
using System.IO;
using UnityEditor;
using UnityEditor.Animations;
using UnityEditor.Events;
using UnityEditor.SceneManagement;
using UnityEngine;
using UnityEngine.EventSystems;
using UnityEngine.InputSystem.UI;
using UnityEngine.Rendering;
using UnityEngine.Rendering.Universal;
using UnityEngine.UI;
using WildWeapon.Pvp;
using WildWeapon.UI;

namespace WildWeapon.EditorTools
{
    /// <summary>
    /// WildWeapon > Construir juego completo.
    /// Importa el arte, procesa las piezas del rig (recorte + mascara de pintura),
    /// crea armas, VFX, animaciones esqueleticas, personajes riggeados, el MapDef
    /// y genera las escenas MainMenu y Arena. Es idempotente.
    /// </summary>
    public static class WildWeaponBuilder
    {
        private const string Root = "Assets/_WildWeapon";
        private const string SrcImages = "Assets/Generated_Images";
        private const string SpritesDir = Root + "/Art/Sprites";
        private const string RigDir = Root + "/Art/Rig";
        private const string RigRawDir = RigDir + "/Raw";
        private const string VfxArtDir = Root + "/Art/VFX";
        private const string MatDir = Root + "/Materials";
        private const string AnimDir = Root + "/Animations";
        private const string WeaponsDir = Root + "/Data/Weapons";
        private const string AbilitiesDir = Root + "/Data/Abilities";
        private const string BotsDataDir = Root + "/Data/Bots";
        private const string MapsDir = Root + "/Data/Maps";
        private const string PrefabDir = Root + "/Prefabs";
        private const string VfxPrefabDir = PrefabDir + "/VFX";
        private const string BotPrefabDir = PrefabDir + "/Bots";
        private const string CharPrefabDir = PrefabDir + "/Characters";
        private const string ScenesDir = Root + "/Scenes";
        private const string MenuScenePath = ScenesDir + "/MainMenu.unity";
        private const string MapSelectScenePath = ScenesDir + "/MapSelect.unity";
        private const string ArenaScenePath = ScenesDir + "/Arena.unity";
        private const string CharSelectScenePath = ScenesDir + "/CharacterSelect.unity";
        private const string CatalogPath = MapsDir + "/MapCatalog.asset";

        // Layout del menu principal (lo comparten la escena y los clips de animacion)
        private const float MenuCardY = 108f;
        private const float MenuInfoY = 266f;
        private const float MenuLogoY = -60f;

        private static Material _unlit;
        private static Material _particle;
        private static Material _trail;
        private static Sprite _soft;
        private static Sprite _panel;      // panel redondeado 9-slice de la UI
        private static Sprite _shine;      // veta de luz para el brillo del logo
        private static Sprite _vignette;   // vineta radial del fondo
        private static Sprite _ring;      // anillo suave para los peligros de arena
        private static Sprite _platShadow; // mancha rectangular suave de las plataformas

        // ---- Rig ----
        private class PartSpr { public Sprite b; public Sprite p; }

        private class RigSet
        {
            public PartSpr head, torso, upper, fore, thigh, shin;
            public bool drone;
            public PartSpr droneBody, droneArm;
        }

        private class RigRefs
        {
            public Animator animator;
            public Transform armFront, foreFront, handFront;
            public readonly List<CharacterVisual.Part> parts = new List<CharacterVisual.Part>();
        }

        // Proporciones del humanoide (unidades del rig, antes de la escala del Visual)
        private const float HeadH = 0.46f, TorsoH = 0.58f, UpperH = 0.34f, ForeH = 0.36f, ThighH = 0.34f, ShinH = 0.38f;
        private const float HipsY = 0.62f;

        [MenuItem("WildWeapon/Construir juego completo (Menu + Arena + Assets)")]
        public static void BuildAll()
        {
            if (!EditorSceneManager.SaveCurrentModifiedScenesIfUserWantsTo()) return;
            BuildAllSilent();
            EditorUtility.DisplayDialog("WildWeapon Mayhem",
                "Juego construido.\n\nEscenas: MainMenu (inicio) y Arena.\nDale Play desde MainMenu.", "OK");
        }

        public static string BuildAllSilent()
        {
            EnsureFolders();
            ImportArt();
            ConfigureRenderer2D();
            CleanupLegacy();

            _soft = EnsureSoftCircle();
            _panel = EnsureUiPanel();
            _shine = EnsureShine();
            _vignette = EnsureVignette();
            _ring = EnsureRing();
            _platShadow = EnsurePlatShadow();
            var slashWhite = EnsureWhiteSlash();
            _unlit = EnsureMaterial(MatDir + "/VFX_SpriteUnlit.mat", null);
            _particle = EnsureMaterial(MatDir + "/VFX_Particle.mat", _soft.texture);
            _trail = EnsureMaterial(MatDir + "/VFX_Trail.mat", Texture2D.whiteTexture);

            // ---------- Piezas del rig ----------
            var cyborg = new RigSet
            {
                head = Part("rig_cy_head", new Vector2(0.45f, 0.04f)),
                torso = Part("rig_cy_torso", new Vector2(0.5f, 0.03f)),
                upper = Part("rig_cy_upperarm", new Vector2(0.5f, 0.93f)),
                fore = Part("rig_cy_forearm", new Vector2(0.5f, 0.96f)),
                thigh = Part("rig_cy_thigh", new Vector2(0.5f, 0.95f)),
                shin = Part("rig_cy_shin", new Vector2(0.32f, 0.96f)),
            };
            var android = new RigSet
            {
                head = Part("rig_an_head", new Vector2(0.55f, 0.04f)),
                torso = cyborg.torso, upper = cyborg.upper, fore = cyborg.fore, thigh = cyborg.thigh, shin = cyborg.shin
            };
            var knight = new RigSet
            {
                head = Part("rig_kn_head", new Vector2(0.5f, 0.04f)),
                torso = Part("rig_kn_torso", new Vector2(0.5f, 0.03f)),
                upper = Part("rig_kn_upperarm", new Vector2(0.5f, 0.93f)),
                fore = Part("rig_kn_forearm", new Vector2(0.5f, 0.96f)),
                thigh = Part("rig_kn_thigh", new Vector2(0.5f, 0.95f)),
                shin = Part("rig_kn_shin", new Vector2(0.32f, 0.96f)),
            };
            var drone = new RigSet
            {
                drone = true,
                droneBody = Part("rig_dr_body", new Vector2(0.5f, 0.5f)),
                droneArm = Part("rig_dr_arm", new Vector2(0.5f, 0.96f)),
            };

            // ---------- VFX ----------
            var cyan = new Color(0.45f, 0.9f, 1f, 1f);
            var orange = new Color(1f, 0.55f, 0.18f, 1f);
            var magenta = new Color(1f, 0.3f, 0.9f, 1f);
            var yellow = new Color(1f, 0.88f, 0.25f, 1f);
            var grey = new Color(0.82f, 0.85f, 0.9f, 1f);

            var katSlash = BuildSlashVfx("VFX_Katana_Slash", Spr("ww_slash"), Color.white, cyan);
            var katHit = BuildHitVfx("VFX_Katana_Hit", cyan, Color.white, 20);
            var axeSlash = BuildSlashVfx("VFX_Hacha_Slash", slashWhite, grey, new Color(1f, 0.8f, 0.5f));
            var axeHit = BuildHitVfx("VFX_Hacha_Hit", new Color(1f, 0.75f, 0.4f), Color.white, 16);
            var hamSlash = BuildSlashVfx("VFX_Mazo_Slash", slashWhite, orange, orange);
            var hamHit = BuildHitVfx("VFX_Mazo_Hit", orange, yellow, 24);
            var spearHit = BuildHitVfx("VFX_Lanza_Hit", magenta, Color.white, 14);
            var sawSlash = BuildSlashVfx("VFX_Sierra_Slash", slashWhite, yellow, yellow);
            var sawHit = BuildHitVfx("VFX_Sierra_Hit", yellow, orange, 12);
            var botDeath = BuildDeathVfx("VFX_Bot_Death", orange, new Color(0.35f, 0.35f, 0.38f, 0.8f));
            var playerDeath = BuildDeathVfx("VFX_Player_Death", new Color(1f, 0.3f, 0.3f), new Color(0.3f, 0.3f, 0.35f, 0.7f));
            var spawnVfx = BuildSpawnVfx("VFX_Bot_Spawn", magenta);

            // ---------- Habilidades de la Katana (Q/E/R, doc §3) ----------
            // Placeholder de VFX: reusa los prefabs de la Katana hasta que llegue el lote de Aura.
            var abQ = Ability("katana_q_circular", "Corte Circular", AbilityKind.CircularSlash,
                20f, 6f, 0.5f, 0.3f, radius: 1.2f, stun: 0.4f,
                castVfx: katSlash, hitVfx: katHit);
            var abE = Ability("katana_e_dash", "Dash-Tajo", AbilityKind.DashSlash,
                26f, 7f, 0.7f, 0.17f, dash: 2.5f,
                castVfx: katSlash, hitVfx: katHit);
            var abR = Ability("katana_r_ocho", "Corte en 8 Direcciones", AbilityKind.RadialBurst,
                48f, 0.5f, 0.8f, 0.31f, projectiles: 8,
                castVfx: katSlash, hitVfx: katHit, adrenaline: 100f);

            // ---------- Armas (pivote en la mano) ----------
            var katana = Weapon("katana", "Katana", 12f, 0.35f, 1.15f, 120f, Spr("ww_katana"), 1.15f, 0f,
                SwingStyle.Slash, 150f, 0.13f, katSlash, katHit, true, cyan, 0.08f,
                abQ, abE, abR);
            var hacha = Weapon("hacha_gris", "Hacha Gris", 17f, 0.6f, 1.05f, 100f, Spr("ww_hacha"), 0.95f, 0f,
                SwingStyle.Slash, 130f, 0.17f, axeSlash, axeHit, true, new Color(1f, 0.85f, 0.6f, 0.8f), 0.12f);
            var mazo = Weapon("mazo_oxidado", "Mazo de Guerra", 22f, 1.6f, 1.3f, 140f, Spr("ww_weapon_hammer"), 1.25f, -0.05f,
                SwingStyle.Slash, 170f, 0.22f, hamSlash, hamHit, true, orange, 0.22f);
            var lanza = Weapon("lanza_plasma", "Lanza de Plasma", 11f, 0.9f, 1.75f, 40f, Spr("ww_weapon_spear"), 1.6f, -0.45f,
                SwingStyle.Thrust, 0f, 0.16f, null, spearHit, true, magenta, 0.07f);
            var sierra = Weapon("sierra_chatarra", "Sierra Giratoria", 6f, 0.45f, 0.9f, 200f, Spr("ww_weapon_saw"), 0.8f, 0f,
                SwingStyle.Spin, 0f, 0.22f, sawSlash, sawHit, false, yellow, 0.04f);

            // ---------- Animacion esqueletica ----------
            var charCtrl = BuildCharacterController();

            // ---------- Personajes ----------
            var playerPrefab = BuildPlayerPrefab("Player_Cyborg", cyborg, charCtrl, katana, hacha, playerDeath);

            var defSaw = BotData("bot_sierra", "Dron Sierra", sierra, 30f, 3.0f, 0.15f, 0.25f, 0.36f, 0.95f, 1.3f, yellow, botDeath);
            var defLan = BotData("bot_lancero", "Androide Lancero", lanza, 45f, 2.5f, 0.38f, 0.45f, 0.4f, 1.05f, 1.1f, new Color(0.62f, 0.38f, 1f), botDeath);
            var defBru = BotData("bot_bruto", "Caballero Pesado", mazo, 95f, 1.55f, 0.6f, 0.6f, 0.58f, 1.35f, 0.8f, new Color(0.9f, 0.3f, 0.25f), botDeath);
            var botSaw = BuildBotPrefab("Bot_Sierra", defSaw, drone, charCtrl);
            var botLan = BuildBotPrefab("Bot_Lancero", defLan, android, charCtrl);
            var botBru = BuildBotPrefab("Bot_Bruto", defBru, knight, charCtrl);

            // ---------- Mapas (4 chicos, 4 medianos, 4 grandes) ----------
            var catalog = BuildMapDefs();

            // ---------- Escenas ----------
            BuildArenaScene(catalog, playerPrefab, new[] { botSaw, botLan, botBru }, spawnVfx);
            BuildMenuScene();
            BuildMapSelectScene(catalog);
            // Personalizacion (previews + selector de color): escena aparte, lista para
            // colgar del menu cuando se decida donde va.
            BuildCharacterSelectScene(cyborg, charCtrl);

            EditorBuildSettings.scenes = new[]
            {
                new EditorBuildSettingsScene(MenuScenePath, true),
                new EditorBuildSettingsScene(MapSelectScenePath, true),
                new EditorBuildSettingsScene(ArenaScenePath, true),
                new EditorBuildSettingsScene(CharSelectScenePath, true)
            };

            AssetDatabase.SaveAssets();
            AssetDatabase.Refresh();
            EditorSceneManager.OpenScene(MenuScenePath);
            return "OK";
        }

        // =====================================================================
        // Arte
        // =====================================================================
        private static void EnsureFolders()
        {
            string[] dirs =
            {
                Root + "/Art", SpritesDir, RigDir, RigRawDir, VfxArtDir, MatDir, AnimDir, AnimDir + "/Character", AnimDir + "/Menu",
                Root + "/Audio", Root + "/Audio/Music",
                Root + "/Data", WeaponsDir, AbilitiesDir, BotsDataDir, MapsDir, PrefabDir, VfxPrefabDir, BotPrefabDir, CharPrefabDir, ScenesDir
            };
            foreach (var d in dirs) EnsureFolder(d);
        }

        private static void EnsureFolder(string path)
        {
            if (AssetDatabase.IsValidFolder(path)) return;
            string parent = Path.GetDirectoryName(path).Replace('\\', '/');
            EnsureFolder(parent);
            AssetDatabase.CreateFolder(parent, Path.GetFileName(path));
        }

        /// <summary>Borra el arte y los prefabs del concepto anterior (dojo / samurai) y de lotes de arte ya reemplazados.</summary>
        private static void CleanupLegacy()
        {
            string[] legacy =
            {
                SpritesDir + "/ww_player_blue.png", SpritesDir + "/ww_player_red.png",
                SpritesDir + "/ww_bot_brute.png", SpritesDir + "/ww_bot_lancer.png", SpritesDir + "/ww_bot_saw.png",
                SpritesDir + "/ww_menu_bg.png", SpritesDir + "/ww_floor.png",
                // Slabs compartidos del lote viejo: cada mapa ahora usa su propio ww_plat_<id>
                SpritesDir + "/ww_plat_chica.png", SpritesDir + "/ww_plat_mediana.png", SpritesDir + "/ww_plat_grande.png",
                CharPrefabDir + "/Player_Azul.prefab", CharPrefabDir + "/Player_Rojo.prefab",
                MapsDir + "/Patio_Dojo.asset", MapsDir + "/Arena_Central.asset"
            };
            foreach (var p in legacy)
                if (File.Exists(p)) AssetDatabase.DeleteAsset(p);
        }

        private struct ArtSpec
        {
            public string name; public Vector2 pivot; public bool tiled; public int maxSize; public float border; public float ppu;
            public ArtSpec(string n, Vector2 p, bool t = false, int m = 1024, float b = 0f, float u = 512f)
            { name = n; pivot = p; tiled = t; maxSize = m; border = b; ppu = u; }
        }

        private static readonly ArtSpec[] Art =
        {
            new ArtSpec("ww_katana", new Vector2(0.1f, 0.5f)),
            new ArtSpec("ww_hacha", new Vector2(0.1f, 0.5f)),
            new ArtSpec("ww_weapon_hammer", new Vector2(0.1f, 0.5f)),
            new ArtSpec("ww_weapon_spear", new Vector2(0.12f, 0.5f)),
            new ArtSpec("ww_weapon_saw", new Vector2(0.08f, 0.5f)),
            new ArtSpec("ww_slash", new Vector2(0.5f, 0.5f)),
            new ArtSpec("ww_prop_rock", new Vector2(0.5f, 0.12f), false, 512),
            new ArtSpec("ww_prop_crate", new Vector2(0.5f, 0.1f), false, 512),
            new ArtSpec("ww_prop_pillar", new Vector2(0.5f, 0.12f), false, 512),
            new ArtSpec("ww_prop_barrel", new Vector2(0.5f, 0.1f), false, 512),
            new ArtSpec("ww_decor_grass", new Vector2(0.5f, 0.5f), false, 256),
            new ArtSpec("ww_decor_bones", new Vector2(0.5f, 0.5f), false, 256),
            new ArtSpec("ww_floor_neutral", new Vector2(0.5f, 0.5f), true),
            new ArtSpec("ww_wall", new Vector2(0.5f, 0.5f), true, 512),
            new ArtSpec("ww_logo", new Vector2(0.5f, 0.5f), false, 2048),
            new ArtSpec("ww_logo_burst", new Vector2(0.5f, 0.5f), false, 2048),
            new ArtSpec("ww_ui_count_3", new Vector2(0.5f, 0.5f), false, 512),
            new ArtSpec("ww_ui_count_2", new Vector2(0.5f, 0.5f), false, 512),
            new ArtSpec("ww_ui_count_1", new Vector2(0.5f, 0.5f), false, 512),
            new ArtSpec("ww_ui_count_go", new Vector2(0.5f, 0.5f), false, 512),
            new ArtSpec("ww_menu_bg_neutral", new Vector2(0.5f, 0.5f), false, 2048),
            new ArtSpec("ww_menu_card_skin", new Vector2(0.5f, 0.5f), false, 1024),
            new ArtSpec("ww_icon_duel", new Vector2(0.5f, 0.5f), false, 512),
            new ArtSpec("ww_icon_pvp", new Vector2(0.5f, 0.5f), false, 512),
            new ArtSpec("ww_icon_survival", new Vector2(0.5f, 0.5f), false, 512),
            new ArtSpec("ww_icon_exit", new Vector2(0.5f, 0.5f), false, 512),
            new ArtSpec("ww_menu_info_skin", new Vector2(0.5f, 0.5f), false, 1024),
            new ArtSpec("ww_menu_chip_skin", new Vector2(0.5f, 0.5f), false, 512),
            new ArtSpec("ww_lobby_panel", new Vector2(0.5f, 0.5f), false, 1024),
            new ArtSpec("ww_lobby_player_card", new Vector2(0.5f, 0.5f), false, 512),
            new ArtSpec("ww_lobby_button_add", new Vector2(0.5f, 0.5f), false, 256),
            new ArtSpec("ww_lobby_button_remove", new Vector2(0.5f, 0.5f), false, 256),
            new ArtSpec("ww_lobby_button_continue", new Vector2(0.5f, 0.5f), false, 256),
            new ArtSpec("ww_lobby_button_back", new Vector2(0.5f, 0.5f), false, 256),
            new ArtSpec("ww_lobby_title_banner", new Vector2(0.5f, 0.5f), false, 1024),
            new ArtSpec("ww_pvp_panel_skin", new Vector2(0.5f, 0.5f), false, 1024),
            new ArtSpec("ww_pvp_button_skin", new Vector2(0.5f, 0.5f), false, 512),
            new ArtSpec("ww_pvp_rule", new Vector2(0.5f, 0.5f), false, 512),
            new ArtSpec("ww_pvp_radar", new Vector2(0.5f, 0.5f), false, 512),
            new ArtSpec("ww_hud_panel_skin", new Vector2(0.5f, 0.5f), false, 1024),
            new ArtSpec("ww_hud_round_plate", new Vector2(0.5f, 0.5f), false, 1024),
            new ArtSpec("ww_hud_status_plate", new Vector2(0.5f, 0.5f), false, 1024),
            new ArtSpec("ww_hud_hp_track", new Vector2(0.5f, 0.5f), false, 1024),
            new ArtSpec("ww_hud_hp_fill", new Vector2(0.5f, 0.5f), false, 1024),
            new ArtSpec("ww_hud_pip", new Vector2(0.5f, 0.5f), false, 256),

            // ---- Arenas: un fondo por mapa (piso + decoracion horneada) ----
            new ArtSpec("ww_map_duela_bg", new Vector2(0.5f, 0.5f), false, 2048),
            new ArtSpec("ww_map_neon_bg", new Vector2(0.5f, 0.5f), false, 2048),
            new ArtSpec("ww_map_camara_bg", new Vector2(0.5f, 0.5f), false, 2048),
            new ArtSpec("ww_map_eco_bg", new Vector2(0.5f, 0.5f), false, 2048),
            new ArtSpec("ww_map_leviatan_bg", new Vector2(0.5f, 0.5f), false, 2048),
            new ArtSpec("ww_map_boveda_bg", new Vector2(0.5f, 0.5f), false, 2048),
            new ArtSpec("ww_map_nebula_bg", new Vector2(0.5f, 0.5f), false, 2048),
            new ArtSpec("ww_map_vivero_bg", new Vector2(0.5f, 0.5f), false, 2048),
            new ArtSpec("ww_map_templo_bg", new Vector2(0.5f, 0.5f), false, 2048),
            new ArtSpec("ww_map_domo_bg", new Vector2(0.5f, 0.5f), false, 2048),
            new ArtSpec("ww_map_mercado_bg", new Vector2(0.5f, 0.5f), false, 2048),
            new ArtSpec("ww_map_nucleo_bg", new Vector2(0.5f, 0.5f), false, 2048),

            // ---- Plataformas: un sprite propio por mapa (9-slice: se estira a la huella del deck) ----
            new ArtSpec("ww_plat_duela", new Vector2(0.5f, 0.5f), false, 1024, 110f, 320f),
            new ArtSpec("ww_plat_neon", new Vector2(0.5f, 0.5f), false, 1024, 110f, 320f),
            new ArtSpec("ww_plat_camara", new Vector2(0.5f, 0.5f), false, 1024, 110f, 320f),
            new ArtSpec("ww_plat_eco", new Vector2(0.5f, 0.5f), false, 1024, 110f, 320f),
            new ArtSpec("ww_plat_leviatan", new Vector2(0.5f, 0.5f), false, 1024, 110f, 320f),
            new ArtSpec("ww_plat_boveda", new Vector2(0.5f, 0.5f), false, 1024, 110f, 320f),
            new ArtSpec("ww_plat_nebula", new Vector2(0.5f, 0.5f), false, 1024, 110f, 320f),
            new ArtSpec("ww_plat_vivero", new Vector2(0.5f, 0.5f), false, 1024, 110f, 320f),
            new ArtSpec("ww_plat_templo", new Vector2(0.5f, 0.5f), false, 1024, 110f, 320f),
            new ArtSpec("ww_plat_domo", new Vector2(0.5f, 0.5f), false, 1024, 110f, 320f),
            new ArtSpec("ww_plat_mercado", new Vector2(0.5f, 0.5f), false, 1024, 110f, 320f),
            new ArtSpec("ww_plat_nucleo", new Vector2(0.5f, 0.5f), false, 1024, 110f, 320f),

            // ---- Props compartidos del nuevo lote ----
            new ArtSpec("ww_prop_chatarra", new Vector2(0.5f, 0.12f), false, 512),
            new ArtSpec("ww_prop_tuberia", new Vector2(0.5f, 0.12f), false, 512),
            new ArtSpec("ww_prop_contenedor", new Vector2(0.5f, 0.1f), false, 512),
            new ArtSpec("ww_prop_totem", new Vector2(0.5f, 0.1f), false, 512),
            new ArtSpec("ww_prop_escombro", new Vector2(0.5f, 0.12f), false, 512),
        };

        private static void ImportArt()
        {
            foreach (var a in Art)
            {
                string dst = $"{SpritesDir}/{a.name}.png";
                string src = $"{SrcImages}/{a.name}.png";
                if (!File.Exists(dst) && File.Exists(src))
                {
                    string err = AssetDatabase.MoveAsset(src, dst);
                    if (!string.IsNullOrEmpty(err)) Debug.LogWarning($"[WildWeapon] No se pudo mover {src}: {err}");
                }
                if (!File.Exists(dst)) { Debug.LogWarning($"[WildWeapon] Falta arte: {dst}"); continue; }
                if (a.border > 0f) ImportUiSprite(dst, a.border, a.ppu, a.maxSize);
                else ImportSprite(dst, a.pivot, a.ppu, a.maxSize, a.tiled);
            }
        }

        private static void ImportSprite(string path, Vector2 pivot, float ppu, int maxSize, bool tiled)
        {
            AssetDatabase.ImportAsset(path, ImportAssetOptions.ForceSynchronousImport);
            var imp = (TextureImporter)AssetImporter.GetAtPath(path);
            if (imp == null) return;
            imp.textureType = TextureImporterType.Sprite;
            imp.spriteImportMode = SpriteImportMode.Single;
            imp.alphaIsTransparency = true;
            imp.mipmapEnabled = false;
            imp.filterMode = FilterMode.Bilinear;
            imp.maxTextureSize = maxSize;
            imp.spritePixelsPerUnit = ppu;
            imp.wrapMode = tiled ? TextureWrapMode.Repeat : TextureWrapMode.Clamp;
            imp.textureCompression = TextureImporterCompression.CompressedHQ;

            var s = new TextureImporterSettings();
            imp.ReadTextureSettings(s);
            s.spriteAlignment = (int)SpriteAlignment.Custom;
            s.spritePivot = pivot;
            s.spriteMeshType = tiled ? SpriteMeshType.FullRect : SpriteMeshType.Tight;
            imp.SetTextureSettings(s);
            imp.SaveAndReimport();
        }

        private static Sprite Spr(string name) => AssetDatabase.LoadAssetAtPath<Sprite>($"{SpritesDir}/{name}.png");

        /// <summary>
        /// Pieza de rig: recorta el PNG al contenido y genera dos sprites:
        /// _base (la pieza completa) y _paint (solo las placas claras y poco saturadas, en gris),
        /// que se tiñe con el color del personaje.
        /// </summary>
        private static PartSpr Part(string name, Vector2 pivot)
        {
            string raw = $"{RigRawDir}/{name}.png";
            string src = $"{SrcImages}/{name}.png";
            if (!File.Exists(raw) && File.Exists(src)) AssetDatabase.MoveAsset(src, raw);

            string bp = $"{RigDir}/{name}_base.png";
            string pp = $"{RigDir}/{name}_paint.png";
            if (File.Exists(raw) && (!File.Exists(bp) || !File.Exists(pp)))
            {
                var tex = new Texture2D(2, 2, TextureFormat.RGBA32, false);
                tex.LoadImage(File.ReadAllBytes(raw));
                int w = tex.width, h = tex.height;
                var px = tex.GetPixels32();

                int x0 = w, y0 = h, x1 = -1, y1 = -1;
                for (int y = 0; y < h; y++)
                for (int x = 0; x < w; x++)
                {
                    if (px[y * w + x].a <= 24) continue;
                    if (x < x0) x0 = x; if (x > x1) x1 = x;
                    if (y < y0) y0 = y; if (y > y1) y1 = y;
                }
                if (x1 < 0) { x0 = 0; y0 = 0; x1 = w - 1; y1 = h - 1; }
                const int pad = 4;
                x0 = Mathf.Max(0, x0 - pad); y0 = Mathf.Max(0, y0 - pad);
                x1 = Mathf.Min(w - 1, x1 + pad); y1 = Mathf.Min(h - 1, y1 + pad);
                int cw = x1 - x0 + 1, ch = y1 - y0 + 1;

                var basePx = new Color32[cw * ch];
                var paintPx = new Color32[cw * ch];
                for (int y = 0; y < ch; y++)
                for (int x = 0; x < cw; x++)
                {
                    var c = px[(y0 + y) * w + (x0 + x)];
                    int i = y * cw + x;
                    basePx[i] = c;
                    Color.RGBToHSV(c, out _, out float sat, out float val);
                    if (c.a > 110 && sat < 0.2f && val > 0.5f)
                    {
                        byte l = (byte)Mathf.Clamp(val * 255f * 1.04f, 0f, 255f);
                        paintPx[i] = new Color32(l, l, l, c.a);
                    }
                    else paintPx[i] = new Color32(0, 0, 0, 0);
                }

                WritePng(bp, cw, ch, basePx);
                WritePng(pp, cw, ch, paintPx);
                Object.DestroyImmediate(tex);
            }

            if (!File.Exists(bp)) { Debug.LogWarning($"[WildWeapon] Falta pieza de rig: {name}"); return new PartSpr(); }
            ImportSprite(bp, pivot, 512f, 512, false);
            ImportSprite(pp, pivot, 512f, 512, false);
            return new PartSpr
            {
                b = AssetDatabase.LoadAssetAtPath<Sprite>(bp),
                p = AssetDatabase.LoadAssetAtPath<Sprite>(pp)
            };
        }

        private static void WritePng(string path, int w, int h, Color32[] px)
        {
            var t = new Texture2D(w, h, TextureFormat.RGBA32, false);
            t.SetPixels32(px);
            t.Apply();
            File.WriteAllBytes(path, t.EncodeToPNG());
            Object.DestroyImmediate(t);
            AssetDatabase.ImportAsset(path, ImportAssetOptions.ForceSynchronousImport);
        }

        private static void ConfigureRenderer2D()
        {
            var data = AssetDatabase.LoadAssetAtPath<ScriptableObject>("Assets/Settings/Renderer2D.asset");
            if (data == null) return;
            var so = new SerializedObject(data);
            var mode = so.FindProperty("m_TransparencySortMode");
            var axis = so.FindProperty("m_TransparencySortAxis");
            if (mode != null) mode.intValue = (int)TransparencySortMode.CustomAxis;
            if (axis != null) axis.vector3Value = new Vector3(0f, 1f, 0f);
            so.ApplyModifiedPropertiesWithoutUndo();
        }

        private static Sprite EnsureSoftCircle()
        {
            string path = VfxArtDir + "/soft_circle.png";
            if (!File.Exists(path))
            {
                const int n = 128;
                var px = new Color32[n * n];
                for (int y = 0; y < n; y++)
                for (int x = 0; x < n; x++)
                {
                    float dx = (x + 0.5f) / n * 2f - 1f, dy = (y + 0.5f) / n * 2f - 1f;
                    float a = Mathf.Clamp01(1f - Mathf.Sqrt(dx * dx + dy * dy));
                    a = a * a * (3f - 2f * a);
                    px[y * n + x] = new Color32(255, 255, 255, (byte)(a * 255));
                }
                WritePng(path, n, n, px);
            }
            ImportSprite(path, new Vector2(0.5f, 0.5f), 128f, 128, false);
            return AssetDatabase.LoadAssetAtPath<Sprite>(path);
        }

        /// <summary>Copia en blanco del arco de tajo para poder teñirlo por arma.</summary>
        private static Sprite EnsureWhiteSlash()
        {
            string src = $"{SpritesDir}/ww_slash.png";
            string dst = VfxArtDir + "/slash_white.png";
            if (!File.Exists(dst) && File.Exists(src))
            {
                var tex = new Texture2D(2, 2, TextureFormat.RGBA32, false);
                tex.LoadImage(File.ReadAllBytes(src));
                var px = tex.GetPixels32();
                for (int i = 0; i < px.Length; i++)
                {
                    var c = px[i];
                    byte lum = (byte)Mathf.Clamp(Mathf.Max(c.r, Mathf.Max(c.g, c.b)) * 1.15f, 0, 255);
                    px[i] = new Color32(255, 255, 255, (byte)Mathf.Min(c.a, lum));
                }
                WritePng(dst, tex.width, tex.height, px);
                Object.DestroyImmediate(tex);
            }
            ImportSprite(src, new Vector2(0.5f, 0.5f), 1024f, 1024, false);
            if (!File.Exists(dst)) return Spr("ww_slash");
            ImportSprite(dst, new Vector2(0.5f, 0.5f), 1024f, 512, false);
            return AssetDatabase.LoadAssetAtPath<Sprite>(dst);
        }

        /// <summary>Panel redondeado blanco (9-slice) para tarjetas, chips y botones.</summary>
        private static Sprite EnsureUiPanel()
        {
            string path = VfxArtDir + "/ui_panel.png";
            if (!File.Exists(path))
            {
                const int n = 128;
                const float r = 30f;
                var px = new Color32[n * n];
                for (int y = 0; y < n; y++)
                for (int x = 0; x < n; x++)
                {
                    float d = RoundedRectDistance(x + 0.5f, y + 0.5f, n, r);
                    float a = Mathf.Clamp01(0.5f - d);
                    px[y * n + x] = new Color32(255, 255, 255, (byte)(a * 255f));
                }
                WritePng(path, n, n, px);
            }
            ImportUiSprite(path, 42f, 128f);
            return AssetDatabase.LoadAssetAtPath<Sprite>(path);
        }

        /// <summary>Veta de luz suave y estirada: barre el logo para darle brillo.</summary>
        private static Sprite EnsureShine()
        {
            string path = VfxArtDir + "/ui_shine.png";
            if (!File.Exists(path))
            {
                const int w = 96, h = 420;
                var px = new Color32[w * h];
                for (int y = 0; y < h; y++)
                for (int x = 0; x < w; x++)
                {
                    float u = (x + 0.5f) / w * 2f - 1f;
                    float band = Mathf.Exp(-u * u * 15f);
                    float v = (y + 0.5f) / h * 2f - 1f;
                    float ends = Mathf.Clamp01(1f - v * v);
                    ends = ends * ends * (3f - 2f * ends);
                    px[y * w + x] = new Color32(255, 255, 255, (byte)(Mathf.Clamp01(band * ends) * 240f));
                }
                WritePng(path, w, h, px);
            }
            ImportSprite(path, new Vector2(0.5f, 0.5f), 128f, 1024, false);
            return AssetDatabase.LoadAssetAtPath<Sprite>(path);
        }

        /// <summary>Anillo suave blanco para ondas y golpes de los peligros de arena.</summary>
        private static Sprite EnsureRing()
        {
            string path = VfxArtDir + "/vfx_ring.png";
            if (!File.Exists(path))
            {
                const int n = 128;
                const float bandR = 0.34f;      // radio medio del anillo
                const float bandW = 0.075f;     // grosor
                var px = new Color32[n * n];
                for (int y = 0; y < n; y++)
                for (int x = 0; x < n; x++)
                {
                    float dx = (x + 0.5f) / n * 2f - 1f, dy = (y + 0.5f) / n * 2f - 1f;
                    float r = Mathf.Sqrt(dx * dx + dy * dy);
                    float d = Mathf.Abs(r - bandR) / bandW;
                    float a = Mathf.Clamp01(1f - d * d);
                    // La orilla de afuera se apaga antes para que se lea como onda.
                    if (r > bandR) a *= Mathf.Clamp01(1f - (r - bandR) / (bandW * 2.2f));
                    px[y * n + x] = new Color32(255, 255, 255, (byte)(Mathf.SmoothStep(0f, 1f, a) * 255f));
                }
                WritePng(path, n, n, px);
            }
            ImportSprite(path, new Vector2(0.5f, 0.5f), 128f, 256, false);
            return AssetDatabase.LoadAssetAtPath<Sprite>(path);
        }

        /// <summary>Mancha rectangular suave (sombra de las plataformas elevadas).</summary>
        private static Sprite EnsurePlatShadow()
        {
            string path = VfxArtDir + "/plat_shadow.png";
            if (!File.Exists(path))
            {
                const int w = 128, h = 64;
                const float feather = 11f;
                const float r = 20f;
                var px = new Color32[w * h];
                for (int y = 0; y < h; y++)
                for (int x = 0; x < w; x++)
                {
                    float d = RoundedRectDistance(x + 0.5f, y + 0.5f, w, h, r);
                    float a = Mathf.Clamp01(0.55f - d / feather);
                    px[y * w + x] = new Color32(0, 0, 0, (byte)(Mathf.SmoothStep(0f, 1f, a) * 255f));
                }
                WritePng(path, w, h, px);
            }
            ImportSprite(path, new Vector2(0.5f, 0.5f), 128f, 256, false);
            return AssetDatabase.LoadAssetAtPath<Sprite>(path);
        }

        /// <summary>Vineta radial negra (alpha creciente hacia los bordes) para el fondo.</summary>
        private static Sprite EnsureVignette()
        {
            string path = VfxArtDir + "/ui_vignette.png";
            if (!File.Exists(path))
            {
                const int n = 256;
                var px = new Color32[n * n];
                for (int y = 0; y < n; y++)
                for (int x = 0; x < n; x++)
                {
                    float dx = (x + 0.5f) / n * 2f - 1f;
                    float dy = (y + 0.5f) / n * 2f - 1f;
                    float r = Mathf.Sqrt(dx * dx + dy * dy);
                    float a = Mathf.SmoothStep(0f, 1f, Mathf.InverseLerp(0.44f, 1.02f, r));
                    px[y * n + x] = new Color32(0, 0, 0, (byte)(a * 255f));
                }
                WritePng(path, n, n, px);
            }
            ImportSprite(path, new Vector2(0.5f, 0.5f), 128f, 512, false);
            return AssetDatabase.LoadAssetAtPath<Sprite>(path);
        }

        /// <summary>Importa un sprite de UI con malla FullRect y borde de 9-slice.</summary>
        private static void ImportUiSprite(string path, float border, float ppu, int maxSize = 1024)
        {
            ImportSprite(path, new Vector2(0.5f, 0.5f), ppu, maxSize, true);
            var imp = (TextureImporter)AssetImporter.GetAtPath(path);
            if (imp == null) return;
            var s = new TextureImporterSettings();
            imp.ReadTextureSettings(s);
            s.spriteMeshType = SpriteMeshType.FullRect;
            s.spriteBorder = new Vector4(border, border, border, border);
            s.spritePixelsPerUnit = ppu;
            imp.SetTextureSettings(s);
            imp.SaveAndReimport();
        }

        /// <summary>Distancia con signo al borde de un rectangulo redondeado centrado (negativa adentro).</summary>
        private static float RoundedRectDistance(float x, float y, int n, float r) => RoundedRectDistance(x, y, n, n, r);

        private static float RoundedRectDistance(float x, float y, int w, int h, float r)
        {
            float hw = w * 0.5f, hh = h * 0.5f;
            float dx = Mathf.Abs(x - hw) - (hw - r);
            float dy = Mathf.Abs(y - hh) - (hh - r);
            float ox = Mathf.Max(dx, 0f), oy = Mathf.Max(dy, 0f);
            return Mathf.Sqrt(ox * ox + oy * oy) + Mathf.Min(Mathf.Max(dx, dy), 0f) - r;
        }

        private static Material EnsureMaterial(string path, Texture tex)
        {
            var mat = AssetDatabase.LoadAssetAtPath<Material>(path);
            var shader = Shader.Find("Universal Render Pipeline/2D/Sprite-Unlit-Default");
            if (shader == null) shader = Shader.Find("Sprites/Default");
            if (mat == null)
            {
                mat = new Material(shader);
                AssetDatabase.CreateAsset(mat, path);
            }
            mat.shader = shader;
            if (tex != null) mat.mainTexture = tex;
            EditorUtility.SetDirty(mat);
            return mat;
        }

        // =====================================================================
        // VFX
        // =====================================================================
        private static GameObject BuildSlashVfx(string name, Sprite arc, Color arcColor, Color sparkColor)
        {
            var root = new GameObject(name);
            var slash = root.AddComponent<SlashVfx>();

            var arcGo = new GameObject("Arc");
            arcGo.transform.SetParent(root.transform, false);
            var sr = arcGo.AddComponent<SpriteRenderer>();
            sr.sprite = arc;
            sr.color = arcColor;
            sr.sharedMaterial = _unlit;
            sr.sortingOrder = 20;
            slash.arc = sr;
            slash.life = 0.18f;

            var ps = Particles(root.transform, "Sparks", 12, new Vector2(0.15f, 0.35f), new Vector2(1.5f, 4f),
                new Vector2(0.04f, 0.1f), sparkColor, Color.white, 150f, 0.35f, 0f, 21);
            var shape = ps.shape;
            shape.rotation = new Vector3(0f, 0f, -75f);
            return SavePrefab(root, $"{VfxPrefabDir}/{name}.prefab");
        }

        private static GameObject BuildHitVfx(string name, Color a, Color b, int count)
        {
            var root = new GameObject(name);
            var auto = root.AddComponent<VfxAutoDestroy>();
            auto.life = 0.8f;

            var flash = new GameObject("Flash");
            flash.transform.SetParent(root.transform, false);
            var sr = flash.AddComponent<SpriteRenderer>();
            sr.sprite = _soft;
            sr.color = new Color(b.r, b.g, b.b, 0.9f);
            sr.sharedMaterial = _unlit;
            sr.sortingOrder = 22;
            auto.flash = sr;
            auto.flashScale = 1.1f;
            auto.flashTime = 0.12f;

            var ps = Particles(root.transform, "Sparks", count, new Vector2(0.15f, 0.4f), new Vector2(2.5f, 6.5f),
                new Vector2(0.05f, 0.13f), a, b, 110f, 0.05f, 0f, 23);
            var shape = ps.shape;
            shape.rotation = new Vector3(0f, 0f, -55f);
            var r = ps.GetComponent<ParticleSystemRenderer>();
            r.renderMode = ParticleSystemRenderMode.Stretch;
            r.velocityScale = 0.04f;
            r.lengthScale = 1.5f;
            return SavePrefab(root, $"{VfxPrefabDir}/{name}.prefab");
        }

        private static GameObject BuildDeathVfx(string name, Color sparks, Color smoke)
        {
            var root = new GameObject(name);
            var auto = root.AddComponent<VfxAutoDestroy>();
            auto.life = 1.6f;

            var flash = new GameObject("Flash");
            flash.transform.SetParent(root.transform, false);
            var sr = flash.AddComponent<SpriteRenderer>();
            sr.sprite = _soft;
            sr.color = new Color(1f, 0.9f, 0.7f, 0.95f);
            sr.sharedMaterial = _unlit;
            sr.sortingOrder = 22;
            auto.flash = sr;
            auto.flashScale = 2.4f;
            auto.flashTime = 0.18f;

            var s = Particles(root.transform, "Smoke", 10, new Vector2(0.6f, 1.1f), new Vector2(0.3f, 1.2f),
                new Vector2(0.5f, 0.9f), smoke, new Color(smoke.r * 0.7f, smoke.g * 0.7f, smoke.b * 0.7f, smoke.a), 360f, 0.2f, -0.05f, 19);
            var sm = s.main;
            sm.startRotation = new ParticleSystem.MinMaxCurve(0f, Mathf.PI * 2f);
            var sizeOl = s.sizeOverLifetime;
            sizeOl.size = new ParticleSystem.MinMaxCurve(1f, AnimationCurve.EaseInOut(0f, 0.5f, 1f, 1.4f));

            var p = Particles(root.transform, "Debris", 26, new Vector2(0.3f, 0.7f), new Vector2(2f, 6f),
                new Vector2(0.06f, 0.16f), sparks, Color.white, 360f, 0.1f, 0f, 23);
            var r = p.GetComponent<ParticleSystemRenderer>();
            r.renderMode = ParticleSystemRenderMode.Stretch;
            r.velocityScale = 0.05f;
            r.lengthScale = 1.2f;
            return SavePrefab(root, $"{VfxPrefabDir}/{name}.prefab");
        }

        private static GameObject BuildSpawnVfx(string name, Color c)
        {
            var root = new GameObject(name);
            var auto = root.AddComponent<VfxAutoDestroy>();
            auto.life = 1.2f;

            var flash = new GameObject("Ring");
            flash.transform.SetParent(root.transform, false);
            var sr = flash.AddComponent<SpriteRenderer>();
            sr.sprite = _soft;
            sr.color = new Color(c.r, c.g, c.b, 0.8f);
            sr.sharedMaterial = _unlit;
            sr.sortingOrder = -5;
            auto.flash = sr;
            auto.flashScale = 1.8f;
            auto.flashTime = 0.5f;

            var ps = Particles(root.transform, "Rise", 24, new Vector2(0.4f, 0.8f), new Vector2(0.5f, 2f),
                new Vector2(0.05f, 0.12f), c, Color.white, 360f, 0.5f, -0.4f, 21);
            var sh = ps.shape;
            sh.radiusThickness = 0f;
            return SavePrefab(root, $"{VfxPrefabDir}/{name}.prefab");
        }

        private static ParticleSystem Particles(Transform parent, string name, int count, Vector2 life, Vector2 speed,
            Vector2 size, Color a, Color b, float arc, float radius, float gravity, int order)
        {
            var go = new GameObject(name);
            go.transform.SetParent(parent, false);
            var ps = go.AddComponent<ParticleSystem>();
            ps.Stop(true, ParticleSystemStopBehavior.StopEmittingAndClear);

            var main = ps.main;
            main.duration = 0.4f;
            main.loop = false;
            main.playOnAwake = true;
            main.startLifetime = new ParticleSystem.MinMaxCurve(life.x, life.y);
            main.startSpeed = new ParticleSystem.MinMaxCurve(speed.x, speed.y);
            main.startSize = new ParticleSystem.MinMaxCurve(size.x, size.y);
            main.startColor = new ParticleSystem.MinMaxGradient(a, b);
            main.gravityModifier = gravity;
            main.simulationSpace = ParticleSystemSimulationSpace.World;
            main.maxParticles = 128;

            var em = ps.emission;
            em.rateOverTime = 0f;
            em.SetBursts(new[] { new ParticleSystem.Burst(0f, (short)count) });

            var shape = ps.shape;
            shape.enabled = true;
            shape.shapeType = ParticleSystemShapeType.Circle;
            shape.radius = Mathf.Max(0.01f, radius);
            shape.arc = arc;

            var col = ps.colorOverLifetime;
            col.enabled = true;
            var g = new Gradient();
            g.SetKeys(new[] { new GradientColorKey(Color.white, 0f), new GradientColorKey(Color.white, 1f) },
                new[] { new GradientAlphaKey(1f, 0f), new GradientAlphaKey(0.8f, 0.5f), new GradientAlphaKey(0f, 1f) });
            col.color = g;

            var sol = ps.sizeOverLifetime;
            sol.enabled = true;
            sol.size = new ParticleSystem.MinMaxCurve(1f, AnimationCurve.Linear(0f, 1f, 1f, 0.1f));

            var limit = ps.limitVelocityOverLifetime;
            limit.enabled = true;
            limit.dampen = 0.15f;
            limit.limit = 0.5f;

            var r = go.GetComponent<ParticleSystemRenderer>();
            r.sharedMaterial = _particle;
            r.sortingOrder = order;
            r.renderMode = ParticleSystemRenderMode.Billboard;
            return ps;
        }

        // =====================================================================
        // Datos
        // =====================================================================
        private static WeaponDef Weapon(string file, string display, float dmg, float cadence, float range, float arc,
            Sprite sprite, float length, float offset, SwingStyle style, float swingAngle, float swingTime,
            GameObject swingVfx, GameObject hitVfx, bool trail, Color trailColor, float shake,
            AbilityDef abilityQ = null, AbilityDef abilityE = null, AbilityDef abilityR = null)
        {
            string path = $"{WeaponsDir}/{file}.asset";
            var def = AssetDatabase.LoadAssetAtPath<WeaponDef>(path);
            bool created = def == null;
            if (created) def = ScriptableObject.CreateInstance<WeaponDef>();

            def.displayName = display;
            def.damage = dmg;
            def.cadence = cadence;
            def.range = range;
            def.arcDegrees = arc;
            def.sprite = sprite;
            def.spriteLength = length;
            def.bladeOffset = offset;
            def.color = Color.white;
            def.swingStyle = style;
            def.swingAngle = swingAngle;
            def.swingDuration = swingTime;
            def.swingVfx = swingVfx;
            def.hitVfx = hitVfx;
            def.trail = trail;
            def.trailColor = trailColor;
            def.shakeOnHit = shake;
            def.abilityQ = abilityQ;
            def.abilityE = abilityE;
            def.abilityR = abilityR;

            if (created) AssetDatabase.CreateAsset(def, path);
            else EditorUtility.SetDirty(def);
            return def;
        }

        private static AbilityDef Ability(string file, string display, AbilityKind kind,
            float damage, float cooldown, float cast, float windupFraction,
            float radius = 0f, float stun = 0f, float dash = 0f, int projectiles = 0,
            GameObject castVfx = null, GameObject hitVfx = null, float adrenaline = 0f)
        {
            string path = $"{AbilitiesDir}/{file}.asset";
            var def = AssetDatabase.LoadAssetAtPath<AbilityDef>(path);
            bool created = def == null;
            if (created) def = ScriptableObject.CreateInstance<AbilityDef>();

            def.abilityName = display;
            def.kind = kind;
            def.damage = damage;
            def.cooldown = cooldown;
            def.castDuration = cast;
            def.windupFraction = windupFraction;
            def.radius = radius;
            def.stunSeconds = stun;
            def.dashDistance = dash;
            def.projectileCount = projectiles;
            def.adrenalineCost = adrenaline;
            def.castVfx = castVfx;
            def.hitVfx = hitVfx;

            if (created) AssetDatabase.CreateAsset(def, path);
            else EditorUtility.SetDirty(def);
            return def;
        }

        private static BotDef BotData(string file, string display, WeaponDef weapon, float hp, float speed,
            float windup, float recover, float radius, float scale, float animSpeed, Color tint, GameObject death)
        {
            string path = $"{BotsDataDir}/{file}.asset";
            var def = AssetDatabase.LoadAssetAtPath<BotDef>(path);
            bool created = def == null;
            if (created) def = ScriptableObject.CreateInstance<BotDef>();
            def.displayName = display;
            def.weapon = weapon;
            def.hp = hp;
            def.moveSpeed = speed;
            def.windup = windup;
            def.recover = recover;
            def.bodyRadius = radius;
            def.visualScale = scale;
            def.animSpeed = animSpeed;
            def.tint = tint;
            def.deathVfx = death;
            if (created) AssetDatabase.CreateAsset(def, path);
            else EditorUtility.SetDirty(def);
            return def;
        }

        // =====================================================================
        // Mapas: 4 chicos + 4 medianos + 4 grandes (MapDefs + MapCatalog)
        // =====================================================================

        /// <summary>Plantilla de prop de arena (tamano, collider y si se puede pisar).</summary>
        private class PropTpl
        {
            public string sprite, label;
            public float size = 1.4f;
            public float radius = 0.33f;
            public float height;      // > 0 = techo pisable (plataforma improvisada)
            public bool decor;
        }

        private static readonly PropTpl[] PropTemplates =
        {
            new PropTpl { sprite = "ww_prop_rock", label = "Roca", size = 1.6f, radius = 0.36f },
            new PropTpl { sprite = "ww_prop_crate", label = "Caja", size = 1.4f, radius = 0.34f, height = 0.55f },
            new PropTpl { sprite = "ww_prop_pillar", label = "Pilar", size = 1.5f, radius = 0.3f },
            new PropTpl { sprite = "ww_prop_barrel", label = "Barril", size = 1.1f, radius = 0.33f, height = 0.5f },
            new PropTpl { sprite = "ww_prop_chatarra", label = "Chatarra", size = 1.35f, radius = 0.32f, height = 0.45f },
            new PropTpl { sprite = "ww_prop_tuberia", label = "Tuberia", size = 1.5f, radius = 0.3f, height = 0.5f },
            new PropTpl { sprite = "ww_prop_contenedor", label = "Contenedor", size = 1.75f, radius = 0.33f, height = 0.75f },
            new PropTpl { sprite = "ww_prop_totem", label = "Totem", size = 1.2f, radius = 0.26f },
            new PropTpl { sprite = "ww_prop_escombro", label = "Escombro", size = 1.3f, radius = 0.34f, height = 0.4f },
            new PropTpl { sprite = "ww_decor_grass", label = "Hierba", size = 0.9f, radius = 0f, decor = true },
            new PropTpl { sprite = "ww_decor_bones", label = "Restos", size = 1.2f, radius = 0f, decor = true },
        };

        /// <summary>Ficha de un mapa del lote: identidad, paleta y contenido de arena.</summary>
        private class MapTheme
        {
            public string id, name, sub, note;
            public MapSizeClass size;
            public Color accent, bg, floorTint = Color.white, wallTint = Color.white, propTint = Color.white;
            [Tooltip("Fraccion del encuadre que ocupa la arena (el resto es entorno del fondo)")]
            public float backdropFraction = 0.66f;
            public MapPlatform[] platforms;
            [Tooltip("Cantidad objetivo de plataformas (0 = usar platforms.Length). Se rellena proceduralmente si hace falta.")]
            public int platformCount = 0;
            public MapHazard[] hazards;
            public string[] obstacles, decor;
            public int obstacleCount, decorCount, botSpawns;
        }

        /// <summary>Crea/actualiza los 12 MapDef y el MapCatalog. Devuelve el catalogo.</summary>
        private static MapCatalog BuildMapDefs()
        {
            var themes = MapThemes();
            var maps = new MapDef[themes.Length];

            for (int i = 0; i < themes.Length; i++)
            {
                var t = themes[i];
                string path = $"{MapsDir}/Map_{t.id}.asset";
                var def = AssetDatabase.LoadAssetAtPath<MapDef>(path);
                bool created = def == null;
                if (created) def = ScriptableObject.CreateInstance<MapDef>();

                Fill(def, t, i);

                if (created) AssetDatabase.CreateAsset(def, path);
                else EditorUtility.SetDirty(def);
                maps[i] = def;
            }

            var catalog = AssetDatabase.LoadAssetAtPath<MapCatalog>(CatalogPath);
            bool newCatalog = catalog == null;
            if (newCatalog) catalog = ScriptableObject.CreateInstance<MapCatalog>();
            catalog.maps = maps;
            if (newCatalog) AssetDatabase.CreateAsset(catalog, CatalogPath);
            else EditorUtility.SetDirty(catalog);

            return catalog;
        }

        private static MapDef Fill(MapDef def, MapTheme t, int index)
        {
            var arena = ArenaSize(t.size);

            def.mapId = t.id;
            def.displayName = t.name;
            def.subtitle = t.sub;
            def.decorNote = t.note;
            def.sizeClass = t.size;
            def.accent = t.accent;
            def.arenaSize = arena;
            def.backgroundColor = t.bg;

            def.floorSprite = Spr("ww_map_" + t.id + "_bg");
            def.previewSprite = def.floorSprite;
            def.floorSingle = true;
            def.floorTileSize = 4.5f;
            def.floorTint = t.floorTint;
            def.backdropArenaFraction = t.backdropFraction;

            // Los muros quedan solo como collider: el entorno del fondo ya muestra el borde del lugar.
            def.wallSprite = null;
            def.wallThickness = 0.8f;
            def.wallTileSize = 1.6f;
            def.wallTint = t.wallTint;

            def.platformSprite = Spr("ww_plat_" + t.id);
            def.platformShadow = _platShadow;
            def.platformTint = 1f;
            // Etapa 2: cantidad de plataformas segun tipo (7/12/20) + reubicacion al nuevo tamano (centros x2).
var platList = new List<MapPlatform>(t.platforms != null ? t.platforms : new MapPlatform[0]);
int targetCount = t.platformCount > 0 ? t.platformCount : platList.Count;
if (targetCount > platList.Count)
{
    var rng = new System.Random(1000 + index * 37 + 7);
    var halfArena = arena * 0.5f;
    int attempts = 0;
    while (platList.Count < targetCount && attempts < 500)
    {
        attempts++;
        float x = (float)(rng.NextDouble() * 2.0 - 1.0) * (halfArena.x - 2.5f);
        float y = (float)(rng.NextDouble() * 2.0 - 1.0) * (halfArena.y - 2.0f);
        if (Mathf.Abs(x) < 2f && Mathf.Abs(y) < 1.5f) continue;   // evita zona de spawns
        bool tooClose = false;
        foreach (var pl in platList)
            if (Vector2.Distance(new Vector2(x, y), pl.center) < 3.5f) { tooClose = true; break; }
        if (tooClose) continue;
        float[] heights = { 0.55f, 0.95f, 1.35f };
        float height = heights[rng.Next(heights.Length)];
        float w = 3.0f + (float)rng.NextDouble() * 2.0f;
        float h = 1.8f + (float)rng.NextDouble() * 1.0f;
        platList.Add(new MapPlatform
        {
            sizeClass = MapPlatformSize.Mediana, center = new Vector2(x, y),
            size = new Vector2(w, h), height = height, mirrored = false,
            name = height >= 1.2f ? "Alta" : (height >= 0.8f ? "Media" : "Baja"),
        });
    }
}
var scaledPlats = new MapPlatform[platList.Count];
for (int i = 0; i < platList.Count; i++)
{
    var p = platList[i];
    scaledPlats[i] = new MapPlatform
    {
        name = p.name, sizeClass = p.sizeClass,
        center = p.center * 2f,
        size = p.size,
        height = p.height, mirrored = p.mirrored, rotation = p.rotation,
    };
}
def.platforms = scaledPlats;

            def.obstacles = Obstacles(t.obstacles, t.propTint);
            def.obstacleCount = t.obstacleCount;
            def.minObstacleSpacing = 2.2f;

            def.decor = Decor(t.decor, t.propTint);
            def.decorCount = t.decorCount;

            def.hazards = t.hazards != null ? t.hazards : new MapHazard[0];

            def.seed = 1000 + index * 37;
            def.randomSeedEachMatch = true;
            def.mirroredForDuel = true;
            def.spawnClearRadius = 2.6f;

            var half = arena * 0.5f;
            def.p1Spawn = new Vector2(-half.x * 0.6f, 0f);
            def.p2Spawn = new Vector2(half.x * 0.6f, 0f);
            def.botSpawnPoints = t.botSpawns;
            return def;
        }

        private static Vector2 ArenaSize(MapSizeClass size)
        {
            // Etapa 2: arenas ampliadas (x2) para espacio de plataformas/contenido futuro (multijugador).
            switch (size)
            {
                case MapSizeClass.Chico: return new Vector2(32f, 18f);
                case MapSizeClass.Grande: return new Vector2(48f, 26f);
                default: return new Vector2(40f, 22f);
            }
        }

        private static PropTpl Tpl(string sprite)
        {
            foreach (var p in PropTemplates)
                if (p.sprite == sprite) return p;
            return PropTemplates[0];
        }

        private static MapProp[] Obstacles(string[] sprites, Color tint)
        {
            var list = new List<MapProp>();
            if (sprites == null) return list.ToArray();
            foreach (var s in sprites)
            {
                var t = Tpl(s);
                list.Add(new MapProp
                {
                    name = t.label, sprite = Spr(t.sprite), size = t.size, solid = true,
                    colliderRadius = t.radius, weight = 1f, height = t.height, tint = tint,
                });
            }
            return list.ToArray();
        }

        private static MapProp[] Decor(string[] sprites, Color tint)
        {
            var list = new List<MapProp>();
            if (sprites == null) return list.ToArray();
            foreach (var s in sprites)
            {
                var t = Tpl(s);
                list.Add(new MapProp
                {
                    name = t.label, sprite = Spr(t.sprite), size = t.size, solid = false,
                    colliderRadius = 0f, weight = 1f, height = 0f, tint = tint,
                    sizeJitter = new Vector2(0.75f, 1.2f),
                });
            }
            return list.ToArray();
        }

        private static MapPlatform Plat(MapPlatformSize size, Vector2 center, Vector2 footprint, float height, bool mirrored = true)
        {
            return new MapPlatform
            {
                sizeClass = size, center = center, size = footprint,
                height = height, mirrored = mirrored, name = height >= 1.2f ? "Alta" : (height >= 0.8f ? "Media" : "Baja"),
            };
        }

        private static MapHazard Haz(HazardKind kind, string name, Vector2 center, Vector2 size,
            float damage, float interval, Color color, float telegraph = 1f, float active = 0.5f,
            float knockback = 3f, float maxHeight = 0.5f, bool mirrored = false, float phase = 0f)
        {
            return new MapHazard
            {
                name = name, kind = kind, center = center, size = size, damage = damage,
                interval = interval, telegraph = telegraph, active = active, knockback = knockback,
                maxHeight = maxHeight, color = color, mirrored = mirrored, phase = phase,
            };
        }

        /// <summary>
        /// Las 12 arenas: chicas (duelos rapidos), medianas y grandes (supervivencia).
        /// Cada mapa reparte sus propios decks (chico 3, mediano 5, grande 9) con su sprite ww_plat_&lt;id&gt;.
        /// El deck central va con mirrored=false para no duplicarse; los pares laterales se espejan a 180 grados.
        /// Peligros, decoracion y obstaculos quedan vacios por ahora: vuelven mas adelante.
        /// </summary>
        private static MapTheme[] MapThemes()
        {
            var rust = new Color(1f, 0.55f, 0.20f);
            var gold = new Color(1f, 0.80f, 0.25f);
            var ice = new Color(0.55f, 0.85f, 1f);
            var violet = new Color(0.72f, 0.45f, 1f);

            return new[]
            {
                // ---------------- CHICAS (32 x 18) ----------------
                new MapTheme
                {
                    id = "duela", name = "Duela de Chatarra", sub = "DUELO SOBRE TABLAS ROTAS",
                    size = MapSizeClass.Chico, accent = rust, bg = new Color(0.09f, 0.06f, 0.04f),
                    floorTint = new Color(1f, 0.96f, 0.9f), wallTint = new Color(0.9f, 0.85f, 0.78f), backdropFraction = 0.68f,
                    note = "Tablones hundidos, sierras oxidadas y pilas de chatarra del primer prototipo",
                    botSpawns = 12, platformCount = 7,
                    platforms = new[]
                    {
                        Plat(MapPlatformSize.Chica, new Vector2(0f, 0f), new Vector2(3.6f, 2f), 0.95f, false),
                        Plat(MapPlatformSize.Chica, new Vector2(5f, 2.6f), new Vector2(3.8f, 2f), 0.55f),
                    },
                },
                new MapTheme
                {
                    id = "neon", name = "Balcon de Neon", sub = "LUZ QUE CORTA",
                    size = MapSizeClass.Chico, accent = new Color(1f, 0.35f, 0.85f), bg = new Color(0.06f, 0.03f, 0.10f),
                    floorTint = new Color(0.92f, 0.9f, 1f), wallTint = new Color(0.8f, 0.76f, 1f), backdropFraction = 0.66f,
                    note = "Balcones de hotel, carteles de neon y cables sueltos sobre el pavimento mojado",
                    botSpawns = 12, platformCount = 7,
                    platforms = new[]
                    {
                        Plat(MapPlatformSize.Chica, new Vector2(0f, 0f), new Vector2(3.4f, 1.8f), 0.55f, false),
                        Plat(MapPlatformSize.Mediana, new Vector2(4.8f, -2.4f), new Vector2(4.2f, 2.2f), 0.95f),
                    },
                },
                new MapTheme
                {
                    id = "camara", name = "Camara Fria", sub = "NO TE CONGELES",
                    size = MapSizeClass.Chico, accent = ice, bg = new Color(0.05f, 0.08f, 0.11f),
                    floorTint = new Color(0.9f, 0.97f, 1f), wallTint = new Color(0.82f, 0.92f, 1f), backdropFraction = 0.64f,
                    note = "Camara de congelados: ganchos, cajas apiladas y escarcha en el piso",
                    botSpawns = 12, platformCount = 7,
                    platforms = new[]
                    {
                        Plat(MapPlatformSize.Chica, new Vector2(0f, 0f), new Vector2(4f, 1.8f), 0.95f, false),
                        Plat(MapPlatformSize.Chica, new Vector2(5.2f, 2.6f), new Vector2(3.6f, 2f), 0.55f),
                    },
                },
                new MapTheme
                {
                    id = "eco", name = "Pozo del Eco", sub = "EL POZO RESPONDE",
                    size = MapSizeClass.Chico, accent = new Color(0.3f, 1f, 0.85f), bg = new Color(0.03f, 0.07f, 0.08f),
                    floorTint = new Color(0.88f, 1f, 0.98f), wallTint = new Color(0.78f, 0.96f, 0.92f), backdropFraction = 0.71f,
                    note = "Pozo seco con paredes de piedra tallada y ecos que empujan desde el centro",
                    botSpawns = 12, platformCount = 7,
                    platforms = new[]
                    {
                        Plat(MapPlatformSize.Chica, new Vector2(0f, 0f), new Vector2(3.6f, 2.1f), 0.55f, false),
                        Plat(MapPlatformSize.Chica, new Vector2(5.3f, -2.5f), new Vector2(3.4f, 2f), 1.35f),
                    },
                },

                // ---------------- MEDIANAS (40 x 22) ----------------
                new MapTheme
                {
                    id = "leviatan", name = "Fosa Leviatan", sub = "ALGO GRANDE MURIO ACA",
                    size = MapSizeClass.Mediano, accent = new Color(0.7f, 0.85f, 0.35f), bg = new Color(0.05f, 0.06f, 0.04f),
                    floorTint = new Color(0.95f, 0.96f, 0.88f), wallTint = new Color(0.86f, 0.88f, 0.78f), backdropFraction = 0.68f,
                    note = "Costillas de un leviatan, charcos de acido y huesos usados como rampas",
                    botSpawns = 14, platformCount = 12,
                    platforms = new[]
                    {
                        Plat(MapPlatformSize.Mediana, new Vector2(0f, 0f), new Vector2(4.6f, 2.4f), 0.95f, false),
                        Plat(MapPlatformSize.Chica, new Vector2(6.4f, 3f), new Vector2(3.6f, 2f), 0.55f),
                        Plat(MapPlatformSize.Chica, new Vector2(6.6f, -2.8f), new Vector2(3.8f, 2f), 1.35f),
                    },
                },
                new MapTheme
                {
                    id = "boveda", name = "Boveda Dorada", sub = "LLUVIA DE MAYHEMCOINS",
                    size = MapSizeClass.Mediano, accent = gold, bg = new Color(0.09f, 0.07f, 0.03f),
                    floorTint = new Color(1f, 0.97f, 0.88f), wallTint = new Color(1f, 0.92f, 0.72f), backdropFraction = 0.68f,
                    note = "Boveda de banco: lingotes, cajas fuertes y una puerta que baja como guillotina",
                    botSpawns = 14, platformCount = 12,
                    platforms = new[]
                    {
                        Plat(MapPlatformSize.Mediana, new Vector2(0f, 0f), new Vector2(4.8f, 2.2f), 0.95f, false),
                        Plat(MapPlatformSize.Chica, new Vector2(7f, 2.6f), new Vector2(3.6f, 2.2f), 0.55f),
                        Plat(MapPlatformSize.Chica, new Vector2(6.8f, -2.9f), new Vector2(3.6f, 2f), 1.35f),
                    },
                },
                new MapTheme
                {
                    id = "nebula", name = "Chatarra Nebula", sub = "VIENTO Y CABLE PELADO",
                    size = MapSizeClass.Mediano, accent = new Color(0.6f, 0.75f, 1f), bg = new Color(0.04f, 0.05f, 0.09f),
                    floorTint = new Color(0.94f, 0.96f, 1f), wallTint = new Color(0.86f, 0.9f, 1f), backdropFraction = 0.67f,
                    note = "Desguace orbital: turbinas que barren la arena y cables de alta tension",
                    botSpawns = 14, platformCount = 12,
                    platforms = new[]
                    {
                        Plat(MapPlatformSize.Mediana, new Vector2(0f, 0f), new Vector2(5.2f, 2.2f), 0.95f, false),
                        Plat(MapPlatformSize.Chica, new Vector2(6.8f, 3f), new Vector2(3.6f, 2f), 0.55f),
                        Plat(MapPlatformSize.Mediana, new Vector2(6.6f, -2.8f), new Vector2(4.4f, 2.4f), 1.35f),
                    },
                },
                new MapTheme
                {
                    id = "vivero", name = "Vivero Mutante", sub = "LAS ESPORAS NO PERDONAN",
                    size = MapSizeClass.Mediano, accent = new Color(0.5f, 1f, 0.5f), bg = new Color(0.04f, 0.07f, 0.04f),
                    floorTint = new Color(0.92f, 1f, 0.9f), wallTint = new Color(0.8f, 0.95f, 0.8f), backdropFraction = 0.66f,
                    note = "Invernadero tomado por enredaderas, macetas gigantes y esporas a media altura",
                    botSpawns = 14, platformCount = 12,
                    platforms = new[]
                    {
                        Plat(MapPlatformSize.Mediana, new Vector2(0f, 0f), new Vector2(4.4f, 2.2f), 0.55f, false),
                        Plat(MapPlatformSize.Chica, new Vector2(6.8f, 2.9f), new Vector2(3.8f, 2.2f), 0.95f),
                        Plat(MapPlatformSize.Chica, new Vector2(6.8f, -2.9f), new Vector2(3.6f, 2f), 0.55f),
                    },
                },

                // ---------------- GRANDES (48 x 26) ----------------
                new MapTheme
                {
                    id = "templo", name = "Templo Hundido", sub = "EL AGUA SUBE Y BAJA",
                    size = MapSizeClass.Grande, accent = new Color(0.35f, 0.9f, 0.95f), bg = new Color(0.03f, 0.06f, 0.08f),
                    floorTint = new Color(0.9f, 0.98f, 1f), wallTint = new Color(0.8f, 0.92f, 0.95f), backdropFraction = 0.68f,
                    note = "Templo inundado: columnas caidas, pasarelas de piedra y estatuas sumergidas",
                    botSpawns = 18, platformCount = 20,
                    platforms = new[]
                    {
                        Plat(MapPlatformSize.Mediana, new Vector2(0f, 0f), new Vector2(5f, 2.4f), 0.95f, false),
                        Plat(MapPlatformSize.Grande, new Vector2(0f, 4.3f), new Vector2(6.6f, 2.2f), 0.55f),
                        Plat(MapPlatformSize.Mediana, new Vector2(8.2f, 3.2f), new Vector2(4.6f, 2.4f), 0.95f),
                        Plat(MapPlatformSize.Chica, new Vector2(8.8f, -3.3f), new Vector2(3.8f, 2f), 0.55f),
                        Plat(MapPlatformSize.Chica, new Vector2(8.8f, 0f), new Vector2(3.6f, 2.6f), 1.35f),
                    },
                },
                new MapTheme
                {
                    id = "domo", name = "Domo de Hielo", sub = "FRENAR ES MORIR",
                    size = MapSizeClass.Grande, accent = ice, bg = new Color(0.05f, 0.08f, 0.12f),
                    floorTint = new Color(0.92f, 0.98f, 1f), wallTint = new Color(0.84f, 0.94f, 1f), backdropFraction = 0.7f,
                    note = "Domo polar: grietas, ventiscas laterales y rafagas que cruzan la cancha",
                    botSpawns = 18, platformCount = 20,
                    platforms = new[]
                    {
                        Plat(MapPlatformSize.Mediana, new Vector2(0f, 0f), new Vector2(5.2f, 2.4f), 0.95f, false),
                        Plat(MapPlatformSize.Grande, new Vector2(0f, 4.3f), new Vector2(6.6f, 2.2f), 0.55f),
                        Plat(MapPlatformSize.Mediana, new Vector2(8.4f, 3.4f), new Vector2(4.6f, 2.4f), 0.95f),
                        Plat(MapPlatformSize.Chica, new Vector2(8.8f, -3.4f), new Vector2(3.6f, 2f), 0.55f),
                        Plat(MapPlatformSize.Chica, new Vector2(8.8f, 0f), new Vector2(3.6f, 2.4f), 1.35f),
                    },
                },
                new MapTheme
                {
                    id = "mercado", name = "Mercado del Caos", sub = "OFERTAS QUE EXPLOTAN",
                    size = MapSizeClass.Grande, accent = new Color(1f, 0.6f, 0.2f), bg = new Color(0.08f, 0.05f, 0.04f),
                    floorTint = new Color(1f, 0.95f, 0.88f), wallTint = new Color(0.95f, 0.86f, 0.76f), backdropFraction = 0.67f,
                    note = "Mercado nocturno: puestos incendiados, toneles de aceite y monedas por el piso",
                    botSpawns = 18, platformCount = 20,
                    platforms = new[]
                    {
                        Plat(MapPlatformSize.Mediana, new Vector2(0f, 0f), new Vector2(4.8f, 2.4f), 0.55f, false),
                        Plat(MapPlatformSize.Grande, new Vector2(0f, 4.2f), new Vector2(7f, 2.2f), 0.55f),
                        Plat(MapPlatformSize.Mediana, new Vector2(8.2f, 3.2f), new Vector2(4.8f, 2.4f), 0.95f),
                        Plat(MapPlatformSize.Chica, new Vector2(8.8f, -3.3f), new Vector2(3.6f, 2f), 0.55f),
                        Plat(MapPlatformSize.Chica, new Vector2(8.8f, 0f), new Vector2(3.6f, 2.6f), 1.35f),
                    },
                },
                new MapTheme
                {
                    id = "nucleo", name = "Nucleo Overdrive", sub = "TOCA EL NUCLEO Y CORRE",
                    size = MapSizeClass.Grande, accent = violet, bg = new Color(0.05f, 0.03f, 0.09f),
                    floorTint = new Color(0.96f, 0.92f, 1f), wallTint = new Color(0.86f, 0.78f, 1f), backdropFraction = 0.67f,
                    note = "Reactor en el centro: cables arqueando, plasma en el piso y fosas de escoria",
                    botSpawns = 18, platformCount = 20,
                    platforms = new[]
                    {
                        Plat(MapPlatformSize.Grande, new Vector2(0f, 0f), new Vector2(6.4f, 2.6f), 1.35f, false),
                        Plat(MapPlatformSize.Grande, new Vector2(0f, 4.3f), new Vector2(6.4f, 2.2f), 0.55f),
                        Plat(MapPlatformSize.Mediana, new Vector2(8.4f, 3.4f), new Vector2(4.4f, 2.2f), 0.95f),
                        Plat(MapPlatformSize.Chica, new Vector2(8.8f, -3.4f), new Vector2(3.6f, 2.2f), 0.55f),
                        Plat(MapPlatformSize.Chica, new Vector2(8.9f, 0f), new Vector2(3.2f, 2.6f), 0.55f),
                    },
                },
            };
        }

        // =====================================================================
        // Animacion esqueletica (Idle / Run / Attack / Hit / Death sobre huesos)
        // =====================================================================
        private const string PH = "Hips";
        private const string PT = "Hips/Torso";
        private const string PHD = "Hips/Torso/Head";
        private const string PAB = "Hips/Torso/ShoulderBack/ArmBack";
        private const string PFB = PAB + "/ForearmBack";
        private const string PAF = "Hips/Torso/ShoulderFront/ArmFront";
        private const string PFF = PAF + "/ForearmFront";
        private const string PLB = "Hips/LegBack";
        private const string PSB = PLB + "/ShinBack";
        private const string PLF = "Hips/LegFront";
        private const string PSF = PLF + "/ShinFront";

        private const string RotZ = "localEulerAnglesRaw.z";
        private const string PosX = "m_LocalPosition.x";
        private const string PosY = "m_LocalPosition.y";

        private struct Cv
        {
            public string path, prop; public Keyframe[] keys;
            public Cv(string path, string prop, params Keyframe[] keys) { this.path = path; this.prop = prop; this.keys = keys; }
        }

        private static AnimatorController BuildCharacterController()
        {
            string dir = AnimDir + "/Character";
            float hy = HipsY;

            var idle = RigClip(dir + "/Char_Idle.anim", true,
                new Cv(PH, PosY, K(0f, hy), K(0.6f, hy - 0.018f), K(1.2f, hy)),
                new Cv(PH, PosX, K(0f, 0f), K(1.2f, 0f)),
                new Cv(PT, RotZ, K(0f, 0f), K(0.6f, 2f), K(1.2f, 0f)),
                new Cv(PHD, RotZ, K(0f, 0f), K(0.6f, -3f), K(1.2f, 0f)),
                new Cv(PAB, RotZ, K(0f, 6f), K(0.6f, 12f), K(1.2f, 6f)),
                new Cv(PFB, RotZ, K(0f, 14f), K(0.6f, 22f), K(1.2f, 14f)),
                new Cv(PAF, RotZ, K(0f, -4f), K(0.6f, -10f), K(1.2f, -4f)),
                new Cv(PFF, RotZ, K(0f, 16f), K(0.6f, 24f), K(1.2f, 16f)),
                new Cv(PLF, RotZ, K(0f, 4f), K(1.2f, 4f)),
                new Cv(PSF, RotZ, K(0f, -4f), K(1.2f, -4f)),
                new Cv(PLB, RotZ, K(0f, -4f), K(1.2f, -4f)),
                new Cv(PSB, RotZ, K(0f, -2f), K(1.2f, -2f)));

            var run = RigClip(dir + "/Char_Run.anim", true,
                new Cv(PH, PosY, K(0f, hy), K(0.125f, hy + 0.06f), K(0.25f, hy), K(0.375f, hy + 0.06f), K(0.5f, hy)),
                new Cv(PH, PosX, K(0f, 0f), K(0.5f, 0f)),
                new Cv(PT, RotZ, K(0f, -9f), K(0.125f, -6f), K(0.25f, -9f), K(0.375f, -6f), K(0.5f, -9f)),
                new Cv(PHD, RotZ, K(0f, 5f), K(0.25f, 3f), K(0.5f, 5f)),
                new Cv(PLF, RotZ, K(0f, 35f), K(0.125f, 0f), K(0.25f, -35f), K(0.375f, 0f), K(0.5f, 35f)),
                new Cv(PSF, RotZ, K(0f, -10f), K(0.125f, -20f), K(0.25f, -50f), K(0.375f, -60f), K(0.5f, -10f)),
                new Cv(PLB, RotZ, K(0f, -35f), K(0.125f, 0f), K(0.25f, 35f), K(0.375f, 0f), K(0.5f, -35f)),
                new Cv(PSB, RotZ, K(0f, -50f), K(0.125f, -60f), K(0.25f, -10f), K(0.375f, -20f), K(0.5f, -50f)),
                new Cv(PAB, RotZ, K(0f, 35f), K(0.25f, -35f), K(0.5f, 35f)),
                new Cv(PFB, RotZ, K(0f, 30f), K(0.25f, 40f), K(0.5f, 30f)),
                new Cv(PAF, RotZ, K(0f, -35f), K(0.25f, 35f), K(0.5f, -35f)),
                new Cv(PFF, RotZ, K(0f, 35f), K(0.25f, 30f), K(0.5f, 35f)));

            var attack = RigClip(dir + "/Char_Attack.anim", false,
                new Cv(PH, PosY, K(0f, hy), K(0.28f, hy)),
                new Cv(PH, PosX, K(0f, -0.03f), K(0.07f, 0.08f), K(0.28f, 0f)),
                new Cv(PT, RotZ, K(0f, 8f), K(0.07f, -18f), K(0.28f, 0f)),
                new Cv(PHD, RotZ, K(0f, 0f), K(0.07f, -6f), K(0.28f, 0f)),
                new Cv(PAF, RotZ, K(0f, 140f), K(0.07f, -40f), K(0.28f, -4f)),
                new Cv(PFF, RotZ, K(0f, 40f), K(0.07f, 5f), K(0.28f, 16f)),
                new Cv(PAB, RotZ, K(0f, -30f), K(0.07f, 35f), K(0.28f, 6f)),
                new Cv(PLF, RotZ, K(0f, 4f), K(0.07f, 22f), K(0.28f, 4f)),
                new Cv(PLB, RotZ, K(0f, -4f), K(0.07f, -20f), K(0.28f, -4f)));

            var hit = RigClip(dir + "/Char_Hit.anim", false,
                new Cv(PH, PosY, K(0f, hy), K(0.22f, hy)),
                new Cv(PH, PosX, K(0f, 0f), K(0.05f, -0.1f), K(0.14f, 0.04f), K(0.22f, 0f)),
                new Cv(PT, RotZ, K(0f, 0f), K(0.05f, 16f), K(0.14f, -4f), K(0.22f, 0f)),
                new Cv(PHD, RotZ, K(0f, 0f), K(0.05f, 14f), K(0.22f, 0f)),
                new Cv(PAB, RotZ, K(0f, 6f), K(0.05f, -35f), K(0.22f, 6f)),
                new Cv(PAF, RotZ, K(0f, -4f), K(0.05f, 30f), K(0.22f, -4f)));

            var death = RigClip(dir + "/Char_Death.anim", false,
                new Cv(PH, PosY, K(0f, hy), K(0.12f, hy + 0.08f), K(0.7f, 0.18f)),
                new Cv(PH, PosX, K(0f, 0f), K(0.7f, -0.2f)),
                new Cv(PT, RotZ, K(0f, 0f), K(0.12f, 10f), K(0.7f, 80f)),
                new Cv(PHD, RotZ, K(0f, 0f), K(0.7f, 25f)),
                new Cv(PLF, RotZ, K(0f, 4f), K(0.7f, 50f)),
                new Cv(PSF, RotZ, K(0f, -4f), K(0.7f, -40f)),
                new Cv(PLB, RotZ, K(0f, -4f), K(0.7f, -20f)),
                new Cv(PAB, RotZ, K(0f, 6f), K(0.7f, 120f)),
                new Cv(PAF, RotZ, K(0f, -4f), K(0.7f, 100f)));

            // ---- Habilidades Q/E/R (Katana) ----
            // Q (Corte Circular, 0.5 s): encoje en windup, gira y estira en cruz en active.
            var castQ = RigClip(dir + "/Char_AbilityQ.anim", false,
                new Cv(PH, PosY, K(0f, hy), K(0.12f, hy - 0.05f), K(0.28f, hy + 0.03f), K(0.5f, hy)),
                new Cv(PH, PosX, K(0f, 0f), K(0.12f, -0.04f), K(0.5f, 0f)),
                new Cv(PT, RotZ, K(0f, 0f), K(0.12f, -25f), K(0.28f, 25f), K(0.5f, 0f)),
                new Cv(PHD, RotZ, K(0f, 0f), K(0.12f, 8f), K(0.28f, -8f), K(0.5f, 0f)),
                new Cv(PAF, RotZ, K(0f, -4f), K(0.12f, -30f), K(0.28f, 80f), K(0.5f, -4f)),
                new Cv(PFF, RotZ, K(0f, 16f), K(0.12f, 30f), K(0.28f, 5f), K(0.5f, 16f)),
                new Cv(PAB, RotZ, K(0f, 6f), K(0.12f, 40f), K(0.28f, -35f), K(0.5f, 6f)),
                new Cv(PLF, RotZ, K(0f, 4f), K(0.12f, 18f), K(0.28f, -6f), K(0.5f, 4f)),
                new Cv(PLB, RotZ, K(0f, -4f), K(0.12f, -8f), K(0.28f, 14f), K(0.5f, -4f)));

            // E (Dash-Tajo, 0.7 s): compresion en windup, estirada total en active, recupera.
            var castE = RigClip(dir + "/Char_AbilityE.anim", false,
                new Cv(PH, PosY, K(0f, hy), K(0.11f, hy - 0.08f), K(0.32f, hy + 0.06f), K(0.55f, hy - 0.02f), K(0.7f, hy)),
                new Cv(PH, PosX, K(0f, 0f), K(0.11f, -0.06f), K(0.32f, 0.1f), K(0.7f, 0f)),
                new Cv(PT, RotZ, K(0f, 0f), K(0.11f, 12f), K(0.32f, -30f), K(0.7f, 0f)),
                new Cv(PHD, RotZ, K(0f, 0f), K(0.11f, 6f), K(0.32f, 4f), K(0.7f, 0f)),
                new Cv(PAF, RotZ, K(0f, -4f), K(0.11f, -20f), K(0.32f, -150f), K(0.7f, -4f)),
                new Cv(PFF, RotZ, K(0f, 16f), K(0.11f, 24f), K(0.32f, 4f), K(0.7f, 16f)),
                new Cv(PAB, RotZ, K(0f, 6f), K(0.11f, 20f), K(0.32f, 55f), K(0.7f, 6f)),
                new Cv(PLF, RotZ, K(0f, 4f), K(0.11f, 22f), K(0.32f, -18f), K(0.7f, 4f)),
                new Cv(PSF, RotZ, K(0f, -4f), K(0.11f, -12f), K(0.32f, -30f), K(0.7f, -4f)),
                new Cv(PLB, RotZ, K(0f, -4f), K(0.11f, -26f), K(0.32f, 30f), K(0.7f, -4f)));

            // R (Corte en 8 Direcciones, 0.8 s): posture baja 0.25 s, explosion con giro, aterriza.
            var castR = RigClip(dir + "/Char_AbilityR.anim", false,
                new Cv(PH, PosY, K(0f, hy), K(0.25f, hy - 0.35f), K(0.45f, hy + 0.15f), K(0.62f, hy - 0.04f), K(0.8f, hy)),
                new Cv(PH, PosX, K(0f, 0f), K(0.25f, -0.08f), K(0.45f, 0.06f), K(0.8f, 0f)),
                new Cv(PT, RotZ, K(0f, 0f), K(0.25f, -18f), K(0.45f, 30f), K(0.62f, 12f), K(0.8f, 0f)),
                new Cv(PHD, RotZ, K(0f, 0f), K(0.25f, 20f), K(0.45f, -12f), K(0.8f, 0f)),
                new Cv(PAF, RotZ, K(0f, -4f), K(0.25f, -40f), K(0.45f, 70f), K(0.8f, -4f)),
                new Cv(PFF, RotZ, K(0f, 16f), K(0.25f, 40f), K(0.45f, 0f), K(0.8f, 16f)),
                new Cv(PAB, RotZ, K(0f, 6f), K(0.25f, 55f), K(0.45f, -50f), K(0.8f, 6f)),
                new Cv(PLF, RotZ, K(0f, 4f), K(0.25f, 55f), K(0.45f, -15f), K(0.8f, 4f)),
                new Cv(PSF, RotZ, K(0f, -4f), K(0.25f, -60f), K(0.45f, -20f), K(0.8f, -4f)),
                new Cv(PLB, RotZ, K(0f, -4f), K(0.25f, -25f), K(0.45f, 25f), K(0.8f, -4f)),
                new Cv(PSB, RotZ, K(0f, -2f), K(0.25f, -18f), K(0.45f, -8f), K(0.8f, -2f)));

            string path = dir + "/Character.controller";
            if (File.Exists(path)) AssetDatabase.DeleteAsset(path);
            var ctrl = AnimatorController.CreateAnimatorControllerAtPath(path);
            ctrl.AddParameter("Speed", AnimatorControllerParameterType.Float);
            ctrl.AddParameter("Attack", AnimatorControllerParameterType.Trigger);
            ctrl.AddParameter("Hit", AnimatorControllerParameterType.Trigger);
            ctrl.AddParameter("Dead", AnimatorControllerParameterType.Bool);
            ctrl.AddParameter("AbilityQ", AnimatorControllerParameterType.Trigger);
            ctrl.AddParameter("AbilityE", AnimatorControllerParameterType.Trigger);
            ctrl.AddParameter("AbilityR", AnimatorControllerParameterType.Trigger);

            var sm = ctrl.layers[0].stateMachine;
            var sIdle = sm.AddState("Idle", new Vector3(300, 0));
            sIdle.motion = idle;
            var sRun = sm.AddState("Run", new Vector3(300, 120));
            sRun.motion = run;
            var sAtk = sm.AddState("Attack", new Vector3(600, 0));
            sAtk.motion = attack;
            var sHit = sm.AddState("Hit", new Vector3(600, 120));
            sHit.motion = hit;
            var sDeath = sm.AddState("Death", new Vector3(600, 240));
            sDeath.motion = death;
            sm.defaultState = sIdle;

            var t = sIdle.AddTransition(sRun);
            t.hasExitTime = false; t.duration = 0.08f;
            t.AddCondition(AnimatorConditionMode.Greater, 0.4f, "Speed");
            t = sRun.AddTransition(sIdle);
            t.hasExitTime = false; t.duration = 0.1f;
            t.AddCondition(AnimatorConditionMode.Less, 0.4f, "Speed");

            t = sm.AddAnyStateTransition(sAtk);
            t.hasExitTime = false; t.duration = 0.02f; t.canTransitionToSelf = true;
            t.AddCondition(AnimatorConditionMode.If, 0f, "Attack");
            t.AddCondition(AnimatorConditionMode.IfNot, 0f, "Dead");
            t = sAtk.AddTransition(sIdle);
            t.hasExitTime = true; t.exitTime = 0.95f; t.duration = 0.06f;

            t = sm.AddAnyStateTransition(sHit);
            t.hasExitTime = false; t.duration = 0.02f; t.canTransitionToSelf = true;
            t.AddCondition(AnimatorConditionMode.If, 0f, "Hit");
            t.AddCondition(AnimatorConditionMode.IfNot, 0f, "Dead");
            t = sHit.AddTransition(sIdle);
            t.hasExitTime = true; t.exitTime = 0.95f; t.duration = 0.06f;

            // Estados de habilidad (mismo patron que Attack)
            var ablStates = new (string stateName, string param, AnimationClip clip, Vector3 pos)[]
            {
                ("Cast_Q", "AbilityQ", castQ, new Vector3(900, 0)),
                ("Cast_E", "AbilityE", castE, new Vector3(900, 120)),
                ("Cast_R", "AbilityR", castR, new Vector3(900, 240)),
            };
            foreach (var entry in ablStates)
            {
                var state = sm.AddState(entry.stateName, entry.pos);
                state.motion = entry.clip;
                t = sm.AddAnyStateTransition(state);
                t.hasExitTime = false; t.duration = 0.02f; t.canTransitionToSelf = false;
                t.AddCondition(AnimatorConditionMode.If, 0f, entry.param);
                t.AddCondition(AnimatorConditionMode.IfNot, 0f, "Dead");
                t = state.AddTransition(sIdle);
                t.hasExitTime = true; t.exitTime = 0.95f; t.duration = 0.08f;
            }

            t = sm.AddAnyStateTransition(sDeath);
            t.hasExitTime = false; t.duration = 0.02f; t.canTransitionToSelf = false;
            t.AddCondition(AnimatorConditionMode.If, 0f, "Dead");
            t = sDeath.AddTransition(sIdle);
            t.hasExitTime = false; t.duration = 0.05f;
            t.AddCondition(AnimatorConditionMode.IfNot, 0f, "Dead");

            EditorUtility.SetDirty(ctrl);
            return ctrl;
        }

        private static Keyframe K(float t, float v) => new Keyframe(t, v);

        private static AnimationClip RigClip(string path, bool loop, params Cv[] curves)
        {
            var clip = NewClip(path);
            foreach (var c in curves) AddCurve(clip, c.path, typeof(Transform), c.prop, c.keys);
            FinishClip(clip, loop);
            return clip;
        }

        private static AnimationClip NewClip(string path)
        {
            var clip = AssetDatabase.LoadAssetAtPath<AnimationClip>(path);
            if (clip == null)
            {
                clip = new AnimationClip();
                AssetDatabase.CreateAsset(clip, path);
            }
            clip.ClearCurves();
            clip.frameRate = 60f;
            return clip;
        }

        private static void FinishClip(AnimationClip clip, bool loop)
        {
            var settings = AnimationUtility.GetAnimationClipSettings(clip);
            settings.loopTime = loop;
            AnimationUtility.SetAnimationClipSettings(clip, settings);
            EditorUtility.SetDirty(clip);
        }

        private static void AddCurve(AnimationClip clip, string relPath, System.Type type, string prop, params Keyframe[] keys)
        {
            var curve = new AnimationCurve(keys);
            for (int i = 0; i < curve.length; i++)
            {
                AnimationUtility.SetKeyLeftTangentMode(curve, i, AnimationUtility.TangentMode.Auto);
                AnimationUtility.SetKeyRightTangentMode(curve, i, AnimationUtility.TangentMode.Auto);
            }
            AnimationUtility.SetEditorCurve(clip, EditorCurveBinding.FloatCurve(relPath, type, prop), curve);
        }

        // =====================================================================
        // Rig de personaje
        // =====================================================================
        private static Transform Bone(Transform parent, string name, Vector2 pos)
        {
            var go = new GameObject(name);
            go.transform.SetParent(parent, false);
            go.transform.localPosition = pos;
            return go.transform;
        }

        private static void Gfx(Transform bone, PartSpr ps, float height, int order, float shade, RigRefs refs)
        {
            if (ps == null || ps.b == null) return;
            var g = new GameObject("Gfx");
            g.transform.SetParent(bone, false);
            float s = height / Mathf.Max(0.01f, ps.b.bounds.size.y);
            g.transform.localScale = new Vector3(s, s, 1f);
            var sr = g.AddComponent<SpriteRenderer>();
            sr.sprite = ps.b;
            sr.sortingOrder = order * 2;
            refs.parts.Add(new CharacterVisual.Part { renderer = sr, paint = false, shade = shade });

            if (ps.p != null)
            {
                var p = new GameObject("Paint");
                p.transform.SetParent(g.transform, false);
                var psr = p.AddComponent<SpriteRenderer>();
                psr.sprite = ps.p;
                psr.sortingOrder = order * 2 + 1;
                refs.parts.Add(new CharacterVisual.Part { renderer = psr, paint = true, shade = shade });
            }
        }

        /// <summary>Construye Rig > Hips > Torso > ... con huesos y piezas. Devuelve refs.</summary>
        private static RigRefs BuildRig(Transform visual, RigSet set, AnimatorController ctrl)
        {
            var refs = new RigRefs();
            var rig = new GameObject("Rig");
            rig.transform.SetParent(visual, false);
            refs.animator = rig.AddComponent<Animator>();
            refs.animator.runtimeAnimatorController = ctrl;

            var hips = Bone(rig.transform, "Hips", new Vector2(0f, HipsY));
            const float back = 0.62f;

            if (set.drone)
            {
                var body = Bone(hips, "Torso", Vector2.zero);
                Gfx(body, set.droneBody, 0.62f, 5, 1f, refs);
                var shB = Bone(body, "ShoulderBack", new Vector2(-0.12f, 0.02f));
                var armB = Bone(shB, "ArmBack", Vector2.zero);
                Gfx(armB, set.droneArm, 0.5f, 0, back, refs);
                var shF = Bone(body, "ShoulderFront", new Vector2(0.06f, -0.06f));
                var armF = Bone(shF, "ArmFront", Vector2.zero);
                Gfx(armF, set.droneArm, 0.5f, 8, 1f, refs);
                refs.armFront = armF;
                refs.handFront = Bone(armF, "HandFront", new Vector2(0f, -0.45f));
                return refs;
            }

            var torso = Bone(hips, "Torso", new Vector2(0f, -0.02f));
            Gfx(torso, set.torso, TorsoH, 5, 1f, refs);

            var head = Bone(torso, "Head", new Vector2(0.03f, TorsoH * 0.9f));
            Gfx(head, set.head, HeadH, 8, 1f, refs);

            // Brazo trasero
            var shoulderB = Bone(torso, "ShoulderBack", new Vector2(-0.05f, TorsoH * 0.8f));
            var armBack = Bone(shoulderB, "ArmBack", Vector2.zero);
            Gfx(armBack, set.upper, UpperH, 0, back, refs);
            var foreBack = Bone(armBack, "ForearmBack", new Vector2(0f, -UpperH * 0.85f));
            Gfx(foreBack, set.fore, ForeH, 1, back, refs);
            Bone(foreBack, "HandBack", new Vector2(0f, -ForeH * 0.82f));

            // Piernas
            var legBack = Bone(hips, "LegBack", new Vector2(-0.06f, 0.03f));
            Gfx(legBack, set.thigh, ThighH, 2, back, refs);
            var shinBack = Bone(legBack, "ShinBack", new Vector2(0f, -ThighH * 0.86f));
            Gfx(shinBack, set.shin, ShinH, 3, back, refs);

            var legFront = Bone(hips, "LegFront", new Vector2(0.05f, 0.02f));
            Gfx(legFront, set.thigh, ThighH, 6, 1f, refs);
            var shinFront = Bone(legFront, "ShinFront", new Vector2(0f, -ThighH * 0.86f));
            Gfx(shinFront, set.shin, ShinH, 7, 1f, refs);

            // Brazo delantero (apunta con el arma)
            var shoulderF = Bone(torso, "ShoulderFront", new Vector2(0.02f, TorsoH * 0.78f));
            var armFront = Bone(shoulderF, "ArmFront", Vector2.zero);
            Gfx(armFront, set.upper, UpperH, 9, 1f, refs);
            var foreFront = Bone(armFront, "ForearmFront", new Vector2(0f, -UpperH * 0.85f));
            Gfx(foreFront, set.fore, ForeH, 10, 1f, refs);
            var handFront = Bone(foreFront, "HandFront", new Vector2(0f, -ForeH * 0.82f));

            refs.armFront = armFront;
            refs.foreFront = foreFront;
            refs.handFront = handFront;
            return refs;
        }

        private static (CharacterVisual visual, RigRefs refs) BuildVisual(Transform parent, RigSet set, AnimatorController ctrl,
            float scale, Color paint, float yOffset)
        {
            var visualGo = new GameObject("Visual");
            visualGo.transform.SetParent(parent, false);
            visualGo.transform.localPosition = new Vector3(0f, yOffset, 0f);
            visualGo.transform.localScale = new Vector3(scale, scale, 1f);
            visualGo.AddComponent<SortingGroup>();
            var visual = visualGo.AddComponent<CharacterVisual>();

            var refs = BuildRig(visualGo.transform, set, ctrl);
            visual.animator = refs.animator;
            visual.parts = refs.parts.ToArray();
            visual.baseScale = scale;
            visual.paintColor = paint;
            visual.Refresh();
            return (visual, refs);
        }

        private static (GameObject root, CharacterVisual visual, Transform pivot, RigAimArm aim) CharacterBase(
            string name, RigSet set, AnimatorController ctrl, float scale, float radius, Color paint)
        {
            var go = new GameObject(name);

            var rb = go.AddComponent<Rigidbody2D>();
            rb.gravityScale = 0f;
            rb.freezeRotation = true;
            rb.linearDamping = 0f;
            rb.collisionDetectionMode = CollisionDetectionMode2D.Continuous;
            rb.interpolation = RigidbodyInterpolation2D.Interpolate;

            var col = go.AddComponent<CircleCollider2D>();
            col.radius = radius;

            var shadow = new GameObject("Shadow");
            shadow.transform.SetParent(go.transform, false);
            shadow.transform.localPosition = new Vector3(0f, -radius * 0.95f, 0f);
            shadow.transform.localScale = new Vector3(radius * 2.6f, radius * 0.9f, 1f);
            var ssr = shadow.AddComponent<SpriteRenderer>();
            ssr.sprite = _soft;
            ssr.color = new Color(0f, 0f, 0f, 0.45f);
            ssr.sortingOrder = -30;

            var (visual, refs) = BuildVisual(go.transform, set, ctrl, scale, paint, -radius);

            var pivot = new GameObject("AimPivot");
            pivot.transform.SetParent(go.transform, false);
            pivot.transform.localPosition = new Vector3(0f, 0.05f, 0f);

            var aim = go.AddComponent<RigAimArm>();
            aim.upperArm = refs.armFront;
            aim.forearm = refs.foreFront;
            aim.hand = refs.handFront;
            aim.aimPivot = pivot.transform;
            aim.elbowBend = set.drone ? 0f : 28f;

            // Altura simulada (2.5D): el rig y el brazo suben con la Z, la sombra queda al ras.
            var height = go.AddComponent<HeightBody>();
            height.followers = new[] { visual.transform, pivot.transform };
            height.shadow = ssr;
            height.baseOrder = 10;
            return (go, visual, pivot.transform, aim);
        }

        private static MeleeWeapon AttachWeapon(Transform pivot, WeaponDef def, string name)
        {
            var wgo = new GameObject(name);
            wgo.transform.SetParent(pivot, false);
            var mw = wgo.AddComponent<MeleeWeapon>();
            mw.def = def;

            var blade = new GameObject("Blade");
            blade.transform.SetParent(wgo.transform, false);
            var bsr = blade.AddComponent<SpriteRenderer>();
            bsr.sprite = def.sprite;
            bsr.sortingOrder = 2;
            mw.blade = blade.transform;
            mw.bladeRenderer = bsr;

            if (def.trail)
            {
                var tip = new GameObject("Tip");
                tip.transform.SetParent(blade.transform, false);
                var tr = tip.AddComponent<TrailRenderer>();
                tr.time = 0.12f;
                tr.minVertexDistance = 0.02f;
                tr.widthCurve = new AnimationCurve(new Keyframe(0f, 0.22f), new Keyframe(1f, 0f));
                tr.sharedMaterial = _trail;
                tr.sortingOrder = 19;
                tr.emitting = false;
                tr.numCapVertices = 2;
                mw.trail = tr;
            }

            mw.ApplyBlade();
            return mw;
        }

        private static GameObject BuildPlayerPrefab(string name, RigSet set, AnimatorController ctrl,
            WeaponDef w1, WeaponDef w2, GameObject deathVfx)
        {
            var (go, visual, pivot, aim) = CharacterBase(name, set, ctrl, 1f, 0.4f, GameSession.Palette[0]);
            var health = go.AddComponent<PlayerHealth>();
            health.bodyRadius = 0.42f;
            health.deathVfx = deathVfx;

            var pc = go.AddComponent<PlayerController>();
            pc.aimPivot = pivot;
            pc.visual = visual;

            AttachWeapon(pivot, w1, "Weapon_Katana");
            AttachWeapon(pivot, w2, "Weapon_Hacha");
            var loadout = go.AddComponent<WeaponLoadout>();
            loadout.weapons = go.GetComponentsInChildren<MeleeWeapon>(true);

            var caster = go.AddComponent<AbilityCaster>();
            caster.controller = pc;
            caster.health = health;
            caster.loadout = loadout;
            caster.visual = visual;

            aim.health = health;
            aim.loadout = loadout;
            return SavePrefab(go, $"{CharPrefabDir}/{name}.prefab");
        }

        private static EnemyBot BuildBotPrefab(string name, BotDef def, RigSet set, AnimatorController ctrl)
        {
            var (go, visual, pivot, aim) = CharacterBase(name, set, ctrl, def.visualScale, def.bodyRadius, def.tint);
            var health = go.AddComponent<PlayerHealth>();
            health.team = 2;
            health.maxHp = def.hp;
            health.bodyRadius = def.bodyRadius;
            health.deathVfx = def.deathVfx;

            var bot = go.AddComponent<EnemyBot>();
            bot.def = def;
            bot.aimPivot = pivot;
            bot.visual = visual;
            bot.weapon = AttachWeapon(pivot, def.weapon, "Weapon_" + def.weapon.name);

            aim.health = health;
            aim.fixedWeapon = bot.weapon;

            var prefab = SavePrefab(go, $"{BotPrefabDir}/{name}.prefab");
            return prefab.GetComponent<EnemyBot>();
        }

        private static GameObject SavePrefab(GameObject go, string path)
        {
            var prefab = PrefabUtility.SaveAsPrefabAsset(go, path);
            Object.DestroyImmediate(go);
            return prefab;
        }

        // =====================================================================
        // Escena Arena
        // =====================================================================
        /// <summary>Busca una pista de audio por prefijo en Audio/Music; con varias versiones (v1/v2/...) toma la alfabeticamente primera.</summary>
        private static AudioClip MusicClip(string prefix)
        {
            var guids = AssetDatabase.FindAssets(prefix + " t:AudioClip", new[] { Root + "/Audio/Music" });
            if (guids == null || guids.Length == 0) return null;
            var paths = new string[guids.Length];
            for (int i = 0; i < guids.Length; i++) paths[i] = AssetDatabase.GUIDToAssetPath(guids[i]);
            System.Array.Sort(paths, System.StringComparer.OrdinalIgnoreCase);
            return AssetDatabase.LoadAssetAtPath<AudioClip>(paths[0]);
        }

        private static void BuildArenaScene(MapCatalog catalog, GameObject playerPrefab, EnemyBot[] bots, GameObject spawnVfx)
        {
            // Misma precaucion que en el selector: usar una referencia fresca del
            // catalogo para que la arena resuelva bien el mapa por defecto.
            var fresh = AssetDatabase.LoadAssetAtPath<MapCatalog>(CatalogPath);
            if (fresh != null) catalog = fresh;

            var scene = EditorSceneManager.NewScene(NewSceneSetup.EmptyScene, NewSceneMode.Single);
            var defaultMap = catalog != null && catalog.Count > 0 ? catalog.Get(0) : null;

            var lightGo = new GameObject("Global Light 2D");
            var light = lightGo.AddComponent<Light2D>();
            light.lightType = Light2D.LightType.Global;
            light.color = new Color(0.97f, 0.98f, 1f);
            light.intensity = 1.05f;

            var camGo = new GameObject("Main Camera");
            camGo.tag = "MainCamera";
            camGo.transform.position = new Vector3(0f, 0f, -10f);
            var cam = camGo.AddComponent<Camera>();
            cam.orthographic = true;
            cam.orthographicSize = 6.4f;
            cam.clearFlags = CameraClearFlags.SolidColor;
            cam.backgroundColor = defaultMap != null ? defaultMap.backgroundColor : new Color(0.05f, 0.05f, 0.07f);
            camGo.AddComponent<AudioListener>();

            var spawn1 = new GameObject("SpawnP1").transform;
            var spawn2 = new GameObject("SpawnP2").transform;

            // Skin de los peligros procedurales (mancha + anillo + chispas).
            var hazardSkin = new GameObject("HazardVisuals");
            var vis = hazardSkin.AddComponent<HazardVisuals>();
            vis.soft = _soft;
            vis.ring = _ring;
            vis.unlit = _unlit;

            var mapGo = new GameObject("Map");
            var gen = mapGo.AddComponent<MapGenerator>();
            gen.spawnP1 = spawn1;
            gen.spawnP2 = spawn2;
            gen.mirrored = true;
            gen.map = defaultMap;
            if (defaultMap != null) gen.Generate(defaultMap.seed, true);

            var p1 = ((GameObject)PrefabUtility.InstantiatePrefab(playerPrefab)).GetComponent<PlayerController>();
            p1.name = "P1";
            p1.scheme = InputScheme.KeyboardMouse;
            p1.GetComponent<PlayerHealth>().team = 0;
            p1.transform.position = spawn1.position;

            var p2 = ((GameObject)PrefabUtility.InstantiatePrefab(playerPrefab)).GetComponent<PlayerController>();
            p2.name = "P2";
            p2.scheme = InputScheme.Auto;
            p2.GetComponent<PlayerHealth>().team = 1;
            p2.transform.position = spawn2.position;
            p2.visual.paintColor = GameSession.Palette[1];
            p2.visual.Refresh();

            var duelRoot = new GameObject("Mode_Duelo");
            var mgr = duelRoot.AddComponent<DuelManager>();
            mgr.players = new List<PlayerController> { p1, p2 };
            mgr.spawns = new[] { spawn1, spawn2 };
            BuildMatchHud(duelRoot.transform, Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf"));
            duelRoot.SetActive(false);

            var botsRoot = new GameObject("Mode_Supervivencia");
            var waves = botsRoot.AddComponent<WaveManager>();
            waves.player = p1;
            waves.playerSpawn = spawn1;
            waves.map = gen;
            waves.botPrefabs = bots;
            waves.spawnVfx = spawnVfx;
            botsRoot.SetActive(false);

            var pvpRoot = new GameObject("Mode_PvP");
            var pvp = pvpRoot.AddComponent<PvpMatchManager>();
            pvp.duel = mgr;
            pvp.duelRoot = duelRoot;
            pvp.p1 = p1;
            pvp.p2 = p2;
            pvp.playerPrefab = AssetDatabase.LoadAssetAtPath<GameObject>("Assets/_WildWeapon/Prefabs/Characters/Player_Cyborg.prefab");
            pvp.spawns = new[] { spawn1, spawn2 };

            // Cuenta regresiva 3-2-1-GO (sprites de Aura) en canvas propio, arriba del HUD.
            var countCanvasGo = new GameObject("PvpCountdownCanvas", typeof(RectTransform));
            countCanvasGo.transform.SetParent(pvpRoot.transform, false);
            var countCanvas = countCanvasGo.AddComponent<Canvas>();
            countCanvas.renderMode = RenderMode.ScreenSpaceOverlay;
            countCanvas.sortingOrder = 60;
            var countScaler = countCanvasGo.AddComponent<CanvasScaler>();
            countScaler.uiScaleMode = CanvasScaler.ScaleMode.ScaleWithScreenSize;
            countScaler.referenceResolution = new Vector2(1920f, 1080f);
            countScaler.matchWidthOrHeight = 1f;
            var count = countCanvasGo.AddComponent<PvpCountdown>();
            count.sprite3 = Spr("ww_ui_count_3");
            count.sprite2 = Spr("ww_ui_count_2");
            count.sprite1 = Spr("ww_ui_count_1");
            count.spriteGo = Spr("ww_ui_count_go");
            var digit = UiImage("Digit", countCanvasGo.transform, count.sprite3, new Color(1f, 1f, 1f, 0f));
            digit.preserveAspect = true;
            var digitRt = digit.rectTransform;
            digitRt.anchorMin = digitRt.anchorMax = new Vector2(0.5f, 0.5f);
            digitRt.anchoredPosition = new Vector2(0f, 40f);
            digitRt.sizeDelta = new Vector2(480f, 480f);
            count.digit = digit;
            pvp.countdown = count;

            // Releer el catalogo justo antes de usarlo: el armado de la escena toca el
            // AssetDatabase y puede dejar obsoleta la referencia cargada al principio.
            var freshCatalog = AssetDatabase.LoadAssetAtPath<MapCatalog>(CatalogPath);
            if (freshCatalog != null && freshCatalog.Count > 0) catalog = freshCatalog;

            var bootGo = new GameObject("GameBootstrap");
            var boot = bootGo.AddComponent<GameBootstrap>();
            boot.map = gen;
            boot.catalog = catalog;
            boot.duelRoot = duelRoot;
            boot.botsRoot = botsRoot;
            boot.pvpRoot = pvpRoot;
            boot.p1 = p1;
            boot.p2 = p2;
            boot.playerPrefab = AssetDatabase.LoadAssetAtPath<GameObject>("Assets/_WildWeapon/Prefabs/Characters/Player_Cyborg.prefab");

            var musicGo = new GameObject("Music");
            var music = musicGo.AddComponent<MusicPlayer>();
            music.clip = MusicClip("ww_music_arena");
            music.volume = 0.5f;
            if (music.clip == null)
                Debug.LogWarning("[WW] Sin pista de arena (Audio/Music/ww_music_arena*): la escena queda sin musica hasta generarla.");

            EditorSceneManager.SaveScene(scene, ArenaScenePath);
        }

        // =====================================================================
        // Escena MainMenu (fondo en capas + logo animado + tarjetas de modo)
        // =====================================================================
        private static void BuildMenuScene()
        {
            var scene = EditorSceneManager.NewScene(NewSceneSetup.EmptyScene, NewSceneMode.Single);
            var font = Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");

            var camGo = MenuCamera();
            MenuLight2D();
            var es = MenuEventSystem();

            var canvasGo = MenuCanvas("MenuCanvas", camGo.GetComponent<Camera>());
            var controller = canvasGo.AddComponent<MainMenuController>();

            BuildBackdrop(canvasGo.transform);

            // ---- Cabecera ----
            var chips = new GameObject("Chips", typeof(RectTransform));
            chips.transform.SetParent(canvasGo.transform, false);
            Stretch((RectTransform)chips.transform);
            TopChip(chips.transform, font, true, "OCEAN AND WILD STUDIOS", new Color(0.34f, 0.9f, 1f));
            TopChip(chips.transform, font, false, "PROTOTIPO F0 · v1.0", new Color(1f, 0.7f, 0.28f));
            chips.AddComponent<CanvasGroup>();

            BuildMenuLogo(canvasGo.transform);

            // ---- Tarjetas de modo ----
            var accents = new[]
            {
                new Color(0.26f, 0.88f, 1f),    // cian    - duelo local
                new Color(0.72f, 0.45f, 1f),    // violeta - pvp online
                new Color(1f, 0.62f, 0.18f),    // naranja - supervivencia
                new Color(0.62f, 0.68f, 0.78f), // gris    - salir
            };
            string[] cardTitles = { "DUELO 1 VS 1", "PVP ONLINE", "SUPERVIVENCIA", "SALIR" };
            string[] cardSubs = { "LOCAL · DOS JUGADORES", "CONTRA OTRO JUGADOR", "OLEADAS VS BOTS", "CERRAR EL JUEGO" };
            string[] cardIcons = { "ww_icon_duel", "ww_icon_pvp", "ww_icon_survival", "ww_icon_exit" };

            var cardsHolder = new GameObject("Cards", typeof(RectTransform));
            cardsHolder.transform.SetParent(canvasGo.transform, false);
            Stretch((RectTransform)cardsHolder.transform);

            var cards = new MenuModeCard[cardTitles.Length];
            for (int i = 0; i < cards.Length; i++)
                cards[i] = ModeCard(cardsHolder.transform, font, i, cardTitles[i], cardSubs[i], accents[i], (i + 1).ToString("00"), Spr(cardIcons[i]));

            var info = ModeInfoStrip(canvasGo.transform, font, accents);
            foreach (var card in cards) card.info = info;

            UnityEventTools.AddPersistentListener(cards[0].GetComponent<Button>().onClick, controller.PlayMulti);
            UnityEventTools.AddPersistentListener(cards[1].GetComponent<Button>().onClick, controller.PlayPvp);
            UnityEventTools.AddPersistentListener(cards[2].GetComponent<Button>().onClick, controller.PlayBots);
            UnityEventTools.AddPersistentListener(cards[3].GetComponent<Button>().onClick, controller.Quit);
            es.firstSelectedGameObject = cards[0].gameObject;

            // ---- Pie ----
            HintRow(canvasGo.transform, font, new[]
            {
                "J1 · WASD + RATÓN",
                "J2 · MANDO O FLECHAS",
                "CLIC / A · ELEGIR"
            });

            // ---- Fader + animator ----
            controller.fader = FaderCanvas();

            // ---- Skins del overlay PVP (el modal las levanta en runtime) ----
            var pvpSkinGo = new GameObject("PvpOverlaySkin", typeof(RectTransform));
            pvpSkinGo.transform.SetParent(canvasGo.transform, false);
            var pvpSkin = pvpSkinGo.AddComponent<PvpOverlaySkin>();
            pvpSkin.panel = Spr("ww_pvp_panel_skin");
            pvpSkin.button = Spr("ww_pvp_button_skin");
            pvpSkin.rule = Spr("ww_pvp_rule");
            pvpSkin.radar = Spr("ww_pvp_radar");
            pvpSkin.shine = EnsureShine();


            var anim = canvasGo.AddComponent<Animator>();
            anim.updateMode = AnimatorUpdateMode.UnscaledTime;
            anim.runtimeAnimatorController = BuildMenuController();

            // ---- Audio ----
            var musicGo = new GameObject("Music");
            var music = musicGo.AddComponent<MusicPlayer>();
            music.clip = MusicClip("ww_music_menu");
            music.volume = 0.5f;
            if (music.clip == null)
                Debug.LogWarning("[WW] Sin pista de menu (Audio/Music/ww_music_menu*): la escena queda sin musica hasta generarla.");

            EditorSceneManager.SaveScene(scene, MenuScenePath);
        }

        // =====================================================================
        // Escena MapSelect (selector de arena: 4 chicas, 4 medianas, 4 grandes)
        // Se llega desde el menu principal despues de elegir modo; las tarjetas
        // salen del MapCatalog y "JUGAR" carga la Arena con el mapa elegido.
        // =====================================================================
        private static void BuildMapSelectScene(MapCatalog catalog)
        {
            var scene = EditorSceneManager.NewScene(NewSceneSetup.EmptyScene, NewSceneMode.Single);
            var font = Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");

            var camGo = MenuCamera();
            MenuLight2D();
            var es = MenuEventSystem();

            var canvasGo = MenuCanvas("MapSelectCanvas", camGo.GetComponent<Camera>());
            var controller = canvasGo.AddComponent<MapSelectController>();

            BuildBackdrop(canvasGo.transform);

            // ---- Cabecera ----
            var chips = new GameObject("Chips", typeof(RectTransform));
            chips.transform.SetParent(canvasGo.transform, false);
            Stretch((RectTransform)chips.transform);
            TopChip(chips.transform, font, true, "OCEAN AND WILD STUDIOS", new Color(0.34f, 0.9f, 1f));
            TopChip(chips.transform, font, false, "ARENAS · PROTOTIPO F0", new Color(1f, 0.7f, 0.28f));

            var title = UiText("Title", canvasGo.transform, font, "ELEGI TU ARENA", 52, Color.white);
            var trt = title.rectTransform;
            trt.anchorMin = trt.anchorMax = new Vector2(0.5f, 0.5f);
            trt.anchoredPosition = new Vector2(0f, 400f);
            trt.sizeDelta = new Vector2(1200f, 66f);
            var tsh = title.gameObject.AddComponent<Shadow>();
            tsh.effectColor = new Color(0f, 0f, 0f, 0.85f);
            tsh.effectDistance = new Vector2(2f, -3f);
            controller.headerTitle = title;

            var mode = UiText("Mode", canvasGo.transform, font, "DUELO 1 VS 1", 22, new Color(0.6f, 0.8f, 1f));
            var mrt = mode.rectTransform;
            mrt.anchorMin = mrt.anchorMax = new Vector2(0.5f, 0.5f);
            mrt.anchoredPosition = new Vector2(0f, 356f);
            mrt.sizeDelta = new Vector2(900f, 30f);
            controller.headerMode = mode;

            // ---- Grilla: 3 filas (chicas / medianas / grandes) x 4 columnas ----
            var grid = new GameObject("Grid", typeof(RectTransform));
            grid.transform.SetParent(canvasGo.transform, false);
            Stretch((RectTransform)grid.transform);

            const int columns = 4;
            const float cardW = 340f, cardH = 168f, pitchX = 364f, pitchY = 198f;
            float firstX = -456f;
            float[] rowY = { 172f, -26f, -224f };
            string[] rowNames = { "CHICAS", "MEDIANAS", "GRANDES" };
            string[] rowCounts = { "DUELOS RAPIDOS", "ESTANDAR", "SUPERVIVENCIA" };

            // Las escenas anteriores del build borran y recrean assets (clips, controllers)
            // y pueden dejar obsoleta la referencia cargada al inicio. El catalogo se
            // relee aca, en el punto de uso: si no, el selector se guardaba sin tarjetas.
            var mapCatalog = AssetDatabase.LoadAssetAtPath<MapCatalog>(CatalogPath);
            if (mapCatalog != null && mapCatalog.Count > 0) catalog = mapCatalog;
            if (catalog == null || catalog.Count == 0)
                Debug.LogError($"[WildWeapon] El selector de arenas no encontro el catalogo ({CatalogPath}).");
            else
                controller.catalog = catalog;

            var cards = new MapSelectCard[catalog != null ? catalog.Count : 0];
            for (int i = 0; i < cards.Length; i++)
            {
                int row = i / columns;
                int col = i % columns;
                var pos = new Vector2(firstX + col * pitchX, rowY[Mathf.Clamp(row, 0, rowY.Length - 1)]);
                cards[i] = MapCard(grid.transform, font, i, pos, cardW, cardH);
                UnityEventTools.AddIntPersistentListener(cards[i].GetComponent<Button>().onClick, controller.Pick, i);
            }
            controller.cards = cards;

            for (int r = 0; r < rowNames.Length; r++)
                MapRowLabel(grid.transform, font, rowNames[r], rowCounts[r], rowY[Mathf.Clamp(r, 0, rowY.Length - 1)]);

            if (cards.Length > 0)
            {
                var nav = new Navigation { mode = Navigation.Mode.Automatic };
                for (int i = 0; i < cards.Length; i++)
                {
                    var b = cards[i].GetComponent<Button>();
                    b.navigation = nav;
                }
                es.firstSelectedGameObject = cards[0].gameObject;
            }

            // ---- Ficha del mapa elegido ----
            var strip = MapInfoStrip(canvasGo.transform, font, controller);

            // ---- Botones ----
            var play = MenuButton(canvasGo.transform, "Play", "JUGAR", font);
            var playRt = (RectTransform)play.transform;
            playRt.anchorMin = playRt.anchorMax = new Vector2(0.5f, 0.5f);
            playRt.anchoredPosition = new Vector2(700f, -400f);
            playRt.sizeDelta = new Vector2(400f, 96f);
            UnityEventTools.AddPersistentListener(play.onClick, controller.Play);
            controller.playButton = play;
            controller.playLabel = play.GetComponentInChildren<Text>();

            var back = MenuButton(canvasGo.transform, "Back", "VOLVER", font);
            var backRt = (RectTransform)back.transform;
            backRt.anchorMin = backRt.anchorMax = new Vector2(0.5f, 0.5f);
            backRt.pivot = new Vector2(0f, 0.5f);
            backRt.anchoredPosition = new Vector2(-880f, 352f);
            backRt.sizeDelta = new Vector2(280f, 64f);
            UnityEventTools.AddPersistentListener(back.onClick, controller.Back);

            // ---- Pie ----
            HintRow(canvasGo.transform, font, new[]
            {
                "CLIC / A · ELEGIR ARENA",
                "ENTER / A · JUGAR",
                "ESC / START · VOLVER"
            });

            // ---- Fader ----
            controller.fader = FaderCanvas();
            controller.info = strip;

            // ---- Audio ----
            var musicGo = new GameObject("Music");
            var music = musicGo.AddComponent<MusicPlayer>();
            music.clip = MusicClip("ww_music_menu");
            music.volume = 0.5f;

            EditorSceneManager.SaveScene(scene, MapSelectScenePath);
        }

        /// <summary>Tarjeta de arena: vista previa del fondo del mapa + ficha corta.</summary>
        private static MapSelectCard MapCard(Transform parent, Font font, int index, Vector2 pos, float w, float h)
        {
            var root = new GameObject("Map" + index.ToString("00"), typeof(RectTransform));
            root.transform.SetParent(parent, false);
            var rt = (RectTransform)root.transform;
            rt.anchorMin = rt.anchorMax = new Vector2(0.5f, 0.5f);
            rt.anchoredPosition = pos;
            rt.sizeDelta = new Vector2(w, h);
            var btn = root.AddComponent<Button>();
            btn.transition = Selectable.Transition.None;

            var body = new GameObject("Body", typeof(RectTransform));
            body.transform.SetParent(root.transform, false);
            Stretch((RectTransform)body.transform);

            var glow = UiImage("Glow", body.transform, _soft, new Color(0.3f, 0.9f, 1f, 0f));
            var grt = glow.rectTransform;
            grt.anchorMin = grt.anchorMax = new Vector2(0.5f, 0.5f);
            grt.anchoredPosition = Vector2.zero;
            grt.sizeDelta = new Vector2(w + 26f, h + 26f);

            var skin = Spr("ww_menu_card_skin");
            var frame = skin != null
                ? UiImage("Frame", body.transform, skin, Color.white)
                : Panel(body.transform, "Frame", new Color(0.035f, 0.055f, 0.09f, 0.88f));
            Stretch(frame.rectTransform);
            frame.raycastTarget = true;
            var outline = frame.gameObject.AddComponent<Outline>();
            outline.effectColor = new Color(1f, 1f, 1f, 0.18f);
            outline.effectDistance = new Vector2(2f, -2f);
            btn.targetGraphic = frame;

            // Vista previa: el fondo de la arena, enmarcado por el borde de la tarjeta.
            var preview = UiImage("Preview", body.transform, null, Color.white);
            var prt = preview.rectTransform;
            prt.anchorMin = Vector2.zero;
            prt.anchorMax = Vector2.one;
            prt.offsetMin = new Vector2(10f, 10f);
            prt.offsetMax = new Vector2(-10f, -10f);
            preview.raycastTarget = false;

            var shade = Panel(body.transform, "Shade", new Color(0.02f, 0.03f, 0.05f, 0.62f));
            var srt = shade.rectTransform;
            srt.anchorMin = Vector2.zero;
            srt.anchorMax = Vector2.one;
            srt.offsetMin = new Vector2(10f, 10f);
            srt.offsetMax = new Vector2(-10f, -10f);
            shade.raycastTarget = false;

            var indexLabel = UiText("Index", body.transform, font, (index + 1).ToString("00"), 22, new Color(1f, 1f, 1f, 0.16f));
            indexLabel.alignment = TextAnchor.UpperLeft;
            var irt = indexLabel.rectTransform;
            irt.anchorMin = irt.anchorMax = new Vector2(0f, 1f);
            irt.pivot = new Vector2(0f, 1f);
            irt.anchoredPosition = new Vector2(20f, -14f);
            irt.sizeDelta = new Vector2(60f, 28f);

            var sizeLabel = UiText("Size", body.transform, font, "CHICA", 18, new Color(1f, 1f, 1f, 0.5f));
            sizeLabel.alignment = TextAnchor.UpperRight;
            var szrt = sizeLabel.rectTransform;
            szrt.anchorMin = szrt.anchorMax = new Vector2(1f, 1f);
            szrt.pivot = new Vector2(1f, 1f);
            szrt.anchoredPosition = new Vector2(-20f, -16f);
            szrt.sizeDelta = new Vector2(140f, 26f);

            var title = UiText("Title", body.transform, font, "ARENA", 27, new Color(0.86f, 0.9f, 0.96f));
            title.alignment = TextAnchor.LowerLeft;
            var lrt = title.rectTransform;
            lrt.anchorMin = new Vector2(0f, 0f);
            lrt.anchorMax = new Vector2(1f, 0f);
            lrt.pivot = new Vector2(0.5f, 0f);
            lrt.anchoredPosition = new Vector2(0f, 34f);
            lrt.sizeDelta = new Vector2(-36f, 34f);

            var sub = UiText("Sub", body.transform, font, "SUBTITULO", 15, new Color(0.7f, 0.76f, 0.85f, 0.5f));
            sub.alignment = TextAnchor.LowerLeft;
            var subrt = sub.rectTransform;
            subrt.anchorMin = new Vector2(0f, 0f);
            subrt.anchorMax = new Vector2(1f, 0f);
            subrt.pivot = new Vector2(0.5f, 0f);
            subrt.anchoredPosition = new Vector2(0f, 14f);
            subrt.sizeDelta = new Vector2(-36f, 22f);

            var accent = Panel(body.transform, "Accent", new Color(0.26f, 0.88f, 1f, 0.7f));
            var art = accent.rectTransform;
            art.anchorMin = new Vector2(0f, 0f);
            art.anchorMax = new Vector2(1f, 0f);
            art.pivot = new Vector2(0.5f, 0f);
            art.anchoredPosition = new Vector2(0f, 4f);
            art.sizeDelta = new Vector2(-24f, 5f);
            accent.raycastTarget = false;

            var card = root.AddComponent<MapSelectCard>();
            card.body = (RectTransform)body.transform;
            card.frame = frame;
            card.frameOutline = outline;
            card.preview = preview;
            card.shade = shade;
            card.accent = accent;
            card.glow = glow;
            card.title = title;
            card.subtitle = sub;
            card.indexLabel = indexLabel;
            card.sizeLabel = sizeLabel;
            card.index = index;
            return card;
        }

        /// <summary>Etiqueta de la fila (chicas / medianas / grandes) a la izquierda de las tarjetas.</summary>
        private static void MapRowLabel(Transform parent, Font font, string label, string note, float y)
        {
            var bar = Panel(parent, "RowBar_" + label, new Color(0.35f, 0.85f, 1f, 0.7f));
            var brt = bar.rectTransform;
            brt.anchorMin = brt.anchorMax = new Vector2(0.5f, 0.5f);
            brt.pivot = new Vector2(1f, 0.5f);
            brt.anchoredPosition = new Vector2(-648f, y);
            brt.sizeDelta = new Vector2(4f, 86f);

            var text = UiText("RowLabel_" + label, parent, font, label, 30, Color.white);
            text.alignment = TextAnchor.MiddleRight;
            var trt = text.rectTransform;
            trt.anchorMin = trt.anchorMax = new Vector2(0.5f, 0.5f);
            trt.pivot = new Vector2(1f, 0.5f);
            trt.anchoredPosition = new Vector2(-666f, y + 14f);
            trt.sizeDelta = new Vector2(240f, 38f);

            var sub = UiText("RowNote_" + label, parent, font, note, 16, new Color(0.68f, 0.74f, 0.84f, 0.6f));
            sub.alignment = TextAnchor.MiddleRight;
            var srt = sub.rectTransform;
            srt.anchorMin = srt.anchorMax = new Vector2(0.5f, 0.5f);
            srt.pivot = new Vector2(1f, 0.5f);
            srt.anchoredPosition = new Vector2(-666f, y - 14f);
            srt.sizeDelta = new Vector2(240f, 24f);
        }

        /// <summary>Ficha del mapa elegido: nombre, tamano, plataformas, peligros y decoracion.</summary>
        private static CanvasGroup MapInfoStrip(Transform parent, Font font, MapSelectController controller)
        {
            var root = new GameObject("MapInfo", typeof(RectTransform));
            root.transform.SetParent(parent, false);
            var rt = (RectTransform)root.transform;
            rt.anchorMin = rt.anchorMax = new Vector2(0.5f, 0.5f);
            rt.anchoredPosition = new Vector2(-170f, -400f);
            rt.sizeDelta = new Vector2(1300f, 168f);
            var group = root.AddComponent<CanvasGroup>();

            var skin = Spr("ww_menu_info_skin");
            var bg = skin != null
                ? UiImage("Bg", root.transform, skin, Color.white)
                : Panel(root.transform, "Bg", new Color(0.02f, 0.035f, 0.06f, 0.72f));
            Stretch(bg.rectTransform);
            var outline = bg.gameObject.AddComponent<Outline>();
            outline.effectColor = new Color(1f, 1f, 1f, 0.06f);
            outline.effectDistance = new Vector2(1f, -1f);

            var bar = Panel(root.transform, "Bar", new Color(0.35f, 0.85f, 1f));
            var brt = bar.rectTransform;
            brt.anchorMin = new Vector2(0f, 0f);
            brt.anchorMax = new Vector2(0f, 1f);
            brt.pivot = new Vector2(0f, 0.5f);
            brt.anchoredPosition = new Vector2(3f, 0f);
            brt.sizeDelta = new Vector2(5f, -18f);

            // Marco de vista previa a la derecha.
            var previewFrame = Panel(root.transform, "PreviewFrame", new Color(0.05f, 0.07f, 0.11f, 0.9f));
            var pfrt = previewFrame.rectTransform;
            pfrt.anchorMin = pfrt.anchorMax = new Vector2(1f, 0.5f);
            pfrt.pivot = new Vector2(1f, 0.5f);
            pfrt.anchoredPosition = new Vector2(-18f, 0f);
            pfrt.sizeDelta = new Vector2(258f, 132f);
            var preview = UiImage("Preview", previewFrame.transform, null, Color.white);
            var prt = preview.rectTransform;
            prt.anchorMin = Vector2.zero;
            prt.anchorMax = Vector2.one;
            prt.offsetMin = new Vector2(7f, 7f);
            prt.offsetMax = new Vector2(-7f, -7f);
            controller.infoPreview = preview;

            var title = UiText("InfoTitle", root.transform, font, "ARENA", 36, Color.white);
            title.alignment = TextAnchor.LowerLeft;
            var trt = title.rectTransform;
            trt.anchorMin = new Vector2(0f, 0.5f);
            trt.anchorMax = new Vector2(0f, 1f);
            trt.pivot = new Vector2(0f, 0f);
            trt.anchoredPosition = new Vector2(26f, 4f);
            trt.sizeDelta = new Vector2(760f, 44f);
            controller.infoTitle = title;

            var sub = UiText("InfoSub", root.transform, font, "SUBTITULO", 19, new Color(0.72f, 0.8f, 0.92f, 0.75f));
            sub.alignment = TextAnchor.UpperLeft;
            var srt = sub.rectTransform;
            srt.anchorMin = new Vector2(0f, 0.5f);
            srt.anchorMax = new Vector2(0f, 1f);
            srt.pivot = new Vector2(0f, 1f);
            srt.anchoredPosition = new Vector2(26f, -4f);
            srt.sizeDelta = new Vector2(760f, 26f);
            controller.infoSubtitle = sub;

            var meta = UiText("InfoMeta", root.transform, font, "MEDIANA · 20x11", 17, new Color(0.66f, 0.72f, 0.82f, 0.8f));
            meta.alignment = TextAnchor.UpperLeft;
            var mrt = meta.rectTransform;
            mrt.anchorMin = mrt.anchorMax = new Vector2(0f, 0.5f);
            mrt.pivot = new Vector2(0f, 1f);
            mrt.anchoredPosition = new Vector2(26f, -6f);
            mrt.sizeDelta = new Vector2(900f, 24f);
            controller.infoMeta = meta;

            var hazards = UiText("InfoHazards", root.transform, font, "PELIGROS: -", 18, new Color(1f, 0.72f, 0.3f, 0.9f));
            hazards.alignment = TextAnchor.UpperLeft;
            var hrt = hazards.rectTransform;
            hrt.anchorMin = hrt.anchorMax = new Vector2(0f, 0.5f);
            hrt.pivot = new Vector2(0f, 1f);
            hrt.anchoredPosition = new Vector2(26f, -34f);
            hrt.sizeDelta = new Vector2(960f, 26f);
            controller.infoHazards = hazards;

            var decor = UiText("InfoDecor", root.transform, font, "DECORACION DEL TEMA", 16, new Color(0.6f, 0.68f, 0.8f, 0.6f));
            decor.alignment = TextAnchor.UpperLeft;
            var drt = decor.rectTransform;
            drt.anchorMin = drt.anchorMax = new Vector2(0f, 0.5f);
            drt.pivot = new Vector2(0f, 1f);
            drt.anchoredPosition = new Vector2(26f, -62f);
            drt.sizeDelta = new Vector2(960f, 24f);
            controller.infoDecor = decor;

            return group;
        }

        // =====================================================================
        // Escena CharacterSelect (personalizacion: previews riggeadas + color).
        // Va aparte del menu: cuando el diseno decida donde vive, se cuelga con
        // SceneManager.LoadScene("CharacterSelect") desde donde corresponda.
        // =====================================================================
        private static void BuildCharacterSelectScene(RigSet cyborg, AnimatorController charCtrl)
        {
            var scene = EditorSceneManager.NewScene(NewSceneSetup.EmptyScene, NewSceneMode.Single);
            var font = Resources.GetBuiltinResource<Font>("LegacyRuntime.ttf");
            var knob = AssetDatabase.GetBuiltinExtraResource<Sprite>("UI/Skin/Knob.psd");

            var camGo = MenuCamera();
            MenuLight2D();
            MenuEventSystem();

            var canvasGo = MenuCanvas("SelectCanvas", camGo.GetComponent<Camera>());
            var controller = canvasGo.AddComponent<CharacterSelectController>();

            BuildBackdrop(canvasGo.transform);

            // ---- Cabecera ----
            var logo = UiImage("LogoSmall", canvasGo.transform, Spr("ww_logo"), Color.white);
            logo.preserveAspect = true;
            var lrt = logo.rectTransform;
            lrt.anchorMin = lrt.anchorMax = new Vector2(0.5f, 1f);
            lrt.pivot = new Vector2(0.5f, 1f);
            lrt.anchoredPosition = new Vector2(0f, -6f);
            lrt.sizeDelta = new Vector2(250f, 250f);

            var title = UiText("Title", canvasGo.transform, font, "PERSONALIZÁ TU LUCHADOR", 44, Color.white);
            var trt = title.rectTransform;
            trt.anchorMin = trt.anchorMax = new Vector2(0.5f, 1f);
            trt.pivot = new Vector2(0.5f, 1f);
            trt.anchoredPosition = new Vector2(0f, -266f);
            trt.sizeDelta = new Vector2(1200f, 56f);
            var titleSh = title.gameObject.AddComponent<Shadow>();
            titleSh.effectColor = new Color(0f, 0f, 0f, 0.8f);
            titleSh.effectDistance = new Vector2(2f, -3f);

            var sub = UiText("Subtitle", canvasGo.transform, font,
                "ELEGÍ EL COLOR DEL CYBORG DE CADA JUGADOR · SE GUARDA SOLO", 20, new Color(1f, 1f, 1f, 0.68f));
            sub.fontStyle = FontStyle.Normal;
            var srt = sub.rectTransform;
            srt.anchorMin = srt.anchorMax = new Vector2(0.5f, 1f);
            srt.pivot = new Vector2(0.5f, 1f);
            srt.anchoredPosition = new Vector2(0f, -324f);
            srt.sizeDelta = new Vector2(1200f, 30f);

            // ---- Emblema central ----
            var vsGlow = UiImage("VsGlow", canvasGo.transform, _soft, new Color(1f, 0.6f, 0.2f, 0.16f));
            var vgrt = vsGlow.rectTransform;
            vgrt.anchorMin = vgrt.anchorMax = new Vector2(0.5f, 0.5f);
            vgrt.anchoredPosition = new Vector2(0f, 30f);
            vgrt.sizeDelta = new Vector2(420f, 420f);

            var divider = Panel(canvasGo.transform, "Divider", new Color(1f, 0.7f, 0.3f, 0.16f));
            var drt = divider.rectTransform;
            drt.anchorMin = drt.anchorMax = new Vector2(0.5f, 0.5f);
            drt.pivot = new Vector2(0.5f, 0.5f);
            drt.anchoredPosition = new Vector2(0f, -70f);
            drt.sizeDelta = new Vector2(3f, 520f);

            var vs = UiText("Vs", canvasGo.transform, font, "VS", 110, new Color(1f, 0.66f, 0.22f, 0.95f));
            var vrt = vs.rectTransform;
            vrt.anchorMin = vrt.anchorMax = new Vector2(0.5f, 0.5f);
            vrt.anchoredPosition = new Vector2(0f, 30f);
            vrt.sizeDelta = new Vector2(400f, 140f);
            var vsSh = vs.gameObject.AddComponent<Shadow>();
            vsSh.effectColor = new Color(0f, 0f, 0f, 0.85f);
            vsSh.effectDistance = new Vector2(3f, -4f);

            // ---- Previews riggeadas + selectores de color ----
            for (int p = 0; p < 2; p++)
            {
                bool left = p == 0;
                var previewRoot = new GameObject($"Preview_J{p + 1}");
                previewRoot.transform.position = new Vector3(left ? -6.3f : 6.3f, -3.6f, 0f);
                var (visual, refs) = BuildVisual(previewRoot.transform, cyborg, charCtrl, 2.3f,
                    GameSession.Palette[GameSession.GetColorIndex(p)], 0f);
                visual.GetComponent<SortingGroup>().sortingOrder = 10;
                if (!left) visual.transform.localScale = new Vector3(-2.3f, 2.3f, 1f);
                visual.baseScale = 2.3f;
                var actor = previewRoot.AddComponent<MenuPreviewActor>();
                actor.visual = visual;

                // Katana en la mano
                var held = new GameObject("HeldKatana");
                held.transform.SetParent(refs.handFront, false);
                held.transform.localRotation = Quaternion.Euler(0f, 0f, -20f);
                var hsr = held.AddComponent<SpriteRenderer>();
                hsr.sprite = Spr("ww_katana");
                hsr.sortingOrder = 30;
                float ks = 1.15f / Mathf.Max(0.01f, hsr.sprite.bounds.size.x);
                held.transform.localScale = new Vector3(ks, ks, 1f);

                var floorGlow = new GameObject("Glow");
                floorGlow.transform.SetParent(previewRoot.transform, false);
                floorGlow.transform.localPosition = new Vector3(0f, 0.05f, 0f);
                floorGlow.transform.localScale = new Vector3(3.2f, 0.9f, 1f);
                var gsr = floorGlow.AddComponent<SpriteRenderer>();
                gsr.sprite = _soft;
                gsr.sharedMaterial = _unlit;
                gsr.color = new Color(0.4f, 0.9f, 1f, 0.35f);
                gsr.sortingOrder = 5;

                var panel = ColorPanel(canvasGo.transform, $"ColorJ{p + 1}", left, $"JUGADOR {p + 1}",
                    font, knob, p, visual);
                var anchor = previewRoot.AddComponent<MenuPreviewAnchor>();
                anchor.target = panel;
                anchor.offset = new Vector2(0f, 1.55f);
            }

            // ---- Volver ----
            var back = MenuButton(canvasGo.transform, "Btn_Volver", "VOLVER AL MENÚ", font);
            var brt = (RectTransform)back.transform;
            brt.anchorMin = brt.anchorMax = new Vector2(0.5f, 0f);
            brt.pivot = new Vector2(0.5f, 0f);
            brt.anchoredPosition = new Vector2(0f, 60f);
            brt.sizeDelta = new Vector2(380f, 68f);
            UnityEventTools.AddPersistentListener(back.onClick, controller.Back);

            var hint = UiText("Hint", canvasGo.transform, font, "ESC · VOLVER AL MENÚ", 17, new Color(1f, 1f, 1f, 0.5f));
            var hrt = hint.rectTransform;
            hrt.anchorMin = hrt.anchorMax = new Vector2(0.5f, 0f);
            hrt.pivot = new Vector2(0.5f, 0f);
            hrt.anchoredPosition = new Vector2(0f, 26f);
            hrt.sizeDelta = new Vector2(600f, 24f);

            controller.fader = FaderCanvas();

            var musicGo = new GameObject("Music");
            var music = musicGo.AddComponent<MusicPlayer>();
            music.clip = MusicClip("ww_music_menu");
            music.volume = 0.5f;

            EditorSceneManager.SaveScene(scene, CharSelectScenePath);
        }

        // =====================================================================
        // Piezas compartidas del menu y de la personalizacion
        // =====================================================================
        private static GameObject MenuCamera()
        {
            var camGo = new GameObject("Main Camera");
            camGo.tag = "MainCamera";
            camGo.transform.position = new Vector3(0f, 0f, -10f);
            var cam = camGo.AddComponent<Camera>();
            cam.orthographic = true;
            cam.orthographicSize = 5.4f;
            cam.clearFlags = CameraClearFlags.SolidColor;
            cam.backgroundColor = Color.black;
            camGo.AddComponent<AudioListener>();
            return camGo;
        }

        private static void MenuLight2D()
        {
            var lightGo = new GameObject("Global Light 2D");
            var light = lightGo.AddComponent<Light2D>();
            light.lightType = Light2D.LightType.Global;
            light.intensity = 1.1f;
        }

        private static EventSystem MenuEventSystem()
        {
            var go = new GameObject("EventSystem");
            var es = go.AddComponent<EventSystem>();
            go.AddComponent<InputSystemUIInputModule>();
            return es;
        }

        private static GameObject MenuCanvas(string name, Camera cam)
        {
            var canvasGo = new GameObject(name, typeof(RectTransform));
            var canvas = canvasGo.AddComponent<Canvas>();
            canvas.renderMode = RenderMode.ScreenSpaceCamera;
            canvas.worldCamera = cam;
            canvas.planeDistance = 5f;
            canvas.sortingOrder = 0;
            var scaler = canvasGo.AddComponent<CanvasScaler>();
            scaler.uiScaleMode = CanvasScaler.ScaleMode.ScaleWithScreenSize;
            scaler.referenceResolution = new Vector2(1920f, 1080f);
            scaler.matchWidthOrHeight = 0.5f;
            canvasGo.AddComponent<GraphicRaycaster>();
            return canvasGo;
        }

        private static CanvasGroup FaderCanvas()
        {
            // OJO: el fader va como canvas raiz. Un canvas anidado delega su
            // renderMode y sortingOrder al canvas raiz, y eso pisaba el modo
            // (Screen Space - Camera) del canvas del menu.
            var faderCanvasGo = new GameObject("FaderCanvas", typeof(RectTransform));
            var fc = faderCanvasGo.AddComponent<Canvas>();
            fc.renderMode = RenderMode.ScreenSpaceOverlay;
            fc.sortingOrder = 100;
            faderCanvasGo.AddComponent<CanvasScaler>();
            faderCanvasGo.AddComponent<GraphicRaycaster>();
            var faderImg = UiImage("Fader", faderCanvasGo.transform, null, Color.black);
            Stretch(faderImg.rectTransform);
            faderImg.raycastTarget = true;
            var fader = faderImg.gameObject.AddComponent<CanvasGroup>();
            fader.alpha = 1f;
            fader.blocksRaycasts = true;
            return fader;
        }

        /// <summary>
        /// Fondo en dos capas de parallax: lejos (fondo + vigas) y cerca (armas
        /// flotantes + brasas), mas sombra, vineta y el rastro del mouse.
        /// Las capas son contenedores vacios: a los hijos los anima el animator.
        /// </summary>
        private static void BuildBackdrop(Transform parent)
        {
            var root = new GameObject("Backdrop", typeof(RectTransform));
            root.transform.SetParent(parent, false);
            Stretch((RectTransform)root.transform);

            var far = new GameObject("LayerFar", typeof(RectTransform));
            far.transform.SetParent(root.transform, false);
            Stretch((RectTransform)far.transform);

            var near = new GameObject("LayerNear", typeof(RectTransform));
            near.transform.SetParent(root.transform, false);
            Stretch((RectTransform)near.transform);

            var bgSpr = Spr("ww_menu_bg_neutral");
            var bg = UiImage("Background", far.transform, bgSpr, Color.white);
            Stretch(bg.rectTransform);
            var fit = bg.gameObject.AddComponent<AspectRatioFitter>();
            fit.aspectMode = AspectRatioFitter.AspectMode.EnvelopeParent;
            fit.aspectRatio = bgSpr != null ? bgSpr.rect.width / bgSpr.rect.height : 1.5f;

            var beams = new GameObject("Beams", typeof(RectTransform));
            beams.transform.SetParent(far.transform, false);
            Stretch((RectTransform)beams.transform);
            Color[] beamColors = { new Color(0.4f, 0.9f, 1f, 0.16f), new Color(1f, 0.7f, 0.35f, 0.12f), new Color(0.6f, 0.95f, 1f, 0.14f) };
            float[] beamX = { -520f, 40f, 560f };
            for (int i = 0; i < 3; i++)
            {
                var b = UiImage("Beam" + i, beams.transform, _soft, beamColors[i]);
                var rt = b.rectTransform;
                rt.anchorMin = rt.anchorMax = new Vector2(0.5f, 1f);
                rt.pivot = new Vector2(0.5f, 1f);
                rt.anchoredPosition = new Vector2(beamX[i], 120f);
                rt.sizeDelta = new Vector2(340f, 1700f);
            }

            var floating = new GameObject("FloatingWeapons", typeof(RectTransform));
            floating.transform.SetParent(near.transform, false);
            Stretch((RectTransform)floating.transform);
            var fw = floating.AddComponent<MenuFloatingWeapons>();
            fw.weapons = new[] { Spr("ww_katana"), Spr("ww_hacha"), Spr("ww_weapon_hammer"), Spr("ww_weapon_spear"), Spr("ww_weapon_saw") };
            fw.count = 16;

            var embers = new GameObject("Embers", typeof(RectTransform));
            embers.transform.SetParent(near.transform, false);
            Stretch((RectTransform)embers.transform);
            var em = embers.AddComponent<MenuEmbers>();
            em.sprite = _soft;
            em.count = 80;

            var shade = UiImage("Shade", root.transform, null, new Color(0f, 0.02f, 0.05f, 0.38f));
            Stretch(shade.rectTransform);

            var vignette = UiImage("Vignette", root.transform, _vignette, Color.white);
            Stretch(vignette.rectTransform);

            var parallax = root.AddComponent<MenuParallax>();
            parallax.layers = new[]
            {
                new MenuParallax.Layer { rect = (RectTransform)far.transform, depth = 0.35f },
                new MenuParallax.Layer { rect = (RectTransform)near.transform, depth = 0.9f },
            };
        }

        /// <summary>
        /// Logo del titulo: halo, estallido que gira por detras y el sprite nuevo.
        /// El brillo (Shine) es hijo del logo con Mask, asi que barre recortado a
        /// la silueta del arte.
        /// </summary>
        private static void BuildMenuLogo(Transform parent)
        {
            var logoGo = new GameObject("Logo", typeof(RectTransform));
            logoGo.transform.SetParent(parent, false);
            var rt = (RectTransform)logoGo.transform;
            rt.anchorMin = rt.anchorMax = new Vector2(0.5f, 1f);
            rt.pivot = new Vector2(0.5f, 1f);
            rt.anchoredPosition = new Vector2(0f, MenuLogoY);
            rt.sizeDelta = new Vector2(640f, 640f);

            var glow = UiImage("Glow", logoGo.transform, _soft, new Color(1f, 0.6f, 0.22f, 0.2f));
            var grt = glow.rectTransform;
            grt.anchorMin = grt.anchorMax = new Vector2(0.5f, 0.5f);
            grt.anchoredPosition = Vector2.zero;
            grt.sizeDelta = new Vector2(1120f, 1120f);

            var burst = UiImage("Burst", logoGo.transform, Spr("ww_logo_burst"), new Color(1f, 1f, 1f, 0.72f));
            var brt = burst.rectTransform;
            brt.anchorMin = brt.anchorMax = new Vector2(0.5f, 0.5f);
            brt.anchoredPosition = Vector2.zero;
            brt.sizeDelta = new Vector2(1000f, 1000f);

            var logo = UiImage("LogoImage", logoGo.transform, Spr("ww_logo"), Color.white);
            Stretch(logo.rectTransform);
            logo.preserveAspect = true;
            logo.gameObject.AddComponent<Mask>().showMaskGraphic = true;

            var shine = UiImage("Shine", logo.transform, _shine, new Color(1f, 0.98f, 0.9f, 0f));
            var srt = shine.rectTransform;
            srt.anchorMin = srt.anchorMax = new Vector2(0.5f, 0.5f);
            srt.pivot = new Vector2(0.5f, 0.5f);
            srt.sizeDelta = new Vector2(260f, 1400f);
            srt.anchoredPosition = new Vector2(660f, 0f);
            srt.localRotation = Quaternion.Euler(0f, 0f, -20f);
        }

        private static Image Panel(Transform parent, string name, Color color)
        {
            var img = UiImage(name, parent, _panel, color);
            img.type = Image.Type.Sliced;
            img.pixelsPerUnitMultiplier = 1f;
            return img;
        }

        private static void TopChip(Transform parent, Font font, bool left, string label, Color accent)
        {
            var go = new GameObject(left ? "Studio" : "Build", typeof(RectTransform));
            go.transform.SetParent(parent, false);
            var rt = (RectTransform)go.transform;
            rt.anchorMin = rt.anchorMax = new Vector2(left ? 0f : 1f, 1f);
            rt.pivot = new Vector2(left ? 0f : 1f, 1f);
            rt.anchoredPosition = new Vector2(left ? 34f : -34f, -22f);
            rt.sizeDelta = new Vector2(left ? 372f : 262f, 42f);

            var bg = Panel(go.transform, "Bg", new Color(0.02f, 0.035f, 0.06f, 0.55f));
            Stretch(bg.rectTransform);

            var dot = UiImage("Dot", go.transform, _soft, accent);
            var drt = dot.rectTransform;
            drt.anchorMin = drt.anchorMax = new Vector2(0f, 0.5f);
            drt.anchoredPosition = new Vector2(21f, 0f);
            drt.sizeDelta = new Vector2(16f, 16f);

            var text = UiText("Label", go.transform, font, label, 17, new Color(1f, 1f, 1f, 0.72f));
            text.alignment = TextAnchor.MiddleLeft;
            var trt = text.rectTransform;
            trt.anchorMin = Vector2.zero;
            trt.anchorMax = Vector2.one;
            trt.offsetMin = new Vector2(38f, 0f);
            trt.offsetMax = new Vector2(-12f, 0f);
        }

        private static void HintRow(Transform parent, Font font, string[] hints)
        {
            var go = new GameObject("Hints", typeof(RectTransform));
            go.transform.SetParent(parent, false);
            var rt = (RectTransform)go.transform;
            rt.anchorMin = rt.anchorMax = new Vector2(0.5f, 0f);
            rt.pivot = new Vector2(0.5f, 0f);
            rt.anchoredPosition = new Vector2(0f, 26f);
            rt.sizeDelta = new Vector2(1240f, 34f);
            go.AddComponent<CanvasGroup>();

            var hlg = go.AddComponent<HorizontalLayoutGroup>();
            hlg.spacing = 14f;
            hlg.childAlignment = TextAnchor.MiddleCenter;
            hlg.childControlWidth = false;
            hlg.childControlHeight = false;
            hlg.childForceExpandWidth = false;
            hlg.childForceExpandHeight = false;

            foreach (var hint in hints)
            {
                var chip = Panel(go.transform, "Hint", new Color(0.03f, 0.05f, 0.08f, 0.5f));
                chip.rectTransform.sizeDelta = new Vector2(Mathf.Clamp(hint.Length * 9.6f + 34f, 150f, 460f), 34f);
                var label = UiText("Label", chip.transform, font, hint, 16, new Color(1f, 1f, 1f, 0.6f));
                Stretch(label.rectTransform);
            }
        }

        /// <summary>Tarjeta de modo: la raiz la anima el intro, el cuerpo lo mueve el runtime.</summary>
        private static MenuModeCard ModeCard(Transform parent, Font font, int i, string title, string subtitle,
            Color accent, string number, Sprite icon)
        {
            var root = new GameObject("Card" + i, typeof(RectTransform));
            root.transform.SetParent(parent, false);
            var rt = (RectTransform)root.transform;
            rt.anchorMin = rt.anchorMax = new Vector2(0.5f, 0f);
            rt.pivot = new Vector2(0.5f, 0f);
            rt.anchoredPosition = new Vector2((i - 1.5f) * 346f, MenuCardY);
            rt.sizeDelta = new Vector2(320f, 144f);
            root.AddComponent<CanvasGroup>();
            var btn = root.AddComponent<Button>();
            btn.transition = Selectable.Transition.None;

            var body = new GameObject("Body", typeof(RectTransform));
            body.transform.SetParent(root.transform, false);
            Stretch((RectTransform)body.transform);

            var glow = UiImage("Glow", body.transform, _soft, new Color(accent.r, accent.g, accent.b, 0f));
            var grt = glow.rectTransform;
            grt.anchorMin = grt.anchorMax = new Vector2(0.5f, 0.5f);
            grt.anchoredPosition = Vector2.zero;
            grt.sizeDelta = new Vector2(408f, 214f);

            var skin = Spr("ww_menu_card_skin");
            var frame = skin != null
                ? UiImage("Frame", body.transform, skin, Color.white)
                : Panel(body.transform, "Frame", new Color(0.035f, 0.055f, 0.09f, 0.82f));
            Stretch(frame.rectTransform);
            frame.raycastTarget = true;
            var outline = frame.gameObject.AddComponent<Outline>();
            outline.effectColor = new Color(accent.r, accent.g, accent.b, 0.16f);
            outline.effectDistance = new Vector2(2f, -2f);
            btn.targetGraphic = frame;

            var accentBar = Panel(body.transform, "Accent", accent);
            var art = accentBar.rectTransform;
            art.anchorMin = new Vector2(0f, 1f);
            art.anchorMax = new Vector2(1f, 1f);
            art.pivot = new Vector2(0.5f, 1f);
            art.anchoredPosition = Vector2.zero;
            art.sizeDelta = new Vector2(0f, 6f);

            // Emblema del modo, fantasma detrás de los textos (se pinta con el acento).
            var mark = UiImage("Mark", body.transform, icon, new Color(accent.r, accent.g, accent.b, 0.1f));
            mark.preserveAspect = true;
            var mrt = mark.rectTransform;
            mrt.anchorMin = mrt.anchorMax = new Vector2(0.5f, 0.5f);
            mrt.anchoredPosition = new Vector2(0f, -2f);
            mrt.sizeDelta = new Vector2(126f, 126f);

            var index = UiText("Index", body.transform, font, number, 24, new Color(1f, 1f, 1f, 0.14f));
            index.alignment = TextAnchor.UpperLeft;
            var irt = index.rectTransform;
            irt.anchorMin = irt.anchorMax = new Vector2(0f, 1f);
            irt.pivot = new Vector2(0f, 1f);
            irt.anchoredPosition = new Vector2(18f, -12f);
            irt.sizeDelta = new Vector2(60f, 30f);

            var label = UiText("Label", body.transform, font, title, 32, new Color(0.8f, 0.85f, 0.92f));
            var lrt = label.rectTransform;
            lrt.anchorMin = lrt.anchorMax = new Vector2(0.5f, 0.5f);
            lrt.anchoredPosition = new Vector2(0f, 12f);
            lrt.sizeDelta = new Vector2(300f, 44f);

            var sub = UiText("Sub", body.transform, font, subtitle, 16, new Color(0.7f, 0.76f, 0.85f, 0.5f));
            var srt = sub.rectTransform;
            srt.anchorMin = srt.anchorMax = new Vector2(0.5f, 0.5f);
            srt.anchoredPosition = new Vector2(0f, -26f);
            srt.sizeDelta = new Vector2(300f, 26f);

            var underline = Panel(body.transform, "Underline", new Color(accent.r, accent.g, accent.b, 0.1f));
            var urt = underline.rectTransform;
            urt.anchorMin = new Vector2(0f, 0f);
            urt.anchorMax = new Vector2(1f, 0f);
            urt.pivot = new Vector2(0.5f, 0f);
            urt.anchoredPosition = new Vector2(0f, 12f);
            urt.sizeDelta = new Vector2(-44f, 2f);

            var card = root.AddComponent<MenuModeCard>();
            card.body = (RectTransform)body.transform;
            card.frame = frame;
            card.frameOutline = outline;
            card.accent = accentBar;
            card.underline = underline;
            card.glow = glow;
            card.watermark = mark;
            card.title = label;
            card.subtitle = sub;
            card.indexLabel = index;
            card.accentColor = accent;
            card.modeIndex = i;
            return card;
        }

        /// <summary>Franja de detalle del modo: titulo, bajada y fichas de datos.</summary>
        private static MenuModeInfo ModeInfoStrip(Transform parent, Font font, Color[] accents)
        {
            var go = new GameObject("ModeInfo", typeof(RectTransform));
            go.transform.SetParent(parent, false);
            var rt = (RectTransform)go.transform;
            rt.anchorMin = rt.anchorMax = new Vector2(0.5f, 0f);
            rt.pivot = new Vector2(0.5f, 0f);
            rt.anchoredPosition = new Vector2(0f, MenuInfoY);
            rt.sizeDelta = new Vector2(1180f, 138f);
            var group = go.AddComponent<CanvasGroup>();

            var stripSkin = Spr("ww_menu_info_skin");
            var bg = stripSkin != null
                ? UiImage("Bg", go.transform, stripSkin, Color.white)
                : Panel(go.transform, "Bg", new Color(0.02f, 0.035f, 0.06f, 0.66f));
            Stretch(bg.rectTransform);
            var outline = bg.gameObject.AddComponent<Outline>();
            outline.effectColor = new Color(1f, 1f, 1f, 0.06f);
            outline.effectDistance = new Vector2(1f, -1f);

            var bar = Panel(go.transform, "Bar", accents[0]);
            var brt = bar.rectTransform;
            brt.anchorMin = new Vector2(0f, 0f);
            brt.anchorMax = new Vector2(0f, 1f);
            brt.pivot = new Vector2(0f, 0.5f);
            brt.anchoredPosition = new Vector2(3f, 0f);
            brt.sizeDelta = new Vector2(5f, -18f);

            // Emblema del modo, fantasma a la derecha (detrás de las fichas).
            var mark = UiImage("Mark", go.transform, Spr("ww_icon_duel"),
                new Color(accents[0].r, accents[0].g, accents[0].b, 0.16f));
            mark.preserveAspect = true;
            var mrt = mark.rectTransform;
            mrt.anchorMin = mrt.anchorMax = new Vector2(1f, 0.5f);
            mrt.pivot = new Vector2(1f, 0.5f);
            mrt.anchoredPosition = new Vector2(-26f, -8f);
            mrt.sizeDelta = new Vector2(108f, 108f);

            var title = UiText("Title", go.transform, font, "", 30, Color.white);
            title.alignment = TextAnchor.MiddleLeft;
            var trt = title.rectTransform;
            trt.anchorMin = new Vector2(0f, 1f);
            trt.anchorMax = new Vector2(1f, 1f);
            trt.pivot = new Vector2(0f, 1f);
            trt.anchoredPosition = new Vector2(36f, -10f);
            trt.sizeDelta = new Vector2(-670f, 40f);

            var blurb = UiText("Blurb", go.transform, font, "", 18, new Color(1f, 1f, 1f, 0.72f));
            blurb.alignment = TextAnchor.UpperLeft;
            blurb.fontStyle = FontStyle.Normal;
            var brrt = blurb.rectTransform;
            brrt.anchorMin = new Vector2(0f, 1f);
            brrt.anchorMax = new Vector2(1f, 1f);
            brrt.pivot = new Vector2(0f, 1f);
            brrt.anchoredPosition = new Vector2(36f, -56f);
            brrt.sizeDelta = new Vector2(-72f, 62f);

            var chipsRow = new GameObject("Chips", typeof(RectTransform));
            chipsRow.transform.SetParent(go.transform, false);
            var crt = (RectTransform)chipsRow.transform;
            crt.anchorMin = new Vector2(1f, 1f);
            crt.anchorMax = new Vector2(1f, 1f);
            crt.pivot = new Vector2(1f, 1f);
            crt.anchoredPosition = new Vector2(-26f, -12f);
            crt.sizeDelta = new Vector2(600f, 36f);
            var hlg = chipsRow.AddComponent<HorizontalLayoutGroup>();
            hlg.spacing = 10f;
            hlg.childAlignment = TextAnchor.MiddleRight;
            hlg.childControlWidth = false;
            hlg.childControlHeight = false;
            hlg.childForceExpandWidth = false;
            hlg.childForceExpandHeight = false;

            var chipSkin = Spr("ww_menu_chip_skin");
            var chips = new MenuModeInfo.Chip[3];
            for (int i = 0; i < chips.Length; i++)
            {
                var cgo = new GameObject("Chip" + i, typeof(RectTransform));
                cgo.transform.SetParent(chipsRow.transform, false);
                ((RectTransform)cgo.transform).sizeDelta = new Vector2(186f, 34f);
                var cg = cgo.AddComponent<CanvasGroup>();
                var cimg = chipSkin != null
                    ? UiImage("Bg", cgo.transform, chipSkin, Color.white)
                    : Panel(cgo.transform, "Bg", new Color(1f, 1f, 1f, 0.06f));
                Stretch(cimg.rectTransform);
                var clabel = UiText("Label", cgo.transform, font, "", 15, new Color(1f, 1f, 1f, 0.8f));
                Stretch(clabel.rectTransform);
                chips[i] = new MenuModeInfo.Chip { group = cg, bg = cimg, label = clabel };
            }

            var info = go.AddComponent<MenuModeInfo>();
            info.group = group;
            info.title = title;
            info.blurb = blurb;
            info.accentBar = bar;
            info.frame = bg;
            info.watermark = mark;
            info.modeIcons = new[] { Spr("ww_icon_duel"), Spr("ww_icon_pvp"), Spr("ww_icon_survival"), Spr("ww_icon_exit") };
            info.chips = chips;
            info.modes = new[]
            {
                new MenuModeInfo.Entry
                {
                    title = "DUELO 1 VS 1",
                    blurb = "Dos jugadores en la misma arena, mejor de tres rondas. A los 75 segundos entra el Overdrive y el daño se multiplica x1.5 hasta que alguien caiga.",
                    chips = new[] { "LOCAL · 2 JUGADORES", "MEJOR DE 3", "OVERDRIVE x1.5" },
                    accent = accents[0]
                },
                new MenuModeInfo.Entry
                {
                    title = "PVP ONLINE",
                    blurb = "Emparejamiento en vivo contra otro jugador. El servidor arbitra las rondas y comparte la semilla, así los dos pelean exactamente la misma arena.",
                    chips = new[] { "ONLINE 1 VS 1", "EL SERVIDOR ARBITRA", "MISMA SEMILLA" },
                    accent = accents[1]
                },
                new MenuModeInfo.Entry
                {
                    title = "SUPERVIVENCIA VS BOTS",
                    blurb = "Oleadas cada vez más duras: drones sierra, androides lanceros y caballeros pesados. Entre oleada y oleada recuperás vida y arranca la siguiente.",
                    chips = new[] { "OLEADAS CRECIENTES", "3 ARQUETIPOS", "+30 DE VIDA" },
                    accent = accents[2]
                },
                new MenuModeInfo.Entry
                {
                    title = "SALIR",
                    blurb = "Cerrás el juego y volvés al escritorio. Adentro de la arena podés volver a este menú cuando quieras con Esc.",
                    chips = new[] { "ESC · VOLVER AL MENÚ", "CIERRA EL JUEGO" },
                    accent = accents[3]
                },
            };
            return info;
        }

        private static RectTransform ColorPanel(Transform parent, string name, bool left, string title, Font font,
            Sprite knob, int playerIndex, CharacterVisual preview)
        {
            var panel = new GameObject(name, typeof(RectTransform));
            panel.transform.SetParent(parent, false);
            var rt = (RectTransform)panel.transform;
            rt.anchorMin = rt.anchorMax = new Vector2(left ? 0f : 1f, 0f);
            rt.pivot = new Vector2(0.5f, 0f);
            rt.anchoredPosition = new Vector2(left ? 340f : -340f, 74f);
            rt.sizeDelta = new Vector2(470f, 120f);
            panel.AddComponent<CanvasGroup>();

            var bg = Panel(panel.transform, "Bg", new Color(0.02f, 0.035f, 0.06f, 0.7f));
            Stretch(bg.rectTransform);
            var outline = bg.gameObject.AddComponent<Outline>();
            outline.effectColor = new Color(0.4f, 0.85f, 1f, 0.22f);
            outline.effectDistance = new Vector2(2f, -2f);

            var label = UiText("Title", panel.transform, font, title, 24, new Color(1f, 1f, 1f, 0.92f));
            var lrt = label.rectTransform;
            lrt.anchorMin = new Vector2(0f, 1f);
            lrt.anchorMax = new Vector2(1f, 1f);
            lrt.pivot = new Vector2(0.5f, 1f);
            lrt.anchoredPosition = new Vector2(0f, -10f);
            lrt.sizeDelta = new Vector2(0f, 34f);

            var row = new GameObject("Swatches", typeof(RectTransform));
            row.transform.SetParent(panel.transform, false);
            var rrt = (RectTransform)row.transform;
            rrt.anchorMin = new Vector2(0f, 0f);
            rrt.anchorMax = new Vector2(1f, 0f);
            rrt.pivot = new Vector2(0.5f, 0f);
            rrt.anchoredPosition = new Vector2(0f, 16f);
            rrt.sizeDelta = new Vector2(-20f, 52f);
            var hlg = row.AddComponent<HorizontalLayoutGroup>();
            hlg.spacing = 8f;
            hlg.childAlignment = TextAnchor.MiddleCenter;
            hlg.childControlWidth = false;
            hlg.childControlHeight = false;
            hlg.childForceExpandWidth = false;
            hlg.childForceExpandHeight = false;

            var buttons = new Button[GameSession.Palette.Length];
            for (int i = 0; i < buttons.Length; i++)
            {
                var sw = UiImage("Swatch" + i, row.transform, knob, GameSession.Palette[i]);
                sw.rectTransform.sizeDelta = new Vector2(40f, 40f);
                sw.raycastTarget = true;
                var btn = sw.gameObject.AddComponent<Button>();
                var nav = btn.navigation;
                nav.mode = Navigation.Mode.Automatic;
                btn.navigation = nav;
                buttons[i] = btn;
            }

            var selector = UiImage("Selector", row.transform, knob, Color.white);
            selector.rectTransform.sizeDelta = new Vector2(52f, 52f);
            selector.gameObject.AddComponent<LayoutElement>().ignoreLayout = true;

            var picker = panel.AddComponent<MenuColorPicker>();
            picker.playerIndex = playerIndex;
            picker.swatches = buttons;
            picker.selector = selector.rectTransform;
            picker.preview = preview;
            return rt;
        }

        /// <summary>Intro + idle del menu. El idle dura 12 s para que el giro del estallido cierre exacto.</summary>
        private static AnimatorController BuildMenuController()
        {
            string dir = AnimDir + "/Menu";
            var rt = typeof(RectTransform);
            var img = typeof(Image);
            var cg = typeof(CanvasGroup);

            // ---------------- INTRO ----------------
            var intro = NewClip(dir + "/Menu_Intro.anim");

            AddCurve(intro, "Backdrop/LayerFar/Background", rt, "m_LocalScale.x", K(0f, 1.26f), K(1.6f, 1.04f));
            AddCurve(intro, "Backdrop/LayerFar/Background", rt, "m_LocalScale.y", K(0f, 1.26f), K(1.6f, 1.04f));
            AddCurve(intro, "Backdrop/Shade", img, "m_Color.a", K(0f, 0.72f), K(1.2f, 0.38f));
            AddCurve(intro, "Backdrop/Vignette", img, "m_Color.a", K(0f, 0f), K(1.35f, 1f));
            for (int i = 0; i < 3; i++)
                AddCurve(intro, $"Backdrop/LayerFar/Beams/Beam{i}", img, "m_Color.a", K(0f, 0f), K(1.5f, 0.15f));

            // Estallido: entra girando y se asienta detras del titulo
            AddCurve(intro, "Logo/Burst", rt, "m_LocalScale.x", K(0f, 0.32f), K(0.5f, 1.24f), K(0.82f, 0.97f), K(1.05f, 1f));
            AddCurve(intro, "Logo/Burst", rt, "m_LocalScale.y", K(0f, 0.32f), K(0.5f, 1.24f), K(0.82f, 0.97f), K(1.05f, 1f));
            AddCurve(intro, "Logo/Burst", rt, RotZ, K(0f, -46f), K(1.6f, 104f));
            AddCurve(intro, "Logo/Burst", img, "m_Color.a", K(0f, 0f), K(0.5f, 0.85f), K(1.6f, 0.72f));

            AddCurve(intro, "Logo/Glow", rt, "m_LocalScale.x", K(0f, 0.55f), K(0.6f, 1.32f), K(1.15f, 1.02f));
            AddCurve(intro, "Logo/Glow", rt, "m_LocalScale.y", K(0f, 0.55f), K(0.6f, 1.32f), K(1.15f, 1.02f));
            AddCurve(intro, "Logo/Glow", img, "m_Color.a", K(0f, 0f), K(0.55f, 0.5f), K(1.45f, 0.2f));

            // Titulo: cae, rebota y aterriza con un giro corto
            AddCurve(intro, "Logo/LogoImage", rt, "m_LocalScale.x",
                K(0f, 0.52f), K(0.2f, 0.52f), K(0.66f, 1.14f), K(0.86f, 0.965f), K(1.04f, 1f));
            AddCurve(intro, "Logo/LogoImage", rt, "m_LocalScale.y",
                K(0f, 0.52f), K(0.2f, 0.52f), K(0.66f, 1.14f), K(0.86f, 0.965f), K(1.04f, 1f));
            AddCurve(intro, "Logo/LogoImage", rt, "m_AnchoredPosition.y",
                K(0f, -140f), K(0.2f, -140f), K(0.82f, 14f), K(1.12f, 0f));
            AddCurve(intro, "Logo/LogoImage", rt, RotZ, K(0f, -17f), K(0.2f, -17f), K(0.66f, 4.5f), K(0.94f, 0f));

            // Brillo que barre el logo justo cuando aterriza
            AddCurve(intro, "Logo/LogoImage/Shine", img, "m_Color.a", K(0f, 0f), K(0.72f, 0f), K(1f, 0.6f), K(1.55f, 0f));
            AddCurve(intro, "Logo/LogoImage/Shine", rt, "m_AnchoredPosition.x", K(0f, -600f), K(0.72f, -600f), K(1.55f, 640f));

            AddCurve(intro, "Chips", cg, "m_Alpha", K(0f, 0f), K(0.5f, 0f), K(1.05f, 1f));

            for (int i = 0; i < 4; i++)
            {
                float t0 = 0.42f + i * 0.11f;
                string cardPath = "Cards/Card" + i;
                AddCurve(intro, cardPath, rt, "m_AnchoredPosition.y",
                    K(0f, MenuCardY - 96f), K(t0, MenuCardY - 96f), K(t0 + 0.44f, MenuCardY));
                AddCurve(intro, cardPath, rt, "m_LocalScale.x", K(0f, 0.82f), K(t0, 0.82f), K(t0 + 0.28f, 1.06f), K(t0 + 0.46f, 1f));
                AddCurve(intro, cardPath, rt, "m_LocalScale.y", K(0f, 0.82f), K(t0, 0.82f), K(t0 + 0.28f, 1.06f), K(t0 + 0.46f, 1f));
                AddCurve(intro, cardPath, cg, "m_Alpha", K(0f, 0f), K(t0, 0f), K(t0 + 0.3f, 1f));
            }

            AddCurve(intro, "Hints", cg, "m_Alpha", K(0f, 0f), K(1.15f, 0f), K(1.65f, 1f));
            FinishClip(intro, false);

            // ---------------- IDLE (12 s) ----------------
            var idle = NewClip(dir + "/Menu_Idle.anim");

            AddCurve(idle, "Logo/LogoImage", rt, "m_LocalScale.x",
                K(0f, 1f), K(2f, 1.028f), K(4f, 1f), K(6f, 1.028f), K(8f, 1f), K(10f, 1.028f), K(12f, 1f));
            AddCurve(idle, "Logo/LogoImage", rt, "m_LocalScale.y",
                K(0f, 1f), K(2f, 1.028f), K(4f, 1f), K(6f, 1.028f), K(8f, 1f), K(10f, 1.028f), K(12f, 1f));
            AddCurve(idle, "Logo/LogoImage", rt, RotZ,
                K(0f, 0f), K(2f, -1.2f), K(4f, 0f), K(6f, 1.2f), K(8f, 0f), K(10f, -1.2f), K(12f, 0f));
            AddCurve(idle, "Logo/LogoImage", rt, "m_AnchoredPosition.y",
                K(0f, 0f), K(3f, 10f), K(6f, 0f), K(9f, 10f), K(12f, 0f));

            AddCurve(idle, "Logo/Burst", rt, RotZ, K(0f, 0f), K(12f, -360f));
            AddCurve(idle, "Logo/Burst", img, "m_Color.a",
                K(0f, 0.68f), K(3f, 0.8f), K(6f, 0.66f), K(9f, 0.78f), K(12f, 0.68f));

            AddCurve(idle, "Logo/Glow", rt, "m_LocalScale.x", K(0f, 1.02f), K(3f, 1.14f), K(6f, 1.02f), K(9f, 1.14f), K(12f, 1.02f));
            AddCurve(idle, "Logo/Glow", rt, "m_LocalScale.y", K(0f, 1.02f), K(3f, 1.14f), K(6f, 1.02f), K(9f, 1.14f), K(12f, 1.02f));
            AddCurve(idle, "Logo/Glow", img, "m_Color.a", K(0f, 0.2f), K(3f, 0.3f), K(6f, 0.19f), K(9f, 0.29f), K(12f, 0.2f));

            // Dos barridos de brillo por vuelta
            AddCurve(idle, "Logo/LogoImage/Shine", rt, "m_AnchoredPosition.x",
                K(0f, 640f), K(1f, 640f), K(2.6f, -640f), K(7f, -640f), K(8.6f, 640f), K(12f, 640f));
            AddCurve(idle, "Logo/LogoImage/Shine", img, "m_Color.a",
                K(0f, 0f), K(1f, 0f), K(1.7f, 0.52f), K(2.6f, 0f), K(7f, 0f), K(7.8f, 0.44f), K(8.6f, 0f), K(12f, 0f));

            AddCurve(idle, "Backdrop/LayerFar/Background", rt, "m_LocalScale.x", K(0f, 1.04f), K(6f, 1.08f), K(12f, 1.04f));
            AddCurve(idle, "Backdrop/LayerFar/Background", rt, "m_LocalScale.y", K(0f, 1.04f), K(6f, 1.08f), K(12f, 1.04f));
            AddCurve(idle, "Backdrop/LayerFar/Background", rt, "m_AnchoredPosition.x", K(0f, -16f), K(6f, 18f), K(12f, -16f));
            AddCurve(idle, "Backdrop/LayerFar/Background", rt, "m_AnchoredPosition.y", K(0f, 9f), K(6f, -10f), K(12f, 9f));

            float[] beamAlpha = { 0.15f, 0.17f, 0.14f };
            for (int i = 0; i < 3; i++)
            {
                float a0 = i % 2 == 0 ? -9f : 7f;
                AddCurve(idle, $"Backdrop/LayerFar/Beams/Beam{i}", rt, RotZ,
                    K(0f, a0), K(3f, -a0), K(6f, a0), K(9f, -a0), K(12f, a0));
                AddCurve(idle, $"Backdrop/LayerFar/Beams/Beam{i}", img, "m_Color.a",
                    K(0f, beamAlpha[i]), K(3f, 0.07f), K(6f, 0.19f), K(9f, 0.08f), K(12f, beamAlpha[i]));
            }

            AddCurve(idle, "Backdrop/Vignette", img, "m_Color.a", K(0f, 1f), K(6f, 0.84f), K(12f, 1f));
            FinishClip(idle, true);

            string path = dir + "/MainMenu.controller";
            if (File.Exists(path)) AssetDatabase.DeleteAsset(path);
            var ctrl = AnimatorController.CreateAnimatorControllerAtPath(path);
            var sm = ctrl.layers[0].stateMachine;
            var sIntro = sm.AddState("Intro", new Vector3(300, 0));
            sIntro.motion = intro;
            var sIdle = sm.AddState("Idle", new Vector3(300, 120));
            sIdle.motion = idle;
            sm.defaultState = sIntro;
            var t = sIntro.AddTransition(sIdle);
            t.hasExitTime = true; t.exitTime = 1f; t.duration = 0.25f;
            EditorUtility.SetDirty(ctrl);
            return ctrl;
        }

        private static Button MenuButton(Transform parent, string name, string label, Font font)
        {
            var img = UiImage(name, parent, null, new Color(0.03f, 0.05f, 0.08f, 0.75f));
            img.rectTransform.sizeDelta = new Vector2(560f, 76f);
            img.raycastTarget = true;
            var outline = img.gameObject.AddComponent<Outline>();
            outline.effectColor = new Color(0.35f, 0.85f, 1f, 0.45f);
            outline.effectDistance = new Vector2(2f, -2f);

            var btn = img.gameObject.AddComponent<Button>();
            var colors = btn.colors;
            colors.normalColor = Color.white;
            colors.highlightedColor = new Color(0.85f, 0.95f, 1f);
            colors.selectedColor = new Color(0.85f, 0.95f, 1f);
            colors.pressedColor = new Color(0.5f, 0.85f, 1f);
            btn.colors = colors;

            var accent = UiImage("Accent", img.transform, null, new Color(1f, 0.6f, 0.15f, 0f));
            var art = accent.rectTransform;
            art.anchorMin = new Vector2(0f, 0f);
            art.anchorMax = new Vector2(1f, 0f);
            art.pivot = new Vector2(0.5f, 0f);
            art.sizeDelta = new Vector2(0f, 5f);
            art.anchoredPosition = Vector2.zero;

            var text = UiText("Label", img.transform, font, label, 36, Color.white);
            Stretch(text.rectTransform);
            var sh = text.gameObject.AddComponent<Shadow>();
            sh.effectColor = new Color(0f, 0f, 0f, 0.8f);
            sh.effectDistance = new Vector2(2f, -3f);

            var fx = img.gameObject.AddComponent<MenuButtonFx>();
            fx.label = text;
            fx.accent = accent;
            return btn;
        }

        // =====================================================================
        // HUD de partida 1v1 (duelo local + PvP online)
        // =====================================================================
        private const float HudPanelW = 420f;
        private const float HudPanelH = 118f;
        private const float HudHpW = 396f;
        private const float HudHpH = 24f;
        private const float HudChipW = 186f;
        private const float HudChipH = 34f;

        /// <summary>
        /// HUD de la partida 1v1: placas de jugador (vida, marcas de ronda y armas),
        /// marcador de ronda/reloj y avisos. Los skins (ww_hud_*) son gris neutro y
        /// se tintean en runtime con el color de cada personaje; si falta un skin,
        /// cae al Panel clasico. Va en canvas propio por debajo de la cuenta
        /// regresiva PVP (sortingOrder 60).
        /// </summary>
        private static MatchHud BuildMatchHud(Transform parent, Font font)
        {
            var canvasGo = new GameObject("MatchHudCanvas", typeof(RectTransform));
            canvasGo.transform.SetParent(parent, false);
            var canvas = canvasGo.AddComponent<Canvas>();
            canvas.renderMode = RenderMode.ScreenSpaceOverlay;
            canvas.sortingOrder = 50;
            var scaler = canvasGo.AddComponent<CanvasScaler>();
            scaler.uiScaleMode = CanvasScaler.ScaleMode.ScaleWithScreenSize;
            scaler.referenceResolution = new Vector2(1920f, 1080f);
            scaler.matchWidthOrHeight = 0.5f;

            var hud = canvasGo.AddComponent<MatchHud>();

            // ---- Marcador de ronda + reloj (arriba al centro) ----
            var round = UiImage("RoundBanner", canvasGo.transform, Spr("ww_hud_round_plate"), Color.white);
            round.raycastTarget = false;
            HudRect(round.rectTransform, new Vector2(0.5f, 1f), new Vector2(0.5f, 1f),
                new Vector2(0f, -16f), new Vector2(384f, 64f));
            if (round.sprite == null) round.color = new Color(0f, 0f, 0f, 0.55f);

            hud.roundLabel = UiText("Round", round.transform, font, "RONDA 1", 26, Color.white);
            HudStretch(hud.roundLabel.rectTransform, new Vector2(0f, 0f), new Vector2(0.5f, 1f),
                new Vector2(36f, 0f), Vector2.zero);
            hud.roundLabel.alignment = TextAnchor.MiddleLeft;

            hud.clockLabel = UiText("Clock", round.transform, font, "00:00", 26, Color.white);
            HudStretch(hud.clockLabel.rectTransform, new Vector2(0.5f, 0f), new Vector2(1f, 1f),
                Vector2.zero, new Vector2(-36f, 0f));
            hud.clockLabel.alignment = TextAnchor.MiddleRight;

            // ---- Aviso de Overdrive (debajo del marcador; late mientras dura) ----
            var od = UiImage("OverdriveBanner", canvasGo.transform, Spr("ww_hud_round_plate"), MatchHud_OdTint);
            od.raycastTarget = false;
            HudRect(od.rectTransform, new Vector2(0.5f, 1f), new Vector2(0.5f, 1f),
                new Vector2(0f, -88f), new Vector2(384f, 64f));
            if (od.sprite == null) od.color = new Color(0.45f, 0f, 0f, 0.6f);
            hud.overdrivePlate = od;
            hud.overdriveGroup = od.gameObject.AddComponent<CanvasGroup>();
            hud.overdriveGroup.alpha = 0f;

            hud.overdriveLabel = UiText("Label", od.transform, font, "¡OVERDRIVE!   DAÑO ×1.5", 21, new Color(1f, 0.93f, 0.9f));
            Stretch(hud.overdriveLabel.rectTransform);

            // ---- Placas de jugador ----
            hud.slots = new[]
            {
                HudPlayerPanel(canvasGo.transform, font, false, GameSession.Palette[0]),
                HudPlayerPanel(canvasGo.transform, font, true, GameSession.Palette[1]),
            };

            // ---- Anuncio central (entra con fundido + desliz) ----
            var statusGo = new GameObject("Status", typeof(RectTransform));
            statusGo.transform.SetParent(canvasGo.transform, false);
            var statusRt = (RectTransform)statusGo.transform;
            HudRect(statusRt, new Vector2(0.5f, 1f), new Vector2(0.5f, 1f),
                new Vector2(0f, -330f), new Vector2(640f, 120f));
            hud.statusRect = statusRt;
            hud.statusGroup = statusGo.AddComponent<CanvasGroup>();

            var statusBg = UiImage("Bg", statusGo.transform, Spr("ww_hud_status_plate"), Color.white);
            Stretch(statusBg.rectTransform);
            if (statusBg.sprite == null) statusBg.color = new Color(0f, 0f, 0f, 0.55f);
            hud.statusPlate = statusBg;

            hud.statusText = UiText("Text", statusGo.transform, font, "", 40, Color.white);
            HudStretch(hud.statusText.rectTransform, Vector2.zero, Vector2.one,
                new Vector2(22f, 30f), new Vector2(-22f, -12f));
            hud.statusText.resizeTextForBestFit = true;
            hud.statusText.resizeTextMinSize = 22;
            hud.statusText.resizeTextMaxSize = 40;
            hud.statusText.horizontalOverflow = HorizontalWrapMode.Wrap;
            hud.statusText.verticalOverflow = VerticalWrapMode.Overflow;

            hud.statusHint = UiText("Hint", statusGo.transform, font, "", 17, new Color(1f, 1f, 1f, 0.85f));
            HudRect(hud.statusHint.rectTransform, new Vector2(0f, 0f), new Vector2(1f, 0f),
                new Vector2(0f, 14f), new Vector2(-32f, 24f));
            hud.statusHint.fontStyle = FontStyle.Normal;
            hud.statusHint.gameObject.SetActive(false);

            // ---- Pie con los controles ----
            hud.footer = UiText("Footer", canvasGo.transform, font, "", 15, new Color(1f, 1f, 1f, 0.45f));
            HudRect(hud.footer.rectTransform, new Vector2(0f, 0f), new Vector2(1f, 0f),
                new Vector2(0f, 12f), new Vector2(-48f, 22f));
            hud.footer.alignment = TextAnchor.MiddleLeft;
            hud.footer.fontStyle = FontStyle.Normal;
            var footShadow = hud.footer.gameObject.AddComponent<Shadow>();
            footShadow.effectColor = new Color(0f, 0f, 0f, 0.7f);
            footShadow.effectDistance = new Vector2(1f, -1f);

            return hud;
        }

        private static readonly Color MatchHud_OdTint = new Color(1f, 0.34f, 0.30f, 1f);

        /// <summary>Placa de jugador: tag + marcas de ronda, canal de vida y chips de arma.</summary>
        private static MatchHud.PlayerSlot HudPlayerPanel(Transform parent, Font font, bool rightSide, Color accent)
        {
            var go = new GameObject(rightSide ? "PanelJ2" : "PanelJ1", typeof(RectTransform));
            go.transform.SetParent(parent, false);
            var rt = (RectTransform)go.transform;
            float side = rightSide ? -1f : 1f;
            HudRect(rt, new Vector2(rightSide ? 1f : 0f, 1f), new Vector2(rightSide ? 1f : 0f, 1f),
                new Vector2(side * 16f, -16f), new Vector2(HudPanelW, HudPanelH));

            var slot = new MatchHud.PlayerSlot();

            slot.panel = UiImage("Bg", go.transform, Spr("ww_hud_panel_skin"), Color.Lerp(new Color(0.80f, 0.84f, 0.92f), accent, 0.22f));
            Stretch(slot.panel.rectTransform);

            slot.tag = UiText("Tag", go.transform, font, rightSide ? "J2" : "J1", 20, accent);
            HudRect(slot.tag.rectTransform, new Vector2(rightSide ? 1f : 0f, 1f), new Vector2(rightSide ? 1f : 0f, 1f),
                new Vector2(side * 18f, -9f), new Vector2(220f, 26f));
            slot.tag.alignment = rightSide ? TextAnchor.MiddleRight : TextAnchor.MiddleLeft;

            // Marcas de ronda ganada, contra el borde interno.
            var pipsGo = new GameObject("Pips", typeof(RectTransform));
            pipsGo.transform.SetParent(go.transform, false);
            var pipsRt = (RectTransform)pipsGo.transform;
            HudRect(pipsRt, new Vector2(rightSide ? 0f : 1f, 1f), new Vector2(rightSide ? 0f : 1f, 1f),
                new Vector2(side * -14f, -11f), new Vector2(DuelRules.RoundsToWin * 22f + 8f, 20f));
            var pipLayout = pipsGo.AddComponent<HorizontalLayoutGroup>();
            pipLayout.spacing = 8f;
            pipLayout.childAlignment = rightSide ? TextAnchor.MiddleLeft : TextAnchor.MiddleRight;
            pipLayout.childControlWidth = false;
            pipLayout.childControlHeight = false;
            pipLayout.childForceExpandWidth = false;
            pipLayout.childForceExpandHeight = false;

            slot.pips = new Image[DuelRules.RoundsToWin];
            for (int i = 0; i < slot.pips.Length; i++)
            {
                var pip = UiImage("Pip" + (i + 1), pipsGo.transform, Spr("ww_hud_pip"), new Color(1f, 1f, 1f, 0.13f));
                pip.rectTransform.sizeDelta = new Vector2(20f, 20f);
                slot.pips[i] = pip;
            }

            // Canal de vida + relleno (el relleno crece desde el borde externo).
            var track = UiImage("HpTrack", go.transform, Spr("ww_hud_hp_track"), Color.white);
            HudRect(track.rectTransform, new Vector2(rightSide ? 1f : 0f, 1f), new Vector2(rightSide ? 1f : 0f, 1f),
                new Vector2(side * 12f, -42f), new Vector2(HudHpW, HudHpH));
            if (track.sprite == null) track.color = new Color(1f, 1f, 1f, 0.12f);

            var fill = UiImage("HpFill", track.transform, Spr("ww_hud_hp_fill"), new Color(0.36f, 0.88f, 0.42f));
            HudRect(fill.rectTransform,
                new Vector2(rightSide ? 1f : 0f, 0.5f), new Vector2(rightSide ? 1f : 0f, 0.5f),
                new Vector2(side * 4f, 0f), new Vector2(HudHpW - 8f, HudHpH - 8f));
            slot.hpFill = fill;

            // Chips de arma: [1] y [2], la activa levanta.
            var chipsGo = new GameObject("Weapons", typeof(RectTransform));
            chipsGo.transform.SetParent(go.transform, false);
            var chipsRt = (RectTransform)chipsGo.transform;
            HudRect(chipsRt, new Vector2(rightSide ? 1f : 0f, 1f), new Vector2(rightSide ? 1f : 0f, 1f),
                new Vector2(side * 12f, -72f), new Vector2(2f * HudChipW + 10f, HudChipH));
            var chipLayout = chipsGo.AddComponent<HorizontalLayoutGroup>();
            chipLayout.spacing = 10f;
            chipLayout.childAlignment = rightSide ? TextAnchor.MiddleRight : TextAnchor.MiddleLeft;
            chipLayout.childControlWidth = false;
            chipLayout.childControlHeight = false;
            chipLayout.childForceExpandWidth = false;
            chipLayout.childForceExpandHeight = false;

            var chipSkin = Spr("ww_menu_chip_skin");
            slot.chipBg = new Image[2];
            slot.chipLabel = new Text[2];
            for (int i = 0; i < 2; i++)
            {
                var chipGo = new GameObject("Chip" + (i + 1), typeof(RectTransform));
                chipGo.transform.SetParent(chipsGo.transform, false);
                ((RectTransform)chipGo.transform).sizeDelta = new Vector2(HudChipW, HudChipH);

                slot.chipBg[i] = chipSkin != null
                    ? UiImage("Bg", chipGo.transform, chipSkin, Color.white)
                    : Panel(chipGo.transform, "Bg", new Color(1f, 1f, 1f, 0.06f));
                Stretch(slot.chipBg[i].rectTransform);

                slot.chipLabel[i] = UiText("Label", chipGo.transform, font, $"[{i + 1}]  -", 15, new Color(1f, 1f, 1f, 0.8f));
                HudStretch(slot.chipLabel[i].rectTransform, Vector2.zero, Vector2.one,
                    new Vector2(rightSide ? 6f : 12f, 0f), new Vector2(rightSide ? -12f : -6f, 0f));
                slot.chipLabel[i].alignment = rightSide ? TextAnchor.MiddleRight : TextAnchor.MiddleLeft;
            }

            return slot;
        }

        /// <summary>Ancla un RectTransform por anchor/pivot + posicion y tamano (sin offsets).</summary>
        private static void HudRect(RectTransform rt, Vector2 anchorMin, Vector2 anchorMax, Vector2 pos, Vector2 size)
        {
            rt.anchorMin = anchorMin;
            rt.anchorMax = anchorMax;
            rt.pivot = new Vector2(Mathf.Approximately(anchorMin.x, anchorMax.x) ? anchorMin.x : 0.5f,
                                   Mathf.Approximately(anchorMin.y, anchorMax.y) ? anchorMin.y : 0.5f);
            rt.anchoredPosition = pos;
            rt.sizeDelta = size;
        }

        /// <summary>Rect estirado entre anchors, definido por sus offsets.</summary>
        private static void HudStretch(RectTransform rt, Vector2 anchorMin, Vector2 anchorMax,
            Vector2 offsetMin, Vector2 offsetMax)
        {
            rt.anchorMin = anchorMin;
            rt.anchorMax = anchorMax;
            rt.offsetMin = offsetMin;
            rt.offsetMax = offsetMax;
        }

        private static Image UiImage(string name, Transform parent, Sprite sprite, Color color)
        {
            var go = new GameObject(name, typeof(RectTransform), typeof(Image));
            go.transform.SetParent(parent, false);
            var img = go.GetComponent<Image>();
            img.sprite = sprite;
            img.color = color;
            img.raycastTarget = false;
            return img;
        }

        private static Text UiText(string name, Transform parent, Font font, string value, int size, Color color)
        {
            var go = new GameObject(name, typeof(RectTransform), typeof(Text));
            go.transform.SetParent(parent, false);
            var t = go.GetComponent<Text>();
            t.font = font;
            t.text = value;
            t.fontSize = size;
            t.fontStyle = FontStyle.Bold;
            t.alignment = TextAnchor.MiddleCenter;
            t.color = color;
            t.raycastTarget = false;
            return t;
        }

        private static void Stretch(RectTransform rt)
        {
            rt.anchorMin = Vector2.zero;
            rt.anchorMax = Vector2.one;
            rt.offsetMin = Vector2.zero;
            rt.offsetMax = Vector2.zero;
        }
    }
}
