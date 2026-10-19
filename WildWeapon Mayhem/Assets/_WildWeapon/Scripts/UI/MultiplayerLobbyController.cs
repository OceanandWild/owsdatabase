using System.Collections.Generic;
using UnityEngine;
using UnityEngine.SceneManagement;
using UnityEngine.UI;

namespace WildWeapon.UI
{
    /// <summary>
    /// Lobby multijugador local: lista de jugadores (nombre + color + control + equipo),
    /// con agregar/quitar y continuar al selector de mapa.
    /// </summary>
    public class MultiplayerLobbyController : MonoBehaviour
    {
        [Header("Lista")]
        public Transform listContainer;
        public GameObject playerCardPrefab;

        [Header("Botones")]
        public Button addButton;
        public Button removeButton;
        public Button continueButton;
        public Button backButton;

        [Header("Paleta")]
        public Color[] palette = GameSession.Palette;

        // (rows are built directly; no card prefab needed)

        void Start()
        {
            Time.timeScale = 1f;

            if (GameSession.MultiPlayers.Count == 0)
            {
                // Default: 2 jugadores
                GameSession.MultiPlayers.Add(new GameSession.PlayerSlot { name = "Jugador 1", colorIndex = 0 });
                GameSession.MultiPlayers.Add(new GameSession.PlayerSlot { name = "Jugador 2", colorIndex = 1 });
            }

            RebuildList();

            if (addButton != null) addButton.onClick.AddListener(AddPlayer);
            if (removeButton != null) removeButton.onClick.AddListener(RemoveLast);
            if (continueButton != null) continueButton.onClick.AddListener(Continue);
            if (backButton != null) backButton.onClick.AddListener(Back);
        }

        private void RebuildList()
        {
            if (listContainer == null) return;
            foreach (Transform c in listContainer) Destroy(c.gameObject);

            for (int i = 0; i < GameSession.MultiPlayers.Count; i++)
            {
                var slot = GameSession.MultiPlayers[i];
                var row = new GameObject("Row" + i);
                row.transform.SetParent(listContainer, false);
                var rt = row.AddComponent<RectTransform>();
                rt.sizeDelta = new Vector2(0, 48);
                var hlg = row.AddComponent<HorizontalLayoutGroup>();
                hlg.spacing = 6; hlg.childForceExpandWidth = false;

                // Name field
                var nameGo = new GameObject("Name");
                nameGo.transform.SetParent(row.transform, false);
                var nameImg = nameGo.AddComponent<Image>(); nameImg.color = new Color(0.15f,0.15f,0.2f);
                var nameField = nameGo.AddComponent<InputField>();
                var nameText = new GameObject("Text").AddComponent<Text>(); nameText.transform.SetParent(nameGo.transform, false);
                nameText.color = Color.white; nameText.fontSize = 14;
                nameField.textComponent = nameText; nameField.text = slot.name;
                int idx = i;
                nameField.onEndEdit.AddListener(v => GameSession.MultiPlayers[idx].name = v);

                // Color button
                var colGo = new GameObject("Color");
                colGo.transform.SetParent(row.transform, false);
                var colImg = colGo.AddComponent<Image>(); colImg.color = GameSession.Palette[Mathf.Clamp(slot.colorIndex, 0, GameSession.Palette.Length-1)];
                var colBtn = colGo.AddComponent<Button>();
                colBtn.onClick.AddListener(() => CycleColor(idx, colImg));

                // Control dropdown
                var ctrlGo = new GameObject("Control");
                ctrlGo.transform.SetParent(row.transform, false);
                var ctrlImg = ctrlGo.AddComponent<Image>(); ctrlImg.color = new Color(0.2f,0.2f,0.25f);
                var ctrlDd = ctrlGo.AddComponent<Dropdown>();
                ctrlDd.ClearOptions(); ctrlDd.AddOptions(new List<string>{"Teclado","Pad 1","Pad 2","Pad 3","Pad 4"});
                ctrlDd.value = slot.controlIndex;
                ctrlDd.onValueChanged.AddListener(v => GameSession.MultiPlayers[idx].controlIndex = v);

                // Team dropdown
                var teamGo = new GameObject("Team");
                teamGo.transform.SetParent(row.transform, false);
                var teamImg = teamGo.AddComponent<Image>(); teamImg.color = new Color(0.2f,0.2f,0.25f);
                var teamDd = teamGo.AddComponent<Dropdown>();
                teamDd.ClearOptions(); teamDd.AddOptions(new List<string>{"Equipo A","Equipo B","Equipo C","Equipo D"});
                teamDd.value = slot.team;
                teamDd.onValueChanged.AddListener(v => GameSession.MultiPlayers[idx].team = v);
            }
        }

        private void CycleColor(int idx, Image img)
        {
            if (idx < 0 || idx >= GameSession.MultiPlayers.Count) return;
            var s = GameSession.MultiPlayers[idx];
            s.colorIndex = (s.colorIndex + 1) % GameSession.Palette.Length;
            img.color = GameSession.Palette[s.colorIndex];
        }

        public void AddPlayer()
        {
            if (GameSession.MultiPlayers.Count >= 15) return;
            int idx = GameSession.MultiPlayers.Count;
            GameSession.MultiPlayers.Add(new GameSession.PlayerSlot
            {
                name = "Jugador " + (idx + 1),
                colorIndex = idx % GameSession.Palette.Length,
                team = idx % 2,
            });
            RebuildList();
        }

        public void RemoveLast()
        {
            if (GameSession.MultiPlayers.Count <= 1) return;
            GameSession.MultiPlayers.RemoveAt(GameSession.MultiPlayers.Count - 1);
            RebuildList();
        }

        public void UpdateSlot(int index, string name, int colorIndex, int controlIndex, int team)
        {
            if (index < 0 || index >= GameSession.MultiPlayers.Count) return;
            var s = GameSession.MultiPlayers[index];
            s.name = name;
            s.colorIndex = colorIndex;
            s.controlIndex = controlIndex;
            s.team = team;
        }

        private void Continue()
        {
            GameSession.Mode = GameMode.Multi;
            SceneManager.LoadScene(GameSession.MapSelectScene);
        }

        private void Back()
        {
            SceneManager.LoadScene(GameSession.MenuScene);
        }
    }


}
