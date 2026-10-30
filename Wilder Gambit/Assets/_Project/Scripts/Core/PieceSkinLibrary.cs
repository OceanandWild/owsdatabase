using System.Collections.Generic;
using UnityEngine;

namespace WilderGambit.Core
{
    /// <summary>
    /// Biblioteca de skins animadas. Asignar en escena via PieceSkinManager.SetLibrary.
    /// </summary>
    [CreateAssetMenu(fileName = "PieceSkinLibrary", menuName = "Wilder Gambit/Piece Skin Library", order = 3)]
    public class PieceSkinLibrary : ScriptableObject
    {
        public List<PieceSkinConfig> skins = new List<PieceSkinConfig>();

        public int Count => skins != null ? skins.Count : 0;

        public PieceSkinConfig GetSkin(int index)
        {
            if (skins == null || index < 0 || index >= skins.Count) return null;
            return skins[index];
        }

        public PieceSkinConfig GetSkinById(string id)
        {
            if (string.IsNullOrEmpty(id) || skins == null) return null;
            foreach (var s in skins)
                if (s != null && s.skinId == id) return s;
            return null;
        }

        public int GetIndexById(string id)
        {
            if (skins == null) return -1;
            for (int i = 0; i < skins.Count; i++)
                if (skins[i] != null && skins[i].skinId == id) return i;
            return -1;
        }

        public List<PieceSkinConfig> GetSkinsForPiece(PieceType type)
        {
            var result = new List<PieceSkinConfig>();
            if (skins == null) return result;
            foreach (var s in skins)
                if (s != null && s.pieceType == type) result.Add(s);
            return result;
        }
    }
}
