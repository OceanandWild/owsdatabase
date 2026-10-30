using System;
using UnityEngine;
using UnityEngine.UIElements;

namespace WilderGambit.UI
{
    /// <summary>
    /// Paginación global de la tienda. Mide el espacio real del catálogo
    /// (columnas × filas que caben sin scroll) y usa ese valor como capacidad
    /// de página: el grid se llena con el espacio disponible y la paginación
    /// solo aparece cuando ya no cabe nada más. Se recalcula al redimensionar
    /// la ventana o al abrir/cerrar el panel de detalle.
    ///
    /// Cualquier pestaña de la tienda (fondos, animaciones, piezas, paquetes…)
    /// se engancha con <see cref="SetSource"/> reutilizando esta misma instancia,
    /// que es la única dueña de los botones de paginación del UXML.
    /// </summary>
    public class ShopGridPager
    {
        private readonly VisualElement _grid;          // shop-items-grid
        private readonly VisualElement _host;          // shop2-catalog: alto real disponible
        private readonly VisualElement _paginationRow; // shop2-pagination (fila completa)
        private readonly Button _btnPrev;
        private readonly Button _btnNext;
        private readonly Button[] _dots = new Button[3];

        private int _capacity;                  // cards por página según el espacio medido
        private int _page;
        private int _itemCount;
        private Action<int, int> _populatePage;  // (startIndex, count)

        // El catálogo se lee mejor en filas parejas (5 + 5) que estirando una
        // sexta card suelta. En pantallas angostas el ancho manda y baja solo.
        private const int MaxCatalogColumns = 5;

        /// <summary>Se dispara cuando cambia el índice de página (flechas o dots).</summary>
        public event Action PageIndexChanged;

        /// <summary>Cards por página (≥1); 6 como fallback antes del primer layout medido.</summary>
        public int Capacity => Mathf.Max(1, _capacity);
        public int Page => _page;
        public int TotalPages => Mathf.Max(1, Mathf.CeilToInt((float)_itemCount / Capacity));
        public int StartIndex => _page * Capacity;

        public ShopGridPager(VisualElement shopRoot, int fallbackCapacity = 6)
        {
            _grid = shopRoot.Q<VisualElement>("shop-items-grid");
            // El espacio real del catálogo es el stage (shop2-catalog, rellena el body),
            // NO shop-connected-view: ese se compacta a su contenido (flex-grow 0) y el
            // paginador creía que solo cabía 1 fila, partiendo en páginas con hueco vacío.
            _host = shopRoot.Q(className: "shop2-catalog");
            if (_host == null)
                _host = shopRoot.Q<VisualElement>("shop-connected-view");
            _paginationRow = shopRoot.Q(className: "shop2-pagination");
            _capacity = fallbackCapacity;

            _dots[0] = shopRoot.Q<Button>("btn-page-1");
            _dots[1] = shopRoot.Q<Button>("btn-page-2");
            _dots[2] = shopRoot.Q<Button>("btn-page-3");
            for (int i = 0; i < _dots.Length; i++)
            {
                int pageIndex = i;
                _dots[i]?.RegisterCallback<ClickEvent>(_ => GoToPage(pageIndex));
            }

            _btnPrev = shopRoot.Q<Button>("btn-page-prev");
            _btnNext = shopRoot.Q<Button>("btn-page-next");
            _btnPrev?.RegisterCallback<ClickEvent>(_ => GoToPage(_page - 1));
            _btnNext?.RegisterCallback<ClickEvent>(_ => GoToPage(_page + 1));

            // Recalcula la capacidad cuando cambia el espacio real (resize / detalle)
            // y cuando cambia el tamaño de las cards (cambio de pestaña: tableros compactos
            // vs variantes grandes). El grid avisa del segundo caso.
            _host?.RegisterCallback<GeometryChangedEvent>(_ => OnHostGeometryChanged());
            _grid?.RegisterCallback<GeometryChangedEvent>(_ => OnHostGeometryChanged());
        }

        /// <summary>
        /// Conecta la fuente de ítems de la pestaña activa: total de elementos y
        /// callback que puebla la página indicada. Recalcula capacidad, repuebla
        /// y actualiza la paginación. Usa <c>resetPage: true</c> al cambiar de pestaña.
        /// </summary>
        public void SetSource(int itemCount, Action<int, int> populatePage, bool resetPage = false)
        {
            _itemCount = Mathf.Max(0, itemCount);
            _populatePage = populatePage;
            if (resetPage) _page = 0;
            _page = Mathf.Clamp(_page, 0, TotalPages - 1);
            Refresh();
        }

        /// <summary>Re mide el espacio (si hay layout), repuebla la página actual y refresca la UI.</summary>
        public void Refresh()
        {
            RecomputeCapacity();
            RenderPage();
            UpdatePaginationUI();
        }

        public void GoToPage(int page)
        {
            int clamped = Mathf.Clamp(page, 0, TotalPages - 1);
            if (clamped != _page)
            {
                _page = clamped;
                PageIndexChanged?.Invoke(); // la selección vive en la página anterior
            }
            RenderPage();
            UpdatePaginationUI();
        }

        private void OnHostGeometryChanged()
        {
            // Solo repinta si el espacio disponible cambió la capacidad
            if (!RecomputeCapacity()) return;
            RenderPage();
            UpdatePaginationUI();
        }

        private void RenderPage()
        {
            if (_itemCount <= 0 || _populatePage == null) return;
            _page = Mathf.Clamp(_page, 0, TotalPages - 1);
            int start = _page * Capacity;
            int count = Mathf.Min(Capacity, _itemCount - start);
            if (count > 0) _populatePage(start, count);

            // Las cards recién creadas aún no tienen layout: re-mide en el próximo
            // frame con su tamaño real y repagina solo si la capacidad cambió.
            // Así el grid siempre se llena antes de paginar (pestañas con cards
            // de distinto tamaño: tableros compactos vs variantes/paquetes).
            _grid?.schedule.Execute(() =>
            {
                if (!RecomputeCapacity()) return;
                _page = Mathf.Clamp(_page, 0, TotalPages - 1);
                int s = _page * Capacity;
                int c = Mathf.Min(Capacity, _itemCount - s);
                if (c > 0) _populatePage(s, c);
                UpdatePaginationUI();
            }).StartingIn(0);
        }

        /// <summary>
        /// Calcula cuántas cards caben realmente en el catálogo (columnas × filas
        /// que entran sin scroll) y los usa como capacidad de página.
        /// Devuelve true si la capacidad cambió.
        /// </summary>
        private bool RecomputeCapacity()
        {
            if (_host == null || _grid == null) return false;

            // Valores NaN-safe: pre-layout las medidas aún no existen
            float hostW = _host.layout.width;
            float hostH = _host.layout.height;
            if (!(hostW > 1f) || !(hostH > 1f)) return false;

            // Métricas reales de la card (respeta los breakpoints responsive)
            float cardW = 176f, cardH = 210f, padX = 12f, padY = 12f; // .bg-card: 176×210, margen 6
            if (_grid.childCount > 0)
            {
                var c = _grid[0];
                if (c.layout.width > 1f)  cardW = c.layout.width;
                if (c.layout.height > 1f) cardH = c.layout.height;
                var rs = c.resolvedStyle;
                if (rs.marginLeft >= 0f && rs.marginRight >= 0f) padX = rs.marginLeft + rs.marginRight;
                if (rs.marginTop >= 0f && rs.marginBottom >= 0f) padY = rs.marginTop + rs.marginBottom;
            }

            // Columnas: se miden contra el ancho real del catálogo (host), no
            // contra el grid: si se limitara el ancho del grid y se volviera a
            // medir, el cálculo se realimentaría y podría quedarse en 1 columna.
            // 36 px = padding lateral del stage (16×2) + padding del scroll (2×2).
            float availW = Mathf.Max(1f, hostW - 36f);
            int cols = Mathf.Max(1, Mathf.FloorToInt(availW / (cardW + padX)));
            cols = Mathf.Min(cols, MaxCatalogColumns);

            // Ancho justo para las columnas elegidas + márgenes simétricos:
            // el flex-wrap reparte las cards en filas parejas (5 + 5) y el
            // bloque queda centrado aunque el content-container no lo centre.
            float gridW = cols * (cardW + padX);
            _grid.style.width = gridW;
            float sideMargin = Mathf.Max(0f, (availW - gridW) * 0.5f);
            _grid.style.marginLeft = sideMargin;
            _grid.style.marginRight = sideMargin;

            // Filas: alto disponible sin scroll = host − margen inferior del scroll
            const float scrollMarginBottom = 10f;
            float paginationBlockH = IsPortraitLayout() ? 84f : 36f; // 72px + margin-top 10px en móvil vertical; 32px + 4px en el resto
            float stepH = cardH + padY;

            // Pasada 1: sin paginación (por si todo cabe en una sola página)
            int rows = Mathf.Max(1, Mathf.FloorToInt((hostH - scrollMarginBottom) / stepH));
            int capacity = cols * rows;

            // Pasada 2: si hace falta más de una página, se reserva el hueco de la paginación
            if (_itemCount > capacity)
            {
                rows = Mathf.Max(1, Mathf.FloorToInt((hostH - scrollMarginBottom - paginationBlockH) / stepH));
                capacity = cols * rows;
            }

            if (capacity <= 0 || capacity == _capacity) return false;

            _capacity = capacity;
            _page = Mathf.Clamp(_page, 0, TotalPages - 1);
            return true;
        }

        private bool IsPortraitLayout()
        {
            for (VisualElement e = _host; e != null; e = e.parent)
                if (e.ClassListContains(UiResponsive.PortraitClass)) return true;
            return false;
        }

        /// <summary>La fila de paginación solo existe cuando hay más de una página.</summary>
        private void UpdatePaginationUI()
        {
            if (_paginationRow != null)
                _paginationRow.style.display = TotalPages > 1 ? DisplayStyle.Flex : DisplayStyle.None;

            for (int i = 0; i < _dots.Length; i++)
            {
                var btn = _dots[i];
                if (btn == null) continue;
                bool visible = i < TotalPages;
                btn.style.display = visible ? DisplayStyle.Flex : DisplayStyle.None;
                if (!visible) continue;
                if (i == _page) btn.AddToClassList("page-active");
                else            btn.RemoveFromClassList("page-active");
            }
        }
    }
}
