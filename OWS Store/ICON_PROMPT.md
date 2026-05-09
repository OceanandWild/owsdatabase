# Prompt para icono de OWS Nexus Store

Genera la imagen con tu herramienta de IA (DALL·E, Midjourney, Ideogram, etc.) y guárdala como **`icon.ico`** en la carpeta `build/`.  
Para Windows, convierte a ICO con [convertico](https://convertio.co/es/png-ico/) o similar si generas PNG primero.

---

## Prompt principal (OWS Nexus Store)

```
App icon for "OWS Nexus Store" - Central Studio Hub. Discover games, tools and experiences from the Ocean and Wild Studios ecosystem. Style: modern, professional, rounded square icon suitable for Windows desktop. Brand colors: cyan (#00f3ff) and electric purple (#bc13fe) on dark navy (#0f172a) background. Gradient or fusion of cube/shop/store symbol. Clean, minimalist, recognizable at 16x16 and 256x256. No text, only symbolic visual. Glass morphism or subtle glow acceptable.
```

---

## Variante corta

```
Square app icon, cyan and purple gradient, cube or store symbol, dark background, modern minimal style, Ocean and Wild Studios, no text.
```

---

## Notas

- **Tamaño recomendado al exportar**: 512x512 px (PNG) y luego convertir a ICO
- **Formato ICO**: debe incluir 16x16, 32x32, 48x48, 256x256 para buena calidad
- Para generar prompts de otros proyectos de `ows_projects`, ejecuta:
  ```bash
  node scripts/fetch-projects.js
  ```
