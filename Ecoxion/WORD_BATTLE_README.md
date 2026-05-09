# ⚔️ Word Battle - Batalla de Palabras

## Descripción
Word Battle es una extensión épica para Ecoxion que permite a los jugadores competir en emocionantes batallas de palabras en español. Los jugadores deben formar palabras válidas usando letras específicas antes de que se acabe el tiempo.

## Características

### 🌐 Sistema Multijugador
- **Salas de Juego**: Crea una sala o únete con un código de 6 caracteres
- **Juego en Tiempo Real**: Cada jugador juega desde su propio dispositivo
- **Sincronización Automática**: El estado del juego se actualiza en tiempo real
- **Host Controls**: El creador de la sala controla el inicio del juego

### 🎮 Mecánicas del Juego
- **Jugadores**: 2-6 jugadores por partida
- **Vidas**: Cada jugador comienza con 3 vidas
- **Tiempo**: 30 segundos por ronda
- **Intentos**: 4 intentos máximos por ronda
- **Letras**: Se proporcionan 2 o 3 letras aleatorias por ronda

### 🏆 Sistema de Recompensas
- **1er Lugar**: 1-7 Ecoxionums
- **2do Lugar**: 1-4 Ecoxionums
- **3er Lugar**: 1-2 Ecoxionums
- **Otros**: Sin recompensa

### 📊 Estadísticas
- Historial de partidas jugadas
- Total de Ecoxionums ganados
- Posición promedio
- Últimas 10 partidas con detalles

## Reglas del Juego

1. **Configuración Inicial**
   - Agregar entre 2 y 6 jugadores
   - Cada jugador debe tener un nombre único
   - Iniciar el juego cuando todos estén listos

2. **Durante la Partida**
   - Se muestran 2 o 3 letras aleatorias
   - El jugador actual tiene 30 segundos para formar una palabra
   - La palabra debe contener todas las letras mostradas
   - Se permiten hasta 4 intentos por ronda

3. **Pérdida de Vidas**
   - Se pierde una vida si se acaba el tiempo
   - Se pierde una vida si se fallan los 4 intentos
   - Un jugador es eliminado cuando pierde sus 3 vidas

4. **Victoria**
   - El juego continúa hasta que solo quede 1 jugador
   - Los 3 primeros lugares reciben recompensas

## Diccionario
El juego incluye un diccionario extenso de palabras en español que cubre:
- Palabras comunes y cotidianas
- Animales, plantas y naturaleza
- Colores, números y días
- Verbos y acciones
- Objetos y lugares
- Y mucho más...

## Instalación

1. La extensión está disponible en la tienda de Ecoxion
2. Precio: 250 Ecoxionums
3. Rareza: Épica
4. Tipo: Activa

## Uso

### Modo Multijugador (Recomendado)

**Crear una Sala:**
1. Instalar y activar la extensión en Ecoxion
2. Hacer clic en "Crear Sala"
3. Ingresar tu nombre
4. Compartir el código de 6 caracteres con tus amigos
5. Esperar a que se unan (2-6 jugadores)
6. Iniciar el juego cuando todos estén listos

**Unirse a una Sala:**
1. Obtener el código de sala de un amigo
2. Hacer clic en "Unirse a Sala"
3. Ingresar el código y tu nombre
4. Esperar a que el host inicie el juego

### Ventajas del Sistema Multijugador
- ✅ Cada jugador usa su propio dispositivo
- ✅ No necesitas estar en el mismo lugar
- ✅ Sincronización automática en tiempo real
- ✅ Fácil de compartir con un código simple

## Endpoints del Servidor

### POST /api/word-battle/verify
Verifica si una palabra es válida en español.

**Request:**
```json
{
  "word": "CASA"
}
```

**Response:**
```json
{
  "valid": true
}
```

### POST /api/word-battle/reward
Guarda una recompensa para un jugador.

**Request:**
```json
{
  "userId": "user123",
  "playerName": "Jorge",
  "position": 1,
  "reward": 7
}
```

**Response:**
```json
{
  "success": true
}
```

### GET /api/word-battle/rewards/:userId
Obtiene el historial de recompensas de un usuario.

**Response:**
```json
[
  {
    "id": 1,
    "user_id": "user123",
    "player_name": "Jorge",
    "position": 1,
    "reward": 7,
    "created_at": "2024-01-15T10:30:00Z"
  }
]
```

## Tecnologías Utilizadas

- **Frontend**: HTML5, CSS3, JavaScript vanilla
- **Backend**: Node.js, Express
- **Base de Datos**: PostgreSQL
- **Estilos**: Gradientes modernos, animaciones CSS

## Características Técnicas

### Interfaz de Usuario
- Diseño responsive y moderno
- Gradientes púrpura/azul
- Animaciones suaves
- Feedback visual inmediato
- Timer con advertencia visual

### Validación de Palabras
- Diccionario extenso en español
- Verificación en tiempo real
- Validación de letras requeridas
- Sistema de intentos

### Persistencia
- Historial de partidas guardado
- Recompensas automáticas
- Sincronización con Ecoxionums
- Estadísticas detalladas

## Futuras Mejoras

- [ ] Modo multijugador online
- [ ] Más categorías de palabras
- [ ] Torneos y rankings globales
- [ ] Logros y medallas especiales
- [ ] Modo práctica individual
- [ ] Diccionario personalizable
- [ ] Temas visuales adicionales
- [ ] Efectos de sonido

## Créditos

Desarrollado para Ocean and Wild Studios
Parte del ecosistema Ecoxion

## Licencia

Propiedad de Ocean and Wild Studios
Todos los derechos reservados
