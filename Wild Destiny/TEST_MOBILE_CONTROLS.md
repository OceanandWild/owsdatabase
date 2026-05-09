# 🧪 Guía de Pruebas - Controles Móviles

## 📋 Checklist de Pruebas

### ✅ Pruebas Básicas

#### 1. Detección de Dispositivo Móvil
- [ ] Abrir el juego en un dispositivo móvil
- [ ] Verificar en la consola: "📱 Mobile Controls initialized"
- [ ] Confirmar que la UI se adapta automáticamente

#### 2. Rotación de Pantalla
- [ ] Abrir en modo portrait (vertical)
- [ ] Verificar que la pantalla rota automáticamente
- [ ] Rotar a landscape (horizontal)
- [ ] Confirmar que el canvas se ajusta correctamente

#### 3. Joystick Virtual
- [ ] Iniciar una Raid
- [ ] Tocar la mitad izquierda de la pantalla
- [ ] Verificar que aparece el joystick
- [ ] Arrastrar el dedo en diferentes direcciones
- [ ] Confirmar que el personaje se mueve correctamente
- [ ] Soltar el dedo y verificar que el personaje se detiene

#### 4. Controles de Habilidades
- [ ] Tocar cada botón de habilidad en la barra inferior
- [ ] Verificar que las habilidades se activan
- [ ] Confirmar que el cooldown funciona
- [ ] Probar combos de habilidades

#### 5. Modo Práctica
- [ ] Entrar al Modo Práctica
- [ ] Usar el joystick para moverse
- [ ] Tocar el panel de control (derecha)
- [ ] Cambiar configuraciones táctilmente
- [ ] Agregar dummies con el botón táctil
- [ ] Salir del modo práctica

---

## 🎮 Pruebas de Raids

### Raid Normal
```
1. Iniciar Raid desde el menú
2. Usar joystick para esquivar enemigos
3. Activar habilidades tocando botones
4. Completar al menos 3 oleadas
5. Verificar que el score se actualiza
6. Pausar con el botón Z (si está disponible)
7. Reanudar y continuar
```

### Raid Personalizada
```
1. Configurar una raid personalizada
2. Iniciar la raid
3. Usar controles móviles
4. Verificar que funciona igual que raid normal
5. Completar la raid
```

---

## 📱 Pruebas de Compatibilidad

### Android
- [ ] Chrome Mobile
- [ ] Firefox Mobile
- [ ] Samsung Internet
- [ ] Opera Mobile

### iOS
- [ ] Safari (iPhone)
- [ ] Safari (iPad)
- [ ] Chrome iOS

### Tamaños de Pantalla
- [ ] Smartphone pequeño (< 5")
- [ ] Smartphone mediano (5-6")
- [ ] Smartphone grande (> 6")
- [ ] Tablet pequeña (7-8")
- [ ] Tablet grande (> 10")

---

## 🔍 Pruebas de Funcionalidad Avanzada

### Multitoque
```
1. Mantener el joystick activo (dedo izquierdo)
2. Tocar habilidades con otro dedo (derecho)
3. Verificar que ambos funcionan simultáneamente
4. Probar con 3+ dedos si es posible
```

### Precisión del Joystick
```
1. Mover el joystick en círculos
2. Verificar que el personaje sigue la dirección
3. Probar movimientos diagonales
4. Verificar la zona muerta (dead zone)
5. Probar el límite de distancia máxima
```

### Rendimiento
```
1. Iniciar raid con muchos enemigos
2. Usar joystick continuamente
3. Activar múltiples habilidades
4. Verificar que no hay lag
5. Comprobar FPS (debería ser > 30)
```

---

## 🐛 Casos de Error Comunes

### Problema: Joystick no aparece
**Solución**:
1. Verificar que estás en Raid o Práctica
2. Tocar específicamente la mitad izquierda
3. Revisar consola para errores
4. Recargar la página

### Problema: Pantalla no rota
**Solución**:
1. Verificar permisos del navegador
2. Rotar manualmente el dispositivo
3. Recargar en orientación horizontal
4. Verificar que no hay bloqueo de rotación en el dispositivo

### Problema: Habilidades no responden
**Solución**:
1. Verificar que no están en cooldown
2. Tocar directamente sobre los botones
3. Asegurarse de tener una clase equipada
4. Revisar que el toque está en la mitad derecha

### Problema: Movimiento errático
**Solución**:
1. Verificar que solo un dedo toca el joystick
2. Limpiar la pantalla del dispositivo
3. Ajustar la sensibilidad (si está disponible)
4. Reiniciar el juego

---

## 📊 Métricas de Éxito

### Funcionalidad
- ✅ Joystick responde en < 50ms
- ✅ Habilidades se activan al primer toque
- ✅ Rotación de pantalla es automática
- ✅ UI es legible en todos los tamaños
- ✅ No hay crashes durante el juego

### Experiencia de Usuario
- ✅ Controles son intuitivos
- ✅ Joystick es visible y claro
- ✅ Botones son suficientemente grandes
- ✅ No hay toques accidentales
- ✅ El juego es disfrutable en móvil

### Rendimiento
- ✅ FPS > 30 en dispositivos modernos
- ✅ FPS > 20 en dispositivos antiguos
- ✅ Sin lag perceptible
- ✅ Batería no se agota rápidamente
- ✅ No hay sobrecalentamiento

---

## 🎯 Escenarios de Prueba Específicos

### Escenario 1: Jugador Nuevo en Móvil
```
1. Abrir el juego por primera vez
2. Equipar un personaje
3. Iniciar primera raid
4. Descubrir controles táctiles
5. Completar raid exitosamente
```

### Escenario 2: Jugador Experimentado
```
1. Equipar clase avanzada
2. Iniciar raid difícil
3. Usar combos complejos
4. Esquivar ataques con precisión
5. Completar raid sin morir
```

### Escenario 3: Modo Práctica Intensivo
```
1. Entrar a modo práctica
2. Configurar dummy inmortal
3. Practicar todos los combos
4. Agregar múltiples dummies
5. Probar todas las habilidades
6. Resetear y repetir
```

### Escenario 4: Sesión Larga
```
1. Jugar durante 30+ minutos
2. Completar múltiples raids
3. Cambiar de clase
4. Entrar y salir de práctica
5. Verificar que no hay degradación de rendimiento
```

---

## 📝 Reporte de Bugs

### Formato de Reporte
```
Título: [Breve descripción del bug]

Dispositivo: [Modelo y OS]
Navegador: [Nombre y versión]
Pasos para reproducir:
1. [Paso 1]
2. [Paso 2]
3. [Paso 3]

Resultado esperado: [Qué debería pasar]
Resultado actual: [Qué pasa realmente]

Capturas de pantalla: [Si es posible]
Logs de consola: [Errores en consola]
```

### Ejemplo
```
Título: Joystick desaparece al cambiar de orientación

Dispositivo: Samsung Galaxy S21, Android 13
Navegador: Chrome 119
Pasos para reproducir:
1. Iniciar raid en landscape
2. Activar joystick
3. Rotar dispositivo a portrait
4. Rotar de vuelta a landscape

Resultado esperado: Joystick sigue funcionando
Resultado actual: Joystick desaparece y no vuelve

Capturas: [adjuntar]
Logs: "Error: touchId is null"
```

---

## ✅ Checklist Final

### Antes de Publicar
- [ ] Todas las pruebas básicas pasan
- [ ] Probado en al menos 3 dispositivos diferentes
- [ ] Probado en al menos 2 navegadores
- [ ] Sin errores críticos en consola
- [ ] Rendimiento aceptable (FPS > 30)
- [ ] UI legible en todos los tamaños
- [ ] Documentación completa
- [ ] README actualizado

### Después de Publicar
- [ ] Monitorear reportes de usuarios
- [ ] Recopilar feedback
- [ ] Identificar mejoras
- [ ] Planear actualizaciones
- [ ] Mantener compatibilidad

---

## 🎉 Criterios de Aprobación

El sistema de controles móviles se considera **APROBADO** si:

✅ Funciona en al menos 90% de dispositivos probados
✅ No hay bugs críticos que impidan jugar
✅ La experiencia es comparable a la versión desktop
✅ Los usuarios pueden completar raids sin problemas
✅ El rendimiento es aceptable (FPS > 30)
✅ La UI es intuitiva y fácil de usar

---

## 📞 Soporte

Si encuentras problemas durante las pruebas:

1. **Revisa la documentación**: MOBILE_CONTROLS_README.md
2. **Consulta el resumen**: MOBILE_IMPLEMENTATION_SUMMARY.md
3. **Revisa la consola**: Busca errores en DevTools
4. **Reporta el bug**: Usa el formato de reporte arriba

---

**Última actualización**: Noviembre 2025
**Versión del sistema**: 1.0.0
**Estado**: ✅ Listo para pruebas
