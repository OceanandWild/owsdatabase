Lee esto al final de realizar una tarea si es posible.

Aqui hay una serie de cosas que debes hacer, es opcional o te serviran durante tus tareas:

- Cuando finalizes de hacer algo, siempre haz un 'git push' ya que el server.js y Ocean Pay/index.html se manejan por Render, plataforma que necesita de GitHub para eso.
- Es muy posible que tu grep tool no encuentre algunas cosas, pero buscalos sin dudar, esto si yo te digo que esta, no estoy loco, asi que buscalo donde puedas.
- Debido al uso de .gitignore, se debe de usar git add server.js "Ocean Pay/" package.json explicitamente y no git add . debido a que subira todo el Espacio de Trabajo, algo no deseado

Se incluiran mas cosas luego, pero esto te ayudara a por lo menos entender como realizar la mayoria de las cosas.

--- NOTAS TÉCNICAS PARA AGENTES ---

- ESTÁNDAR DE MONEDA (Ecoxionums): El modelo 2D oficial es un "Cyan Coin" (Cian/Azul con patrón de cruz). 
  - En Canvas: Usar la función 'drawEcoxionumsIcon'.
  - En HTML: Usar la clase CSS '.icon-ecoxionum'.
  - Emojis a reemplazar: 🪙 y 💎.

- ESTÁNDAR DE PERSISTENCIA:
  - NO USAR 'ocean_pay_metadata' para saldos de Ecoxionums.
  - USAR SIEMPRE 'ocean_pay_cards' (columna JSONB 'balances').
  - Endpoint de cambio: POST /ocean-pay/ecoxionums/change.
  - Endpoint de sync: POST /ocean-pay/sync-ecoxionums (Migración inicial).

- DEPLOY SELECTIVO:
  Para evitar subir el escritorio completo, usa estrictamente:
  git add server.js "Ocean Pay/" .gitignore package.json package-lock.json README.txt
  git commit -m "..." 
  git push origin main