






































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































































//     <script>
        // ===== PARTICLES BACKGROUND =====
        const particleCanvas = document.getElementById('particles-bg');
        const particleCtx = particleCanvas.getContext('2d');
        particleCanvas.width = window.innerWidth;
        particleCanvas.height = window.innerHeight;

        const particles = [];
        for (let i = 0; i < 100; i++) {
            particles.push({
                x: Math.random() * particleCanvas.width,
                y: Math.random() * particleCanvas.height,
                vx: (Math.random() - 0.5) * 0.5,
                vy: (Math.random() - 0.5) * 0.5,
                size: Math.random() * 2 + 1
            });
        }

        function animateParticles() {
            particleCtx.clearRect(0, 0, particleCanvas.width, particleCanvas.height);
            particleCtx.fillStyle = 'rgba(0, 217, 255, 0.5)';

            particles.forEach(p => {
                p.x += p.vx;
                p.y += p.vy;

                if (p.x < 0 || p.x > particleCanvas.width) p.vx *= -1;
                if (p.y < 0 || p.y > particleCanvas.height) p.vy *= -1;

                particleCtx.beginPath();
                particleCtx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
                particleCtx.fill();
            });

            requestAnimationFrame(animateParticles);
        }
        animateParticles();

        // ===== ASSET LOADER =====
        const AssetLoader = {
            images: new Map(),
            totalAssets: 0,
            loadedAssets: 0,

            loadImage(path) {
                return new Promise((resolve) => {
                    if (this.images.has(path)) {
                        resolve(this.images.get(path));
                        return;
                    }

                    const img = new Image();
                    img.onload = () => {
                        this.images.set(path, img);
                        this.loadedAssets++;
                        this.updateLoadingProgress();
                        resolve(img);
                    };
                    img.onerror = () => {
                        // Try with .jpeg if .jpg failed
                        if (path.endsWith('.jpg')) {
                            const jpegPath = path.replace(/\.jpg$/i, '.jpeg');
                            const jpegImg = new Image();
                            jpegImg.onload = () => {
                                this.images.set(path, jpegImg); // Cache with original path
                                this.images.set(jpegPath, jpegImg); // Also cache with .jpeg path
                                this.loadedAssets++;
                                this.updateLoadingProgress();
                                resolve(jpegImg);
                            };
                            jpegImg.onerror = () => {
                                const placeholder = this.createPlaceholder(path);
                                this.images.set(path, placeholder);
                                this.loadedAssets++;
                                this.updateLoadingProgress();
                                resolve(placeholder);
                            };
                            jpegImg.src = jpegPath;
                        } else {
                            const placeholder = this.createPlaceholder(path);
                            this.images.set(path, placeholder);
                            this.loadedAssets++;
                            this.updateLoadingProgress();
                            resolve(placeholder);
                        }
                    };
                    img.src = path;
                });
            },

            async preloadAssets(paths) {
                this.totalAssets = paths.length;
                this.loadedAssets = 0;
                await Promise.all(paths.map(path => this.loadImage(path)));
            },

            getImage(path) {
                return this.images.get(path) || null;
            },

            updateLoadingProgress() {
                if (this.totalAssets === 0) return;
                const progress = (this.loadedAssets / this.totalAssets) * 100;
                const progressBar = document.querySelector('.loading-progress');
                if (progressBar) progressBar.style.width = `${progress}%`;
            },

            createPlaceholder(path) {
                const canvas = document.createElement('canvas');
                canvas.width = 64;
                canvas.height = 64;
                const ctx = canvas.getContext('2d');
                const name = path.split('/').pop().split('.')[0];

                const gradient = ctx.createLinearGradient(0, 0, 64, 64);
                gradient.addColorStop(0, '#00d9ff');
                gradient.addColorStop(1, '#ff006e');
                ctx.fillStyle = gradient;
                ctx.fillRect(0, 0, 64, 64);

                ctx.strokeStyle = '#fff';
                ctx.lineWidth = 2;
                ctx.strokeRect(2, 2, 60, 60);
                ctx.fillStyle = '#fff';
                ctx.font = 'bold 10px Arial';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText('MISSING', 32, 28);
                ctx.fillText(name.substring(0, 8), 32, 40);

                return canvas;
            }
        };

        // Helper function to normalize ability names for image paths
        function normalizeImageName(name) {
            return name
                .toLowerCase()
                .normalize('NFD')
                .replace(/[\u0300-\u036f]/g, '') // Remove diacritics (tildes, accents, etc.)
                .replace(/[^a-z0-9]/g, ''); // Remove all non-alphanumeric characters (spaces, :, -, etc.)
        }

        // Helper function to get image path with fallback for .jpg/.jpeg
        function getImagePath(basePath) {
            // Si ya tiene extensión, devolverla tal cual
            if (basePath && (basePath.endsWith('.jpg') || basePath.endsWith('.jpeg') || basePath.endsWith('.png'))) {
                return basePath;
            }
            // Si no tiene extensión, intentar con .jpg primero (más común)
            return basePath + '.jpg';
        }

        // Helper function to create image element with fallback
        function createImageWithFallback(basePath, alt, onErrorCallback) {
            const img = new Image();
            let attempts = 0;
            const extensions = ['.jpg', '.jpeg', '.png'];

            function tryLoad(index) {
                if (index >= extensions.length) {
                    if (onErrorCallback) onErrorCallback();
                    return;
                }

                const pathWithoutExt = basePath.replace(/\.(jpg|jpeg|png)$/i, '');
                img.src = pathWithoutExt + extensions[index];

                img.onerror = () => {
                    tryLoad(index + 1);
                };
            }

            img.alt = alt;
            tryLoad(0);
            return img;
        }

        // ===== ROLE DATA - ORIGINAL CHARACTERS (NO COPYRIGHT) =====
        const rolesData = {
            // CHARACTERS = Unique heroes with special abilities
            characters: [
                {
                    id: 'char_rex',
                    name: 'Rex "Thunderjaw" Striker',
                    title: 'El Depredador Primordial',
                    type: 'character',
                    imagePath: 'assets/characters/rex.png',
                    icon: '🦖',
                    race: 'Saurio Ancestral',
                    age: '10,000 años',
                    origin: 'Tierras Salvajes del Cretáceo',

                    // Atributos base
                    stats: {
                        strength: 95,      // Fuerza física
                        agility: 70,       // Velocidad y reflejos
                        intelligence: 45,  // Poder mágico
                        vitality: 90,      // HP y resistencia
                        luck: 60          // Crítico y drops
                    },

                    // Personalidad y trasfondo
                    personality: 'Feroz pero honorable. Rex es un guerrero ancestral que valora la fuerza bruta y el combate directo.',
                    backstory: 'íltimo superviviente de una era olvidada, Rex despertí de su letargo milenario para enfrentar las amenazas del presente. Su rugido hace temblar montañas y su furia es legendaria.',

                    // Especialización
                    playstyle: 'Bruiser de corto alcance con alto daño físico y resistencia',
                    strengths: ['Daño cuerpo a cuerpo devastador', 'Alta supervivencia', 'Control de írea con rugidos'],
                    weaknesses: ['Vulnerable a ataques a distancia', 'Baja movilidad', 'Sin habilidades mígicas'],

                    description: 'Guerrero primordial con fuerza devastadora y rugidos que aturden enemigos',
                    abilities: [
                        { id: 'rex_claw', name: 'Garra Primordial', type: 'standard', cooldown: 2500, currentCooldown: 0, keyBinding: 'q', effectId: 'effect_claw', icon: '🦖', description: 'Golpe salvaje que inflige daño masivo y aplica sangrado' },
                        { id: 'rex_roar', name: 'Rugido del Trueno', type: 'standard', cooldown: 4000, currentCooldown: 0, keyBinding: 'w', effectId: 'effect_roar', icon: '??', description: 'Aturde enemigos cercanos y reduce su defensa por 5s' }
                    ],
                    ultimateAbility: { id: 'rex_ultimate', name: 'Furia del Apex', type: 'ultimate', cooldown: 20000, currentCooldown: 0, keyBinding: 'r', effectId: 'effect_apex', icon: '🔥', description: 'Entra en modo berserker: +50% daño, +30% velocidad, inmune a control por 8s' }
                },
                {
                    id: 'char_nova',
                    name: 'Nova "Stardust" Lumina',
                    title: 'La Guardiana Cósmica',
                    type: 'character',
                    imagePath: 'assets/characters/nova.png',
                    icon: '?',
                    race: 'Celestial Estelar',
                    age: '5,000 años luz',
                    origin: 'Nebulosa de Andrómeda',

                    stats: {
                        strength: 40,
                        agility: 85,
                        intelligence: 95,
                        vitality: 65,
                        luck: 75
                    },

                    personality: 'Serena y sabia. Nova busca el equilibrio entre luz y oscuridad, protegiendo a los inocentes con su poder císmico.',
                    backstory: 'Nacida del corazón de una supernova, Nova viaja entre dimensiones como guardiana del balance universal. Su luz puede sanar o destruir según su voluntad.',

                    playstyle: 'Mago de soporte/daño con habilidades versátiles de luz cósmica',
                    strengths: ['Alto daño mágico a distancia', 'Escudos protectores', 'Movilidad aírea'],
                    weaknesses: ['Baja defensa física', 'Vulnerable en combate cercano', 'Cooldowns largos'],

                    description: 'Ser celestial que manipula energía estelar para proteger y devastar',
                    abilities: [
                        { id: 'nova_beam', name: 'Rayo Estelar', type: 'standard', cooldown: 3000, currentCooldown: 0, keyBinding: 'q', effectId: 'effect_star_beam', icon: '?', description: 'Dispara un rayo de luz pura que atraviesa enemigos' },
                        { id: 'nova_shield', name: 'Escudo Cósmico', type: 'standard', cooldown: 4500, currentCooldown: 0, keyBinding: 'w', effectId: 'effect_cosmic_shield', icon: '🛡️', description: 'Crea un escudo que absorbe daño y refleja proyectiles' }
                    ],
                    ultimateAbility: { id: 'nova_ultimate', name: 'Supernova Divina', type: 'ultimate', cooldown: 22000, currentCooldown: 0, keyBinding: 'r', effectId: 'effect_supernova', icon: '⭐', description: 'Explota en luz cegadora: daño masivo AoE + cura aliados cercanos' }
                },
                {
                    id: 'char_blade',
                    name: 'Kael "Nightblade" Umbra',
                    title: 'El Asesino Fantasma',
                    type: 'character',
                    imagePath: 'assets/characters/blade.png',
                    icon: '???',
                    race: 'Elfo Oscuro',
                    age: '247 años',
                    origin: 'Reino de las Sombras Eternas',

                    stats: {
                        strength: 70,
                        agility: 98,
                        intelligence: 60,
                        vitality: 55,
                        luck: 85
                    },

                    personality: 'Silencioso y letal. Kael es un perfeccionista que valora la precisión sobre la fuerza bruta. Habla poco pero sus acciones son definitivas.',
                    backstory: 'Exiliado de su clan por negarse a asesinar inocentes, Kael ahora usa sus habilidades para cazar a los verdaderos villanos. Sus espadas gemelas nunca fallan.',

                    playstyle: 'Asesino de alta movilidad con daño explosivo y evasión',
                    strengths: ['Críticos devastadores', 'Movilidad extrema', 'Invisibilidad temporal'],
                    weaknesses: ['Muy frágil', 'Requiere precisión', 'Inefectivo contra grupos grandes'],

                    description: 'Maestro de espadas gemelas que danza entre las sombras con letalidad absoluta',
                    abilities: [
                        { id: 'blade_slash', name: 'Corte Fantasma', type: 'standard', cooldown: 2800, currentCooldown: 0, keyBinding: 'q', effectId: 'effect_shadow_slash', icon: '⚔️', description: 'Dash rápido que corta múltiples veces, garantiza crítico' },
                        { id: 'blade_dash', name: 'Paso de Sombra', type: 'standard', cooldown: 4200, currentCooldown: 0, keyBinding: 'w', effectId: 'effect_dash', icon: '??', description: 'Teletransporte corto + invisibilidad por 2s' }
                    ],
                    ultimateAbility: { id: 'blade_ultimate', name: 'Danza de las Mil Hojas', type: 'ultimate', cooldown: 18000, currentCooldown: 0, keyBinding: 'r', effectId: 'effect_blade_storm', icon: '⚔️', description: 'Ataque frenético: 20 cortes en 3s, cada uno con 50% crítico' }
                },
                {
                    id: 'char_phoenix',
                    name: 'Ember "Ashborn" Pyra',
                    title: 'La Inmortal Llameante',
                    type: 'character',
                    imagePath: 'assets/characters/phoenix.png',
                    icon: '??',
                    race: 'Fénix Ancestral',
                    age: 'Inmortal (renacida 47 veces)',
                    origin: 'Volcán del Fin del Mundo',

                    stats: {
                        strength: 65,
                        agility: 75,
                        intelligence: 80,
                        vitality: 70,
                        luck: 90
                    },

                    personality: 'Apasionada y resiliente. Ember ha vivido mil vidas y cada muerte la hace más fuerte. Nunca se rinde y siempre encuentra esperanza en las cenizas.',
                    backstory: 'Cada vez que muere, renace más poderosa. Ember ha presenciado el ascenso y caída de imperios, y su sabiduría es tan vasta como su poder sobre las llamas.',

                    playstyle: 'Mago de fuego con regeneraciín y segunda oportunidad al morir',
                    strengths: ['Renace al morir (1 vez por raid)', 'DoT de fuego potente', 'Auto-curación'],
                    weaknesses: ['Vulnerable a hielo/agua', 'Daño moderado', 'Depende de su pasiva de renacimiento'],

                    description: 'Ave inmortal que controla llamas purificadoras y renace de sus cenizas',
                    abilities: [
                        { id: 'phoenix_flame', name: 'Alas de Fuego', type: 'standard', cooldown: 3200, currentCooldown: 0, keyBinding: 'q', effectId: 'effect_flame_wing', icon: '??', description: 'Lanza plumas ardientes que aplican quemadura por 6s' },
                        { id: 'phoenix_heal', name: 'Renacimiento Menor', type: 'standard', cooldown: 6000, currentCooldown: 0, keyBinding: 'w', effectId: 'effect_rebirth', icon: '??', description: 'Cura 30% HP + elimina efectos negativos' }
                    ],
                    ultimateAbility: { id: 'phoenix_ultimate', name: 'Resurrección del Fénix', type: 'ultimate', cooldown: 25000, currentCooldown: 0, keyBinding: 'r', effectId: 'effect_phoenix_rise', icon: '🔥', description: 'Explota en llamas: daño AoE + renace con 50% HP si muere en 10s' }
                },
                {
                    id: 'char_titan',
                    name: 'Gorath "Ironheart" Magnus',
                    title: 'El Coloso Inquebrantable',
                    type: 'character',
                    imagePath: 'assets/characters/titan.png',
                    icon: '??',
                    race: 'Gigante de Piedra',
                    age: '800 años',
                    origin: 'Montañas del Fin del Mundo',

                    stats: {
                        strength: 92,
                        agility: 45,
                        intelligence: 50,
                        vitality: 100,
                        luck: 55
                    },

                    personality: 'Estoico y protector. Gorath habla con acciones, no palabras. Su presencia inspira confianza y su determinación es inquebrantable.',
                    backstory: 'Forjado en las profundidades de la tierra, Gorath jurí proteger a los díbiles. Su cuerpo de piedra viviente puede soportar cualquier castigo mientras sus aliados están a salvo.',

                    playstyle: 'Tanque puro con control de masas y protección de equipo',
                    strengths: ['HP masivo', 'Alta defensa', 'Aturde grupos', 'Protege aliados'],
                    weaknesses: ['Muy lento', 'Bajo daño', 'Vulnerable a magia penetrante'],

                    description: 'Gigante de piedra viviente con defensa impenetrable y fuerza titánica',
                    abilities: [
                        { id: 'titan_smash', name: 'Puño Sísmico', type: 'standard', cooldown: 3500, currentCooldown: 0, keyBinding: 'q', effectId: 'effect_smash', icon: '👊', description: 'Golpea el suelo: daño AoE + aturde 2s + ralentiza' },
                        { id: 'titan_wall', name: 'Muro de Hierro', type: 'standard', cooldown: 5000, currentCooldown: 0, keyBinding: 'w', effectId: 'effect_wall', icon: '🧱', description: 'Crea barrera que bloquea proyectiles + reduce daño 40% por 5s' }
                    ],
                    ultimateAbility: { id: 'titan_ultimate', name: 'Ira del Coloso', type: 'ultimate', cooldown: 24000, currentCooldown: 0, keyBinding: 'r', effectId: 'effect_titan_wrath', icon: '?', description: 'Crece al doble: +100% HP, +50% defensa, ondas de choque cada 2s por 10s' }
                }
            ],

            // CLASSES = Combat styles/themes
            classes: [
                // SSS TIER - Legendary (1 ticket required) - 6 ABILITIES TOTAL
                {
                    id: 'class_dragonhunter',
                    name: 'Dragonhunter',
                    type: 'class',
                    tier: 'SSS',
                    tierColor: '#ff0000',
                    ticketsRequired: 1,
                    imagePath: 'assets/dragonhunter.jpg',
                    icon: '??',
                    description: 'Legendary dragon slayer with devastating fire abilities',
                    abilities: [
                        { id: 'dragon_arrow', name: 'Triple Flecha Flamígera', type: 'standard', cooldown: 3000, currentCooldown: 0, keyBinding: 'q', effectId: 'effect_flame_arrow', icon: '🏹', iconImage: 'assets/tripleflechaflamigera.jpg', burnStacks: 0, description: 'Dispara tres flechas flamígeras que aplican quemadura acumulativa a los enemigos.' },
                        { id: 'dragon_breath', name: 'Bomba de Aliento de Dragón', type: 'standard', cooldown: 8000, currentCooldown: 0, keyBinding: 'w', effectId: 'effect_dragon_breath', icon: '🐉', description: 'Lanza una bomba explosiva que libera aliento de dragón, quemando a todos los enemigos en el área.' },
                        { id: 'triple_arrow', name: 'Flecha Triple Uso', type: 'standard', cooldown: 5000, currentCooldown: 0, keyBinding: 'e', effectId: 'effect_triple', icon: '🏹', description: 'Dispara tres flechas simultáneas en diferentes direcciones para atacar múltiples objetivos.' },
                        { id: 'nature_rise', name: 'Naturaleza en Ascenso', type: 'standard', cooldown: 12000, currentCooldown: 0, keyBinding: 't', effectId: 'effect_nature', icon: '??', description: 'Invoca el poder de la naturaleza para regenerar vida y aumentar tu defensa temporalmente.' }
                    ],
                    semiUltimate: { id: 'dragon_madness', name: 'Locura Dracónica', type: 'semi-ultimate', cooldown: 18000, currentCooldown: 0, keyBinding: 'a', effectId: 'effect_madness', icon: '🐉', description: 'Entras en un estado de locura dracónica que aumenta masivamente tu velocidad de ataque y daño por fuego.' },
                    ultimateAbility: { id: 'dragon_ultimate', name: 'Explosión Dracónica', type: 'ultimate', cooldown: 25000, currentCooldown: 0, keyBinding: 's', effectId: 'effect_draconic', icon: '💥', description: 'Liberas una explosión devastadora de energía dracónica que vaporiza a todos los enemigos cercanos.' }
                },
                // SSS TIER - EVENTO ESPECIAL: CIVILIZACIONES HISTÓRICAS - ROMA
                {
                    id: 'class_roman_legionary',
                    name: 'Legionario Romano',
                    type: 'class',
                    tier: 'SSS',
                    tierColor: '#dc143c', // Rojo carmesí romano
                    ticketsRequired: 1,
                    imagePath: 'assets/legionarioromano.jpg',
                    icon: '???',
                    title: 'Gloria de Roma',
                    description: 'Guerrero legendario del Imperio Romano. Maestro de la formación testudo y la disciplina militar. La gloria de las legiones vive en cada golpe de su gladius.',
                    abilities: [
                        { id: 'roman_gladius', name: 'Gladius Fulminante', type: 'standard', cooldown: 2800, currentCooldown: 0, keyBinding: 'q', effectId: 'effect_gladius', icon: '??', description: 'Ejecuta una serie de estocadas rápidas con el gladius romano, cada golpe aumenta tu velocidad de ataque un 5% acumulativo.' },
                        { id: 'roman_testudo', name: 'Formación Testudo', type: 'standard', cooldown: 7000, currentCooldown: 0, keyBinding: 'w', effectId: 'effect_testudo', icon: '???', description: 'Adoptas la legendaria formación de tortuga romana. Reduces el daño recibido en 70% y reflejas el 30% del daño bloqueado a los atacantes durante 5 segundos.' },
                        { id: 'roman_pilum', name: 'Lanzamiento de Pilum', type: 'standard', cooldown: 4500, currentCooldown: 0, keyBinding: 'e', effectId: 'effect_pilum', icon: '???', description: 'Lanzas tres jabalinas pilum que atraviesan enemigos en línea recta, causando sangrado masivo y reduciendo su armadura un 40%.' },
                        { id: 'roman_centurion', name: 'Grito del Centurión', type: 'standard', cooldown: 10000, currentCooldown: 0, keyBinding: 't', effectId: 'effect_centurion', icon: '??', description: 'Emites el grito de guerra de un centurión romano. Aturde a todos los enemigos cercanos por 2 segundos y aumenta tu daño un 50% durante 8 segundos.' }
                    ],
                    semiUltimate: {
                        id: 'roman_aquila',
                        name: 'Águila Imperial',
                        type: 'semi-ultimate',
                        cooldown: 20000,
                        currentCooldown: 0,
                        keyBinding: 'a',
                        effectId: 'effect_aquila',
                        icon: '??',
                        description: 'Invocas el espíritu del Aquila romana. Un Águila dorada gigante desciende del cielo, otorgándote invulnerabilidad por 3 segundos mientras emite ondas de choque doradas que empujan y dañan a todos los enemigos. Tu siguiente ataque causa daño crítico garantizado.'
                    },
                    ultimateAbility: {
                        id: 'roman_legio',
                        name: 'Legio Aeterna',
                        type: 'ultimate',
                        cooldown: 30000,
                        currentCooldown: 0,
                        keyBinding: 's',
                        effectId: 'effect_legio_aeterna',
                        icon: '??',
                        description: 'Levantas tu escudo al cielo mientras el campo de batalla se oscurece. Aparecen 20 legionarios de Élite fantasmales en formación de V que cargan pisoteando todo a su paso. Quedas en el centro con un aura dorada radiante y capa carmesí ondeando, invulnerable durante 4.5 segundos. Los legionarios causan daño masivo y aplican el efecto "Terror Romano" que reduce la velocidad y daño enemigo un 80%. Duración: 4.5s. Colores: Rojo carmesí y oro imperial.'
                    }
                },
                // SSS TIER - EVENTO ESPECIAL: CIVILIZACIONES HISTÓRICAS - GRECIA
                {
                    id: 'class_spartan_hoplite',
                    name: 'Hoplita Espartano',
                    type: 'class',
                    tier: 'SSS',
                    tierColor: '#8B0000', // Rojo espartano
                    ticketsRequired: 1,
                    imagePath: 'assets/hoplitaespartano.jpg',
                    icon: '???',
                    title: 'Gloria de Esparta',
                    description: 'Guerrero legendario de Esparta. Maestro de la falange y el combate hoplon. "Volver con el escudo o sobre íl" - el código del guerrero espartano.',
                    abilities: [
                        { id: 'spartan_dory', name: 'Doru Penetrante', type: 'standard', cooldown: 3000, currentCooldown: 0, keyBinding: 'q', effectId: 'effect_dory', icon: '???', description: 'Lanzas tu doru (lanza espartana) que atraviesa a todos los enemigos en línea recta, causando daño masivo y aplicando sangrado.' },
                        { id: 'spartan_phalanx', name: 'Falange Espartana', type: 'standard', cooldown: 8000, currentCooldown: 0, keyBinding: 'w', effectId: 'effect_phalanx', icon: '???', description: 'Adoptas la formación de falange con tu escudo hoplon. Reduces el daño recibido en 75% y empujas a los enemigos cercanos. Duración: 6 segundos.' },
                        { id: 'spartan_charge', name: 'Carga Espartana', type: 'standard', cooldown: 5000, currentCooldown: 0, keyBinding: 'e', effectId: 'effect_charge', icon: '?', description: 'Cargas hacia adelante con tu escudo, empujando y aturdiendo a todos los enemigos en tu camino. Aumenta tu velocidad un 50% durante 3 segundos.' },
                        { id: 'spartan_aroo', name: 'Grito de Guerra: ¡AROO!', type: 'standard', cooldown: 12000, currentCooldown: 0, keyBinding: 't', effectId: 'effect_aroo', icon: '??', description: 'Emites el legendario grito de guerra espartano. Aumenta tu daño un 60% y tu resistencia un 40% durante 10 segundos. Los enemigos cercanos son intimidados.' }
                    ],
                    semiUltimate: {
                        id: 'spartan_ares',
                        name: 'Bendición de Ares',
                        type: 'semi-ultimate',
                        cooldown: 22000,
                        currentCooldown: 0,
                        keyBinding: 'a',
                        effectId: 'effect_ares',
                        icon: '??',
                        description: 'Ares, el dios de la guerra, te bendice. Tus ataques causan el doble de daño, eres inmune al control de masas y cada golpe cura el 20% del daño infligido. Duración: 8 segundos.'
                    },
                    ultimateAbility: {
                        id: 'spartan_thermopylae',
                        name: 'Las Termópilas',
                        type: 'ultimate',
                        cooldown: 35000,
                        currentCooldown: 0,
                        keyBinding: 's',
                        effectId: 'effect_thermopylae',
                        icon: '??',
                        description: 'Invocas el espíritu de los 300 espartanos de las Termópilas. 18 hoplitas de Élite aparecen en formación de falange a tu lado, avanzando implacablemente. Eres invulnerable durante 5 segundos. Los hoplitas causan daño devastador y aplican "Miedo Espartano" que reduce la velocidad y daño enemigo un 70%. Colores: Rojo espartano y bronce.'
                    }
                },
                // SSS TIER - EVENTO ESPECIAL: RUINAS ANTIGUAS
                {
                    id: 'ancient-guardian',
                    name: 'Guardián Ancestral',
                    type: 'class',
                    tier: 'SSS',
                    tierColor: '#8B7355', // Color piedra/ruinas
                    ticketsRequired: 1,
                    imagePath: 'assets/guardianancestral.jpg',
                    icon: '???',
                    title: 'Protector de las Ruinas',
                    description: 'Guardián milenario de las ruinas antiguas. Maestro de la tierra y la piedra, canaliza el poder ancestral de civilizaciones olvidadas. La fuerza de los antiguos fluye a través de cada golpe.',
                    abilities: [
                        { id: 'guardian_quake', name: 'Fisura Sísmica Ancestral', type: 'standard', cooldown: 3200, currentCooldown: 0, keyBinding: 'q', effectId: 'effect_quake', icon: '🌋', iconImage: 'assets/fisurasismicaancestral.jpg', description: 'Golpeas el suelo liberando el poder telúrico ancestral. Creas 3 ondas sísmicas expansivas (radio 150/250/350) que se propagan en secuencia. Cada onda causa daño creciente (40/60/80), aplica ralentización acumulativa (30%/50%/70%) y genera 16 fragmentos de roca que orbitan brevemente antes de explotar. Los enemigos atrapados en las 3 ondas quedan aturdidos 1.5s. Efecto visual: Grietas doradas se expanden desde tu posición con partículas de tierra levitando.' },
                        { id: 'guardian_pillar', name: 'Bastión de los Antiguos', type: 'standard', cooldown: 4800, currentCooldown: 0, keyBinding: 'w', effectId: 'effect_pillar', icon: '🏛️', iconImage: 'assets/bastiondelosantiguos.jpg', description: 'Invocas 8 pilares ancestrales de 4 metros que emergen en formación octagonal (radio 180). Los pilares rotan lentamente creando una barrera móvil que bloquea proyectiles y empuja enemigos. Cada pilar tiene runas brillantes que pulsan, curándote 3% HP/s mientras estás dentro. Al expirar (10s), los pilares colapsan en una explosión de escombros que causa 120 de daño y aplica "Aplastamiento" (movimiento reducido 60% por 4s). Puedes reactivar para colapsar anticipadamente.' },
                        { id: 'guardian_armor', name: 'Piel de Titán Pétreo', type: 'standard', cooldown: 7500, currentCooldown: 0, keyBinding: 'e', effectId: 'effect_armor', icon: '🛡️', iconImage: 'assets/pieldetitanpetreo.jpg', description: 'Tu cuerpo se transforma en roca viviente ancestral. Reduces daño recibido 65%, reflejas 40% del daño bloqueado como fragmentos de roca explosivos, y ganas inmunidad a control de masas. Cada golpe recibido genera una capa de "Escudo Geológico" (máx 5 capas, cada capa absorbe 50 de daño). Al terminar (7s) o al acumular 5 capas, explotas en una nova de rocas (radio 200) que causa daño igual al daño bloqueado total. Efecto visual: Armadura de piedra con vetas doradas brillantes y aura marrón pulsante.' },
                        { id: 'guardian_spikes', name: 'Lanzas del Subsuelo', type: 'standard', cooldown: 5500, currentCooldown: 0, keyBinding: 't', effectId: 'effect_spikes', icon: '⛰️', iconImage: 'assets/lanzasdelsubsuelo.jpg', description: 'Canalizas energía telúrica creando 3 líneas de pinchos (separadas 45°) que avanzan 600 unidades. Cada línea tiene 12 pinchos que emergen secuencialmente (intervalo 0.15s), perforando enemigos y lanzándolos 150 unidades hacia arriba. Los enemigos impactados sufren "Empalamiento Pétreo": sangrado de 15 daño/s durante 6s y vulnerabilidad +25%. Los pinchos permanecen 4s como obstáculos que bloquean movimiento enemigo. Efecto visual: Pinchos de roca con puntas brillantes doradas, dejando grietas luminosas en el suelo.' }
                    ],
                    semiUltimate: {
                        id: 'guardian_colossus',
                        name: 'Despertar del Titán Olvidado',
                        type: 'semi-ultimate',
                        cooldown: 23000,
                        currentCooldown: 0,
                        keyBinding: 'a',
                        effectId: 'effect_colossus',
                        icon: '🗿',
                        iconImage: 'assets/despertardeltitanolvidado.jpg',
                        description: 'Te fusionas con un antiguo titán de piedra en una transformación épica de 2s (invulnerable durante canalización). Tu tamaño aumenta 180%, daño +90%, resistencia +75%, y velocidad de movimiento +40%. Cada paso genera un terremoto (radio 120) que causa 45 de daño y ralentiza 50% por 2s. Tus ataques básicos lanzan fragmentos de roca (3 proyectiles por golpe) que explotan al impactar. Generas un aura de gravedad (radio 250) que atrae enemigos lentamente hacia ti. Al terminar (12s), creas una onda de choque final (radio 400) que causa 200 de daño. Efecto visual: Cuerpo de roca maciza con runas ancestrales brillantes, ojos dorados luminosos, aura marrón-dorada pulsante con partículas de tierra orbitando.'
                    },
                    ultimateAbility: {
                        id: 'guardian_cataclysm',
                        name: 'Juicio de las Ruinas Eternas',
                        type: 'ultimate',
                        cooldown: 30000,
                        currentCooldown: 0,
                        keyBinding: 's',
                        effectId: 'effect_cataclysm',
                        icon: '💥',
                        iconImage: 'assets/juiciodelaruinaseternas.jpg',
                        description: 'Invocas el poder absoluto de las civilizaciones perdidas. El cielo se oscurece mientras levantas ambos brazos. El suelo se agrieta en patrones geométricos ancestrales (radio 500) y 15 gólems de piedra colosales (3m altura) emergen en formación de estrella. Eres invulnerable 6s con un aura de energía dorada-marrón radiante y símbolos ancestrales flotando a tu alrededor. Los gólems avanzan en espiral convergente aplastando todo (80 daño/golpe), causando terremotos continuos cada 0.8s (radio 150, 35 daño). Aplica "Maldición de las Ruinas": enemigos sufren -80% velocidad, -70% daño, y reciben +50% daño de todas las fuentes. Cada 2s, pilares de luz dorada caen del cielo (8 pilares aleatorios) causando 100 de daño en área. Al finalizar (6s), todos los gólems explotan simultáneamente en una detonación masiva (radio 600, 250 daño). Colores: Marrón piedra, dorado ancestral brillante, y destellos de energía turquesa antigua.'
                    }
                },
                // SSS TIER - EVENTO ESPECIAL: CIVILIZACIONES ANTIGUAS - EGIPTO
                {
                    id: 'class_anubis',
                    name: 'Guardián de Anubis',
                    type: 'class',
                    tier: 'SSS',
                    tierColor: '#FFD700', // Dorado egipcio
                    ticketsRequired: 1,
                    imagePath: 'assets/anubis',
                    icon: '🐺',
                    title: 'Juez de las Almas',
                    description: 'Guardián legendario del inframundo egipcio. Maestro de la muerte y la resurrección, pesa las almas de los caídos y controla las arenas del desierto eterno. El poder de los dioses antiguos fluye en cada movimiento.',
                    abilities: [
                        { id: 'anubis_judgment', name: 'Juicio de las Almas', type: 'standard', cooldown: 3500, currentCooldown: 0, keyBinding: 'q', effectId: 'effect_judgment', icon: '⚖️', iconImage: 'assets/juiciodelasalmas.jpg', description: 'Invocas la balanza sagrada de Anubis. Lanzas 3 proyectiles de energía dorada que persiguen a los enemigos más cercanos. Al impactar, "pesan" el alma del enemigo: si tiene más del 50% HP, recibe daño normal; si tiene menos del 50% HP, recibe el doble de daño y es marcado con el "Sello de la Muerte" que aumenta el daño recibido un 30% por 5 segundos.' },
                        { id: 'anubis_sandstorm', name: 'Tormenta de Arena Maldita', type: 'standard', cooldown: 6000, currentCooldown: 0, keyBinding: 'w', effectId: 'effect_sandstorm', icon: '🌪️', iconImage: 'assets/tormentadearenamaldita.jpg', description: 'Creas una tormenta de arena dorada en un radio de 300 unidades alrededor tuyo. La tormenta dura 6 segundos, inflige 20 de daño por segundo a todos los enemigos dentro, reduce su precisión un 40% y aplica "Ceguera del Desierto" que invierte sus controles de movimiento. Tú eres inmune y te curas 15 HP por segundo mientras estás en la tormenta.' },
                        { id: 'anubis_jackal', name: 'Forma del Chacal Divino', type: 'standard', cooldown: 8000, currentCooldown: 0, keyBinding: 'e', effectId: 'effect_jackal', icon: '🐺', iconImage: 'assets/formadelchacaldivino.jpg', description: 'Te transformas en un chacal espectral dorado durante 8 segundos. Tu velocidad de movimiento aumenta un 60%, tus ataques aplican sangrado que causa 10 de daño por segundo durante 4 segundos, y dejas un rastro de fuego dorado que daña a los enemigos que lo pisan (15 daño/s). Además, tus ataques tienen 40% de probabilidad de ejecutar instantáneamente enemigos con menos del 15% HP.' },
                        { id: 'anubis_ankh', name: 'Ankh de la Resurrección', type: 'standard', cooldown: 12000, currentCooldown: 0, keyBinding: 't', effectId: 'effect_ankh', icon: '☥', iconImage: 'assets/ankhdelaresurreccion.jpg', description: 'Invocas el poder del Ankh sagrado. Creas un símbolo dorado brillante en el suelo (radio 200) que dura 10 segundos. Mientras estés dentro del área: te curas 25 HP por segundo, tu daño aumenta un 35%, y si tu HP llega a 0, automáticamente resucitas con 40% HP (solo una vez por uso). Los enemigos dentro del área reciben daño de 15 por segundo y tienen su curación reducida un 80%.' }
                    ],
                    semiUltimate: {
                        id: 'anubis_plague',
                        name: 'Plaga de las Diez Maldiciones',
                        type: 'semi-ultimate',
                        cooldown: 25000,
                        currentCooldown: 0,
                        keyBinding: 'a',
                        effectId: 'effect_plague',
                        icon: '💀',
                        iconImage: 'assets/plagadelasdiezmaldiciones.jpg',
                        description: 'Invocas las legendarias plagas de Egipto. Levantas tu cetro mientras el cielo se oscurece con un tono verde enfermizo. Durante 10 segundos, desatas 5 plagas consecutivas cada 2 segundos: 1) Lluvia de sangre (30 daño AoE), 2) Enjambre de langostas (aplica veneno 15 daño/s por 5s), 3) Oscuridad total (enemigos ciegos por 3s), 4) Granizo de fuego (40 daño + quemadura), 5) Muerte de los primogénitos (ejecuta instantáneamente enemigos con menos del 25% HP). Eres invulnerable durante la canalización y emites un aura verde-dorada pulsante. Los enemigos afectados reciben el debuff "Maldición Faraónica" que reduce todos sus stats un 50% por 8 segundos.'
                    },
                    ultimateAbility: {
                        id: 'anubis_underworld',
                        name: 'Portal del Inframundo',
                        type: 'ultimate',
                        cooldown: 35000,
                        currentCooldown: 0,
                        keyBinding: 's',
                        effectId: 'effect_underworld',
                        icon: '🌑',
                        iconImage: 'assets/portaldelinframundo.jpg',
                        description: 'Abres un portal masivo al Duat (inframundo egipcio). Golpeas el suelo con tu cetro mientras el campo de batalla se oscurece completamente. Un portal circular gigante (radio 600) se abre bajo tus pies con jeroglíficos dorados brillantes girando en sus bordes. Del portal emergen 12 guerreros momificados de élite con armaduras doradas que atacan a todos los enemigos durante 7 segundos. Simultáneamente, 8 columnas de fuego espectral verde-dorado erupcionan aleatoriamente cada segundo causando 120 de daño cada una. Tú levitas en el centro con una forma espectral de Anubis (cabeza de chacal gigante) manifestándose detrás de ti, invulnerable durante toda la duración. Los enemigos dentro del portal sufren "Juicio Final": -90% velocidad de movimiento, -80% daño, y sus almas son "pesadas" - si tienen más kills que muertes, reciben 200 de daño adicional; si no, son aturdidos por 4 segundos. Al finalizar, el portal implosiona causando 300 de daño a todos los enemigos restantes y absorbiendo sus almas para curarte 50 HP por enemigo eliminado. Colores: Negro profundo, dorado brillante egipcio, verde espectral, y destellos de energía turquesa antigua.'
                    }
                },
                // S+ TIER (2 tickets required) - 5 ABILITIES
                {
                    id: 'class_gunslinger',
                    name: 'Cyber Gunslinger',
                    type: 'class',
                    tier: 'S+',
                    tierColor: '#ffd700',
                    ticketsRequired: 2,
                    imagePath: 'assets/cybergunslinger.jpg',
                    icon: '??',
                    description: 'High-tech ranged specialist',
                    abilities: [
                        { id: 'gun_rapid', name: 'Rapid Fire', type: 'standard', cooldown: 2200, currentCooldown: 0, keyBinding: 'q', effectId: 'effect_rapid', icon: '🔫', description: 'Dispara una ráfaga rápida de proyectiles de energía hacia los enemigos cercanos.' },
                        { id: 'gun_grenade', name: 'Plasma Grenade', type: 'standard', cooldown: 4800, currentCooldown: 0, keyBinding: 'w', effectId: 'effect_grenade', icon: '💣', description: 'Lanza una granada de plasma que explota causando daño en área.' },
                        { id: 'gun_shield', name: 'Energy Shield', type: 'standard', cooldown: 8000, currentCooldown: 0, keyBinding: 'e', effectId: 'effect_shield', icon: '🛡️', description: 'Activa un escudo de energía que te protege del daño enemigo temporalmente.' },
                        { id: 'gun_dash', name: 'Tactical Dash', type: 'standard', cooldown: 5000, currentCooldown: 0, keyBinding: 't', effectId: 'effect_dash', icon: '🏃', description: 'Realiza un dash táctico rápido para reposicionarte y esquivar ataques.' }
                    ],
                    ultimateAbility: { id: 'gun_ultimate', name: 'Orbital Strike', type: 'ultimate', cooldown: 16000, currentCooldown: 0, keyBinding: 'a', effectId: 'effect_orbital', icon: '🛰️', description: 'Llama un ataque orbital devastador que aniquila a todos los enemigos en el área objetivo.' }
                },
                // S TIER (3 tickets required)
                {
                    id: 'class_elementalist',
                    name: 'Elementalist',
                    type: 'class',
                    tier: 'S',
                    tierColor: '#ff6b00',
                    ticketsRequired: 3,
                    imagePath: 'assets/elementalist.jpg',
                    icon: '??',
                    description: 'Master of the four elements with devastating area control',
                    abilities: [
                        { id: 'elem_storm', name: 'Cadena de Relámpagos', type: 'standard', cooldown: 3500, currentCooldown: 0, keyBinding: 'e', effectId: 'effect_elem_bolt', icon: '⚡', description: 'Lanza un rayo que salta entre enemigos, electrocutando a múltiples objetivos.' },
                        { id: 'elem_ice', name: 'Prisión de Hielo', type: 'standard', cooldown: 5000, currentCooldown: 0, keyBinding: 't', effectId: 'effect_barrier', icon: '🧊', description: 'Congela a los enemigos cercanos en bloques de hielo, inmovilizándolos temporalmente.' }
                    ],
                    ultimateAbility: { id: 'elem_ultimate', name: 'Furia Elemental', type: 'ultimate', cooldown: 22000, currentCooldown: 0, keyBinding: 'f', effectId: 'effect_fury', icon: '🌪️', description: 'Desata la furia de los cuatro elementos en una tormenta devastadora que arrasa con todo.' }
                },
                {
                    id: 'class_mystic',
                    name: 'Mystic Sage',
                    type: 'class',
                    tier: 'S',
                    tierColor: '#ff6b00',
                    ticketsRequired: 3,
                    imagePath: 'assets/mysticsage.jpg',
                    icon: '??',
                    description: 'Wielder of ancient magic',
                    abilities: [
                        { id: 'mystic_orb', name: 'Mystic Orb', type: 'standard', cooldown: 2800, currentCooldown: 0, keyBinding: 'e', effectId: 'effect_orb', icon: '🔮', description: 'Lanza un orbe místico de energía arcana que persigue y daña a los enemigos.' },
                        { id: 'mystic_heal', name: 'Healing Aura', type: 'standard', cooldown: 7000, currentCooldown: 0, keyBinding: 't', effectId: 'effect_heal_aura', icon: '??', description: 'Crea un aura curativa que regenera tu vida gradualmente durante varios segundos.' }
                    ],
                    ultimateAbility: { id: 'mystic_ultimate', name: 'Arcane Storm', type: 'ultimate', cooldown: 19000, currentCooldown: 0, keyBinding: 'f', effectId: 'effect_arcane_storm', icon: '⚡', description: 'Invoca una tormenta arcana masiva que bombardea el área con energía mágica pura.' }
                },
                // A TIER (5 tickets required)
                {
                    id: 'class_berserker',
                    name: 'Wild Berserker',
                    type: 'class',
                    tier: 'A',
                    tierColor: '#9d4edd',
                    ticketsRequired: 5,
                    imagePath: 'assets/wildberserker.jpg',
                    icon: '??',
                    description: 'Guerrero salvaje que se vuelve más fuerte cuanto más daño recibe y más enemigos mata',
                    abilities: [
                        { id: 'berserker_rage', name: 'Ira Imparable', type: 'standard', cooldown: 4000, currentCooldown: 0, keyBinding: 'q', effectId: 'effect_rage', icon: '??', description: 'Entra en un estado de furia que aumenta tu daño y velocidad de ataque temporalmente.' },
                        { id: 'berserker_leap', name: 'Hacha Giratoria', type: 'standard', cooldown: 3500, currentCooldown: 0, keyBinding: 'w', effectId: 'effect_leap', icon: '🌪️', description: 'Gira tu hacha en un círculo devastador, dañando a todos los enemigos cercanos.' },
                        { id: 'berserker_surprise', name: 'Corte Sorpresa', type: 'standard', cooldown: 6000, currentCooldown: 0, keyBinding: 'e', effectId: 'effect_surprise', icon: '?', description: 'Invoca rápidamente dos hachas y las balancea hacia la derecha e izquierda para liberar un corte rápido al enemigo más cercano. Al golpear, recibes un buff de daño de +7% por 3 segundos.' },
                        { id: 'berserker_axes', name: 'Doble Hacha', type: 'standard', cooldown: 7000, currentCooldown: 0, keyBinding: 't', effectId: 'effect_axes', icon: '🪓', description: 'Ataque de área con hachas duales que inflige 40 de daño a todos los enemigos en un radio de 200.' }
                    ],
                    ultimateAbility: { id: 'berserker_ultimate', name: 'Frenesí de Batalla', type: 'ultimate', cooldown: 19000, currentCooldown: 0, keyBinding: 'a', effectId: 'effect_frenzy', icon: '⚔️', description: 'Entras en un frenesí incontrolable que aumenta masivamente tu daño y velocidad mientras te curas con cada golpe.' }
                },
                {
                    id: 'class_ninja',
                    name: 'Shadow Ninja',
                    type: 'class',
                    tier: 'A',
                    tierColor: '#9d4edd',
                    ticketsRequired: 5,
                    imagePath: 'assets/shadowninja.jpg',
                    icon: '??',
                    description: 'Maestro de las sombras que ataca desde la oscuridad con letalidad absoluta',
                    abilities: [
                        { id: 'ninja_shadow_strike', name: 'Golpe de Sombra', type: 'standard', cooldown: 3500, currentCooldown: 0, keyBinding: 'q', effectId: 'effect_shadow_strike', icon: '???', description: 'Dash rápido hacia el enemigo más cercano infligiendo daño crítico. Deja una estela de sombras que daña a enemigos que la atraviesen.' },
                        { id: 'ninja_shuriken', name: 'Marca de Muerte', type: 'standard', cooldown: 5000, currentCooldown: 0, keyBinding: 'w', effectId: 'effect_shuriken', icon: '??', description: 'Marca a los 3 enemigos más cercanos. Los enemigos marcados reciben 30% más daño por 8 segundos.' },
                        { id: 'ninja_smoke', name: 'Paso Fantasma', type: 'standard', cooldown: 6000, currentCooldown: 0, keyBinding: 'e', effectId: 'effect_smoke', icon: '??', description: 'Te teletransportas detrás del enemigo más cercano, infliges un golpe crítico y te vuelves invisible por 2 segundos.' },
                        { id: 'ninja_clone', name: 'Clon de Sombra', type: 'standard', cooldown: 8000, currentCooldown: 0, keyBinding: 't', effectId: 'effect_clone', icon: '??', description: 'Crea 2 clones de sombra que atacan a enemigos cercanos durante 6 segundos. Los clones infligen 50% de tu daño.' }
                    ],
                    ultimateAbility: { id: 'ninja_ultimate', name: 'Asesino de Sombras', type: 'ultimate', cooldown: 17000, currentCooldown: 0, keyBinding: 'a', effectId: 'effect_assassin', icon: '??', description: 'Ejecuta instantáneamente a todos los enemigos con menos del 30% de HP. Inflige daño masivo a los demás y te vuelves invisible por 4 segundos.' }
                },
                {
                    id: 'class_wind_master',
                    name: 'Wind Master',
                    type: 'class',
                    tier: 'S',
                    tierColor: '#ff0080',
                    ticketsRequired: 3,
                    imagePath: 'assets/windmaster.jpg',
                    icon: '???',
                    description: 'Maestro supremo del viento que controla el aire tóxico y radioactivo para devastar enemigos. Sus mobs son extremadamente peligrosos.',
                    abilities: [
                        { id: 'wind_radioactive', name: 'Viento Radioactivo', type: 'standard', cooldown: 3800, currentCooldown: 0, keyBinding: 'q', effectId: 'effect_radioactive', icon: '??', description: 'Lanza viento radioactivo en 4 direcciones que aplica daño continuo por radiación a los enemigos afectados.' },
                        { id: 'wind_bubbles', name: 'Burbujas de Aire Tóxico', type: 'standard', cooldown: 3200, currentCooldown: 0, keyBinding: 'w', effectId: 'effect_toxic', icon: '??', description: 'Crea 5 burbujas tóxicas que explotan al contacto con enemigos, causando daño en írea.' },
                        { id: 'wind_ventoso', name: 'Ventoso', type: 'standard', cooldown: 5000, currentCooldown: 0, keyBinding: 'e', effectId: 'effect_ventoso', icon: '??', description: 'Genera un viento poderoso que empuja a los enemigos lejos de ti y los ralentiza.' },
                        { id: 'wind_ciclon', name: 'Ciclón', type: 'standard', cooldown: 7000, currentCooldown: 0, keyBinding: 't', effectId: 'effect_ciclon', icon: '??', description: 'Crea un ciclón que atrae a los enemigos hacia su centro y los daña continuamente.' }
                    ],
                    ultimateAbility: { id: 'wind_ultimate', name: 'Atracción del Viento Fuerte', type: 'ultimate', cooldown: 18000, currentCooldown: 0, keyBinding: 'a', effectId: 'effect_wind_pull', icon: '???', description: 'Desata un viento devastador que atrae a todos los enemigos hacia ti y los aplasta con presión atmosfírica.' }
                },
                // B TIER (8 tickets required)
                {
                    id: 'class_samurai',
                    name: 'Ronin Samurai',
                    type: 'class',
                    tier: 'B',
                    tierColor: '#00b4d8',
                    ticketsRequired: 8,
                    imagePath: 'assets/roninsamurai.jpg',
                    icon: '??',
                    description: 'Honorable warrior of the blade',
                    abilities: [
                        { id: 'samurai_dash', name: 'Corte Veloz', type: 'standard', cooldown: 3000, currentCooldown: 0, keyBinding: 'q', effectId: 'effect_iaido', icon: '??', description: 'Dash rápido hacia adelante dañando a todos los enemigos en el camino. Perfecto para cerrar distancias o escapar.' },
                        { id: 'samurai_counter', name: 'Contraataque', type: 'standard', cooldown: 5000, currentCooldown: 0, keyBinding: 'w', effectId: 'effect_parry', icon: '???', description: 'Adopta una postura defensiva. El próximo ataque enemigo serí reflejado con el doble de daño.' },
                        { id: 'samurai_ninja_power', name: 'Poder Ninja', type: 'standard', cooldown: 15000, currentCooldown: 0, keyBinding: 'e', effectId: 'effect_ninja_power', icon: '??', description: 'Te vuelves invisible por 10 segundos y dejas una bola de humo mediana. Los enemigos que toquen el humo recibirán confusión por 9 segundos.' },
                        { id: 'samurai_surprise_cut', name: 'Golpe Rápido', type: 'standard', cooldown: 6000, currentCooldown: 0, keyBinding: 't', effectId: 'effect_surprise_cut', icon: '?', description: 'Ataque rápido doble al enemigo más cercano. Dos cortes veloces que infligen 25 de daño cada uno.' }
                    ],
                    ultimateAbility: { id: 'samurai_ultimate', name: 'Danza de las Mil Hojas', type: 'ultimate', cooldown: 18000, currentCooldown: 0, keyBinding: 'a', effectId: 'effect_thousand', icon: '??', description: 'Desata una tormenta de cortes devastadores que golpean a todos los enemigos cercanos múltiples veces.' }
                }
            ],

            // FRUITS = Special powers
            fruits: [
                {
                    id: 'fruit_inferno',
                    name: 'Inferno Fruit',
                    type: 'fruit',
                    imagePath: 'assets/fruits/inferno.png',
                    icon: '??',
                    description: 'Grants mastery over flames',
                    abilities: [
                        { id: 'inferno_blast', name: 'Fire Blast', type: 'standard', cooldown: 2500, currentCooldown: 0, keyBinding: 'a', effectId: 'effect_fire_blast', icon: '??' },
                        { id: 'inferno_wall', name: 'Flame Wall', type: 'standard', cooldown: 4000, currentCooldown: 0, keyBinding: 's', effectId: 'effect_flame_wall', icon: '??' }
                    ],
                    ultimateAbility: { id: 'inferno_ultimate', name: 'Inferno Nova', type: 'ultimate', cooldown: 15000, currentCooldown: 0, keyBinding: 'd', effectId: 'effect_inferno_nova', icon: '??' }
                },
                {
                    id: 'fruit_glacier',
                    name: 'Glacier Fruit',
                    type: 'fruit',
                    imagePath: 'assets/fruits/glacier.png',
                    icon: '??',
                    description: 'Controls ice and frost',
                    abilities: [
                        { id: 'glacier_shard', name: 'Ice Shard', type: 'standard', cooldown: 2500, currentCooldown: 0, keyBinding: 'a', effectId: 'effect_ice_shard', icon: '??' },
                        { id: 'glacier_freeze', name: 'Deep Freeze', type: 'standard', cooldown: 5000, currentCooldown: 0, keyBinding: 's', effectId: 'effect_freeze', icon: '??' }
                    ],
                    ultimateAbility: { id: 'glacier_ultimate', name: 'Eternal Winter', type: 'ultimate', cooldown: 18000, currentCooldown: 0, keyBinding: 'd', effectId: 'effect_winter', icon: '???' }
                },
                {
                    id: 'fruit_storm',
                    name: 'Storm Fruit',
                    type: 'fruit',
                    imagePath: 'assets/fruits/storm.png',
                    icon: '?',
                    description: 'Commands thunder and lightning',
                    abilities: [
                        { id: 'storm_bolt', name: 'Lightning Bolt', type: 'standard', cooldown: 2000, currentCooldown: 0, keyBinding: 'a', effectId: 'effect_lightning', icon: '?' },
                        { id: 'storm_field', name: 'Thunder Field', type: 'standard', cooldown: 4500, currentCooldown: 0, keyBinding: 's', effectId: 'effect_thunder_field', icon: '??' }
                    ],
                    ultimateAbility: { id: 'storm_ultimate', name: 'Tempest Rage', type: 'ultimate', cooldown: 16000, currentCooldown: 0, keyBinding: 'd', effectId: 'effect_tempest', icon: '???' }
                },
                {
                    id: 'fruit_void',
                    name: 'Void Fruit',
                    type: 'fruit',
                    imagePath: 'assets/fruits/void.png',
                    icon: '??',
                    description: 'Manipulates darkness and gravity',
                    abilities: [
                        { id: 'void_hole', name: 'Void Hole', type: 'standard', cooldown: 3000, currentCooldown: 0, keyBinding: 'a', effectId: 'effect_void_hole', icon: '?' },
                        { id: 'void_pull', name: 'Gravity Pull', type: 'standard', cooldown: 4000, currentCooldown: 0, keyBinding: 's', effectId: 'effect_gravity', icon: '??' }
                    ],
                    ultimateAbility: { id: 'void_ultimate', name: 'Singularity', type: 'ultimate', cooldown: 17000, currentCooldown: 0, keyBinding: 'd', effectId: 'effect_singularity', icon: '??' }
                },
                {
                    id: 'fruit_radiance',
                    name: 'Radiance Fruit',
                    type: 'fruit',
                    imagePath: 'assets/fruits/radiance.png',
                    icon: '??',
                    description: 'Harnesses pure light energy',
                    abilities: [
                        { id: 'radiance_beam', name: 'Light Beam', type: 'standard', cooldown: 2000, currentCooldown: 0, keyBinding: 'a', effectId: 'effect_light_beam', icon: '?' },
                        { id: 'radiance_speed', name: 'Light Speed', type: 'standard', cooldown: 6000, currentCooldown: 0, keyBinding: 's', effectId: 'effect_light_speed', icon: '??' }
                    ],
                    ultimateAbility: { id: 'radiance_ultimate', name: 'Solar Flare', type: 'ultimate', cooldown: 14000, currentCooldown: 0, keyBinding: 'd', effectId: 'effect_solar', icon: '??' }
                },
                {
                    id: 'fruit_nature',
                    name: 'Nature Fruit',
                    type: 'fruit',
                    imagePath: 'assets/fruits/nature.png',
                    icon: '??',
                    description: 'Controls plants and life force',
                    abilities: [
                        { id: 'nature_vine', name: 'Vine Whip', type: 'standard', cooldown: 2800, currentCooldown: 0, keyBinding: 'a', effectId: 'effect_vine', icon: '??' },
                        { id: 'nature_growth', name: 'Rapid Growth', type: 'standard', cooldown: 5500, currentCooldown: 0, keyBinding: 's', effectId: 'effect_growth', icon: '??' }
                    ],
                    ultimateAbility: { id: 'nature_ultimate', name: 'Forest Awakening', type: 'ultimate', cooldown: 19000, currentCooldown: 0, keyBinding: 'd', effectId: 'effect_forest', icon: '??' }
                }
            ],

            // MASTER CLASSES - Unlocked through mastery missions
            masterClasses: [
                {
                    id: 'master_storm_of_tornados',
                    name: 'Tornado Overlord',
                    type: 'master_class',
                    tier: 'MASTER',
                    tierColor: '#ff00ff',
                    baseClassId: 'class_wind_master',
                    imagePath: 'assets/tornadooverlord.jpg',
                    icon: '????',
                    description: 'Versión maestra del Wind Master. Dominio absoluto sobre tormentas devastadoras y vientos apocalípticos.',
                    abilities: [
                        { id: 'master_singularity', name: 'Singularidad Eólica', type: 'standard', cooldown: 8000, currentCooldown: 0, keyBinding: 'q', effectId: 'effect_singularity', icon: '?', description: 'Crea una esfera de vacío estática que atrae a todos los enemigos cercanos hacia su centro y los aturde por 3 segundos.' },
                        { id: 'master_pressure', name: 'Presión Atmosférica', type: 'standard', cooldown: 7000, currentCooldown: 0, keyBinding: 'w', effectId: 'effect_pressure', icon: '??', description: 'Aumenta la presión del aire hacia abajo, inmovilizando enemigos por 2s y rompiendo su armadura (Defensa 0, +20% daño recibido) por 4s.' },
                        { id: 'master_tornado_barrage', name: 'Ráfaga de Tornados', type: 'standard', cooldown: 3500, currentCooldown: 0, keyBinding: 'e', effectId: 'effect_tornado_barrage', icon: '???', description: 'Lanza 5 tornados que atraviesan enemigos, causando daño y confusión por 4 segundos.' },
                        { id: 'master_storm_shield', name: 'Escudo de Tormenta', type: 'standard', cooldown: 6000, currentCooldown: 0, keyBinding: 't', effectId: 'effect_storm_shield', icon: '???', description: 'Crea un escudo que te hace invulnerable por 4s y reduce el daño recibido en 30% por 6s adicionales.' }
                    ],
                    semiUltimate: { id: 'master_enemy_tornado', name: 'Tornado de Enemigo', type: 'semi_ultimate', cooldown: 15000, currentCooldown: 0, keyBinding: 's', effectId: 'effect_enemy_tornado', icon: '??', description: 'Toma al enemigo más cercano y lo hace girar creando un tornado masivo. Empuja y daña gravemente a otros enemigos, luego lanza a la víctima y genera 4 tormentas estáticas. Aplica Viento Fuerte por 7s.' },
                    ultimateAbility: { id: 'master_apocalyptic_storm', name: 'Tormenta Apocalíptica', type: 'ultimate', cooldown: 25000, currentCooldown: 0, keyBinding: 'd', effectId: 'effect_apocalyptic', icon: '???', description: 'Desata una tormenta apocalíptica que atrae enemigos, inflige daño masivo, aplica confusión y radioactividad, y lanza 20 tornados devastadores. +50% daño por 10s.' },
                    masteryMission: {
                        title: 'Dominio de la Tormenta',
                        description: 'Demuestra tu maestría sobre el viento completando estos desafíos extremos',
                        requirements: [
                            { id: 'kill_tempest_lord', type: 'kill_boss', target: 'tempest_lord', amount: 5, current: 0, description: 'Derrota al Tempest Lord 5 veces' },
                            { id: 'kill_with_wind', type: 'kill_count', classId: 'class_wind_master', amount: 100, current: 0, description: 'Elimina 100 enemigos usando Wind Master' },
                            { id: 'survive_raid', type: 'survive_waves', classId: 'class_wind_master', waves: 15, current: 0, description: 'Sobrevive 15 oleadas en una raid usando Wind Master' },
                            { id: 'deal_damage', type: 'damage_dealt', classId: 'class_wind_master', amount: 50000, current: 0, description: 'Inflige 50,000 de daño total con Wind Master' }
                        ]
                    }
                },
                {
                    id: 'master_cybernetic_warlord',
                    name: 'Cybernetic Warlord',
                    type: 'master_class',
                    tier: 'MASTER',
                    tierColor: '#00ffff',
                    baseClassId: 'class_gunslinger',
                    imagePath: 'assets/cyberneticwarlord.jpg',
                    icon: '???',
                    description: 'Versión maestra del Cyber Gunslinger. Tecnología de guerra avanzada con sistema de calor y armamento devastador.',
                    passiveSystem: {
                        name: 'Sistema de Calor',
                        description: 'Cada disparo aumenta el calor. >50%: Doble daño. 100%: Sobrecarga (explosión AoE + Silencio 2s)'
                    },
                    abilities: [
                        { id: 'cyber_plasma_cannon', name: 'Cañón de Plasma', type: 'standard', cooldown: 5000, currentCooldown: 0, keyBinding: 'q', effectId: 'effect_plasma_cannon', icon: '??', description: 'Dispara un rayo láser grueso continuo que atraviesa todos los enemigos en línea recta. Genera +15% Calor.' },
                        { id: 'cyber_singularity_grenade', name: 'Granada de Singularidad', type: 'standard', cooldown: 8000, currentCooldown: 0, keyBinding: 'w', effectId: 'effect_singularity_grenade', icon: '??', description: 'Lanza un dispositivo que crea un campo de gravedad, atrayendo enemigos por 2s antes de detonar con daño masivo.' },
                        { id: 'cyber_drone_swarm', name: 'Enjambre de Drones', type: 'standard', cooldown: 12000, currentCooldown: 0, keyBinding: 'e', effectId: 'effect_drone_swarm', icon: '??', description: 'Despliega 4 drones que orbitan alrededor del jugador por 8s, disparando láseres automíticamente.' },
                        { id: 'cyber_photon_barrier', name: 'Barrera de Fotones', type: 'standard', cooldown: 15000, currentCooldown: 0, keyBinding: 't', effectId: 'effect_photon_barrier', icon: '???', description: 'Despliega un muro de energía estático que dura 5s. Bloquea enemigos y los quema al contacto. Puedes disparar a travís.' }
                    ],
                    semiUltimate: { id: 'cyber_mech_suit', name: 'Protocolo: MECH-SUIT', type: 'semi_ultimate', cooldown: 20000, currentCooldown: 0, keyBinding: 'a', effectId: 'effect_mech_suit', icon: '??', description: 'Invoca armadura pesada que cae del cielo. Durante 10s: -20% velocidad, +80% defensa, ataques se convierten en misiles teledirigidos.' },
                    ultimateAbility: { id: 'cyber_orbital_ragnarok', name: 'Satélite Orbital "Ragnarok"', type: 'ultimate', cooldown: 30000, currentCooldown: 0, keyBinding: 'f', effectId: 'effect_orbital_ragnarok', icon: '???', description: 'Marca una zona. Tras 3s, un rayo láser masivo vaporiza todo (9999 daño puro) y deja suelo quemado por 5s.' },
                    masteryMission: {
                        title: 'Supremacía Cibernética',
                        description: 'Demuestra tu dominio sobre la tecnología de guerra avanzada',
                        requirements: [
                            { id: 'kill_mech_titan', type: 'kill_boss', target: 'mech_titan', amount: 3, current: 0, description: 'Derrota al Mech Titan 3 veces' },
                            { id: 'kill_combat_drones', type: 'kill_specific', target: 'combat_drone', amount: 50, current: 0, description: 'Elimina 50 Combat Drones' },
                            { id: 'kill_with_gunslinger', type: 'kill_count', classId: 'class_gunslinger', amount: 100, current: 0, description: 'Elimina 100 enemigos usando Cyber Gunslinger' },
                            { id: 'use_orbital_strike', type: 'ability_usage', abilityId: 'gun_ultimate', amount: 15, current: 0, description: 'Usa Orbital Strike 15 veces' }
                        ]
                    }
                },
                {
                    id: 'master_abyssal_shadowlord',
                    name: 'Abyssal Shadowlord',
                    type: 'master_class',
                    tier: 'MASTER',
                    tierColor: '#2f2f2f',
                    baseClassId: 'class_ninja',
                    imagePath: 'assets/abyssalshadowlord.jpg',
                    icon: '???',
                    description: 'Versión maestra del Shadow Ninja. Dominio absoluto sobre el Reino de las Sombras con clones legionarios y oscuridad que ciega enemigos.',
                    passiveSystem: {
                        name: 'Abismo Letal',
                        description: 'Cada kill genera esencia sombra (+10% crítico stackeable hasta 5 stacks). Resetea al morir.'
                    },
                    abilities: [
                        { id: 'abyssal_blade_storm', name: 'Tormenta de Cuchillas Sombrías', type: 'standard', cooldown: 3000, currentCooldown: 0, keyBinding: 'q', effectId: 'effect_blade_storm', icon: '???', description: 'Dash múltiple con 5 slashes giratorios. Deja estelas que causan DoT y ralentizan 50%.' },
                        { id: 'abyssal_death_chain', name: 'Cadena de Muerte', type: 'standard', cooldown: 4000, currentCooldown: 0, keyBinding: 'w', effectId: 'effect_death_chain', icon: '??', description: 'Marca 6 enemigos en cadena (+40% daño recibido). El daño salta entre targets cercanos.' },
                        { id: 'abyssal_void_leap', name: 'Salto al Vacío Fantasma', type: 'standard', cooldown: 5000, currentCooldown: 0, keyBinding: 'e', effectId: 'effect_void_leap', icon: '??', description: 'TP detrás del boss/enemigo elite + crítico x2 + AoE oscuridad que ciega 3s y reduce visión enemiga.' },
                        { id: 'abyssal_shadow_legion', name: 'Legión de Sombras', type: 'standard', cooldown: 8000, currentCooldown: 0, keyBinding: 't', effectId: 'effect_shadow_legion', icon: '??', description: 'Invoca 5 clones (75% de tu daño, duran 8s). Explotan al morir causando 60 de daño.' }
                    ],
                    semiUltimate: { id: 'abyssal_shadow_emperor', name: 'Emperador Sombra', type: 'semi_ultimate', cooldown: 15000, currentCooldown: 0, keyBinding: 'a', effectId: 'effect_shadow_emperor', icon: '??', description: 'Invoca un mini-boss sombra (200 HP) que ataca independientemente y copia tus ataques bísicos.' },
                    ultimateAbility: { id: 'abyssal_eternal_night', name: 'Noche Eterna', type: 'ultimate', cooldown: 25000, currentCooldown: 0, keyBinding: 'r', effectId: 'effect_eternal_night', icon: '??', description: 'Oscurece toda la pantalla 6s. Ejecuta enemigos <25% HP en cadena (salta 10x) + DoT masivo. Tí invisible + 50% velocidad permanente durante.' },
                    masteryMission: {
                        title: 'Señor del Abismo',
                        description: 'Demuestra tu dominio sobre las sombras completando estos desafíos letales',
                        requirements: [
                            { id: 'kill_shadow_emperor', type: 'kill_boss', target: 'shadow_emperor', amount: 3, current: 0, description: 'Derrota al Shadow Emperor 3 veces' },
                            { id: 'kill_with_ninja', type: 'kill_count', classId: 'class_ninja', amount: 150, current: 0, description: 'Elimina 150 enemigos usando Shadow Ninja' },
                            { id: 'survive_ninja_raid', type: 'survive_waves', classId: 'class_ninja', waves: 20, current: 0, description: 'Sobrevive 20 oleadas en una raid usando Shadow Ninja' },
                            { id: 'use_silent_execution', type: 'ability_usage', abilityId: 'ninja_ultimate', amount: 12, current: 0, description: 'Usa Asesino de Sombras 12 veces' }
                        ]
                    }
                }
            ]
        };

        // ===== CLASS PROGRESSION SYSTEM =====
        const ClassProgressionSystem = {
            classLevels: {}, // { classId: { level: 1, exp: 0, expToNext: 100 } }
            maxClassLevel: 10,

            // Define unique upgrades for each class
            // Each class has its own progression tree based on its abilities and playstyle
            classUpgrades: {
                // DRAGONHUNTER - Fire and Nature themed
                'class_dragonhunter': {
                    icon: '??',
                    name: 'Dragonhunter',
                    upgrades: {
                        2: [{ type: 'damage', bonus: 5, icon: '??', iconImage: 'assets/tripleflechaflamigera.jpg', description: 'Triple Flecha Flamigera', detail: '+5% Dano de fuego' }],
                        3: [{ type: 'burn_damage', bonus: 10, icon: '??', iconImage: 'assets/tripleflechaflamigera.jpg', description: 'Quemadura Intensa', detail: '+10% Dano de quemadura' }],
                        4: [{ type: 'nature_heal', bonus: 15, icon: '??', description: 'Naturaleza en Ascenso', detail: '+15% Curacion y defensa' }],
                        5: [{ type: 'arrow_count', bonus: 1, icon: '??', description: 'Flecha Triple Uso', detail: 'Dispara 1 flecha adicional' }],
                        6: [{ type: 'cooldown', bonus: 10, icon: '??', description: 'Aliento Rapido', detail: '-10% Cooldown' }],
                        7: [{ type: 'crit', bonus: 15, icon: '??', description: 'Punteria Mortal', detail: '+15% Critico' }],
                        8: [{ type: 'range', bonus: 20, icon: '??', description: 'Alcance Draconico', detail: '+20% Rango' }],
                        9: [{ type: 'madness_duration', bonus: 30, icon: '??', description: 'Locura Draconica', detail: '+30% Duracion' }],
                        10: [{ type: 'ultimate', bonus: 50, icon: '??', description: 'EXPLOSION DRACONICA', detail: 'Ultimate +50% dano' }]
                    }
                },

                // SHADOW NINJA - Stealth and assassination
                'class_ninja': {
                    icon: '??',
                    name: 'Shadow Ninja',
                    upgrades: {
                        2: [{ type: 'stealth_duration', bonus: 20, icon: '??', iconImage: 'assets/pasofantasma.jpg', description: 'Paso Fantasma', detail: '+20% Duración de invisibilidad' }],
                        3: [{ type: 'backstab', bonus: 25, icon: '???', iconImage: 'assets/golpedesombra.jpg', description: 'Golpe de Sombra', detail: '+25% Daño desde invisibilidad' }],
                        4: [{ type: 'speed', bonus: 15, icon: '?', description: 'Paso Silencioso', detail: '+15% Velocidad de movimiento' }],
                        5: [{ type: 'shuriken_count', bonus: 2, icon: '??', iconImage: 'assets/marcademuerte.jpg', description: 'Marca de Muerte', detail: '+2 Enemigos marcados' }],
                        6: [{ type: 'clone_damage', bonus: 30, icon: '??', iconImage: 'assets/clondesombra.jpg', description: 'Clon de Sombra', detail: '+30% Daño de clones' }],
                        7: [{ type: 'cooldown', bonus: 15, icon: '??', description: 'Asesino Eficiente', detail: '-15% Cooldown' }],
                        8: [{ type: 'crit', bonus: 20, icon: '??', description: 'Golpe Crítico Ninja', detail: '+20% Crítico' }],
                        9: [{ type: 'smoke_radius', bonus: 40, icon: '??', description: 'Velo Expandido', detail: '+40% Radio de humo' }],
                        10: [{ type: 'ultimate', bonus: 100, icon: '??', iconImage: 'assets/asesinodesombras.jpg', description: 'Asesino de Sombras', detail: 'Ultimate +100% daño' }]
                    }
                },

                // WIND MASTER - Wind and toxic abilities
                'class_wind_master': {
                    icon: '???',
                    name: 'Wind Master',
                    upgrades: {
                        2: [{ type: 'toxic_damage', bonus: 10, icon: '💚', iconImage: 'assets/burbujasdeairetoxico.jpg', description: 'Burbujas de Aire Toxico', detail: '+10% Dano de veneno' }],
                        3: [{ type: 'bubble_duration', bonus: 25, icon: '💚', iconImage: 'assets/burbujasdeairetoxico.jpg', description: 'Burbujas de Aire Toxico', detail: '+25% Duracion de burbujas' }],
                        4: [{ type: 'wind_speed', bonus: 15, icon: '💨', iconImage: 'assets/ventoso.jpg', description: 'Ventoso', detail: '+15% Velocidad de viento' }],
                        5: [{ type: 'ciclon_size', bonus: 30, icon: '🌀', iconImage: 'assets/ciclon.jpg', description: 'Ciclon', detail: '+30% Tamano de Ciclon' }],
                        6: [{ type: 'radioactive_spread', bonus: 20, icon: '☢️', iconImage: 'assets/vientoradioactivo.jpg', description: 'Viento Radioactivo', detail: '+20% Radio de propagacion' }],
                        7: [{ type: 'cooldown', bonus: 12, icon: '⏱️', description: 'Vientos Rapidos', detail: '-12% Cooldown' }],
                        8: [{ type: 'dot_damage', bonus: 35, icon: '🔥', description: 'Veneno Letal', detail: '+35% Dano con el tiempo' }],
                        9: [{ type: 'attraction_power', bonus: 40, icon: '🌀', iconImage: 'assets/atracciondelvientofuerte.jpg', description: 'Atraccion del Viento Fuerte', detail: '+40% Poder de atraccion' }],
                        10: [{ type: 'ultimate', bonus: 50, icon: '🌪️', iconImage: 'assets/atracciondelvientofuerte.jpg', description: 'Atraccion del Viento Fuerte', detail: 'Ultimate +50% dano' }]
                    }
                },

                // WILD BERSERKER - Rage and brute force
                'class_berserker': {
                    icon: '⚔️',
                    name: 'Wild Berserker',
                    upgrades: {
                        2: [{ type: 'rage_damage', bonus: 15, icon: '🔥', iconImage: 'assets/iraimparable.jpg', description: 'Ira Imparable', detail: '+15% Dano durante furia' }],
                        3: [{ type: 'lifesteal', bonus: 5, icon: '❤️', iconImage: 'assets/frenesidebatalla.jpg', description: 'Frenesi de Batalla', detail: '+5% Robo de vida' }],
                        4: [{ type: 'leap_damage', bonus: 25, icon: '🌪️', iconImage: 'assets/hachagiratoria.jpg', description: 'Hacha Giratoria', detail: '+25% Dano de giro' }],
                        5: [{ type: 'axes_count', bonus: 1, icon: '🪓', iconImage: 'assets/doblehacha.jpg', description: 'Doble Hacha', detail: 'Lanza 1 hacha adicional' }],
                        6: [{ type: 'rage_duration', bonus: 30, icon: '⏱️', description: 'Furia Prolongada', detail: '+30% Duracion de buffs' }],
                        7: [{ type: 'crit', bonus: 18, icon: '💥', description: 'Golpe Brutal', detail: '+18% Critico' }],
                        8: [{ type: 'bloodlust_heal', bonus: 40, icon: '⚡', iconImage: 'assets/cortesorpresa.jpg', description: 'Corte Sorpresa', detail: '+40% Buff de dano' }],
                        9: [{ type: 'damage', bonus: 35, icon: '⚔️', description: 'Fuerza Titanica', detail: '+35% Dano total' }],
                        10: [{ type: 'ultimate', bonus: 50, icon: '💀', iconImage: 'assets/frenesidebatalla.jpg', description: 'Frenesí de Batalla', detail: 'Ultimate +50% daño' }]
                    }
                },

                // GUARDIAN ANCESTRAL - Tank and earth abilities
                'ancient-guardian': {
                    icon: '???',
                    name: 'Guardián Ancestral',
                    upgrades: {
                        2: [{ type: 'quake_waves', bonus: 1, icon: '🌋', iconImage: 'assets/fisurasismicaancestral.jpg', description: 'Fisura Sísmica Ancestral', detail: '+1 Onda sísmica' }],
                        3: [{ type: 'pillar_duration', bonus: 30, icon: '🏛️', iconImage: 'assets/bastiondelosantiguos.jpg', description: 'Bastión de los Antiguos', detail: '+30% Duración pilares' }],
                        4: [{ type: 'armor_reduction', bonus: 10, icon: '🛡️', iconImage: 'assets/pieldetitanpetreo.jpg', description: 'Piel de Titán Pétreo', detail: '+10% Reducción daño' }],
                        5: [{ type: 'spike_count', bonus: 3, icon: '⛰️', iconImage: 'assets/lanzasdelsubsuelo.jpg', description: 'Lanzas del Subsuelo', detail: '+3 Pinchos' }],
                        6: [{ type: 'colossus_size', bonus: 25, icon: '🗿', iconImage: 'assets/despertardeltitanolvidado.jpg', description: 'Despertar del Titán Olvidado', detail: '+25% Tamaño' }],
                        7: [{ type: 'cooldown', bonus: 15, icon: '⚡', description: 'Tierra Rápida', detail: '-15% Cooldown' }],
                        8: [{ type: 'stun_duration', bonus: 40, icon: '💫', description: 'Aturdimiento Pétreo', detail: '+40% Duración stun' }],
                        9: [{ type: 'range', bonus: 30, icon: '📏', description: 'Alcance Telúrico', detail: '+30% Rango' }],
                        10: [{ type: 'ultimate', bonus: 75, icon: '💥', iconImage: 'assets/juiciodelaruinaseternas.jpg', description: 'Juicio de las Ruinas Eternas', detail: 'Ultimate +75% daño' }]
                    }
                },

                // ELEMENTALIST - Master of elements
                'class_elementalist': {
                    icon: '??',
                    name: 'Elementalist',
                    upgrades: {
                        2: [{ type: 'chain_damage', bonus: 10, icon: '?', iconImage: 'assets/cadenaderelampagos.jpg', description: 'Cadena de Relámpagos', detail: '+10% Daño eléctrico' }],
                        3: [{ type: 'chain_targets', bonus: 1, icon: '?', iconImage: 'assets/cadenaderelampagos.jpg', description: 'Cadena de Relámpagos', detail: '+1 Objetivo en cadena' }],
                        4: [{ type: 'ice_duration', bonus: 25, icon: '??', iconImage: 'assets/prisiondehielo.jpg', description: 'Prisión de Hielo', detail: '+25% Duración congelamiento' }],
                        5: [{ type: 'freeze_radius', bonus: 20, icon: '??', iconImage: 'assets/prisiondehielo.jpg', description: 'Prisión de Hielo', detail: '+20% Radio de hielo' }],
                        6: [{ type: 'cooldown', bonus: 12, icon: '??', description: 'Maestría Elemental', detail: '-12% Cooldown' }],
                        7: [{ type: 'crit', bonus: 15, icon: '??', description: 'Golpe Elemental', detail: '+15% Crítico' }],
                        8: [{ type: 'damage', bonus: 25, icon: '??', description: 'Poder Elemental', detail: '+25% Daño' }],
                        9: [{ type: 'storm_duration', bonus: 35, icon: '???', description: 'Tormenta Prolongada', detail: '+35% Duración efectos' }],
                        10: [{ type: 'ultimate', bonus: 60, icon: '???', iconImage: 'assets/furiaelemental.jpg', description: 'Furia Elemental', detail: 'Ultimate +60% daño' }]
                    }
                },

                // RONIN SAMURAI - Honorable warrior
                'class_samurai': {
                    icon: '??',
                    name: 'Ronin Samurai',
                    upgrades: {
                        2: [{ type: 'dash_damage', bonus: 15, icon: '??', iconImage: 'assets/corteveloz.jpg', description: 'Corte Veloz', detail: '+15% Daño de dash' }],
                        3: [{ type: 'counter_multiplier', bonus: 20, icon: '???', iconImage: 'assets/contraataque.jpg', description: 'Contraataque', detail: '+20% Daño reflejado' }],
                        4: [{ type: 'invisibility_duration', bonus: 30, icon: '??', iconImage: 'assets/poderninja.jpg', description: 'Poder Ninja', detail: '+30% Duración invisibilidad' }],
                        5: [{ type: 'surprise_hits', bonus: 1, icon: '?', iconImage: 'assets/golperapido.jpg', description: 'Golpe Rápido', detail: '+1 Corte adicional' }],
                        6: [{ type: 'cooldown', bonus: 15, icon: '??', description: 'Samurai Veloz', detail: '-15% Cooldown' }],
                        7: [{ type: 'crit', bonus: 20, icon: '??', description: 'Corte Crítico', detail: '+20% Crítico' }],
                        8: [{ type: 'speed', bonus: 18, icon: '?', description: 'Paso del Viento', detail: '+18% Velocidad' }],
                        9: [{ type: 'confusion_duration', bonus: 40, icon: '??', description: 'Humo Persistente', detail: '+40% Duración confusión' }],
                        10: [{ type: 'ultimate', bonus: 80, icon: '??', iconImage: 'assets/danzadelasmilhojas.jpg', description: 'Danza de las Mil Hojas', detail: 'Ultimate +80% daño' }]
                    }
                },

                // ROMAN LEGIONARY - Roman warrior
                'class_roman_legionary': {
                    icon: '???',
                    name: 'Roman Legionary',
                    upgrades: {
                        2: [{ type: 'gladius_damage', bonus: 12, icon: '??', iconImage: 'assets/gladiusfulminante.jpg', description: 'Gladius Fulminante', detail: '+12% Daño de espada' }],
                        3: [{ type: 'testudo_defense', bonus: 20, icon: '???', iconImage: 'assets/formaciontestudo.jpg', description: 'Formación Testudo', detail: '+20% Defensa' }],
                        4: [{ type: 'pilum_pierce', bonus: 15, icon: '???', iconImage: 'assets/lanzamientopilum.jpg', description: 'Lanzamiento Pilum', detail: '+15% Penetración' }],
                        5: [{ type: 'centurion_buff', bonus: 25, icon: '??', iconImage: 'assets/gritodelcenturion.jpg', description: 'Grito del Centurión', detail: '+25% Buff de equipo' }],
                        6: [{ type: 'cooldown', bonus: 12, icon: '??', description: 'Disciplina Romana', detail: '-12% Cooldown' }],
                        7: [{ type: 'armor_reduction', bonus: 15, icon: '???', description: 'Rompe Armaduras', detail: '+15% Reducción armadura enemiga' }],
                        8: [{ type: 'bleed_damage', bonus: 30, icon: '??', description: 'Sangrado Profundo', detail: '+30% Daño sangrado' }],
                        9: [{ type: 'eagle_power', bonus: 35, icon: '??', iconImage: 'assets/aguilaimperial.jpg', description: 'Águila Imperial', detail: '+35% Poder de Águila' }],
                        10: [{ type: 'ultimate', bonus: 70, icon: '??', iconImage: 'assets/legioaeterna.jpg', description: 'Legio Aeterna', detail: 'Ultimate +70% daño' }]
                    }
                },

                // SPARTAN HOPLITE - Spartan warrior
                'class_spartan_hoplite': {
                    icon: '🛡️',
                    name: 'Spartan Hoplite',
                    upgrades: {
                        2: [{ type: 'dory_damage', bonus: 15, icon: '🗡️', iconImage: 'assets/dorupenetrante.jpg', description: 'Doru Penetrante', detail: '+15% Daño de lanza' }],
                        3: [{ type: 'phalanx_defense', bonus: 25, icon: '🛡️', iconImage: 'assets/falangeespartana.jpg', description: 'Falange Espartana', detail: '+25% Defensa' }],
                        4: [{ type: 'charge_damage', bonus: 30, icon: '⚡', iconImage: 'assets/cargaespartana.jpg', description: 'Carga Espartana', detail: '+30% Daño de carga' }],
                        5: [{ type: 'aroo_buff', bonus: 20, icon: '📯', iconImage: 'assets/gritodeguerraaroo.jpg', description: 'Grito de Guerra: AROO!', detail: '+20% Buff de combate' }],
                        6: [{ type: 'cooldown', bonus: 15, icon: '⏱️', description: 'Guerrero Veloz', detail: '-15% Cooldown' }],
                        7: [{ type: 'ares_blessing', bonus: 35, icon: '⚔️', iconImage: 'assets/bendiciondeares.jpg', description: 'Bendición de Ares', detail: '+35% Daño bendecido' }],
                        8: [{ type: 'shield_bash', bonus: 25, icon: '🛡️', description: 'Golpe de Escudo', detail: '+25% Daño de escudo' }],
                        9: [{ type: 'formation_bonus', bonus: 40, icon: '🛡️', description: 'Formación Perfecta', detail: '+40% Bonus formación' }],
                        10: [{ type: 'ultimate', bonus: 100, icon: '⚔️', iconImage: 'assets/lastermopilas.jpg', description: 'Las Termópilas', detail: 'Invulnerabilidad mejorada' }]
                    }
                },

                // CYBER GUNSLINGER - Tech warrior
                'class_gunslinger': {
                    icon: '🔫',
                    name: 'Cyber Gunslinger',
                    upgrades: {
                        2: [{ type: 'bullet_damage', bonus: 10, icon: '💥', iconImage: 'assets/rapidfire.jpg', description: 'Rapid Fire', detail: '+10% Daño de balas' }],
                        3: [{ type: 'fire_rate', bonus: 15, icon: '💥', iconImage: 'assets/rapidfire.jpg', description: 'Rapid Fire', detail: '+15% Velocidad de disparo' }],
                        4: [{ type: 'reload_speed', bonus: 20, icon: '🛡️', iconImage: 'assets/energyshield.jpg', description: 'Energy Shield', detail: '+20% Velocidad recarga' }],
                        5: [{ type: 'crit', bonus: 18, icon: '💥', description: 'Tiro Certero', detail: '+18% Crítico' }],
                        6: [{ type: 'cooldown', bonus: 12, icon: '⏱️', description: 'Pistolero Veloz', detail: '-12% Cooldown' }],
                        7: [{ type: 'penetration', bonus: 25, icon: '💣', iconImage: 'assets/plasmagrenade.jpg', description: 'Plasma Grenade', detail: '+25% Penetración' }],
                        8: [{ type: 'multishot', bonus: 2, icon: '⚡', iconImage: 'assets/tacticaldash.jpg', description: 'Tactical Dash', detail: '+2 Balas por disparo' }],
                        9: [{ type: 'range', bonus: 30, icon: '🎯', description: 'Alcance Extendido', detail: '+30% Rango' }],
                        10: [{ type: 'ultimate', bonus: 100, icon: '🛸', iconImage: 'assets/orbitalstrike.jpg', description: 'Orbital Strike', detail: 'Ultimate +100% daño' }]
                    }
                },

                // ===== MASTER CLASSES =====

                // TORNADO OVERLORD - Master of Wind Master
                'master_storm_of_tornados': {
                    icon: '????',
                    name: 'Tornado Overlord',
                    upgrades: {
                        2: [{ type: 'singularity_power', bonus: 15, icon: '?', iconImage: 'assets/singularidadeolica.jpg', description: 'Singularidad Eólica', detail: '+15% Poder de atracción' }],
                        3: [{ type: 'pressure_duration', bonus: 25, icon: '??', iconImage: 'assets/presionatmosferica.jpg', description: 'Presión Atmosférica', detail: '+25% Duración inmovilización' }],
                        4: [{ type: 'tornado_count', bonus: 2, icon: '???', iconImage: 'assets/rafagadetornados.jpg', description: 'Ráfaga de Tornados', detail: '+2 Tornados adicionales' }],
                        5: [{ type: 'shield_duration', bonus: 30, icon: '???', iconImage: 'assets/escudodetormenta.jpg', description: 'Escudo de Tormenta', detail: '+30% Duración escudo' }],
                        6: [{ type: 'cooldown', bonus: 15, icon: '??', description: 'Señor de las Tormentas', detail: '-15% Cooldown' }],
                        7: [{ type: 'enemy_tornado_damage', bonus: 40, icon: '??', description: 'Tornado de Enemigo', detail: '+40% Daño' }],
                        8: [{ type: 'confusion_duration', bonus: 35, icon: '??', description: 'Confusión Prolongada', detail: '+35% Duración confusión' }],
                        9: [{ type: 'storm_radius', bonus: 45, icon: '???', description: 'Tormenta Expandida', detail: '+45% Radio de tormenta' }],
                        10: [{ type: 'ultimate', bonus: 100, icon: '???', description: 'Tormenta Apocalíptica', detail: 'Ultimate +100% daño' }]
                    }
                },

                // CYBERNETIC WARLORD - Master of Cyber Gunslinger
                'master_cybernetic_warlord': {
                    icon: '??',
                    name: 'Cybernetic Warlord',
                    upgrades: {
                        2: [{ type: 'plasma_damage', bonus: 20, icon: '?', iconImage: 'assets/canondeplasma.jpg', description: 'Cañón de Plasma', detail: '+20% Daño de plasma' }],
                        3: [{ type: 'singularity_radius', bonus: 25, icon: '??', iconImage: 'assets/granadaddesingularidad.jpg', description: 'Granada de Singularidad', detail: '+25% Radio de singularidad' }],
                        4: [{ type: 'drone_count', bonus: 2, icon: '??', iconImage: 'assets/enjambrededrones.jpg', description: 'Enjambre de Drones', detail: '+2 Drones adicionales' }],
                        5: [{ type: 'barrier_strength', bonus: 30, icon: '???', iconImage: 'assets/barreradefotones.jpg', description: 'Barrera de Fotones', detail: '+30% Resistencia barrera' }],
                        6: [{ type: 'cooldown', bonus: 15, icon: '??', description: 'Sistemas Optimizados', detail: '-15% Cooldown' }],
                        7: [{ type: 'mech_duration', bonus: 40, icon: '??', iconImage: 'assets/protocolomechtsuit.jpg', description: 'Protocolo: MECH-SUIT', detail: '+40% Duración mech' }],
                        8: [{ type: 'heat_efficiency', bonus: 35, icon: '??', description: 'Gestión Térmica', detail: '+35% Eficiencia calor' }],
                        9: [{ type: 'tech_damage', bonus: 50, icon: '?', description: 'Sobrecarga Tecnológica', detail: '+50% Daño tecnológico' }],
                        10: [{ type: 'ultimate', bonus: 150, icon: '??', iconImage: 'assets/sateliteorbitalragnarok.jpg', description: 'Satélite Orbital "Ragnarok"', detail: 'Ultimate +150% daño' }]
                    }
                },

                // ABYSSAL SHADOWLORD - Master of Shadow Ninja
                'master_abyssal_shadowlord': {
                    icon: '??',
                    name: 'Abyssal Shadowlord',
                    upgrades: {
                        2: [{ type: 'blade_storm_damage', bonus: 25, icon: '???', iconImage: 'assets/tormentadecuchillassombrias.jpg', description: 'Tormenta de Cuchillas Sombrías', detail: '+25% Daño de hojas' }],
                        3: [{ type: 'death_chain_targets', bonus: 2, icon: '??', iconImage: 'assets/cadenademuerte.jpg', description: 'Cadena de Muerte', detail: '+2 Objetivos en cadena' }],
                        4: [{ type: 'void_leap_distance', bonus: 30, icon: '??', iconImage: 'assets/saltoalvaciofantasma.jpg', description: 'Salto al Vacío Fantasma', detail: '+30% Distancia de salto' }],
                        5: [{ type: 'shadow_legion_count', bonus: 2, icon: '??', iconImage: 'assets/legiondesombras.jpg', description: 'Legión de Sombras', detail: '+2 Clones adicionales' }],
                        6: [{ type: 'cooldown', bonus: 18, icon: '??', description: 'Señor de las Sombras', detail: '-18% Cooldown' }],
                        7: [{ type: 'emperor_power', bonus: 45, icon: '?', iconrImage: 'assets/emperadorsombra.jpg', description: 'Emperador Sombra', detail: '+45% Poder imperial' }],
                        8: [{ type: 'darkness_duration', bonus: 40, icon: '??', iconImage: 'assets/nocheeterna.jpg', description: 'Noche Eterna', detail: '+40% Duración oscuridad' }],
                        9: [{ type: 'abyss_damage', bonus: 60, icon: '??', description: 'Poder Abisal', detail: '+60% Daño abisal' }],
                        10: [{ type: 'ultimate', bonus: 200, icon: '??', iconImage: 'assets/nocheeterna.jpg', description: 'Noche Eterna', detail: 'Ultimate +200% daño' }]
                    }
                }
            },

            init() {
                this.loadProgress();
            },

            getClassLevel(classId) {
                if (!this.classLevels[classId]) {
                    this.classLevels[classId] = {
                        level: 1,
                        exp: 0,
                        expToNext: 100
                    };
                }
                return this.classLevels[classId];
            },

            addClassExp(classId, exp) {
                const classData = this.getClassLevel(classId);

                if (classData.level >= this.maxClassLevel) {
                    console.log(`? ${classId} ya está en nivel máximo (${this.maxClassLevel})`);
                    return false;
                }

                classData.exp += exp;

                // Check for level up
                while (classData.exp >= classData.expToNext && classData.level < this.maxClassLevel) {
                    classData.exp -= classData.expToNext;
                    classData.level++;
                    classData.expToNext = Math.floor(classData.expToNext * 1.5); // Increase exp requirement

                    this.onLevelUp(classId, classData.level);
                }

                this.saveProgress();
                return true;
            },

            onLevelUp(classId, newLevel) {
                console.log(`?? í${classId} subií a nivel ${newLevel}!`);

                // Show level up notification
                this.showLevelUpNotification(classId, newLevel);

                // Apply new upgrades
                this.applyClassUpgrades(classId);
            },

            showLevelUpNotification(classId, level) {
                const notification = document.createElement('div');
                notification.style.cssText = `
                    position: fixed;
                    top: 50%;
                    left: 50%;
                    transform: translate(-50%, -50%);
                    background: linear-gradient(135deg, #ffbe0b, #ff006e);
                    color: white;
                    padding: 30px 50px;
                    border-radius: 20px;
                    font-size: 24px;
                    font-weight: 900;
                    z-index: 10000;
                    box-shadow: 0 0 50px rgba(255, 190, 11, 0.8);
                    animation: levelUpPulse 0.5s ease-out;
                    text-align: center;
                    font-family: 'Orbitron', sans-serif;
                `;

                const upgrades = this.getClassUpgrades(classId, level);
                const upgradeText = upgrades.map(u => u.description).join('<br>');

                notification.innerHTML = `
                    <div style="font-size: 32px; margin-bottom: 10px;">? NIVEL ${level} ?</div>
                    <div style="font-size: 18px; margin-bottom: 15px;">${classId.toUpperCase()}</div>
                    <div style="font-size: 14px; color: #fff; opacity: 0.9;">${upgradeText}</div>
                `;

                document.body.appendChild(notification);

                setTimeout(() => {
                    notification.style.animation = 'fadeOut 0.5s ease-out';
                    setTimeout(() => notification.remove(), 500);
                }, 3000);
            },

            getClassUpgrades(classId, level) {
                const classTree = this.classUpgrades[classId];
                if (!classTree) return [];
                return classTree.upgrades[level] || [];
            },

            getAllUpgradesForClass(classId) {
                const classData = this.getClassLevel(classId);
                const classTree = this.classUpgrades[classId];
                if (!classTree) return [];

                const allUpgrades = [];

                // Get all upgrades up to current level
                for (let lvl = 1; lvl <= classData.level; lvl++) {
                    const levelUpgrades = classTree.upgrades[lvl] || [];
                    allUpgrades.push(...levelUpgrades);
                }

                return allUpgrades;
            },

            getClassInfo(classId) {
                return this.classUpgrades[classId] || { icon: '?', name: 'Unknown', upgrades: {} };
            },

            applyClassUpgrades(classId) {
                // Upgrades are applied dynamically when calculating damage/duration/cooldown
                // This method is called to trigger any immediate effects
                console.log(`? Mejoras aplicadas para ${classId}`);
            },

            getDamageMultiplier(classId) {
                const allUpgrades = this.getAllUpgradesForClass(classId);
                const damageUpgrades = allUpgrades.filter(u => u.type === 'damage');
                const totalBonus = damageUpgrades.reduce((sum, u) => sum + u.bonus, 0);
                return 1 + (totalBonus / 100);
            },

            getDurationMultiplier(classId) {
                const allUpgrades = this.getAllUpgradesForClass(classId);
                const durationUpgrades = allUpgrades.filter(u => u.type === 'duration');
                const totalBonus = durationUpgrades.reduce((sum, u) => sum + u.bonus, 0);
                return 1 + (totalBonus / 100);
            },

            getCooldownMultiplier(classId) {
                const allUpgrades = this.getAllUpgradesForClass(classId);
                const cooldownUpgrades = allUpgrades.filter(u => u.type === 'cooldown');
                const totalBonus = cooldownUpgrades.reduce((sum, u) => sum + u.bonus, 0);
                return 1 - (totalBonus / 100);
            },

            getSpeedMultiplier(classId) {
                const allUpgrades = this.getAllUpgradesForClass(classId);
                const speedUpgrades = allUpgrades.filter(u => u.type === 'speed');
                const totalBonus = speedUpgrades.reduce((sum, u) => sum + u.bonus, 0);
                return 1 + (totalBonus / 100);
            },

            saveProgress() {
                try {
                    localStorage.setItem('wildDestinyClassLevels', JSON.stringify(this.classLevels));
                } catch (e) {
                    console.error('Failed to save class levels:', e);
                }
            },

            loadProgress() {
                try {
                    const saved = localStorage.getItem('wildDestinyClassLevels');
                    if (saved) {
                        this.classLevels = JSON.parse(saved);
                        console.log('?? Class levels loaded:', this.classLevels);
                    }
                } catch (e) {
                    console.error('Failed to load class levels:', e);
                }
            },

            showUpgradesModal() {
                const modal = document.createElement('div');
                modal.id = 'class-upgrades-modal';
                modal.style.cssText = `
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0, 0, 0, 0.95);
                    z-index: 10000;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    animation: fadeIn 0.3s ease-out;
                `;

                const content = document.createElement('div');
                content.style.cssText = `
                    background: linear-gradient(135deg, rgba(10, 14, 39, 0.98), rgba(15, 5, 30, 0.98));
                    border: 3px solid #00d9ff;
                    border-radius: 20px;
                    width: 90%;
                    max-width: 1200px;
                    height: 85%;
                    padding: 30px;
                    overflow-y: auto;
                    box-shadow: 0 0 50px rgba(0, 217, 255, 0.5);
                `;

                // Get current equipped class
                const equippedRole = EquipmentManager.equippedRole;
                let html = `
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px;">
                        <h2 style="color: #00d9ff; font-family: 'Orbitron', sans-serif; font-size: 32px; margin: 0;">
                            ? MEJORAS DE CLASE
                        </h2>
                        <button id="close-upgrades-modal" style="background: #ff006e; border: none; color: white; padding: 10px 20px; border-radius: 10px; font-size: 16px; font-weight: 700; cursor: pointer;">
                            ? Cerrar
                        </button>
                    </div>
                `;

                if (equippedRole && (equippedRole.type === 'class' || equippedRole.type === 'master_class')) {
                    const classData = this.getClassLevel(equippedRole.id);
                    const classInfo = this.getClassInfo(equippedRole.id);
                    const allUpgrades = this.getAllUpgradesForClass(equippedRole.id);

                    // Header with class info
                    html += `
                        <div style="background: rgba(0, 217, 255, 0.1); border: 2px solid #00d9ff; border-radius: 15px; padding: 20px; margin-bottom: 30px;">
                            <div style="display: flex; align-items: center; gap: 20px;">
                                <div style="font-size: 64px;">${classInfo.icon}</div>
                                <div style="flex: 1;">
                                    <h3 style="color: #fff; font-size: 28px; margin: 0 0 10px 0;">${classInfo.name}</h3>
                                    <div style="color: #ffbe0b; font-size: 18px; font-weight: 700;">Nivel ${classData.level} / ${this.maxClassLevel}</div>
                                    <div style="background: rgba(0, 0, 0, 0.5); border-radius: 10px; height: 25px; margin-top: 10px; overflow: hidden;">
                                        <div style="background: linear-gradient(90deg, #ffbe0b, #ff006e); height: 100%; width: ${(classData.exp / classData.expToNext) * 100}%; transition: width 0.3s;"></div>
                                    </div>
                                    <div style="color: #fff; font-size: 14px; margin-top: 5px;">${classData.exp} / ${classData.expToNext} EXP</div>
                                </div>
                            </div>
                        </div>
                    `;

                    // Upgrades by level
                    html += `<div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 20px;">`;

                    for (let level = 2; level <= this.maxClassLevel; level++) {
                        const levelUpgrades = this.getClassUpgrades(equippedRole.id, level);
                        const isUnlocked = classData.level >= level;

                        html += `
                            <div style="background: ${isUnlocked ? 'rgba(0, 217, 255, 0.1)' : 'rgba(100, 100, 100, 0.1)'}; border: 2px solid ${isUnlocked ? '#00d9ff' : '#666'}; border-radius: 15px; padding: 20px; ${!isUnlocked ? 'opacity: 0.5;' : ''}">
                                <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 15px;">
                                    <div style="background: ${isUnlocked ? 'linear-gradient(135deg, #ffbe0b, #ff006e)' : '#666'}; width: 50px; height: 50px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 24px; font-weight: 900; color: white;">
                                        ${level}
                                    </div>
                                    <div>
                                        <div style="color: ${isUnlocked ? '#00d9ff' : '#999'}; font-size: 18px; font-weight: 700;">NIVEL ${level}</div>
                                        <div style="color: ${isUnlocked ? '#0f0' : '#f00'}; font-size: 12px;">${isUnlocked ? '? DESBLOQUEADO' : '?? BLOQUEADO'}</div>
                                    </div>
                                </div>
                                <div style="display: flex; flex-direction: column; gap: 10px;">
                        `;

                        levelUpgrades.forEach(upgrade => {
                            // Generate image path from description (ability name)
                            let imagePath = upgrade.iconImage;
                            if (!imagePath && upgrade.description) {
                                // Try to generate image path from ability name
                                const cleanName = upgrade.description
                                    .toLowerCase()
                                    .normalize('NFD').replace(/[\u0300-\u036f]/g, '') // Remove accents
                                    .replace(/[^a-z0-9]+/g, '');
                                imagePath = `assets/${cleanName}.jpg`;
                            }

                            const iconHtml = `
                                <img src="${imagePath}" style="width: 48px; height: 48px; border-radius: 8px; object-fit: cover; border: 2px solid #ffbe0b; background: rgba(255, 190, 11, 0.1);" onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';">
                                <div style="display: none; font-size: 28px; width: 48px; height: 48px; align-items: center; justify-content: center; background: rgba(255, 190, 11, 0.2); border-radius: 8px; border: 2px solid #ffbe0b;">${upgrade.icon}</div>
                            `;

                            html += `
                                <div style="background: rgba(0, 0, 0, 0.3); border-radius: 10px; padding: 12px; display: flex; align-items: center; gap: 12px;">
                                    <div style="display: flex; align-items: center; justify-content: center;">
                                        ${iconHtml}
                                    </div>
                                    <div style="flex: 1;">
                                        <div style="color: #ffbe0b; font-size: 14px; font-weight: 700;">${upgrade.description}</div>
                                        <div style="color: #fff; font-size: 12px; opacity: 0.8;">${upgrade.detail}</div>
                                    </div>
                                </div>
                            `;
                        });

                        html += `
                                </div>
                            </div>
                        `;
                    }

                    html += `</div>`;

                } else {
                    html += `
                        <div style="text-align: center; padding: 100px 20px; color: #999;">
                            <div style="font-size: 64px; margin-bottom: 20px;">?</div>
                            <h3 style="color: #fff; font-size: 24px; margin-bottom: 10px;">No hay clase equipada</h3>
                            <p style="font-size: 16px;">Equipa una clase para ver sus mejoras y progresiín</p>
                        </div>
                    `;
                }

                content.innerHTML = html;
                modal.appendChild(content);
                document.body.appendChild(modal);

                // Close button
                document.getElementById('close-upgrades-modal').addEventListener('click', () => {
                    modal.style.animation = 'fadeOut 0.3s ease-out';
                    setTimeout(() => modal.remove(), 300);
                });

                // Close on background click
                modal.addEventListener('click', (e) => {
                    if (e.target === modal) {
                        modal.style.animation = 'fadeOut 0.3s ease-out';
                        setTimeout(() => modal.remove(), 300);
                    }
                });
            }
        };

        // ===== EQUIPMENT MANAGER =====
        const EquipmentManager = {
            equippedRole: null, // Only ONE role can be equipped
            classTickets: {}, // Object with class-specific tickets { dragonhunter: 2, elementalist: 1, ... }
            unlockedClasses: [], // Array of unlocked class IDs

            // Load saved data from localStorage
            loadProgress() {
                try {
                    const saved = localStorage.getItem('wildDestinyProgress');
                    if (saved) {
                        const data = JSON.parse(saved);
                        this.classTickets = data.classTickets || {};
                        this.unlockedClasses = data.unlockedClasses || [];

                        // Update ticket counter (show total)
                        const totalTickets = Object.values(this.classTickets).reduce((a, b) => a + b, 0);
                        document.getElementById('ticket-counter').textContent = totalTickets;

                        // Update stats display
                        this.updateStatsDisplay();

                        // Restore equipped role if saved
                        if (data.equippedRole) {
                            const allRoles = [...rolesData.characters, ...rolesData.classes, ...rolesData.masterClasses];
                            const role = allRoles.find(r => r.id === data.equippedRole.id);
                            if (role) {
                                this.equipRole(role);
                            }
                        } else {
                            // No equipped role saved, equip Wild Berserker by default
                            const defaultClass = rolesData.classes.find(c => c.id === 'class_berserker');
                            if (defaultClass) {
                                this.equipRole(defaultClass);
                                console.log('?? Equipped default class: Wild Berserker');
                            }
                        }

                        console.log('?? Progress loaded:', data);
                    } else {
                        // First time playing, equip Wild Berserker by default
                        const defaultClass = rolesData.classes.find(c => c.id === 'class_berserker');
                        if (defaultClass) {
                            this.equipRole(defaultClass);
                            console.log('?? First time setup: Equipped Wild Berserker');
                        }
                    }
                } catch (e) {
                    console.error('Failed to load progress:', e);
                    // On error, still try to equip default class
                    const defaultClass = rolesData.classes.find(c => c.id === 'class_berserker');
                    if (defaultClass) {
                        this.equipRole(defaultClass);
                    }
                }
            },

            // Save data to localStorage
            saveProgress() {
                try {
                    const data = {
                        classTickets: this.classTickets,
                        unlockedClasses: this.unlockedClasses,
                        equippedRole: this.equippedRole ? { id: this.equippedRole.id, type: this.equippedRole.type } : null
                    };
                    localStorage.setItem('wildDestinyProgress', JSON.stringify(data));
                    console.log('?? Progress saved');

                    // Update stats display
                    this.updateStatsDisplay();
                } catch (e) {
                    console.error('Failed to save progress:', e);
                }
            },

            updateStatsDisplay() {
                // Update total tickets
                const totalTickets = Object.values(this.classTickets).reduce((a, b) => a + b, 0);
                const ticketEl = document.getElementById('total-tickets-display');
                if (ticketEl) ticketEl.textContent = totalTickets;

                // Update unlocked classes count
                const unlockedEl = document.getElementById('unlocked-classes-display');
                if (unlockedEl) unlockedEl.textContent = this.unlockedClasses.length;

                // Update masteries completed count
                const masteriesEl = document.getElementById('masteries-completed-display');
                if (masteriesEl) masteriesEl.textContent = LoadoutManager.unlockedMasterClasses.length;

                // Update Level and EXP bar
                const expPercent = (Player.exp / Player.expToNextLevel) * 100;
                const expCard = document.querySelector('.stat-card:nth-child(3)');
                if (expCard) {
                    const expBar = expCard.querySelector('.stat-bar-fill');
                    const expText = expCard.querySelectorAll('.stat-text span');

                    if (expBar) expBar.style.width = `${expPercent}%`;
                    if (expText[0]) expText[0].textContent = `Nivel ${Player.level}`;
                    if (expText[1]) expText[1].textContent = `${Math.floor(expPercent)}%`;
                }

                // Update HP bar
                const hpPercent = (Player.hp / Player.maxHp) * 100;
                const hpCard = document.querySelector('.stat-card:nth-child(1)');
                if (hpCard) {
                    const hpBar = hpCard.querySelector('.stat-bar-fill');
                    const hpText = hpCard.querySelectorAll('.stat-text span');

                    if (hpBar) hpBar.style.width = `${hpPercent}%`;
                    if (hpText[0]) hpText[0].textContent = `${Math.round(Player.hp)} / ${Player.maxHp}`;
                    if (hpText[1]) hpText[1].textContent = `${Math.floor(hpPercent)}%`;
                }

                // Update hero card in stats panel
                const heroCard = document.getElementById('stats-hero-card');
                const heroName = document.getElementById('stats-hero-name');
                const heroType = document.getElementById('stats-hero-type');
                const heroImage = document.getElementById('stats-hero-image');
                const sectionTitle = document.getElementById('stats-hero-section-title');

                if (this.equippedRole) {
                    const role = this.equippedRole;

                    // Update section title based on type
                    if (sectionTitle) {
                        if (role.type === 'character') {
                            sectionTitle.textContent = '👤 Héroe';
                        } else {
                            sectionTitle.textContent = '🎯 Clase';
                        }
                    }

                    // Update name and type
                    if (heroName) {
                        let displayName = role.name;
                        // Add class level for classes
                        if (role.type === 'class' || role.type === 'master_class') {
                            const classData = ClassProgressionSystem.getClassLevel(role.id);
                            displayName = `${role.name} [Nv.${classData.level}]`;
                        }
                        heroName.textContent = displayName;
                    }
                    if (heroType) {
                        if (role.type === 'character') {
                            heroType.textContent = '👤 Personaje';
                        } else if (role.type === 'master_class') {
                            const classData = ClassProgressionSystem.getClassLevel(role.id);
                            const expPercent = Math.floor((classData.exp / classData.expToNext) * 100);
                            heroType.textContent = `🏆 ${role.tier || 'Clase Maestra'} | EXP: ${expPercent}%`;
                        } else {
                            const classData = ClassProgressionSystem.getClassLevel(role.id);
                            const expPercent = Math.floor((classData.exp / classData.expToNext) * 100);
                            heroType.textContent = `🎯 ${role.tier || 'Clase'} | EXP: ${expPercent}%`;
                        }
                    }

                    // Generate image path (without extension for fallback)
                    let baseImagePath = '';
                    if (role.type === 'character') {
                        const cleanName = role.name.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
                        baseImagePath = role.imagePath ? role.imagePath.replace(/\.(jpg|jpeg|png)$/i, '') : `assets/${cleanName}`;
                    } else if (role.type === 'master_class') {
                        if (role.id === 'master_storm_of_tornados') {
                            baseImagePath = 'assets/tornadooverlord';
                        } else if (role.id === 'master_cybernetic_warlord') {
                            baseImagePath = 'assets/cyberneticwarlord';
                        } else if (role.id === 'master_abyssal_shadowlord') {
                            baseImagePath = 'assets/abyssalshadowlord';
                        }
                    } else if (role.type === 'class') {
                        const basePath = role.imagePath || `assets/${normalizeImageName(role.name)}`;
                        baseImagePath = basePath.replace(/\.(jpg|jpeg|png)$/i, '');
                    }

                    // Update image with fallback
                    if (heroImage && baseImagePath) {
                        heroImage.innerHTML = `
                            <img src="${baseImagePath}.jpg" alt="${role.name}" onerror="this.onerror=null; this.src='${baseImagePath}.jpeg'; this.onerror=function(){this.style.display='none'; this.parentElement.querySelector('.equip-card-image-fallback').style.display='flex';};">
                            <div class="equip-card-image-fallback" style="display: none;">${role.icon}</div>
                        `;
                    } else if (heroImage) {
                        heroImage.innerHTML = `<div class="equip-card-image-fallback">${role.icon}</div>`;
                    }

                    if (heroCard) heroCard.classList.add('equipped');
                } else {
                    // No equipment
                    if (sectionTitle) sectionTitle.textContent = '👤 Héroe';
                    if (heroName) heroName.textContent = 'Sin Equipamiento';
                    if (heroType) heroType.textContent = 'Selecciona un personaje o clase';
                    if (heroImage) heroImage.innerHTML = '<div class="equip-card-image-fallback">?</div>';
                    if (heroCard) heroCard.classList.remove('equipped');
                }
            },

            equipRole(role) {
                // Unequip previous role
                if (this.equippedRole) {
                    console.log(`? Unequipped ${this.equippedRole.type}: ${this.equippedRole.name}`);
                }

                // Equip new role
                this.equippedRole = role;

                // Update player image if it's a character
                if (role.type === 'character') {
                    const img = AssetLoader.getImage(role.imagePath);
                    if (img) Player.currentImage = img;
                } else {
                    Player.currentImage = null; // Reset to default if not a character
                }

                // Preload ability images
                if (role.abilities) {
                    role.abilities.forEach(ability => {
                        const imageName = normalizeImageName(ability.name);
                        const imagePath = ability.iconImage || `assets/${imageName}.jpg`;
                        AssetLoader.loadImage(imagePath);
                    });
                }
                if (role.semiUltimate) {
                    const imageName = normalizeImageName(role.semiUltimate.name);
                    const imagePath = role.semiUltimate.iconImage || `assets/${imageName}.jpg`;
                    AssetLoader.loadImage(imagePath);
                }
                if (role.ultimateAbility) {
                    const imageName = normalizeImageName(role.ultimateAbility.name);
                    const imagePath = role.ultimateAbility.iconImage || `assets/${imageName}.jpg`;
                    AssetLoader.loadImage(imagePath);
                }

                this.updateEquipmentUI();
                this.updateAbilityBar();
                this.saveProgress(); // Save after equipping
                console.log(`? Equipped ${role.type}: ${role.name}`);
            },

            unlockClass(classId) {
                if (!this.unlockedClasses.includes(classId)) {
                    this.unlockedClasses.push(classId);
                    this.saveProgress();
                    console.log(`?? Class unlocked: ${classId}`);
                }
            },

            isClassUnlocked(classId) {
                return this.unlockedClasses.includes(classId);
            },

            getEquippedRole(type) {
                // Return the equipped role if it matches the type, otherwise null
                if (this.equippedRole && this.equippedRole.type === type) {
                    return this.equippedRole;
                }
                return null;
            },

            getAllAbilities() {
                const abilities = [];
                if (this.equippedRole) {
                    abilities.push(...this.equippedRole.abilities);
                    // Add semi-ultimate if it exists (for SSS tier classes)
                    if (this.equippedRole.semiUltimate) {
                        abilities.push(this.equippedRole.semiUltimate);
                    }
                    abilities.push(this.equippedRole.ultimateAbility);
                }
                return abilities;
            },

            updateEquipmentUI() {
                const types = ['character', 'class', 'fruit'];
                const typeNames = {
                    character: 'Personaje',
                    class: 'Clase',
                    fruit: 'Fruta'
                };

                types.forEach(type => {
                    const role = this.getEquippedRole(type);
                    const card = document.getElementById(`card-${type}`);
                    const nameEl = document.getElementById(`${type === 'character' ? 'char' : type}-name`);
                    const imageContainer = document.getElementById(`${type === 'character' ? 'char' : type}-image`);
                    const status = card.querySelector('.equip-status');

                    if (role) {
                        nameEl.textContent = role.name;
                        status.textContent = '? Equipado';
                        card.classList.add('equipped');

                        // Generate image path (without extension for fallback)
                        let baseImagePath = '';
                        if (type === 'character') {
                            const cleanName = role.name.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
                            baseImagePath = role.imagePath ? role.imagePath.replace(/\.(jpg|jpeg|png)$/i, '') : `assets/${cleanName}`;
                        } else if (type === 'class') {
                            const basePath = role.imagePath || `assets/${normalizeImageName(role.name)}`;
                            baseImagePath = basePath.replace(/\.(jpg|jpeg|png)$/i, '');
                        }

                        // Update image with fallback
                        if (baseImagePath) {
                            imageContainer.innerHTML = `
                                <img src="${baseImagePath}.jpg" alt="${role.name}" onerror="this.onerror=null; this.src='${baseImagePath}.jpeg'; this.onerror=function(){this.style.display='none'; this.parentElement.querySelector('.equip-card-image-fallback').style.display='flex';};">
                                <div class="equip-card-image-fallback" style="display: none;">${role.icon}</div>
                            `;
                        } else {
                            imageContainer.innerHTML = `<div class="equip-card-image-fallback">${role.icon}</div>`;
                        }
                    } else {
                        nameEl.textContent = `Sin ${typeNames[type]}`;
                        status.textContent = 'Vacío';
                        card.classList.remove('equipped');

                        // Reset to default icon
                        const defaultIcon = type === 'character' ? '👤' : type === 'class' ? '🎯' : '🍎';
                        imageContainer.innerHTML = `<div class="equip-card-image-fallback">${defaultIcon}</div>`;
                    }
                });
            },

            updateAbilityBar() {
                const abilities = this.getAllAbilities();
                const abilitySlots = document.querySelectorAll('.ability-slot');

                abilitySlots.forEach((slot, index) => {
                    const ability = abilities[index];
                    const iconElement = slot.querySelector('.ability-icon');

                    if (ability) {
                        // Generate image path from ability name: assets/(name in lowercase without spaces).jpg
                        const imageName = normalizeImageName(ability.name);
                        const imagePath = ability.iconImage || `assets/${imageName}.jpg`;

                        // Create or update image element
                        iconElement.innerHTML = '';
                        iconElement.style.padding = '0';
                        iconElement.style.overflow = 'hidden';

                        const img = document.createElement('img');
                        img.src = imagePath;
                        img.alt = ability.name;
                        img.style.cssText = 'width: 100%; height: 100%; object-fit: cover; border-radius: 8px;';
                        img.onerror = function () {
                            // Fallback to emoji if image fails to load
                            iconElement.innerHTML = '';
                            iconElement.textContent = ability.icon;
                            iconElement.style.padding = '';
                        };
                        iconElement.appendChild(img);

                        slot.querySelector('.ability-name').textContent = ability.name;
                        slot.querySelector('.ability-key').textContent = ability.keyBinding.toUpperCase();
                        slot.dataset.abilityId = ability.id;
                        slot.dataset.key = ability.keyBinding.toUpperCase();
                    } else {
                        iconElement.innerHTML = '';
                        iconElement.textContent = '?';
                        iconElement.style.padding = '';
                        slot.querySelector('.ability-name').textContent = 'Empty';
                        slot.dataset.abilityId = '';
                    }
                });
            }
        };

        // ===== LOADOUT MANAGER - MASTERY MISSIONS SYSTEM =====
        const LoadoutManager = {
            masteryProgress: {}, // { class_id: { mission: {...}, unlocked: false } }
            unlockedMasterClasses: [], // Array of unlocked master class IDs
            currentTab: 'equipped',
            missionTrackerVisible: false, // Controls if mission tracker is shown in-game

            init() {
                this.loadMasteries();
                this.setupEventListeners();
            },

            loadMasteries() {
                try {
                    const saved = localStorage.getItem('wildDestinyMasteries');
                    if (saved) {
                        const data = JSON.parse(saved);
                        this.masteryProgress = data.masteryProgress || {};
                        this.unlockedMasterClasses = data.unlockedMasterClasses || [];
                        console.log('? Masteries loaded:', this.masteryProgress);
                    }
                } catch (e) {
                    console.error('Failed to load masteries:', e);
                }
            },

            saveMasteries() {
                try {
                    const data = {
                        masteryProgress: this.masteryProgress,
                        unlockedMasterClasses: this.unlockedMasterClasses
                    };
                    localStorage.setItem('wildDestinyMasteries', JSON.stringify(data));
                    console.log('? Masteries saved');
                } catch (e) {
                    console.error('Failed to save masteries:', e);
                }
            },

            getMissionProgress(classId) {
                if (!this.masteryProgress[classId]) {
                    const masterClass = rolesData.masterClasses.find(mc => mc.baseClassId === classId);
                    if (masterClass && masterClass.masteryMission) {
                        this.masteryProgress[classId] = {
                            requirements: JSON.parse(JSON.stringify(masterClass.masteryMission.requirements)),
                            completed: false
                        };
                    }
                }
                return this.masteryProgress[classId];
            },

            updateMissionProgress(classId, requirementId, amount = 1) {
                const progress = this.getMissionProgress(classId);
                if (!progress || progress.completed) return;

                const req = progress.requirements.find(r => r.id === requirementId);
                if (req) {
                    const maxValue = req.amount || req.waves || 0;
                    req.current = Math.min(req.current + amount, maxValue);

                    console.log(`? Mission Progress [${classId}]: ${req.description} - ${req.current}/${maxValue}`);

                    // Check if all requirements are met
                    const allComplete = progress.requirements.every(r =>
                        r.current >= (r.amount || r.waves)
                    );

                    if (allComplete && !progress.completed) {
                        this.completeMission(classId);
                    }

                    this.saveMasteries();
                }
            },

            trackAbilityUsage(abilityId) {
                // Track ability usage for mastery missions
                if (!EquipmentManager.equippedRole || EquipmentManager.equippedRole.type !== 'class') return;

                const classId = EquipmentManager.equippedRole.id;
                const progress = this.getMissionProgress(classId);
                if (!progress || progress.completed) return;

                // Find requirement that tracks this ability
                const req = progress.requirements.find(r => r.type === 'ability_usage' && r.abilityId === abilityId);
                if (req) {
                    this.updateMissionProgress(classId, req.id, 1);
                }
            },

            completeMission(classId) {
                const progress = this.getMissionProgress(classId);
                if (progress) {
                    progress.completed = true;
                    const masterClass = rolesData.masterClasses.find(mc => mc.baseClassId === classId);
                    if (masterClass && !this.unlockedMasterClasses.includes(masterClass.id)) {
                        this.unlockedMasterClasses.push(masterClass.id);
                        this.showMasterClassUnlocked(masterClass);
                    }
                    this.saveMasteries();

                    // Update stats display
                    EquipmentManager.updateStatsDisplay();
                }
            },

            showMasterClassUnlocked(masterClass) {
                const notification = document.createElement('div');
                notification.style.cssText = `
                    position: fixed;
                    top: 50%;
                    left: 50%;
                    transform: translate(-50%, -50%);
                    background: linear-gradient(135deg, rgba(255, 0, 255, 0.95), rgba(138, 43, 226, 0.95));
                    border: 3px solid #ff00ff;
                    border-radius: 20px;
                    padding: 50px 70px;
                    z-index: 10000;
                    text-align: center;
                    box-shadow: 0 0 60px rgba(255, 0, 255, 0.9);
                    animation: popupFade 4s ease-out forwards;
                `;
                notification.innerHTML = `
                    <div style="font-size: 80px; margin-bottom: 20px;">??</div>
                    <div style="font-size: 36px; font-weight: 900; color: #fff; margin-bottom: 15px;">íCLASE MAESTRA DESBLOQUEADA!</div>
                    <div style="font-size: 48px; margin-bottom: 10px;">${masterClass.icon}</div>
                    <div style="font-size: 32px; font-weight: 900; color: #fff;">${masterClass.name}</div>
                    <div style="font-size: 16px; color: rgba(255, 255, 255, 0.8); margin-top: 15px;">íAhora puedes equipar esta poderosa clase!</div>
                `;
                document.body.appendChild(notification);
                setTimeout(() => notification.remove(), 4000);
            },


            openLoadoutModal() {
                document.getElementById('loadout-modal').classList.remove('hidden');
                this.showTab('equipped');
            },

            closeLoadoutModal() {
                document.getElementById('loadout-modal').classList.add('hidden');
            },

            setupEventListeners() {
                // Close button
                document.getElementById('close-loadout')?.addEventListener('click', () => {
                    this.closeLoadoutModal();
                });

                // Sidebar navigation items
                document.querySelectorAll('.loadout-nav-item').forEach(item => {
                    item.addEventListener('click', () => {
                        const tab = item.dataset.tab;
                        this.showTab(tab);
                    });
                });
            },

            showTab(tabName) {
                this.currentTab = tabName;

                // Update active nav item (sidebar)
                document.querySelectorAll('.loadout-nav-item').forEach(item => {
                    if (item.dataset.tab === tabName) {
                        item.classList.add('active');
                        item.style.background = 'rgba(0, 217, 255, 0.15)';
                        item.style.borderLeftColor = 'var(--primary)';
                    } else {
                        item.classList.remove('active');
                        item.style.background = '';
                        item.style.borderLeftColor = 'transparent';
                    }
                });

                // Update content header titles
                const titles = {
                    equipped: { title: '⚔️ EQUIPADO', subtitle: 'Gestiona tu equipamiento actual y habilidades' },
                    characters: { title: '👤 PERSONAJES', subtitle: 'Selecciona tu héroe y personaliza tu estilo de juego' },
                    classes: { title: '🎯 CLASES', subtitle: 'Desbloquea y equipa clases poderosas con tickets' },
                    masteries: { title: '🏆 MAESTRÍAS', subtitle: 'Completa misiones épicas para desbloquear clases maestras' }
                };

                const titleEl = document.getElementById('loadout-content-title');
                const subtitleEl = document.getElementById('loadout-content-subtitle');
                if (titleEl && titles[tabName]) {
                    titleEl.textContent = titles[tabName].title;
                    subtitleEl.textContent = titles[tabName].subtitle;
                }

                // Load content
                const content = document.getElementById('loadout-content');
                switch (tabName) {
                    case 'equipped':
                        content.innerHTML = this.renderEquippedTab();
                        break;
                    case 'characters':
                        content.innerHTML = this.renderCharactersTab();
                        this.attachCharacterListeners();
                        break;
                    case 'classes':
                        content.innerHTML = this.renderClassesTab();
                        this.attachClassListeners();
                        break;
                    case 'masteries':
                        content.innerHTML = this.renderMasteriesTab();
                        break;
                }
            },

            renderEquippedTab() {
                const equipped = EquipmentManager.equippedRole;

                if (!equipped) {
                    return `
                        <div style="text-align: center; padding: 100px 50px;">
                            <div style="font-size: 120px; margin-bottom: 30px; opacity: 0.3;">?</div>
                            <h2 style="font-size: 36px; color: var(--primary); margin-bottom: 20px;">No hay nada equipado</h2>
                            <p style="font-size: 18px; color: rgba(224, 231, 255, 0.7); margin-bottom: 40px;">Selecciona un personaje o clase para comenzar</p>
                            <button onclick="LoadoutManager.showTab('characters')" style="padding: 15px 40px; font-size: 18px; background: linear-gradient(135deg, var(--primary), var(--secondary)); border: none; border-radius: 12px; color: white; cursor: pointer; font-weight: 700;">
                                ?? Ver Personajes
                            </button>
                        </div>
                    `;
                }

                // Generate image path for equipped role (without extension for fallback)
                let equippedImagePath = '';
                if (equipped.type === 'character') {
                    // For characters, use full name
                    const cleanName = equipped.name.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
                    equippedImagePath = equipped.imagePath ? equipped.imagePath.replace(/\.(jpg|jpeg|png)$/i, '') : `assets/${cleanName}`;
                } else if (equipped.type === 'master_class') {
                    // For master classes
                    if (equipped.id === 'master_storm_of_tornados') {
                        equippedImagePath = 'assets/tornadooverlord';
                    } else if (equipped.id === 'master_cybernetic_warlord') {
                        equippedImagePath = 'assets/cyberneticwarlord';
                    } else if (equipped.id === 'master_abyssal_shadowlord') {
                        equippedImagePath = 'assets/abyssalshadowlord';
                    }
                } else if (equipped.type === 'class') {
                    // For regular classes, use imagePath or normalize name
                    const basePath = equipped.imagePath || `assets/${normalizeImageName(equipped.name)}`;
                    equippedImagePath = basePath.replace(/\.(jpg|jpeg|png)$/i, '');
                }

                // Check if this class has a mastery mission
                const hasMasteryMission = rolesData.masterClasses.some(mc => mc.baseClassId === equipped.id);
                const missionProgress = hasMasteryMission ? this.getMissionProgress(equipped.id) : null;

                let abilitiesHTML = '';
                if (equipped.abilities) {
                    equipped.abilities.forEach(ability => {
                        // Generate image path from ability name (without extension for fallback)
                        const imageName = normalizeImageName(ability.name);
                        const basePath = ability.iconImage ? ability.iconImage.replace(/\.(jpg|jpeg|png)$/i, '') : `assets/${imageName}`;

                        abilitiesHTML += `
                            <div style="background: linear-gradient(135deg, rgba(0, 217, 255, 0.1), rgba(255, 0, 110, 0.1)); border: 2px solid rgba(0, 217, 255, 0.3); border-radius: 15px; overflow: hidden; transition: all 0.3s; cursor: pointer;" onmouseover="this.style.transform='translateY(-5px)'; this.style.boxShadow='0 15px 40px rgba(0, 217, 255, 0.4)'; this.style.borderColor='#00d9ff';" onmouseout="this.style.transform=''; this.style.boxShadow=''; this.style.borderColor='rgba(0, 217, 255, 0.3)';">
                                <!-- Ability Image Header -->
                                <div style="width: 100%; height: 140px; position: relative; overflow: hidden; background: linear-gradient(135deg, rgba(0, 0, 0, 0.6), rgba(0, 217, 255, 0.2));">
                                    <img src="${basePath}.jpg" alt="${ability.name}" style="width: 100%; height: 100%; object-fit: cover; opacity: 0.8;" onerror="this.onerror=null; this.src='${basePath}.jpeg'; this.onerror=function(){this.style.display='none'; this.parentElement.querySelector('div').style.display='flex';};">
                                    <div style="display: none; position: absolute; inset: 0; align-items: center; justify-content: center; font-size: 70px; background: linear-gradient(135deg, rgba(0, 0, 0, 0.7), rgba(0, 217, 255, 0.3));">${ability.icon}</div>
                                    <!-- Key Badge -->
                                    <div style="position: absolute; top: 10px; right: 10px; background: rgba(255, 190, 11, 0.95); padding: 8px 16px; border-radius: 20px; font-weight: 900; font-size: 16px; color: #000; box-shadow: 0 4px 15px rgba(0, 0, 0, 0.5); border: 2px solid rgba(255, 255, 255, 0.3); font-family: 'Orbitron', sans-serif;">
                                        ${ability.keyBinding.toUpperCase()}
                                    </div>
                                </div>
                                
                                <!-- Ability Info -->
                                <div style="padding: 20px;">
                                    <div style="color: #00d9ff; font-weight: 900; font-size: 20px; margin-bottom: 8px; font-family: 'Orbitron', sans-serif; text-shadow: 0 0 10px rgba(0, 217, 255, 0.5);">${ability.name}</div>
                                    <div style="color: rgba(224, 231, 255, 0.7); font-size: 13px; margin-bottom: 12px; display: flex; align-items: center; gap: 10px;">
                                        <span style="background: rgba(0, 217, 255, 0.2); padding: 4px 12px; border-radius: 12px; border: 1px solid rgba(0, 217, 255, 0.4);">?? ${ability.cooldown / 1000}s</span>
                                    </div>
                                    ${ability.description ? `<div style="color: rgba(224, 231, 255, 0.85); font-size: 13px; line-height: 1.6; padding: 12px; background: rgba(0, 0, 0, 0.4); border-radius: 10px; border-left: 3px solid #00d9ff;">${ability.description}</div>` : ''}
                                </div>
                            </div>
                        `;
                    });
                }

                // Semi-Ultimate (for SSS tier classes)
                if (equipped.semiUltimate) {
                    // Generate image path from ability name (without extension for fallback)
                    const imageName = normalizeImageName(equipped.semiUltimate.name);
                    const basePath = equipped.semiUltimate.iconImage ? equipped.semiUltimate.iconImage.replace(/\.(jpg|jpeg|png)$/i, '') : `assets/${imageName}`;

                    abilitiesHTML += `
                        <div style="background: linear-gradient(135deg, rgba(255, 140, 0, 0.2), rgba(255, 69, 0, 0.2)); border: 3px solid rgba(255, 140, 0, 0.8); border-radius: 15px; overflow: hidden; box-shadow: 0 10px 40px rgba(255, 140, 0, 0.5); transition: all 0.3s; cursor: pointer; grid-column: span 1;" onmouseover="this.style.transform='translateY(-8px)'; this.style.boxShadow='0 20px 50px rgba(255, 140, 0, 0.7)';" onmouseout="this.style.transform=''; this.style.boxShadow='0 10px 40px rgba(255, 140, 0, 0.5)';">
                            <!-- Semi-Ultimate Badge -->
                            <div style="background: linear-gradient(90deg, #ff8c00, #ff4500); padding: 12px 20px; text-align: center; border-bottom: 2px solid rgba(255, 140, 0, 0.5);">
                                <div style="color: #fff; font-weight: 900; font-size: 14px; letter-spacing: 3px; text-shadow: 0 2px 10px rgba(0, 0, 0, 0.8); font-family: 'Orbitron', sans-serif;">?? HABILIDAD SEMI-DEFINITIVA</div>
                            </div>
                            
                            <!-- Ability Image Header -->
                            <div style="width: 100%; height: 160px; position: relative; overflow: hidden; background: linear-gradient(135deg, rgba(0, 0, 0, 0.6), rgba(255, 140, 0, 0.3));">
                                <img src="${basePath}.jpg" alt="${equipped.semiUltimate.name}" style="width: 100%; height: 100%; object-fit: cover; opacity: 0.9;" onerror="this.onerror=null; this.src='${basePath}.jpeg'; this.onerror=function(){this.style.display='none'; this.parentElement.querySelector('div').style.display='flex';};">
                                <div style="display: none; position: absolute; inset: 0; align-items: center; justify-content: center; font-size: 80px; background: linear-gradient(135deg, rgba(0, 0, 0, 0.7), rgba(255, 140, 0, 0.4));">${equipped.semiUltimate.icon}</div>
                                <!-- Key Badge -->
                                <div style="position: absolute; top: 15px; right: 15px; background: rgba(255, 190, 11, 0.95); padding: 10px 20px; border-radius: 25px; font-weight: 900; font-size: 20px; color: #000; box-shadow: 0 4px 20px rgba(0, 0, 0, 0.6); border: 3px solid rgba(255, 255, 255, 0.4); font-family: 'Orbitron', sans-serif;">
                                    ${equipped.semiUltimate.keyBinding.toUpperCase()}
                                </div>
                            </div>
                            
                            <!-- Ability Info -->
                            <div style="padding: 25px;">
                                <div style="color: #ff8c00; font-weight: 900; font-size: 24px; margin-bottom: 10px; font-family: 'Orbitron', sans-serif; text-shadow: 0 0 15px rgba(255, 140, 0, 0.8);">${equipped.semiUltimate.name}</div>
                                <div style="color: rgba(224, 231, 255, 0.8); font-size: 14px; margin-bottom: 15px; display: flex; align-items: center; gap: 10px;">
                                    <span style="background: rgba(255, 140, 0, 0.3); padding: 6px 15px; border-radius: 15px; border: 2px solid rgba(255, 140, 0, 0.6); font-weight: 700;">?? ${equipped.semiUltimate.cooldown / 1000}s</span>
                                </div>
                                ${equipped.semiUltimate.description ? `<div style="color: rgba(224, 231, 255, 0.9); font-size: 14px; line-height: 1.7; padding: 15px; background: rgba(0, 0, 0, 0.5); border-radius: 12px; border-left: 4px solid #ff8c00;">${equipped.semiUltimate.description}</div>` : ''}
                            </div>
                        </div>
                    `;
                }

                if (equipped.ultimateAbility) {
                    // Generate image path from ability name (without extension for fallback)
                    const imageName = normalizeImageName(equipped.ultimateAbility.name);
                    const basePath = equipped.ultimateAbility.iconImage ? equipped.ultimateAbility.iconImage.replace(/\.(jpg|jpeg|png)$/i, '') : `assets/${imageName}`;

                    abilitiesHTML += `
                        <div style="background: linear-gradient(135deg, rgba(255, 190, 11, 0.25), rgba(255, 0, 110, 0.25)); border: 4px solid rgba(255, 190, 11, 0.9); border-radius: 15px; overflow: hidden; box-shadow: 0 15px 50px rgba(255, 190, 11, 0.6); transition: all 0.3s; cursor: pointer; grid-column: span 1;" onmouseover="this.style.transform='translateY(-10px) scale(1.02)'; this.style.boxShadow='0 25px 60px rgba(255, 190, 11, 0.8)';" onmouseout="this.style.transform=''; this.style.boxShadow='0 15px 50px rgba(255, 190, 11, 0.6)';">
                            <!-- Ultimate Badge -->
                            <div style="background: linear-gradient(90deg, #ffbe0b, #ff006e); padding: 15px 20px; text-align: center; border-bottom: 3px solid rgba(255, 190, 11, 0.6); position: relative; overflow: hidden;">
                                <div style="position: absolute; inset: 0; background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent); animation: shimmer 2s infinite;"></div>
                                <div style="color: #fff; font-weight: 900; font-size: 16px; letter-spacing: 4px; text-shadow: 0 3px 15px rgba(0, 0, 0, 0.9); font-family: 'Orbitron', sans-serif; position: relative;">? HABILIDAD DEFINITIVA</div>
                            </div>
                            
                            <!-- Ability Image Header -->
                            <div style="width: 100%; height: 180px; position: relative; overflow: hidden; background: linear-gradient(135deg, rgba(0, 0, 0, 0.6), rgba(255, 190, 11, 0.3));">
                                <img src="${basePath}.jpg" alt="${equipped.ultimateAbility.name}" style="width: 100%; height: 100%; object-fit: cover; opacity: 0.95;" onerror="this.onerror=null; this.src='${basePath}.jpeg'; this.onerror=function(){this.style.display='none'; this.parentElement.querySelector('div').style.display='flex';};">
                                <div style="display: none; position: absolute; inset: 0; align-items: center; justify-content: center; font-size: 90px; background: linear-gradient(135deg, rgba(0, 0, 0, 0.7), rgba(255, 190, 11, 0.4));">${equipped.ultimateAbility.icon}</div>
                                <!-- Key Badge -->
                                <div style="position: absolute; top: 15px; right: 15px; background: linear-gradient(135deg, #ffbe0b, #ff006e); padding: 12px 24px; border-radius: 30px; font-weight: 900; font-size: 22px; color: #fff; box-shadow: 0 6px 25px rgba(0, 0, 0, 0.7); border: 3px solid rgba(255, 255, 255, 0.5); font-family: 'Orbitron', sans-serif; text-shadow: 0 2px 10px rgba(0, 0, 0, 0.8);">
                                    ${equipped.ultimateAbility.keyBinding.toUpperCase()}
                                </div>
                            </div>
                            
                            <!-- Ability Info -->
                            <div style="padding: 30px;">
                                <div style="color: #ffbe0b; font-weight: 900; font-size: 28px; margin-bottom: 12px; font-family: 'Orbitron', sans-serif; text-shadow: 0 0 20px rgba(255, 190, 11, 1);">${equipped.ultimateAbility.name}</div>
                                <div style="color: rgba(224, 231, 255, 0.9); font-size: 15px; margin-bottom: 18px; display: flex; align-items: center; gap: 10px;">
                                    <span style="background: rgba(255, 190, 11, 0.3); padding: 8px 18px; border-radius: 20px; border: 2px solid rgba(255, 190, 11, 0.7); font-weight: 800;">?? ${equipped.ultimateAbility.cooldown / 1000}s</span>
                                </div>
                                ${equipped.ultimateAbility.description ? `<div style="color: rgba(224, 231, 255, 0.95); font-size: 14px; line-height: 1.8; padding: 18px; background: rgba(0, 0, 0, 0.6); border-radius: 12px; border-left: 5px solid #ffbe0b; box-shadow: inset 0 0 20px rgba(255, 190, 11, 0.2);">${equipped.ultimateAbility.description}</div>` : ''}
                            </div>
                        </div>
                    `;
                }



                return `
                    <div style="padding: 40px; max-width: 1600px; margin: 0 auto;">
                        <!-- Hero Banner -->
                        <div style="background: linear-gradient(135deg, rgba(0, 217, 255, 0.15), rgba(255, 0, 110, 0.15)); border: 3px solid ${equipped.tierColor || '#00d9ff'}; border-radius: 25px; padding: 0; margin-bottom: 40px; overflow: hidden; box-shadow: 0 20px 60px rgba(0, 0, 0, 0.6), 0 0 40px ${equipped.tierColor || '#00d9ff'}40;">
                            <!-- Hero Image Header -->
                            <div style="position: relative; width: 100%; height: 400px; overflow: hidden;">
                                <img src="${equippedImagePath}.jpg" alt="${equipped.name}" style="width: 100%; height: 100%; object-fit: cover;" onerror="this.onerror=null; this.src='${equippedImagePath}.jpeg'; this.onerror=function(){this.style.display='none'; this.nextElementSibling.style.display='flex';};">
                                <div style="display: none; position: absolute; inset: 0; align-items: center; justify-content: center; font-size: 200px; background: linear-gradient(135deg, rgba(0, 0, 0, 0.7), rgba(${equipped.tierColor?.replace('#', '').match(/.{2}/g)?.map(x => parseInt(x, 16)).join(',') || '0,217,255'}, 0.4)); filter: drop-shadow(0 0 50px ${equipped.tierColor || '#00d9ff'});">
                                    ${equipped.icon}
                                </div>
                                <!-- Gradient Overlay -->
                                <div style="position: absolute; inset: 0; background: linear-gradient(180deg, transparent 0%, rgba(0, 0, 0, 0.8) 100%);"></div>
                                
                                <!-- Badges -->
                                ${equipped.tier ? `<div style="position: absolute; top: 25px; left: 25px; background: ${equipped.tierColor}; padding: 15px 35px; border-radius: 30px; font-weight: 900; font-size: 24px; color: #000; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.6); border: 3px solid rgba(255, 255, 255, 0.4);">TIER ${equipped.tier}</div>` : ''}
                                <div style="position: absolute; top: 25px; right: 25px; background: #00ff00; padding: 12px 30px; border-radius: 30px; font-weight: 900; font-size: 16px; color: #000; box-shadow: 0 10px 30px rgba(0, 255, 0, 0.6); border: 3px solid rgba(255, 255, 255, 0.4);">? EQUIPADO</div>
                                
                                <!-- Hero Name Overlay -->
                                <div style="position: absolute; bottom: 30px; left: 40px; right: 40px;">
                                    <div style="font-size: 56px; font-weight: 900; color: #fff; margin-bottom: 10px; font-family: 'Orbitron', sans-serif; text-shadow: 0 4px 20px rgba(0, 0, 0, 0.9), 0 0 40px ${equipped.tierColor || '#00d9ff'}; line-height: 1.1;">${equipped.name}</div>
                                    ${equipped.title ? `<div style="font-size: 20px; color: var(--accent); font-weight: 700; text-transform: uppercase; letter-spacing: 3px; text-shadow: 0 2px 10px rgba(0, 0, 0, 0.8);">${equipped.title}</div>` : ''}
                                </div>
                            </div>
                            
                            <!-- Hero Info Content -->
                            <div style="padding: 40px 50px;">
                                <div style="display: flex; align-items: center; gap: 20px; margin-bottom: 30px;">
                                    <div style="background: rgba(0, 217, 255, 0.2); border: 2px solid var(--primary); padding: 12px 25px; border-radius: 25px; font-weight: 800; font-size: 15px; text-transform: uppercase; letter-spacing: 2px; color: var(--primary);">
                                        ${equipped.type === 'character' ? '?? PERSONAJE' : equipped.type === 'master_class' ? '? CLASE MAESTRA' : '?? CLASE'}
                                    </div>
                                </div>
                                
                                <div style="color: rgba(224, 231, 255, 0.95); font-size: 18px; line-height: 1.9; margin-bottom: 35px;">
                                    ${equipped.description || 'Sin descripción disponible'}
                                </div>
                                
                                ${equipped.stats ? `
                                    <div style="background: rgba(0, 0, 0, 0.4); border-radius: 20px; padding: 30px; border: 2px solid rgba(0, 217, 255, 0.3);">
                                        <div style="color: var(--primary); font-size: 14px; font-weight: 900; margin-bottom: 25px; letter-spacing: 3px; text-transform: uppercase;">⚡ ATRIBUTOS DEL HÉROE</div>
                                        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 20px;">
                                            <div style="text-align: center; background: rgba(255, 107, 107, 0.1); padding: 20px; border-radius: 15px; border: 2px solid rgba(255, 107, 107, 0.3);">
                                                <div style="color: #ff6b6b; font-size: 38px; font-weight: 900; font-family: 'Orbitron', sans-serif; margin-bottom: 10px;">${equipped.stats.strength}</div>
                                                <div style="color: rgba(224, 231, 255, 0.9); font-size: 11px; text-transform: uppercase; font-weight: 700; letter-spacing: 1px;">?? Fuerza</div>
                                            </div>
                                            <div style="text-align: center; background: rgba(78, 205, 196, 0.1); padding: 20px; border-radius: 15px; border: 2px solid rgba(78, 205, 196, 0.3);">
                                                <div style="color: #4ecdc4; font-size: 38px; font-weight: 900; font-family: 'Orbitron', sans-serif; margin-bottom: 10px;">${equipped.stats.agility}</div>
                                                <div style="color: rgba(224, 231, 255, 0.9); font-size: 11px; text-transform: uppercase; font-weight: 700; letter-spacing: 1px;">? Agilidad</div>
                                            </div>
                                            <div style="text-align: center; background: rgba(162, 155, 254, 0.1); padding: 20px; border-radius: 15px; border: 2px solid rgba(162, 155, 254, 0.3);">
                                                <div style="color: #a29bfe; font-size: 38px; font-weight: 900; font-family: 'Orbitron', sans-serif; margin-bottom: 10px;">${equipped.stats.intelligence}</div>
                                                <div style="color: rgba(224, 231, 255, 0.9); font-size: 11px; text-transform: uppercase; font-weight: 700; letter-spacing: 1px;">?? Inteligencia</div>
                                            </div>
                                            <div style="text-align: center; background: rgba(85, 239, 196, 0.1); padding: 20px; border-radius: 15px; border: 2px solid rgba(85, 239, 196, 0.3);">
                                                <div style="color: #55efc4; font-size: 38px; font-weight: 900; font-family: 'Orbitron', sans-serif; margin-bottom: 10px;">${equipped.stats.vitality}</div>
                                                <div style="color: rgba(224, 231, 255, 0.9); font-size: 11px; text-transform: uppercase; font-weight: 700; letter-spacing: 1px;">?? Vitalidad</div>
                                            </div>
                                            <div style="text-align: center; background: rgba(255, 215, 0, 0.1); padding: 20px; border-radius: 15px; border: 2px solid rgba(255, 215, 0, 0.3);">
                                                <div style="color: #ffd700; font-size: 38px; font-weight: 900; font-family: 'Orbitron', sans-serif; margin-bottom: 10px;">${equipped.stats.luck}</div>
                                                <div style="color: rgba(224, 231, 255, 0.9); font-size: 11px; text-transform: uppercase; font-weight: 700; letter-spacing: 1px;">?? Suerte</div>
                                            </div>
                                        </div>
                                    </div>
                                ` : ''}
                            </div>
                        </div>

                        <!-- Abilities Section -->
                        <div style="margin-bottom: 30px;">
                            <h3 style="color: #00d9ff; font-size: 32px; margin-bottom: 30px; font-weight: 900; font-family: 'Orbitron', sans-serif; text-shadow: 0 0 20px rgba(0, 217, 255, 0.5); display: flex; align-items: center; gap: 15px;">
                                <span style="font-size: 40px;">??</span> HABILIDADES
                            </h3>
                            <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(380px, 1fr)); gap: 20px;">
                                ${abilitiesHTML}
                            </div>
                        </div>

                        <!-- Mastery Mission (if exists) -->
                        ${missionProgress ? `
                            <div style="background: linear-gradient(135deg, rgba(255, 0, 255, 0.15), rgba(138, 43, 226, 0.15)); border: 3px solid #ff00ff; border-radius: 20px; padding: 35px; box-shadow: 0 10px 40px rgba(255, 0, 255, 0.3);">
                                <h3 style="color: #ff00ff; font-size: 28px; margin-bottom: 20px; text-align: center; font-weight: 900; font-family: 'Orbitron', sans-serif; text-shadow: 0 0 20px rgba(255, 0, 255, 0.8);">? MISIÓN DE MAESTRÍA</h3>
                                <div style="text-align: center; margin-bottom: 25px;">
                                    <div style="display: inline-block; background: ${missionProgress.completed ? 'rgba(0, 255, 0, 0.2)' : 'rgba(255, 215, 0, 0.2)'}; border: 2px solid ${missionProgress.completed ? '#00ff00' : '#ffd700'}; padding: 12px 30px; border-radius: 25px; font-size: 16px; color: ${missionProgress.completed ? '#00ff00' : '#ffd700'}; font-weight: 900;">
                                        ${missionProgress.completed ? '? COMPLETADA' : '?? EN PROGRESO'}
                                    </div>
                                </div>
                                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 15px; margin-bottom: 20px;">
                                    ${missionProgress.requirements.map(req => `
                                        <div style="background: rgba(0, 0, 0, 0.4); padding: 20px; border-radius: 12px; border: 2px solid rgba(255, 0, 255, 0.3);">
                                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                                                <span style="color: rgba(224, 231, 255, 0.95); font-size: 14px; font-weight: 600;">${req.description}</span>
                                                <span style="color: ${req.current >= (req.amount || req.waves) ? '#00ff00' : '#ffd700'}; font-weight: 900; font-size: 18px; font-family: 'Orbitron', sans-serif;">
                                                    ${req.current >= (req.amount || req.waves) ? '?' : `${req.current}/${req.amount || req.waves}`}
                                                </span>
                                            </div>
                                            <div style="background: rgba(0, 0, 0, 0.5); height: 10px; border-radius: 5px; overflow: hidden; border: 1px solid rgba(255, 0, 255, 0.3);">
                                                <div style="height: 100%; background: linear-gradient(90deg, #ff00ff, #8a2be2); width: ${(req.current / (req.amount || req.waves)) * 100}%; transition: width 0.3s; box-shadow: 0 0 10px rgba(255, 0, 255, 0.8);"></div>
                                            </div>
                                        </div>
                                    `).join('')}
                                </div>
                                ${missionProgress.completed ? `
                                    <button onclick="LoadoutManager.showTab('masteries')" style="width: 100%; padding: 18px; background: linear-gradient(135deg, #ff00ff, #8a2be2); border: none; border-radius: 12px; color: white; font-weight: 900; cursor: pointer; font-size: 16px; text-transform: uppercase; letter-spacing: 2px; box-shadow: 0 8px 25px rgba(255, 0, 255, 0.5); transition: all 0.3s;" onmouseover="this.style.transform='translateY(-3px)'; this.style.boxShadow='0 12px 35px rgba(255, 0, 255, 0.7)';" onmouseout="this.style.transform=''; this.style.boxShadow='0 8px 25px rgba(255, 0, 255, 0.5)';">
                                        ?? Ver Clase Maestra Desbloqueada
                                    </button>
                                ` : ''}
                            </div>
                        ` : ''}
                    </div>
                `;
            },

            renderCharactersTab() {
                let html = '<div style="padding: 30px;"><div class="role-grid">';

                rolesData.characters.forEach(char => {
                    const isEquipped = EquipmentManager.equippedRole?.id === char.id;

                    // Generate image path automatically from character name
                    // Remove all non-alphanumeric characters and convert to lowercase
                    const cleanName = char.name.replace(/[^a-zA-Z0-9]/g, '').toLowerCase();
                    const baseImagePath = char.imagePath ? char.imagePath.replace(/\.(jpg|jpeg|png)$/i, '') : `assets/${cleanName}`;

                    html += `
                        <div class="role-card ${isEquipped ? 'equipped' : ''}" data-role-id="${char.id}" data-role-type="character" style="cursor: pointer; border-radius: 15px; padding: 0; overflow: hidden; position: relative;">
                            ${isEquipped ? '<div style="position: absolute; top: 15px; right: 15px; background: #00ff00; color: #000; padding: 5px 15px; border-radius: 20px; font-weight: 900; font-size: 12px; z-index: 10; box-shadow: 0 0 20px #00ff00;">? EQUIPADO</div>' : ''}
                            
                            <!-- Image or Icon -->
                            <div style="width: 100%; height: 200px; position: relative; overflow: hidden; background: linear-gradient(135deg, rgba(0, 217, 255, 0.1), rgba(255, 0, 110, 0.1));">
                                <img src="${baseImagePath}.jpg" alt="${char.name}" style="width: 100%; height: 100%; object-fit: cover; position: absolute; inset: 0;" onerror="this.onerror=null; this.src='${baseImagePath}.jpeg'; this.onerror=function(){this.style.display='none'; this.nextElementSibling.style.display='flex';};">
                                <div style="display: none; position: absolute; inset: 0; align-items: center; justify-content: center; flex-direction: column; padding: 20px;">
                                    <div style="font-size: 80px; margin-bottom: 10px; filter: drop-shadow(0 0 20px var(--primary));">${char.icon}</div>
                                </div>
                                <div style="position: absolute; bottom: 0; left: 0; right: 0; background: linear-gradient(transparent, rgba(0, 0, 0, 0.9)); padding: 20px 15px 10px; z-index: 2;">
                                    <div style="color: var(--primary); font-size: 18px; font-weight: 900; text-shadow: 0 0 15px var(--primary);">${char.name}</div>
                                    ${char.title ? `<div style="color: var(--accent); font-size: 11px; font-weight: 700; margin-top: 3px;">${char.title}</div>` : ''}
                                </div>
                            </div>
                            
                            <!-- Info Section -->
                            <div style="padding: 20px;">
                                <div style="text-align: center; margin-bottom: 15px;">
                                    <div style="display: inline-block; background: var(--primary); color: #000; padding: 6px 16px; border-radius: 20px; font-weight: 900; font-size: 11px; box-shadow: 0 5px 15px rgba(0, 217, 255, 0.4);">?? PERSONAJE</div>
                                </div>
                                
                                ${char.race ? `
                                    <div style="color: rgba(224, 231, 255, 0.9); font-size: 12px; text-align: center; margin-bottom: 8px;">
                                        <span style="color: var(--accent); font-weight: 700;">Raza:</span> ${char.race}
                                    </div>
                                ` : ''}
                                
                                <div style="color: rgba(224, 231, 255, 0.85); font-size: 13px; line-height: 1.6; text-align: center; margin-bottom: 15px; min-height: 60px;">
                                    ${char.description}
                                </div>
                                
                                ${char.stats ? `
                                    <div style="background: rgba(0, 217, 255, 0.1); border: 1px solid rgba(0, 217, 255, 0.3); border-radius: 10px; padding: 12px; margin-bottom: 10px;">
                                        <div style="color: var(--primary); font-size: 10px; font-weight: 900; margin-bottom: 8px; letter-spacing: 1px; text-align: center;">?? ATRIBUTOS</div>
                                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 6px; font-size: 11px;">
                                            <div style="color: rgba(224, 231, 255, 0.8);"><span style="color: #ff6b6b;">??</span> ${char.stats.strength}</div>
                                            <div style="color: rgba(224, 231, 255, 0.8);"><span style="color: #4ecdc4;">?</span> ${char.stats.agility}</div>
                                            <div style="color: rgba(224, 231, 255, 0.8);"><span style="color: #a29bfe;">??</span> ${char.stats.intelligence}</div>
                                            <div style="color: rgba(224, 231, 255, 0.8);"><span style="color: #55efc4;">??</span> ${char.stats.vitality}</div>
                                            <div style="color: rgba(224, 231, 255, 0.8);" colspan="2"><span style="color: #ffd700;">??</span> ${char.stats.luck}</div>
                                        </div>
                                    </div>
                                ` : ''}
                            </div>
                        </div>
                    `;
                });

                html += '</div></div>';
                return html;
            },

            renderClassesTab() {
                let html = `
                    <div style="padding: 30px;">
                        <!-- TIER CLASSES SECTION -->
                        <div style="margin-bottom: 50px;">
                            <div style="text-align: center; margin-bottom: 30px;">
                                <h2 style="font-size: 36px; color: #00d9ff; margin-bottom: 10px; font-weight: 900; text-shadow: 0 0 20px #00d9ff;">?? CLASES POR TIER</h2>
                                <p style="font-size: 14px; color: rgba(224, 231, 255, 0.7);">Desbloquea clases derrotando enemigos y jefes para obtener tickets</p>
                            </div>
                            <div class="role-grid">
                `;

                // Render regular classes grouped by tier
                const tierGroups = {
                    'A': [],
                    'B': [],
                    'S+': [],
                    'S': [],
                    'SS': [],
                    'SSS': []
                };

                rolesData.classes.forEach(cls => {
                    if (cls.tier && tierGroups[cls.tier]) {
                        tierGroups[cls.tier].push(cls);
                    }
                });

                // Render each tier group
                ['A', 'B', 'S+', 'S', 'SS', 'SSS'].forEach(tier => {
                    if (tierGroups[tier].length > 0) {
                        tierGroups[tier].forEach(cls => {
                            const isEquipped = EquipmentManager.equippedRole?.id === cls.id;
                            const isUnlocked = EquipmentManager.isClassUnlocked(cls.id);
                            const currentTickets = EquipmentManager.classTickets[cls.id] || 0;
                            const hasEnoughTickets = currentTickets >= cls.ticketsRequired;
                            const canUnlock = !isUnlocked && hasEnoughTickets;

                            // Use defined imagePath or generate from class name
                            let imagePath = cls.imagePath || `assets/${cls.name.toLowerCase().replace(/\s+/g, '')}`;
                            // Remove extension if present to allow fallback
                            const baseImagePath = imagePath.replace(/\.(jpg|jpeg|png)$/i, '');

                            html += `
                                <div class="role-card ${isEquipped ? 'equipped' : ''} ${!isUnlocked && !hasEnoughTickets ? 'locked' : ''}" data-role-id="${cls.id}" data-role-type="class" style="cursor: pointer; border-color: ${cls.tierColor}; box-shadow: 0 0 20px ${cls.tierColor}40; position: relative; overflow: hidden; padding: 0; background: linear-gradient(135deg, rgba(0, 0, 0, 0.8), rgba(${cls.tierColor.replace('#', '').match(/.{2}/g).map(x => parseInt(x, 16)).join(',')}, 0.2)); border-radius: 12px;">
                                    ${isEquipped ? '<div style="position: absolute; top: 10px; right: 10px; background: #00ff00; color: #000; padding: 3px 10px; border-radius: 15px; font-weight: 900; font-size: 10px; z-index: 10;">? EQUIPADO</div>' : ''}
                                    
                                    <!-- Image or Icon -->
                                    <div style="width: 100%; height: 140px; position: relative; background-color: rgba(0, 0, 0, 0.5); overflow: hidden;">
                                        <!-- Fallback icon if image doesn't load -->
                                        <div style="position: absolute; inset: 0; display: none; align-items: center; justify-content: center; font-size: 60px; background: linear-gradient(135deg, rgba(0, 0, 0, 0.7), rgba(${cls.tierColor.replace('#', '').match(/.{2}/g).map(x => parseInt(x, 16)).join(',')}, 0.3)); z-index: 1;">${cls.icon}</div>
                                        <img src="${baseImagePath}.jpg" alt="${cls.name}" style="width: 100%; height: 100%; object-fit: cover; position: absolute; inset: 0; z-index: 2;" onerror="this.onerror=null; this.src='${baseImagePath}.jpeg'; this.onerror=function(){this.style.display='none'; this.parentElement.querySelector('div').style.display='flex';};">
                                        <div style="position: absolute; inset: 0; background: linear-gradient(transparent 40%, rgba(0, 0, 0, 0.9)); display: flex; align-items: flex-end; padding: 10px; z-index: 3;">
                                            <div style="width: 100%;">
                                                <div class="role-card-name" style="color: #fff; font-size: 16px; font-weight: 900; text-shadow: 0 2px 10px rgba(0, 0, 0, 0.8);">${cls.name}</div>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <!-- Info Section -->
                                    <div style="padding: 15px;">
                                        <div style="color: ${cls.tierColor}; font-weight: 900; font-size: 18px; text-align: center; margin-bottom: 8px; text-shadow: 0 0 10px ${cls.tierColor};">TIER ${cls.tier}</div>
                                        <div style="color: ${isUnlocked ? '#00ff00' : canUnlock ? '#ffd700' : '#999'}; font-size: 12px; text-align: center; margin-bottom: 5px; font-weight: 700;">
                                            ${isUnlocked ? '? Desbloqueada' : canUnlock ? '? Lista' : '?? Bloqueada'}
                                        </div>
                                        <div style="color: rgba(224, 231, 255, 0.8); font-size: 11px; text-align: center;">
                                            ?? ${currentTickets}/${cls.ticketsRequired}
                                        </div>
                                    </div>
                                </div>
                            `;
                        });
                    }
                });

                html += `
                            </div>
                        </div>
                        
                        <!-- MASTER CLASSES SECTION -->
                        <div>
                            <div style="text-align: center; margin-bottom: 30px;">
                                <h2 style="font-size: 40px; color: #ff00ff; margin-bottom: 10px; font-weight: 900; text-shadow: 0 0 30px #ff00ff;">? CLASES DE MAESTRÍA</h2>
                                <p style="font-size: 14px; color: rgba(224, 231, 255, 0.7);">Versiones supremas desbloqueadas completando misiones de maestría</p>
                            </div>
                            <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 25px;">
                `;

                // Render master classes with images
                rolesData.masterClasses.forEach(masterCls => {
                    const isEquipped = EquipmentManager.equippedRole?.id === masterCls.id;
                    const isUnlocked = LoadoutManager.unlockedMasterClasses.includes(masterCls.id);

                    // Determine image path
                    let imagePath = '';
                    if (masterCls.id === 'master_storm_of_tornados') {
                        imagePath = 'assets/tornadooverlord.jpg';
                    } else if (masterCls.id === 'master_cybernetic_warlord') {
                        imagePath = 'assets/cyberneticwarlord.jpg';
                    } else if (masterCls.id === 'master_abyssal_shadowlord') {
                        imagePath = 'assets/abyssalshadowlord.jpg';
                    }

                    html += `
                        <div class="role-card" data-role-id="${masterCls.id}" data-role-type="master_class" style="cursor: pointer; border: 3px solid ${masterCls.tierColor}; box-shadow: 0 0 40px ${masterCls.tierColor}80; background: linear-gradient(135deg, rgba(0, 0, 0, 0.8), rgba(${masterCls.tierColor.replace('#', '').match(/.{2}/g).map(x => parseInt(x, 16)).join(',')}, 0.2)); border-radius: 15px; padding: 0; overflow: hidden; position: relative; ${!isUnlocked ? 'opacity: 0.7; filter: grayscale(60%);' : ''}">
                            ${isEquipped ? '<div style="position: absolute; top: 15px; right: 15px; background: #00ff00; color: #000; padding: 5px 15px; border-radius: 20px; font-weight: 900; font-size: 12px; z-index: 10; box-shadow: 0 0 20px #00ff00;">? EQUIPADO</div>' : ''}
                            ${!isUnlocked ? '<div style="position: absolute; top: 15px; left: 15px; background: rgba(255, 0, 255, 0.9); color: #fff; padding: 5px 15px; border-radius: 20px; font-weight: 900; font-size: 11px; z-index: 10;">?? BLOQUEADA</div>' : ''}
                            
                            <!-- Image or Icon -->
                            <div style="width: 100%; height: 200px; position: relative; overflow: hidden; background-color: rgba(0, 0, 0, 0.5);">
                                ${imagePath ? `
                                    <img src="${imagePath}" alt="${masterCls.name}" style="width: 100%; height: 100%; object-fit: cover; position: absolute; inset: 0;" onerror="this.style.display='none'; this.nextElementSibling.nextElementSibling.style.display='flex';">
                                    <div style="position: absolute; bottom: 0; left: 0; right: 0; background: linear-gradient(transparent, rgba(0, 0, 0, 0.9)); padding: 20px 15px 10px; z-index: 2;">
                                        <div style="color: ${masterCls.tierColor}; font-size: 24px; font-weight: 900; text-shadow: 0 0 15px ${masterCls.tierColor};">${masterCls.name}</div>
                                    </div>
                                    <!-- Fallback icon -->
                                    <div style="position: absolute; inset: 0; display: none; flex-direction: column; align-items: center; justify-content: center; background: linear-gradient(135deg, rgba(0, 0, 0, 0.7), rgba(${masterCls.tierColor.replace('#', '').match(/.{2}/g).map(x => parseInt(x, 16)).join(',')}, 0.3)); z-index: 1;">
                                        <div style="font-size: 80px; margin-bottom: 10px; filter: drop-shadow(0 0 20px ${masterCls.tierColor});">${masterCls.icon}</div>
                                        <div style="color: ${masterCls.tierColor}; font-size: 24px; font-weight: 900; text-shadow: 0 0 15px ${masterCls.tierColor};">${masterCls.name}</div>
                                    </div>
                                ` : `
                                    <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; background: linear-gradient(135deg, rgba(0, 0, 0, 0.7), rgba(${masterCls.tierColor.replace('#', '').match(/.{2}/g).map(x => parseInt(x, 16)).join(',')}, 0.3));">
                                        <div style="font-size: 80px; margin-bottom: 10px; filter: drop-shadow(0 0 20px ${masterCls.tierColor});">${masterCls.icon}</div>
                                        <div style="color: ${masterCls.tierColor}; font-size: 24px; font-weight: 900; text-shadow: 0 0 15px ${masterCls.tierColor};">${masterCls.name}</div>
                                    </div>
                                `}
                            </div>
                            
                            <!-- Info Section -->
                            <div style="padding: 20px;">
                                <div style="text-align: center; margin-bottom: 15px;">
                                    <div style="display: inline-block; background: ${masterCls.tierColor}; color: #000; padding: 8px 20px; border-radius: 20px; font-weight: 900; font-size: 16px; box-shadow: 0 5px 15px ${masterCls.tierColor}60;">? ${masterCls.tier}</div>
                                </div>
                                
                                <div style="color: rgba(224, 231, 255, 0.85); font-size: 13px; line-height: 1.6; text-align: center; margin-bottom: 15px; min-height: 60px;">
                                    ${masterCls.description}
                                </div>
                                
                                ${masterCls.passiveSystem ? `
                                    <div style="background: rgba(255, 0, 255, 0.15); border: 2px solid rgba(255, 0, 255, 0.4); border-radius: 10px; padding: 12px; margin-bottom: 15px;">
                                        <div style="color: #ff00ff; font-size: 11px; font-weight: 900; margin-bottom: 5px; letter-spacing: 1px;">?? PASIVA íNICA</div>
                                        <div style="color: #ffd700; font-size: 13px; font-weight: 700; margin-bottom: 3px;">${masterCls.passiveSystem.name}</div>
                                        <div style="color: rgba(224, 231, 255, 0.8); font-size: 11px; line-height: 1.4;">${masterCls.passiveSystem.description}</div>
                                    </div>
                                ` : ''}
                                
                                <div style="display: flex; gap: 10px; justify-content: center;">
                                    <div style="flex: 1; text-align: center; background: rgba(0, 217, 255, 0.1); border: 1px solid rgba(0, 217, 255, 0.3); border-radius: 8px; padding: 8px;">
                                        <div style="color: #00d9ff; font-size: 11px; font-weight: 700;">HABILIDADES</div>
                                        <div style="color: #fff; font-size: 18px; font-weight: 900;">${masterCls.abilities.length}</div>
                                    </div>
                                    <div style="flex: 1; text-align: center; background: rgba(255, 140, 0, 0.1); border: 1px solid rgba(255, 140, 0, 0.3); border-radius: 8px; padding: 8px;">
                                        <div style="color: #ff8c00; font-size: 11px; font-weight: 700;">SEMI-ULT</div>
                                        <div style="color: #fff; font-size: 18px; font-weight: 900;">1</div>
                                    </div>
                                    <div style="flex: 1; text-align: center; background: rgba(255, 190, 11, 0.1); border: 1px solid rgba(255, 190, 11, 0.3); border-radius: 8px; padding: 8px;">
                                        <div style="color: #ffbe0b; font-size: 11px; font-weight: 700;">ULTIMATE</div>
                                        <div style="color: #fff; font-size: 18px; font-weight: 900;">1</div>
                                    </div>
                                </div>
                                
                                ${!isUnlocked ? `
                                    <div style="margin-top: 15px; text-align: center;">
                                        <button onclick="LoadoutManager.showTab('masteries')" style="width: 100%; padding: 12px; background: linear-gradient(135deg, #ff00ff, #8a2be2); border: none; border-radius: 10px; color: white; font-weight: 900; font-size: 14px; cursor: pointer; box-shadow: 0 5px 15px rgba(255, 0, 255, 0.4); transition: all 0.3s;" onmouseover="this.style.transform='translateY(-2px)'; this.style.boxShadow='0 8px 20px rgba(255, 0, 255, 0.6)'" onmouseout="this.style.transform='translateY(0)'; this.style.boxShadow='0 5px 15px rgba(255, 0, 255, 0.4)'">
                                            ?? Ver Misión de Maestría
                                        </button>
                                    </div>
                                ` : ''}
                            </div>
                        </div>
                    `;
                });

                html += `
                            </div>
                        </div>
                    </div>
                `;

                return html;
            },

            renderMasteriesTab() {
                let html = `
                    <div style="padding: 30px; animation: fadeIn 0.5s ease-out;">
                        <div style="text-align: center; margin-bottom: 50px;">
                            <h2 style="font-size: 42px; color: #ff00ff; margin-bottom: 10px; font-weight: 900; text-transform: uppercase; letter-spacing: 2px; text-shadow: 0 0 30px rgba(255, 0, 255, 0.6);">
                                <span style="border-bottom: 4px solid #ff00ff; padding-bottom: 10px;">Zona de Maestrías</span>
                            </h2>
                            <p style="font-size: 16px; color: rgba(224, 231, 255, 0.6); margin-top: 20px; font-style: italic;">"La evolución solo llega a aquellos que sobreviven al caos."</p>
                        </div>
                `;

                // --- 1. CLASS MASTERIES (EVOLUTION LINE DESIGN) ---
                html += `
                    <div style="margin-bottom: 80px;">
                        <div style="display: flex; align-items: center; gap: 20px; margin-bottom: 40px; border-bottom: 2px solid rgba(255, 0, 255, 0.3); padding-bottom: 20px;">
                            <div style="background: #ff00ff; color: #000; width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; border-radius: 5px; font-weight: 900; font-size: 24px;">C</div>
                            <div>
                                <h3 style="color: #fff; font-size: 28px; font-weight: 900; margin: 0;">EVOLUCIÓN DE CLASES</h3>
                                <div style="color: rgba(255, 255, 255, 0.5); font-size: 13px; margin-top: 5px;">Completa las misiones para trascender tus límites</div>
                            </div>
                        </div>

                        <div style="display: flex; flex-direction: column; gap: 40px;">
                `;

                // Filter only classes WITH masteries
                const classesWithMastery = rolesData.classes.filter(cls =>
                    rolesData.masterClasses.some(mc => mc.baseClassId === cls.id)
                );

                if (classesWithMastery.length === 0) {
                    html += `<div style="text-align:center; color: #666; font-size: 18px;">No hay maestrías disponibles aún.</div>`;
                }

                classesWithMastery.forEach(cls => {
                    const masterClass = rolesData.masterClasses.find(mc => mc.baseClassId === cls.id);
                    const progress = this.getMissionProgress(cls.id);
                    const isUnlocked = this.unlockedMasterClasses.includes(masterClass.id);

                    const totalReqs = progress?.requirements.length || 0;
                    const completedReqs = progress?.requirements.filter(r => r.current >= (r.amount || r.waves)).length || 0;
                    const percent = totalReqs > 0 ? (completedReqs / totalReqs) * 100 : 0;

                    const clsImagePath = cls.imagePath || `assets/${cls.name.toLowerCase().replace(/\s+/g, '')}.jpg`;
                    const masterImagePath = masterClass.imagePath || `assets/${masterClass.name.toLowerCase().replace(/\s+/g, '')}.jpg`;

                    // Card Container
                    html += `
                        <div style="background: linear-gradient(90deg, rgba(20,20,30,0.9), rgba(40,20,60,0.9)); border: 1px solid rgba(255, 0, 255, 0.3); border-radius: 20px; overflow: hidden; position: relative; box-shadow: 0 10px 40px rgba(0,0,0,0.5);">
                            <!-- Connection Line Graphic in Background -->
                            <div style="position: absolute; top: 50%; left: 0; right: 0; height: 2px; background: linear-gradient(90deg, transparent, rgba(255,0,255,0.2), transparent); transform: translateY(-50%); z-index: 0;"></div>

                            <div style="display: flex; align-items: stretch; position: relative; z-index: 1; flex-wrap: wrap;">

                                <!-- LEFT: Base Class (Smaller) -->
                                <div style="width: 200px; background: rgba(0,0,0,0.4); border-right: 1px solid rgba(255,255,255,0.05); padding: 30px; display: flex; flex-direction: column; align-items: center; justify-content: center;">
                                    <div style="width: 80px; height: 80px; border-radius: 15px; overflow: hidden; border: 2px solid ${cls.tierColor}; margin-bottom: 20px; box-shadow: 0 0 20px rgba(0,0,0,0.5); opacity: 0.8;">
                                        <img src="${clsImagePath}" style="width: 100%; height: 100%; object-fit: cover;" onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';">
                                        <div style="display: none; width: 100%; height: 100%; background: #222; align-items: center; justify-content: center; font-size: 30px;">${cls.icon}</div>
                                    </div>
                                    <h4 style="color: ${cls.tierColor}; font-size: 14px; font-weight: 700; text-align: center; margin: 0;">${cls.name}</h4>
                                    <div style="color: #666; font-size: 11px; margin-top: 5px;">Clase Base</div>
                                </div>

                                <!-- CENTER: Arrow/Connector -->
                                <div style="width: 60px; display: flex; align-items: center; justify-content: center; position: relative;">
                                    <div style="color: rgba(255,0,255,0.5); font-size: 24px; animation: pulseArrow 2s infinite;">?</div>
                                </div>

                                <!-- RIGHT: Master Class (Larger) -->
                                <div style="flex: 1; padding: 40px; display: flex; align-items: center; gap: 40px; background: ${isUnlocked ? 'linear-gradient(135deg, rgba(0,255,0,0.05), transparent)' : 'transparent'}; min-width: 300px;">
                                    
                                    <!-- Master Image -->
                                    <div style="width: 140px; height: 140px; border-radius: 20px; border: 3px solid ${isUnlocked ? '#00ff00' : '#ff00ff'}; box-shadow: 0 0 30px ${isUnlocked ? 'rgba(0,255,0,0.2)' : 'rgba(255,0,255,0.2)'}; overflow: hidden; position: relative; flex-shrink: 0;">
                                        <img src="${masterImagePath}" style="width: 100%; height: 100%; object-fit: cover; filter: ${isUnlocked ? 'none' : 'grayscale(100%) contrast(1.2)'}; transition: filter 0.3s;" onerror="this.style.display='none'; this.nextElementSibling.style.display='flex';">
                                        <div style="display: none; width: 100%; height: 100%; background: #111; align-items: center; justify-content: center; font-size: 50px;">${masterClass.icon || '?'}</div>
                                        
                                        ${!isUnlocked ? '<div style="position: absolute; inset: 0; background: rgba(0,0,0,0.6); display: flex; align-items: center; justify-content: center; color: #ff00ff; font-size: 40px;">?</div>' : ''}
                                    </div>

                                    <!-- Master Info -->
                                    <div style="flex: 1;">
                                        <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 15px;">
                                            <div>
                                                <h3 style="color: ${isUnlocked ? '#00ff00' : '#ff00ff'}; font-size: 28px; font-weight: 900; margin: 0 0 10px 0; text-shadow: 0 0 20px ${isUnlocked ? 'rgba(0,255,0,0.3)' : 'rgba(255,0,255,0.3)'};">${masterClass.name}</h3>
                                                <p style="color: rgba(224, 231, 255, 0.8); font-size: 13px; line-height: 1.5; margin: 0; max-width: 500px;">${masterClass.description}</p>
                                            </div>
                                            ${isUnlocked ? `
                                                <div style="background: rgba(0,255,0,0.1); border: 1px solid #00ff00; padding: 5px 15px; border-radius: 20px; color: #00ff00; font-size: 11px; font-weight: 900;">DESBLOQUEADO</div>
                                            ` : ''}
                                        </div>

                                        <!-- Requirements / Unlock Check -->
                                        ${!isUnlocked ? `
                                            <div style="background: rgba(0,0,0,0.3); border-radius: 12px; padding: 20px; border: 1px solid rgba(255,0,255,0.2);">
                                                <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                                                    <span style="color: #ff00ff; font-size: 12px; font-weight: 700; text-transform: uppercase;">Progreso de Maestría</span>
                                                    <span style="color: #fff;">${Math.round(percent)}%</span>
                                                </div>
                                                
                                                <div style="width: 100%; height: 6px; background: rgba(255,255,255,0.1); border-radius: 4px; overflow: hidden; margin-bottom: 15px;">
                                                    <div style="width: ${percent}%; height: 100%; background: linear-gradient(90deg, #ff00ff, #8a2be2); box-shadow: 0 0 10px #ff00ff;"></div>
                                                </div>

                                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                                                    ${progress.requirements.map(req => {
                        const reqMet = req.current >= (req.amount || req.waves);
                        return `
                                                            <div style="display: flex; align-items: center; gap: 10px; font-size: 11px; color: ${reqMet ? '#00ff00' : '#aaa'};">
                                                                <span>${reqMet ? '?' : '?'}</span>
                                                                <span>${req.description}</span>
                                                                <span style="margin-left: auto; font-family: monospace;">${req.current}/${req.amount || req.waves}</span>
                                                            </div>
                                                        `;
                    }).join('')}
                                                </div>
                                            </div>
                                        ` : `
                                            <div style="display: inline-flex; align-items: center; gap: 15px; background: rgba(0,255,0,0.05); padding: 15px 25px; border-radius: 10px; border-left: 3px solid #00ff00;">
                                                <span style="font-size: 24px;">?</span>
                                                <div>
                                                    <div style="color: #00ff00; font-weight: 700; font-size: 13px;">Lista para equipar</div>
                                                    <div style="color: #aaa; font-size: 11px;">Ve al menú de Clases para usarla</div>
                                                </div>
                                                <button onclick="LoadoutManager.showTab('classes')" style="margin-left: 20px; background: #00ff00; color: #000; border: none; padding: 8px 20px; border-radius: 5px; font-weight: 900; cursor: pointer; transition: transform 0.2s;">IR AHORA</button>
                                            </div>
                                        `}
                                    </div>
                                </div>
                            </div>
                        </div>
                    `;
                });

                html += `</div></div>`; // End Classes

                // --- 2 & 3. CHARACTERS & FRUITS (CONSTRUCTION ZONES) ---
                const renderConstructionZone = (title, icon) => `
                    <div style="margin-bottom: 60px;">
                        <!-- Header -->
                        <div style="display: flex; align-items: center; gap: 20px; margin-bottom: 30px; border-bottom: 2px solid #ffd700; padding-bottom: 20px;">
                            <div style="background: #ffd700; color: #000; width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; border-radius: 5px; font-weight: 900; font-size: 24px;">?</div>
                            <div>
                                <h3 style="color: #fff; font-size: 28px; font-weight: 900; margin: 0;">${title}</h3>
                                <div style="color: rgba(255, 255, 255, 0.5); font-size: 13px; margin-top: 5px;">Área restringida - Desarrollo en curso</div>
                            </div>
                        </div>

                        <!-- Door Container -->
                        <div style="
                            height: 350px;
                            background: #111;
                            border-radius: 20px;
                            border: 4px solid #333;
                            position: relative;
                            overflow: hidden;
                            display: flex;
                            align-items: center;
                            justify-content: center;
                            box-shadow: inset 0 0 100px #000;
                        ">
                            <!-- Background Grid/Metal Plate Effect -->
                            <div style="
                                position: absolute;
                                inset: 0;
                                background-image: 
                                    linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px),
                                    linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px);
                                background-size: 50px 50px;
                                opacity: 0.5;
                            "></div>

                            <!-- Diagonal Vigilance Stripes (Top) -->
                            <div style="
                                position: absolute;
                                top: 40px;
                                left: -50px;
                                right: -50px;
                                height: 50px;
                                background: repeating-linear-gradient(
                                    45deg,
                                    #ffd700,
                                    #ffd700 20px,
                                    #000 20px,
                                    #000 40px
                                );
                                transform: rotate(2deg);
                                box-shadow: 0 5px 15px rgba(0,0,0,0.5);
                                display: flex;
                                align-items: center;
                                justify-content: center;
                                z-index: 10;
                            ">
                                <span style="color: #000; background: #ffd700; padding: 2px 10px; font-weight: 900; font-size: 18px; letter-spacing: 5px;">ZONA DE CONSTRUCCIÓN</span>
                            </div>

                            <!-- Diagonal Vigilance Stripes (Bottom) -->
                            <div style="
                                position: absolute;
                                bottom: 40px;
                                left: -50px;
                                right: -50px;
                                height: 50px;
                                background: repeating-linear-gradient(
                                    45deg,
                                    #ffd700,
                                    #ffd700 20px,
                                    #000 20px,
                                    #000 40px
                                );
                                transform: rotate(-2deg);
                                box-shadow: 0 5px 15px rgba(0,0,0,0.5);
                                display: flex;
                                align-items: center;
                                justify-content: center;
                                z-index: 10;
                            ">
                                <span style="color: #000; background: #ffd700; padding: 2px 10px; font-weight: 900; font-size: 18px; letter-spacing: 5px;">MANTÉNGASE ALEJADO</span>
                            </div>

                            <!-- Central Lock UI -->
                            <div style="
                                position: relative;
                                z-index: 20;
                                background: rgba(10,10,10,0.9);
                                border: 2px solid #ffd700;
                                border-radius: 20px;
                                padding: 40px 60px;
                                text-align: center;
                                backdrop-filter: blur(10px);
                                box-shadow: 0 0 50px rgba(255, 215, 0, 0.2);
                            ">
                                <div style="font-size: 80px; margin-bottom: 20px; color: #ffd700; text-shadow: 0 0 20px #ffd700; animation: pulse 2s infinite;">?</div>
                                <h2 style="color: #fff; font-size: 30px; font-weight: 900; margin: 0; text-transform: uppercase; letter-spacing: 2px;">Próximamente</h2>
                                <p style="color: #888; margin-top: 10px;">Vuelve más tarde para novedades</p>
                            </div>
                        </div>
                    </div>
                `;

                html += renderConstructionZone('MAESTRÍA DE PERSONAJES', '?');
                html += renderConstructionZone('MAESTRÍA DE FRUTAS', '?');

                html += `</div>`;
                return html;
            },

            attachCharacterListeners() {
                document.querySelectorAll('[data-role-type="character"]').forEach(card => {
                    card.addEventListener('click', () => {
                        const roleId = card.dataset.roleId;
                        const role = rolesData.characters.find(r => r.id === roleId);
                        if (role) {
                            EquipmentManager.equipRole(role);
                            this.showTab('equipped');
                        }
                    });
                });
            },

            attachClassListeners() {
                document.querySelectorAll('[data-role-type="class"]').forEach(card => {
                    card.addEventListener('click', () => {
                        const roleId = card.dataset.roleId;
                        const role = rolesData.classes.find(r => r.id === roleId);
                        if (role) {
                            UIManager.showRoleInfoPanel(role,
                                !EquipmentManager.isClassUnlocked(role.id) && (EquipmentManager.classTickets[role.id] || 0) < role.ticketsRequired,
                                EquipmentManager.classTickets[role.id] || 0,
                                !EquipmentManager.isClassUnlocked(role.id) && (EquipmentManager.classTickets[role.id] || 0) >= role.ticketsRequired,
                                EquipmentManager.isClassUnlocked(role.id)
                            );
                        }
                    });
                });

                // Master Classes listeners
                document.querySelectorAll('[data-role-type="master_class"]').forEach(card => {
                    card.addEventListener('click', () => {
                        const roleId = card.dataset.roleId;
                        const role = rolesData.masterClasses.find(r => r.id === roleId);
                        if (role) {
                            const isUnlocked = LoadoutManager.unlockedMasterClasses.includes(role.id);
                            if (isUnlocked) {
                                EquipmentManager.equipRole(role);
                                this.showTab('equipped');
                            } else {
                                alert('🔒 Debes completar la misión de maestría para desbloquear esta clase. Ve a la pestaña "Maestrías" para ver los requisitos.');
                            }
                        }
                    });
                });
            },

            // Mission Tracker Methods
            toggleMissionTracker() {
                this.missionTrackerVisible = !this.missionTrackerVisible;
                console.log(this.missionTrackerVisible ? '? Mission Tracker: ON' : '? Mission Tracker: OFF');
            },

            showMissionTracker() {
                this.missionTrackerVisible = true;
            },

            hideMissionTracker() {
                this.missionTrackerVisible = false;
            },

        };

        // ===== PLAYER SYSTEM ===== v19.11.2025
        const Player = {

            x: 550,
            y: 350,
            width: 70,
            height: 70,
            speed: 280,
            baseSpeed: 280, // NEW: Store base speed to fix permanent speed reduction bug
            currentImage: null,
            hp: 100,
            maxHp: 100,
            invulnerable: false,
            invulnerableTime: 0,
            damageBoost: 0, // Percentage damage boost
            damageBoostTime: 0,
            counterActive: false,
            counterTime: 0,
            // NEW v19.11.2025: Passive Regeneration System
            lastDamageTime: 0,
            regenDelay: 3000, // 3 seconds without damage to start regen
            regenRate: 2, // HP per second
            regenActive: false,
            // NEW v19.11.2025: Electrified Status (Storm Titan exclusive)
            electrified: false,
            electrifiedTime: 0,
            // NEW: Invisibility System (Ninja Power)
            invisible: false,
            invisibleTime: 0,
            // NEW: Heat System (Cybernetic Warlord)
            heat: 0, // 0-100
            maxHeat: 100,
            heatDecayRate: 2, // Heat per second decay (BALANCED: 5 ? 2 para hacer el sistema alcanzable)
            overheated: false,
            overheatedTime: 0,
            silenced: false,
            silencedTime: 0,
            // NEW: Level System
            level: 1,
            exp: 0,
            expToNextLevel: 100,
            baseDamage: 10, // Base damage at level 1
            damagePerLevel: 2, // Damage increase per level

            move(dx, dy) {
                const canvas = document.getElementById('game-canvas');
                const halfWidth = this.width / 2;
                const halfHeight = this.height / 2;

                this.x += dx;
                this.y += dy;

                this.x = Math.max(halfWidth, Math.min(canvas.width - halfWidth, this.x));
                this.y = Math.max(halfHeight, Math.min(canvas.height - halfHeight, this.y));

                // Update position display if element exists
                const posDisplay = document.getElementById('pos-display');
                if (posDisplay) {
                    posDisplay.textContent = `${Math.floor(this.x)}, ${Math.floor(this.y)}`;
                }
            },

            render(ctx) {
                // Apply invisibility effect
                if (this.invisible) {
                    ctx.globalAlpha = 0.3; // 30% opacity when invisible
                }

                if (this.currentImage) {
                    ctx.save();
                    ctx.shadowColor = '#00d9ff';
                    ctx.shadowBlur = 20;
                    ctx.drawImage(
                        this.currentImage,
                        this.x - this.width / 2,
                        this.y - this.height / 2,
                        this.width,
                        this.height
                    );
                    ctx.restore();
                } else {
                    // PREMIUM PLAYER MODEL
                    ctx.save();

                    const time = Date.now();
                    const pulse = 1 + Math.sin(time / 200) * 0.05;
                    const size = (this.width / 2) * pulse;

                    // 1. Outer Glow Aura
                    const aura = ctx.createRadialGradient(this.x, this.y, size * 0.5, this.x, this.y, size * 1.5);
                    aura.addColorStop(0, 'rgba(0, 217, 255, 0.2)');
                    aura.addColorStop(1, 'rgba(0, 217, 255, 0)');
                    ctx.fillStyle = aura;
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, size * 1.5, 0, Math.PI * 2);
                    ctx.fill();

                    // 2. Main Body Gradient
                    const bodyGrad = ctx.createLinearGradient(
                        this.x - size, this.y - size,
                        this.x + size, this.y + size
                    );
                    bodyGrad.addColorStop(0, '#00d9ff');
                    bodyGrad.addColorStop(0.5, '#0066cc');
                    bodyGrad.addColorStop(1, '#00d9ff');

                    ctx.fillStyle = bodyGrad;
                    ctx.shadowBlur = 20;
                    ctx.shadowColor = '#00d9ff';

                    // Main Diamond Shape
                    ctx.beginPath();
                    ctx.moveTo(this.x, this.y - size);
                    ctx.lineTo(this.x + size, this.y);
                    ctx.lineTo(this.x, this.y + size);
                    ctx.lineTo(this.x - size, this.y);
                    ctx.closePath();
                    ctx.fill();

                    // 3. Inner Core Energy
                    ctx.fillStyle = '#fff';
                    ctx.shadowBlur = 30;
                    ctx.shadowColor = '#fff';
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, size * 0.3, 0, Math.PI * 2);
                    ctx.fill();

                    // 4. Rotating Tech Rings
                    ctx.lineWidth = 2;
                    ctx.lineCap = 'round';

                    // Ring 1 (Clockwise)
                    ctx.strokeStyle = 'rgba(255, 0, 110, 0.8)';
                    ctx.shadowColor = '#ff006e';
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, size * 0.7, time / 500, time / 500 + Math.PI * 1.2);
                    ctx.stroke();

                    // Ring 2 (Counter-Clockwise)
                    ctx.strokeStyle = 'rgba(255, 190, 11, 0.8)';
                    ctx.shadowColor = '#ffbe0b';
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, size * 0.9, -time / 800, -time / 800 + Math.PI * 1.2);
                    ctx.stroke();

                    // 5. Tech Details
                    ctx.strokeStyle = 'rgba(255, 255, 255, 0.5)';
                    ctx.lineWidth = 1;
                    ctx.shadowBlur = 0;
                    ctx.beginPath();
                    ctx.moveTo(this.x - size * 1.2, this.y);
                    ctx.lineTo(this.x + size * 1.2, this.y);
                    ctx.moveTo(this.x, this.y - size * 1.2);
                    ctx.lineTo(this.x, this.y + size * 1.2);
                    ctx.stroke();

                    ctx.restore();
                }

                // Draw HP bar above player
                const barWidth = 80;
                const barHeight = 8;
                const barX = this.x - barWidth / 2;
                const barY = this.y - this.height / 2 - 20;

                ctx.fillStyle = 'rgba(0, 0, 0, 0.7)';
                ctx.fillRect(barX, barY, barWidth, barHeight);

                const hpPercent = this.hp / this.maxHp;
                const hpColor = hpPercent > 0.5 ? '#00ff00' : hpPercent > 0.25 ? '#ffff00' : '#ff0000';
                ctx.fillStyle = hpColor;
                ctx.fillRect(barX, barY, barWidth * hpPercent, barHeight);

                // HP text (FIXED v19.11.2025: Round to avoid long decimals)
                ctx.fillStyle = '#fff';
                ctx.font = 'bold 10px Arial';
                ctx.textAlign = 'center';
                ctx.fillText(`${Math.round(this.hp)}/${this.maxHp}`, this.x, barY - 5);

                // Heat bar (Cybernetic Warlord)
                if (this.heat > 0) {
                    const heatBarY = barY - 15;
                    const heatBarWidth = 80;
                    const heatBarHeight = 6;
                    const heatBarX = this.x - heatBarWidth / 2;

                    // Background
                    ctx.fillStyle = 'rgba(0, 0, 0, 0.7)';
                    ctx.fillRect(heatBarX, heatBarY, heatBarWidth, heatBarHeight);

                    // Heat fill
                    const heatPercent = this.heat / this.maxHeat;
                    let heatColor;
                    if (heatPercent >= 1.0) {
                        heatColor = '#ff0000'; // Red at 100%
                    } else if (heatPercent >= 0.5) {
                        heatColor = '#ff6600'; // Orange at 50%+
                    } else {
                        heatColor = '#00ffff'; // Cyan below 50%
                    }

                    ctx.fillStyle = heatColor;
                    ctx.fillRect(heatBarX, heatBarY, heatBarWidth * heatPercent, heatBarHeight);

                    // Heat text
                    ctx.fillStyle = '#fff';
                    ctx.font = 'bold 9px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillText(`HEAT ${Math.round(this.heat)}%`, this.x, heatBarY - 3);

                    // Warning at high heat
                    if (heatPercent >= 0.8) {
                        ctx.fillStyle = '#ff0000';
                        ctx.font = 'bold 10px Arial';
                        ctx.fillText('??', this.x + heatBarWidth / 2 + 10, heatBarY + 3);
                    }
                }

                // MECH-SUIT visual effect
                if (this.mechSuitActive) {
                    ctx.save();

                    // Armor glow
                    const armorGlow = ctx.createRadialGradient(this.x, this.y, this.width / 2, this.x, this.y, this.width / 2 + 20);
                    armorGlow.addColorStop(0, 'rgba(0, 255, 255, 0)');
                    armorGlow.addColorStop(0.7, 'rgba(0, 255, 255, 0.3)');
                    armorGlow.addColorStop(1, 'rgba(0, 255, 255, 0)');

                    ctx.fillStyle = armorGlow;
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, this.width / 2 + 20, 0, Math.PI * 2);
                    ctx.fill();

                    // Armor plates (hexagons around player)
                    for (let i = 0; i < 6; i++) {
                        const angle = (i * Math.PI / 3) + (Date.now() / 1000);
                        const plateX = this.x + Math.cos(angle) * (this.width / 2 + 15);
                        const plateY = this.y + Math.sin(angle) * (this.width / 2 + 15);

                        ctx.strokeStyle = '#00ffff';
                        ctx.lineWidth = 2;
                        ctx.shadowBlur = 10;
                        ctx.shadowColor = '#00ffff';
                        ctx.beginPath();
                        ctx.arc(plateX, plateY, 8, 0, Math.PI * 2);
                        ctx.stroke();
                    }

                    // MECH-SUIT text
                    ctx.font = 'bold 10px Arial';
                    ctx.fillStyle = '#00ffff';
                    ctx.textAlign = 'center';
                    ctx.shadowBlur = 10;
                    ctx.shadowColor = '#00ffff';
                    ctx.fillText('?? MECH-SUIT', this.x, this.y + this.height / 2 + 25);

                    ctx.restore();
                }

                // LEGIO AETERNA visual effect (Roman Legionary Ultimate)
                if (this.legioAeternaAura) {
                    ctx.save();

                    // Aura dorada radiante masiva
                    const megaPulse = 1 + Math.sin(Date.now() * 0.008) * 0.4;
                    const auraGradient = ctx.createRadialGradient(
                        this.x, this.y, 0,
                        this.x, this.y, this.legioAeternaAura.radius * megaPulse
                    );
                    auraGradient.addColorStop(0, 'rgba(255, 215, 0, 0.9)');
                    auraGradient.addColorStop(0.3, 'rgba(255, 215, 0, 0.6)');
                    auraGradient.addColorStop(0.6, 'rgba(220, 20, 60, 0.4)');
                    auraGradient.addColorStop(1, 'rgba(255, 215, 0, 0)');

                    ctx.fillStyle = auraGradient;
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, this.legioAeternaAura.radius * megaPulse, 0, Math.PI * 2);
                    ctx.fill();

                    // Capa carmesí ondeando
                    this.legioAeternaAura.capeWave += 0.1;
                    const capePoints = [];
                    const capeSegments = 12;

                    for (let i = 0; i <= capeSegments; i++) {
                        const t = i / capeSegments;
                        const angle = Math.PI + (t - 0.5) * Math.PI * 0.8;
                        const wave = Math.sin(this.legioAeternaAura.capeWave + t * Math.PI * 2) * 15;
                        const distance = 50 + wave;

                        capePoints.push({
                            x: this.x + Math.cos(angle) * distance,
                            y: this.y + Math.sin(angle) * distance + 20
                        });
                    }

                    // Dibujar capa
                    ctx.fillStyle = '#dc143c';
                    ctx.strokeStyle = '#8b0000';
                    ctx.lineWidth = 3;
                    ctx.shadowBlur = 25;
                    ctx.shadowColor = '#dc143c';

                    ctx.beginPath();
                    ctx.moveTo(this.x, this.y);
                    capePoints.forEach(point => {
                        ctx.lineTo(point.x, point.y);
                    });
                    ctx.closePath();
                    ctx.fill();
                    ctx.stroke();

                    // Símbolos romanos girando alrededor
                    const symbolCount = 12;
                    for (let i = 0; i < symbolCount; i++) {
                        const angle = (Math.PI * 2 / symbolCount) * i + (Date.now() / 600);
                        const symbolX = this.x + Math.cos(angle) * 90;
                        const symbolY = this.y + Math.sin(angle) * 90;

                        ctx.font = 'bold 28px Arial';
                        ctx.fillStyle = '#ffd700';
                        ctx.textAlign = 'center';
                        ctx.shadowBlur = 20;
                        ctx.shadowColor = '#ffd700';
                        ctx.fillText('??', symbolX, symbolY);
                    }

                    // Corona imperial sobre el jugador
                    ctx.font = 'bold 40px Arial';
                    ctx.fillStyle = '#ffd700';
                    ctx.textAlign = 'center';
                    ctx.shadowBlur = 30;
                    ctx.shadowColor = '#ffd700';
                    ctx.fillText('??', this.x, this.y - this.height / 2 - 40);

                    ctx.restore();
                }

                // THERMOPYLAE visual effect (Spartan Hoplite Ultimate)
                if (this.thermopylaeAura) {
                    ctx.save();

                    // Aura masiva roja y bronce
                    const megaPulse = 1 + Math.sin(Date.now() * 0.009) * 0.45;
                    const auraGradient = ctx.createRadialGradient(
                        this.x, this.y, 0,
                        this.x, this.y, this.thermopylaeAura.radius * megaPulse
                    );
                    auraGradient.addColorStop(0, 'rgba(139, 0, 0, 0.85)');
                    auraGradient.addColorStop(0.3, 'rgba(139, 0, 0, 0.6)');
                    auraGradient.addColorStop(0.6, 'rgba(205, 127, 50, 0.4)');
                    auraGradient.addColorStop(1, 'rgba(139, 0, 0, 0)');

                    ctx.fillStyle = auraGradient;
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, this.thermopylaeAura.radius * megaPulse, 0, Math.PI * 2);
                    ctx.fill();

                    // Capa roja ondeando
                    this.thermopylaeAura.capeWave += 0.12;
                    const capePoints = [];
                    const capeSegments = 10;

                    for (let i = 0; i <= capeSegments; i++) {
                        const t = i / capeSegments;
                        const angle = Math.PI + (t - 0.5) * Math.PI * 0.75;
                        const wave = Math.sin(this.thermopylaeAura.capeWave + t * Math.PI * 2) * 18;
                        const distance = 55 + wave;

                        capePoints.push({
                            x: this.x + Math.cos(angle) * distance,
                            y: this.y + Math.sin(angle) * distance + 25
                        });
                    }

                    // Dibujar capa
                    ctx.fillStyle = '#8B0000';
                    ctx.strokeStyle = '#CD7F32';
                    ctx.lineWidth = 4;
                    ctx.shadowBlur = 28;
                    ctx.shadowColor = '#8B0000';

                    ctx.beginPath();
                    ctx.moveTo(this.x, this.y);
                    capePoints.forEach(point => {
                        ctx.lineTo(point.x, point.y);
                    });
                    ctx.closePath();
                    ctx.fill();
                    ctx.stroke();

                    // Símbolos lambda girando
                    const symbolCount = 14;
                    for (let i = 0; i < symbolCount; i++) {
                        const angle = (Math.PI * 2 / symbolCount) * i + (Date.now() / 550);
                        const symbolX = this.x + Math.cos(angle) * 95;
                        const symbolY = this.y + Math.sin(angle) * 95;

                        ctx.font = 'bold 30px Arial';
                        ctx.fillStyle = '#CD7F32';
                        ctx.textAlign = 'center';
                        ctx.shadowBlur = 22;
                        ctx.shadowColor = '#CD7F32';
                        ctx.fillText('?', symbolX, symbolY);
                    }

                    // Casco espartano sobre el jugador
                    ctx.font = 'bold 45px Arial';
                    ctx.fillStyle = '#CD7F32';
                    ctx.textAlign = 'center';
                    ctx.shadowBlur = 35;
                    ctx.shadowColor = '#CD7F32';
                    ctx.fillText('??', this.x, this.y - this.height / 2 - 45);

                    ctx.restore();
                }

                // ARES BLESSING visual effect (Spartan Hoplite)
                if (this.aresBlessing && this.aresSymbol) {
                    ctx.save();

                    // Aura de fuego rojo intenso
                    const megaPulse = 1 + Math.sin(Date.now() * 0.01) * 0.4;
                    const fireGradient = ctx.createRadialGradient(
                        this.x, this.y, 0,
                        this.x, this.y, 90 * megaPulse
                    );
                    fireGradient.addColorStop(0, 'rgba(139, 0, 0, 0.7)');
                    fireGradient.addColorStop(0.4, 'rgba(255, 69, 0, 0.5)');
                    fireGradient.addColorStop(0.7, 'rgba(205, 127, 50, 0.3)');
                    fireGradient.addColorStop(1, 'rgba(139, 0, 0, 0)');

                    ctx.fillStyle = fireGradient;
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, 90 * megaPulse, 0, Math.PI * 2);
                    ctx.fill();

                    // Símbolo de Ares girando (espadas cruzadas)
                    this.aresSymbol.rotation += 0.02;

                    ctx.save();
                    ctx.translate(this.x, this.y - this.height / 2 - 50);
                    ctx.rotate(this.aresSymbol.rotation);

                    // Espadas cruzadas
                    ctx.font = 'bold 40px Arial';
                    ctx.fillStyle = '#8B0000';
                    ctx.textAlign = 'center';
                    ctx.shadowBlur = 25;
                    ctx.shadowColor = '#8B0000';
                    ctx.fillText('??', -15, 0);
                    ctx.fillText('??', 15, 0);

                    ctx.restore();

                    // Llamas alrededor del jugador
                    const flameCount = 12;
                    for (let i = 0; i < flameCount; i++) {
                        const angle = (Math.PI * 2 / flameCount) * i + (Date.now() / 400);
                        const flameX = this.x + Math.cos(angle) * 60;
                        const flameY = this.y + Math.sin(angle) * 60;

                        ctx.font = 'bold 20px Arial';
                        ctx.fillStyle = '#FF4500';
                        ctx.textAlign = 'center';
                        ctx.shadowBlur = 15;
                        ctx.shadowColor = '#FF4500';
                        ctx.fillText('??', flameX, flameY);
                    }

                    // Texto de bendición
                    ctx.font = 'bold 14px Orbitron';
                    ctx.fillStyle = '#8B0000';
                    ctx.textAlign = 'center';
                    ctx.shadowBlur = 20;
                    ctx.shadowColor = '#8B0000';
                    ctx.fillText('?? ARES ??', this.x, this.y + this.height / 2 + 30);

                    ctx.font = 'bold 10px Arial';
                    ctx.fillStyle = '#FF4500';
                    ctx.fillText('x2 DMG | 20% LIFESTEAL', this.x, this.y + this.height / 2 + 45);

                    ctx.restore();
                }

                // AROO AURA visual effect (Spartan Hoplite)
                if (this.arooAura && (Date.now() - this.arooAura.startTime < this.arooAura.duration)) {
                    ctx.save();

                    // Aura roja espartana intensa
                    const pulse = 1 + Math.sin(Date.now() * 0.006) * 0.35;
                    const auraGradient = ctx.createRadialGradient(
                        this.x, this.y, 0,
                        this.x, this.y, this.arooAura.radius * pulse
                    );
                    auraGradient.addColorStop(0, 'rgba(139, 0, 0, 0.5)');
                    auraGradient.addColorStop(0.5, 'rgba(205, 127, 50, 0.35)');
                    auraGradient.addColorStop(1, 'rgba(139, 0, 0, 0)');

                    ctx.fillStyle = auraGradient;
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, this.arooAura.radius * pulse, 0, Math.PI * 2);
                    ctx.fill();

                    // Lanzas girando alrededor del jugador
                    const spearCount = 8;
                    for (let i = 0; i < spearCount; i++) {
                        const angle = (Math.PI * 2 / spearCount) * i + (Date.now() / 700);
                        const spearX = this.x + Math.cos(angle) * 55;
                        const spearY = this.y + Math.sin(angle) * 55;

                        ctx.font = 'bold 22px Arial';
                        ctx.fillStyle = '#CD7F32';
                        ctx.textAlign = 'center';
                        ctx.shadowBlur = 18;
                        ctx.shadowColor = '#CD7F32';
                        ctx.fillText('???', spearX, spearY);
                    }

                    // Texto de buff
                    ctx.font = 'bold 12px Orbitron';
                    ctx.fillStyle = '#8B0000';
                    ctx.textAlign = 'center';
                    ctx.shadowBlur = 18;
                    ctx.shadowColor = '#8B0000';
                    ctx.fillText('?? AROO!', this.x, this.y + this.height / 2 + 30);

                    ctx.font = 'bold 10px Arial';
                    ctx.fillStyle = '#CD7F32';
                    ctx.fillText('+60% DMG +40% RES', this.x, this.y + this.height / 2 + 45);

                    ctx.restore();
                } else if (this.arooAura) {
                    this.arooAura = null;
                }

                // CENTURION AURA visual effect (Roman Legionary)
                if (this.centurionAura && (Date.now() - this.centurionAura.startTime < this.centurionAura.duration)) {
                    ctx.save();

                    // Aura carmesí pulsante de poder
                    const pulse = 1 + Math.sin(Date.now() * 0.005) * 0.3;
                    const auraGradient = ctx.createRadialGradient(
                        this.x, this.y, 0,
                        this.x, this.y, this.centurionAura.radius * pulse
                    );
                    auraGradient.addColorStop(0, 'rgba(220, 20, 60, 0.4)');
                    auraGradient.addColorStop(0.5, 'rgba(255, 215, 0, 0.3)');
                    auraGradient.addColorStop(1, 'rgba(220, 20, 60, 0)');

                    ctx.fillStyle = auraGradient;
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, this.centurionAura.radius * pulse, 0, Math.PI * 2);
                    ctx.fill();

                    // Espadas girando alrededor del jugador
                    const swordCount = 6;
                    for (let i = 0; i < swordCount; i++) {
                        const angle = (Math.PI * 2 / swordCount) * i + (Date.now() / 800);
                        const swordX = this.x + Math.cos(angle) * 50;
                        const swordY = this.y + Math.sin(angle) * 50;

                        ctx.font = 'bold 20px Arial';
                        ctx.fillStyle = '#ffd700';
                        ctx.textAlign = 'center';
                        ctx.shadowBlur = 15;
                        ctx.shadowColor = '#ffd700';
                        ctx.fillText('??', swordX, swordY);
                    }

                    // Texto de buff
                    ctx.font = 'bold 12px Orbitron';
                    ctx.fillStyle = '#dc143c';
                    ctx.textAlign = 'center';
                    ctx.shadowBlur = 15;
                    ctx.shadowColor = '#dc143c';
                    ctx.fillText('?? CENTURIÓN', this.x, this.y + this.height / 2 + 30);

                    ctx.font = 'bold 10px Arial';
                    ctx.fillStyle = '#ffd700';
                    ctx.fillText('+50% DMG', this.x, this.y + this.height / 2 + 45);

                    ctx.restore();
                } else if (this.centurionAura) {
                    // Limpiar aura cuando expire
                    this.centurionAura = null;
                }

                // TESTUDO FORMATION visual effect (Roman Legionary)
                if (this.testudoActive && this.testudoShields) {
                    ctx.save();

                    // Aura dorada pulsante
                    const pulse = 1 + Math.sin(Date.now() * this.testudoAura.pulseSpeed) * 0.2;
                    const auraGradient = ctx.createRadialGradient(
                        this.x, this.y, 0,
                        this.x, this.y, this.testudoAura.radius * pulse
                    );
                    auraGradient.addColorStop(0, 'rgba(255, 215, 0, 0.3)');
                    auraGradient.addColorStop(0.5, 'rgba(220, 20, 60, 0.2)');
                    auraGradient.addColorStop(1, 'rgba(255, 215, 0, 0)');

                    ctx.fillStyle = auraGradient;
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, this.testudoAura.radius * pulse, 0, Math.PI * 2);
                    ctx.fill();

                    // Escudos romanos girando alrededor del jugador
                    this.testudoShields.forEach((shield, index) => {
                        const rotationSpeed = 0.002;
                        shield.angle += rotationSpeed;

                        const shieldX = this.x + Math.cos(shield.angle) * shield.distance;
                        const shieldY = this.y + Math.sin(shield.angle) * shield.distance;

                        // Escudo con borde dorado
                        ctx.strokeStyle = '#ffd700';
                        ctx.fillStyle = '#dc143c';
                        ctx.lineWidth = 3;
                        ctx.shadowBlur = 15;
                        ctx.shadowColor = '#ffd700';

                        // Forma de escudo (rectángulo redondeado)
                        const shieldWidth = 20;
                        const shieldHeight = 28;
                        ctx.beginPath();
                        ctx.roundRect(
                            shieldX - shieldWidth / 2,
                            shieldY - shieldHeight / 2,
                            shieldWidth,
                            shieldHeight,
                            4
                        );
                        ctx.fill();
                        ctx.stroke();

                        // Símbolo romano en el escudo
                        ctx.font = 'bold 14px Arial';
                        ctx.fillStyle = '#ffd700';
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';
                        ctx.shadowBlur = 5;
                        ctx.fillText('??', shieldX, shieldY);
                    });

                    // Texto TESTUDO
                    ctx.font = 'bold 12px Orbitron';
                    ctx.fillStyle = '#ffd700';
                    ctx.textAlign = 'center';
                    ctx.shadowBlur = 15;
                    ctx.shadowColor = '#ffd700';
                    ctx.fillText('??? TESTUDO', this.x, this.y + this.height / 2 + 30);

                    // Mostrar reducción de daño
                    ctx.font = 'bold 10px Arial';
                    ctx.fillStyle = '#dc143c';
                    ctx.fillText('-70% DMG', this.x, this.y + this.height / 2 + 45);

                    ctx.restore();
                }

                // PHALANX FORMATION visual effect (Spartan Hoplite)
                if (this.phalanxActive && this.phalanxShields) {
                    ctx.save();

                    // Aura roja espartana pulsante
                    const pulse = 1 + Math.sin(Date.now() * this.phalanxAura.pulseSpeed) * 0.25;
                    const auraGradient = ctx.createRadialGradient(
                        this.x, this.y, 0,
                        this.x, this.y, this.phalanxAura.radius * pulse
                    );
                    auraGradient.addColorStop(0, 'rgba(139, 0, 0, 0.4)');
                    auraGradient.addColorStop(0.5, 'rgba(205, 127, 50, 0.25)');
                    auraGradient.addColorStop(1, 'rgba(139, 0, 0, 0)');

                    ctx.fillStyle = auraGradient;
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, this.phalanxAura.radius * pulse, 0, Math.PI * 2);
                    ctx.fill();

                    // Escudos hoplon girando alrededor del jugador
                    this.phalanxShields.forEach((shield, index) => {
                        const rotationSpeed = 0.0025;
                        shield.angle += rotationSpeed;

                        const shieldX = this.x + Math.cos(shield.angle) * shield.distance;
                        const shieldY = this.y + Math.sin(shield.angle) * shield.distance;

                        // Escudo hoplon con borde de bronce
                        ctx.strokeStyle = '#CD7F32';
                        ctx.fillStyle = '#8B0000';
                        ctx.lineWidth = 3;
                        ctx.shadowBlur = 18;
                        ctx.shadowColor = '#CD7F32';

                        // Forma de escudo circular (hoplon)
                        ctx.beginPath();
                        ctx.arc(shieldX, shieldY, 15, 0, Math.PI * 2);
                        ctx.fill();
                        ctx.stroke();

                        // Lambda espartana en el escudo (?)
                        ctx.font = 'bold 16px Arial';
                        ctx.fillStyle = '#CD7F32';
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';
                        ctx.shadowBlur = 8;
                        ctx.fillText('?', shieldX, shieldY);
                    });

                    // Texto FALANGE
                    ctx.font = 'bold 12px Orbitron';
                    ctx.fillStyle = '#8B0000';
                    ctx.textAlign = 'center';
                    ctx.shadowBlur = 18;
                    ctx.shadowColor = '#8B0000';
                    ctx.fillText('??? FALANGE', this.x, this.y + this.height / 2 + 30);

                    // Mostrar reducción de daño
                    ctx.font = 'bold 10px Arial';
                    ctx.fillStyle = '#CD7F32';
                    ctx.fillText('-75% DMG', this.x, this.y + this.height / 2 + 45);

                    ctx.restore();
                }

                // Silenced effect
                if (this.silenced) {
                    ctx.save();
                    ctx.font = 'bold 20px Arial';
                    ctx.fillStyle = '#ff0000';
                    ctx.textAlign = 'center';
                    ctx.shadowBlur = 10;
                    ctx.shadowColor = '#ff0000';
                    ctx.fillText('??', this.x, this.y - this.height / 2 - 35);
                    ctx.restore();
                }

                // NEW v19.11.2025: Electrified visual effect (sparks around player only)
                if (this.electrified) {
                    // Electric sparks around player
                    const sparkCount = 4;
                    for (let i = 0; i < sparkCount; i++) {
                        const angle = (Date.now() / 100 + i * Math.PI / 2) % (Math.PI * 2);
                        const sparkX = this.x + Math.cos(angle) * 40;
                        const sparkY = this.y + Math.sin(angle) * 40;
                        ctx.font = '24px Arial';
                        ctx.fillStyle = '#ffff00';
                        ctx.shadowBlur = 15;
                        ctx.shadowColor = '#ffff00';
                        ctx.fillText('?', sparkX, sparkY);
                        ctx.shadowBlur = 0;
                    }
                }

                // Invulnerability flash
                if (this.invulnerable && Math.floor(Date.now() / 100) % 2 === 0) {
                    ctx.globalAlpha = 0.5;
                }
                ctx.globalAlpha = 1;
            },

            // Level System Functions
            gainExp(amount, isCustomRaid = false) {
                // Reduce EXP in custom raids by 50%
                if (isCustomRaid) {
                    amount = Math.floor(amount * 0.5);
                }

                this.exp += amount;

                // Show EXP gain notification
                this.showExpGain(amount);

                // Check for level up
                while (this.exp >= this.expToNextLevel) {
                    this.levelUp();
                }

                // Save progress
                EquipmentManager.saveProgress();
            },

            levelUp() {
                this.exp -= this.expToNextLevel;
                this.level++;

                // Calculate new stats
                const oldMaxHp = this.maxHp;
                this.maxHp = 100 + (this.level - 1) * 10; // +10 HP per level

                // Heal to full on level up
                this.hp = this.maxHp;

                // Update EXP requirement (exponential growth)
                this.expToNextLevel = Math.floor(100 * Math.pow(1.15, this.level - 1));

                // Show level up notification
                this.showLevelUp();

                console.log(`?? LEVEL UP! Level ${this.level} | HP: ${this.maxHp} | Next: ${this.expToNextLevel} EXP`);
            },

            getCurrentDamage() {
                // Base damage + level scaling
                return this.baseDamage + (this.level - 1) * this.damagePerLevel;
            },

            showExpGain(amount) {
                const popup = document.createElement('div');
                popup.style.cssText = `
                    position: fixed;
                    top: 25%;
                    right: 50px;
                    background: linear-gradient(135deg, #00d9ff, #00ff88);
                    color: white;
                    padding: 8px 16px;
                    border-radius: 8px;
                    font-size: 14px;
                    font-weight: 700;
                    z-index: 5000;
                    pointer-events: none;
                    animation: slideInRight 0.5s ease-out, fadeOut 0.5s ease-out 1.5s forwards;
                    font-family: 'Orbitron', sans-serif;
                    border: 2px solid #00ff88;
                    box-shadow: 0 0 15px rgba(0, 255, 136, 0.5);
                `;
                popup.textContent = `+${amount} EXP`;
                document.body.appendChild(popup);

                setTimeout(() => popup.remove(), 2000);
            },

            showLevelUp() {
                const popup = document.createElement('div');
                popup.style.cssText = `
                    position: fixed;
                    top: 50%;
                    left: 50%;
                    transform: translate(-50%, -50%);
                    background: linear-gradient(135deg, #ffd700, #ffbe0b);
                    color: #000;
                    padding: 20px 40px;
                    border-radius: 15px;
                    font-size: 32px;
                    font-weight: 900;
                    z-index: 6000;
                    pointer-events: none;
                    animation: scaleIn 0.5s ease-out, fadeOut 0.5s ease-out 2s forwards;
                    font-family: 'Orbitron', sans-serif;
                    border: 4px solid #ffd700;
                    box-shadow: 0 0 40px rgba(255, 215, 0, 0.8);
                    text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
                `;
                popup.innerHTML = `?? LEVEL ${this.level}! ??`;
                document.body.appendChild(popup);

                setTimeout(() => popup.remove(), 2500);
            },

            takeDamage(damage, attackerId = null) {
                if (this.invulnerable) return;

                // Counter attack if active
                if (this.counterActive && attackerId && MobRaidSystem.active) {
                    this.counterActive = false;
                    MobRaidSystem.damageMob(attackerId, damage * 2);
                    console.log('? Counter! Reflected', damage * 2, 'damage!');
                    return;
                }

                // Apply Curse effect (double damage)
                if (this.cursed && Date.now() < this.curseEndTime) {
                    damage *= 2;
                    console.log('?? íMALDICIÓN! Daño duplicado:', damage);
                } else if (this.cursed && Date.now() >= this.curseEndTime) {
                    // Remove curse if expired
                    this.cursed = false;
                    this.curseStacks = 0;
                    console.log('?? Maldición expirada');
                }

                this.hp = Math.max(0, this.hp - damage);
                this.invulnerable = true;
                this.invulnerableTime = 1000; // 1 second invulnerability

                // NEW v19.11.2025: Reset regeneration timer
                this.lastDamageTime = Date.now();
                this.regenActive = false;

                console.log('?? Player took', damage, 'damage! HP:', this.hp);

                if (this.hp <= 0) {
                    console.log('?? Player died!');

                    // Reset Abyssal Shadowlord passive stacks on death
                    if (this.shadowEssenceStacks) {
                        this.shadowEssenceStacks = 0;
                        this.critBoost = 0;
                        console.log('? Abismo Letal stacks reset on death');
                    }

                    MobRaidSystem.stopRaid(true); // Pass true to indicate player died
                }
            },

            update(deltaTime) {
                if (this.invulnerable) {
                    this.invulnerableTime -= deltaTime;
                    if (this.invulnerableTime <= 0) {
                        this.invulnerable = false;
                    }
                }

                // NEW: Invisibility system
                if (this.invisible) {
                    this.invisibleTime -= deltaTime;
                    if (this.invisibleTime <= 0) {
                        this.invisible = false;
                        // Restore normal speed
                        this.speed = this.baseSpeed;
                        console.log('?? Invisibility ended! Speed restored.');
                    }
                }

                // NEW: Heat System decay (Cybernetic Warlord)
                if (this.heat > 0 && !this.overheated) {
                    this.heat = Math.max(0, this.heat - (this.heatDecayRate * deltaTime / 1000));
                }

                // Silenced timer
                if (this.silenced) {
                    this.silencedTime -= deltaTime;
                    if (this.silencedTime <= 0) {
                        this.silenced = false;
                    }
                }

                if (this.damageBoost > 0) {
                    this.damageBoostTime -= deltaTime;
                    if (this.damageBoostTime <= 0) {
                        this.damageBoost = 0;
                    }
                }

                if (this.counterActive) {
                    this.counterTime -= deltaTime;
                    if (this.counterTime <= 0) {
                        this.counterActive = false;
                        console.log('??? Counter stance expired');
                    }
                }

                // NEW v19.11.2025: Passive Regeneration System
                const timeSinceLastDamage = Date.now() - this.lastDamageTime;
                if (this.hp < this.maxHp && timeSinceLastDamage >= this.regenDelay) {
                    if (!this.regenActive) {
                        this.regenActive = true;
                        console.log('?? Passive regeneration activated!');
                    }

                    const regenAmount = (this.regenRate * deltaTime) / 1000;
                    this.hp = Math.min(this.maxHp, this.hp + regenAmount);
                }

                // NEW v19.11.2025: Electrified Status (stun effect)
                if (this.electrified) {
                    this.electrifiedTime -= deltaTime;
                    if (this.electrifiedTime <= 0) {
                        this.electrified = false;
                        console.log('? Electrified effect ended - movement restored!');
                    }
                }

                // NEW v19.11.2025: Fix permanent speed reduction bug
                // Reset speed to base if no active slow effects
                if (this.speed < this.baseSpeed && !this.hasActiveSlowEffect && !this.electrified) {
                    this.speed = this.baseSpeed;
                }
            },

            applyDamageBoost(percentage, duration) {
                this.damageBoost = percentage;
                this.damageBoostTime = duration;
                console.log(`?? Damage boost: +${percentage}% for ${duration / 1000}s`);
            }
        };

        // ===== INPUT HANDLER =====
        const InputHandler = {
            keysPressed: new Set(),

            handleKeyDown(event) {
                this.keysPressed.add(event.key.toLowerCase());
            },

            handleKeyUp(event) {
                this.keysPressed.delete(event.key.toLowerCase());
            },

            processMovement(deltaTime) {
                // Prevent movement when game is paused
                if (MobRaidSystem.paused) {
                    return; // Cannot move while paused
                }

                // NEW v19.11.2025: Cannot move while electrified (stunned)
                if (Player.electrified) {
                    return; // Stunned, no movement allowed
                }

                let dx = 0, dy = 0;

                if (this.keysPressed.has('w') || this.keysPressed.has('arrowup')) dy -= 1;
                if (this.keysPressed.has('s') || this.keysPressed.has('arrowdown')) dy += 1;
                if (this.keysPressed.has('a') || this.keysPressed.has('arrowleft')) dx -= 1;
                if (this.keysPressed.has('d') || this.keysPressed.has('arrowright')) dx += 1;

                if (dx !== 0 && dy !== 0) {
                    const length = Math.sqrt(dx * dx + dy * dy);
                    dx /= length;
                    dy /= length;
                }

                if (dx !== 0 || dy !== 0) {
                    // Apply class speed multiplier
                    let speed = Player.speed;
                    if (EquipmentManager.equippedRole && EquipmentManager.equippedRole.type === 'class') {
                        const classId = EquipmentManager.equippedRole.id;
                        const speedMultiplier = ClassProgressionSystem.getSpeedMultiplier(classId);
                        speed *= speedMultiplier;
                    }

                    Player.move(dx * speed * deltaTime, dy * speed * deltaTime);
                }
            },

            processAbilityInputs() {
                const abilities = EquipmentManager.getAllAbilities();
                const abilityKeys = ['q', 'w', 'e', 't', 'a', 's', 'r', 'f', 'd'];

                abilityKeys.forEach(key => {
                    if (this.keysPressed.has(key)) {
                        const ability = abilities.find(a => a.keyBinding === key);
                        if (ability) {
                            AbilityManager.activateAbility(ability.id);
                            this.keysPressed.delete(key);
                        }
                    }
                });
            }
        };

        window.addEventListener('keydown', (e) => {
            InputHandler.handleKeyDown(e);

            // Z key to pause/unpause raid
            if (e.key.toLowerCase() === 'z' && MobRaidSystem.active) {
                MobRaidSystem.paused = !MobRaidSystem.paused;
                console.log(MobRaidSystem.paused ? '?? PAUSED' : '?? RESUMED');
            }

            // M key to toggle mission tracker
            if (e.key.toLowerCase() === 'm') {
                LoadoutManager.toggleMissionTracker();
            }

            // P key to toggle practice mode control panel
            if (e.key.toLowerCase() === 'p' && PracticeModeManager.active) {
                PracticeModeManager.controlPanel.collapsed = !PracticeModeManager.controlPanel.collapsed;
                console.log(PracticeModeManager.controlPanel.collapsed ? '?? Panel colapsado' : '?? Panel expandido');
            }
        });
        window.addEventListener('keyup', (e) => InputHandler.handleKeyUp(e));

        // ===== EFFECT RENDERER =====
        const EffectRenderer = {
            activeEffects: [],
            effectDefinitions: {
                // Character effects
                effect_claw: { type: 'particle', duration: 600, color: '#ff6b6b', size: 28, count: 18 },
                effect_roar: { type: 'particle', duration: 800, color: '#ffd700', size: 35, count: 30 },
                effect_apex: { type: 'particle', duration: 2000, color: '#ff0000', size: 65, count: 55 },
                effect_star_beam: { type: 'particle', duration: 700, color: '#00d9ff', size: 25, count: 20 },
                effect_cosmic_shield: { type: 'particle', duration: 1200, color: '#9b59b6', size: 40, count: 35 },
                effect_supernova: { type: 'particle', duration: 2200, color: '#ffbe0b', size: 70, count: 70 },
                effect_shadow_slash: { type: 'particle', duration: 650, color: '#4a4a4a', size: 30, count: 22 },
                effect_dash: { type: 'particle', duration: 500, color: '#00bfff', size: 25, count: 18 },
                effect_blade_storm: { type: 'particle', duration: 1800, color: '#c0c0c0', size: 50, count: 60 },
                effect_flame_wing: { type: 'particle', duration: 750, color: '#ff4500', size: 32, count: 25 },
                effect_rebirth: { type: 'particle', duration: 1500, color: '#00ff88', size: 35, count: 40 },
                effect_phoenix_rise: { type: 'particle', duration: 2500, color: '#ff6600', size: 75, count: 80 },
                effect_smash: { type: 'particle', duration: 800, color: '#8b4513', size: 40, count: 30 },
                effect_wall: { type: 'particle', duration: 1000, color: '#808080', size: 45, count: 35 },
                effect_titan_wrath: { type: 'particle', duration: 2400, color: '#ffd700', size: 70, count: 65 },

                // Class effects
                effect_shuriken: { type: 'particle', duration: 500, color: '#c0c0c0', size: 18, count: 15 },
                effect_smoke: { type: 'particle', duration: 1000, color: '#696969', size: 40, count: 35 },
                effect_clone: { type: 'particle', duration: 1500, color: '#4169e1', size: 50, count: 40 },
                effect_iaido: { type: 'particle', duration: 600, color: '#ff1493', size: 30, count: 20 },
                effect_parry: { type: 'particle', duration: 800, color: '#ffd700', size: 35, count: 25 },
                effect_thousand: { type: 'particle', duration: 1800, color: '#ffb6c1', size: 45, count: 65 },
                effect_elem_bolt: { type: 'particle', duration: 700, color: '#00bfff', size: 25, count: 18 },
                effect_barrier: { type: 'particle', duration: 1200, color: '#9370db', size: 40, count: 35 },
                effect_fury: { type: 'particle', duration: 2000, color: '#ff6347', size: 60, count: 55 },
                effect_rage: { type: 'particle', duration: 700, color: '#dc143c', size: 32, count: 22 },
                effect_leap: { type: 'particle', duration: 800, color: '#ff8c00', size: 35, count: 28 },
                effect_frenzy: { type: 'particle', duration: 1700, color: '#8b0000', size: 55, count: 60 },
                effect_orb: { type: 'particle', duration: 650, color: '#4169e1', size: 25, count: 18 },
                effect_heal_aura: { type: 'particle', duration: 1500, color: '#32cd32', size: 38, count: 40 },
                effect_arcane_storm: { type: 'particle', duration: 1900, color: '#9400d3', size: 60, count: 65 },
                effect_rapid: { type: 'particle', duration: 550, color: '#ff4500', size: 20, count: 25 },
                effect_grenade: { type: 'particle', duration: 900, color: '#ff6347', size: 35, count: 30 },
                effect_orbital: { type: 'particle', duration: 1600, color: '#00ced1', size: 65, count: 70 },

                // Guardian Ancestral effects - Custom implementations
                effect_quake: { type: 'custom_quake', duration: 2000, color: '#8B7355', size: 45, count: 80 },
                effect_pillar: { type: 'custom_pillar', duration: 1800, color: '#A0826D', size: 50, count: 60 },
                effect_armor: { type: 'custom_armor', duration: 1500, color: '#CD853F', size: 40, count: 55 },
                effect_spikes: { type: 'custom_spikes', duration: 1200, color: '#8B4513', size: 35, count: 50 },
                effect_colossus: { type: 'custom_colossus', duration: 2500, color: '#8B7355', size: 70, count: 90 },
                effect_cataclysm: { type: 'custom_cataclysm', duration: 3000, color: '#DAA520', size: 85, count: 120 },

                // Anubis effects - Custom Egyptian themed implementations
                effect_judgment: { type: 'custom_judgment', duration: 1800, color: '#FFD700', size: 40, count: 60 },
                effect_sandstorm: { type: 'custom_sandstorm', duration: 2200, color: '#DEB887', size: 50, count: 80 },
                effect_jackal: { type: 'custom_jackal', duration: 2000, color: '#FFD700', size: 45, count: 70 },
                effect_ankh: { type: 'custom_ankh', duration: 2500, color: '#00CED1', size: 55, count: 75 },
                effect_plague: { type: 'custom_plague', duration: 3500, color: '#228B22', size: 70, count: 100 },
                effect_underworld: { type: 'custom_underworld', duration: 4000, color: '#000000', size: 90, count: 150 },

                // Fruit effects
                effect_fire_blast: { type: 'particle', duration: 700, color: '#ff4500', size: 30, count: 22 },
                effect_flame_wall: { type: 'particle', duration: 1000, color: '#ff6600', size: 42, count: 38 },
                effect_inferno_nova: { type: 'particle', duration: 1500, color: '#ff0000', size: 65, count: 60 },
                effect_ice_shard: { type: 'particle', duration: 600, color: '#00ffff', size: 22, count: 20 },
                effect_freeze: { type: 'particle', duration: 1100, color: '#87ceeb', size: 38, count: 35 },
                effect_winter: { type: 'particle', duration: 1800, color: '#b0e0e6', size: 60, count: 65 },
                effect_lightning: { type: 'particle', duration: 500, color: '#ffff00', size: 28, count: 18 },
                effect_thunder_field: { type: 'particle', duration: 1000, color: '#ffd700', size: 42, count: 45 },
                effect_tempest: { type: 'particle', duration: 1600, color: '#ffff00', size: 65, count: 70 },
                effect_void_hole: { type: 'particle', duration: 800, color: '#000000', size: 38, count: 30 },
                effect_gravity: { type: 'particle', duration: 900, color: '#4b0082', size: 35, count: 35 },
                effect_singularity: { type: 'particle', duration: 1700, color: '#000000', size: 60, count: 60 },
                effect_light_beam: { type: 'particle', duration: 500, color: '#ffffff', size: 25, count: 20 },
                effect_light_speed: { type: 'particle', duration: 1200, color: '#ffffe0', size: 42, count: 40 },
                effect_solar: { type: 'particle', duration: 1400, color: '#fffacd', size: 55, count: 50 },
                effect_vine: { type: 'particle', duration: 700, color: '#228b22', size: 28, count: 22 },
                effect_growth: { type: 'particle', duration: 1100, color: '#32cd32', size: 40, count: 38 },
                effect_forest: { type: 'particle', duration: 1900, color: '#006400', size: 60, count: 65 }
            },

            playEffect(effectId, x, y) {
                const effectDef = this.effectDefinitions[effectId];
                if (!effectDef) return;

                const effect = {
                    id: effectId,
                    x: x,
                    y: y,
                    startTime: Date.now(),
                    duration: effectDef.duration,
                    type: effectDef.type,
                    color: effectDef.color,
                    size: effectDef.size,
                    particles: [],
                    customData: {}
                };

                if (effectDef.type === 'particle') {
                    for (let i = 0; i < effectDef.count; i++) {
                        const angle = (Math.PI * 2 * i) / effectDef.count;
                        const speed = 90 + Math.random() * 140;
                        effect.particles.push({
                            x: x,
                            y: y,
                            vx: Math.cos(angle) * speed,
                            vy: Math.sin(angle) * speed,
                            size: effectDef.size * (0.6 + Math.random() * 0.4),
                            life: 1.0
                        });
                    }
                }
                // Custom Guardian Ancestral effects
                else if (effectDef.type === 'custom_quake') {
                    // 3 ondas sísmicas expansivas
                    effect.customData.waves = [
                        { radius: 0, maxRadius: 150, delay: 0, active: true },
                        { radius: 0, maxRadius: 250, delay: 400, active: false },
                        { radius: 0, maxRadius: 350, delay: 800, active: false }
                    ];
                    // Grietas doradas
                    effect.customData.cracks = [];
                    for (let i = 0; i < 12; i++) {
                        const angle = (Math.PI * 2 / 12) * i;
                        effect.customData.cracks.push({
                            angle: angle,
                            length: 0,
                            maxLength: 100 + Math.random() * 80
                        });
                    }
                }
                else if (effectDef.type === 'custom_pillar') {
                    // 8 pilares en formación octagonal
                    effect.customData.pillars = [];
                    for (let i = 0; i < 8; i++) {
                        const angle = (Math.PI * 2 / 8) * i;
                        effect.customData.pillars.push({
                            angle: angle,
                            distance: 180,
                            height: 0,
                            maxHeight: 80,
                            rotation: 0
                        });
                    }
                }
                else if (effectDef.type === 'custom_armor') {
                    // Armadura de roca con capas
                    effect.customData.layers = [];
                    for (let i = 0; i < 5; i++) {
                        effect.customData.layers.push({
                            radius: 40 + i * 15,
                            alpha: 0,
                            rotation: Math.random() * Math.PI * 2
                        });
                    }
                    // Fragmentos orbitantes
                    effect.customData.fragments = [];
                    for (let i = 0; i < 16; i++) {
                        effect.customData.fragments.push({
                            angle: (Math.PI * 2 / 16) * i,
                            distance: 60,
                            size: 8 + Math.random() * 6
                        });
                    }
                }
                else if (effectDef.type === 'custom_spikes') {
                    // 3 líneas de pinchos
                    effect.customData.lines = [];
                    for (let line = 0; line < 3; line++) {
                        const baseAngle = -Math.PI / 4 + (line * Math.PI / 4);
                        const spikes = [];
                        for (let i = 0; i < 12; i++) {
                            spikes.push({
                                distance: 50 * (i + 1),
                                height: 0,
                                maxHeight: 40,
                                delay: i * 50
                            });
                        }
                        effect.customData.lines.push({
                            angle: baseAngle,
                            spikes: spikes
                        });
                    }
                }
                else if (effectDef.type === 'custom_colossus') {
                    // Transformación Épica con aura
                    effect.customData.auraRings = [];
                    for (let i = 0; i < 4; i++) {
                        effect.customData.auraRings.push({
                            radius: 0,
                            maxRadius: 80 + i * 40,
                            delay: i * 200,
                            active: false
                        });
                    }
                    // Runas flotantes
                    effect.customData.runes = [];
                    for (let i = 0; i < 8; i++) {
                        effect.customData.runes.push({
                            angle: (Math.PI * 2 / 8) * i,
                            distance: 100,
                            yOffset: 0,
                            size: 20
                        });
                    }
                }
                else if (effectDef.type === 'custom_cataclysm') {
                    // Ultimate devastador
                    effect.customData.groundCracks = [];
                    for (let i = 0; i < 20; i++) {
                        const angle = (Math.PI * 2 / 20) * i;
                        effect.customData.groundCracks.push({
                            angle: angle,
                            length: 0,
                            maxLength: 200 + Math.random() * 150
                        });
                    }
                    // Pilares de luz
                    effect.customData.lightPillars = [];
                    for (let i = 0; i < 8; i++) {
                        effect.customData.lightPillars.push({
                            x: x + (Math.random() - 0.5) * 400,
                            y: y + (Math.random() - 0.5) * 400,
                            height: 0,
                            maxHeight: 300,
                            delay: i * 250,
                            active: false
                        });
                    }
                    // Explosión central
                    effect.customData.centralExplosion = {
                        radius: 0,
                        maxRadius: 600
                    };
                }
                // Custom Anubis effects
                else if (effectDef.type === 'custom_judgment') {
                    // 3 proyectiles de energía dorada que persiguen
                    effect.customData.projectiles = [];
                    for (let i = 0; i < 3; i++) {
                        const angle = (Math.PI * 2 / 3) * i;
                        effect.customData.projectiles.push({
                            x: x,
                            y: y,
                            angle: angle,
                            speed: 200,
                            size: 25,
                            trail: []
                        });
                    }
                    // Balanza sagrada en el centro
                    effect.customData.scale = {
                        rotation: 0,
                        size: 60,
                        glow: 0
                    };
                }
                else if (effectDef.type === 'custom_sandstorm') {
                    // Tormenta de arena circular
                    effect.customData.sandParticles = [];
                    for (let i = 0; i < 100; i++) {
                        const angle = Math.random() * Math.PI * 2;
                        const distance = Math.random() * 300;
                        effect.customData.sandParticles.push({
                            angle: angle,
                            distance: distance,
                            speed: 0.05 + Math.random() * 0.05,
                            size: 3 + Math.random() * 5,
                            alpha: 0.3 + Math.random() * 0.4
                        });
                    }
                    effect.customData.radius = 0;
                    effect.customData.maxRadius = 300;
                }
                else if (effectDef.type === 'custom_jackal') {
                    // Transformación en chacal dorado
                    effect.customData.aura = {
                        radius: 0,
                        maxRadius: 100,
                        pulsePhase: 0
                    };
                    // Rastro de fuego dorado
                    effect.customData.fireTrail = [];
                    for (let i = 0; i < 20; i++) {
                        effect.customData.fireTrail.push({
                            x: x,
                            y: y,
                            life: 1,
                            size: 15 + Math.random() * 10
                        });
                    }
                    // Silueta de chacal
                    effect.customData.jackalForm = {
                        scale: 0,
                        alpha: 0,
                        rotation: 0
                    };
                }
                else if (effectDef.type === 'custom_ankh') {
                    // Símbolo Ankh sagrado
                    effect.customData.ankhSymbol = {
                        scale: 0,
                        rotation: 0,
                        glow: 0
                    };
                    // Círculo de curación
                    effect.customData.healingCircle = {
                        radius: 0,
                        maxRadius: 200,
                        pulsePhase: 0
                    };
                    // Rayos de luz curativos
                    effect.customData.lightRays = [];
                    for (let i = 0; i < 12; i++) {
                        effect.customData.lightRays.push({
                            angle: (Math.PI * 2 / 12) * i,
                            length: 0,
                            maxLength: 150,
                            width: 8
                        });
                    }
                }
                else if (effectDef.type === 'custom_plague') {
                    // 5 plagas consecutivas
                    effect.customData.plagues = [
                        { type: 'blood', active: false, delay: 0, particles: [] },
                        { type: 'locusts', active: false, delay: 2000, particles: [] },
                        { type: 'darkness', active: false, delay: 4000, particles: [] },
                        { type: 'hail', active: false, delay: 6000, particles: [] },
                        { type: 'death', active: false, delay: 8000, particles: [] }
                    ];
                    // Aura verde-dorada
                    effect.customData.auraRings = [];
                    for (let i = 0; i < 5; i++) {
                        effect.customData.auraRings.push({
                            radius: 50 + i * 30,
                            alpha: 0,
                            rotation: 0
                        });
                    }
                }
                else if (effectDef.type === 'custom_underworld') {
                    // Portal masivo del Duat
                    effect.customData.portal = {
                        radius: 0,
                        maxRadius: 600,
                        rotation: 0
                    };
                    // Jeroglíficos giratorios
                    effect.customData.hieroglyphs = [];
                    for (let i = 0; i < 24; i++) {
                        effect.customData.hieroglyphs.push({
                            angle: (Math.PI * 2 / 24) * i,
                            distance: 550,
                            symbol: ['☥', '𓂀', '𓁹', '𓆣'][Math.floor(Math.random() * 4)],
                            size: 30,
                            glow: Math.random()
                        });
                    }
                    // Guerreros momificados
                    effect.customData.warriors = [];
                    for (let i = 0; i < 12; i++) {
                        const angle = (Math.PI * 2 / 12) * i;
                        effect.customData.warriors.push({
                            angle: angle,
                            distance: 400,
                            height: 0,
                            maxHeight: 80,
                            delay: i * 100
                        });
                    }
                    // Columnas de fuego espectral
                    effect.customData.fireColumns = [];
                    for (let i = 0; i < 8; i++) {
                        effect.customData.fireColumns.push({
                            x: x + (Math.random() - 0.5) * 500,
                            y: y + (Math.random() - 0.5) * 500,
                            height: 0,
                            maxHeight: 200,
                            delay: i * 300,
                            active: false
                        });
                    }
                    // Forma espectral de Anubis
                    effect.customData.anubisForm = {
                        scale: 0,
                        alpha: 0,
                        yOffset: 0
                    };
                }

                this.activeEffects.push(effect);

                // Update effects count if element exists
                const effectsCount = document.getElementById('effects-count');
                if (effectsCount) {
                    effectsCount.textContent = this.activeEffects.length;
                }
            },

            updateEffects(deltaTime) {
                const now = Date.now();

                this.activeEffects = this.activeEffects.filter(effect => {
                    const elapsed = now - effect.startTime;
                    if (elapsed >= effect.duration) return false;

                    const progress = elapsed / effect.duration;
                    effect.particles.forEach(particle => {
                        particle.x += particle.vx * (deltaTime / 1000);
                        particle.y += particle.vy * (deltaTime / 1000);
                        particle.life = 1.0 - progress;
                        particle.size *= 0.96;
                    });

                    return true;
                });

                // Update effects count if element exists
                const effectsCount = document.getElementById('effects-count');
                if (effectsCount) {
                    effectsCount.textContent = this.activeEffects.length;
                }
            },

            renderEffects(ctx) {
                this.activeEffects.forEach(effect => {
                    const elapsed = Date.now() - effect.startTime;
                    const progress = Math.min(elapsed / effect.duration, 1);

                    // Render custom Guardian Ancestral effects
                    if (effect.type === 'custom_quake') {
                        this.renderQuakeEffect(ctx, effect, progress);
                    }
                    else if (effect.type === 'custom_pillar') {
                        this.renderPillarEffect(ctx, effect, progress);
                    }
                    else if (effect.type === 'custom_armor') {
                        this.renderArmorEffect(ctx, effect, progress);
                    }
                    else if (effect.type === 'custom_spikes') {
                        this.renderSpikesEffect(ctx, effect, progress);
                    }
                    else if (effect.type === 'custom_colossus') {
                        this.renderColossusEffect(ctx, effect, progress);
                    }
                    else if (effect.type === 'custom_cataclysm') {
                        this.renderCataclysmEffect(ctx, effect, progress);
                    }
                    // Render Anubis effects
                    else if (effect.type === 'custom_judgment') {
                        this.renderJudgmentEffect(ctx, effect, progress);
                    }
                    else if (effect.type === 'custom_sandstorm') {
                        this.renderSandstormEffect(ctx, effect, progress);
                    }
                    else if (effect.type === 'custom_jackal') {
                        this.renderJackalEffect(ctx, effect, progress);
                    }
                    else if (effect.type === 'custom_ankh') {
                        this.renderAnkhEffect(ctx, effect, progress);
                    }
                    else if (effect.type === 'custom_plague') {
                        this.renderPlagueEffect(ctx, effect, progress);
                    }
                    else if (effect.type === 'custom_underworld') {
                        this.renderUnderworldEffect(ctx, effect, progress);
                    }
                    // Render standard particle effects
                    else {
                        effect.particles.forEach(particle => {
                            ctx.save();
                            ctx.globalAlpha = particle.life * 0.85;

                            const gradient = ctx.createRadialGradient(
                                particle.x, particle.y, 0,
                                particle.x, particle.y, particle.size
                            );
                            gradient.addColorStop(0, effect.color);
                            gradient.addColorStop(1, 'transparent');

                            ctx.fillStyle = gradient;
                            ctx.shadowColor = effect.color;
                            ctx.shadowBlur = 15;
                            ctx.beginPath();
                            ctx.arc(particle.x, particle.y, particle.size, 0, Math.PI * 2);
                            ctx.fill();
                            ctx.restore();
                        });
                    }
                });
            },

            renderQuakeEffect(ctx, effect, progress) {
                ctx.save();
                // Ondas sísmicas
                effect.customData.waves.forEach((wave, index) => {
                    if (progress * effect.duration > wave.delay) {
                        wave.active = true;
                        wave.radius = Math.min(wave.radius + 8, wave.maxRadius);

                        ctx.globalAlpha = (1 - wave.radius / wave.maxRadius) * 0.7;
                        ctx.strokeStyle = '#DAA520';
                        ctx.lineWidth = 4;
                        ctx.shadowColor = '#DAA520';
                        ctx.shadowBlur = 20;
                        ctx.beginPath();
                        ctx.arc(effect.x, effect.y, wave.radius, 0, Math.PI * 2);
                        ctx.stroke();
                    }
                });
                // Grietas doradas
                effect.customData.cracks.forEach(crack => {
                    crack.length = Math.min(crack.length + 3, crack.maxLength);
                    const endX = effect.x + Math.cos(crack.angle) * crack.length;
                    const endY = effect.y + Math.sin(crack.angle) * crack.length;

                    ctx.globalAlpha = 0.8 * (1 - progress);
                    ctx.strokeStyle = '#DAA520';
                    ctx.lineWidth = 3;
                    ctx.shadowColor = '#DAA520';
                    ctx.shadowBlur = 15;
                    ctx.beginPath();
                    ctx.moveTo(effect.x, effect.y);
                    ctx.lineTo(endX, endY);
                    ctx.stroke();
                });
                ctx.restore();
            },

            renderPillarEffect(ctx, effect, progress) {
                ctx.save();
                effect.customData.pillars.forEach((pillar, index) => {
                    pillar.height = Math.min(pillar.height + 4, pillar.maxHeight);
                    pillar.rotation += 0.02;

                    const px = effect.x + Math.cos(pillar.angle + pillar.rotation) * pillar.distance;
                    const py = effect.y + Math.sin(pillar.angle + pillar.rotation) * pillar.distance;

                    ctx.globalAlpha = 0.8 * (1 - progress);
                    // Pilar
                    ctx.fillStyle = '#A0826D';
                    ctx.shadowColor = '#DAA520';
                    ctx.shadowBlur = 20;
                    ctx.fillRect(px - 15, py - pillar.height, 30, pillar.height);
                    // Runas en el pilar
                    ctx.fillStyle = '#DAA520';
                    ctx.font = '20px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillText('?', px, py - pillar.height / 2);
                });
                ctx.restore();
            },

            renderArmorEffect(ctx, effect, progress) {
                ctx.save();
                // Capas de armadura
                effect.customData.layers.forEach((layer, index) => {
                    layer.alpha = Math.min(layer.alpha + 0.05, 0.6);
                    layer.rotation += 0.03 * (index % 2 === 0 ? 1 : -1);

                    ctx.globalAlpha = layer.alpha * (1 - progress);
                    ctx.strokeStyle = '#CD853F';
                    ctx.lineWidth = 3;
                    ctx.shadowColor = '#DAA520';
                    ctx.shadowBlur = 15;
                    ctx.setLineDash([10, 10]);
                    ctx.lineDashOffset = layer.rotation * 50;
                    ctx.beginPath();
                    ctx.arc(effect.x, effect.y, layer.radius, 0, Math.PI * 2);
                    ctx.stroke();
                    ctx.setLineDash([]);
                });
                // Fragmentos orbitantes
                effect.customData.fragments.forEach(frag => {
                    frag.angle += 0.05;
                    const fx = effect.x + Math.cos(frag.angle) * frag.distance;
                    const fy = effect.y + Math.sin(frag.angle) * frag.distance;

                    ctx.globalAlpha = 0.9 * (1 - progress);
                    ctx.fillStyle = '#8B7355';
                    ctx.shadowColor = '#DAA520';
                    ctx.shadowBlur = 10;
                    ctx.fillRect(fx - frag.size / 2, fy - frag.size / 2, frag.size, frag.size);
                });
                ctx.restore();
            },

            renderSpikesEffect(ctx, effect, progress) {
                ctx.save();
                effect.customData.lines.forEach(line => {
                    line.spikes.forEach(spike => {
                        if (progress * effect.duration > spike.delay) {
                            spike.height = Math.min(spike.height + 5, spike.maxHeight);

                            const sx = effect.x + Math.cos(line.angle) * spike.distance;
                            const sy = effect.y + Math.sin(line.angle) * spike.distance;

                            ctx.globalAlpha = 0.85 * (1 - progress);
                            // Pincho
                            ctx.fillStyle = '#8B4513';
                            ctx.shadowColor = '#DAA520';
                            ctx.shadowBlur = 15;
                            ctx.beginPath();
                            ctx.moveTo(sx, sy);
                            ctx.lineTo(sx - 10, sy);
                            ctx.lineTo(sx - 5, sy - spike.height);
                            ctx.lineTo(sx + 5, sy - spike.height);
                            ctx.lineTo(sx + 10, sy);
                            ctx.closePath();
                            ctx.fill();
                        }
                    });
                });
                ctx.restore();
            },

            renderColossusEffect(ctx, effect, progress) {
                ctx.save();
                // Anillos de aura
                effect.customData.auraRings.forEach(ring => {
                    if (progress * effect.duration > ring.delay) {
                        ring.active = true;
                        ring.radius = Math.min(ring.radius + 6, ring.maxRadius);

                        ctx.globalAlpha = (1 - ring.radius / ring.maxRadius) * 0.8;
                        ctx.strokeStyle = '#8B7355';
                        ctx.lineWidth = 5;
                        ctx.shadowColor = '#DAA520';
                        ctx.shadowBlur = 25;
                        ctx.beginPath();
                        ctx.arc(effect.x, effect.y, ring.radius, 0, Math.PI * 2);
                        ctx.stroke();
                    }
                });
                // Runas flotantes
                effect.customData.runes.forEach(rune => {
                    rune.angle += 0.04;
                    rune.yOffset = Math.sin(Date.now() / 200 + rune.angle) * 20;

                    const rx = effect.x + Math.cos(rune.angle) * rune.distance;
                    const ry = effect.y + Math.sin(rune.angle) * rune.distance + rune.yOffset;

                    ctx.globalAlpha = 0.9 * (1 - progress);
                    ctx.fillStyle = '#DAA520';
                    ctx.font = `${rune.size}px Arial`;
                    ctx.textAlign = 'center';
                    ctx.shadowColor = '#DAA520';
                    ctx.shadowBlur = 20;
                    ctx.fillText('?', rx, ry);
                });
                ctx.restore();
            },

            renderCataclysmEffect(ctx, effect, progress) {
                ctx.save();
                // Grietas del suelo
                effect.customData.groundCracks.forEach(crack => {
                    crack.length = Math.min(crack.length + 5, crack.maxLength);
                    const endX = effect.x + Math.cos(crack.angle) * crack.length;
                    const endY = effect.y + Math.sin(crack.angle) * crack.length;

                    ctx.globalAlpha = 0.9 * (1 - progress);
                    ctx.strokeStyle = '#DAA520';
                    ctx.lineWidth = 4;
                    ctx.shadowColor = '#DAA520';
                    ctx.shadowBlur = 25;
                    ctx.beginPath();
                    ctx.moveTo(effect.x, effect.y);
                    ctx.lineTo(endX, endY);
                    ctx.stroke();
                });
                // Pilares de luz
                effect.customData.lightPillars.forEach(pillar => {
                    if (progress * effect.duration > pillar.delay) {
                        pillar.active = true;
                        pillar.height = Math.min(pillar.height + 10, pillar.maxHeight);

                        ctx.globalAlpha = 0.7 * (1 - progress);
                        const gradient = ctx.createLinearGradient(pillar.x, pillar.y, pillar.x, pillar.y - pillar.height);
                        gradient.addColorStop(0, '#DAA520');
                        gradient.addColorStop(1, 'rgba(218, 165, 32, 0)');
                        ctx.fillStyle = gradient;
                        ctx.shadowColor = '#DAA520';
                        ctx.shadowBlur = 30;
                        ctx.fillRect(pillar.x - 20, pillar.y - pillar.height, 40, pillar.height);
                    }
                });
                // Explosión central
                effect.customData.centralExplosion.radius = Math.min(effect.customData.centralExplosion.radius + 10, effect.customData.centralExplosion.maxRadius);
                ctx.globalAlpha = (1 - progress) * 0.5;
                ctx.strokeStyle = '#DAA520';
                ctx.lineWidth = 8;
                ctx.shadowColor = '#DAA520';
                ctx.shadowBlur = 40;
                ctx.beginPath();
                ctx.arc(effect.x, effect.y, effect.customData.centralExplosion.radius, 0, Math.PI * 2);
                ctx.stroke();
                ctx.restore();
            },

            // ===== ANUBIS EFFECT RENDERERS =====
            renderJudgmentEffect(ctx, effect, progress) {
                ctx.save();
                // Balanza sagrada en el centro
                effect.customData.scale.rotation += 0.03;
                effect.customData.scale.glow = Math.sin(Date.now() / 200) * 0.5 + 0.5;

                ctx.globalAlpha = 0.8 * (1 - progress);
                ctx.save();
                ctx.translate(effect.x, effect.y);
                ctx.rotate(effect.customData.scale.rotation);
                ctx.strokeStyle = '#FFD700';
                ctx.lineWidth = 4;
                ctx.shadowColor = '#FFD700';
                ctx.shadowBlur = 20 + effect.customData.scale.glow * 15;
                // Dibujar balanza
                ctx.beginPath();
                ctx.moveTo(-30, 0);
                ctx.lineTo(30, 0);
                ctx.moveTo(-20, 0);
                ctx.lineTo(-20, -20);
                ctx.moveTo(20, 0);
                ctx.lineTo(20, -20);
                ctx.stroke();
                ctx.restore();

                // Proyectiles dorados
                effect.customData.projectiles.forEach(proj => {
                    proj.angle += 0.08;
                    proj.x = effect.x + Math.cos(proj.angle) * 80;
                    proj.y = effect.y + Math.sin(proj.angle) * 80;

                    // Rastro
                    proj.trail.push({ x: proj.x, y: proj.y, life: 1 });
                    if (proj.trail.length > 10) proj.trail.shift();

                    proj.trail.forEach((t, i) => {
                        t.life -= 0.1;
                        ctx.globalAlpha = t.life * 0.6;
                        ctx.fillStyle = '#FFD700';
                        ctx.shadowColor = '#FFD700';
                        ctx.shadowBlur = 15;
                        ctx.beginPath();
                        ctx.arc(t.x, t.y, proj.size * (i / proj.trail.length), 0, Math.PI * 2);
                        ctx.fill();
                    });

                    // Proyectil principal
                    ctx.globalAlpha = 0.9 * (1 - progress);
                    ctx.fillStyle = '#FFD700';
                    ctx.shadowColor = '#FFD700';
                    ctx.shadowBlur = 25;
                    ctx.beginPath();
                    ctx.arc(proj.x, proj.y, proj.size, 0, Math.PI * 2);
                    ctx.fill();
                });
                ctx.restore();
            },

            renderSandstormEffect(ctx, effect, progress) {
                ctx.save();
                effect.customData.radius = Math.min(effect.customData.radius + 5, effect.customData.maxRadius);

                // Partículas de arena
                effect.customData.sandParticles.forEach(particle => {
                    particle.angle += particle.speed;
                    const px = effect.x + Math.cos(particle.angle) * particle.distance;
                    const py = effect.y + Math.sin(particle.angle) * particle.distance;

                    ctx.globalAlpha = particle.alpha * (1 - progress);
                    ctx.fillStyle = '#DEB887';
                    ctx.shadowColor = '#DEB887';
                    ctx.shadowBlur = 10;
                    ctx.beginPath();
                    ctx.arc(px, py, particle.size, 0, Math.PI * 2);
                    ctx.fill();
                });

                // Anillo de tormenta
                ctx.globalAlpha = 0.4 * (1 - progress);
                ctx.strokeStyle = '#DEB887';
                ctx.lineWidth = 20;
                ctx.shadowColor = '#DEB887';
                ctx.shadowBlur = 30;
                ctx.beginPath();
                ctx.arc(effect.x, effect.y, effect.customData.radius, 0, Math.PI * 2);
                ctx.stroke();
                ctx.restore();
            },

            renderJackalEffect(ctx, effect, progress) {
                ctx.save();
                // Aura dorada pulsante
                effect.customData.aura.pulsePhase += 0.1;
                effect.customData.aura.radius = Math.min(effect.customData.aura.radius + 3, effect.customData.aura.maxRadius);
                const pulse = Math.sin(effect.customData.aura.pulsePhase) * 0.3 + 0.7;

                ctx.globalAlpha = 0.5 * pulse * (1 - progress);
                ctx.strokeStyle = '#FFD700';
                ctx.lineWidth = 6;
                ctx.shadowColor = '#FFD700';
                ctx.shadowBlur = 30;
                ctx.beginPath();
                ctx.arc(effect.x, effect.y, effect.customData.aura.radius, 0, Math.PI * 2);
                ctx.stroke();

                // Rastro de fuego dorado
                effect.customData.fireTrail.forEach((fire, i) => {
                    fire.life -= 0.05;
                    ctx.globalAlpha = fire.life * 0.7;
                    ctx.fillStyle = '#FFD700';
                    ctx.shadowColor = '#FF8C00';
                    ctx.shadowBlur = 20;
                    ctx.beginPath();
                    ctx.arc(fire.x, fire.y, fire.size, 0, Math.PI * 2);
                    ctx.fill();
                });

                // Silueta de chacal
                effect.customData.jackalForm.scale = Math.min(effect.customData.jackalForm.scale + 0.05, 1.5);
                effect.customData.jackalForm.alpha = Math.min(effect.customData.jackalForm.alpha + 0.03, 0.8);
                effect.customData.jackalForm.rotation += 0.02;

                ctx.globalAlpha = effect.customData.jackalForm.alpha * (1 - progress);
                ctx.save();
                ctx.translate(effect.x, effect.y);
                ctx.scale(effect.customData.jackalForm.scale, effect.customData.jackalForm.scale);
                ctx.rotate(effect.customData.jackalForm.rotation);
                ctx.fillStyle = '#FFD700';
                ctx.shadowColor = '#FFD700';
                ctx.shadowBlur = 40;
                ctx.font = '60px Arial';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText('🐺', 0, 0);
                ctx.restore();
                ctx.restore();
            },

            renderAnkhEffect(ctx, effect, progress) {
                ctx.save();
                // Círculo de curación
                effect.customData.healingCircle.radius = Math.min(effect.customData.healingCircle.radius + 4, effect.customData.healingCircle.maxRadius);
                effect.customData.healingCircle.pulsePhase += 0.08;
                const pulse = Math.sin(effect.customData.healingCircle.pulsePhase) * 0.4 + 0.6;

                ctx.globalAlpha = 0.4 * pulse * (1 - progress);
                ctx.fillStyle = '#00CED1';
                ctx.shadowColor = '#00CED1';
                ctx.shadowBlur = 35;
                ctx.beginPath();
                ctx.arc(effect.x, effect.y, effect.customData.healingCircle.radius, 0, Math.PI * 2);
                ctx.fill();

                // Rayos de luz curativos
                effect.customData.lightRays.forEach(ray => {
                    ray.length = Math.min(ray.length + 5, ray.maxLength);
                    const endX = effect.x + Math.cos(ray.angle) * ray.length;
                    const endY = effect.y + Math.sin(ray.angle) * ray.length;

                    ctx.globalAlpha = 0.6 * (1 - progress);
                    ctx.strokeStyle = '#00CED1';
                    ctx.lineWidth = ray.width;
                    ctx.shadowColor = '#00CED1';
                    ctx.shadowBlur = 25;
                    ctx.beginPath();
                    ctx.moveTo(effect.x, effect.y);
                    ctx.lineTo(endX, endY);
                    ctx.stroke();
                });

                // Símbolo Ankh
                effect.customData.ankhSymbol.scale = Math.min(effect.customData.ankhSymbol.scale + 0.04, 2);
                effect.customData.ankhSymbol.rotation += 0.03;
                effect.customData.ankhSymbol.glow = Math.sin(Date.now() / 150) * 0.5 + 0.5;

                ctx.globalAlpha = 0.9 * (1 - progress);
                ctx.save();
                ctx.translate(effect.x, effect.y);
                ctx.scale(effect.customData.ankhSymbol.scale, effect.customData.ankhSymbol.scale);
                ctx.rotate(effect.customData.ankhSymbol.rotation);
                ctx.fillStyle = '#FFD700';
                ctx.shadowColor = '#FFD700';
                ctx.shadowBlur = 30 + effect.customData.ankhSymbol.glow * 20;
                ctx.font = '50px Arial';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText('☥', 0, 0);
                ctx.restore();
                ctx.restore();
            },

            renderPlagueEffect(ctx, effect, progress) {
                ctx.save();
                const elapsed = progress * effect.duration;

                // Activar plagas según el tiempo
                effect.customData.plagues.forEach((plague, index) => {
                    if (elapsed > plague.delay && !plague.active) {
                        plague.active = true;
                        // Inicializar partículas de la plaga
                        for (let i = 0; i < 30; i++) {
                            plague.particles.push({
                                x: effect.x + (Math.random() - 0.5) * 400,
                                y: effect.y + (Math.random() - 0.5) * 400,
                                vx: (Math.random() - 0.5) * 3,
                                vy: (Math.random() - 0.5) * 3,
                                size: 5 + Math.random() * 10,
                                life: 1
                            });
                        }
                    }

                    if (plague.active) {
                        plague.particles.forEach(p => {
                            p.x += p.vx;
                            p.y += p.vy;
                            p.life -= 0.01;

                            if (p.life > 0) {
                                ctx.globalAlpha = p.life * 0.7;
                                let color = '#228B22';
                                if (plague.type === 'blood') color = '#8B0000';
                                if (plague.type === 'locusts') color = '#556B2F';
                                if (plague.type === 'darkness') color = '#000000';
                                if (plague.type === 'hail') color = '#4682B4';
                                if (plague.type === 'death') color = '#800080';

                                ctx.fillStyle = color;
                                ctx.shadowColor = color;
                                ctx.shadowBlur = 15;
                                ctx.beginPath();
                                ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
                                ctx.fill();
                            }
                        });
                    }
                });

                // Aura verde-dorada
                effect.customData.auraRings.forEach((ring, i) => {
                    ring.alpha = Math.min(ring.alpha + 0.02, 0.5);
                    ring.rotation += 0.02 * (i % 2 === 0 ? 1 : -1);

                    ctx.globalAlpha = ring.alpha * (1 - progress);
                    ctx.strokeStyle = i % 2 === 0 ? '#228B22' : '#FFD700';
                    ctx.lineWidth = 4;
                    ctx.shadowColor = i % 2 === 0 ? '#228B22' : '#FFD700';
                    ctx.shadowBlur = 20;
                    ctx.setLineDash([15, 15]);
                    ctx.lineDashOffset = ring.rotation * 100;
                    ctx.beginPath();
                    ctx.arc(effect.x, effect.y, ring.radius, 0, Math.PI * 2);
                    ctx.stroke();
                    ctx.setLineDash([]);
                });
                ctx.restore();
            },

            renderUnderworldEffect(ctx, effect, progress) {
                ctx.save();
                // Portal del Duat
                effect.customData.portal.radius = Math.min(effect.customData.portal.radius + 12, effect.customData.portal.maxRadius);
                effect.customData.portal.rotation += 0.02;

                // Portal oscuro
                ctx.globalAlpha = 0.8 * (1 - progress);
                const gradient = ctx.createRadialGradient(effect.x, effect.y, 0, effect.x, effect.y, effect.customData.portal.radius);
                gradient.addColorStop(0, '#000000');
                gradient.addColorStop(0.5, '#1a1a1a');
                gradient.addColorStop(1, 'rgba(0, 0, 0, 0)');
                ctx.fillStyle = gradient;
                ctx.shadowColor = '#FFD700';
                ctx.shadowBlur = 50;
                ctx.beginPath();
                ctx.arc(effect.x, effect.y, effect.customData.portal.radius, 0, Math.PI * 2);
                ctx.fill();

                // Borde dorado del portal
                ctx.globalAlpha = 0.9 * (1 - progress);
                ctx.strokeStyle = '#FFD700';
                ctx.lineWidth = 8;
                ctx.shadowColor = '#FFD700';
                ctx.shadowBlur = 40;
                ctx.beginPath();
                ctx.arc(effect.x, effect.y, effect.customData.portal.radius, 0, Math.PI * 2);
                ctx.stroke();

                // Jeroglíficos giratorios
                effect.customData.hieroglyphs.forEach(h => {
                    h.angle += 0.03;
                    h.glow = Math.sin(Date.now() / 100 + h.angle) * 0.5 + 0.5;
                    const hx = effect.x + Math.cos(h.angle + effect.customData.portal.rotation) * h.distance;
                    const hy = effect.y + Math.sin(h.angle + effect.customData.portal.rotation) * h.distance;

                    ctx.globalAlpha = 0.9 * (1 - progress);
                    ctx.fillStyle = '#FFD700';
                    ctx.shadowColor = '#FFD700';
                    ctx.shadowBlur = 20 + h.glow * 15;
                    ctx.font = `${h.size}px Arial`;
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText(h.symbol, hx, hy);
                });

                // Guerreros momificados
                effect.customData.warriors.forEach(warrior => {
                    if (progress * effect.duration > warrior.delay) {
                        warrior.height = Math.min(warrior.height + 4, warrior.maxHeight);
                        const wx = effect.x + Math.cos(warrior.angle) * warrior.distance;
                        const wy = effect.y + Math.sin(warrior.angle) * warrior.distance;

                        ctx.globalAlpha = 0.8 * (1 - progress);
                        ctx.fillStyle = '#FFD700';
                        ctx.shadowColor = '#FFD700';
                        ctx.shadowBlur = 25;
                        ctx.fillRect(wx - 15, wy - warrior.height, 30, warrior.height);

                        // Cabeza del guerrero
                        ctx.beginPath();
                        ctx.arc(wx, wy - warrior.height - 10, 10, 0, Math.PI * 2);
                        ctx.fill();
                    }
                });

                // Columnas de fuego espectral
                effect.customData.fireColumns.forEach(col => {
                    if (progress * effect.duration > col.delay) {
                        col.active = true;
                        col.height = Math.min(col.height + 8, col.maxHeight);

                        ctx.globalAlpha = 0.7 * (1 - progress);
                        const fireGradient = ctx.createLinearGradient(col.x, col.y, col.x, col.y - col.height);
                        fireGradient.addColorStop(0, '#228B22');
                        fireGradient.addColorStop(0.5, '#FFD700');
                        fireGradient.addColorStop(1, 'rgba(255, 215, 0, 0)');
                        ctx.fillStyle = fireGradient;
                        ctx.shadowColor = '#228B22';
                        ctx.shadowBlur = 35;
                        ctx.fillRect(col.x - 25, col.y - col.height, 50, col.height);
                    }
                });

                // Forma espectral de Anubis
                effect.customData.anubisForm.scale = Math.min(effect.customData.anubisForm.scale + 0.03, 3);
                effect.customData.anubisForm.alpha = Math.min(effect.customData.anubisForm.alpha + 0.02, 0.9);
                effect.customData.anubisForm.yOffset = Math.sin(Date.now() / 300) * 20;

                ctx.globalAlpha = effect.customData.anubisForm.alpha * (1 - progress);
                ctx.save();
                ctx.translate(effect.x, effect.y - 100 + effect.customData.anubisForm.yOffset);
                ctx.scale(effect.customData.anubisForm.scale, effect.customData.anubisForm.scale);
                ctx.fillStyle = '#FFD700';
                ctx.shadowColor = '#FFD700';
                ctx.shadowBlur = 60;
                ctx.font = '80px Arial';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillText('🐺', 0, 0);
                ctx.restore();
                ctx.restore();
            }
        };

        // ===== ABILITY MANAGER =====
        const AbilityManager = {
            activateAbility(abilityId) {
                // Prevent ability usage when game is paused
                if (MobRaidSystem.paused) {
                    console.log('?? Cannot use abilities while paused!');
                    return false;
                }

                const abilities = EquipmentManager.getAllAbilities();
                const ability = abilities.find(a => a.id === abilityId);

                if (!ability) return false;
                if (!this.isAbilityReady(abilityId)) return false;

                console.log(`? ${ability.name}`);

                // Apply class cooldown multiplier
                let cooldown = ability.cooldown;
                if (EquipmentManager.equippedRole && EquipmentManager.equippedRole.type === 'class') {
                    const classId = EquipmentManager.equippedRole.id;
                    const cooldownMultiplier = ClassProgressionSystem.getCooldownMultiplier(classId);
                    cooldown = Math.floor(cooldown * cooldownMultiplier);
                }
                ability.currentCooldown = cooldown;

                EffectRenderer.playEffect(ability.effectId, Player.x, Player.y);
                this.showAbilityPopup(ability.name, ability.type === 'ultimate');

                if (ability.type === 'ultimate') {
                    this.screenShake();
                }

                // Special class abilities
                if (MobRaidSystem.active || PracticeModeManager.active) {
                    // Dragonhunter
                    if (abilityId === 'dragon_arrow') {
                        MobRaidSystem.dragonFlameArrow(ability);
                    } else if (abilityId === 'dragon_breath') {
                        MobRaidSystem.dragonBreathBomb();
                    } else if (abilityId === 'triple_arrow') {
                        MobRaidSystem.tripleArrowUse();
                    } else if (abilityId === 'nature_rise') {
                        MobRaidSystem.natureRising();
                    } else if (abilityId === 'dragon_madness') {
                        MobRaidSystem.draconicMadness();
                    } else if (abilityId === 'dragon_ultimate') {
                        MobRaidSystem.draconicExplosion();
                    }
                    // Elementalist
                    else if (abilityId === 'elem_storm') {
                        MobRaidSystem.elementalStorm();
                    } else if (abilityId === 'elem_ice') {
                        MobRaidSystem.iceBarrier();
                    } else if (abilityId === 'elem_ultimate') {
                        MobRaidSystem.elementalCataclysm();
                    }
                    // Ronin Samurai
                    else if (abilityId === 'samurai_dash') {
                        MobRaidSystem.swiftCut();
                    } else if (abilityId === 'samurai_counter') {
                        MobRaidSystem.counterAttack();
                    } else if (abilityId === 'samurai_ninja_power') {
                        MobRaidSystem.ninjaPower();
                    } else if (abilityId === 'samurai_surprise_cut') {
                        MobRaidSystem.surpriseCut();
                    } else if (abilityId === 'samurai_ultimate') {
                        MobRaidSystem.thousandLeavesDance();
                    }
                    // Wild Berserker
                    else if (abilityId === 'berserker_rage') {
                        MobRaidSystem.wildRage();
                    } else if (abilityId === 'berserker_leap') {
                        MobRaidSystem.devastatingLeap();
                    } else if (abilityId === 'berserker_surprise') {
                        MobRaidSystem.berserkerSurprise();
                    } else if (abilityId === 'berserker_axes') {
                        MobRaidSystem.doubleAxes();
                    } else if (abilityId === 'berserker_ultimate') {
                        MobRaidSystem.bloodlust();
                    }
                    // Shadow Ninja
                    else if (abilityId === 'ninja_shadow_strike') {
                        MobRaidSystem.shadowStrike();
                    } else if (abilityId === 'ninja_shuriken') {
                        MobRaidSystem.shurikenRain();
                    } else if (abilityId === 'ninja_smoke') {
                        MobRaidSystem.shadowVeil();
                    } else if (abilityId === 'ninja_clone') {
                        MobRaidSystem.shadowClone();
                    } else if (abilityId === 'ninja_ultimate') {
                        LoadoutManager.trackAbilityUsage('ninja_ultimate');
                        MobRaidSystem.silentExecution();
                    }
                    // Wind Master
                    else if (abilityId === 'wind_radioactive') {
                        MobRaidSystem.radioactiveWind();
                    } else if (abilityId === 'wind_bubbles') {
                        MobRaidSystem.toxicAirBubbles();
                    } else if (abilityId === 'wind_ventoso') {
                        MobRaidSystem.ventoso();
                    } else if (abilityId === 'wind_ciclon') {
                        MobRaidSystem.ciclon();
                    } else if (abilityId === 'wind_ultimate') {
                        MobRaidSystem.strongWindAttraction();
                    }
                    // Tornado Overlord (Master Class)
                    else if (abilityId === 'master_singularity') {
                        MobRaidSystem.windSingularity();
                    } else if (abilityId === 'master_pressure') {
                        MobRaidSystem.atmosphericPressure();
                    } else if (abilityId === 'master_tornado_barrage') {
                        MobRaidSystem.tornadoBarrage();
                    } else if (abilityId === 'master_storm_shield') {
                        MobRaidSystem.stormShield();
                    } else if (abilityId === 'master_enemy_tornado') {
                        MobRaidSystem.enemyTornado();
                    } else if (abilityId === 'master_apocalyptic_storm') {
                        MobRaidSystem.apocalypticStorm();
                    }
                    // Abyssal Shadowlord (Master Class - Shadow Ninja)
                    else if (abilityId === 'abyssal_blade_storm') {
                        MobRaidSystem.abyssalBladeStorm();
                    } else if (abilityId === 'abyssal_death_chain') {
                        MobRaidSystem.abyssalDeathChain();
                    } else if (abilityId === 'abyssal_void_leap') {
                        MobRaidSystem.abyssalVoidLeap();
                    } else if (abilityId === 'abyssal_shadow_legion') {
                        MobRaidSystem.abyssalShadowLegion();
                    } else if (abilityId === 'abyssal_shadow_emperor') {
                        MobRaidSystem.abyssalShadowEmperor();
                    } else if (abilityId === 'abyssal_eternal_night') {
                        MobRaidSystem.abyssalEternalNight();
                    }
                    // Roman Legionary
                    else if (abilityId === 'roman_gladius') {
                        MobRaidSystem.gladiusFulminante();
                    } else if (abilityId === 'roman_testudo') {
                        MobRaidSystem.formacionTestudo();
                    } else if (abilityId === 'roman_pilum') {
                        MobRaidSystem.lanzamientoPilum();
                    } else if (abilityId === 'roman_centurion') {
                        MobRaidSystem.gritoCenturion();
                    } else if (abilityId === 'roman_aquila') {
                        MobRaidSystem.aguilaImperial();
                    } else if (abilityId === 'roman_legio') {
                        MobRaidSystem.legioAeterna();
                    }
                    // Spartan Hoplite
                    else if (abilityId === 'spartan_dory') {
                        MobRaidSystem.doruPenetrante();
                    } else if (abilityId === 'spartan_phalanx') {
                        MobRaidSystem.falangeEspartana();
                    } else if (abilityId === 'spartan_charge') {
                        MobRaidSystem.cargaEspartana();
                    } else if (abilityId === 'spartan_aroo') {
                        MobRaidSystem.gritoAroo();
                    } else if (abilityId === 'spartan_ares') {
                        MobRaidSystem.bendicionAres();
                    } else if (abilityId === 'spartan_thermopylae') {
                        MobRaidSystem.lasTermopilas();
                    }
                    // Cyber Gunslinger (Base Class)
                    else if (abilityId === 'gun_ultimate') {
                        MobRaidSystem.orbitalStrike();
                    }
                    // Cybernetic Warlord (Master Class)
                    else if (abilityId === 'cyber_plasma_cannon') {
                        MobRaidSystem.plasmaCannon();
                    } else if (abilityId === 'cyber_singularity_grenade') {
                        MobRaidSystem.singularityGrenade();
                    } else if (abilityId === 'cyber_drone_swarm') {
                        MobRaidSystem.droneSwarm();
                    } else if (abilityId === 'cyber_photon_barrier') {
                        MobRaidSystem.photonBarrier();
                    } else if (abilityId === 'cyber_mech_suit') {
                        MobRaidSystem.mechSuit();
                    } else if (abilityId === 'cyber_orbital_ragnarok') {
                        MobRaidSystem.orbitalRagnarok();
                    }
                    // Regular abilities
                    else {
                        const damage = ability.type === 'ultimate' ? 50 : 25;
                        if (MobRaidSystem.active) {
                            MobRaidSystem.checkAbilityHit(Player.x, Player.y, 150, damage);
                        }
                        if (PracticeModeManager.active) {
                            PracticeModeManager.applyDamageToDummies(Player.x, Player.y, 150, damage);
                        }
                    }
                }

                this.updateAbilityUI();
                return true;
            },

            updateCooldowns(deltaTime) {
                // Don't update cooldowns when game is paused
                if (MobRaidSystem.paused) return;

                const abilities = EquipmentManager.getAllAbilities();
                abilities.forEach(ability => {
                    if (ability.currentCooldown > 0) {
                        ability.currentCooldown = Math.max(0, ability.currentCooldown - deltaTime);
                    }
                });
                this.updateAbilityUI();
            },

            isAbilityReady(abilityId) {
                const abilities = EquipmentManager.getAllAbilities();
                const ability = abilities.find(a => a.id === abilityId);
                return ability && ability.currentCooldown === 0;
            },

            updateAbilityUI() {
                const abilities = EquipmentManager.getAllAbilities();
                const abilitySlots = document.querySelectorAll('.ability-slot');

                abilitySlots.forEach((slot, index) => {
                    const ability = abilities[index];
                    if (!ability) return;

                    const cooldownDiv = slot.querySelector('.ability-cooldown');

                    if (ability.currentCooldown > 0) {
                        slot.classList.add('on-cooldown');
                        const seconds = Math.ceil(ability.currentCooldown / 1000);
                        cooldownDiv.textContent = seconds;
                    } else {
                        slot.classList.remove('on-cooldown');
                        cooldownDiv.textContent = '';
                    }
                });
            },

            showAbilityPopup(name, isUltimate) {
                const popup = document.createElement('div');
                popup.style.cssText = `
                    position: fixed;
                    top: 20%;
                    left: 50%;
                    transform: translate(-50%, -50%);
                    background: ${isUltimate ? 'linear-gradient(135deg, #ffbe0b, #ff006e)' : 'linear-gradient(135deg, #00d9ff, #ff006e)'};
                    color: white;
                    padding: ${isUltimate ? '15px 30px' : '12px 25px'};
                    border-radius: 12px;
                    font-size: ${isUltimate ? '20px' : '16px'};
                    font-weight: 700;
                    z-index: 6000;
                    pointer-events: none;
                    animation: popupFade 0.8s ease-out forwards;
                    border: 2px solid ${isUltimate ? '#ffbe0b' : '#00d9ff'};
                    box-shadow: 0 0 20px ${isUltimate ? 'rgba(255, 190, 11, 0.6)' : 'rgba(0, 217, 255, 0.5)'};
                    font-family: 'Orbitron', sans-serif;
                    letter-spacing: 1px;
                    text-shadow: 0 0 10px rgba(0, 0, 0, 0.8);
                `;
                popup.textContent = name;
                document.body.appendChild(popup);

                setTimeout(() => popup.remove(), 800);
            },

            screenShake() {
                const container = document.querySelector('.main-canvas');
                container.style.animation = 'shake 0.7s ease-in-out';
                setTimeout(() => {
                    container.style.animation = '';
                }, 700);
            }
        };

        // ===== UI MANAGER =====
        const UIManager = {
            currentTab: 'characters',

            showRoleSelection(type = 'characters') {
                this.currentTab = type;
                document.getElementById('role-selection-modal').classList.remove('hidden');
                this.renderRoleGrid(type);
            },

            hideRoleSelection() {
                document.getElementById('role-selection-modal').classList.add('hidden');
            },

            renderRoleGrid(type) {
                const grid = document.getElementById('role-grid');
                grid.innerHTML = '';

                let roles = [...(rolesData[type] || [])]; // Create a copy to avoid mutating original

                // Sort roles by tier (SSS > S+ > S > A > B > C, then by name)
                const tierOrder = { 'SSS': 0, 'S+': 1, 'S': 2, 'A': 3, 'B': 4, 'C': 5 };

                roles.sort((a, b) => {
                    const aTier = a.tier || 'Z'; // Put items without tier at the end
                    const bTier = b.tier || 'Z';

                    const aTierValue = tierOrder[aTier] !== undefined ? tierOrder[aTier] : 999;
                    const bTierValue = tierOrder[bTier] !== undefined ? tierOrder[bTier] : 999;

                    // Sort by tier first
                    if (aTierValue !== bTierValue) {
                        return aTierValue - bTierValue;
                    }

                    // If same tier, sort alphabetically by name
                    return a.name.localeCompare(b.name);
                });

                console.log('Sorted roles:', roles.map(r => `${r.name} (${r.tier || 'No tier'})`));

                roles.forEach(role => {
                    const card = document.createElement('div');
                    card.className = 'role-card';

                    // Get current tickets for this class
                    const currentTickets = role.type === 'class' ? (EquipmentManager.classTickets[role.id] || 0) : 0;

                    // Check if class is locked (not unlocked AND doesn't have enough tickets)
                    const isUnlocked = EquipmentManager.isClassUnlocked(role.id);
                    const hasEnoughTickets = currentTickets >= (role.ticketsRequired || 0);
                    const isLocked = role.type === 'class' && role.ticketsRequired && !isUnlocked && !hasEnoughTickets;
                    const canUnlock = role.type === 'class' && role.ticketsRequired && !isUnlocked && hasEnoughTickets;

                    // Add tier styling for classes
                    if (role.tier) {
                        card.style.borderColor = role.tierColor;
                        card.style.boxShadow = `0 0 20px ${role.tierColor}40`;
                    }

                    // Add locked styling
                    if (isLocked) {
                        card.style.opacity = '0.6';
                        card.style.filter = 'grayscale(50%)';
                    }

                    // Add "can unlock" styling
                    if (canUnlock) {
                        card.style.borderColor = '#ffd700';
                        card.style.boxShadow = '0 0 30px rgba(255, 215, 0, 0.6)';
                        card.style.animation = 'pulse 2s ease-in-out infinite';
                    }

                    card.innerHTML = `
                        <div class="role-card-icon">${role.icon}</div>
                        <div class="role-card-name">${role.name}</div>
                        <div class="role-card-type">${role.type}</div>
                        ${role.tier ? `<div style="color: ${role.tierColor}; font-weight: 900; font-size: 16px; margin-top: 5px;">Tier ${role.tier}</div>` : ''}
                        ${role.ticketsRequired ? `<div style="color: ${isUnlocked ? '#00ff00' : canUnlock ? '#ffd700' : '#999'}; font-size: 12px; margin-top: 3px;">${isUnlocked ? '?' : canUnlock ? '?' : '??'} ${currentTickets}/${role.ticketsRequired} Tickets ${isUnlocked ? 'Unlocked' : canUnlock ? 'Ready!' : 'to Unlock'}</div>` : ''}
                    `;

                    card.addEventListener('click', () => {
                        // Show info panel
                        this.showRoleInfoPanel(role, isLocked, currentTickets, canUnlock, isUnlocked);
                    });

                    grid.appendChild(card);
                });
            },

            showRoleInfoPanel(role, isLocked, currentTickets, canUnlock, isUnlocked) {
                // Remove existing panel if any
                const existingPanel = document.getElementById('role-info-panel');
                if (existingPanel) existingPanel.remove();

                // Create info panel
                const panel = document.createElement('div');
                panel.id = 'role-info-panel';
                panel.style.cssText = `
                    position: fixed;
                    right: 0;
                    top: 0;
                    width: 450px;
                    height: 100%;
                    background: linear-gradient(135deg, rgba(10, 14, 39, 0.98), rgba(5, 8, 20, 0.98));
                    border-left: 3px solid ${role.tierColor || '#00d9ff'};
                    z-index: 11000;
                    padding: 30px;
                    overflow-y: auto;
                    box-shadow: -10px 0 50px rgba(0, 0, 0, 0.8);
                    animation: slideInRight 0.3s ease-out;
                `;

                // Build abilities HTML
                let abilitiesHTML = '';
                if (role.abilities) {
                    role.abilities.forEach((ability, index) => {
                        // Generate image path from ability name (without extension for fallback)
                        const imageName = normalizeImageName(ability.name);
                        const basePath = ability.iconImage ? ability.iconImage.replace(/\.(jpg|jpeg|png)$/i, '') : `assets/${imageName}`;
                        const abilityIconHTML = `<div style="width: 60px; height: 60px; border-radius: 10px; overflow: hidden; border: 2px solid rgba(0, 217, 255, 0.5); box-shadow: 0 0 15px rgba(0, 217, 255, 0.3);">
                            <img src="${basePath}.jpg" alt="${ability.name}" style="width: 100%; height: 100%; object-fit: cover;" onerror="this.onerror=null; this.src='${basePath}.jpeg'; this.onerror=function(){this.style.display='none'; this.parentElement.innerHTML='<div style=\\'font-size: 36px; display: flex; align-items: center; justify-content: center; height: 100%;\\'>${ability.icon}</div>';};">
                           </div>`;

                        abilitiesHTML += `
                            <div style="background: linear-gradient(135deg, rgba(0, 217, 255, 0.1), rgba(255, 0, 110, 0.1)); border: 2px solid rgba(0, 217, 255, 0.3); border-radius: 12px; padding: 15px; margin-bottom: 15px;">
                                <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 10px;">
                                    ${abilityIconHTML}
                                    <div style="flex: 1;">
                                        <div style="color: #00d9ff; font-weight: 800; font-size: 16px; margin-bottom: 3px;">${ability.name}</div>
                                        <div style="color: rgba(224, 231, 255, 0.7); font-size: 12px;">Recarga: ${ability.cooldown / 1000}s | Tecla: ${ability.keyBinding.toUpperCase()}</div>
                                    </div>
                                </div>
                            </div>
                        `;
                    });
                }

                // Ultimate ability
                if (role.ultimateAbility) {
                    // Generate image path from ability name (without extension for fallback)
                    const imageName = normalizeImageName(role.ultimateAbility.name);
                    const basePath = role.ultimateAbility.iconImage ? role.ultimateAbility.iconImage.replace(/\.(jpg|jpeg|png)$/i, '') : `assets/${imageName}`;
                    const ultimateIconHTML = `<div style="width: 70px; height: 70px; border-radius: 12px; overflow: hidden; border: 3px solid rgba(255, 190, 11, 0.7); box-shadow: 0 0 20px rgba(255, 190, 11, 0.5);">
                        <img src="${basePath}.jpg" alt="${role.ultimateAbility.name}" style="width: 100%; height: 100%; object-fit: cover;" onerror="this.onerror=null; this.src='${basePath}.jpeg'; this.onerror=function(){this.style.display='none'; this.parentElement.innerHTML='<div style=\\'font-size: 42px; display: flex; align-items: center; justify-content: center; height: 100%;\\'>${role.ultimateAbility.icon}</div>';};">
                       </div>`;

                    abilitiesHTML += `
                        <div style="background: linear-gradient(135deg, rgba(255, 190, 11, 0.15), rgba(255, 0, 110, 0.15)); border: 3px solid rgba(255, 190, 11, 0.6); border-radius: 12px; padding: 15px; margin-bottom: 15px; box-shadow: 0 0 20px rgba(255, 190, 11, 0.3);">
                            <div style="color: #ffbe0b; font-weight: 900; font-size: 12px; margin-bottom: 10px; letter-spacing: 2px;">? HABILIDAD DEFINITIVA</div>
                            <div style="display: flex; align-items: center; gap: 15px; margin-bottom: 10px;">
                                ${ultimateIconHTML}
                                <div style="flex: 1;">
                                    <div style="color: #ffbe0b; font-weight: 800; font-size: 18px; margin-bottom: 3px;">${role.ultimateAbility.name}</div>
                                    <div style="color: rgba(224, 231, 255, 0.7); font-size: 12px;">Recarga: ${role.ultimateAbility.cooldown / 1000}s | Tecla: ${role.ultimateAbility.keyBinding.toUpperCase()}</div>
                                </div>
                            </div>
                        </div>
                    `;
                }

                // Use defined imagePath or generate from role name (without extension for fallback)
                const basePath = role.imagePath ? role.imagePath.replace(/\.(jpg|jpeg|png)$/i, '') : `assets/${role.name.toLowerCase().replace(/\s+/g, '')}`;

                panel.innerHTML = `
                    <button id="close-info-panel" style="
                        position: absolute;
                        top: 20px;
                        right: 20px;
                        background: rgba(255, 0, 110, 0.2);
                        border: 2px solid #ff006e;
                        color: #ff006e;
                        width: 40px;
                        height: 40px;
                        border-radius: 50%;
                        font-size: 20px;
                        cursor: pointer;
                        transition: all 0.3s;
                        z-index: 10;
                    " onmouseover="this.style.background='#ff006e'; this.style.color='#fff'" onmouseout="this.style.background='rgba(255, 0, 110, 0.2)'; this.style.color='#ff006e'">?</button>

                    <div style="text-align: center; margin-bottom: 30px;">
                        <!-- Class Image -->
                        <div style="width: 100%; height: 220px; margin-bottom: 20px; border-radius: 15px; overflow: hidden; position: relative; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.6); border: 3px solid ${role.tierColor || '#00d9ff'};">
                            <div style="display: none; position: absolute; inset: 0; align-items: center; justify-content: center; font-size: 100px; background: linear-gradient(135deg, rgba(0, 0, 0, 0.7), rgba(${role.tierColor?.replace('#', '').match(/.{2}/g)?.map(x => parseInt(x, 16)).join(',') || '0,217,255'}, 0.3)); filter: drop-shadow(0 0 20px ${role.tierColor || '#00d9ff'}); z-index: 1;">
                                ${role.icon}
                            </div>
                            <img src="${basePath}.jpg" alt="${role.name}" style="width: 100%; height: 100%; object-fit: cover; position: relative; z-index: 2;" onerror="this.onerror=null; this.src='${basePath}.jpeg'; this.onerror=function(){this.style.display='none'; this.previousElementSibling.style.display='flex';};">
                        </div>
                        
                        <h2 style="font-size: 32px; color: ${role.tierColor || '#00d9ff'}; margin-bottom: 10px; font-weight: 900; text-shadow: 0 0 20px ${role.tierColor || '#00d9ff'};">${role.name}</h2>
                        <div style="color: rgba(224, 231, 255, 0.8); font-size: 14px; margin-bottom: 15px; line-height: 1.6;">${role.description}</div>
                        ${role.tier ? `<div style="display: inline-block; background: linear-gradient(135deg, ${role.tierColor}, rgba(${role.tierColor.replace('#', '').match(/.{2}/g).map(x => parseInt(x, 16)).join(',')}, 0.5)); padding: 8px 20px; border-radius: 20px; font-weight: 900; font-size: 16px; color: #fff; box-shadow: 0 5px 15px rgba(0, 0, 0, 0.3);">TIER ${role.tier}</div>` : ''}
                    </div>

                    ${role.ticketsRequired ? `
                        <div style="background: ${isUnlocked ? 'rgba(0, 255, 0, 0.1)' : canUnlock ? 'rgba(255, 215, 0, 0.1)' : 'rgba(255, 0, 0, 0.1)'}; border: 2px solid ${isUnlocked ? '#00ff00' : canUnlock ? '#ffd700' : '#ff0000'}; border-radius: 12px; padding: 15px; margin-bottom: 25px; text-align: center;">
                            <div style="font-size: 14px; color: rgba(224, 231, 255, 0.9); margin-bottom: 8px;">
                                ${isUnlocked ? '? DESBLOQUEADO' : canUnlock ? '? LISTO PARA DESBLOQUEAR' : '?? BLOQUEADO'}
                            </div>
                            <div style="font-size: 24px; color: ${isUnlocked ? '#00ff00' : canUnlock ? '#ffd700' : '#ff0000'}; font-weight: 900;">
                                ${currentTickets} / ${role.ticketsRequired} Tickets
                            </div>
                            ${isLocked ? `<div style="color: rgba(224, 231, 255, 0.7); font-size: 12px; margin-top: 8px;">Necesitas ${role.ticketsRequired - currentTickets} tickets más</div>` : ''}
                            ${canUnlock ? `<div style="color: rgba(255, 215, 0, 0.9); font-size: 12px; margin-top: 8px;">?? íHaz clic en "Desbloquear" para usar esta clase!</div>` : ''}
                            ${isUnlocked ? `<div style="color: rgba(0, 255, 0, 0.8); font-size: 12px; margin-top: 8px;">? Clase desbloqueada y lista para usar</div>` : ''}
                        </div>
                    ` : ''}

                    <div style="margin-bottom: 25px;">
                        <h3 style="color: #00d9ff; font-size: 20px; margin-bottom: 15px; font-weight: 800; text-transform: uppercase; letter-spacing: 2px;">?? Habilidades</h3>
                        ${abilitiesHTML}
                    </div>

                    <button id="equip-role-btn" style="
                        width: 100%;
                        padding: 18px;
                        font-size: 20px;
                        font-weight: 900;
                        background: ${isLocked ? 'linear-gradient(135deg, #666, #444)' : canUnlock ? 'linear-gradient(135deg, #ffd700, #ff8c00)' : 'linear-gradient(135deg, #00d9ff, #ff006e)'};
                        border: none;
                        border-radius: 12px;
                        color: white;
                        cursor: pointer;
                        font-family: 'Orbitron', sans-serif;
                        box-shadow: ${isLocked ? '0 8px 25px rgba(0, 0, 0, 0.5)' : canUnlock ? '0 8px 25px rgba(255, 215, 0, 0.5)' : '0 8px 25px rgba(0, 217, 255, 0.5)'};
                        transition: all 0.3s;
                        letter-spacing: 2px;
                        text-transform: uppercase;
                        ${isLocked ? 'opacity: 0.5; cursor: not-allowed;' : ''}
                    " ${isLocked ? 'disabled' : ''} onmouseover="if(!this.disabled) { this.style.transform='translateY(-3px)'; this.style.boxShadow='0 12px 35px ${canUnlock ? 'rgba(255, 215, 0, 0.7)' : 'rgba(0, 217, 255, 0.7)'}'; }" onmouseout="if(!this.disabled) { this.style.transform='translateY(0)'; this.style.boxShadow='0 8px 25px ${canUnlock ? 'rgba(255, 215, 0, 0.5)' : 'rgba(0, 217, 255, 0.5)'}'; }">
                        ${isLocked ? '?? Bloqueado' : canUnlock ? '?? Desbloquear' : '? Equipar'}
                    </button>
                `;

                // Add CSS animation
                const style = document.createElement('style');
                style.textContent = `
                    @keyframes slideInRight {
                        from {
                            transform: translateX(100%);
                            opacity: 0;
                        }
                        to {
                            transform: translateX(0);
                            opacity: 1;
                        }
                    }
                `;
                document.head.appendChild(style);

                document.body.appendChild(panel);

                // Close button
                document.getElementById('close-info-panel').addEventListener('click', () => {
                    panel.remove();
                });

                // Equip button
                if (!isLocked) {
                    document.getElementById('equip-role-btn').addEventListener('click', () => {
                        // Check if class needs to be unlocked
                        if (role.type === 'class' && role.ticketsRequired) {
                            // Check if already unlocked
                            if (!EquipmentManager.isClassUnlocked(role.id)) {
                                // Check specific class tickets
                                const currentTickets = EquipmentManager.classTickets[role.id] || 0;

                                if (currentTickets < role.ticketsRequired) {
                                    alert(`? Not enough ${role.name} tickets! You need ${role.ticketsRequired} but only have ${currentTickets}.`);
                                    return;
                                }
                                // Unlock the class
                                EquipmentManager.classTickets[role.id] -= role.ticketsRequired;
                                EquipmentManager.unlockClass(role.id);

                                // Update total counter
                                const totalTickets = Object.values(EquipmentManager.classTickets).reduce((a, b) => a + b, 0);
                                document.getElementById('ticket-counter').textContent = totalTickets;

                                EquipmentManager.saveProgress();
                                EquipmentManager.updateStatsDisplay();
                                console.log(`?? Unlocked ${role.name}! Used ${role.ticketsRequired} tickets. Remaining:`, EquipmentManager.classTickets[role.id]);
                                alert(`?? ${role.name} unlocked! You can now equip it anytime.`);
                            }
                        }
                        EquipmentManager.equipRole(role);
                        this.hideRoleSelection();
                        panel.remove();
                    });
                }
            }
        };

        // Event listeners
        // Hamburger Menu Toggle
        const menuToggle = document.getElementById('menu-toggle');
        const sideMenu = document.getElementById('side-menu');
        const menuOverlay = document.getElementById('menu-overlay');

        function openMenu() {
            sideMenu.classList.add('open');
            menuOverlay.classList.add('active');
            menuToggle.classList.add('active');
        }

        function closeMenu() {
            sideMenu.classList.remove('open');
            menuOverlay.classList.remove('active');
            menuToggle.classList.remove('active');
        }

        menuToggle.addEventListener('click', () => {
            if (sideMenu.classList.contains('open')) {
                closeMenu();
            } else {
                openMenu();
            }
        });

        menuOverlay.addEventListener('click', closeMenu);

        // Menu Items
        document.getElementById('menu-raid-btn').addEventListener('click', () => {
            closeMenu();
            if (!MobRaidSystem.active) {
                MobRaidSystem.startRaid();
            }
        });

        document.getElementById('menu-custom-raid-btn').addEventListener('click', () => {
            closeMenu();
            customRaidSelectedMobs.clear();
            customRaidSelectedBosses.clear();
            populateCustomRaidOptions();
            document.getElementById('custom-raid-modal').classList.remove('hidden');
        });

        document.getElementById('menu-practice-btn').addEventListener('click', () => {
            closeMenu();
            PracticeModeManager.enterPracticeMode();
        });

        document.getElementById('menu-loadout-btn').addEventListener('click', () => {
            closeMenu();
            LoadoutManager.openLoadoutModal();
        });

        document.getElementById('menu-class-upgrades-btn').addEventListener('click', () => {
            closeMenu();
            ClassProgressionSystem.showUpgradesModal();
        });

        document.getElementById('menu-update-log-btn').addEventListener('click', () => {
            closeMenu();
            document.getElementById('update-log-modal').classList.remove('hidden');
        });

        document.querySelector('.close-button').addEventListener('click', () => {
            UIManager.hideRoleSelection();
        });

        document.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', () => {
                document.querySelectorAll('.tab-button').forEach(b => b.classList.remove('active'));
                button.classList.add('active');
                UIManager.renderRoleGrid(button.dataset.tab);
            });
        });

        // Update Log Modal - Close button
        document.getElementById('close-update-log').addEventListener('click', () => {
            document.getElementById('update-log-modal').classList.add('hidden');
        });

        // Update Log Navigation
        document.querySelectorAll('.update-item').forEach(item => {
            item.addEventListener('click', () => {
                // Remove active from all items
                document.querySelectorAll('.update-item').forEach(i => {
                    i.classList.remove('active');
                    i.style.background = 'rgba(0, 217, 255, 0.1)';
                    i.style.borderLeftColor = 'transparent';
                });

                // Add active to clicked item
                item.classList.add('active');
                item.style.background = 'rgba(0, 217, 255, 0.2)';
                item.style.borderLeftColor = 'var(--primary)';

                // Hide all content
                document.querySelectorAll('.update-content').forEach(content => {
                    content.style.display = 'none';
                });

                // Show selected content
                const updateId = item.dataset.update;
                const content = document.querySelector(`.update-content[data-update="${updateId}"]`);
                if (content) {
                    content.style.display = 'block';
                }
            });
        });

        // News Video Slider
        let currentVideo = 1;
        const maxVideos = 3;
        let newsInterval;

        function switchNewsVideo(videoNumber) {
            const video = document.getElementById('news-video');
            const source = document.getElementById('news-video-source');
            const dots = document.querySelectorAll('.news-dot');

            // Update video source
            source.src = `assets/video${videoNumber}.mp4`;
            video.load();
            video.play().catch(() => {
                // If video fails to load, try next one
                if (videoNumber < maxVideos) {
                    setTimeout(() => switchNewsVideo(videoNumber + 1), 1000);
                } else {
                    setTimeout(() => switchNewsVideo(1), 1000);
                }
            });

            // Update dots
            dots.forEach((dot, index) => {
                if (index + 1 === videoNumber) {
                    dot.classList.add('active');
                    dot.style.background = 'var(--primary)';
                    dot.style.opacity = '1';
                } else {
                    dot.classList.remove('active');
                    dot.style.background = 'rgba(255, 255, 255, 0.5)';
                    dot.style.opacity = '0.5';
                }
            });

            currentVideo = videoNumber;
        }

        function startNewsSlider() {
            newsInterval = setInterval(() => {
                currentVideo = currentVideo >= maxVideos ? 1 : currentVideo + 1;
                switchNewsVideo(currentVideo);
            }, 10000); // Change video every 10 seconds
        }

        // News video ended event
        document.getElementById('news-video').addEventListener('ended', () => {
            currentVideo = currentVideo >= maxVideos ? 1 : currentVideo + 1;
            switchNewsVideo(currentVideo);
        });

        // News dots click events
        document.querySelectorAll('.news-dot').forEach((dot, index) => {
            dot.addEventListener('click', () => {
                clearInterval(newsInterval);
                switchNewsVideo(index + 1);
                startNewsSlider();
            });
        });

        // Close news slider
        document.getElementById('close-news').addEventListener('click', () => {
            document.getElementById('news-slider').style.display = 'none';
            clearInterval(newsInterval);
        });

        // Start news slider
        startNewsSlider();

        // Custom Raid Modal
        const customRaidSelectedMobs = new Set();
        const customRaidSelectedBosses = new Set();

        function populateCustomRaidOptions() {
            const mobsGrid = document.getElementById('custom-mobs-grid');
            const bossesGrid = document.getElementById('custom-bosses-grid');

            mobsGrid.innerHTML = '';
            bossesGrid.innerHTML = '';

            // Regular mobs
            const regularMobs = [
                { type: 'tornado_apprentice', ...MobRaidSystem.mobTypes.tornado_apprentice },
                { type: 'necromancer', ...MobRaidSystem.mobTypes.necromancer },
                { type: 'fire_drake', ...MobRaidSystem.mobTypes.fire_drake },
                { type: 'water_elemental', ...MobRaidSystem.mobTypes.water_elemental },
                { type: 'ronin_warrior', ...MobRaidSystem.mobTypes.ronin_warrior },
                { type: 'combat_drone', ...MobRaidSystem.mobTypes.combat_drone },
                { type: 'arcane_wisp', ...MobRaidSystem.mobTypes.arcane_wisp },
                { type: 'toxic_zephyr', ...MobRaidSystem.mobTypes.toxic_zephyr },
                { type: 'radioactive_cyclone', ...MobRaidSystem.mobTypes.radioactive_cyclone },
                { type: 'blood_reaver', ...MobRaidSystem.mobTypes.blood_reaver },
                { type: 'axe_thrower', ...MobRaidSystem.mobTypes.axe_thrower },
                { type: 'shadow_assassin', ...MobRaidSystem.mobTypes.shadow_assassin },
                { type: 'smoke_phantom', ...MobRaidSystem.mobTypes.smoke_phantom },
                { type: 'roman_soldier', ...MobRaidSystem.mobTypes.roman_soldier },
                { type: 'praetorian_guard', ...MobRaidSystem.mobTypes.praetorian_guard },
                { type: 'spartan_warrior', ...MobRaidSystem.mobTypes.spartan_warrior },
                { type: 'athenian_hoplite', ...MobRaidSystem.mobTypes.athenian_hoplite },
                { type: 'stone_golem', ...MobRaidSystem.mobTypes.stone_golem },
                { type: 'ancient_sentinel', ...MobRaidSystem.mobTypes.ancient_sentinel },
                { type: 'anubis_jackal', ...MobRaidSystem.mobTypes.anubis_jackal },
                { type: 'anubis_mummy', ...MobRaidSystem.mobTypes.anubis_mummy },
                { type: 'anubis_sphinx', ...MobRaidSystem.mobTypes.anubis_sphinx }
            ];

            regularMobs.forEach(mob => {
                const card = document.createElement('div');
                card.style.cssText = `
                    background: linear-gradient(135deg, rgba(0, 217, 255, 0.1), rgba(255, 0, 110, 0.1));
                    border: 2px solid rgba(0, 217, 255, 0.3);
                    border-radius: 10px;
                    padding: 15px;
                    cursor: pointer;
                    transition: all 0.3s;
                    text-align: center;
                `;
                card.innerHTML = `
                    <div style="font-size: 40px; margin-bottom: 10px;">${mob.icon}</div>
                    <div style="font-weight: bold; color: var(--light); margin-bottom: 5px;">${mob.name}</div>
                    <div style="font-size: 12px; color: var(--primary);">HP: ${mob.hp} | DMG: ${mob.damage}</div>
                    ${mob.dropsTicketFor ? `<div style="font-size: 11px; color: #ffd700; margin-top: 5px;">?? ${mob.dropsTicketFor.replace('class_', '').toUpperCase()}</div>` : ''}
                `;

                card.addEventListener('click', () => {
                    if (customRaidSelectedMobs.has(mob.type)) {
                        customRaidSelectedMobs.delete(mob.type);
                        card.style.border = '2px solid rgba(0, 217, 255, 0.3)';
                        card.style.background = 'linear-gradient(135deg, rgba(0, 217, 255, 0.1), rgba(255, 0, 110, 0.1))';
                    } else {
                        customRaidSelectedMobs.add(mob.type);
                        card.style.border = '2px solid #00ff00';
                        card.style.background = 'linear-gradient(135deg, rgba(0, 255, 0, 0.2), rgba(0, 217, 255, 0.2))';
                    }
                });

                mobsGrid.appendChild(card);
            });

            // Bosses
            const bosses = [
                { type: 'tornado_master', ...MobRaidSystem.mobTypes.tornado_master },
                { type: 'king_of_skeletons', ...MobRaidSystem.mobTypes.king_of_skeletons },
                { type: 'ancient_dragon', ...MobRaidSystem.mobTypes.ancient_dragon },
                { type: 'storm_titan', ...MobRaidSystem.mobTypes.storm_titan },
                { type: 'shogun_lord', ...MobRaidSystem.mobTypes.shogun_lord },
                { type: 'mech_titan', ...MobRaidSystem.mobTypes.mech_titan },
                { type: 'elder_sorcerer', ...MobRaidSystem.mobTypes.elder_sorcerer },
                { type: 'tempest_lord', ...MobRaidSystem.mobTypes.tempest_lord },
                { type: 'warlord_colossus', ...MobRaidSystem.mobTypes.warlord_colossus },
                { type: 'shadow_emperor', ...MobRaidSystem.mobTypes.shadow_emperor },
                { type: 'caesar_imperator', ...MobRaidSystem.mobTypes.caesar_imperator },
                { type: 'leonidas_king', ...MobRaidSystem.mobTypes.leonidas_king },
                { type: 'aether_dragon', ...MobRaidSystem.mobTypes.aether_dragon },
                { type: 'taurha_giant', ...MobRaidSystem.mobTypes.taurha_giant },
                { type: 'anubis_pharaoh', ...MobRaidSystem.mobTypes.anubis_pharaoh },
                { type: 'anubis_colossus', ...MobRaidSystem.mobTypes.anubis_colossus },
                { type: 'anubis_avatar', ...MobRaidSystem.mobTypes.anubis_avatar }
            ];

            bosses.forEach(boss => {
                const card = document.createElement('div');
                card.style.cssText = `
                    background: linear-gradient(135deg, rgba(255, 215, 0, 0.1), rgba(255, 0, 110, 0.1));
                    border: 2px solid rgba(255, 215, 0, 0.3);
                    border-radius: 10px;
                    padding: 15px;
                    cursor: pointer;
                    transition: all 0.3s;
                    text-align: center;
                `;
                card.innerHTML = `
                    <div style="font-size: 40px; margin-bottom: 10px;">${boss.icon}</div>
                    <div style="font-weight: bold; color: #ffd700; margin-bottom: 5px;">${boss.name}</div>
                    <div style="font-size: 12px; color: var(--accent);">HP: ${boss.hp} | DMG: ${boss.damage}</div>
                    ${boss.dropsTicketFor ? `<div style="font-size: 11px; color: #ffd700; margin-top: 5px;">?? ${boss.dropsTicketFor.replace('class_', '').toUpperCase()}</div>` : ''}
                `;

                card.addEventListener('click', () => {
                    if (customRaidSelectedBosses.has(boss.type)) {
                        customRaidSelectedBosses.delete(boss.type);
                        card.style.border = '2px solid rgba(255, 215, 0, 0.3)';
                        card.style.background = 'linear-gradient(135deg, rgba(255, 215, 0, 0.1), rgba(255, 0, 110, 0.1))';
                    } else {
                        customRaidSelectedBosses.add(boss.type);
                        card.style.border = '2px solid #00ff00';
                        card.style.background = 'linear-gradient(135deg, rgba(0, 255, 0, 0.2), rgba(255, 215, 0, 0.2))';
                    }
                });

                bossesGrid.appendChild(card);
            });
        }

        document.getElementById('close-custom-raid').addEventListener('click', () => {
            document.getElementById('custom-raid-modal').classList.add('hidden');
        });

        document.getElementById('cancel-custom-raid-btn').addEventListener('click', () => {
            document.getElementById('custom-raid-modal').classList.add('hidden');
        });

        document.getElementById('start-custom-raid-btn').addEventListener('click', () => {
            if (customRaidSelectedMobs.size === 0 && customRaidSelectedBosses.size === 0) {
                alert('?? Debes seleccionar al menos un mob o jefe!');
                return;
            }

            // Set custom raid configuration
            MobRaidSystem.isCustomRaid = true;
            MobRaidSystem.customMobTypes = Array.from(customRaidSelectedMobs);
            MobRaidSystem.customBossTypes = Array.from(customRaidSelectedBosses);

            // Close modal and start raid directly (no info screen for custom raids)
            document.getElementById('custom-raid-modal').classList.add('hidden');

            // Start raid directly without info screen
            MobRaidSystem.actuallyStartRaid();

            console.log('?? Custom Raid configured:', {
                mobs: MobRaidSystem.customMobTypes,
                bosses: MobRaidSystem.customBossTypes,
                penalty: `${MobRaidSystem.customDropPenalty * 100}%`
            });
        });

        // ===== PLAYER STATUS EFFECTS RENDERER =====
        function renderPlayerStatusEffects(ctx) {
            const canvas = ctx.canvas;
            const effects = [];

            // Collect active positive effects
            if (Player.damageBoost > 0) {
                effects.push({
                    icon: '??',
                    name: 'Daño Aumentado',
                    value: `+${Player.damageBoost}%`,
                    color: '#ffbe0b',
                    time: Math.ceil(Player.damageBoostTime / 1000)
                });
            }

            if (Player.invisible) {
                effects.push({
                    icon: '?',
                    name: 'Invisible',
                    value: 'Invulnerable',
                    color: '#9d4edd',
                    time: Math.ceil(Player.invisibleTime / 1000)
                });
            } else if (Player.invulnerable) {
                effects.push({
                    icon: '???',
                    name: 'Invulnerable',
                    value: '',
                    color: '#00d9ff',
                    time: Math.ceil(Player.invulnerableTime / 1000)
                });
            }

            if (Player.counterActive) {
                effects.push({
                    icon: '??',
                    name: 'Contraataque',
                    value: '',
                    color: '#ff006e',
                    time: Math.ceil(Player.counterTime / 1000)
                });
            }

            if (Player.regenActive) {
                effects.push({
                    icon: '??',
                    name: 'Regeneración',
                    value: `+${Player.regenRate}/s`,
                    color: '#00ff88',
                    time: '8'
                });
            }

            // Collect active negative effects
            if (Player.electrified) {
                effects.push({
                    icon: '?',
                    name: 'Electrificado',
                    value: 'Aturdido',
                    color: '#ffff00',
                    time: Math.ceil(Player.electrifiedTime / 1000),
                    isNegative: true
                });
            }

            if (Player.hasActiveSlowEffect) {
                effects.push({
                    icon: '??',
                    name: 'Ralentizado',
                    value: '-30% Vel',
                    color: '#87ceeb',
                    time: '?',
                    isNegative: true
                });
            }

            if (Player.cursed && Date.now() < Player.curseEndTime) {
                const timeLeft = Math.ceil((Player.curseEndTime - Date.now()) / 1000);
                effects.push({
                    icon: '??',
                    name: 'MALDICIÓN',
                    value: 'x2 Daño',
                    color: '#9370DB',
                    time: timeLeft,
                    isNegative: true,
                    stacks: Player.curseStacks > 1 ? Player.curseStacks : null
                });
            }

            // Render effects at top center of screen
            if (effects.length > 0) {
                const effectWidth = 140;
                const effectHeight = 70;
                const effectSpacing = 10;
                const totalWidth = (effects.length * effectWidth) + ((effects.length - 1) * effectSpacing);
                const startX = (canvas.width - totalWidth) / 2;
                const startY = 100;

                effects.forEach((effect, index) => {
                    const x = startX + (index * (effectWidth + effectSpacing));
                    const y = startY;

                    // Background with pulsing animation
                    const pulse = 1 + Math.sin(Date.now() / 300) * 0.05;
                    ctx.save();
                    ctx.globalAlpha = 0.95;

                    // Background
                    const gradient = ctx.createLinearGradient(x, y, x, y + effectHeight);
                    if (effect.isNegative) {
                        gradient.addColorStop(0, 'rgba(255, 0, 0, 0.3)');
                        gradient.addColorStop(1, 'rgba(139, 0, 0, 0.3)');
                    } else {
                        gradient.addColorStop(0, 'rgba(0, 217, 255, 0.2)');
                        gradient.addColorStop(1, 'rgba(255, 0, 110, 0.2)');
                    }
                    ctx.fillStyle = gradient;
                    ctx.fillRect(x, y, effectWidth, effectHeight);

                    // Border with glow
                    ctx.strokeStyle = effect.color;
                    ctx.lineWidth = 2 * pulse;
                    ctx.shadowColor = effect.color;
                    ctx.shadowBlur = 15 * pulse;
                    ctx.strokeRect(x, y, effectWidth, effectHeight);
                    ctx.shadowBlur = 0;

                    // Icon
                    ctx.font = '32px Arial';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'top';
                    ctx.fillText(effect.icon, x + effectWidth / 2, y + 8);

                    // Stacks (if applicable)
                    if (effect.stacks) {
                        ctx.font = 'bold 14px Arial';
                        ctx.fillStyle = '#ffffff';
                        ctx.strokeStyle = '#000000';
                        ctx.lineWidth = 3;
                        ctx.textAlign = 'right';
                        ctx.strokeText(`x${effect.stacks}`, x + effectWidth - 8, y + 35);
                        ctx.fillText(`x${effect.stacks}`, x + effectWidth - 8, y + 35);
                    }

                    // Name
                    ctx.font = 'bold 12px Arial';
                    ctx.fillStyle = effect.color;
                    ctx.fillText(effect.name, x + effectWidth / 2, y + 42);

                    // Value and time
                    ctx.font = 'bold 10px Arial';
                    ctx.fillStyle = '#ffffff';
                    if (effect.value) {
                        ctx.fillText(effect.value, x + effectWidth / 2, y + 56);
                    }

                    // Time remaining (top right corner)
                    if (effect.time !== '8') {
                        ctx.font = 'bold 14px Arial';
                        ctx.fillStyle = effect.color;
                        ctx.textAlign = 'right';
                        ctx.fillText(`${effect.time}s`, x + effectWidth - 8, y + 8);
                    }

                    ctx.restore();
                });
            }
        }

        // ===== MINIMAP =====
        const minimapCanvas = document.getElementById('minimap');
        const minimapCtx = minimapCanvas.getContext('2d');

        function renderMinimap() {
            const mainCanvas = document.getElementById('game-canvas');
            const scaleX = minimapCanvas.width / mainCanvas.width;
            const scaleY = minimapCanvas.height / mainCanvas.height;

            minimapCtx.fillStyle = 'rgba(10, 14, 39, 0.8)';
            minimapCtx.fillRect(0, 0, minimapCanvas.width, minimapCanvas.height);

            minimapCtx.strokeStyle = 'rgba(0, 217, 255, 0.3)';
            minimapCtx.strokeRect(0, 0, minimapCanvas.width, minimapCanvas.height);

            // Player position
            const playerX = Player.x * scaleX;
            const playerY = Player.y * scaleY;

            const gradient = minimapCtx.createRadialGradient(playerX, playerY, 0, playerX, playerY, 8);
            gradient.addColorStop(0, '#00d9ff');
            gradient.addColorStop(1, '#ff006e');

            minimapCtx.fillStyle = gradient;
            minimapCtx.beginPath();
            minimapCtx.arc(playerX, playerY, 5, 0, Math.PI * 2);
            minimapCtx.fill();

            minimapCtx.strokeStyle = '#fff';
            minimapCtx.lineWidth = 2;
            minimapCtx.stroke();
        }

        // ===== GAME LOOP =====
        let lastTime = 0;
        let frameCount = 0;
        let fpsTime = 0;
        const canvas = document.getElementById('game-canvas');
        const ctx = canvas.getContext('2d');

        // Canvas click handler for practice mode controls
        canvas.addEventListener('click', (e) => {
            if (!PracticeModeManager.active) return;

            const rect = canvas.getBoundingClientRect();
            const scaleX = canvas.width / rect.width;
            const scaleY = canvas.height / rect.height;
            const x = (e.clientX - rect.left) * scaleX;
            const y = (e.clientY - rect.top) * scaleY;

            PracticeModeManager.handleCanvasClick(x, y);
        });

        function gameLoop(currentTime) {
            const deltaTime = currentTime - lastTime;
            lastTime = currentTime;

            // FPS Counter
            frameCount++;
            fpsTime += deltaTime;
            if (fpsTime >= 1000) {
                document.getElementById('fps-counter').textContent = frameCount;
                frameCount = 0;
                fpsTime = 0;
            }

            // Update
            InputHandler.processMovement(deltaTime / 1000);
            InputHandler.processAbilityInputs();
            AbilityManager.updateCooldowns(deltaTime);
            EffectRenderer.updateEffects(deltaTime);
            Player.update(deltaTime);
            MobRaidSystem.update(deltaTime);
            PracticeModeManager.update(deltaTime);

            // Update mobile controls
            if (typeof MobileControlsSystem !== 'undefined') {
                MobileControlsSystem.update(deltaTime);
            }

            // Render
            ctx.clearRect(0, 0, canvas.width, canvas.height);

            // Animated hexagonal grid
            ctx.strokeStyle = 'rgba(0, 217, 255, 0.08)';
            ctx.lineWidth = 1;
            const gridSize = 60;
            const offset = (currentTime / 60) % gridSize;

            for (let x = -offset; x < canvas.width + gridSize; x += gridSize) {
                for (let y = -offset; y < canvas.height + gridSize; y += gridSize) {
                    ctx.beginPath();
                    for (let i = 0; i < 6; i++) {
                        const angle = (Math.PI / 3) * i;
                        const px = x + Math.cos(angle) * 20;
                        const py = y + Math.sin(angle) * 20;
                        if (i === 0) ctx.moveTo(px, py);
                        else ctx.lineTo(px, py);
                    }
                    ctx.closePath();
                    ctx.stroke();
                }
            }

            // Render game objects
            MobRaidSystem.render(ctx);
            Player.render(ctx);
            EffectRenderer.renderEffects(ctx);
            PracticeModeManager.render(ctx);

            // Render player status effects at top of screen
            renderPlayerStatusEffects(ctx);

            // Update minimap
            renderMinimap();

            requestAnimationFrame(gameLoop);
        }

        // ===== INITIALIZATION =====
        async function initGame() {
            const loadingScreen = document.getElementById('loading-screen');
            const loadingProgress = document.querySelector('.loading-progress');
            const loadingPercentage = document.querySelector('.loading-percentage');
            const loadingStatus = document.querySelector('.loading-status');
            const loadingParticles = document.getElementById('loading-particles');
            const loadingVideo = document.querySelector('.loading-image video');

            // Create animated particles
            for (let i = 0; i < 30; i++) {
                const particle = document.createElement('div');
                particle.className = 'loading-particle';
                particle.style.left = `${Math.random() * 100}%`;
                particle.style.animationDelay = `${Math.random() * 3}s`;
                particle.style.animationDuration = `${3 + Math.random() * 2}s`;
                loadingParticles.appendChild(particle);
            }

            const loadingSteps = [
                { progress: 20, status: 'Inicializando sistemas...' },
                { progress: 40, status: 'Cargando clases y personajes...' },
                { progress: 60, status: 'Preparando habilidades...' },
                { progress: 80, status: 'Configurando maestrías...' },
                { progress: 100, status: '¡Listo para la batalla!' }
            ];

            // Load saved progress
            ClassProgressionSystem.init();
            EquipmentManager.loadProgress();
            LoadoutManager.init();
            PracticeModeManager.loadPracticeSettings();

            // Update stats display after both systems have loaded
            EquipmentManager.updateStatsDisplay();

            // Track if loading is complete
            let loadingComplete = false;
            let videoEnded = false;

            // Animate loading with steps
            for (const step of loadingSteps) {
                const currentProgress = parseInt(loadingProgress.style.width) || 0;
                for (let i = currentProgress; i <= step.progress; i++) {
                    loadingProgress.style.width = `${i}%`;
                    loadingPercentage.textContent = `${i}%`;
                    await new Promise(resolve => setTimeout(resolve, 20));
                }
                loadingStatus.textContent = step.status;
                await new Promise(resolve => setTimeout(resolve, 300));
            }

            loadingComplete = true;

            // Wait for video to end if it's still playing
            if (loadingVideo && !loadingVideo.paused && !loadingVideo.ended) {
                loadingStatus.textContent = 'Preparando experiencia épica...';

                // Remove loop attribute so video ends naturally
                loadingVideo.loop = false;

                // Wait for video to end
                await new Promise(resolve => {
                    loadingVideo.addEventListener('ended', () => {
                        videoEnded = true;
                        resolve();
                    }, { once: true });

                    // Fallback timeout in case video doesn't end (max 10 seconds wait)
                    setTimeout(() => {
                        if (!videoEnded) {
                            resolve();
                        }
                    }, 10000);
                });
            }

            // Close loading screen
            setTimeout(() => {
                loadingScreen.classList.add('hidden');
                setTimeout(() => {
                    loadingScreen.style.display = 'none';
                }, 500);
                requestAnimationFrame(gameLoop);
                console.log('⚔️ Wild Destiny: Infinity Source - Ready!');
                console.log('✨ All characters are ORIGINAL - No copyright issues!');
                console.log('🏆 Loadout & Masteries System - Active!');
            }, 400);
        }

        // ===== MOB RAID SYSTEM =====
        const MobRaidSystem = {
            active: false,
            paused: false,
            mobs: [],
            bosses: [],
            projectiles: [],
            wave: 0,
            score: 0,
            isCustomRaid: false,
            customMobTypes: [],
            customBossTypes: [],
            customDropPenalty: 0.05, // 5% penalty (reduced from 10%)
            // NEW v19.11.2025: Attack Indicators System (Telegraphing)
            attackIndicators: [],

            mobTypes: {
                tornado_apprentice: {
                    name: 'Tornado Apprentice',
                    icon: '🌪️',
                    hp: 55, // Buffed +5
                    maxHp: 55,
                    speed: 85, // Slightly faster
                    damage: 12, // Buffed +2
                    color: '#00BFFF', // Deep Sky Blue
                    size: 30,
                    isBoss: false,
                    ability: 'tornado',
                    abilityCooldown: 2800,
                    abilityRange: 320
                },
                necromancer: {
                    name: 'Necromancer',
                    icon: '🧙‍♂️',
                    hp: 70, // Buffed +10
                    maxHp: 70,
                    speed: 75,
                    damage: 18, // Buffed +3
                    color: '#9400D3', // Dark Violet
                    size: 32,
                    isBoss: false,
                    ability: 'summon',
                    abilityCooldown: 4500,
                    abilityRange: 250
                },
                tornado_master: {
                    name: 'Tornado Master',
                    icon: '⚡',
                    hp: 250, // Buffed +50
                    maxHp: 250,
                    speed: 65,
                    damage: 35, // Buffed +5
                    color: '#1E90FF', // Dodger Blue
                    size: 50,
                    isBoss: true,
                    ability: 'tornado',
                    abilityCooldown: 1800,
                    abilityRange: 450
                },
                king_of_skeletons: {
                    name: 'King of Skeletons',
                    icon: '👑',
                    hp: 300, // Buffed +50
                    maxHp: 300,
                    speed: 55,
                    damage: 40, // Buffed +5
                    color: '#FFD700', // Gold
                    size: 60,
                    isBoss: true,
                    ability: 'summon',
                    abilityCooldown: 2500,
                    abilityRange: 300
                },
                fire_drake: {
                    name: 'Fire Drake',
                    icon: '🦎',
                    hp: 90, // Buffed +10
                    maxHp: 90,
                    speed: 70,
                    damage: 25, // Buffed +5
                    color: '#FF4500', // Orange Red
                    size: 35,
                    isBoss: false,
                    ability: 'fireball',
                    abilityCooldown: 3500,
                    abilityRange: 380
                },
                ancient_dragon: {
                    name: 'Ancient Dragon',
                    icon: '🐉',
                    hp: 500, // Buffed +100
                    maxHp: 500,
                    speed: 50,
                    damage: 60, // Buffed +10
                    color: '#8B0000', // Dark Red
                    size: 80, // Larger
                    isBoss: true,
                    ability: 'dragon_rage',
                    abilityCooldown: 4000,
                    abilityRange: 550
                },
                skeleton: {
                    name: 'Skeleton',
                    icon: '💀',
                    hp: 35, // Buffed +15
                    maxHp: 35,
                    speed: 90, // Slightly slower (was 100)
                    damage: 8, // Buffed +3
                    color: '#C0C0C0', // Silver
                    size: 25,
                    isBoss: false,
                    ability: null
                },
                // ELEMENTALIST MOBS
                water_elemental: {
                    name: 'Water Elemental',
                    icon: '💧',
                    hp: 80, // Buffed +10
                    maxHp: 80,
                    speed: 75,
                    damage: 20, // Buffed +2
                    color: '#00FFFF', // Aqua
                    size: 33,
                    isBoss: false,
                    ability: 'water_blast',
                    abilityCooldown: 4000,
                    abilityRange: 320,
                    dropsTicketFor: 'class_elementalist'
                },
                storm_titan: {
                    name: 'Storm Titan',
                    icon: '🌩️',
                    hp: 400, // Buffed +50
                    maxHp: 400,
                    speed: 55,
                    damage: 55, // Buffed +3
                    color: '#FFD700', // Gold
                    size: 70, // Larger
                    isBoss: true,
                    ability: 'lightning_storm',
                    abilityCooldown: 3000,
                    abilityRange: 500,
                    dropsTicketFor: 'class_elementalist',
                    // NEW v19.11.2025: Stationary Boss System
                    isStationaryBoss: true, // This boss stays in center and attacks from there
                    stationaryPosition: 'center-bottom' // 'center' or 'center-bottom'
                },
                // SAMURAI MOBS
                ronin_warrior: {
                    name: 'Ronin Warrior',
                    icon: '👺',
                    hp: 75, // Buffed +10
                    maxHp: 75,
                    speed: 90, // Faster
                    damage: 25, // Buffed +3
                    color: '#DC143C', // Crimson
                    size: 32,
                    isBoss: false,
                    ability: 'quick_slash',
                    abilityCooldown: 3000,
                    abilityRange: 280,
                    dropsTicketFor: 'class_samurai'
                },
                shogun_lord: {
                    name: 'Shogun Lord',
                    icon: '🏯',
                    hp: 350, // Buffed +30
                    maxHp: 350,
                    speed: 65, // Faster
                    damage: 45, // Buffed +3
                    color: '#8B0000', // Dark Red
                    size: 65,
                    isBoss: true,
                    ability: 'blade_dance',
                    abilityCooldown: 3500,
                    abilityRange: 400,
                    dropsTicketFor: 'class_samurai'
                },
                // CYBER GUNSLINGER MOBS
                combat_drone: {
                    name: 'Combat Drone',
                    icon: '🛸',
                    hp: 60, // Buffed +5
                    maxHp: 60,
                    speed: 95, // Faster
                    damage: 20, // Buffed +2
                    color: '#00FFFF', // Cyan
                    size: 30,
                    isBoss: false,
                    ability: 'laser_burst',
                    abilityCooldown: 2800,
                    abilityRange: 350,
                    dropsTicketFor: 'class_gunslinger'
                },
                mech_titan: {
                    name: 'Mech Titan',
                    icon: '🦾',
                    hp: 450, // Buffed +70
                    maxHp: 450,
                    speed: 50,
                    damage: 55, // Buffed +7
                    color: '#32CD32', // Lime Green
                    size: 75,
                    isBoss: true,
                    ability: 'missile_barrage',
                    abilityCooldown: 4000,
                    abilityRange: 500,
                    dropsTicketFor: 'class_gunslinger'
                },
                // MYSTIC SAGE MOBS
                arcane_wisp: {
                    name: 'Arcane Wisp',
                    icon: '✨',
                    hp: 50, // Buffed +5
                    maxHp: 50,
                    speed: 100, // Faster
                    damage: 18, // Buffed +2
                    color: '#9370DB', // Medium Purple
                    size: 28,
                    isBoss: false,
                    ability: 'magic_bolt',
                    abilityCooldown: 2500, // Faster cooldown
                    abilityRange: 350,
                    dropsTicketFor: 'class_mystic'
                },
                elder_sorcerer: {
                    name: 'Elder Sorcerer',
                    icon: '🔮',
                    hp: 360, // Buffed +20
                    maxHp: 360,
                    speed: 60,
                    damage: 48, // Buffed +4
                    color: '#4B0082', // Indigo
                    size: 64,
                    isBoss: true,
                    ability: 'arcane_explosion',
                    abilityCooldown: 3800,
                    abilityRange: 450,
                    dropsTicketFor: 'class_mystic'
                },
                // WIND MASTER MOBS - EXTREMELY ANNOYING AND CHALLENGING
                toxic_zephyr: {
                    name: 'Toxic Zephyr',
                    icon: '🍃',
                    hp: 55, // Buffed +5
                    maxHp: 55,
                    speed: 90, // Buffed speed
                    damage: 12,
                    color: '#32CD32', // Lime Green
                    size: 32,
                    isBoss: false,
                    ability: 'toxic_dash',
                    abilityCooldown: 3500,
                    abilityRange: 380,
                    dropsTicketFor: 'class_wind_master',
                    // Special traits
                    dashSpeed: 220,
                    evasionChance: 0.15, // Buffed evasion
                    pullStrength: 0.35
                },
                radioactive_cyclone: {
                    name: 'Radioactive Cyclone',
                    icon: '☢️',
                    hp: 70, // Buffed +10
                    maxHp: 70,
                    speed: 80, // Buffed speed
                    damage: 15, // Buffed +3
                    color: '#7FFF00', // Chartreuse
                    size: 34,
                    isBoss: false,
                    ability: 'radiation_pulse',
                    abilityCooldown: 4500,
                    abilityRange: 350,
                    dropsTicketFor: 'class_wind_master',
                    // Special traits
                    constantRadiation: true,
                    pullEffect: true,
                    pullStrength: 0.45
                },
                tempest_lord: {
                    name: 'Tempest Lord',
                    icon: '🌪️',
                    hp: 300, // Buffed +30
                    maxHp: 300,
                    speed: 55, // Buffed speed
                    damage: 32, // Buffed +4
                    color: '#2E8B57', // Sea Green
                    size: 75,
                    isBoss: true,
                    ability: 'tempest_fury',
                    abilityCooldown: 6000,
                    abilityRange: 480,
                    dropsTicketFor: 'class_wind_master',
                    // Special boss traits
                    phaseShift: true,
                    windBarrier: true, // Reflects damage
                    summonMinions: false,
                    enrageThreshold: 0.15,
                    // NEW v19.11.2025: Stationary Boss System
                    isStationaryBoss: true, // This boss stays in center and attacks from there
                    stationaryPosition: 'center' // 'center' or 'center-bottom'
                },
                // WILD BERSERKER MOBS - BRUTAL AND AGGRESSIVE
                blood_reaver: {
                    name: 'Blood Reaver',
                    icon: '🩸',
                    hp: 85, // Buffed +10
                    maxHp: 85,
                    speed: 75, // Faster
                    damage: 28, // Buffed +4
                    color: '#B22222', // Firebrick
                    size: 34,
                    isBoss: false,
                    ability: 'blood_frenzy',
                    abilityCooldown: 3800,
                    abilityRange: 250,
                    dropsTicketFor: 'class_berserker',
                    // Special traits
                    enrageOnLowHp: true,
                    lifeSteal: 0.20 // Buffed lifesteal
                },
                axe_thrower: {
                    name: 'Axe Thrower',
                    icon: '🪓',
                    hp: 65, // Buffed +5
                    maxHp: 65,
                    speed: 70, // Faster
                    damage: 22, // Buffed +2
                    color: '#D2691E', // Chocolate
                    size: 32,
                    isBoss: false,
                    ability: 'axe_throw',
                    abilityCooldown: 3200,
                    abilityRange: 420,
                    dropsTicketFor: 'class_berserker',
                    // Special traits
                    rangedAttacker: true,
                    axeCount: 3
                },
                warlord_colossus: {
                    name: 'Warlord Colossus',
                    icon: '👹',
                    hp: 480, // Buffed +60
                    maxHp: 480,
                    speed: 0, // STATIONARY BOSS
                    damage: 65, // Buffed +10
                    color: '#800000', // Maroon
                    size: 85,
                    isBoss: true,
                    ability: 'ground_slam',
                    abilityCooldown: 4500,
                    abilityRange: 650,
                    dropsTicketFor: 'class_berserker',
                    // Special boss traits
                    isStationaryBoss: true,
                    stationaryPosition: 'center',
                    intimidating: true,
                    armorPlating: 0.25, // Buffed armor
                    rageMeter: 0,
                    summonMinions: true
                },
                // SHADOW NINJA MOBS - STEALTHY AND DECEPTIVE
                shadow_assassin: {
                    name: 'Shadow Assassin',
                    icon: '🥷',
                    hp: 60, // Buffed +10
                    maxHp: 60,
                    speed: 105, // Faster
                    damage: 32, // Buffed +4
                    color: '#1A1A1A', // Very Dark Grey
                    size: 30,
                    isBoss: false,
                    ability: 'shadow_strike',
                    abilityCooldown: 4000,
                    abilityRange: 280,
                    dropsTicketFor: 'class_ninja',
                    // Special traits
                    stealthMode: true,
                    criticalStrike: 0.35, // Buffed crit
                    evasionChance: 0.30 // Buffed evasion
                },
                smoke_phantom: {
                    name: 'Smoke Phantom',
                    icon: '🌫️',
                    hp: 65, // Buffed +10
                    maxHp: 65,
                    speed: 90, // Faster
                    damage: 25, // Buffed +3
                    color: '#696969', // Dim Grey
                    size: 32,
                    isBoss: false,
                    ability: 'smoke_bomb',
                    abilityCooldown: 4500,
                    abilityRange: 400,
                    dropsTicketFor: 'class_ninja',
                    // Special traits
                    leavesSmoke: true,
                    teleportChance: 0.25 // Buffed teleport
                },
                shadow_emperor: {
                    name: 'Shadow Emperor',
                    icon: '🌑',
                    hp: 420, // Buffed +40
                    maxHp: 420,
                    speed: 0, // STATIONARY BOSS
                    damage: 55, // Buffed +5
                    color: '#000000', // Black
                    size: 80,
                    isBoss: true,
                    ability: 'shadow_realm',
                    abilityCooldown: 5500,
                    abilityRange: 600,
                    dropsTicketFor: 'class_ninja',
                    // Special boss traits
                    isStationaryBoss: true,
                    stationaryPosition: 'center',
                    intimidating: true,
                    shadowClones: true,
                    phaseShift: true,
                    darkAura: true,
                    summonMinions: true
                },
                // ROMAN LEGIONARY MOBS - EVENTO ESPECIAL: CIVILIZACIONES HISTÓRICAS
                roman_soldier: {
                    name: 'Soldado Romano',
                    icon: '🛡️',
                    hp: 100, // Buffed +15
                    maxHp: 100,
                    speed: 80, // Faster
                    damage: 25, // Buffed +3
                    color: '#DC143C', // Crimson
                    size: 34,
                    isBoss: false,
                    ability: 'gladius_strike',
                    abilityCooldown: 3500,
                    abilityRange: 220,
                    dropsTicketFor: 'class_roman_legionary',
                    // Special traits
                    shieldBlock: true, // 25% chance to block attacks
                    formationBonus: true
                },
                praetorian_guard: {
                    name: 'Guardia Pretoriana',
                    icon: '💂',
                    hp: 140, // Buffed +20
                    maxHp: 140,
                    speed: 75, // Faster
                    damage: 32, // Buffed +4
                    color: '#800080', // Purple
                    size: 38,
                    isBoss: false,
                    ability: 'testudo_defense',
                    abilityCooldown: 4500,
                    abilityRange: 280,
                    dropsTicketFor: 'class_roman_legionary',
                    // Special traits
                    eliteGuard: true,
                    shieldWall: true,
                    counterAttack: true
                },
                caesar_imperator: {
                    name: 'César Imperator',
                    icon: '👑',
                    hp: 500, // Buffed +50
                    maxHp: 500,
                    speed: 70, // Faster
                    damage: 65, // Buffed +10
                    color: '#FFD700', // Gold
                    size: 85,
                    isBoss: true,
                    ability: 'imperial_command',
                    abilityCooldown: 4000,
                    abilityRange: 550,
                    dropsTicketFor: 'class_roman_legionary',
                    // Special boss traits
                    isStationaryBoss: false,
                    commandAura: true,
                    summonLegions: true,
                    imperialShield: true,
                    goldenAura: true,
                    tacticalGenius: true
                },
                // SPARTAN HOPLITE MOBS - EVENTO ESPECIAL: CIVILIZACIONES HISTÓRICAS - GRECIA
                spartan_warrior: {
                    name: 'Guerrero Espartano',
                    icon: '???',
                    hp: 85,
                    maxHp: 85,
                    speed: 75,
                    damage: 28,
                    color: '#8B0000', // Rojo espartano
                    size: 38,
                    isBoss: false,
                    ability: 'shield_bash',
                    abilityCooldown: 4000,
                    abilityRange: 250,
                    dropsTicketFor: 'class_spartan_hoplite',
                    // Special traits
                    spartanDiscipline: true, // Never retreats, fights to the death
                    phalanxFormation: true // Gets stronger when near other Spartans
                },
                athenian_hoplite: {
                    name: 'Hoplita Ateniense',
                    icon: '??',
                    hp: 95,
                    maxHp: 95,
                    speed: 70,
                    damage: 32,
                    color: '#4169E1', // Azul ateniense
                    size: 42,
                    isBoss: false,
                    ability: 'spear_thrust',
                    abilityCooldown: 3500,
                    abilityRange: 300,
                    dropsTicketFor: 'class_spartan_hoplite',
                    // Special traits
                    tacticalMind: true, // Uses strategic positioning
                    hoplonDefense: true // Strong shield defense
                },
                leonidas_king: {
                    name: 'Rey Leónidas',
                    icon: '??',
                    hp: 500,
                    maxHp: 500,
                    speed: 70,
                    damage: 60,
                    color: '#8B0000', // Rojo espartano
                    size: 85,
                    isBoss: true,
                    ability: 'spartan_rage',
                    abilityCooldown: 4000,
                    abilityRange: 450,
                    dropsTicketFor: 'class_spartan_hoplite',
                    // Special boss traits
                    isStationaryBoss: false,
                    kingOfSparta: true, // Inspires all nearby Greek mobs (+30% damage)
                    thermopylaeStand: true, // Gets stronger as HP decreases
                    spartanFury: true, // Enrages at 30% HP
                    legendaryLeader: true, // Summons Spartan Warriors periodically
                    unyielding: true // Cannot be stunned or slowed
                },

                // ===== LEGENDARY BOSSES =====
                aether_dragon: {
                    name: 'Dragón del Éter',
                    icon: '??',
                    hp: 650,
                    maxHp: 650,
                    speed: 55,
                    damage: 70,
                    color: '#9370DB', // Púrpura místico
                    size: 90,
                    isBoss: true,
                    ability: 'aether_abilities',
                    abilityCooldown: 3500,
                    abilityRange: 500,
                    dropsTicketFor: 'class_mystic', // Drops Mystic ticket
                    // Special Aether Dragon traits
                    isLegendaryBoss: true,
                    deathRayCharging: false,
                    deathRayCharged: false,
                    deathRayTarget: null,
                    etherExplosionCharging: false,
                    cursedBarrierActive: false,
                    cursedBarrierAngle: 0,
                    destructionPhaseActive: false,
                    destructionShieldActive: false,
                    summonedMinions: [],
                    lastAbilityUsed: null,
                    abilityRotation: 0
                },

                // ===== ANCIENT RUINS MOBS =====
                stone_golem: {
                    name: 'Gólem de Piedra',
                    icon: '??',
                    hp: 100,
                    maxHp: 100,
                    speed: 60,
                    damage: 30,
                    color: '#A0826D',
                    size: 40,
                    isBoss: false,
                    ability: 'rock_throw',
                    abilityCooldown: 4500,
                    abilityRange: 300,
                    dropsTicketFor: 'ancient-guardian',
                    // Special traits
                    stoneArmor: true, // Reduces damage taken by 20%
                    earthquakeStep: true // Causes small tremors when moving
                },
                ancient_sentinel: {
                    name: 'Centinela Ancestral',
                    icon: '??',
                    hp: 110,
                    maxHp: 110,
                    speed: 70,
                    damage: 35,
                    color: '#CD853F',
                    size: 42,
                    isBoss: false,
                    ability: 'ancient_curse',
                    abilityCooldown: 5000,
                    abilityRange: 250,
                    dropsTicketFor: 'ancient-guardian',
                    // Special traits
                    ancientWisdom: true, // Predicts player movement
                    runicShield: true // Periodic shield that blocks one attack
                },

                taurha_giant: {
                    name: 'Taurha',
                    icon: '???',
                    hp: 800,
                    maxHp: 800,
                    speed: 40,
                    damage: 80,
                    color: '#8B7355', // Color piedra/ruinas
                    size: 95,
                    isBoss: true,
                    ability: 'taurha_abilities',
                    abilityCooldown: 4000,
                    abilityRange: 600,
                    dropsTicketFor: 'ancient-guardian',
                    // Special Taurha traits
                    isLegendaryBoss: true,
                    level: 20, // Fixed level 20
                    columnWeapon: true,
                    lastAbilityUsed: null,
                    abilityRotation: 0,
                    acidCracks: [],
                    swingCount: 0
                },
                // ANUBIS GUARDIAN MOBS - Egyptian themed
                anubis_jackal: {
                    name: 'Chacal del Duat',
                    icon: '🐺',
                    color: '#FFD700',
                    hp: 180,
                    maxHp: 180,
                    speed: 65, // Fast mob
                    damage: 35,
                    size: 35,
                    isBoss: false,
                    ability: 'sand_dash',
                    abilityCooldown: 3800,
                    abilityRange: 300,
                    dropsTicketFor: 'class_anubis',
                    // Special traits
                    sandDash: true, // Dashes through sand leaving trail
                    goldAura: true // Leaves golden particles
                },
                anubis_mummy: {
                    name: 'Momia Guardiana',
                    icon: '🧟',
                    color: '#DEB887',
                    hp: 220,
                    maxHp: 220,
                    speed: 35, // Slow mob
                    damage: 45,
                    size: 40,
                    isBoss: false,
                    ability: 'curse_touch',
                    abilityCooldown: 4500,
                    abilityRange: 250,
                    dropsTicketFor: 'class_anubis',
                    // Special traits
                    cursedTouch: true, // Slows player on hit
                    regenerates: true // Slowly regenerates HP
                },
                anubis_sphinx: {
                    name: 'Esfinge Menor',
                    icon: '🦁',
                    color: '#CD853F',
                    hp: 280,
                    maxHp: 280,
                    speed: 50, // Medium speed
                    damage: 50,
                    size: 50,
                    isBoss: false,
                    ability: 'riddle_blast',
                    abilityCooldown: 5000,
                    abilityRange: 400,
                    dropsTicketFor: 'class_anubis',
                    // Special traits
                    riddleAttack: true, // Confuses player controls briefly
                    stoneGaze: true // Slows enemies in cone
                },
                // ANUBIS BOSSES
                anubis_pharaoh: {
                    name: 'Faraón Maldito',
                    icon: '👑',
                    color: '#FFD700',
                    hp: 1200,
                    maxHp: 1200,
                    speed: 45, // Medium boss speed
                    damage: 70,
                    size: 65,
                    isBoss: true,
                    ability: 'pharaoh_curse',
                    abilityCooldown: 4000,
                    abilityRange: 450,
                    dropsTicketFor: 'class_anubis',
                    // Special boss traits
                    isStationaryBoss: false,
                    summonsMummies: true, // Summons 2 mummies every 15s
                    plagueCurse: true, // Applies stacking curse debuff
                    goldShield: true // 30% damage reduction
                },
                anubis_colossus: {
                    name: 'Coloso de Anubis',
                    icon: '🗿',
                    color: '#8B7355',
                    hp: 1800,
                    maxHp: 1800,
                    speed: 30, // Slow but stationary
                    damage: 90,
                    size: 80,
                    isBoss: true,
                    ability: 'anubis_judgment',
                    abilityCooldown: 5000,
                    abilityRange: 500,
                    dropsTicketFor: 'class_anubis',
                    // Special boss traits
                    isStationaryBoss: true,
                    stationaryPosition: 'center',
                    massiveSize: true, // Larger hitbox
                    earthquakeStomps: true, // Creates shockwaves when moving
                    ancientPower: true // Increases damage over time
                },
                anubis_avatar: {
                    name: 'Avatar de Anubis',
                    icon: '☥',
                    color: '#00CED1',
                    hp: 2500,
                    maxHp: 2500,
                    speed: 55, // Fast legendary boss
                    damage: 100,
                    size: 90,
                    isBoss: true,
                    ability: 'divine_wrath',
                    abilityCooldown: 3500,
                    abilityRange: 600,
                    dropsTicketFor: 'class_anubis',
                    // Special legendary boss traits
                    isLegendaryBoss: true,
                    level: 22, // Fixed level 22
                    portalSummon: true, // Opens portals that spawn enemies
                    soulWeighing: true, // Executes low HP enemies instantly
                    divineForm: true, // Transforms at 50% HP
                    lastAbilityUsed: null,
                    abilityRotation: 0
                }
            },

            startRaid() {
                // Show mob info screen first
                this.showMobInfo();
            },

            actuallyStartRaid() {
                this.active = true;
                this.mobs = [];
                this.bosses = [];
                this.projectiles = [];
                this.wave = 1;
                this.score = 0;
                this.paused = false;
                Player.hp = Player.maxHp;

                this.spawnWave();
                console.log('?? Raid Started! Press Z to pause. Boss every 5 waves!');
            },

            stopRaid(playerDied = false) {
                this.active = false;
                this.mobs = [];
                this.bosses = [];
                this.projectiles = [];
                this.paused = false;

                // Reset custom raid settings
                this.isCustomRaid = false;
                this.customMobTypes = [];
                this.customBossTypes = [];

                // NEW v19.11.2025: Complete scene cleanup
                // Clear all toxic bubbles
                if (this.toxicBubbles) {
                    this.toxicBubbles = [];
                }

                // Clear all floating texts
                if (this.floatingTexts) {
                    this.floatingTexts = [];
                }

                // Reset Player state completely
                Player.speed = Player.baseSpeed;
                Player.hasActiveSlowEffect = false;
                Player.radioactiveDamageBuff = 0;
                Player.damageBoost = 0;
                Player.invulnerable = false;
                Player.counterActive = false;
                Player.regenActive = false;

                // Clear any lingering visual effects from canvas
                const canvas = document.getElementById('game-canvas');
                const ctx = canvas.getContext('2d');
                ctx.clearRect(0, 0, canvas.width, canvas.height);

                // Exit fullscreen
                if (document.exitFullscreen) {
                    document.exitFullscreen().catch(err => console.log('Exit fullscreen failed:', err));
                } else if (document.webkitExitFullscreen) {
                    document.webkitExitFullscreen();
                } else if (document.msExitFullscreen) {
                    document.msExitFullscreen();
                }

                // Raid stopped - no button to update anymore (using menu now)

                if (playerDied) {
                    console.log('?? Raid ended - Player died! Scene cleaned.');
                } else {
                    console.log('?? Raid Stopped - Scene cleaned for next raid.');
                }
            },

            showMobInfo() {
                const fontLink = document.createElement('link');
                fontLink.href = 'https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@300;400;500;600;700&family=Rajdhani:wght@300;400;500;600;700&display=swap';
                fontLink.rel = 'stylesheet';
                document.head.appendChild(fontLink);

                const infoScreen = document.createElement('div');
                infoScreen.id = 'mob-info-screen';

                const style = document.createElement('style');
                style.textContent = `
                    #mob-info-screen { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: #050810; z-index: 10000; display: flex; font-family: 'Rajdhani', sans-serif; overflow: hidden; opacity: 0; transition: opacity 0.3s; }
                    #mob-info-screen.visible { opacity: 1; }
                    .raid-sidebar { width: 300px; background: rgba(10, 15, 30, 0.95); border-right: 1px solid rgba(255, 255, 255, 0.1); display: flex; flex-direction: column; overflow-y: auto; backdrop-filter: blur(10px); }
                    .raid-header-logo { padding: 30px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); text-align: center; }
                    .raid-header-logo h1 { font-family: 'Chakra Petch', sans-serif; font-size: 32px; margin: 0; background: linear-gradient(45deg, #00d9ff, #0056b3); -webkit-background-clip: text; -webkit-text-fill-color: transparent; font-weight: 700; letter-spacing: 2px; }
                    .raid-header-logo p { font-size: 10px; text-transform: uppercase; letter-spacing: 4px; color: rgba(255, 255, 255, 0.4); margin-top: 5px; }
                    .raid-menu { padding: 20px; flex: 1; }
                    .raid-menu-item { display: flex; align-items: center; padding: 15px; margin-bottom: 10px; border-radius: 8px; cursor: pointer; transition: all 0.2s; border: 1px solid transparent; }
                    .raid-menu-item:hover { background: rgba(255, 255, 255, 0.03); transform: translateX(5px); }
                    .raid-menu-item.active { background: linear-gradient(90deg, rgba(0, 217, 255, 0.1), transparent); border-left: 3px solid currentColor; }
                    .raid-menu-icon { width: 40px; height: 40px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 20px; margin-right: 15px; background: rgba(255, 255, 255, 0.05); }
                    .raid-menu-info h3 { margin: 0; font-size: 16px; font-weight: 600; text-transform: uppercase; }
                    .raid-menu-info p { margin: 3px 0 0; font-size: 11px; color: rgba(255, 255, 255, 0.4); }
                    .raid-main { flex: 1; display: flex; flex-direction: column; position: relative; background: radial-gradient(ellipse at top right, rgba(0, 217, 255, 0.05), transparent 70%); }
                    .close-btn { position: absolute; top: 20px; right: 20px; width: 40px; height: 40px; border-radius: 50%; background: rgba(255, 255, 255, 0.05); display: flex; align-items: center; justify-content: center; cursor: pointer; transition: all 0.2s; z-index: 10; border: 1px solid rgba(255, 255, 255, 0.1); }
                    .close-btn:hover { background: rgba(255, 0, 0, 0.2); border-color: rgba(255, 0, 0, 0.5); transform: rotate(90deg); }
                    .mob-content-area { flex: 1; padding: 40px; overflow-y: auto; scrollbar-width: thin; scrollbar-color: #00d9ff rgba(0,0,0,0.3); }
                    .raid-banner { padding: 40px; border-radius: 20px; background: linear-gradient(135deg, rgba(255, 255, 255, 0.03), transparent); border: 1px solid rgba(255, 255, 255, 0.05); margin-bottom: 40px; position: relative; overflow: hidden; }
                    .raid-banner::before { content: ''; position: absolute; top: 0; left: 0; width: 4px; height: 100%; background: currentColor; box-shadow: 0 0 20px currentColor; }
                    .raid-banner h2 { font-family: 'Chakra Petch', sans-serif; font-size: 48px; margin: 0 0 20px; text-transform: uppercase; font-weight: 700; letter-spacing: 2px; text-shadow: 0 0 30px rgba(0,0,0,0.5); }
                    .raid-controls { display: flex; gap: 30px; padding-top: 20px; border-top: 1px solid; }
                    .raid-stat { display: flex; flex-direction: column; gap: 5px; }
                    .raid-stat span:first-child { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: rgba(255, 255, 255, 0.4); }
                    .raid-stat span:last-child { font-size: 16px; font-weight: 600; }
                    .section-divider { display: flex; align-items: center; gap: 20px; margin: 40px 0 20px; }
                    .section-line { flex: 1; height: 1px; background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent); }
                    .section-title { font-size: 14px; font-weight: 600; letter-spacing: 2px; color: #00d9ff; padding: 5px 15px; border: 1px solid rgba(0, 217, 255, 0.3); border-radius: 20px; background: rgba(0, 217, 255, 0.05); }
                    .mobs-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 20px; }
                    .mob-card { background: rgba(255, 255, 255, 0.02); border: 1px solid rgba(255, 255, 255, 0.05); border-radius: 12px; padding: 20px; transition: all 0.3s; position: relative; overflow: hidden; }
                    .mob-card:hover { transform: translateY(-5px); background: rgba(255, 255, 255, 0.05); border-color: currentColor; box-shadow: 0 10px 30px -10px rgba(0,0,0,0.5); }
                    .mob-card-icon { font-size: 48px; text-align: center; margin-bottom: 15px; filter: drop-shadow(0 0 10px currentColor); }
                    .mob-card h3 { text-align: center; margin: 0 0 15px; font-size: 18px; font-weight: 600; color: white; }
                    .mob-stats { background: rgba(0, 0, 0, 0.3); border-radius: 8px; padding: 10px; font-size: 12px; }
                    .stat-row { display: flex; justify-content: space-between; margin-bottom: 5px; }
                    .stat-row:last-child { margin-bottom: 0; }
                    .stat-label { color: rgba(255, 255, 255, 0.5); }
                    .ticket-badge { margin-top: 15px; padding: 8px; text-align: center; border: 1px solid; border-radius: 6px; font-size: 10px; font-weight: 700; letter-spacing: 1px; }
                    .boss-highlight { grid-column: span 2; display: grid; grid-template-columns: auto 1fr; gap: 20px; align-items: center; background: linear-gradient(135deg, rgba(255, 215, 0, 0.05), transparent); border: 1px solid rgba(255, 215, 0, 0.2); }
                    .boss-highlight .mob-card-icon { font-size: 80px; margin: 0; }
                    .boss-highlight h3 { text-align: left; font-size: 24px; margin-bottom: 10px; }
                    .boss-highlight .mob-stats { grid-column: 2; }
                    .boss-highlight .ticket-badge { grid-column: 1 / -1; margin-top: 0; }
                    .boss-tag { position: absolute; top: 10px; right: 10px; background: #ffd700; color: black; font-size: 9px; font-weight: 900; padding: 2px 6px; border-radius: 4px; }
                    .raid-footer { padding: 20px 40px; border-top: 1px solid rgba(255, 255, 255, 0.1); display: flex; justify-content: space-between; align-items: center; background: rgba(10, 15, 30, 0.9); }
                    .start-btn { padding: 15px 40px; background: linear-gradient(135deg, #00d9ff, #0056b3); border: none; border-radius: 8px; color: white; font-family: 'Chakra Petch', sans-serif; font-weight: 700; font-size: 18px; letter-spacing: 2px; cursor: pointer; transition: all 0.3s; display: flex; align-items: center; gap: 10px; text-transform: uppercase; box-shadow: 0 0 20px rgba(0, 217, 255, 0.3); }
                    .start-btn:hover { transform: scale(1.05); box-shadow: 0 0 40px rgba(0, 217, 255, 0.5); }
                    .start-btn svg { width: 24px; height: 24px; }
                    .raid-info-text { font-size: 12px; color: rgba(255, 255, 255, 0.5); letter-spacing: 2px; display: flex; align-items: center; gap: 10px; }
                    .rec-classes { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 20px; }
                    .rec-tag { font-size: 10px; padding: 4px 8px; border: 1px solid; border-radius: 4px; font-weight: 600; }
                `;
                infoScreen.appendChild(style);

                setTimeout(() => infoScreen.classList.add('visible'), 10);

                // Group mobs by class for better organization
                const mobsByClass = {
                    'Dragonhunter': {
                        color: '#ff4500',
                        mobs: ['fire_drake'],
                        bosses: ['ancient_dragon'],
                        recommendedClasses: ['??? Roman Legionary', '?? Spartan Hoplite', '?? Dragonhunter']
                    },
                    'Elementalist': {
                        color: '#00d9ff',
                        mobs: ['water_elemental'],
                        bosses: ['storm_titan'],
                        recommendedClasses: ['?? Elementalist', '?? Aquamancer', '? Storm Caller']
                    },
                    'Samurai': {
                        color: '#ff006e',
                        mobs: ['ronin_warrior'],
                        bosses: ['shogun_lord'],
                        recommendedClasses: ['?? Samurai', '?? Shadow Ninja', '??? Blade Master']
                    },
                    'Gunslinger': {
                        color: '#00ffff',
                        mobs: ['combat_drone'],
                        bosses: ['mech_titan'],
                        recommendedClasses: ['?? Cyber Gunslinger', '?? Cybernetic Warlord', '?? Tech Specialist']
                    },
                    'Mystic': {
                        color: '#9370db',
                        mobs: ['arcane_wisp'],
                        bosses: ['elder_sorcerer'],
                        recommendedClasses: ['? Mystic', '?? Arcane Mage', '?? Celestial Sorcerer']
                    },
                    'Wind Master': {
                        color: '#39ff14',
                        mobs: ['toxic_zephyr', 'radioactive_cyclone'],
                        bosses: ['tempest_lord'],
                        recommendedClasses: ['?? Wind Master', '??? Storm Weaver', '? Lightning Caller']
                    },
                    'Wild Berserker': {
                        color: '#8b0000',
                        mobs: ['blood_reaver', 'axe_thrower'],
                        bosses: ['warlord_colossus'],
                        recommendedClasses: ['?? Wild Berserker', '?? Spartan Hoplite', '??? Roman Legionary']
                    },
                    'Shadow Ninja': {
                        color: '#2f2f2f',
                        mobs: ['shadow_assassin', 'smoke_phantom'],
                        bosses: ['shadow_emperor'],
                        recommendedClasses: ['?? Shadow Ninja', '? Abyssal Shadowlord', '??? Assassin']
                    },
                    'General': {
                        color: '#ffffff',
                        mobs: ['tornado_apprentice', 'necromancer'],
                        bosses: ['tornado_master', 'king_of_skeletons'],
                        recommendedClasses: ['?? Todas las Clases', '??? Clases Tanque', '?? Clases DPS']
                    },
                    'Aether Realm': {
                        color: '#9370DB',
                        mobs: ['arcane_wisp', 'shadow_assassin'],
                        bosses: ['aether_dragon'],
                        recommendedClasses: ['? Mystic', '?? Shadow Ninja', '? Abyssal Shadowlord']
                    },
                    'Ancient Ruins': {
                        color: '#8B7355',
                        mobs: ['stone_golem', 'ancient_sentinel'],
                        bosses: ['taurha_giant'],
                        recommendedClasses: ['??? Ancient Guardian', '??? Clases Tanque', '?? Clases de Alto Dao']
                    }
                };



                // Chunk 1 deleted

                // Deleted 34-35

                // Chunk 3 deleted
                // Deleted 39

                // Create Layout
                const sidebar = document.createElement('div');
                sidebar.className = 'raid-sidebar';
                sidebar.innerHTML = `
                    <div class="raid-header-logo">
                        <h1>RAID OPS</h1>
                        <p>Command Center</p>
                    </div>
                    <div class="raid-menu" id="raid-menu-list"></div>
                `;

                const mainArea = document.createElement('div');
                mainArea.className = 'raid-main';
                mainArea.innerHTML = `
                    <div class="close-btn" id="close-raid-ui">?</div>
                    <div class="mob-content-area" id="mob-content-area"></div>
                    <div class="raid-footer">
                        <div class="raid-info-text">
                            <span style="display:inline-block; width:8px; height:8px; background:#00ff00; border-radius:50%; box-shadow:0 0 5px #00ff00"></span>
                            SYSTEM READY
                        </div>
                        <button class="start-btn" id="start-raid-btn">
                            ?? INICIAR RAID
                        </button>
                    </div>
                `;

                infoScreen.appendChild(sidebar);
                infoScreen.appendChild(mainArea);
                document.body.appendChild(infoScreen);

                setTimeout(() => infoScreen.classList.add('visible'), 10);

                // --- Logic --- //
                const menuList = sidebar.querySelector('#raid-menu-list');
                const contentArea = mainArea.querySelector('#mob-content-area');
                let currentCategory = Object.keys(mobsByClass)[0];

                // Render Menu Items
                const renderMenu = () => {
                    menuList.innerHTML = Object.keys(mobsByClass).map(className => {
                        const data = mobsByClass[className];
                        const firstMob = data.mobs[0];
                        const mobDef = this.mobTypes[firstMob] || {};
                        const icon = mobDef.icon || '??';
                        const isActive = className === currentCategory;

                        return `
                            <div class="raid-menu-item ${isActive ? 'active' : ''}" data-category="${className}" style="color: ${data.color}">
                                <div class="raid-menu-icon" style="${isActive ? `background: ${data.color}; color: white;` : `color: ${data.color}; background: rgba(0,0,0,0.3);`}">
                                    <div>${icon}</div>
                                </div>
                                <div class="raid-menu-info">
                                    <h3>${className}</h3>
                                    <p>${data.mobs.length} Hostiles | ${data.bosses.length} Boss</p>
                                </div>
                            </div>
                        `;
                    }).join('');

                    menuList.querySelectorAll('.raid-menu-item').forEach(item => {
                        item.addEventListener('click', () => {
                            currentCategory = item.getAttribute('data-category');
                            renderMenu();
                            renderContent();
                        });
                    });
                };

                // Render Content
                const renderContent = () => {
                    const data = mobsByClass[currentCategory];
                    const bannerColor = data.color;
                    const recClassesHTML = data.recommendedClasses ? `
                        <div class="rec-classes">
                            ${data.recommendedClasses.map(cls => `<span class="rec-tag" style="color:${bannerColor}; border-color:${bannerColor}; background:rgba(0,0,0,0.2)">${cls}</span>`).join('')}
                        </div>
                   ` : '';

                    let html = `
                        <div class="class-raid-section">
                            <div class="raid-banner" style="color: ${bannerColor}">
                                <h2>${currentCategory} RAID</h2>
                                <div class="raid-controls" style="border-color: ${bannerColor}">
                                    <div class="raid-stat">
                                        <span>Dificultad</span>
                                        <span style="color: #ffbe0b">?????</span>
                                    </div>
                                    <div class="raid-stat">
                                        <span>Recompensa</span>
                                        <span style="color: ${bannerColor}">Class Ticket</span>
                                    </div>
                                    <div class="raid-stat">
                                        <span>Boss Wave</span>
                                        <span>5, 10, 15...</span>
                                    </div>
                                </div>
                                ${recClassesHTML}
                            </div>
                   `;

                    if (data.mobs.length > 0) {
                        html += `
                            <div class="section-divider">
                                <span class="section-line"></span>
                                <div class="section-title">?? HOSTILES REGULARES</div>
                                <span class="section-line"></span>
                            </div>
                            <div class="mobs-grid">
                        `;
                        data.mobs.forEach(mobType => {
                            const mob = this.mobTypes[mobType];
                            if (!mob) return;
                            html += `
                                <div class="mob-card" style="color: ${bannerColor}">
                                    <div class="mob-card-icon" style="color: ${bannerColor}">${mob.icon}</div>
                                    <h3>${mob.name}</h3>
                                    <div class="mob-stats">
                                        <div class="stat-row">
                                            <span class="stat-label">HP Base</span>
                                            <span class="stat-value" style="color:#00ff00">${mob.hp}</span>
                                        </div>
                                        <div class="stat-row">
                                            <span class="stat-label">Dao</span>
                                            <span class="stat-value" style="color:#ff006e">${mob.damage}</span>
                                        </div>
                                        <div class="stat-row">
                                            <span class="stat-label">Velocidad</span>
                                            <span class="stat-value" style="color:#ffbe0b">${mob.speed}</span>
                                        </div>
                                    </div>
                                    ${mob.dropsTicketFor ? `
                                        <div class="ticket-badge" style="border-color: ${bannerColor}; color: ${bannerColor}; background: rgba(0,0,0,0.2)">
                                            ?? ${mob.dropsTicketFor.replace('class_', '').replace('_', ' ').toUpperCase()} TICKET
                                        </div>
                                    ` : ''}
                                </div>
                            `;
                        });
                        html += `</div>`;
                    }

                    if (data.bosses.length > 0) {
                        html += `
                            <div class="section-divider" style="margin-top: 50px;">
                                <span class="section-line"></span>
                                <div class="section-title" style="color: #ffd700; border-color: #ffd700">?? JEFES DE OLEADA</div>
                                <span class="section-line"></span>
                            </div>
                            <div class="mobs-grid">
                        `;
                        data.bosses.forEach(bossType => {
                            const boss = this.mobTypes[bossType];
                            if (!boss) return;
                            html += `
                                <div class="mob-card boss-highlight" style="color: #ffd700; border-color: rgba(255, 215, 0, 0.4)">
                                    <div class="boss-tag">BOSS</div>
                                    <div class="mob-card-icon" style="color: #ffd700; font-size: 80px">${boss.icon}</div>
                                    <h3 style="color: #ffd700; font-size: 24px;">${boss.name}</h3>
                                    <div class="mob-stats" style="border-color: rgba(255, 215, 0, 0.2)">
                                        <div class="stat-row">
                                            <span class="stat-label">HP Base</span>
                                            <span class="stat-value" style="color:#00ff00">${boss.hp}</span>
                                        </div>
                                        <div class="stat-row">
                                            <span class="stat-label">Dao</span>
                                            <span class="stat-value" style="color:#ff006e">${boss.damage}</span>
                                        </div>
                                        <div class="stat-row">
                                            <span class="stat-label">Velocidad</span>
                                            <span class="stat-value" style="color:#ffbe0b">${boss.speed}</span>
                                        </div>
                                    </div>
                                    ${boss.dropsTicketFor ? `
                                        <div class="ticket-badge">
                                            ?? ${boss.dropsTicketFor.replace('class_', '').replace('_', ' ').toUpperCase()} TICKET
                                        </div>
                                    ` : ''}
                                </div>
                            `;
                        });
                        html += `</div>`;
                    }
                    html += `</div>`;
                    contentArea.innerHTML = html;
                };

                // Init
                renderMenu();
                renderContent();

                // Events
                document.getElementById('close-raid-ui').addEventListener('click', () => {
                    infoScreen.style.opacity = '0';
                    setTimeout(() => infoScreen.remove(), 400);
                });

                document.getElementById('start-raid-btn').addEventListener('click', () => {
                    // 1. Enter Fullscreen IMMEDIATELY (User Gesture requirement)
                    const canvas = document.getElementById('game-canvas');
                    const requestFullScreen = canvas.requestFullscreen ||
                        canvas.webkitRequestFullscreen ||
                        canvas.mozRequestFullScreen ||
                        canvas.msRequestFullscreen;
                    if (requestFullScreen) {
                        requestFullScreen.call(canvas).catch(err => console.warn('Fullscreen failed:', err));
                    }

                    // Set up the selected raid
                    const raidData = mobsByClass[currentCategory];

                    this.selectedRaidName = currentCategory;
                    this.isCustomRaid = true;
                    this.customMobTypes = raidData.mobs;
                    this.customBossTypes = raidData.bosses;

                    console.log(`?? Starting ${currentCategory} Raid!`);

                    // Animate out
                    infoScreen.style.transform = 'scale(1.1)';
                    infoScreen.style.opacity = '0';
                    setTimeout(() => {
                        infoScreen.remove();
                        this.actuallyStartRaid();
                    }, 300);
                });
            },


            actuallyStartRaid() {
                this.wave = 0;
                this.score = 0;
                this.mobs = [];
                this.bosses = [];
                this.projectiles = [];
                this.active = true;
                this.paused = false;

                // Reset Player
                const gameCanvas = document.getElementById('game-canvas');
                if (typeof Player !== 'undefined' && gameCanvas) {
                    Player.hp = Player.maxHp;
                    Player.x = gameCanvas.width / 2;
                    Player.y = gameCanvas.height / 2;
                }

                // Start
                this.startWave();

                // Show notification
                if (!this.specialWaveNotifications) this.specialWaveNotifications = [];
                this.specialWaveNotifications.push({
                    text: `?? RAID INICIADA: ${this.selectedRaidName.toUpperCase()} ??`,
                    startTime: Date.now(),
                    duration: 4000,
                    color: '#00d9ff'
                });
            },

            spawnWave() {
                const canvas = document.getElementById('game-canvas');
                console.log('?? Spawning wave', this.wave, 'Canvas:', canvas.width, 'x', canvas.height);

                // NEW: Check if this is a special wave (every 7 waves)
                const isSpecialWave = this.wave % 7 === 0;
                if (isSpecialWave) {
                    console.log('? SPECIAL WAVE! x4 enemies!');

                    // Show fullscreen notification
                    if (!this.specialWaveNotifications) this.specialWaveNotifications = [];
                    this.specialWaveNotifications.push({
                        text: '? OLEADA ESPECIAL - x4 ENEMIGOS ?',
                        startTime: Date.now(),
                        duration: 3000
                    });
                }

                // NEW v19.11.2025: Determine if stationary boss will spawn
                let stationaryBossType = null;
                const isBossWave = this.wave % 5 === 0; // Boss every 5 waves

                if (isBossWave) {
                    if (this.isCustomRaid && this.customBossTypes.length > 0) {
                        const bossType = this.customBossTypes[Math.floor(Math.random() * this.customBossTypes.length)];
                        if (this.mobTypes[bossType]?.isStationaryBoss) {
                            stationaryBossType = bossType;
                        }
                    } else {
                        const rand = Math.random();
                        let bossType;
                        if (rand < 0.091) bossType = 'tornado_master';
                        else if (rand < 0.182) bossType = 'king_of_skeletons';
                        else if (rand < 0.273) bossType = 'ancient_dragon';
                        else if (rand < 0.364) bossType = 'storm_titan';
                        else if (rand < 0.455) bossType = 'shogun_lord';
                        else if (rand < 0.545) bossType = 'mech_titan';
                        else if (rand < 0.636) bossType = 'elder_sorcerer';
                        else if (rand < 0.727) bossType = 'tempest_lord';
                        else if (rand < 0.818) bossType = 'warlord_colossus';
                        else if (rand < 0.909) bossType = 'shadow_emperor';
                        else bossType = 'aether_dragon'; // NEW: Aether Dragon

                        if (this.mobTypes[bossType]?.isStationaryBoss) {
                            stationaryBossType = bossType;
                        }
                    }
                }

                // Custom Raid Logic
                if (this.isCustomRaid) {
                    // Reduced mobs if stationary boss (1-2 max), x4 if special wave
                    let baseMobCount = stationaryBossType ? Math.min(2, 1 + Math.floor(this.wave / 2)) : 3 + this.wave;
                    const mobCount = isSpecialWave ? baseMobCount * 4 : baseMobCount;

                    for (let i = 0; i < mobCount; i++) {
                        if (this.customMobTypes.length > 0) {
                            const mobType = this.customMobTypes[Math.floor(Math.random() * this.customMobTypes.length)];
                            this.spawnMob(mobType, canvas);
                        }
                    }

                    if (isBossWave && this.customBossTypes.length > 0) {
                        const bossType = stationaryBossType || this.customBossTypes[Math.floor(Math.random() * this.customBossTypes.length)];
                        this.spawnMob(bossType, canvas, stationaryBossType !== null);
                    }
                } else {
                    // Normal Raid Logic - REDUCED mobs if stationary boss
                    // NEW v19.11.2025: Special wave every 7 waves (x4 enemies)
                    const isSpecialWave = this.wave % 7 === 0;
                    let baseMobCount = stationaryBossType ? Math.min(2, 1 + Math.floor(this.wave / 2)) : 3 + this.wave;
                    const mobCount = isSpecialWave ? baseMobCount * 4 : baseMobCount;

                    if (isSpecialWave) {
                        console.log('?? SPECIAL WAVE! x4 ENEMIES!');
                    }
                    for (let i = 0; i < mobCount; i++) {
                        const rand = Math.random();
                        let mobType;
                        if (rand < 0.077) mobType = 'tornado_apprentice';
                        else if (rand < 0.154) mobType = 'necromancer';
                        else if (rand < 0.231) mobType = 'fire_drake';
                        else if (rand < 0.308) mobType = 'water_elemental';
                        else if (rand < 0.385) mobType = 'ronin_warrior';
                        else if (rand < 0.462) mobType = 'combat_drone';
                        else if (rand < 0.539) mobType = 'arcane_wisp';
                        else if (rand < 0.616) mobType = 'toxic_zephyr';
                        else if (rand < 0.693) mobType = 'radioactive_cyclone';
                        else if (rand < 0.770) mobType = 'blood_reaver';
                        else if (rand < 0.847) mobType = 'axe_thrower';
                        else if (rand < 0.924) mobType = 'shadow_assassin';
                        else mobType = 'smoke_phantom';
                        this.spawnMob(mobType, canvas);
                    }

                    if (isBossWave) {
                        const rand = Math.random();
                        let bossType;
                        if (rand < 0.091) bossType = 'tornado_master';
                        else if (rand < 0.182) bossType = 'king_of_skeletons';
                        else if (rand < 0.273) bossType = 'ancient_dragon';
                        else if (rand < 0.364) bossType = 'storm_titan';
                        else if (rand < 0.455) bossType = 'shogun_lord';
                        else if (rand < 0.545) bossType = 'mech_titan';
                        else if (rand < 0.636) bossType = 'elder_sorcerer';
                        else if (rand < 0.727) bossType = 'tempest_lord';
                        else if (rand < 0.818) bossType = 'warlord_colossus';
                        else if (rand < 0.909) bossType = 'shadow_emperor';
                        else bossType = 'aether_dragon'; // NEW: Aether Dragon
                        this.spawnMob(bossType, canvas, this.mobTypes[bossType]?.isStationaryBoss);
                    }
                }

                // SAFETY MECHANIC: If stationary boss spawned, move player to safe position and give invulnerability
                if (stationaryBossType) {
                    console.log('??? STATIONARY BOSS DETECTED! Moving player to safe position...');

                    // Move player to bottom-left corner (safe distance from center)
                    Player.x = 150;
                    Player.y = canvas.height - 150;

                    // Give player 3 seconds of invulnerability to escape
                    Player.invulnerable = true;
                    Player.invulnerableTime = 3000;

                    // Show warning notification
                    if (!this.specialWaveNotifications) this.specialWaveNotifications = [];
                    this.specialWaveNotifications.push({
                        text: '?? BOSS ESTACIONARIO - 3s INVULNERABILIDAD ??',
                        startTime: Date.now(),
                        duration: 3000
                    });

                    console.log('??? Player moved to safe position with 3s invulnerability!');
                }

                console.log('?? Mobs:', this.mobs.length, 'Bosses:', this.bosses.length, stationaryBossType ? '?? STATIONARY!' : '');
            },

            startWave() {
                this.wave++;
                console.log(`=== STARTING WAVE ${this.wave} ===`);

                // Create Wave Notification
                if (this.wave > 1) {
                    if (!this.specialWaveNotifications) this.specialWaveNotifications = [];
                    this.specialWaveNotifications.push({
                        text: `?? OLEADA ${this.wave}`,
                        startTime: Date.now(),
                        duration: 3000,
                        color: '#ffffff'
                    });
                }

                // Mob Count Scaling
                let mobCount = 5 + Math.floor(this.wave * 1.5);
                if (mobCount > 18) mobCount = 18;

                // Spawn Mobs
                const canvas = document.getElementById('game-canvas');
                const mobTypes = this.isCustomRaid ? this.customMobTypes : ['tornado_apprentice'];

                if (mobTypes && mobTypes.length > 0) {
                    for (let i = 0; i < mobCount; i++) {
                        const type = mobTypes[Math.floor(Math.random() * mobTypes.length)];
                        if (this.mobTypes[type]) {
                            this.spawnMob(type, canvas, false);
                        }
                    }
                }

                // Boss Spawn (Every 5 waves)
                if (this.wave % 5 === 0) {
                    const bossTypes = this.isCustomRaid ? this.customBossTypes : ['tornado_master'];
                    if (bossTypes && bossTypes.length > 0) {
                        const bossType = bossTypes[Math.floor(Math.random() * bossTypes.length)];
                        if (this.mobTypes[bossType]) {
                            // Check for special boss notification
                            if (!this.specialWaveNotifications) this.specialWaveNotifications = [];
                            this.specialWaveNotifications.push({
                                text: `?? JEFE APROXIMÁNDOSE: ${this.mobTypes[bossType].name.toUpperCase()} ??`,
                                startTime: Date.now(),
                                duration: 5000,
                                color: '#ff0000'
                            });

                            // Spawn slightly delayed so player sees warning
                            setTimeout(() => {
                                this.spawnMob(bossType, canvas, true);
                            }, 2000);
                        }
                    }
                }
            },

            spawnMob(type, canvas, isStationary = false) {
                const mobData = this.mobTypes[type];
                let x, y;

                // NEW v19.11.2025: Stationary Boss Positioning
                if (isStationary && mobData.isStationaryBoss) {
                    if (mobData.stationaryPosition === 'center') {
                        x = canvas.width / 2;
                        y = canvas.height / 2;
                    } else if (mobData.stationaryPosition === 'center-bottom') {
                        x = canvas.width / 2;
                        y = canvas.height * 0.75; // 75% down
                    }
                    console.log(`?? Stationary Boss spawned at ${mobData.stationaryPosition}:`, x, y);
                } else {
                    // Normal spawn from edges
                    const side = Math.floor(Math.random() * 4);
                    switch (side) {
                        case 0: x = Math.random() * canvas.width; y = -50; break;
                        case 1: x = canvas.width + 50; y = Math.random() * canvas.height; break;
                        case 2: x = Math.random() * canvas.width; y = canvas.height + 50; break;
                        case 3: x = -50; y = Math.random() * canvas.height; break;
                    }
                }

                const mob = {
                    id: Date.now() + Math.random(),
                    type: type,
                    x: x,
                    y: y,
                    ...mobData,
                    currentAbilityCooldown: 0,
                    burning: false,
                    burnStacks: 0,
                    burnDamage: 0,
                    confused: false,
                    confusedTime: 0,
                    damageReduction: 0,
                    damageReductionPermanent: false,
                    // NEW v19.11.2025: Stationary boss flag
                    isStationary: isStationary && mobData.isStationaryBoss,
                    targetX: x, // For stationary bosses
                    targetY: y,
                    returnTimer: 0, // Timer to return to position after being moved
                    needsReturn: false // Flag to indicate boss needs to return
                };

                // Validate HP values to prevent NaN/Infinity errors (only if invalid)
                if (typeof mob.maxHp !== 'number' || !isFinite(mob.maxHp) || mob.maxHp <= 0) {
                    console.warn(`⚠️ Invalid maxHp for ${type}, using fallback`);
                    mob.maxHp = 100; // Default fallback only if truly invalid
                }
                if (typeof mob.hp !== 'number' || !isFinite(mob.hp)) {
                    mob.hp = mob.maxHp;
                }

                if (mobData.isBoss) {
                    this.bosses.push(mob);
                } else {
                    this.mobs.push(mob);
                }
            },

            update(deltaTime) {
                if (!this.active || this.paused) return;

                // NEW v19.11.2025: Update attack indicators
                this.updateAttackIndicators(deltaTime);

                const allMobs = [...this.mobs, ...this.bosses];

                allMobs.forEach(mob => {
                    // Update status effects
                    if (mob.confused) {
                        mob.confusedTime -= deltaTime;
                        if (mob.confusedTime <= 0) {
                            mob.confused = false;
                        }
                    }

                    // Radioactivity effect - constant damage + spreads to nearby enemies
                    if (mob.radioactive) {
                        if (!mob.radioactiveLastTick) mob.radioactiveLastTick = Date.now();

                        const timeSinceLastTick = Date.now() - mob.radioactiveLastTick;
                        if (timeSinceLastTick >= mob.radioactiveTickInterval) {
                            this.damageMob(mob.id, mob.radioactiveDamage);
                            mob.radioactiveLastTick = Date.now();

                            // Check for nearby enemies to spread radioactivity
                            allMobs.forEach(otherMob => {
                                if (otherMob.id !== mob.id && !otherMob.radioactive) {
                                    const dx = otherMob.x - mob.x;
                                    const dy = otherMob.y - mob.y;
                                    const dist = Math.sqrt(dx * dx + dy * dy);

                                    // Spread if very close (infection mechanic)
                                    if (dist < 80) {
                                        otherMob.radioactive = true;
                                        otherMob.radioactiveTime = 7000;
                                        otherMob.radioactiveDamage = 4;
                                        otherMob.radioactiveTickInterval = 500;
                                        console.log(`?? Radioactividad se propagí a ${otherMob.name}!`);
                                    }
                                }
                            });
                        }

                        mob.radioactiveTime -= deltaTime;
                        if (mob.radioactiveTime <= 0) {
                            mob.radioactive = false;
                            delete mob.radioactiveLastTick;
                        }
                    }

                    // Poison effect - constant damage + defense reduction + speed reduction
                    if (mob.poisoned) {
                        if (!mob.poisonLastTick) mob.poisonLastTick = Date.now();

                        const timeSinceLastTick = Date.now() - mob.poisonLastTick;
                        if (timeSinceLastTick >= mob.poisonTickInterval) {
                            this.damageMob(mob.id, mob.poisonDamage);
                            mob.poisonLastTick = Date.now();
                        }

                        mob.poisonTime -= deltaTime;
                        if (mob.poisonTime <= 0) {
                            mob.poisoned = false;
                            delete mob.poisonLastTick;
                        }
                    }

                    // Handle being thrown by wind
                    if (mob.beingThrown) {
                        mob.x += mob.throwVelocityX * (deltaTime / 1000);
                        mob.y += mob.throwVelocityY * (deltaTime / 1000);
                        // Slow down over time
                        mob.throwVelocityX *= 0.95;
                        mob.throwVelocityY *= 0.95;
                    }

                    // WIND MASTER MOB SPECIAL MECHANICS

                    // Toxic Zephyr - Constant radiation emission
                    if (mob.constantRadiation && mob.type === 'toxic_zephyr') {
                        if (!mob.radiationEmitTimer) mob.radiationEmitTimer = 0;
                        mob.radiationEmitTimer += deltaTime;

                        if (mob.radiationEmitTimer >= 2000) { // Every 2 seconds
                            const dx = Player.x - mob.x;
                            const dy = Player.y - mob.y;
                            const dist = Math.sqrt(dx * dx + dy * dy);

                            if (dist < 150) {
                                Player.takeDamage(3); // Small constant damage
                            }
                            mob.radiationEmitTimer = 0;
                        }
                    }

                    // Radioactive Cyclone - Pull effect (NERFED v19.11.2025)
                    if (mob.pullEffect && mob.type === 'radioactive_cyclone') {
                        const dx = mob.x - Player.x;
                        const dy = mob.y - Player.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);

                        if (dist < 250 && dist > 0) {
                            // Reduced pull strength (NERFED v19.11.2025)
                            const pullStrength = mob.pullStrength || 0.4;
                            Player.x += (dx / dist) * pullStrength * (deltaTime / 1000) * 60;
                            Player.y += (dy / dist) * pullStrength * (deltaTime / 1000) * 60;
                        }
                    }

                    // Tempest Lord - Wind Barrier (reflects damage)
                    if (mob.windBarrier && mob.type === 'tempest_lord') {
                        // This is handled in damageMob function
                    }

                    // Tempest Lord - Enrage when below 30% HP
                    if (mob.enrageThreshold && mob.type === 'tempest_lord') {
                        const healthPercent = mob.hp / mob.maxHp;
                        if (healthPercent < mob.enrageThreshold && !mob.enraged) {
                            mob.enraged = true;
                            mob.speed *= 1.5; // 50% faster
                            mob.damage *= 1.3; // 30% more damage
                            mob.color = '#ff0000'; // Turn red
                            console.log('??? Tempest Lord ENRAGED! Speed and damage increased!');
                        }
                    }

                    // Tempest Lord - Phase shift teleport
                    if (mob.phaseShift && mob.type === 'tempest_lord') {
                        if (!mob.phaseShiftTimer) mob.phaseShiftTimer = 0;
                        mob.phaseShiftTimer += deltaTime;

                        if (mob.phaseShiftTimer >= 8000) { // Every 8 seconds
                            const canvas = document.getElementById('game-canvas');
                            mob.x = 100 + Math.random() * (canvas.width - 200);
                            mob.y = 100 + Math.random() * (canvas.height - 200);
                            console.log('??? Tempest Lord phase shifted!');
                            mob.phaseShiftTimer = 0;
                        }
                    }

                    // Burn stacks don't do passive damage - only when enemy attacks

                    // Move towards player (NEW v19.11.2025: Stationary bosses don't move)
                    // NEW: Enemies can't see invisible player
                    const dx = Player.x - mob.x;
                    const dy = Player.y - mob.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (!mob.isStationary) {
                        if (dist > 0 && !mob.confused && !Player.invisible) {
                            // Normal movement toward player (only if player is visible)
                            mob.x += (dx / dist) * mob.speed * (deltaTime / 1000);
                            mob.y += (dy / dist) * mob.speed * (deltaTime / 1000);
                        } else if (mob.confused || Player.invisible) {
                            // Random movement when confused OR when player is invisible
                            const randomAngle = Math.random() * Math.PI * 2;
                            mob.x += Math.cos(randomAngle) * mob.speed * 0.5 * (deltaTime / 1000);
                            mob.y += Math.sin(randomAngle) * mob.speed * 0.5 * (deltaTime / 1000);
                        }
                    } else {
                        // NEW v19.11.2025: Stationary boss return system
                        const distFromTarget = Math.sqrt(Math.pow(mob.x - mob.targetX, 2) + Math.pow(mob.y - mob.targetY, 2));

                        if (distFromTarget > 10) {
                            // Boss was moved, start return timer
                            if (!mob.needsReturn) {
                                mob.needsReturn = true;
                                mob.returnTimer = 2000; // 2 seconds
                                console.log(`?? ${mob.name} was moved! Returning in 2s...`);
                            }

                            mob.returnTimer -= deltaTime;
                            if (mob.returnTimer <= 0) {
                                // Return to position
                                mob.x = mob.targetX;
                                mob.y = mob.targetY;
                                mob.needsReturn = false;
                                console.log(`?? ${mob.name} returned to position!`);
                            }
                        } else {
                            // Boss is at target position
                            mob.x = mob.targetX;
                            mob.y = mob.targetY;
                            mob.needsReturn = false;
                        }
                    }

                    // Check collision with player
                    if (dist < mob.size + 25) {
                        // If mob has burn stacks, it takes damage BEFORE attacking (Dragonhunter's Triple Flecha Flamígera)
                        if (mob.burning && mob.burnStacks > 0) {
                            const burnDamage = 35; // Fixed damage per attack attempt
                            this.damageMob(mob.id, burnDamage);
                            mob.burnStacks--;
                            console.log(`?? ${mob.name} tried to attack but took ${burnDamage} burn damage! ${mob.burnStacks} stacks left`);

                            if (mob.burnStacks === 0) {
                                mob.burning = false;
                                console.log(`?? ${mob.name} is no longer burning!`);
                            }
                        }

                        // Then mob attacks player normally
                        let finalDamage = mob.damage;
                        if (mob.damageReduction > 0) {
                            finalDamage *= (1 - mob.damageReduction / 100);
                        }
                        Player.takeDamage(Math.floor(finalDamage), mob.id);
                    }

                    // Update ability cooldown
                    if (mob.currentAbilityCooldown > 0) {
                        mob.currentAbilityCooldown -= deltaTime;
                    }

                    // Use ability if in range and cooldown ready (not when confused or player invisible)
                    if (mob.ability && !mob.confused && !Player.invisible && mob.currentAbilityCooldown <= 0 && dist < mob.abilityRange) {
                        this.useMobAbility(mob);
                        mob.currentAbilityCooldown = mob.abilityCooldown;
                    }
                });

                // Update projectiles
                this.projectiles = this.projectiles.filter(proj => {
                    proj.x += proj.vx * (deltaTime / 1000);
                    proj.y += proj.vy * (deltaTime / 1000);
                    proj.life -= deltaTime;

                    // Check collision with player (only for enemy projectiles)
                    if (!proj.isPlayerProjectile) {
                        const dx = Player.x - proj.x;
                        const dy = Player.y - proj.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);
                        if (dist < 25 + proj.size) {
                            Player.takeDamage(proj.damage);

                            // NEW v19.11.2025: Apply Electrified effect from Storm Titan projectiles
                            if (proj.electrifies) {
                                Player.electrified = true;
                                Player.electrifiedTime = 2000; // 2 seconds stun
                                console.log('? Player is ELECTRIFIED! Stunned for 2s!');
                            }

                            return false;
                        }
                    } else {
                        // Check collision with mobs for player projectiles
                        const allMobs = [...this.mobs, ...this.bosses];

                        // Also check collision with dummies in practice mode
                        let allTargets = allMobs;
                        if (PracticeModeManager.active && TrainingDummySystem.dummies.length > 0) {
                            allTargets = [...allMobs, ...TrainingDummySystem.dummies.map(d => ({
                                ...d,
                                isDummy: true
                            }))];
                        }

                        for (let mob of allTargets) {
                            const dx = mob.x - proj.x;
                            const dy = mob.y - proj.y;
                            const dist = Math.sqrt(dx * dx + dy * dy);
                            if (dist < mob.size + proj.size) {
                                // Special handling for Pilum (piercing projectile)
                                if (proj.isPilum && proj.piercing) {
                                    // Check if we already hit this enemy
                                    if (!proj.hitEnemies.has(mob.id)) {
                                        if (mob.isDummy) {
                                            TrainingDummySystem.damageDummy(mob.id, proj.damage);
                                        } else {
                                            this.damageMob(mob.id, proj.damage);
                                        }
                                        proj.hitEnemies.add(mob.id);

                                        // Apply armor reduction
                                        if (!mob.armorReduced) {
                                            mob.originalDamageReduction = mob.damageReduction || 0;
                                            mob.damageReduction = Math.max(0, mob.originalDamageReduction - proj.armorReduction);
                                            mob.armorReduced = true;

                                            // Restore armor after 8 seconds
                                            setTimeout(() => {
                                                if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                                                    mob.damageReduction = mob.originalDamageReduction;
                                                    mob.armorReduced = false;
                                                }
                                            }, 8000);
                                        }

                                        // Apply bleeding effect
                                        mob.bleeding = true;
                                        mob.bleedDamage = proj.bleedDamage;
                                        mob.bleedDuration = proj.bleedDuration;
                                        mob.bleedStartTime = Date.now();

                                        // Bleeding damage over time
                                        if (!mob.bleedInterval) {
                                            mob.bleedInterval = setInterval(() => {
                                                if (mob.bleeding && (Date.now() - mob.bleedStartTime < mob.bleedDuration)) {
                                                    this.damageMob(mob.id, mob.bleedDamage);
                                                } else {
                                                    mob.bleeding = false;
                                                    clearInterval(mob.bleedInterval);
                                                    mob.bleedInterval = null;
                                                }
                                            }, 1000); // Damage every second
                                        }

                                        console.log(`??? Pilum atravesó a ${mob.name}! Sangrado y -40% armadura!`);
                                    }
                                    // Don't remove pilum, it continues through
                                }
                                // Special handling for Doru (Spartan spear - piercing projectile)
                                else if (proj.isDoru && proj.piercing) {
                                    if (!proj.hitEnemies.has(mob.id)) {
                                        if (mob.isDummy) {
                                            TrainingDummySystem.damageDummy(mob.id, proj.damage);
                                        } else {
                                            this.damageMob(mob.id, proj.damage);
                                        }
                                        proj.hitEnemies.add(mob.id);

                                        // Apply bleeding effect
                                        mob.bleeding = true;
                                        mob.bleedDamage = proj.bleedDamage;
                                        mob.bleedDuration = proj.bleedDuration;
                                        mob.bleedStartTime = Date.now();

                                        if (!mob.bleedInterval) {
                                            mob.bleedInterval = setInterval(() => {
                                                if (mob.bleeding && (Date.now() - mob.bleedStartTime < mob.bleedDuration)) {
                                                    this.damageMob(mob.id, mob.bleedDamage);
                                                } else {
                                                    mob.bleeding = false;
                                                    clearInterval(mob.bleedInterval);
                                                    mob.bleedInterval = null;
                                                }
                                            }, 1000);
                                        }

                                        console.log(`??? Doru atravesó a ${mob.name}! Sangrado espartano!`);
                                    }
                                    // Don't remove doru, it continues through
                                } else {
                                    // Normal projectile - remove after hit
                                    if (mob.isDummy) {
                                        TrainingDummySystem.damageDummy(mob.id, proj.damage);
                                    } else {
                                        this.damageMob(mob.id, proj.damage);
                                    }
                                    return false;
                                }
                            }
                        }
                    }

                    return proj.life > 0;
                });

                // Check if wave is complete
                if (this.mobs.length === 0 && this.bosses.length === 0) {
                    this.wave++;

                    // Award class experience for completing wave
                    if (EquipmentManager.equippedRole && EquipmentManager.equippedRole.type === 'class') {
                        const classId = EquipmentManager.equippedRole.id;
                        const expReward = 50 + (this.wave * 10); // More exp for higher waves
                        ClassProgressionSystem.addClassExp(classId, expReward);
                        console.log(`? +${expReward} EXP para ${classId} (Wave ${this.wave})`);
                    }

                    // Track wave survival for mastery missions
                    if (EquipmentManager.equippedRole && EquipmentManager.equippedRole.type === 'class') {
                        const classId = EquipmentManager.equippedRole.id;
                        // Use class-specific requirement IDs for wave survival
                        if (classId === 'class_wind_master') {
                            LoadoutManager.updateMissionProgress(classId, 'survive_raid', 1);
                        } else if (classId === 'class_gunslinger') {
                            // Gunslinger doesn't have wave survival requirement, skip
                        } else if (classId === 'class_ninja') {
                            LoadoutManager.updateMissionProgress(classId, 'survive_ninja_raid', 1);
                        }
                    }

                    this.spawnWave();
                }
            },

            useMobAbility(mob) {
                // Burn stacks are now only applied when mob attacks player (not when using abilities)

                if (mob.ability === 'tornado') {
                    // Shoot 3 projectiles in a spread
                    const angleToPlayer = Math.atan2(Player.y - mob.y, Player.x - mob.x);
                    for (let i = -1; i <= 1; i++) {
                        const angle = angleToPlayer + (i * 0.3);
                        this.projectiles.push({
                            x: mob.x,
                            y: mob.y,
                            vx: Math.cos(angle) * 200,
                            vy: Math.sin(angle) * 200,
                            size: 10,
                            damage: 15,
                            color: mob.color,
                            life: 3000
                        });
                    }
                    console.log('???', mob.name, 'used Tornado ability!');
                } else if (mob.ability === 'summon') {
                    // Summon a skeleton nearby
                    const canvas = document.getElementById('game-canvas');
                    const angle = Math.random() * Math.PI * 2;
                    const distance = 50;
                    const skeleton = {
                        id: Date.now() + Math.random(),
                        type: 'skeleton',
                        x: mob.x + Math.cos(angle) * distance,
                        y: mob.y + Math.sin(angle) * distance,
                        ...this.mobTypes.skeleton,
                        currentAbilityCooldown: 0
                    };
                    this.mobs.push(skeleton);
                    console.log('??', mob.name, 'summoned a Skeleton!');
                } else if (mob.ability === 'fireball') {
                    // Fire Drake shoots a single powerful fireball
                    const angleToPlayer = Math.atan2(Player.y - mob.y, Player.x - mob.x);
                    this.projectiles.push({
                        x: mob.x,
                        y: mob.y,
                        vx: Math.cos(angleToPlayer) * 250,
                        vy: Math.sin(angleToPlayer) * 250,
                        size: 15,
                        damage: 25,
                        color: '#ff4500',
                        life: 4000
                    });
                    console.log('??', mob.name, 'shot a Fireball!');
                } else if (mob.ability === 'dragon_rage') {
                    // Ancient Dragon shoots 5 fireballs in a cone
                    const angleToPlayer = Math.atan2(Player.y - mob.y, Player.x - mob.x);
                    for (let i = -2; i <= 2; i++) {
                        const angle = angleToPlayer + (i * 0.2);
                        this.projectiles.push({
                            x: mob.x,
                            y: mob.y,
                            vx: Math.cos(angle) * 300,
                            vy: Math.sin(angle) * 300,
                            size: 18,
                            damage: 35,
                            color: '#8b0000',
                            life: 5000
                        });
                    }
                    console.log('??', mob.name, 'unleashed Dragon Rage!');
                } else if (mob.ability === 'blood_frenzy') {
                    // Blood Reaver - Frenzy
                    if (!mob.frenzied) {
                        mob.frenzied = true;
                        mob.originalColor = mob.color;
                        mob.color = '#ff0000'; // Bright red
                        mob.damage *= 1.5;
                        mob.speed *= 1.5;

                        // Check if EffectRenderer exists
                        if (typeof EffectRenderer !== 'undefined') {
                            EffectRenderer.playEffect('effect_explosion', mob.x, mob.y);
                        }

                        setTimeout(() => {
                            if (this.mobs.includes(mob)) {
                                mob.frenzied = false;
                                mob.color = mob.originalColor;
                                mob.damage /= 1.5;
                                mob.speed /= 1.5;
                            }
                        }, 3000);
                        console.log('???', mob.name, 'entered BLOOD FRENZY!');
                    }
                } else if (mob.ability === 'axe_throw') {
                    // Axe Thrower - Throws an axe
                    const angleToPlayer = Math.atan2(Player.y - mob.y, Player.x - mob.x);
                    this.projectiles.push({
                        x: mob.x,
                        y: mob.y,
                        vx: Math.cos(angleToPlayer) * 350,
                        vy: Math.sin(angleToPlayer) * 350,
                        size: 20,
                        damage: 30,
                        color: mob.color,
                        life: 3000
                    });
                    console.log('???', mob.name, 'threw an Axe!');
                } else if (mob.ability === 'ground_slam') {
                    // Warlord Colossus - Ground Slam
                    const slamRadius = 250;

                    // Telegraph
                    this.addAttackIndicator(mob.x, mob.y, slamRadius, slamRadius, 1000, '#8B0000', 'circle');

                    setTimeout(() => {
                        // Check player distance
                        const dx = Player.x - mob.x;
                        const dy = Player.y - mob.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);

                        if (dist < slamRadius) {
                            Player.takeDamage(50);

                            // Massive Knockback
                            const knockAngle = Math.atan2(dy, dx);
                            // Ensure Player stays in bounds or move function handles it
                            if (Player.move) {
                                Player.move(Math.cos(knockAngle) * 100, Math.sin(knockAngle) * 100);
                            } else {
                                Player.x += Math.cos(knockAngle) * 100;
                                Player.y += Math.sin(knockAngle) * 100;
                            }
                        }
                        console.log('???', mob.name, 'used GROUND SLAM!');
                    }, 1000);
                } else if (mob.ability === 'water_blast') {
                    // Water Elemental shoots water projectile
                    const angleToPlayer = Math.atan2(Player.y - mob.y, Player.x - mob.x);
                    this.projectiles.push({
                        x: mob.x,
                        y: mob.y,
                        vx: Math.cos(angleToPlayer) * 220,
                        vy: Math.sin(angleToPlayer) * 220,
                        size: 12,
                        damage: 18,
                        color: '#00d9ff',
                        life: 3500
                    });
                    console.log('??', mob.name, 'used Water Blast!');
                } else if (mob.ability === 'lightning_storm') {
                    // Storm Titan shoots lightning bolts - BUFFED v19.11.2025
                    // Phase 1: Cardinal directions (4 bolts)
                    for (let i = 0; i < 4; i++) {
                        const angle = (Math.PI * 2 / 4) * i;
                        const lineLength = 200;
                        this.addAttackIndicator(mob.x, mob.y, lineLength, 30, 700, '#ffbe0b', 'rect', angle);
                    }

                    setTimeout(() => {
                        for (let i = 0; i < 4; i++) {
                            const angle = (Math.PI * 2 / 4) * i;
                            this.projectiles.push({
                                x: mob.x,
                                y: mob.y,
                                vx: Math.cos(angle) * 280,
                                vy: Math.sin(angle) * 280,
                                size: 16,
                                damage: 35,
                                color: '#ffbe0b',
                                life: 4000,
                                electrifies: true // NEW: Applies Electrified status
                            });
                        }
                    }, 700);

                    // Phase 2: Diagonal directions (4 more bolts)
                    setTimeout(() => {
                        for (let i = 0; i < 4; i++) {
                            const angle = (Math.PI * 2 / 4) * i + Math.PI / 4;
                            const lineLength = 180;
                            this.addAttackIndicator(mob.x, mob.y, lineLength, 25, 600, '#ff8c00', 'rect', angle);
                        }
                    }, 400);

                    setTimeout(() => {
                        for (let i = 0; i < 4; i++) {
                            const angle = (Math.PI * 2 / 4) * i + Math.PI / 4;
                            this.projectiles.push({
                                x: mob.x,
                                y: mob.y,
                                vx: Math.cos(angle) * 260,
                                vy: Math.sin(angle) * 260,
                                size: 14,
                                damage: 28,
                                color: '#ff8c00',
                                life: 3800,
                                electrifies: true // NEW: Applies Electrified status
                            });
                        }
                    }, 1000);

                    // Phase 3: Circular wave (12 bolts) - NEW PATTERN!
                    setTimeout(() => {
                        const circleIndicator = this.addAttackIndicator(mob.x, mob.y, 100, 100, 500, '#ffff00', 'circle');

                        setTimeout(() => {
                            for (let i = 0; i < 12; i++) {
                                const angle = (Math.PI * 2 / 12) * i;
                                this.projectiles.push({
                                    x: mob.x,
                                    y: mob.y,
                                    vx: Math.cos(angle) * 240,
                                    vy: Math.sin(angle) * 240,
                                    size: 12,
                                    damage: 25,
                                    color: '#ffff00',
                                    life: 3500,
                                    electrifies: true // NEW: Applies Electrified status
                                });
                            }
                            console.log('?', mob.name, 'summoned ULTIMATE Lightning Storm! (24 bolts total)');
                        }, 500);
                    }, 1200);
                } else if (mob.ability === 'quick_slash') {
                    // Ronin Warrior dashes toward player
                    const angleToPlayer = Math.atan2(Player.y - mob.y, Player.x - mob.x);
                    mob.x += Math.cos(angleToPlayer) * 50;
                    mob.y += Math.sin(angleToPlayer) * 50;
                    console.log('??', mob.name, 'used Quick Slash!');
                } else if (mob.ability === 'blade_dance') {
                    // Shogun Lord spins and shoots blades
                    for (let i = 0; i < 6; i++) {
                        const angle = (Math.PI * 2 / 6) * i;
                        this.projectiles.push({
                            x: mob.x,
                            y: mob.y,
                            vx: Math.cos(angle) * 260,
                            vy: Math.sin(angle) * 260,
                            size: 14,
                            damage: 28,
                            color: '#8b0000',
                            life: 4500
                        });
                    }
                    console.log('??', mob.name, 'performed Blade Dance!');
                } else if (mob.ability === 'laser_burst') {
                    // Combat Drone shoots rapid laser bursts
                    const angleToPlayer = Math.atan2(Player.y - mob.y, Player.x - mob.x);
                    for (let i = 0; i < 3; i++) {
                        setTimeout(() => {
                            this.projectiles.push({
                                x: mob.x,
                                y: mob.y,
                                vx: Math.cos(angleToPlayer) * 280,
                                vy: Math.sin(angleToPlayer) * 280,
                                size: 8,
                                damage: 12,
                                color: '#00ffff',
                                life: 3000
                            });
                        }, i * 150);
                    }
                    console.log('??', mob.name, 'fired Laser Burst!');
                } else if (mob.ability === 'missile_barrage') {
                    // Mech Titan launches homing missiles
                    for (let i = 0; i < 5; i++) {
                        const angle = (Math.PI * 2 / 5) * i + Math.random() * 0.3;
                        this.projectiles.push({
                            x: mob.x,
                            y: mob.y,
                            vx: Math.cos(angle) * 240,
                            vy: Math.sin(angle) * 240,
                            size: 14,
                            damage: 32,
                            color: '#00ff00',
                            life: 4500
                        });
                    }
                    console.log('??', mob.name, 'launched Missile Barrage!');
                } else if (mob.ability === 'magic_bolt') {
                    // Arcane Wisp shoots magical projectile
                    const angleToPlayer = Math.atan2(Player.y - mob.y, Player.x - mob.x);
                    this.projectiles.push({
                        x: mob.x,
                        y: mob.y,
                        vx: Math.cos(angleToPlayer) * 200,
                        vy: Math.sin(angleToPlayer) * 200,
                        size: 10,
                        damage: 16,
                        color: '#9370db',
                        life: 3200
                    });
                    console.log('?', mob.name, 'cast Magic Bolt!');
                } else if (mob.ability === 'arcane_explosion') {
                    // Elder Sorcerer creates expanding arcane ring
                    for (let i = 0; i < 8; i++) {
                        const angle = (Math.PI * 2 / 8) * i;
                        this.projectiles.push({
                            x: mob.x,
                            y: mob.y,
                            vx: Math.cos(angle) * 220,
                            vy: Math.sin(angle) * 220,
                            size: 16,
                            damage: 28,
                            color: '#8b00ff',
                            life: 4200
                        });
                    }
                    console.log('??', mob.name, 'unleashed Arcane Explosion!');
                }
                // WIND MASTER MOB ABILITIES - EXTREMELY ANNOYING
                else if (mob.ability === 'toxic_dash') {
                    // Toxic Zephyr - Dashes toward player leaving poison trail
                    const angleToPlayer = Math.atan2(Player.y - mob.y, Player.x - mob.x);
                    const dashDistance = 150;

                    // Store starting position
                    const startX = mob.x;
                    const startY = mob.y;

                    // Dash toward player
                    mob.x += Math.cos(angleToPlayer) * dashDistance;
                    mob.y += Math.sin(angleToPlayer) * dashDistance;

                    // Leave poison trail (create toxic bubbles along path)
                    for (let i = 0; i < 3; i++) {
                        const t = (i + 1) / 4; // 0.25, 0.5, 0.75
                        const trailX = startX + (mob.x - startX) * t;
                        const trailY = startY + (mob.y - startY) * t;

                        // Create mini toxic bubble
                        if (!this.toxicBubbles) this.toxicBubbles = [];
                        this.toxicBubbles.push({
                            x: trailX,
                            y: trailY,
                            size: 25,
                            color: '#00ff88',
                            lifetime: 4000,
                            createdAt: Date.now(),
                            exploded: false
                        });
                    }

                    console.log('??', mob.name, 'dashed and left poison trail!');
                }
                else if (mob.ability === 'radiation_pulse') {
                    // Radioactive Cyclone - Pulses radiation in area
                    const allMobs = [...this.mobs, ...this.bosses];

                    // Create expanding radiation wave
                    for (let ring = 0; ring < 3; ring++) {
                        setTimeout(() => {
                            const radius = 100 + (ring * 60); // 100, 160, 220

                            // Check if player is in range
                            const dx = Player.x - mob.x;
                            const dy = Player.y - mob.y;
                            const dist = Math.sqrt(dx * dx + dy * dy);

                            if (dist < radius) {
                                Player.takeDamage(12);
                                // Apply brief slow (FIXED v19.11.2025: Use baseSpeed to prevent permanent reduction)
                                Player.hasActiveSlowEffect = true;
                                Player.speed = Player.baseSpeed * 0.7;
                                setTimeout(() => {
                                    Player.speed = Player.baseSpeed;
                                    Player.hasActiveSlowEffect = false;
                                }, 1500);
                            }

                            // Visual projectiles in circle
                            for (let i = 0; i < 12; i++) {
                                const angle = (Math.PI * 2 / 12) * i;
                                this.projectiles.push({
                                    x: mob.x + Math.cos(angle) * radius * 0.5,
                                    y: mob.y + Math.sin(angle) * radius * 0.5,
                                    vx: Math.cos(angle) * 150,
                                    vy: Math.sin(angle) * 150,
                                    size: 8,
                                    damage: 10,
                                    color: '#39ff14',
                                    life: 1500
                                });
                            }
                        }, ring * 300);
                    }

                    console.log('??', mob.name, 'pulsed radiation waves!');
                }
                else if (mob.ability === 'tempest_fury') {
                    // Tempest Lord - Multi-phase devastating attack
                    console.log('???', mob.name, 'unleashing Tempest Fury!');

                    // NEW v19.11.2025: Show attack indicators for each phase
                    // Phase 1 indicator: Pull effect (circular)
                    this.addAttackIndicator(mob.x, mob.y, 80, 80, 1000, '#00ffaa', 'circle');

                    // Phase 2 indicators: 16 directional lines for projectiles
                    for (let i = 0; i < 16; i++) {
                        const angle = (Math.PI * 2 / 16) * i;
                        const lineLength = 150;

                        setTimeout(() => {
                            // Line starts from boss position and extends in the angle direction
                            this.addAttackIndicator(mob.x, mob.y, lineLength, 8, 500, '#00ffaa', 'line', angle);
                        }, 1000);
                    }

                    // Phase 1: Pull player slightly (0-1s)
                    const pullDuration = 1000;
                    const pullStartTime = Date.now();
                    const pullInterval = setInterval(() => {
                        if (Date.now() - pullStartTime >= pullDuration) {
                            clearInterval(pullInterval);
                        } else {
                            const dx = mob.x - Player.x;
                            const dy = mob.y - Player.y;
                            const dist = Math.sqrt(dx * dx + dy * dy);
                            if (dist > 0 && dist < 400) {
                                Player.x += (dx / dist) * 3;
                                Player.y += (dy / dist) * 3;
                            }
                        }
                    }, 16);

                    // Phase 2: Toxic wind spiral (1.5s)
                    setTimeout(() => {
                        for (let i = 0; i < 16; i++) {
                            const angle = (Math.PI * 2 / 16) * i;
                            this.projectiles.push({
                                x: mob.x,
                                y: mob.y,
                                vx: Math.cos(angle) * 200,
                                vy: Math.sin(angle) * 200,
                                size: 14,
                                damage: 25,
                                color: '#00ffaa',
                                life: 4000,
                                isRadioactive: true
                            });
                        }
                    }, 1500);

                    // Phase 3: Summon toxic zephyrs if below 50% HP (2.5s)
                    setTimeout(() => {
                        if (mob.hp / mob.maxHp < 0.5 && mob.summonMinions) {
                            for (let i = 0; i < 2; i++) {
                                const angle = Math.random() * Math.PI * 2;
                                const distance = 100;
                                const minion = {
                                    id: Date.now() + Math.random(),
                                    type: 'toxic_zephyr',
                                    x: mob.x + Math.cos(angle) * distance,
                                    y: mob.y + Math.sin(angle) * distance,
                                    ...this.mobTypes.toxic_zephyr,
                                    currentAbilityCooldown: 0
                                };
                                this.mobs.push(minion);
                            }
                            console.log('??? Tempest Lord summoned Toxic Zephyrs!');
                        }
                    }, 2500);

                    // Phase 4: Teleport randomly (3s)
                    if (mob.phaseShift) {
                        setTimeout(() => {
                            const canvas = document.getElementById('game-canvas');
                            mob.x = 100 + Math.random() * (canvas.width - 200);
                            mob.y = 100 + Math.random() * (canvas.height - 200);
                            console.log('??? Tempest Lord teleported!');
                        }, 3000);
                    }
                }
                // WILD BERSERKER MOB ABILITIES
                else if (mob.ability === 'blood_frenzy') {
                    // Blood Reaver enters frenzy, increasing speed and damage
                    const angleToPlayer = Math.atan2(Player.y - mob.y, Player.x - mob.x);

                    // Dash toward player
                    mob.x += Math.cos(angleToPlayer) * 60;
                    mob.y += Math.sin(angleToPlayer) * 60;

                    // Temporary speed and damage boost
                    if (!mob.frenzied) {
                        mob.originalSpeed = mob.speed;
                        mob.originalDamage = mob.damage;
                    }
                    mob.speed = mob.originalSpeed * 1.3;
                    mob.damage = mob.originalDamage * 1.2;
                    mob.frenzied = true;

                    setTimeout(() => {
                        if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                            mob.speed = mob.originalSpeed;
                            mob.damage = mob.originalDamage;
                            mob.frenzied = false;
                        }
                    }, 3000);

                    console.log('??', mob.name, 'entered Blood Frenzy! +30% speed, +20% damage!');
                }
                else if (mob.ability === 'axe_throw') {
                    // Axe Thrower throws 3 axes in a spread
                    const angleToPlayer = Math.atan2(Player.y - mob.y, Player.x - mob.x);

                    for (let i = -1; i <= 1; i++) {
                        const angle = angleToPlayer + (i * 0.3);
                        this.projectiles.push({
                            x: mob.x,
                            y: mob.y,
                            vx: Math.cos(angle) * 300,
                            vy: Math.sin(angle) * 300,
                            size: 16,
                            damage: 22,
                            color: '#ff4500',
                            life: 3500
                        });
                    }
                    console.log('??', mob.name, 'threw 3 axes!');
                }
                else if (mob.ability === 'ground_slam') {
                    // Warlord Colossus slams ground, creating shockwaves
                    console.log('??', mob.name, 'used Ground Slam!');

                    // Show attack indicator
                    this.addAttackIndicator(mob.x, mob.y, 200, 200, 800, '#8b0000', 'circle');

                    setTimeout(() => {
                        // Create 3 expanding shockwave rings
                        for (let ring = 0; ring < 3; ring++) {
                            setTimeout(() => {
                                const radius = 80 + (ring * 60);

                                // Check if player is in range
                                const dx = Player.x - mob.x;
                                const dy = Player.y - mob.y;
                                const dist = Math.sqrt(dx * dx + dy * dy);

                                if (dist < radius) {
                                    Player.takeDamage(30);
                                    // Knockback
                                    const knockAngle = Math.atan2(dy, dx);
                                    Player.x += Math.cos(knockAngle) * 40;
                                    Player.y += Math.sin(knockAngle) * 40;
                                }

                                // Visual projectiles in circle
                                for (let i = 0; i < 16; i++) {
                                    const angle = (Math.PI * 2 / 16) * i;
                                    this.projectiles.push({
                                        x: mob.x + Math.cos(angle) * radius * 0.5,
                                        y: mob.y + Math.sin(angle) * radius * 0.5,
                                        vx: Math.cos(angle) * 180,
                                        vy: Math.sin(angle) * 180,
                                        size: 12,
                                        damage: 25,
                                        color: '#8b0000',
                                        life: 2000
                                    });
                                }
                            }, ring * 400);
                        }
                    }, 800);

                    // Summon Blood Reavers if below 50% HP
                    if (mob.hp / mob.maxHp < 0.5 && mob.summonMinions) {
                        setTimeout(() => {
                            for (let i = 0; i < 2; i++) {
                                const angle = Math.random() * Math.PI * 2;
                                const distance = 100;
                                const minion = {
                                    id: Date.now() + Math.random(),
                                    type: 'blood_reaver',
                                    x: mob.x + Math.cos(angle) * distance,
                                    y: mob.y + Math.sin(angle) * distance,
                                    ...this.mobTypes.blood_reaver,
                                    currentAbilityCooldown: 0
                                };
                                this.mobs.push(minion);
                            }
                            console.log('?? Warlord Colossus summoned Blood Reavers!');
                        }, 1200);
                    }
                }
                // SHADOW NINJA MOB ABILITIES
                else if (mob.ability === 'shadow_strike') {
                    // Shadow Assassin dashes and strikes
                    const angleToPlayer = Math.atan2(Player.y - mob.y, Player.x - mob.x);

                    // Become invisible briefly
                    mob.invisible = true;
                    setTimeout(() => {
                        if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                            mob.invisible = false;
                        }
                    }, 1000);

                    // Dash toward player
                    mob.x += Math.cos(angleToPlayer) * 80;
                    mob.y += Math.sin(angleToPlayer) * 80;

                    // Critical strike projectile
                    this.projectiles.push({
                        x: mob.x,
                        y: mob.y,
                        vx: Math.cos(angleToPlayer) * 350,
                        vy: Math.sin(angleToPlayer) * 350,
                        size: 14,
                        damage: 35,
                        color: '#2f2f2f',
                        life: 2500
                    });

                    console.log('??', mob.name, 'used Shadow Strike!');
                }
                else if (mob.ability === 'smoke_bomb') {
                    // Smoke Phantom creates smoke cloud
                    console.log('??', mob.name, 'threw Smoke Bomb!');

                    // Create smoke cloud at mob position
                    const smokeCloud = {
                        x: mob.x,
                        y: mob.y,
                        radius: 70,
                        duration: 5000,
                        startTime: Date.now()
                    };

                    if (!this.smokeClouds) this.smokeClouds = [];
                    this.smokeClouds.push(smokeCloud);

                    // Check for player in smoke (confuses and damages)
                    const smokeInterval = setInterval(() => {
                        if (Date.now() - smokeCloud.startTime > smokeCloud.duration) {
                            clearInterval(smokeInterval);
                            this.smokeClouds = this.smokeClouds.filter(s => s !== smokeCloud);
                            return;
                        }

                        const dx = Player.x - smokeCloud.x;
                        const dy = Player.y - smokeCloud.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);

                        if (dist < smokeCloud.radius) {
                            Player.takeDamage(5);
                        }
                    }, 500);

                    // Teleport chance
                    if (Math.random() < mob.teleportChance) {
                        const angle = Math.random() * Math.PI * 2;
                        const distance = 100 + Math.random() * 50;
                        mob.x += Math.cos(angle) * distance;
                        mob.y += Math.sin(angle) * distance;
                        console.log('??', mob.name, 'teleported!');
                    }
                }
                else if (mob.ability === 'shadow_realm') {
                    // Shadow Emperor creates shadow realm
                    console.log('??', mob.name, 'opened Shadow Realm!');

                    // Show attack indicator
                    this.addAttackIndicator(mob.x, mob.y, 250, 250, 1000, '#000000', 'circle');

                    setTimeout(() => {
                        // Create shadow clones
                        if (mob.shadowClones) {
                            for (let i = 0; i < 3; i++) {
                                const angle = (Math.PI * 2 / 3) * i;
                                const distance = 120;

                                // Clone shoots projectile toward player
                                const cloneX = mob.x + Math.cos(angle) * distance;
                                const cloneY = mob.y + Math.sin(angle) * distance;

                                const angleToPlayer = Math.atan2(Player.y - cloneY, Player.x - cloneX);
                                this.projectiles.push({
                                    x: cloneX,
                                    y: cloneY,
                                    vx: Math.cos(angleToPlayer) * 280,
                                    vy: Math.sin(angleToPlayer) * 280,
                                    size: 12,
                                    damage: 28,
                                    color: '#000000',
                                    life: 3500
                                });
                            }
                        }

                        // Damage and slow player in range
                        const dx = Player.x - mob.x;
                        const dy = Player.y - mob.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);

                        if (dist < 250) {
                            Player.takeDamage(35);
                            // Slow player
                            Player.hasActiveSlowEffect = true;
                            Player.speed = Player.baseSpeed * 0.6;
                            setTimeout(() => {
                                Player.speed = Player.baseSpeed;
                                Player.hasActiveSlowEffect = false;
                            }, 3000);
                        }
                    }, 1000);

                    // Summon Shadow Assassins if below 50% HP
                    if (mob.hp / mob.maxHp < 0.5 && mob.summonMinions) {
                        setTimeout(() => {
                            for (let i = 0; i < 2; i++) {
                                const angle = Math.random() * Math.PI * 2;
                                const distance = 100;
                                const minion = {
                                    id: Date.now() + Math.random(),
                                    type: 'shadow_assassin',
                                    x: mob.x + Math.cos(angle) * distance,
                                    y: mob.y + Math.sin(angle) * distance,
                                    ...this.mobTypes.shadow_assassin,
                                    currentAbilityCooldown: 0
                                };
                                this.mobs.push(minion);
                            }
                            console.log('?? Shadow Emperor summoned Shadow Assassins!');
                        }, 1500);
                    }

                    // Phase shift teleport
                    if (mob.phaseShift && Math.random() < 0.3) {
                        setTimeout(() => {
                            const canvas = document.getElementById('game-canvas');
                            mob.x = 100 + Math.random() * (canvas.width - 200);
                            mob.y = 100 + Math.random() * (canvas.height - 200);
                            console.log('?? Shadow Emperor phase shifted!');
                        }, 2000);
                    }
                }
                // ===== AETHER DRAGON ABILITIES =====
                else if (mob.ability === 'aether_abilities') {
                    this.useAetherDragonAbility(mob);
                }
                // ===== TAURHA ABILITIES =====
                else if (mob.ability === 'taurha_abilities') {
                    this.useTaurhaAbility(mob);
                }
            },

            useAetherDragonAbility(dragon) {
                // Check for Destruction Phase (below 30% HP)
                const hpPercent = dragon.hp / dragon.maxHp;

                if (hpPercent < 0.3 && !dragon.destructionPhaseActive && !dragon.destructionShieldActive) {
                    this.aetherDragonDestructionPhase(dragon);
                    return;
                }

                // Don't use other abilities during destruction phase
                if (dragon.destructionShieldActive) return;

                // Rotate through abilities
                const abilities = ['death_ray', 'ether_explosion', 'cursed_barrier'];
                const abilityIndex = dragon.abilityRotation % abilities.length;
                const selectedAbility = abilities[abilityIndex];
                dragon.abilityRotation++;

                switch (selectedAbility) {
                    case 'death_ray':
                        this.aetherDragonDeathRay(dragon);
                        break;
                    case 'ether_explosion':
                        this.aetherDragonEtherExplosion(dragon);
                        break;
                    case 'cursed_barrier':
                        this.aetherDragonCursedBarrier(dragon);
                        break;
                }
            },

            aetherDragonDeathRay(dragon) {
                console.log('?? Dragón del Éter: íRAYO DE MUERTE!');

                // Phase 1: Charging (2 seconds)
                dragon.deathRayCharging = true;
                dragon.deathRayTarget = { x: Player.x, y: Player.y };

                // Visual charging effect
                const chargingInterval = setInterval(() => {
                    if (!dragon.deathRayCharging) {
                        clearInterval(chargingInterval);
                        return;
                    }

                    // Purple particles gathering
                    for (let i = 0; i < 3; i++) {
                        const angle = Math.random() * Math.PI * 2;
                        const distance = 100 + Math.random() * 50;
                        this.projectiles.push({
                            x: dragon.x + Math.cos(angle) * distance,
                            y: dragon.y + Math.sin(angle) * distance,
                            vx: -Math.cos(angle) * 150,
                            vy: -Math.sin(angle) * 150,
                            size: 6,
                            damage: 0,
                            color: '#9370DB',
                            life: 800,
                            isPlayerProjectile: false,
                            isParticle: true
                        });
                    }
                }, 100);

                // Show attack indicator line
                const angleToTarget = Math.atan2(dragon.deathRayTarget.y - dragon.y, dragon.deathRayTarget.x - dragon.x);
                this.addAttackIndicator(dragon.x, dragon.y, 600, 40, 2000, '#9370DB', 'line', angleToTarget);

                // Phase 2: Fire the ray (after 2 seconds)
                setTimeout(() => {
                    dragon.deathRayCharging = false;
                    dragon.deathRayCharged = true;
                    clearInterval(chargingInterval);

                    // Create massive death ray
                    const angle = Math.atan2(dragon.deathRayTarget.y - dragon.y, dragon.deathRayTarget.x - dragon.x);

                    // Main ray projectile
                    this.projectiles.push({
                        x: dragon.x,
                        y: dragon.y,
                        vx: Math.cos(angle) * 500,
                        vy: Math.sin(angle) * 500,
                        size: 40,
                        damage: 60,
                        color: '#9370DB',
                        life: 3000,
                        isPlayerProjectile: false,
                        isDeathRay: true,
                        piercing: true,
                        appliesCurse: true,
                        curseDuration: 4000,
                        knockbackForce: 150
                    });

                    // Ray trail particles
                    for (let i = 0; i < 20; i++) {
                        setTimeout(() => {
                            this.projectiles.push({
                                x: dragon.x,
                                y: dragon.y,
                                vx: Math.cos(angle) * (450 + Math.random() * 100),
                                vy: Math.sin(angle) * (450 + Math.random() * 100),
                                size: 15 + Math.random() * 10,
                                damage: 0,
                                color: '#9370DB',
                                life: 1500,
                                isPlayerProjectile: false,
                                isParticle: true
                            });
                        }, i * 50);
                    }

                    console.log('?? íRayo de Muerte disparado!');

                    setTimeout(() => {
                        dragon.deathRayCharged = false;
                    }, 1000);
                }, 2000);
            },

            aetherDragonEtherExplosion(dragon) {
                console.log('?? Dragón del Éter: íEXPLOSIíN íTER!');

                // Phase 1: Brief charge (1 second)
                dragon.etherExplosionCharging = true;

                // Pulsing purple aura
                const pulseInterval = setInterval(() => {
                    if (!dragon.etherExplosionCharging) {
                        clearInterval(pulseInterval);
                        return;
                    }

                    for (let i = 0; i < 8; i++) {
                        const angle = (Math.PI * 2 / 8) * i;
                        this.projectiles.push({
                            x: dragon.x,
                            y: dragon.y,
                            vx: Math.cos(angle) * 80,
                            vy: Math.sin(angle) * 80,
                            size: 8,
                            damage: 0,
                            color: '#9370DB',
                            life: 500,
                            isPlayerProjectile: false,
                            isParticle: true
                        });
                    }
                }, 200);

                // Show attack indicator
                this.addAttackIndicator(dragon.x, dragon.y, 180, 180, 1000, '#9370DB', 'circle');

                // Phase 2: Explosion (after 1 second)
                setTimeout(() => {
                    dragon.etherExplosionCharging = false;
                    clearInterval(pulseInterval);

                    // Create explosion
                    for (let ring = 0; ring < 3; ring++) {
                        setTimeout(() => {
                            const radius = 60 + (ring * 60); // 60, 120, 180

                            // Check if player is in range
                            const dx = Player.x - dragon.x;
                            const dy = Player.y - dragon.y;
                            const dist = Math.sqrt(dx * dx + dy * dy);

                            if (dist < radius) {
                                Player.takeDamage(45);
                                // Apply Curse for 2 seconds
                                this.applyCurseToPlayer(2000);
                            }

                            // Visual explosion projectiles
                            for (let i = 0; i < 16; i++) {
                                const angle = (Math.PI * 2 / 16) * i;
                                this.projectiles.push({
                                    x: dragon.x + Math.cos(angle) * radius * 0.5,
                                    y: dragon.y + Math.sin(angle) * radius * 0.5,
                                    vx: Math.cos(angle) * 200,
                                    vy: Math.sin(angle) * 200,
                                    size: 12,
                                    damage: 0,
                                    color: '#9370DB',
                                    life: 1500,
                                    isPlayerProjectile: false,
                                    isParticle: true
                                });
                            }
                        }, ring * 200);
                    }

                    console.log('?? ¡Explosión Éter detonada!');
                }, 1000);
            },

            aetherDragonCursedBarrier(dragon) {
                console.log('?? Dragón del Éter: íBARRERA MALDITA!');

                dragon.cursedBarrierActive = true;
                dragon.cursedBarrierAngle = 0;

                const duration = 4000; // 4 seconds
                const startTime = Date.now();

                // Create rotating cursed trail
                const barrierInterval = setInterval(() => {
                    if (Date.now() - startTime >= duration) {
                        clearInterval(barrierInterval);
                        dragon.cursedBarrierActive = false;
                        console.log('?? Barrera Maldita terminada');
                        return;
                    }

                    // Rotate angle
                    dragon.cursedBarrierAngle += 0.15;

                    // Create trail particles
                    const radius = 100;
                    for (let i = 0; i < 8; i++) {
                        const angle = dragon.cursedBarrierAngle + (Math.PI * 2 / 8) * i;
                        const trailX = dragon.x + Math.cos(angle) * radius;
                        const trailY = dragon.y + Math.sin(angle) * radius;

                        // Check if player touches the trail
                        const dx = Player.x - trailX;
                        const dy = Player.y - trailY;
                        const dist = Math.sqrt(dx * dx + dy * dy);

                        if (dist < 30) {
                            Player.takeDamage(15);
                            // Apply Curse for 2 seconds (stacks)
                            this.applyCurseToPlayer(2000);
                        }

                        // Visual trail
                        this.projectiles.push({
                            x: trailX,
                            y: trailY,
                            vx: 0,
                            vy: 0,
                            size: 20,
                            damage: 0,
                            color: '#9370DB',
                            life: 300,
                            isPlayerProjectile: false,
                            isParticle: true,
                            isCursedTrail: true
                        });
                    }
                }, 50);
            },

            aetherDragonDestructionPhase(dragon) {
                console.log('?? íDRAGíN DEL íTER: DESTRUCCIÓN PARCIAL!');

                dragon.destructionPhaseActive = true;
                dragon.destructionShieldActive = true;

                // Make dragon invincible
                dragon.invincible = true;

                // Create purple shield visual
                dragon.destructionShield = {
                    active: true,
                    radius: 120,
                    pulsePhase: 0
                };

                // Summon 4 Aether Minions
                const minionPositions = [
                    { angle: 0 },
                    { angle: Math.PI / 2 },
                    { angle: Math.PI },
                    { angle: Math.PI * 1.5 }
                ];

                dragon.summonedMinions = [];

                minionPositions.forEach((pos, index) => {
                    const distance = 200;
                    const minionX = dragon.x + Math.cos(pos.angle) * distance;
                    const minionY = dragon.y + Math.sin(pos.angle) * distance;

                    const minion = {
                        id: Date.now() + Math.random(),
                        type: 'aether_minion',
                        name: 'Sirviente del Éter',
                        icon: '??',
                        x: minionX,
                        y: minionY,
                        hp: 80,
                        maxHp: 80,
                        speed: 70,
                        damage: 20,
                        color: '#9370DB',
                        size: 25,
                        isBoss: false,
                        currentAbilityCooldown: 0,
                        isAetherMinion: true,
                        parentDragon: dragon
                    };

                    this.mobs.push(minion);
                    dragon.summonedMinions.push(minion.id);
                });

                console.log('?? í4 Sirvientes del Éter invocados! ¡Elimínalos rápido!');

                // Check minions every second
                const checkInterval = setInterval(() => {
                    // Count alive minions
                    const aliveMinions = this.mobs.filter(m =>
                        dragon.summonedMinions.includes(m.id)
                    );

                    // If all minions dead, break shield and explode
                    if (aliveMinions.length === 0) {
                        clearInterval(checkInterval);

                        console.log('?? íTodos los sirvientes eliminados! ¡El escudo se rompe!');

                        // Remove shield
                        dragon.destructionShieldActive = false;
                        dragon.invincible = false;
                        dragon.destructionShield = null;

                        // Massive explosion
                        this.addAttackIndicator(dragon.x, dragon.y, 300, 300, 1000, '#9370DB', 'circle');

                        setTimeout(() => {
                            const dx = Player.x - dragon.x;
                            const dy = Player.y - dragon.y;
                            const dist = Math.sqrt(dx * dx + dy * dy);

                            if (dist < 300) {
                                // 90% of player's current HP as damage
                                const explosionDamage = Math.floor(Player.hp * 0.9);
                                Player.takeDamage(explosionDamage);
                                console.log(`?? ¡Explosión masiva! ${explosionDamage} de daño!`);

                                // Knockback
                                const angle = Math.atan2(dy, dx);
                                Player.x += Math.cos(angle) * 100;
                                Player.y += Math.sin(angle) * 100;
                            }

                            // Explosion particles
                            for (let i = 0; i < 50; i++) {
                                const angle = Math.random() * Math.PI * 2;
                                this.projectiles.push({
                                    x: dragon.x,
                                    y: dragon.y,
                                    vx: Math.cos(angle) * (200 + Math.random() * 200),
                                    vy: Math.sin(angle) * (200 + Math.random() * 200),
                                    size: 15 + Math.random() * 15,
                                    damage: 0,
                                    color: '#9370DB',
                                    life: 2000,
                                    isPlayerProjectile: false,
                                    isParticle: true
                                });
                            }
                        }, 1000);
                    }
                }, 500);
            },

            applyCurseToPlayer(duration) {
                if (!Player.cursed) {
                    Player.cursed = true;
                    Player.curseEndTime = Date.now() + duration;
                    Player.curseStacks = 1;
                    console.log('?? ¡Jugador MALDITO! Recibirí el doble de daño!');
                } else {
                    // Stack curse (extend duration)
                    Player.curseEndTime = Math.max(Player.curseEndTime, Date.now() + duration);
                    Player.curseStacks = (Player.curseStacks || 1) + 1;
                    console.log(`?? íMaldición acumulada! (x${Player.curseStacks})`);
                }
            },

            // ===== TAURHA ABILITIES =====
            useTaurhaAbility(taurha) {
                // Rotate through abilities
                const abilities = ['column_swings', 'acid_rain', 'seismic_slam', 'underground_poison'];
                const abilityIndex = taurha.abilityRotation % abilities.length;
                const selectedAbility = abilities[abilityIndex];
                taurha.abilityRotation++;

                switch (selectedAbility) {
                    case 'column_swings':
                        this.taurhaColumnSwings(taurha);
                        break;
                    case 'acid_rain':
                        this.taurhaAcidRain(taurha);
                        break;
                    case 'seismic_slam':
                        this.taurhaSeismicSlam(taurha);
                        break;
                    case 'underground_poison':
                        this.taurhaUndergroundPoison(taurha);
                        break;
                }
            },

            taurhaColumnSwings(taurha) {
                console.log('??? Taurha: íBALANCEO DE COLUMNA!');

                taurha.swingCount = 0;
                const totalSwings = 6;

                const swingInterval = setInterval(() => {
                    if (taurha.swingCount >= totalSwings) {
                        clearInterval(swingInterval);
                        return;
                    }

                    const isSlam = taurha.swingCount >= 3;
                    const angle = Math.random() * Math.PI * 2;
                    const range = isSlam ? 200 : 150;
                    const indicatorTime = 800;

                    this.addAttackIndicator(
                        taurha.x + Math.cos(angle) * 100,
                        taurha.y + Math.sin(angle) * 100,
                        range,
                        range,
                        indicatorTime,
                        isSlam ? '#8B4513' : '#D2691E',
                        'circle'
                    );

                    setTimeout(() => {
                        const dx = Player.x - (taurha.x + Math.cos(angle) * 100);
                        const dy = Player.y - (taurha.y + Math.sin(angle) * 100);
                        const dist = Math.sqrt(dx * dx + dy * dy);

                        if (dist < range) {
                            const damage = isSlam ? 60 : 40;
                            Player.takeDamage(damage);

                            const knockAngle = Math.atan2(dy, dx);
                            Player.x += Math.cos(knockAngle) * 50;
                            Player.y += Math.sin(knockAngle) * 50;
                        }

                        for (let i = 0; i < 12; i++) {
                            const particleAngle = (Math.PI * 2 / 12) * i;
                            this.projectiles.push({
                                x: taurha.x + Math.cos(angle) * 100,
                                y: taurha.y + Math.sin(angle) * 100,
                                vx: Math.cos(particleAngle) * 150,
                                vy: Math.sin(particleAngle) * 150,
                                size: 8,
                                damage: 0,
                                color: '#8B7355',
                                life: 800,
                                isPlayerProjectile: false,
                                isParticle: true
                            });
                        }
                    }, indicatorTime);

                    taurha.swingCount++;
                }, 1200);
            },

            taurhaAcidRain(taurha) {
                console.log('??? Taurha: ¡LLUVIA ÁCIDA!');

                const totalBalls = 11;
                let ballsDropped = 0;

                const dropInterval = setInterval(() => {
                    if (ballsDropped >= totalBalls) {
                        clearInterval(dropInterval);
                        return;
                    }

                    const targetX = Player.x + (Math.random() - 0.5) * 100;
                    const targetY = Player.y + (Math.random() - 0.5) * 100;

                    this.addAttackIndicator(targetX, targetY, 40, 40, 1500, '#39FF14', 'circle');

                    setTimeout(() => {
                        const acidBall = {
                            x: targetX,
                            y: -50,
                            targetX: targetX,
                            targetY: targetY,
                            vx: 0,
                            vy: 400,
                            size: 20,
                            damage: 35,
                            color: '#39FF14',
                            life: 3000,
                            isPlayerProjectile: false,
                            isAcidBall: true,
                            appliesPoison: true,
                            poisonDuration: 2000
                        };

                        this.projectiles.push(acidBall);
                    }, 1000);

                    ballsDropped++;
                }, 500);
            },

            taurhaSeismicSlam(taurha) {
                console.log('??? Taurha: ¡GOLPE SÍSMICO GRADUAL!');

                const slams = [
                    { range: 150, delay: 0, color: '#CD853F' },
                    { range: 250, delay: 1000, color: '#D2691E' },
                    { range: 400, delay: 2000, color: '#8B4513' }
                ];

                slams.forEach((slam, index) => {
                    setTimeout(() => {
                        this.addAttackIndicator(taurha.x, taurha.y, slam.range, slam.range, 800, slam.color, 'circle');

                        setTimeout(() => {
                            const dx = Player.x - taurha.x;
                            const dy = Player.y - taurha.y;
                            const dist = Math.sqrt(dx * dx + dy * dy);

                            if (dist < slam.range) {
                                Player.takeDamage(45 + index * 10);

                                if (!Player.slipping) {
                                    Player.slipping = true;
                                    Player.originalFriction = 0.85;
                                    Player.friction = 0.98;
                                    Player.acceleration = 0.3;
                                    console.log('?? ¡Jugador deslizándose!');
                                }

                                Player.slippingEndTime = Date.now() + 3000;
                            }

                            if (this.cameraShake) {
                                this.cameraShake.intensity = 5 + index * 3;
                                this.cameraShake.duration = 500;
                            }

                            for (let ring = 0; ring < 3; ring++) {
                                setTimeout(() => {
                                    for (let i = 0; i < 16; i++) {
                                        const angle = (Math.PI * 2 / 16) * i;
                                        const radius = slam.range * 0.7;
                                        this.projectiles.push({
                                            x: taurha.x + Math.cos(angle) * radius * 0.5,
                                            y: taurha.y + Math.sin(angle) * radius * 0.5,
                                            vx: Math.cos(angle) * 180,
                                            vy: Math.sin(angle) * 180,
                                            size: 10,
                                            damage: 0,
                                            color: slam.color,
                                            life: 1000,
                                            isPlayerProjectile: false,
                                            isParticle: true
                                        });
                                    }
                                }, ring * 150);
                            }
                        }, 800);
                    }, slam.delay);
                });
            },

            taurhaUndergroundPoison(taurha) {
                console.log('??? Taurha: ¡ENVENENAMIENTO SUBTERRÁNEO!');

                this.addAttackIndicator(taurha.x, taurha.y, 100, 100, 1000, '#8B7355', 'circle');

                setTimeout(() => {
                    for (let i = 0; i < 5; i++) {
                        const angle = (Math.PI * 2 / 5) * i + Math.random() * 0.3;
                        const crackLength = 200 + Math.random() * 100;

                        const crack = {
                            startX: taurha.x,
                            startY: taurha.y,
                            endX: taurha.x + Math.cos(angle) * crackLength,
                            endY: taurha.y + Math.sin(angle) * crackLength,
                            width: 30,
                            color: '#39FF14',
                            lifetime: 8000,
                            createdAt: Date.now(),
                            poisonDamage: 15,
                            poisonDuration: 3000
                        };

                        if (!taurha.acidCracks) taurha.acidCracks = [];
                        taurha.acidCracks.push(crack);

                        for (let j = 0; j < 20; j++) {
                            setTimeout(() => {
                                const t = j / 20;
                                const crackX = crack.startX + (crack.endX - crack.startX) * t;
                                const crackY = crack.startY + (crack.endY - crack.startY) * t;

                                this.projectiles.push({
                                    x: crackX,
                                    y: crackY,
                                    vx: (Math.random() - 0.5) * 50,
                                    vy: -50 - Math.random() * 50,
                                    size: 6,
                                    damage: 0,
                                    color: '#39FF14',
                                    life: 1500,
                                    isPlayerProjectile: false,
                                    isParticle: true
                                });
                            }, j * 50);
                        }
                    }

                    console.log('??? íGrietas venenosas creadas!');
                }, 1000);

                const checkInterval = setInterval(() => {
                    if (!taurha.acidCracks || taurha.acidCracks.length === 0) {
                        clearInterval(checkInterval);
                        return;
                    }

                    taurha.acidCracks = taurha.acidCracks.filter(crack =>
                        Date.now() - crack.createdAt < crack.lifetime
                    );

                    taurha.acidCracks.forEach(crack => {
                        const dx = crack.endX - crack.startX;
                        const dy = crack.endY - crack.startY;
                        const length = Math.sqrt(dx * dx + dy * dy);
                        const nx = dx / length;
                        const ny = dy / length;

                        const px = Player.x - crack.startX;
                        const py = Player.y - crack.startY;
                        const dot = px * nx + py * ny;

                        if (dot >= 0 && dot <= length) {
                            const perpX = px - dot * nx;
                            const perpY = py - dot * ny;
                            const perpDist = Math.sqrt(perpX * perpX + perpY * perpY);

                            if (perpDist < crack.width) {
                                if (!Player.poisoned || Date.now() > Player.poisonEndTime) {
                                    Player.poisoned = true;
                                    Player.poisonDamage = crack.poisonDamage;
                                    Player.poisonTickInterval = 500;
                                    Player.poisonLastTick = Date.now();
                                    console.log('?? ¡Jugador ENVENENADO por grieta!');
                                }
                                Player.poisonEndTime = Date.now() + crack.poisonDuration;
                            }
                        }
                    });
                }, 100);

                setTimeout(() => clearInterval(checkInterval), 10000);
            },

            // ===== TAURHA - GIGANTE EN RUINAS ABILITIES =====
            useTaurhaAbility(taurha) {
                // Rotate through abilities
                const abilities = ['column_swings', 'acid_rain', 'seismic_slam', 'underground_poison'];
                const abilityIndex = taurha.abilityRotation % abilities.length;
                const selectedAbility = abilities[abilityIndex];
                taurha.abilityRotation++;

                switch (selectedAbility) {
                    case 'column_swings':
                        this.taurhaColumnSwings(taurha);
                        break;
                    case 'acid_rain':
                        this.taurhaAcidRain(taurha);
                        break;
                    case 'seismic_slam':
                        this.taurhaSeismicSlam(taurha);
                        break;
                    case 'underground_poison':
                        this.taurhaUndergroundPoison(taurha);
                        break;
                }
            },

            taurhaColumnSwings(taurha) {
                console.log('??? Taurha: íFURIA DE COLUMNA!');

                taurha.swingCount = 0;
                const totalSwings = 6;

                const swingInterval = setInterval(() => {
                    if (taurha.swingCount >= totalSwings) {
                        clearInterval(swingInterval);
                        return;
                    }

                    const isSlam = taurha.swingCount >= 3;
                    const angle = Math.random() * Math.PI * 2;
                    const range = isSlam ? 200 : 150;

                    this.addAttackIndicator(
                        taurha.x + Math.cos(angle) * 100,
                        taurha.y + Math.sin(angle) * 100,
                        range, range, 800,
                        isSlam ? '#8B4513' : '#D2691E',
                        'circle'
                    );

                    setTimeout(() => {
                        const dx = Player.x - (taurha.x + Math.cos(angle) * 100);
                        const dy = Player.y - (taurha.y + Math.sin(angle) * 100);
                        const dist = Math.sqrt(dx * dx + dy * dy);

                        if (dist < range) {
                            Player.takeDamage(isSlam ? 60 : 40);
                            const knockAngle = Math.atan2(dy, dx);
                            Player.x += Math.cos(knockAngle) * 50;
                            Player.y += Math.sin(knockAngle) * 50;
                        }

                        for (let i = 0; i < 12; i++) {
                            const pAngle = (Math.PI * 2 / 12) * i;
                            this.projectiles.push({
                                x: taurha.x + Math.cos(angle) * 100,
                                y: taurha.y + Math.sin(angle) * 100,
                                vx: Math.cos(pAngle) * 150,
                                vy: Math.sin(pAngle) * 150,
                                size: 8, damage: 0, color: '#8B7355',
                                life: 800, isPlayerProjectile: false, isParticle: true
                            });
                        }
                    }, 800);

                    taurha.swingCount++;
                }, 1200);
            },

            taurhaAcidRain(taurha) {
                console.log('??? Taurha: ¡LLUVIA ÁCIDA!');

                let ballsDropped = 0;
                const dropInterval = setInterval(() => {
                    if (ballsDropped >= 11) {
                        clearInterval(dropInterval);
                        return;
                    }

                    const targetX = Player.x + (Math.random() - 0.5) * 100;
                    const targetY = Player.y + (Math.random() - 0.5) * 100;

                    this.addAttackIndicator(targetX, targetY, 40, 40, 1500, '#39FF14', 'circle');

                    setTimeout(() => {
                        this.projectiles.push({
                            x: targetX, y: -50,
                            vx: 0, vy: 400,
                            size: 20, damage: 35,
                            color: '#39FF14', life: 3000,
                            isPlayerProjectile: false,
                            isAcidBall: true,
                            appliesPoison: true,
                            poisonDuration: 2000
                        });
                    }, 1000);

                    ballsDropped++;
                }, 500);
            },

            taurhaSeismicSlam(taurha) {
                console.log('??? Taurha: ¡GOLPE SÍSMICO GRADUAL!');

                const slams = [
                    { range: 150, delay: 0, color: '#CD853F' },
                    { range: 250, delay: 1000, color: '#D2691E' },
                    { range: 400, delay: 2000, color: '#8B4513' }
                ];

                slams.forEach((slam, index) => {
                    setTimeout(() => {
                        this.addAttackIndicator(taurha.x, taurha.y, slam.range, slam.range, 800, slam.color, 'circle');

                        setTimeout(() => {
                            const dx = Player.x - taurha.x;
                            const dy = Player.y - taurha.y;
                            const dist = Math.sqrt(dx * dx + dy * dy);

                            if (dist < slam.range) {
                                Player.takeDamage(45 + index * 10);
                                Player.slipping = true;
                                Player.slippingEndTime = Date.now() + 3000;
                                console.log('?? ¡Jugador deslizándose!');
                            }

                            for (let ring = 0; ring < 3; ring++) {
                                setTimeout(() => {
                                    for (let i = 0; i < 16; i++) {
                                        const angle = (Math.PI * 2 / 16) * i;
                                        this.projectiles.push({
                                            x: taurha.x + Math.cos(angle) * slam.range * 0.5,
                                            y: taurha.y + Math.sin(angle) * slam.range * 0.5,
                                            vx: Math.cos(angle) * 180,
                                            vy: Math.sin(angle) * 180,
                                            size: 10, damage: 0, color: slam.color,
                                            life: 1000, isPlayerProjectile: false, isParticle: true
                                        });
                                    }
                                }, ring * 150);
                            }
                        }, 800);
                    }, slam.delay);
                });
            },

            taurhaUndergroundPoison(taurha) {
                console.log('??? Taurha: ¡ENVENENAMIENTO SUBTERRÁNEO!');

                this.addAttackIndicator(taurha.x, taurha.y, 100, 100, 1000, '#8B7355', 'circle');

                setTimeout(() => {
                    for (let i = 0; i < 5; i++) {
                        const angle = (Math.PI * 2 / 5) * i + Math.random() * 0.3;
                        const crackLength = 200 + Math.random() * 100;

                        const crack = {
                            startX: taurha.x, startY: taurha.y,
                            endX: taurha.x + Math.cos(angle) * crackLength,
                            endY: taurha.y + Math.sin(angle) * crackLength,
                            width: 30, color: '#39FF14',
                            lifetime: 8000, createdAt: Date.now(),
                            poisonDamage: 15, poisonDuration: 3000
                        };

                        if (!taurha.acidCracks) taurha.acidCracks = [];
                        taurha.acidCracks.push(crack);

                        for (let j = 0; j < 20; j++) {
                            setTimeout(() => {
                                const t = j / 20;
                                const crackX = crack.startX + (crack.endX - crack.startX) * t;
                                const crackY = crack.startY + (crack.endY - crack.startY) * t;

                                this.projectiles.push({
                                    x: crackX, y: crackY,
                                    vx: (Math.random() - 0.5) * 50,
                                    vy: -50 - Math.random() * 50,
                                    size: 6, damage: 0, color: '#39FF14',
                                    life: 1500, isPlayerProjectile: false, isParticle: true
                                });
                            }, j * 50);
                        }
                    }
                }, 1000);
            },

            render(ctx) {
                if (!this.active) return;

                const allMobs = [...this.mobs, ...this.bosses];

                allMobs.forEach(mob => {

                    // PREMIUM MOB RENDER
                    ctx.save();
                    const time = Date.now();
                    const isBoss = mob.isBoss;

                    // Dynamic Pulse
                    const pulse = 1 + Math.sin(time / (isBoss ? 300 : 200)) * (isBoss ? 0.1 : 0.05);
                    const size = mob.size * pulse;

                    // 1. Aura
                    // 1. Aura (Universal)
                    const gradient = ctx.createRadialGradient(mob.x, mob.y, size * 0.2, mob.x, mob.y, size * (isBoss ? 2 : 1.5));
                    gradient.addColorStop(0, mob.color);
                    gradient.addColorStop(1, 'rgba(0,0,0,0)');

                    ctx.fillStyle = gradient;
                    ctx.globalAlpha = 0.4;
                    ctx.beginPath();
                    ctx.arc(mob.x, mob.y, size * 1.5, 0, Math.PI * 2);
                    ctx.fill();
                    ctx.globalAlpha = 1.0;

                    // CUSTOM MODEL RENDERING
                    ctx.strokeStyle = mob.color;
                    ctx.lineWidth = isBoss ? 3 : 2;
                    ctx.shadowColor = mob.color;
                    ctx.shadowBlur = isBoss ? 20 : 10;
                    ctx.fillStyle = 'rgba(0,0,0,0.7)'; // Dark backing

                    const type = mob.type || '';

                    if (type.includes('tornado') || type.includes('cyclone') || type.includes('zephyr') || type.includes('tempest')) {
                        // === TORNADO / WIND MODEL ===
                        // Draw spinning spirals
                        const spins = 3;
                        ctx.beginPath();
                        for (let i = 0; i < spins; i++) {
                            const angleOffset = (Math.PI * 2 * i) / spins + (time / 200);
                            for (let j = 0; j < 20; j++) {
                                const r = (j / 20) * size;
                                const theta = angleOffset + j * 0.5;
                                const px = mob.x + Math.cos(theta) * r;
                                const py = mob.y + Math.sin(theta) * r;
                                if (j === 0) ctx.moveTo(px, py);
                                else ctx.lineTo(px, py);
                            }
                        }
                        ctx.stroke();
                        // Eye of the storm
                        ctx.beginPath();
                        ctx.arc(mob.x, mob.y, size * 0.3, 0, Math.PI * 2);
                        ctx.fillStyle = mob.color;
                        ctx.fill();

                    } else if (type.includes('skeleton') || type.includes('necro') || type.includes('anubis')) {
                        // === UNDEAD / SKULL MODEL ===
                        // Draw a skull-like shape or jagged circle
                        ctx.beginPath();
                        const skullPoints = 8;
                        for (let i = 0; i <= skullPoints; i++) {
                            const angle = (Math.PI * 2 * i) / skullPoints;
                            // Jagged uneven radius
                            const r = size * (0.8 + Math.sin(angle * 3 + time / 500) * 0.2);
                            const px = mob.x + Math.cos(angle) * r;
                            const py = mob.y + Math.sin(angle) * r;
                            if (i === 0) ctx.moveTo(px, py);
                            else ctx.lineTo(px, py);
                        }
                        ctx.closePath();
                        ctx.fillStyle = mob.color; // Use mob color
                        ctx.fill();
                        ctx.stroke();

                        // Glowing Eyes
                        ctx.fillStyle = '#fff';
                        ctx.shadowBlur = 10;
                        ctx.beginPath();
                        ctx.arc(mob.x - size * 0.3, mob.y - size * 0.1, size * 0.15, 0, Math.PI * 2);
                        ctx.arc(mob.x + size * 0.3, mob.y - size * 0.1, size * 0.15, 0, Math.PI * 2);
                        ctx.fill();

                    } else if (type.includes('berserker') || type.includes('warlord') || type.includes('axe') || type.includes('reaver')) {
                        // === BERSERKER / WARLORD MODEL ===
                        // Aggressive spiky star/gear shape
                        const spikes = isBoss ? 12 : 6;
                        const outerR = size;
                        const innerR = size * 0.6;

                        ctx.beginPath();
                        const rot = time / 400;
                        for (let i = 0; i < spikes * 2; i++) {
                            const r = (i % 2 === 0) ? outerR : innerR;
                            const angle = (Math.PI * i) / spikes + rot;
                            const px = mob.x + Math.cos(angle) * r;
                            const py = mob.y + Math.sin(angle) * r;
                            if (i === 0) ctx.moveTo(px, py);
                            else ctx.lineTo(px, py);
                        }
                        ctx.closePath();
                        ctx.fillStyle = mob.color; // Use specific mob color
                        ctx.fill();
                        ctx.stroke();

                        // Inner Detail (Tribal Mark / Axe)
                        ctx.beginPath();
                        ctx.strokeStyle = 'rgba(255,255,255,0.7)';
                        ctx.lineWidth = 3;
                        // X shape mimic axes
                        const xSize = size * 0.5;
                        ctx.moveTo(mob.x - xSize, mob.y - xSize);
                        ctx.lineTo(mob.x + xSize, mob.y + xSize);
                        ctx.moveTo(mob.x + xSize, mob.y - xSize);
                        ctx.lineTo(mob.x - xSize, mob.y + xSize);
                        ctx.stroke();

                        if (type.includes('warlord')) {
                            // Crown/Horns for boss
                            ctx.beginPath();
                            ctx.strokeStyle = '#ffd700';
                            ctx.moveTo(mob.x - size, mob.y - size);
                            ctx.lineTo(mob.x - size * 0.5, mob.y - size * 1.5);
                            ctx.lineTo(mob.x + size * 0.5, mob.y - size * 1.5);
                            ctx.lineTo(mob.x + size, mob.y - size);
                            ctx.stroke();
                        }

                    } else if (type.includes('drone') || type.includes('mech') || type.includes('titan')) {
                        // === MECH / ROBOT MODEL ===
                        // Geometric tech shape (Octagon or Square with details)
                        const sides = isBoss ? 8 : 4;
                        ctx.beginPath();
                        const rot = isBoss ? time / 1000 : -time / 800;
                        for (let i = 0; i < sides; i++) {
                            const angle = (Math.PI * 2 * i) / sides + rot;
                            const px = mob.x + Math.cos(angle) * size;
                            const py = mob.y + Math.sin(angle) * size;
                            if (i === 0) ctx.moveTo(px, py);
                            else ctx.lineTo(px, py);
                        }
                        ctx.closePath();
                        ctx.fillStyle = 'rgba(0, 20, 40, 0.8)';
                        ctx.fill();
                        ctx.stroke();

                        // Core Reactor
                        ctx.beginPath();
                        ctx.arc(mob.x, mob.y, size * 0.4, 0, Math.PI * 2);
                        ctx.fillStyle = mob.color;
                        ctx.fill();
                        // Tech lines
                        ctx.beginPath();
                        ctx.moveTo(mob.x - size, mob.y);
                        ctx.lineTo(mob.x + size, mob.y);
                        ctx.moveTo(mob.x, mob.y - size);
                        ctx.lineTo(mob.x, mob.y + size);
                        ctx.strokeStyle = 'rgba(255,255,255,0.5)';
                        ctx.stroke();

                    } else if (type.includes('ninja') || type.includes('shadow') || type.includes('phantom') || type.includes('ronin') || type.includes('shogun')) {
                        // === NINJA / SHURIKEN MODEL ===
                        // Spinning star shape
                        const points = isBoss ? 8 : 4;
                        const outerRadius = size;
                        const innerRadius = size * 0.4;
                        const spin = time / 600;

                        ctx.beginPath();
                        for (let i = 0; i < points * 2; i++) {
                            const radius = (i % 2 === 0) ? outerRadius : innerRadius;
                            const angle = (Math.PI * i) / points + spin;
                            const px = mob.x + Math.cos(angle) * radius;
                            const py = mob.y + Math.sin(angle) * radius;
                            if (i === 0) ctx.moveTo(px, py);
                            else ctx.lineTo(px, py);
                        }
                        ctx.closePath();
                        ctx.fillStyle = 'rgba(20,20,20,0.9)';
                        ctx.fill();
                        ctx.stroke();

                        // Ninja headband tail (trail)
                        ctx.beginPath();
                        ctx.moveTo(mob.x, mob.y - size * 0.5);
                        ctx.quadraticCurveTo(mob.x + size, mob.y - size, mob.x + size * 1.5 + Math.sin(time / 200) * 10, mob.y - size * 0.5);
                        ctx.strokeStyle = mob.color;
                        ctx.lineWidth = 3;
                        ctx.stroke();

                    } else if (type.includes('roman') || type.includes('spartan') || type.includes('hoplite') || type.includes('leonidas') || type.includes('caesar') || type.includes('guard')) {
                        // === WARRIOR / SHIELD MODEL ===
                        // Round Shield (Aspis)
                        ctx.beginPath();
                        ctx.arc(mob.x, mob.y, size, 0, Math.PI * 2);
                        // Bronze/Gold metallic look
                        const shieldGrad = ctx.createRadialGradient(mob.x, mob.y, size * 0.2, mob.x, mob.y, size);
                        shieldGrad.addColorStop(0, mob.color);
                        shieldGrad.addColorStop(1, '#333');
                        ctx.fillStyle = shieldGrad;
                        ctx.fill();
                        ctx.lineWidth = 4;
                        ctx.stroke();

                        // Emblem (Lambda or Eagle abstract)
                        ctx.beginPath();
                        ctx.moveTo(mob.x - size * 0.5, mob.y + size * 0.4);
                        ctx.lineTo(mob.x, mob.y - size * 0.5);
                        ctx.lineTo(mob.x + size * 0.5, mob.y + size * 0.4);
                        ctx.strokeStyle = '#fff';
                        ctx.lineWidth = 3;
                        ctx.stroke();

                    } else if (type.includes('dragon') || type.includes('drake')) {
                        // === DRAGON MODEL ===
                        // Diamond / Scale shape
                        ctx.beginPath();
                        const wingSpan = size * (1 + Math.sin(time / 400) * 0.2); // Flapping wings
                        ctx.moveTo(mob.x, mob.y - size); // Head
                        ctx.lineTo(mob.x + wingSpan, mob.y); // Right Wing
                        ctx.lineTo(mob.x, mob.y + size * 1.2); // Tail
                        ctx.lineTo(mob.x - wingSpan, mob.y); // Left Wing
                        ctx.closePath();

                        ctx.fillStyle = 'rgba(0,0,0, 0.6)';
                        ctx.fill();
                        ctx.stroke();

                        // Eye
                        ctx.beginPath();
                        ctx.arc(mob.x, mob.y - size * 0.4, size * 0.15, 0, Math.PI * 2);
                        ctx.fillStyle = '#ffff00';
                        ctx.fill();

                    } else if (type.includes('elemental') || type.includes('wisp')) {
                        // === ELEMENTAL MODEL ===
                        // Amorphous blob
                        ctx.beginPath();
                        const blobPoints = 8;
                        for (let i = 0; i <= blobPoints; i++) {
                            const angle = (Math.PI * 2 * i) / blobPoints;
                            const variance = Math.sin(time / 300 + i * 3) * size * 0.2;
                            const r = size + variance;
                            const px = mob.x + Math.cos(angle) * r;
                            const py = mob.y + Math.sin(angle) * r;
                            if (i === 0) ctx.moveTo(px, py);
                            else ctx.quadraticCurveTo(mob.x + Math.cos(angle - 0.2) * r * 1.1, mob.y + Math.sin(angle - 0.2) * r * 1.1, px, py);
                        }
                        ctx.fillStyle = mob.color;
                        ctx.globalAlpha = 0.6;
                        ctx.fill();
                        ctx.globalAlpha = 1.0;

                        // Core
                        ctx.beginPath();
                        ctx.arc(mob.x, mob.y, size * 0.6, 0, Math.PI * 2);
                        ctx.fillStyle = '#fff';
                        ctx.globalAlpha = 0.8;
                        ctx.fill();
                        ctx.globalAlpha = 1.0;
                    } else {
                        // === GENERIC FALLBACK ===
                        ctx.beginPath();
                        if (isBoss) {
                            // Hexagon
                            for (let i = 0; i < 6; i++) {
                                const angle = (Math.PI / 3) * i + (time / 1000);
                                const px = mob.x + Math.cos(angle) * size;
                                const py = mob.y + Math.sin(angle) * size;
                                if (i === 0) ctx.moveTo(px, py);
                                else ctx.lineTo(px, py);
                            }
                        } else {
                            ctx.arc(mob.x, mob.y, size, 0, Math.PI * 2);
                        }
                        ctx.closePath();
                        ctx.fill();
                        ctx.stroke();

                        // Small icon fallback
                        ctx.font = `${mob.size * 0.6}px Arial`;
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';
                        ctx.fillStyle = '#fff';
                        ctx.fillText(mob.icon || '?', mob.x, mob.y);
                    }

                    ctx.restore();

                    // Draw level (above mob/boss)
                    if (mob.isBoss) {
                        // Boss level (larger, golden text)
                        ctx.font = 'bold 14px Arial';
                        ctx.fillStyle = '#ffd700';
                        ctx.strokeStyle = '#000000';
                        ctx.lineWidth = 3;
                        ctx.strokeText(`Lv.${mob.level || 1}`, mob.x, mob.y - mob.size - 8);
                        ctx.fillText(`Lv.${mob.level || 1}`, mob.x, mob.y - mob.size - 8);
                    } else {
                        // Regular mob level (smaller, white text)
                        ctx.font = 'bold 10px Arial';
                        ctx.fillStyle = '#ffffff';
                        ctx.strokeStyle = '#000000';
                        ctx.lineWidth = 2;
                        ctx.strokeText(`Lv.${mob.level || 1}`, mob.x, mob.y - mob.size - 5);
                        ctx.fillText(`Lv.${mob.level || 1}`, mob.x, mob.y - mob.size - 5);
                    }

                    // Draw HP bar (only for regular mobs, bosses have top bar)
                    if (!mob.isBoss) {
                        const barWidth = mob.size * 2;
                        const barHeight = 6;
                        const barX = mob.x - barWidth / 2;
                        const barY = mob.y - mob.size - 15;

                        ctx.fillStyle = 'rgba(0, 0, 0, 0.5)';
                        ctx.fillRect(barX, barY, barWidth, barHeight);

                        const hpPercent = Math.max(0, Math.min(1, mob.hp / mob.maxHp));
                        const fillWidth = Math.max(0, barWidth * hpPercent);

                        if (fillWidth > 0 && isFinite(fillWidth)) {
                            ctx.fillStyle = hpPercent > 0.5 ? '#00ff00' : hpPercent > 0.25 ? '#ffff00' : '#ff0000';
                            ctx.fillRect(barX, barY, fillWidth, barHeight);
                        }
                    }

                    // Draw status effect indicators
                    let statusX = mob.x + mob.size + 10;
                    if (mob.burning && mob.burnStacks > 0) {
                        ctx.font = '16px Arial';
                        ctx.fillText('??', statusX, mob.y - 10);
                        ctx.font = '10px Arial';
                        ctx.fillStyle = '#ff4500';
                        ctx.fillText(mob.burnStacks, statusX, mob.y + 5);
                        statusX += 20;
                    }
                    if (mob.confused) {
                        ctx.font = '16px Arial';
                        ctx.fillText('??', statusX, mob.y);
                        statusX += 20;
                    }
                    if (mob.radioactive) {
                        ctx.font = '18px Arial';
                        ctx.fillText('??', statusX, mob.y);
                        // Pulsing glow effect
                        ctx.save();
                        ctx.shadowBlur = 20 + Math.sin(Date.now() / 200) * 10;
                        ctx.shadowColor = '#39ff14';
                        ctx.fillText('??', statusX, mob.y);
                        ctx.restore();
                        statusX += 20;
                    }
                    if (mob.poisoned) {
                        ctx.font = '16px Arial';
                        ctx.fillText('??', statusX, mob.y);
                        ctx.save();
                        ctx.shadowBlur = 15;
                        ctx.shadowColor = '#00ff88';
                        ctx.fillText('??', statusX, mob.y);
                        ctx.restore();
                        statusX += 20;
                    }
                    if (mob.damageReduction > 0) {
                        ctx.font = '16px Arial';
                        ctx.fillText('???', statusX, mob.y);
                        ctx.font = '10px Arial';
                        ctx.fillStyle = '#00d9ff';
                        ctx.fillText(`-${mob.damageReduction}%`, statusX, mob.y + 12);
                        statusX += 20;
                    }
                    if (mob.bleeding) {
                        ctx.font = '18px Arial';
                        ctx.fillText('??', statusX, mob.y);
                        ctx.save();
                        ctx.shadowBlur = 15;
                        ctx.shadowColor = '#dc143c';
                        ctx.fillText('??', statusX, mob.y);
                        ctx.restore();
                        statusX += 20;
                    }
                    if (mob.armorReduced) {
                        ctx.font = '16px Arial';
                        ctx.fillText('??', statusX, mob.y);
                        ctx.font = '10px Arial';
                        ctx.fillStyle = '#ff0000';
                        ctx.fillText('-40%', statusX, mob.y + 12);
                        statusX += 20;
                    }
                    if (mob.stunned) {
                        // Estrellas girando sobre la cabeza del enemigo aturdido
                        const starCount = 3;
                        for (let i = 0; i < starCount; i++) {
                            const angle = (Math.PI * 2 / starCount) * i + (Date.now() / 300);
                            const starX = mob.x + Math.cos(angle) * 25;
                            const starY = mob.y - mob.size - 25 + Math.sin(angle) * 5;

                            ctx.font = '16px Arial';
                            ctx.fillStyle = '#ffff00';
                            ctx.shadowBlur = 10;
                            ctx.shadowColor = '#ffff00';
                            ctx.fillText('?', starX, starY);
                        }
                        ctx.shadowBlur = 0;
                    }
                    if (mob.spartanFear) {
                        // Efecto de Miedo Espartano
                        ctx.save();

                        // Aura de miedo roja
                        const fearGradient = ctx.createRadialGradient(
                            mob.x, mob.y, 0,
                            mob.x, mob.y, mob.size + 25
                        );
                        fearGradient.addColorStop(0, 'rgba(139, 0, 0, 0.35)');
                        fearGradient.addColorStop(1, 'rgba(0, 0, 0, 0)');

                        ctx.fillStyle = fearGradient;
                        ctx.beginPath();
                        ctx.arc(mob.x, mob.y, mob.size + 25, 0, Math.PI * 2);
                        ctx.fill();

                        // Lanzas espartanas
                        ctx.font = '18px Arial';
                        ctx.fillStyle = '#8B0000';
                        ctx.textAlign = 'center';
                        ctx.shadowBlur = 12;
                        ctx.shadowColor = '#8B0000';
                        ctx.fillText('???', mob.x - 22, mob.y);
                        ctx.fillText('???', mob.x + 22, mob.y);

                        // Texto de debuff
                        ctx.font = 'bold 10px Arial';
                        ctx.fillStyle = '#8B0000';
                        ctx.shadowBlur = 10;
                        ctx.fillText('MIEDO', mob.x, mob.y + mob.size + 22);
                        ctx.fillText('-70%', mob.x, mob.y + mob.size + 34);

                        ctx.restore();
                    }
                    if (mob.terrorRomano) {
                        // Efecto de Terror Romano - Aura oscura con símbolos romanos
                        ctx.save();

                        // Aura de terror
                        const terrorGradient = ctx.createRadialGradient(
                            mob.x, mob.y, 0,
                            mob.x, mob.y, mob.size + 20
                        );
                        terrorGradient.addColorStop(0, 'rgba(139, 0, 0, 0.3)');
                        terrorGradient.addColorStop(1, 'rgba(0, 0, 0, 0)');

                        ctx.fillStyle = terrorGradient;
                        ctx.beginPath();
                        ctx.arc(mob.x, mob.y, mob.size + 20, 0, Math.PI * 2);
                        ctx.fill();

                        // Cadenas romanas
                        ctx.font = '20px Arial';
                        ctx.fillStyle = '#8b0000';
                        ctx.textAlign = 'center';
                        ctx.shadowBlur = 15;
                        ctx.shadowColor = '#8b0000';
                        ctx.fillText('??', mob.x - 20, mob.y);
                        ctx.fillText('??', mob.x + 20, mob.y);

                        // Texto de debuff
                        ctx.font = 'bold 10px Arial';
                        ctx.fillStyle = '#dc143c';
                        ctx.shadowBlur = 10;
                        ctx.fillText('TERROR', mob.x, mob.y + mob.size + 20);
                        ctx.fillText('-80%', mob.x, mob.y + mob.size + 32);

                        ctx.restore();
                    }
                });

                // Render toxic bubbles
                if (this.toxicBubbles && this.toxicBubbles.length > 0) {
                    this.toxicBubbles.forEach(bubble => {
                        if (bubble.exploded) return;

                        ctx.save();
                        // Pulsing effect
                        const pulse = 1 + Math.sin(Date.now() / 300) * 0.1;
                        const size = bubble.size * pulse;

                        // Outer glow
                        ctx.shadowBlur = 25;
                        ctx.shadowColor = bubble.color;

                        // Gradient fill
                        const gradient = ctx.createRadialGradient(bubble.x, bubble.y, 0, bubble.x, bubble.y, size);
                        gradient.addColorStop(0, 'rgba(0, 255, 136, 0.6)');
                        gradient.addColorStop(0.7, 'rgba(0, 255, 136, 0.3)');
                        gradient.addColorStop(1, 'rgba(0, 255, 136, 0.1)');

                        ctx.fillStyle = gradient;
                        ctx.beginPath();
                        ctx.arc(bubble.x, bubble.y, size, 0, Math.PI * 2);
                        ctx.fill();

                        // Inner circle
                        ctx.fillStyle = 'rgba(0, 255, 136, 0.8)';
                        ctx.beginPath();
                        ctx.arc(bubble.x, bubble.y, size * 0.3, 0, Math.PI * 2);
                        ctx.fill();

                        // Toxic symbol
                        ctx.font = `${size * 0.6}px Arial`;
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';
                        ctx.fillStyle = '#000';
                        ctx.fillText('?', bubble.x, bubble.y);

                        ctx.restore();
                    });
                }

                // Render nature obstacles (trees/bushes)
                if (this.natureObstacles && this.natureObstacles.length > 0) {
                    this.natureObstacles.forEach(obstacle => {
                        ctx.save();

                        // Draw tree/bush base
                        const gradient = ctx.createRadialGradient(obstacle.x, obstacle.y, 0, obstacle.x, obstacle.y, obstacle.radius);
                        gradient.addColorStop(0, 'rgba(34, 139, 34, 0.8)');
                        gradient.addColorStop(0.7, 'rgba(34, 139, 34, 0.5)');
                        gradient.addColorStop(1, 'rgba(34, 139, 34, 0.2)');

                        ctx.fillStyle = gradient;
                        ctx.beginPath();
                        ctx.arc(obstacle.x, obstacle.y, obstacle.radius, 0, Math.PI * 2);
                        ctx.fill();

                        // Draw tree icon
                        ctx.font = `${obstacle.radius * 1.5}px Arial`;
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';
                        ctx.fillStyle = '#228b22';
                        ctx.shadowBlur = 10;
                        ctx.shadowColor = '#00ff00';
                        ctx.fillText('??', obstacle.x, obstacle.y);

                        ctx.restore();
                    });
                }

                // Render smoke balls (from Ninja Power)
                if (this.smokeBalls && this.smokeBalls.length > 0) {
                    this.smokeBalls.forEach(smoke => {
                        ctx.save();

                        // Pulsing effect
                        const pulse = 1 + Math.sin(Date.now() / 200) * 0.15;
                        const size = smoke.radius * pulse;

                        // Smoke gradient
                        const gradient = ctx.createRadialGradient(smoke.x, smoke.y, 0, smoke.x, smoke.y, size);
                        gradient.addColorStop(0, 'rgba(100, 100, 100, 0.8)');
                        gradient.addColorStop(0.5, 'rgba(80, 80, 80, 0.5)');
                        gradient.addColorStop(1, 'rgba(60, 60, 60, 0.1)');

                        ctx.fillStyle = gradient;
                        ctx.beginPath();
                        ctx.arc(smoke.x, smoke.y, size, 0, Math.PI * 2);
                        ctx.fill();

                        // Smoke icon
                        ctx.font = `${size * 0.8}px Arial`;
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';
                        ctx.fillStyle = '#ffffff';
                        ctx.shadowBlur = 10;
                        ctx.shadowColor = '#888888';
                        ctx.fillText('??', smoke.x, smoke.y);

                        ctx.restore();
                    });
                }

                // Render projectiles
                this.projectiles.forEach(proj => {
                    ctx.save();

                    // Special rendering for Pilum (Roman Legionary)
                    if (proj.isPilum) {
                        // Pilum trail effect
                        if (!proj.trail) proj.trail = [];
                        proj.trail.push({ x: proj.x, y: proj.y, time: Date.now() });
                        // Keep only last 10 trail points
                        if (proj.trail.length > 10) proj.trail.shift();

                        // Render trail
                        proj.trail.forEach((point, index) => {
                            const age = Date.now() - point.time;
                            const alpha = Math.max(0, 1 - (age / 300));
                            const size = proj.size * (0.3 + (index / proj.trail.length) * 0.7);

                            ctx.globalAlpha = alpha * 0.5;
                            ctx.fillStyle = '#ffd700';
                            ctx.beginPath();
                            ctx.arc(point.x, point.y, size * 0.4, 0, Math.PI * 2);
                            ctx.fill();
                        });

                        ctx.globalAlpha = 1;

                        // Pilum body (wooden shaft)
                        const length = 40;
                        const width = 6;
                        ctx.save();
                        ctx.translate(proj.x, proj.y);
                        ctx.rotate(proj.angle);

                        // Shaft shadow
                        ctx.shadowBlur = 15;
                        ctx.shadowColor = '#000000';

                        // Wooden shaft
                        ctx.fillStyle = '#8b4513';
                        ctx.fillRect(-length / 2, -width / 2, length * 0.7, width);

                        // Iron tip
                        ctx.fillStyle = '#696969';
                        ctx.beginPath();
                        ctx.moveTo(length * 0.2, 0);
                        ctx.lineTo(length * 0.5, -width);
                        ctx.lineTo(length * 0.5, width);
                        ctx.closePath();
                        ctx.fill();

                        // Tip shine
                        ctx.fillStyle = '#c0c0c0';
                        ctx.beginPath();
                        ctx.moveTo(length * 0.25, 0);
                        ctx.lineTo(length * 0.45, -width * 0.5);
                        ctx.lineTo(length * 0.45, width * 0.5);
                        ctx.closePath();
                        ctx.fill();

                        // Golden glow around pilum
                        ctx.shadowBlur = 20;
                        ctx.shadowColor = '#ffd700';
                        ctx.strokeStyle = '#ffd700';
                        ctx.lineWidth = 2;
                        ctx.globalAlpha = 0.6;
                        ctx.beginPath();
                        ctx.moveTo(-length / 2, 0);
                        ctx.lineTo(length * 0.5, 0);
                        ctx.stroke();

                        ctx.restore();
                    }
                    // Special rendering for Doru (Spartan Hoplite)
                    else if (proj.isDoru) {
                        // Doru trail effect
                        if (!proj.trail) proj.trail = [];
                        proj.trail.push({ x: proj.x, y: proj.y, time: Date.now() });
                        if (proj.trail.length > 12) proj.trail.shift();

                        // Render trail
                        proj.trail.forEach((point, index) => {
                            const age = Date.now() - point.time;
                            const alpha = Math.max(0, 1 - (age / 350));
                            const size = proj.size * (0.3 + (index / proj.trail.length) * 0.7);

                            ctx.globalAlpha = alpha * 0.6;
                            ctx.fillStyle = '#8B0000'; // Rojo espartano
                            ctx.beginPath();
                            ctx.arc(point.x, point.y, size * 0.4, 0, Math.PI * 2);
                            ctx.fill();
                        });

                        ctx.globalAlpha = 1;

                        // Doru body (lanza espartana)
                        const length = 45;
                        const width = 7;
                        ctx.save();
                        ctx.translate(proj.x, proj.y);
                        ctx.rotate(proj.angle);

                        // Shaft shadow
                        ctx.shadowBlur = 18;
                        ctx.shadowColor = '#8B0000';

                        // Wooden shaft
                        ctx.fillStyle = '#8B4513';
                        ctx.fillRect(-length / 2, -width / 2, length * 0.65, width);

                        // Bronze tip
                        ctx.fillStyle = '#CD7F32';
                        ctx.beginPath();
                        ctx.moveTo(length * 0.15, 0);
                        ctx.lineTo(length * 0.5, -width * 1.2);
                        ctx.lineTo(length * 0.5, width * 1.2);
                        ctx.closePath();
                        ctx.fill();

                        // Tip shine
                        ctx.fillStyle = '#DAA520';
                        ctx.beginPath();
                        ctx.moveTo(length * 0.2, 0);
                        ctx.lineTo(length * 0.45, -width * 0.6);
                        ctx.lineTo(length * 0.45, width * 0.6);
                        ctx.closePath();
                        ctx.fill();

                        // Red glow around doru
                        ctx.shadowBlur = 22;
                        ctx.shadowColor = '#8B0000';
                        ctx.strokeStyle = '#8B0000';
                        ctx.lineWidth = 2;
                        ctx.globalAlpha = 0.7;
                        ctx.beginPath();
                        ctx.moveTo(-length / 2, 0);
                        ctx.lineTo(length * 0.5, 0);
                        ctx.stroke();

                        ctx.restore();
                    } else {
                        // Normal projectile rendering
                        ctx.fillStyle = proj.color;
                        ctx.shadowBlur = 10;
                        ctx.shadowColor = proj.color;
                        ctx.beginPath();
                        ctx.arc(proj.x, proj.y, proj.size, 0, Math.PI * 2);
                        ctx.fill();
                    }

                    ctx.restore();
                });

                // Render shadow clones
                if (this.shadowClones && this.shadowClones.length > 0) {
                    this.shadowClones.forEach(clone => {
                        ctx.save();

                        // Pulsing shadow effect
                        const pulse = 1 + Math.sin(Date.now() / 200) * 0.1;
                        const size = 25 * pulse;

                        // Shadow gradient
                        const gradient = ctx.createRadialGradient(clone.x, clone.y, 0, clone.x, clone.y, size);
                        gradient.addColorStop(0, 'rgba(47, 47, 47, 0.9)');
                        gradient.addColorStop(0.5, 'rgba(47, 47, 47, 0.6)');
                        gradient.addColorStop(1, 'rgba(47, 47, 47, 0.2)');

                        ctx.fillStyle = gradient;
                        ctx.beginPath();
                        ctx.arc(clone.x, clone.y, size, 0, Math.PI * 2);
                        ctx.fill();

                        // Clone icon
                        ctx.font = '32px Arial';
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';
                        ctx.fillStyle = '#2f2f2f';
                        ctx.shadowBlur = 15;
                        ctx.shadowColor = '#000000';
                        ctx.fillText('??', clone.x, clone.y);

                        ctx.restore();
                    });
                }

                // Render wind singularities (Tornado Overlord)
                if (this.windSingularities && this.windSingularities.length > 0) {
                    this.windSingularities.forEach(singularity => {
                        ctx.save();

                        // Pulsing black hole effect
                        const pulse = 1 + Math.sin(Date.now() / 150) * 0.3;
                        const size = singularity.radius * pulse;

                        // Dark center
                        const gradient = ctx.createRadialGradient(singularity.x, singularity.y, 0, singularity.x, singularity.y, size);
                        gradient.addColorStop(0, 'rgba(0, 0, 0, 0.9)');
                        gradient.addColorStop(0.3, 'rgba(57, 255, 20, 0.6)');
                        gradient.addColorStop(0.7, 'rgba(57, 255, 20, 0.3)');
                        gradient.addColorStop(1, 'rgba(57, 255, 20, 0.1)');

                        ctx.fillStyle = gradient;
                        ctx.beginPath();
                        ctx.arc(singularity.x, singularity.y, size, 0, Math.PI * 2);
                        ctx.fill();

                        // Swirling effect
                        for (let i = 0; i < 8; i++) {
                            const angle = (Date.now() / 100 + i * Math.PI / 4) % (Math.PI * 2);
                            const x = singularity.x + Math.cos(angle) * size * 0.8;
                            const y = singularity.y + Math.sin(angle) * size * 0.8;

                            ctx.font = '16px Arial';
                            ctx.textAlign = 'center';
                            ctx.fillStyle = '#39ff14';
                            ctx.fillText('??', x, y);
                        }

                        ctx.restore();
                    });
                }

                // Render static storms (Tornado Overlord)
                if (this.staticStorms && this.staticStorms.length > 0) {
                    this.staticStorms.forEach(storm => {
                        ctx.save();

                        // Lightning storm effect
                        const pulse = 1 + Math.sin(Date.now() / 200) * 0.2;
                        const size = storm.radius * pulse;

                        // Storm gradient
                        const gradient = ctx.createRadialGradient(storm.x, storm.y, 0, storm.x, storm.y, size);
                        gradient.addColorStop(0, 'rgba(255, 255, 0, 0.8)');
                        gradient.addColorStop(0.5, 'rgba(57, 255, 20, 0.5)');
                        gradient.addColorStop(1, 'rgba(57, 255, 20, 0.1)');

                        ctx.fillStyle = gradient;
                        ctx.beginPath();
                        ctx.arc(storm.x, storm.y, size, 0, Math.PI * 2);
                        ctx.fill();

                        // Lightning bolts
                        ctx.font = '24px Arial';
                        ctx.textAlign = 'center';
                        ctx.fillStyle = '#ffff00';
                        ctx.shadowBlur = 15;
                        ctx.shadowColor = '#ffff00';
                        ctx.fillText('?', storm.x, storm.y);

                        ctx.restore();
                    });
                }

                // Render singularity grenades (Cybernetic Warlord)
                if (this.singularityGrenades && this.singularityGrenades.length > 0) {
                    this.singularityGrenades.forEach(grenade => {
                        ctx.save();

                        if (!grenade.detonated) {
                            // Pulsing gravity field
                            const pulse = 1 + Math.sin(Date.now() / 150) * 0.3;
                            const size = grenade.pullRadius * pulse;

                            // Gravity gradient
                            const gradient = ctx.createRadialGradient(grenade.x, grenade.y, 0, grenade.x, grenade.y, size);
                            gradient.addColorStop(0, 'rgba(138, 43, 226, 0.8)');
                            gradient.addColorStop(0.5, 'rgba(0, 255, 255, 0.4)');
                            gradient.addColorStop(1, 'rgba(0, 255, 255, 0.1)');

                            ctx.fillStyle = gradient;
                            ctx.beginPath();
                            ctx.arc(grenade.x, grenade.y, size, 0, Math.PI * 2);
                            ctx.fill();

                            // Grenade icon
                            ctx.font = '32px Arial';
                            ctx.textAlign = 'center';
                            ctx.fillStyle = '#00ffff';
                            ctx.shadowBlur = 20;
                            ctx.shadowColor = '#00ffff';
                            ctx.fillText('??', grenade.x, grenade.y);
                        } else {
                            // Explosion effect
                            const explosionSize = grenade.radius * 1.5;
                            const gradient = ctx.createRadialGradient(grenade.x, grenade.y, 0, grenade.x, grenade.y, explosionSize);
                            gradient.addColorStop(0, 'rgba(255, 255, 255, 1)');
                            gradient.addColorStop(0.3, 'rgba(0, 255, 255, 0.8)');
                            gradient.addColorStop(1, 'rgba(138, 43, 226, 0)');

                            ctx.fillStyle = gradient;
                            ctx.beginPath();
                            ctx.arc(grenade.x, grenade.y, explosionSize, 0, Math.PI * 2);
                            ctx.fill();
                        }

                        ctx.restore();
                    });
                }

                // Render combat drones (Cybernetic Warlord)
                if (this.combatDrones && this.combatDrones.length > 0) {
                    this.combatDrones.forEach(drone => {
                        const droneX = Player.x + Math.cos(drone.angle) * drone.distance;
                        const droneY = Player.y + Math.sin(drone.angle) * drone.distance;

                        ctx.save();

                        // Drone body
                        const gradient = ctx.createRadialGradient(droneX, droneY, 0, droneX, droneY, 15);
                        gradient.addColorStop(0, 'rgba(0, 255, 255, 1)');
                        gradient.addColorStop(1, 'rgba(0, 150, 150, 0.6)');

                        ctx.fillStyle = gradient;
                        ctx.beginPath();
                        ctx.arc(droneX, droneY, 15, 0, Math.PI * 2);
                        ctx.fill();

                        // Drone icon
                        ctx.font = '20px Arial';
                        ctx.textAlign = 'center';
                        ctx.fillStyle = '#ffffff';
                        ctx.shadowBlur = 10;
                        ctx.shadowColor = '#00ffff';
                        ctx.fillText('??', droneX, droneY + 5);

                        ctx.restore();
                    });
                }

                // Render photon barriers (Cybernetic Warlord)
                if (this.photonBarriers && this.photonBarriers.length > 0) {
                    this.photonBarriers.forEach(barrier => {
                        ctx.save();

                        // Pulsing energy barrier
                        const pulse = 1 + Math.sin(Date.now() / 100) * 0.2;
                        const alpha = 0.6 + Math.sin(Date.now() / 150) * 0.2;

                        // Barrier gradient
                        const gradient = ctx.createLinearGradient(
                            barrier.x - barrier.width / 2, barrier.y - barrier.height / 2,
                            barrier.x + barrier.width / 2, barrier.y + barrier.height / 2
                        );
                        gradient.addColorStop(0, `rgba(0, 255, 255, ${alpha})`);
                        gradient.addColorStop(0.5, `rgba(255, 255, 255, ${alpha})`);
                        gradient.addColorStop(1, `rgba(0, 255, 255, ${alpha})`);

                        ctx.fillStyle = gradient;
                        ctx.fillRect(
                            barrier.x - barrier.width / 2,
                            barrier.y - barrier.height / 2,
                            barrier.width * pulse,
                            barrier.height
                        );

                        // Border glow
                        ctx.strokeStyle = '#00ffff';
                        ctx.lineWidth = 3;
                        ctx.shadowBlur = 20;
                        ctx.shadowColor = '#00ffff';
                        ctx.strokeRect(
                            barrier.x - barrier.width / 2,
                            barrier.y - barrier.height / 2,
                            barrier.width * pulse,
                            barrier.height
                        );

                        ctx.restore();
                    });
                }

                // Render orbital strikes (Cybernetic Warlord)
                if (this.orbitalStrikes && this.orbitalStrikes.length > 0) {
                    this.orbitalStrikes.forEach(orbital => {
                        ctx.save();

                        if (!orbital.fired) {
                            // Warning indicator
                            const pulse = 1 + Math.sin(Date.now() / 100) * 0.3;
                            const size = orbital.radius * pulse;

                            // Red warning circle
                            ctx.strokeStyle = '#ff0000';
                            ctx.lineWidth = 4;
                            ctx.shadowBlur = 20;
                            ctx.shadowColor = '#ff0000';
                            ctx.beginPath();
                            ctx.arc(orbital.x, orbital.y, size, 0, Math.PI * 2);
                            ctx.stroke();

                            // Warning text
                            ctx.font = 'bold 24px Arial';
                            ctx.textAlign = 'center';
                            ctx.fillStyle = '#ff0000';
                            ctx.fillText('??', orbital.x, orbital.y);

                            // Countdown
                            const timeLeft = Math.ceil((orbital.warningTime - (Date.now() - orbital.startTime)) / 1000);
                            ctx.font = 'bold 18px Arial';
                            ctx.fillText(timeLeft, orbital.x, orbital.y + 30);
                        } else {
                            // Laser beam effect
                            const gradient = ctx.createRadialGradient(orbital.x, orbital.y, 0, orbital.x, orbital.y, orbital.radius);
                            gradient.addColorStop(0, 'rgba(255, 255, 255, 1)');
                            gradient.addColorStop(0.3, 'rgba(0, 255, 255, 0.9)');
                            gradient.addColorStop(0.7, 'rgba(0, 150, 255, 0.5)');
                            gradient.addColorStop(1, 'rgba(0, 100, 255, 0)');

                            ctx.fillStyle = gradient;
                            ctx.beginPath();
                            ctx.arc(orbital.x, orbital.y, orbital.radius, 0, Math.PI * 2);
                            ctx.fill();
                        }

                        ctx.restore();
                    });
                }

                // Render burned grounds (Cybernetic Warlord)
                if (this.burnedGrounds && this.burnedGrounds.length > 0) {
                    this.burnedGrounds.forEach(ground => {
                        ctx.save();

                        // Burned ground effect
                        const alpha = 0.4 + Math.sin(Date.now() / 200) * 0.1;
                        const gradient = ctx.createRadialGradient(ground.x, ground.y, 0, ground.x, ground.y, ground.radius);
                        gradient.addColorStop(0, `rgba(255, 100, 0, ${alpha})`);
                        gradient.addColorStop(0.5, `rgba(200, 50, 0, ${alpha * 0.7})`);
                        gradient.addColorStop(1, `rgba(100, 0, 0, 0)`);

                        ctx.fillStyle = gradient;
                        ctx.beginPath();
                        ctx.arc(ground.x, ground.y, ground.radius, 0, Math.PI * 2);
                        ctx.fill();

                        // Fire particles
                        for (let i = 0; i < 5; i++) {
                            const angle = (Date.now() / 500 + i * Math.PI * 2 / 5) % (Math.PI * 2);
                            const dist = ground.radius * 0.6;
                            const x = ground.x + Math.cos(angle) * dist;
                            const y = ground.y + Math.sin(angle) * dist;

                            ctx.font = '16px Arial';
                            ctx.textAlign = 'center';
                            ctx.fillStyle = '#ff6600';
                            ctx.fillText('??', x, y);
                        }

                        ctx.restore();
                    });
                }

                // Render Gladius Fulminante thrusts (Roman Legionary)
                if (this.gladiusThrusts && this.gladiusThrusts.length > 0) {
                    this.gladiusThrusts = this.gladiusThrusts.filter(thrust => {
                        const age = Date.now() - thrust.createdAt;
                        if (age >= thrust.lifetime) return false;

                        ctx.save();

                        // Línea de estocada con efecto de brillo
                        const alpha = 1 - (age / thrust.lifetime);
                        ctx.globalAlpha = alpha;

                        // Sombra brillante
                        ctx.shadowColor = thrust.color;
                        ctx.shadowBlur = 15;

                        // Línea principal
                        ctx.strokeStyle = thrust.color;
                        ctx.lineWidth = thrust.width;
                        ctx.lineCap = 'round';
                        ctx.beginPath();
                        ctx.moveTo(thrust.startX, thrust.startY);
                        ctx.lineTo(thrust.endX, thrust.endY);
                        ctx.stroke();

                        // Línea dorada interior
                        ctx.strokeStyle = '#ffd700';
                        ctx.lineWidth = thrust.width / 2;
                        ctx.beginPath();
                        ctx.moveTo(thrust.startX, thrust.startY);
                        ctx.lineTo(thrust.endX, thrust.endY);
                        ctx.stroke();

                        ctx.restore();
                        return true;
                    });
                }

                // Render Testudo shockwaves (Roman Legionary)
                if (this.testudoShockwaves && this.testudoShockwaves.length > 0) {
                    this.testudoShockwaves = this.testudoShockwaves.filter(wave => {
                        const age = Date.now() - wave.createdAt;
                        if (age >= wave.lifetime) return false;

                        // Expandir onda
                        wave.radius = Math.min(wave.maxRadius, (age / wave.lifetime) * wave.maxRadius);

                        ctx.save();

                        const alpha = 1 - (age / wave.lifetime);
                        ctx.globalAlpha = alpha;

                        // Onda de choque dorada
                        ctx.strokeStyle = wave.color;
                        ctx.lineWidth = 4;
                        ctx.shadowBlur = 20;
                        ctx.shadowColor = wave.color;
                        ctx.beginPath();
                        ctx.arc(wave.x, wave.y, wave.radius, 0, Math.PI * 2);
                        ctx.stroke();

                        // Onda interior dorada (solo si el radio es suficiente)
                        if (wave.radius > 5) {
                            ctx.strokeStyle = '#ffd700';
                            ctx.lineWidth = 2;
                            ctx.beginPath();
                            ctx.arc(wave.x, wave.y, wave.radius - 3, 0, Math.PI * 2);
                            ctx.stroke();
                        }

                        ctx.restore();
                        return true;
                    });
                }

                // Render Imperial Eagles (Roman Legionary)
                if (this.imperialEagles && this.imperialEagles.length > 0) {
                    this.imperialEagles = this.imperialEagles.filter(eagle => {
                        const age = Date.now() - eagle.startTime;
                        if (age >= eagle.duration) return false;

                        ctx.save();

                        // Águila dorada gigante con aura brillante
                        const pulse = 1 + Math.sin(Date.now() / 100) * 0.1;
                        const size = eagle.size * pulse;

                        // Aura dorada radiante
                        const auraGradient = ctx.createRadialGradient(
                            eagle.x, eagle.y, 0,
                            eagle.x, eagle.y, size * 1.5
                        );
                        auraGradient.addColorStop(0, 'rgba(255, 215, 0, 0.8)');
                        auraGradient.addColorStop(0.5, 'rgba(255, 215, 0, 0.4)');
                        auraGradient.addColorStop(1, 'rgba(255, 215, 0, 0)');

                        ctx.fillStyle = auraGradient;
                        ctx.beginPath();
                        ctx.arc(eagle.x, eagle.y, size * 1.5, 0, Math.PI * 2);
                        ctx.fill();

                        // Águila
                        ctx.font = `${size}px Arial`;
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';
                        ctx.shadowBlur = 30;
                        ctx.shadowColor = '#ffd700';
                        ctx.fillStyle = '#ffd700';
                        ctx.fillText('??', eagle.x, eagle.y);

                        // Rayos de luz dorados
                        const rayCount = 12;
                        for (let i = 0; i < rayCount; i++) {
                            const angle = (Math.PI * 2 / rayCount) * i + (Date.now() / 500);
                            const rayLength = 60 + Math.sin(Date.now() / 200 + i) * 20;

                            ctx.strokeStyle = 'rgba(255, 215, 0, 0.6)';
                            ctx.lineWidth = 3;
                            ctx.beginPath();
                            ctx.moveTo(eagle.x, eagle.y);
                            ctx.lineTo(
                                eagle.x + Math.cos(angle) * rayLength,
                                eagle.y + Math.sin(angle) * rayLength
                            );
                            ctx.stroke();
                        }

                        ctx.restore();
                        return true;
                    });
                }

                // Render Phalanx shockwaves (Spartan Hoplite)
                if (this.phalanxShockwaves && this.phalanxShockwaves.length > 0) {
                    this.phalanxShockwaves = this.phalanxShockwaves.filter(wave => {
                        const age = Date.now() - wave.createdAt;
                        if (age >= wave.lifetime) return false;

                        wave.radius = Math.min(wave.maxRadius, (age / wave.lifetime) * wave.maxRadius);

                        ctx.save();

                        const alpha = 1 - (age / wave.lifetime);
                        ctx.globalAlpha = alpha;

                        // Onda de choque roja espartana
                        ctx.strokeStyle = wave.color;
                        ctx.lineWidth = 5;
                        ctx.shadowBlur = 22;
                        ctx.shadowColor = wave.color;
                        ctx.beginPath();
                        ctx.arc(wave.x, wave.y, wave.radius, 0, Math.PI * 2);
                        ctx.stroke();

                        // Onda interior de bronce
                        if (wave.radius > 5) {
                            ctx.strokeStyle = '#CD7F32';
                            ctx.lineWidth = 3;
                            ctx.beginPath();
                            ctx.arc(wave.x, wave.y, wave.radius - 3, 0, Math.PI * 2);
                            ctx.stroke();
                        }

                        ctx.restore();
                        return true;
                    });
                }

                // Render Eagle shockwaves (Roman Legionary)
                if (this.eagleShockwaves && this.eagleShockwaves.length > 0) {
                    this.eagleShockwaves = this.eagleShockwaves.filter(wave => {
                        const age = Date.now() - wave.createdAt;
                        if (age >= wave.lifetime) return false;

                        wave.radius = Math.min(wave.maxRadius, (age / wave.lifetime) * wave.maxRadius);

                        ctx.save();

                        const alpha = 1 - (age / wave.lifetime);
                        ctx.globalAlpha = alpha;

                        // Onda dorada brillante
                        ctx.strokeStyle = wave.color;
                        ctx.lineWidth = 8;
                        ctx.shadowBlur = 30;
                        ctx.shadowColor = wave.color;
                        ctx.beginPath();
                        ctx.arc(wave.x, wave.y, wave.radius, 0, Math.PI * 2);
                        ctx.stroke();

                        // Onda interior carmesí (solo si el radio es suficiente)
                        if (wave.radius > 6) {
                            ctx.strokeStyle = '#dc143c';
                            ctx.lineWidth = 4;
                            ctx.beginPath();
                            ctx.arc(wave.x, wave.y, wave.radius - 4, 0, Math.PI * 2);
                            ctx.stroke();
                        }

                        // Plumas doradas en la onda
                        const featherCount = 12;
                        for (let i = 0; i < featherCount; i++) {
                            const angle = (Math.PI * 2 / featherCount) * i;
                            const featherX = wave.x + Math.cos(angle) * wave.radius;
                            const featherY = wave.y + Math.sin(angle) * wave.radius;

                            ctx.font = 'bold 14px Arial';
                            ctx.fillStyle = '#ffd700';
                            ctx.textAlign = 'center';
                            ctx.shadowBlur = 15;
                            ctx.fillText('??', featherX, featherY);
                        }

                        ctx.restore();
                        return true;
                    });
                }

                // Render AROO sound waves (Spartan Hoplite)
                if (this.arooWaves && this.arooWaves.length > 0) {
                    this.arooWaves = this.arooWaves.filter(wave => {
                        const age = Date.now() - wave.createdAt;
                        if (age >= wave.lifetime) return false;

                        wave.radius = Math.min(wave.maxRadius, (age / wave.lifetime) * wave.maxRadius);

                        ctx.save();

                        const alpha = 1 - (age / wave.lifetime);
                        ctx.globalAlpha = alpha;

                        // Onda de sonido roja espartana masiva
                        const vibration = Math.sin(Date.now() / 40) * 4;
                        const mainRadius = Math.max(1, wave.radius + vibration);

                        ctx.strokeStyle = wave.color;
                        ctx.lineWidth = 8;
                        ctx.shadowBlur = 30;
                        ctx.shadowColor = wave.color;
                        ctx.beginPath();
                        ctx.arc(wave.x, wave.y, mainRadius, 0, Math.PI * 2);
                        ctx.stroke();

                        // Onda secundaria de bronce
                        const secondaryRadius = wave.radius - 6 + vibration;
                        if (secondaryRadius > 1) {
                            ctx.strokeStyle = '#CD7F32';
                            ctx.lineWidth = 4;
                            ctx.beginPath();
                            ctx.arc(wave.x, wave.y, secondaryRadius, 0, Math.PI * 2);
                            ctx.stroke();
                        }

                        // Símbolos lambda espartanos en la onda
                        const symbolCount = 10;
                        for (let i = 0; i < symbolCount; i++) {
                            const angle = (Math.PI * 2 / symbolCount) * i + (Date.now() / 600);
                            const symbolX = wave.x + Math.cos(angle) * wave.radius;
                            const symbolY = wave.y + Math.sin(angle) * wave.radius;

                            ctx.font = 'bold 18px Arial';
                            ctx.fillStyle = '#CD7F32';
                            ctx.textAlign = 'center';
                            ctx.shadowBlur = 12;
                            ctx.fillText('?', symbolX, symbolY);
                        }

                        ctx.restore();
                        return true;
                    });
                }

                // Render Centurion sound waves (Roman Legionary)
                if (this.centurionWaves && this.centurionWaves.length > 0) {
                    this.centurionWaves = this.centurionWaves.filter(wave => {
                        const age = Date.now() - wave.createdAt;
                        if (age >= wave.lifetime) return false;

                        // Expandir onda de sonido
                        wave.radius = Math.min(wave.maxRadius, (age / wave.lifetime) * wave.maxRadius);

                        ctx.save();

                        const alpha = 1 - (age / wave.lifetime);
                        ctx.globalAlpha = alpha;

                        // Onda de sonido carmesí con efecto de vibración
                        const vibration = Math.sin(Date.now() / 50) * 3;

                        // Onda principal - asegurar que el radio sea positivo
                        const mainRadius = Math.max(1, wave.radius + vibration);
                        ctx.strokeStyle = wave.color;
                        ctx.lineWidth = 6;
                        ctx.shadowBlur = 25;
                        ctx.shadowColor = wave.color;
                        ctx.beginPath();
                        ctx.arc(wave.x, wave.y, mainRadius, 0, Math.PI * 2);
                        ctx.stroke();

                        // Onda secundaria (solo si el radio es suficiente para evitar negativos)
                        const secondaryRadius = wave.radius - 5 + vibration;
                        if (secondaryRadius > 1) {
                            ctx.strokeStyle = '#ffd700';
                            ctx.lineWidth = 3;
                            ctx.beginPath();
                            ctx.arc(wave.x, wave.y, secondaryRadius, 0, Math.PI * 2);
                            ctx.stroke();
                        }

                        // Símbolos romanos en la onda
                        const symbolCount = 8;
                        for (let i = 0; i < symbolCount; i++) {
                            const angle = (Math.PI * 2 / symbolCount) * i + (Date.now() / 500);
                            const symbolX = wave.x + Math.cos(angle) * wave.radius;
                            const symbolY = wave.y + Math.sin(angle) * wave.radius;

                            ctx.font = 'bold 16px Arial';
                            ctx.fillStyle = '#ffd700';
                            ctx.textAlign = 'center';
                            ctx.shadowBlur = 10;
                            ctx.fillText('??', symbolX, symbolY);
                        }

                        ctx.restore();
                        return true;
                    });
                }

                // Render Aether Dragon special effects
                this.bosses.forEach(boss => {
                    if (boss.type === 'aether_dragon' || boss.name === 'Dragón del Éter') {
                        ctx.save();

                        // Render Destruction Shield
                        if (boss.destructionShield && boss.destructionShield.active) {
                            const shield = boss.destructionShield;
                            shield.pulsePhase += 0.05;
                            const pulse = 1 + Math.sin(shield.pulsePhase) * 0.2;
                            const shieldRadius = shield.radius * pulse;

                            // Shield gradient
                            const gradient = ctx.createRadialGradient(boss.x, boss.y, 0, boss.x, boss.y, shieldRadius);
                            gradient.addColorStop(0, 'rgba(147, 112, 219, 0.6)');
                            gradient.addColorStop(0.7, 'rgba(147, 112, 219, 0.4)');
                            gradient.addColorStop(1, 'rgba(147, 112, 219, 0)');

                            ctx.fillStyle = gradient;
                            ctx.beginPath();
                            ctx.arc(boss.x, boss.y, shieldRadius, 0, Math.PI * 2);
                            ctx.fill();

                            // Shield border
                            ctx.strokeStyle = '#9370DB';
                            ctx.lineWidth = 4;
                            ctx.shadowBlur = 20;
                            ctx.shadowColor = '#9370DB';
                            ctx.beginPath();
                            ctx.arc(boss.x, boss.y, shieldRadius, 0, Math.PI * 2);
                            ctx.stroke();

                            // Shield text
                            ctx.font = 'bold 16px Orbitron';
                            ctx.fillStyle = '#9370DB';
                            ctx.textAlign = 'center';
                            ctx.shadowBlur = 15;
                            ctx.shadowColor = '#9370DB';
                            ctx.fillText('INVENCIBLE', boss.x, boss.y - 30);
                            ctx.fillText('¡Elimina los sirvientes!', boss.x, boss.y + 30);
                        }

                        // Render Death Ray charging effect
                        if (boss.deathRayCharging) {
                            const chargeProgress = 1 - ((boss.deathRayTarget ? 2000 : 0) / 2000);
                            const chargeRadius = 60 + (chargeProgress * 40);

                            // Charging aura
                            const gradient = ctx.createRadialGradient(boss.x, boss.y, 0, boss.x, boss.y, chargeRadius);
                            gradient.addColorStop(0, 'rgba(147, 112, 219, 0.8)');
                            gradient.addColorStop(1, 'rgba(147, 112, 219, 0)');

                            ctx.fillStyle = gradient;
                            ctx.beginPath();
                            ctx.arc(boss.x, boss.y, chargeRadius, 0, Math.PI * 2);
                            ctx.fill();

                            // Warning text
                            ctx.font = 'bold 14px Arial';
                            ctx.fillStyle = '#9370DB';
                            ctx.textAlign = 'center';
                            ctx.shadowBlur = 15;
                            ctx.shadowColor = '#9370DB';
                            ctx.fillText('íCARGANDO RAYO!', boss.x, boss.y - boss.size - 30);
                        }

                        // Render Ether Explosion charging
                        if (boss.etherExplosionCharging) {
                            const pulse = 1 + Math.sin(Date.now() / 100) * 0.3;
                            const explosionRadius = 80 * pulse;

                            const gradient = ctx.createRadialGradient(boss.x, boss.y, 0, boss.x, boss.y, explosionRadius);
                            gradient.addColorStop(0, 'rgba(147, 112, 219, 0.7)');
                            gradient.addColorStop(1, 'rgba(147, 112, 219, 0)');

                            ctx.fillStyle = gradient;
                            ctx.beginPath();
                            ctx.arc(boss.x, boss.y, explosionRadius, 0, Math.PI * 2);
                            ctx.fill();
                        }

                        // Render Cursed Barrier trail
                        if (boss.cursedBarrierActive) {
                            const radius = 100;
                            for (let i = 0; i < 8; i++) {
                                const angle = boss.cursedBarrierAngle + (Math.PI * 2 / 8) * i;
                                const trailX = boss.x + Math.cos(angle) * radius;
                                const trailY = boss.y + Math.sin(angle) * radius;

                                // Trail glow
                                const gradient = ctx.createRadialGradient(trailX, trailY, 0, trailX, trailY, 25);
                                gradient.addColorStop(0, 'rgba(147, 112, 219, 0.9)');
                                gradient.addColorStop(1, 'rgba(147, 112, 219, 0)');

                                ctx.fillStyle = gradient;
                                ctx.beginPath();
                                ctx.arc(trailX, trailY, 25, 0, Math.PI * 2);
                                ctx.fill();
                            }
                        }

                        ctx.restore();
                    }
                });

                // Render Curse aura on player (visual effect only, status shown in top bar)
                if (Player.cursed && Date.now() < Player.curseEndTime) {
                    ctx.save();

                    // Purple aura around player
                    const cursePhase = Date.now() / 200;
                    const cursePulse = 1 + Math.sin(cursePhase) * 0.3;
                    const curseRadius = 50 * cursePulse;

                    const gradient = ctx.createRadialGradient(Player.x, Player.y, 0, Player.x, Player.y, curseRadius);
                    gradient.addColorStop(0, 'rgba(147, 112, 219, 0.5)');
                    gradient.addColorStop(1, 'rgba(147, 112, 219, 0)');

                    ctx.fillStyle = gradient;
                    ctx.beginPath();
                    ctx.arc(Player.x, Player.y, curseRadius, 0, Math.PI * 2);
                    ctx.fill();

                    ctx.restore();
                }

                // Render boss health bars at top of screen
                this.renderBossHealthBars(ctx);

                // Render Las Termópilas (Spartan Hoplite Ultimate)
                if (Player.thermopylaeActive) {
                    const canvas = ctx.canvas;

                    // Oscurecer el campo de batalla
                    ctx.fillStyle = 'rgba(0, 0, 0, 0.65)';
                    ctx.fillRect(0, 0, canvas.width, canvas.height);

                    // Renderizar hoplitas espartanos
                    if (Player.thermopylaeHoplites) {
                        ctx.save();
                        ctx.font = '22px Arial';
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';
                        ctx.shadowBlur = 10;

                        Player.thermopylaeHoplites.forEach(hoplite => {
                            // Mover hoplitas hacia adelante
                            hoplite.y -= hoplite.speed;

                            // Solo renderizar si está visible
                            if (hoplite.y < -50 || hoplite.y > canvas.height + 50) return;

                            // Efecto fantasmal pulsante
                            const pulse = 0.65 + Math.sin(Date.now() / 180 + hoplite.x) * 0.2;
                            ctx.globalAlpha = pulse;

                            // Escudo hoplon rojo
                            ctx.shadowColor = '#8B0000';
                            ctx.fillStyle = '#8B0000';
                            ctx.fillText('???', hoplite.x, hoplite.y);

                            // Lanza de bronce
                            ctx.shadowColor = '#CD7F32';
                            ctx.fillStyle = '#CD7F32';
                            ctx.fillText('???', hoplite.x + 10, hoplite.y);
                        });

                        ctx.restore();
                    }

                    // Texto Épico (solo primeros 2 segundos)
                    const elapsed = Date.now() - Player.thermopylaeStartTime;

                    if (elapsed < 2000) {
                        const textAlpha = Math.min(1, elapsed / 500);

                        ctx.save();
                        ctx.globalAlpha = textAlpha;
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';

                        // Título
                        ctx.font = 'bold 68px Orbitron';
                        ctx.fillStyle = '#8B0000';
                        ctx.shadowBlur = 35;
                        ctx.shadowColor = '#8B0000';
                        ctx.fillText('LAS TERMÓPILAS', canvas.width / 2, canvas.height / 2 - 100);

                        // Subtítulo
                        ctx.font = 'bold 34px Orbitron';
                        ctx.fillStyle = '#CD7F32';
                        ctx.shadowColor = '#CD7F32';
                        ctx.fillText('?? LOS 300 DE ESPARTA ??', canvas.width / 2, canvas.height / 2 - 40);

                        // Frase legendaria
                        ctx.font = 'bold 22px Arial';
                        ctx.fillStyle = '#ffffff';
                        ctx.shadowBlur = 18;
                        ctx.shadowColor = '#ffffff';
                        ctx.fillText('Esta noche cenamos en el Hades', canvas.width / 2, canvas.height / 2 + 20);

                        ctx.restore();
                    }
                }

                // Render Legio Aeterna (Roman Legionary Ultimate)
                if (Player.legioAeternaActive) {
                    const canvas = ctx.canvas;

                    // Oscurecer el campo de batalla
                    ctx.fillStyle = 'rgba(0, 0, 0, 0.6)';
                    ctx.fillRect(0, 0, canvas.width, canvas.height);

                    // Renderizar legionarios fantasmales (OPTIMIZADO - Con efectos visuales Épicos)
                    if (Player.legioAeternaLegionaries) {
                        ctx.save();
                        ctx.font = '24px Arial';
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';
                        ctx.shadowBlur = 8; // Sombra moderada para rendimiento

                        Player.legioAeternaLegionaries.forEach(leg => {
                            // Mover legionarios hacia adelante
                            leg.y -= leg.speed;

                            // Solo renderizar si está visible en pantalla
                            if (leg.y < -50 || leg.y > canvas.height + 50) return;

                            // Alpha con variación para efecto fantasmal
                            const pulse = 0.6 + Math.sin(Date.now() / 200 + leg.x) * 0.15;
                            ctx.globalAlpha = pulse;

                            // Escudo dorado con sombra
                            ctx.shadowColor = '#ffd700';
                            ctx.fillStyle = '#ffd700';
                            ctx.fillText('???', leg.x, leg.y);

                            // Espada carmesí con sombra
                            ctx.shadowColor = '#dc143c';
                            ctx.fillStyle = '#dc143c';
                            ctx.fillText('??', leg.x + 8, leg.y);
                        });

                        ctx.restore();
                    }

                    // Texto Épico en el centro (OPTIMIZADO: solo mostrar durante los primeros 2 segundos)
                    const elapsed = Date.now() - Player.legioAeternaStartTime;

                    if (elapsed < 2000) {
                        const textAlpha = Math.min(1, elapsed / 500);

                        ctx.save();
                        ctx.globalAlpha = textAlpha;
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';

                        // Título principal
                        ctx.font = 'bold 72px Orbitron';
                        ctx.fillStyle = '#ffd700';
                        ctx.shadowBlur = 30; // Reducido de 40 a 30
                        ctx.shadowColor = '#ffd700';
                        ctx.fillText('LEGIO AETERNA', canvas.width / 2, canvas.height / 2 - 100);

                        // Subtítulo
                        ctx.font = 'bold 36px Orbitron';
                        ctx.fillStyle = '#dc143c';
                        ctx.shadowColor = '#dc143c';
                        ctx.fillText('?? LA LEGIÓN ETERNA ??', canvas.width / 2, canvas.height / 2 - 40);

                        // Lema romano
                        ctx.font = 'bold 24px Arial';
                        ctx.fillStyle = '#ffffff';
                        ctx.shadowBlur = 15; // Reducido de 20 a 15
                        ctx.shadowColor = '#ffffff';
                        ctx.fillText('Gloria Imperii Romani', canvas.width / 2, canvas.height / 2 + 20);

                        ctx.restore();
                    }
                }

                // Render pause overlay
                if (this.paused) {
                    const canvas = ctx.canvas;
                    ctx.fillStyle = 'rgba(0, 0, 0, 0.7)';
                    ctx.fillRect(0, 0, canvas.width, canvas.height);

                    ctx.font = 'bold 72px Orbitron';
                    ctx.fillStyle = '#ffffff';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.shadowColor = '#00d9ff';
                    ctx.shadowBlur = 30;
                    ctx.fillText('?? PAUSED', canvas.width / 2, canvas.height / 2 - 40);

                    ctx.font = 'bold 24px Orbitron';
                    ctx.fillStyle = '#ffbe0b';
                    ctx.shadowBlur = 15;
                    ctx.fillText('Press Z to Resume', canvas.width / 2, canvas.height / 2 + 40);
                    ctx.shadowBlur = 0;
                }

                // Render ability cooldowns in fullscreen
                this.renderAbilityCooldowns(ctx);

                // Render floating texts (critical hits, etc.)
                this.renderFloatingTexts(ctx);

                // Render canvas notifications (ticket drops, unlock notifications)
                this.renderCanvasNotifications(ctx);

                // Render unlock indicators
                this.renderUnlockIndicators(ctx);

                // Render mission tracker
                this.renderMissionTracker(ctx);

                // NEW v19.11.2025: Render attack indicators (telegraphing)
                this.renderAttackIndicators(ctx);
            },

            renderCanvasNotifications(ctx) {
                if (!this.canvasNotifications) return;

                const now = Date.now();
                this.canvasNotifications = this.canvasNotifications.filter(notif => {
                    const elapsed = now - notif.startTime;
                    if (elapsed >= notif.duration) return false;

                    const progress = elapsed / notif.duration;
                    const alpha = 1 - progress;
                    const yOffset = progress * 100; // Float up

                    ctx.save();
                    ctx.globalAlpha = alpha;
                    ctx.font = notif.isUnlockNotification ? 'bold 32px Orbitron' : 'bold 24px Arial';
                    ctx.fillStyle = notif.color;
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.shadowColor = notif.color;
                    ctx.shadowBlur = 20;

                    const displayY = notif.y - yOffset;
                    ctx.fillText(notif.text, notif.x, displayY);

                    ctx.restore();
                    return true;
                });
            },

            renderUnlockIndicators(ctx) {
                const classes = rolesData.classes.filter(c => c.ticketsRequired);
                const unlockable = [];

                classes.forEach(cls => {
                    if (!EquipmentManager.isClassUnlocked(cls.id)) {
                        const currentTickets = EquipmentManager.classTickets[cls.id] || 0;
                        if (currentTickets >= cls.ticketsRequired) {
                            unlockable.push(cls);
                        }
                    }
                });

                if (unlockable.length === 0) return;

                const canvas = ctx.canvas;
                const boxWidth = 250;
                const boxHeight = 40 + (unlockable.length * 35);
                const boxX = canvas.width - boxWidth - 20;
                const boxY = 20;

                // Background box
                ctx.fillStyle = 'rgba(0, 0, 0, 0.85)';
                ctx.fillRect(boxX, boxY, boxWidth, boxHeight);

                // Border with glow
                ctx.strokeStyle = '#00ff00';
                ctx.lineWidth = 3;
                ctx.shadowColor = '#00ff00';
                ctx.shadowBlur = 15;
                ctx.strokeRect(boxX, boxY, boxWidth, boxHeight);
                ctx.shadowBlur = 0;

                // Title
                ctx.font = 'bold 16px Orbitron';
                ctx.fillStyle = '#00ff00';
                ctx.textAlign = 'center';
                ctx.fillText('? READY TO UNLOCK ?', boxX + boxWidth / 2, boxY + 20);

                // List classes
                ctx.font = 'bold 14px Arial';
                ctx.textAlign = 'left';
                unlockable.forEach((cls, index) => {
                    const y = boxY + 45 + (index * 35);

                    // Icon
                    ctx.font = '20px Arial';
                    ctx.fillText(cls.icon, boxX + 15, y);

                    // Name
                    ctx.font = 'bold 14px Arial';
                    ctx.fillStyle = cls.tierColor || '#ffffff';
                    ctx.fillText(cls.name, boxX + 45, y);

                    // Tier badge
                    ctx.font = 'bold 12px Arial';
                    ctx.fillStyle = cls.tierColor || '#ffffff';
                    ctx.fillText(`[${cls.tier}]`, boxX + boxWidth - 50, y);
                });

                // Pulsing animation
                const pulseAlpha = 0.5 + Math.sin(Date.now() / 300) * 0.3;
                ctx.globalAlpha = pulseAlpha;
                ctx.strokeStyle = '#00ff00';
                ctx.lineWidth = 2;
                ctx.strokeRect(boxX - 2, boxY - 2, boxWidth + 4, boxHeight + 4);
                ctx.globalAlpha = 1;
            },

            renderAbilityCooldowns(ctx) {
                const abilities = EquipmentManager.getAllAbilities();
                if (abilities.length === 0) return;

                const canvas = ctx.canvas;
                const abilitySize = 60;
                const abilitySpacing = 15;
                const startX = canvas.width / 2 - ((abilities.length * (abilitySize + abilitySpacing)) / 2);
                const startY = canvas.height - abilitySize - 30;

                abilities.forEach((ability, index) => {
                    const x = startX + (index * (abilitySize + abilitySpacing));
                    const y = startY;

                    // Background
                    ctx.fillStyle = 'rgba(0, 0, 0, 0.7)';
                    ctx.fillRect(x, y, abilitySize, abilitySize);

                    // Border
                    const isReady = ability.currentCooldown === 0;
                    ctx.strokeStyle = isReady ? '#00ff00' : '#666666';
                    ctx.lineWidth = 3;
                    ctx.strokeRect(x, y, abilitySize, abilitySize);

                    // Icon - Try to use image first, fallback to emoji
                    const imageName = normalizeImageName(ability.name);
                    const imagePath = ability.iconImage || `assets/${imageName}.jpg`;

                    // Try to get cached image
                    let img = AssetLoader.getImage(imagePath);

                    // If not cached, try to load it now
                    if (!img) {
                        AssetLoader.loadImage(imagePath);
                        // Also try .jpeg if .jpg fails
                        if (imagePath.endsWith('.jpg')) {
                            const jpegPath = imagePath.replace(/\.jpg$/i, '.jpeg');
                            AssetLoader.loadImage(jpegPath);
                        }
                    }

                    // Check if image is loaded and valid
                    if (img && img.complete && img.naturalWidth > 0) {
                        // Draw image
                        ctx.save();
                        if (!isReady) {
                            ctx.globalAlpha = 0.4;
                        }
                        ctx.drawImage(img, x + 2, y + 2, abilitySize - 4, abilitySize - 4);
                        ctx.restore();
                    } else {
                        // Fallback to emoji
                        ctx.font = '32px Arial';
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';
                        ctx.fillStyle = isReady ? '#ffffff' : '#666666';
                        ctx.fillText(ability.icon, x + abilitySize / 2, y + abilitySize / 2);
                    }

                    // Cooldown overlay
                    if (ability.currentCooldown > 0) {
                        const cooldownPercent = ability.currentCooldown / ability.cooldown;
                        const overlayHeight = abilitySize * cooldownPercent;

                        ctx.fillStyle = 'rgba(0, 0, 0, 0.7)';
                        ctx.fillRect(x, y, abilitySize, overlayHeight);

                        // Cooldown text
                        ctx.font = 'bold 20px Arial';
                        ctx.fillStyle = '#ffffff';
                        ctx.shadowColor = '#000000';
                        ctx.shadowBlur = 5;
                        const seconds = Math.ceil(ability.currentCooldown / 1000);
                        ctx.fillText(seconds, x + abilitySize / 2, y + abilitySize / 2);
                        ctx.shadowBlur = 0;
                    }

                    // Key binding
                    ctx.font = 'bold 12px Arial';
                    ctx.fillStyle = '#ffbe0b';
                    ctx.fillText(ability.keyBinding.toUpperCase(), x + abilitySize / 2, y + abilitySize + 15);
                });

                // Render class progress bar
                this.renderClassProgress(ctx);
            },

            renderClassProgress(ctx) {
                if (!EquipmentManager.equippedRole) return;
                const role = EquipmentManager.equippedRole;
                if (role.type !== 'class' && role.type !== 'master_class') return;

                const classData = ClassProgressionSystem.getClassLevel(role.id);
                const canvas = ctx.canvas;

                // Position above abilities
                const barWidth = 300;
                const barHeight = 30;
                const x = canvas.width / 2 - barWidth / 2;
                const y = canvas.height - 130;

                ctx.save();

                // Background
                ctx.fillStyle = 'rgba(0, 0, 0, 0.8)';
                ctx.strokeStyle = '#ffbe0b';
                ctx.lineWidth = 2;
                ctx.beginPath();
                ctx.roundRect(x, y, barWidth, barHeight, 5);
                ctx.fill();
                ctx.stroke();

                // Progress bar
                const progress = classData.exp / classData.expToNext;
                const progressWidth = (barWidth - 4) * progress;

                const gradient = ctx.createLinearGradient(x + 2, y + 2, x + 2 + progressWidth, y + 2);
                gradient.addColorStop(0, '#ffbe0b');
                gradient.addColorStop(1, '#ff006e');

                ctx.fillStyle = gradient;
                ctx.beginPath();
                ctx.roundRect(x + 2, y + 2, progressWidth, barHeight - 4, 3);
                ctx.fill();

                // Text
                ctx.fillStyle = '#fff';
                ctx.font = 'bold 14px Arial';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.shadowColor = '#000';
                ctx.shadowBlur = 3;

                const levelText = `Nivel ${classData.level}`;
                const expText = `${classData.exp} / ${classData.expToNext} EXP`;
                ctx.fillText(`${levelText} | ${expText}`, x + barWidth / 2, y + barHeight / 2);

                ctx.restore();
            },

            renderFloatingTexts(ctx) {
                if (!this.floatingTexts) return;

                const now = Date.now();
                ctx.save();

                this.floatingTexts = this.floatingTexts.filter(text => {
                    const age = now - text.startTime;
                    if (age > text.life) return false;

                    const progress = age / text.life;
                    const y = text.y - (progress * 50); // Float upwards
                    const alpha = 1 - progress;

                    ctx.globalAlpha = alpha;
                    ctx.font = 'bold 20px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillStyle = text.color;
                    ctx.shadowColor = '#000';
                    ctx.shadowBlur = 5;
                    ctx.fillText(text.text, text.x, y);

                    return true;
                });

                ctx.restore();
            },

            renderBossHealthBars(ctx) {
                if (this.bosses.length === 0) return;

                const canvas = ctx.canvas;
                const barHeight = 40;
                const barPadding = 10;
                let yOffset = 20;

                this.bosses.forEach((boss, index) => {
                    const barWidth = canvas.width * 0.6;
                    const barX = (canvas.width - barWidth) / 2;
                    const barY = yOffset + (index * (barHeight + barPadding));

                    // Background
                    ctx.fillStyle = 'rgba(0, 0, 0, 0.8)';
                    ctx.fillRect(barX - 10, barY - 10, barWidth + 20, barHeight + 20);

                    // Boss icon and name
                    ctx.font = '24px Arial';
                    ctx.textAlign = 'left';
                    ctx.textBaseline = 'middle';
                    ctx.fillText(boss.icon, barX - 40, barY + barHeight / 2);

                    ctx.font = 'bold 16px Orbitron';
                    ctx.fillStyle = '#ffd700';
                    ctx.fillText(`${boss.name} (Lv.${boss.level || 1})`, barX, barY - 5);

                    // HP bar background
                    ctx.fillStyle = 'rgba(50, 50, 50, 0.9)';
                    ctx.fillRect(barX, barY + 15, barWidth, 20);

                    // HP bar fill with validation
                    const hpPercent = Math.max(0, Math.min(1, boss.hp / boss.maxHp));
                    const fillWidth = Math.max(0, barWidth * hpPercent);

                    // Only draw if fillWidth is valid and greater than 0
                    if (fillWidth > 0 && isFinite(fillWidth)) {
                        const gradient = ctx.createLinearGradient(barX, 0, barX + fillWidth, 0);
                        if (hpPercent > 0.5) {
                            gradient.addColorStop(0, '#00ff00');
                            gradient.addColorStop(1, '#00cc00');
                        } else if (hpPercent > 0.25) {
                            gradient.addColorStop(0, '#ffff00');
                            gradient.addColorStop(1, '#ffaa00');
                        } else {
                            gradient.addColorStop(0, '#ff0000');
                            gradient.addColorStop(1, '#cc0000');
                        }

                        ctx.fillStyle = gradient;
                        ctx.fillRect(barX, barY + 15, fillWidth, 20);
                    }

                    // HP text
                    ctx.font = 'bold 14px Arial';
                    ctx.fillStyle = '#ffffff';
                    ctx.textAlign = 'center';
                    ctx.fillText(`${Math.ceil(boss.hp)} / ${boss.maxHp}`, barX + barWidth / 2, barY + 25);

                    // Border
                    ctx.strokeStyle = '#ffd700';
                    ctx.lineWidth = 2;
                    ctx.strokeRect(barX, barY + 15, barWidth, 20);
                });
            },

            renderMissionTracker(ctx) {
                // Only show if LoadoutManager says it should be visible
                if (!LoadoutManager.missionTrackerVisible) return;

                // Check if player has a class equipped with a mastery mission
                if (!EquipmentManager.equippedRole || EquipmentManager.equippedRole.type !== 'class') return;

                const classId = EquipmentManager.equippedRole.id;
                const masterClass = rolesData.masterClasses.find(mc => mc.baseClassId === classId);
                if (!masterClass) return;

                const progress = LoadoutManager.getMissionProgress(classId);
                if (!progress) return;

                const canvas = ctx.canvas;
                const boxWidth = 350;
                const boxX = canvas.width - boxWidth - 20;
                const boxY = canvas.height - 280;

                // Background
                ctx.fillStyle = 'rgba(10, 14, 39, 0.95)';
                ctx.fillRect(boxX, boxY, boxWidth, 260);

                // Border
                ctx.strokeStyle = '#ff00ff';
                ctx.lineWidth = 2;
                ctx.strokeRect(boxX, boxY, boxWidth, 260);

                // Header
                ctx.fillStyle = '#ff00ff';
                ctx.font = 'bold 16px Orbitron';
                ctx.textAlign = 'left';
                ctx.fillText('? MISIÓN ACTIVA', boxX + 15, boxY + 25);

                ctx.font = '10px Arial';
                ctx.fillStyle = 'rgba(224, 231, 255, 0.6)';
                ctx.textAlign = 'right';
                ctx.fillText('Presiona M para ocultar', boxX + boxWidth - 15, boxY + 25);

                // Mission name
                ctx.font = 'bold 14px Arial';
                ctx.fillStyle = '#ffffff';
                ctx.textAlign = 'left';
                ctx.fillText(masterClass.name, boxX + 15, boxY + 50);

                // Overall progress
                const totalReqs = progress.requirements.length;
                const completedReqs = progress.requirements.filter(r => r.current >= (r.amount || r.waves)).length;
                const overallProgress = (completedReqs / totalReqs);

                ctx.font = 'bold 12px Arial';
                ctx.fillStyle = '#ffd700';
                ctx.textAlign = 'right';
                ctx.fillText(`${completedReqs}/${totalReqs}`, boxX + boxWidth - 15, boxY + 50);

                // Overall progress bar
                const barY = boxY + 60;
                const barWidth = boxWidth - 30;
                ctx.fillStyle = 'rgba(0, 0, 0, 0.4)';
                ctx.fillRect(boxX + 15, barY, barWidth, 8);

                const gradient = ctx.createLinearGradient(boxX + 15, 0, boxX + 15 + barWidth, 0);
                gradient.addColorStop(0, '#ff00ff');
                gradient.addColorStop(1, '#8a2be2');
                ctx.fillStyle = gradient;
                ctx.fillRect(boxX + 15, barY, barWidth * overallProgress, 8);

                // Requirements
                let reqY = boxY + 85;
                progress.requirements.forEach(req => {
                    const maxValue = req.amount || req.waves;
                    const reqProgress = Math.min(req.current / maxValue, 1);
                    const isComplete = req.current >= maxValue;

                    // Requirement background
                    ctx.fillStyle = 'rgba(0, 0, 0, 0.3)';
                    ctx.fillRect(boxX + 15, reqY, boxWidth - 30, 38);

                    // Left border indicator
                    ctx.fillStyle = isComplete ? '#00ff00' : '#ff00ff';
                    ctx.fillRect(boxX + 15, reqY, 3, 38);

                    // Description
                    ctx.font = '11px Arial';
                    ctx.fillStyle = 'rgba(224, 231, 255, 0.9)';
                    ctx.textAlign = 'left';
                    const maxTextWidth = boxWidth - 100;
                    let text = req.description;
                    if (ctx.measureText(text).width > maxTextWidth) {
                        while (ctx.measureText(text + '...').width > maxTextWidth && text.length > 0) {
                            text = text.slice(0, -1);
                        }
                        text += '...';
                    }
                    ctx.fillText(text, boxX + 25, reqY + 12);

                    // Progress text
                    ctx.font = 'bold 12px Arial';
                    ctx.fillStyle = isComplete ? '#00ff00' : '#ffd700';
                    ctx.textAlign = 'right';
                    ctx.fillText(isComplete ? '?' : `${req.current}/${maxValue}`, boxX + boxWidth - 25, reqY + 12);

                    // Progress bar
                    const reqBarY = reqY + 22;
                    const reqBarWidth = boxWidth - 50;
                    ctx.fillStyle = 'rgba(0, 0, 0, 0.4)';
                    ctx.fillRect(boxX + 25, reqBarY, reqBarWidth, 5);

                    if (isComplete) {
                        const completeGradient = ctx.createLinearGradient(boxX + 25, 0, boxX + 25 + reqBarWidth, 0);
                        completeGradient.addColorStop(0, '#00ff00');
                        completeGradient.addColorStop(1, '#00aa00');
                        ctx.fillStyle = completeGradient;
                    } else {
                        const progressGradient = ctx.createLinearGradient(boxX + 25, 0, boxX + 25 + reqBarWidth, 0);
                        progressGradient.addColorStop(0, '#ffd700');
                        progressGradient.addColorStop(1, '#ff8c00');
                        ctx.fillStyle = progressGradient;
                    }
                    ctx.fillRect(boxX + 25, reqBarY, reqBarWidth * reqProgress, 5);

                    reqY += 43;
                });

                // Completion message
                if (progress.completed) {
                    ctx.fillStyle = 'rgba(0, 255, 0, 0.2)';
                    ctx.fillRect(boxX + 15, reqY, boxWidth - 30, 30);
                    ctx.strokeStyle = '#00ff00';
                    ctx.lineWidth = 2;
                    ctx.strokeRect(boxX + 15, reqY, boxWidth - 30, 30);

                    ctx.font = 'bold 14px Arial';
                    ctx.fillStyle = '#00ff00';
                    ctx.textAlign = 'center';
                    ctx.fillText('?? íMISIÓN COMPLETADA!', boxX + boxWidth / 2, reqY + 20);
                }
            },

            // NEW v19.11.2025: Attack Indicator System (Telegraphing)
            addAttackIndicator(x, y, width, height, duration, color = '#ff0000', shape = 'rect', angle = 0) {
                this.attackIndicators.push({
                    x, y, width, height,
                    duration,
                    maxDuration: duration,
                    color,
                    shape, // 'rect', 'circle', 'line'
                    angle, // Rotation angle in radians
                    startTime: Date.now()
                });
            },

            updateAttackIndicators(deltaTime) {
                this.attackIndicators = this.attackIndicators.filter(indicator => {
                    indicator.duration -= deltaTime;
                    return indicator.duration > 0;
                });
            },

            renderAttackIndicators(ctx) {
                this.attackIndicators.forEach(indicator => {
                    const progress = 1 - (indicator.duration / indicator.maxDuration);
                    const alpha = 0.3 + (progress * 0.4); // Fade in as it fills

                    ctx.save();

                    // Apply rotation if angle is specified
                    if (indicator.angle && indicator.angle !== 0) {
                        ctx.translate(indicator.x, indicator.y);
                        ctx.rotate(indicator.angle);
                        ctx.translate(-indicator.x, -indicator.y);
                    }

                    if (indicator.shape === 'rect') {
                        // Center the rectangle vertically for proper rotation
                        const rectY = indicator.y - indicator.height / 2;

                        // Draw background
                        ctx.fillStyle = `rgba(0, 0, 0, 0.3)`;
                        ctx.fillRect(indicator.x, rectY, indicator.width, indicator.height);

                        // Draw fill from center
                        const fillWidth = indicator.width * progress;
                        const startX = indicator.x + (indicator.width - fillWidth) / 2;

                        ctx.fillStyle = indicator.color.replace(')', `, ${alpha})`).replace('rgb', 'rgba');
                        ctx.fillRect(startX, rectY, fillWidth, indicator.height);

                        // Draw border
                        ctx.strokeStyle = indicator.color;
                        ctx.lineWidth = 2;
                        ctx.strokeRect(indicator.x, rectY, indicator.width, indicator.height);

                    } else if (indicator.shape === 'circle') {
                        // Draw background circle
                        ctx.fillStyle = `rgba(0, 0, 0, 0.3)`;
                        ctx.beginPath();
                        ctx.arc(indicator.x, indicator.y, indicator.width, 0, Math.PI * 2);
                        ctx.fill();

                        // Draw fill arc
                        ctx.fillStyle = indicator.color.replace(')', `, ${alpha})`).replace('rgb', 'rgba');
                        ctx.beginPath();
                        ctx.arc(indicator.x, indicator.y, indicator.width * progress, 0, Math.PI * 2);
                        ctx.fill();

                        // Draw border
                        ctx.strokeStyle = indicator.color;
                        ctx.lineWidth = 3;
                        ctx.beginPath();
                        ctx.arc(indicator.x, indicator.y, indicator.width, 0, Math.PI * 2);
                        ctx.stroke();

                    } else if (indicator.shape === 'line') {
                        // Draw line indicator with proper direction
                        const lineLength = indicator.width * progress;
                        ctx.strokeStyle = indicator.color;
                        ctx.lineWidth = indicator.height;
                        ctx.beginPath();
                        ctx.moveTo(indicator.x, indicator.y);
                        ctx.lineTo(indicator.x + lineLength, indicator.y);
                        ctx.stroke();
                    }

                    ctx.restore();
                });
            },

            damageMob(mobId, damage) {
                let mob = this.mobs.find(m => m.id === mobId);
                let isBoss = false;

                if (!mob) {
                    mob = this.bosses.find(m => m.id === mobId);
                    isBoss = true;
                }

                if (mob) {
                    // Check if mob is invincible (e.g., Aether Dragon during Destruction Phase)
                    if (mob.invincible) {
                        console.log(`??? ${mob.name} is INVINCIBLE! No damage taken.`);
                        return; // No damage taken
                    }

                    // TOXIC ZEPHYR - Evasion chance
                    if (mob.evasionChance && mob.type === 'toxic_zephyr') {
                        if (Math.random() < mob.evasionChance) {
                            console.log(`?? ${mob.name} evaded the attack!`);
                            // Quick dash away
                            const angle = Math.random() * Math.PI * 2;
                            mob.x += Math.cos(angle) * 60;
                            mob.y += Math.sin(angle) * 60;
                            return; // No damage taken
                        }
                    }

                    // TEMPEST LORD - Wind Barrier (reflects damage) - NERFED v4
                    if (mob.windBarrier && mob.type === 'tempest_lord') {
                        const reflectedDamage = Math.floor(damage * 0.10); // 10% reflection (NERFED v4: 12% ? 10%)
                        Player.takeDamage(reflectedDamage);
                        console.log(`??? Wind Barrier reflected ${reflectedDamage} damage back!`);
                    }

                    // BUFFED v5: Apply Radioactive Damage Buff from Wind Master
                    let finalDamage = damage;
                    if (Player.radioactiveDamageBuff && Player.radioactiveDamageBuff > 0) {
                        // Check if buff is still active
                        const buffTimeElapsed = Date.now() - (Player.radioactiveBuffStartTime || 0);
                        if (buffTimeElapsed < (Player.radioactiveBuffDuration || 0)) {
                            finalDamage = damage * (1 + Player.radioactiveDamageBuff);
                        } else {
                            // Buff expired
                            Player.radioactiveDamageBuff = 0;
                        }
                    }

                    mob.hp -= finalDamage;

                    // Track damage dealt for mastery missions
                    if (EquipmentManager.equippedRole && EquipmentManager.equippedRole.type === 'class') {
                        LoadoutManager.updateMissionProgress(EquipmentManager.equippedRole.id, 'deal_damage', damage);
                    }

                    if (mob.hp <= 0) {
                        this.score += isBoss ? 100 : 10;

                        // Track kills for mastery missions
                        if (EquipmentManager.equippedRole && EquipmentManager.equippedRole.type === 'class') {
                            const classId = EquipmentManager.equippedRole.id;

                            // Track general kills for all classes
                            if (classId === 'class_wind_master') {
                                LoadoutManager.updateMissionProgress(classId, 'kill_with_wind', 1);
                            } else if (classId === 'class_gunslinger') {
                                LoadoutManager.updateMissionProgress(classId, 'kill_with_gunslinger', 1);
                            } else if (classId === 'class_ninja') {
                                // Track kills for Shadow Ninja mastery mission
                                LoadoutManager.updateMissionProgress(classId, 'kill_with_ninja', 1);
                            }
                        }

                        // Abyssal Shadowlord Passive: Abismo Letal
                        // Each kill generates shadow essence (+10% crit stackable up to 5 stacks)
                        if (EquipmentManager.equippedRole && EquipmentManager.equippedRole.id === 'master_abyssal_shadowlord') {
                            if (!Player.shadowEssenceStacks) Player.shadowEssenceStacks = 0;
                            if (Player.shadowEssenceStacks < 5) {
                                Player.shadowEssenceStacks++;
                                Player.critBoost = Player.shadowEssenceStacks * 10; // 10% per stack
                                console.log(`? Abismo Letal: ${Player.shadowEssenceStacks} stacks (+${Player.critBoost}% crit)`);
                            }
                        }

                        // Continue with class-specific tracking
                        if (EquipmentManager.equippedRole && EquipmentManager.equippedRole.type === 'class') {
                            const classId = EquipmentManager.equippedRole.id;

                            // Track boss kills
                            if (isBoss && mob.type) {
                                if (classId === 'class_wind_master' && mob.type === 'tempest_lord') {
                                    LoadoutManager.updateMissionProgress(classId, 'kill_tempest_lord', 1);
                                } else if (classId === 'class_gunslinger' && mob.type === 'mech_titan') {
                                    LoadoutManager.updateMissionProgress(classId, 'kill_mech_titan', 1);
                                } else if (classId === 'class_ninja' && mob.type === 'shadow_emperor') {
                                    // Track Shadow Emperor kills for Shadow Ninja mastery mission
                                    LoadoutManager.updateMissionProgress(classId, 'kill_shadow_emperor', 1);
                                }
                            }

                            // Track specific mob kills (for Cyber Gunslinger)
                            if (classId === 'class_gunslinger' && mob.type === 'combat_drone') {
                                LoadoutManager.updateMissionProgress(classId, 'kill_combat_drones', 1);
                            }
                        }

                        // Drop class tickets
                        this.dropClassTicket(mob, isBoss);

                        // Give EXP based on mob level and type
                        let expGain = 0;
                        if (isBoss) {
                            expGain = 100 + (mob.level || 1) * 20; // Bosses give more EXP
                        } else {
                            expGain = 10 + (mob.level || 1) * 5; // Regular mobs
                        }

                        Player.gainExp(expGain, this.isCustomRaid);

                        if (isBoss) {
                            this.bosses = this.bosses.filter(m => m.id !== mobId);
                        } else {
                            this.mobs = this.mobs.filter(m => m.id !== mobId);
                        }
                    }
                }
            },

            // Helper method to get all targets (mobs in raids, dummies in practice mode)
            getAllTargets() {
                if (PracticeModeManager.active) {
                    // Return dummies as targets in practice mode
                    return TrainingDummySystem.dummies.map(dummy => ({
                        id: dummy.id,
                        x: dummy.x,
                        y: dummy.y,
                        size: dummy.size,
                        hp: dummy.hp,
                        maxHp: dummy.maxHp,
                        isDummy: true
                    }));
                } else {
                    // Return mobs and bosses in raid mode
                    return [...this.mobs, ...this.bosses];
                }
            },

            // Show floating text (for critical hits, etc.)
            showFloatingText(x, y, text, color = '#fff') {
                if (!this.floatingTexts) this.floatingTexts = [];

                this.floatingTexts.push({
                    x: x,
                    y: y,
                    text: text,
                    color: color,
                    life: 1000,
                    startTime: Date.now()
                });
            },

            // Helper method to apply damage to any target (mob or dummy)
            damageTarget(target, damage) {
                let finalDamage = damage;

                // Apply critical hit chance
                if (EquipmentManager.equippedRole && EquipmentManager.equippedRole.type === 'class') {
                    const classId = EquipmentManager.equippedRole.id;
                    const allUpgrades = ClassProgressionSystem.getAllUpgradesForClass(classId);
                    const critUpgrades = allUpgrades.filter(u => u.type === 'crit');
                    const critChance = critUpgrades.reduce((sum, u) => sum + u.bonus, 0);

                    if (critChance > 0 && Math.random() * 100 < critChance) {
                        finalDamage *= 2; // Critical hit does 2x damage
                        console.log(`?? íCRÍTICO! ${finalDamage} daño`);

                        // Show critical hit indicator
                        this.showFloatingText(target.x, target.y, '?? CRÍTICO!', '#ff0');
                    }
                }

                // Apply lifesteal
                if (EquipmentManager.equippedRole && EquipmentManager.equippedRole.type === 'class') {
                    const classId = EquipmentManager.equippedRole.id;
                    const allUpgrades = ClassProgressionSystem.getAllUpgradesForClass(classId);
                    const lifestealUpgrades = allUpgrades.filter(u => u.type === 'lifesteal');
                    const lifestealPercent = lifestealUpgrades.reduce((sum, u) => sum + u.bonus, 0);

                    if (lifestealPercent > 0) {
                        const healAmount = Math.floor(finalDamage * (lifestealPercent / 100));
                        Player.hp = Math.min(Player.maxHp, Player.hp + healAmount);
                        console.log(`?? Robo de vida: +${healAmount} HP`);
                    }
                }

                if (target.isDummy) {
                    TrainingDummySystem.damageDummy(target.id, Math.floor(finalDamage));
                } else {
                    this.damageMob(target.id, Math.floor(finalDamage));
                }
            },

            checkAbilityHit(x, y, radius, damage = 25) {
                const allTargets = this.getAllTargets();
                let baseDamage = damage;
                let effectiveRadius = radius;

                // Apply player damage boost
                if (Player.damageBoost > 0) {
                    baseDamage *= (1 + Player.damageBoost / 100);
                }

                // Apply class damage multiplier and range multiplier
                if (EquipmentManager.equippedRole && EquipmentManager.equippedRole.type === 'class') {
                    const classId = EquipmentManager.equippedRole.id;
                    const damageMultiplier = ClassProgressionSystem.getDamageMultiplier(classId);
                    baseDamage *= damageMultiplier;

                    // Apply range multiplier
                    const allUpgrades = ClassProgressionSystem.getAllUpgradesForClass(classId);
                    const rangeUpgrades = allUpgrades.filter(u => u.type === 'range');
                    const rangeBonus = rangeUpgrades.reduce((sum, u) => sum + u.bonus, 0);
                    effectiveRadius *= (1 + rangeBonus / 100);
                }

                allTargets.forEach(target => {
                    const dx = target.x - x;
                    const dy = target.y - y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist < effectiveRadius + target.size) {
                        this.damageTarget(target, baseDamage);
                    }
                });
            },

            // DRAGONHUNTER ABILITIES
            dragonFlameArrow(ability) {
                const allTargets = this.getAllTargets();
                const nearbyTargets = allTargets.filter(target => {
                    const dx = target.x - Player.x;
                    const dy = target.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    return dist < 300;
                }).slice(0, 3); // Only 3 closest

                if (nearbyTargets.length === 0) {
                    console.log('?? No enemies nearby for Flame Arrow!');
                    return;
                }

                nearbyTargets.forEach(target => {
                    // Apply burn stacks (enemy will take damage when it attacks) - only for mobs
                    if (!target.isDummy) {
                        target.burning = true;
                        target.burnStacks = 3;
                    }

                    // Shoot arrow projectile
                    const angle = Math.atan2(target.y - Player.y, target.x - Player.x);
                    this.projectiles.push({
                        x: Player.x,
                        y: Player.y,
                        vx: Math.cos(angle) * 400,
                        vy: Math.sin(angle) * 400,
                        size: 8,
                        damage: 30,
                        color: '#ff4500',
                        life: 2000,
                        isFlameArrow: true,
                        isPlayerProjectile: true, // Mark as player projectile
                        targetId: target.id,
                        targetIsDummy: target.isDummy
                    });
                });

                console.log(`?? Flame Arrows shot at ${nearbyTargets.length} enemies! They'll take damage when attacking!`);
            },

            dragonBreathBomb() {
                const allMobs = this.getAllTargets();
                let affectedCount = 0;

                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 200) { // Medium radius
                        // Apply confusion
                        mob.confused = true;
                        mob.confusedTime = 4000; // 4 seconds

                        // 65% chance for burn
                        if (Math.random() < 0.65) {
                            mob.burning = true;
                            mob.burnStacks = Math.max(mob.burnStacks, 2);
                        }

                        affectedCount++;
                    }
                });

                console.log(`?? Dragon Breath affected ${affectedCount} enemies! Confusion + Burn!`);
            },

            draconicExplosion() {
                // Apply player buff
                Player.applyDamageBoost(25, 11000); // 25% for 11 seconds

                const allMobs = this.getAllTargets();
                let affectedCount = 0;

                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 250) { // Large radius
                        // Apply permanent damage reduction
                        mob.damageReduction = 10;
                        mob.damageReductionPermanent = true;

                        // Immediate damage
                        this.damageMob(mob.id, 80);

                        affectedCount++;
                    }
                });

                console.log(`?? Draconic Explosion! Player: +25% DMG | Enemies: -10% DMG (${affectedCount} affected)`);
            },

            // NEW DRAGONHUNTER ABILITIES
            tripleArrowUse() {
                // Flecha Triple Uso: 3 flechas a direcciones aleatorias
                // - Una traspasa enemigos (más daño por cada traspaso)
                // - Una inflige quemadura por 5s
                // - Una empuja hacia atrás

                const allMobs = [...this.mobs, ...this.bosses];
                if (allMobs.length === 0) {
                    console.log('?? No enemies for Triple Arrow!');
                    return;
                }

                // Arrow 1: Piercing arrow (traspasa enemigos)
                const angle1 = Math.random() * Math.PI * 2;
                let piercingDamage = 25;
                let piercedCount = 0;

                this.projectiles.push({
                    x: Player.x,
                    y: Player.y,
                    vx: Math.cos(angle1) * 450,
                    vy: Math.sin(angle1) * 450,
                    size: 10,
                    damage: piercingDamage,
                    color: '#00ffff',
                    life: 2500,
                    isPiercing: true,
                    piercedEnemies: [],
                    isPlayerProjectile: true,
                    onHit: (mob) => {
                        piercedCount++;
                        piercingDamage += 8; // +8 damage per pierce
                        return piercingDamage;
                    }
                });

                // Arrow 2: Burning arrow (quemadura 5s)
                const angle2 = Math.random() * Math.PI * 2;
                this.projectiles.push({
                    x: Player.x,
                    y: Player.y,
                    vx: Math.cos(angle2) * 450,
                    vy: Math.sin(angle2) * 450,
                    size: 10,
                    damage: 30,
                    color: '#ff4500',
                    life: 2500,
                    isBurningArrow: true,
                    isPlayerProjectile: true,
                    onHit: (mob) => {
                        mob.burning = true;
                        mob.burnStacks = 5;
                        mob.burnDuration = 5000; // 5 seconds
                        return 30;
                    }
                });

                // Arrow 3: Knockback arrow (empuja hacia atrás)
                const angle3 = Math.random() * Math.PI * 2;
                this.projectiles.push({
                    x: Player.x,
                    y: Player.y,
                    vx: Math.cos(angle3) * 450,
                    vy: Math.sin(angle3) * 450,
                    size: 10,
                    damage: 28,
                    color: '#ffbe0b',
                    life: 2500,
                    isKnockbackArrow: true,
                    isPlayerProjectile: true,
                    onHit: (mob) => {
                        const dx = mob.x - Player.x;
                        const dy = mob.y - Player.y;
                        const knockAngle = Math.atan2(dy, dx);
                        mob.x += Math.cos(knockAngle) * 80;
                        mob.y += Math.sin(knockAngle) * 80;
                        return 28;
                    }
                });

                console.log('?? Triple Arrow launched! Piercing, Burning, and Knockback arrows!');
            },

            draconicMadness() {
                // Locura Dracónica: Empuja enemigos + quemadura 2s + invencibilidad + 7 flechas + 3 flechas aleatorias con quemadura 4s
                const allMobs = this.getAllTargets();
                let affectedCount = 0;

                // PHASE 1: Push and burn nearby enemies
                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 300) { // Long range
                        // Push away
                        const pushAngle = Math.atan2(dy, dx);
                        mob.x += Math.cos(pushAngle) * 100;
                        mob.y += Math.sin(pushAngle) * 100;

                        // Apply burn for 2s
                        mob.burning = true;
                        mob.burnStacks = 2;
                        mob.burnDuration = 2000;

                        affectedCount++;
                    }
                });

                // PHASE 2: Invincibility
                Player.invulnerable = true;
                Player.invulnerableTime = 3000; // 3 seconds

                // PHASE 3: Shoot 7 arrows at nearby enemies (after 0.5s)
                setTimeout(() => {
                    const nearbyMobs = allMobs.filter(mob => {
                        const dx = mob.x - Player.x;
                        const dy = mob.y - Player.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);
                        return dist < 350;
                    }).slice(0, 7);

                    nearbyMobs.forEach(mob => {
                        const angle = Math.atan2(mob.y - Player.y, mob.x - Player.x);
                        this.projectiles.push({
                            x: Player.x,
                            y: Player.y,
                            vx: Math.cos(angle) * 500,
                            vy: Math.sin(angle) * 500,
                            size: 9,
                            damage: 35,
                            color: '#ff0000',
                            life: 2000,
                            isPlayerProjectile: true
                        });
                    });

                    console.log(`?? Locura Dracónica - Phase 2: ${nearbyMobs.length} arrows fired!`);
                }, 500);

                // PHASE 4: Shoot 3 random burning arrows (after 1.2s)
                setTimeout(() => {
                    for (let i = 0; i < 3; i++) {
                        const angle = Math.random() * Math.PI * 2;
                        this.projectiles.push({
                            x: Player.x,
                            y: Player.y,
                            vx: Math.cos(angle) * 450,
                            vy: Math.sin(angle) * 450,
                            size: 10,
                            damage: 32,
                            color: '#ff6600',
                            life: 2500,
                            isBurningArrow: true,
                            isPlayerProjectile: true,
                            onHit: (mob) => {
                                mob.burning = true;
                                mob.burnStacks = 4;
                                mob.burnDuration = 4000; // 4 seconds
                                return 32;
                            }
                        });
                    }

                    console.log('?? Locura Dracónica - Phase 3: 3 burning arrows launched!');
                }, 1200);

                console.log(`?? Locura Dracónica activated! ${affectedCount} enemies pushed and burned! Invincibility active!`);
            },

            natureRising() {
                // Naturaleza en Ascenso: Invoca írboles y arbustos que reducen velocidad de enemigos
                const allMobs = [...this.mobs, ...this.bosses];

                // Create 8 nature obstacles around player
                const obstacles = [];
                for (let i = 0; i < 8; i++) {
                    const angle = (Math.PI * 2 * i) / 8;
                    const distance = 80 + Math.random() * 40;
                    obstacles.push({
                        x: Player.x + Math.cos(angle) * distance,
                        y: Player.y + Math.sin(angle) * distance,
                        radius: 25,
                        duration: 8000, // 8 seconds
                        startTime: Date.now()
                    });
                }

                // Store obstacles for rendering and collision
                if (!this.natureObstacles) this.natureObstacles = [];
                this.natureObstacles.push(...obstacles);

                // Apply slow effect to enemies that touch obstacles
                const slowInterval = setInterval(() => {
                    if (this.natureObstacles.length === 0) {
                        clearInterval(slowInterval);
                        return;
                    }

                    allMobs.forEach(mob => {
                        this.natureObstacles.forEach(obstacle => {
                            const dx = mob.x - obstacle.x;
                            const dy = mob.y - obstacle.y;
                            const dist = Math.sqrt(dx * dx + dy * dy);

                            if (dist < obstacle.radius + mob.size) {
                                // Apply slow (30% speed reduction)
                                if (!mob.natureSlowed) {
                                    mob.speed *= 0.7;
                                    mob.natureSlowed = true;

                                    // Remove slow after 2s
                                    setTimeout(() => {
                                        if (mob.natureSlowed) {
                                            mob.speed /= 0.7;
                                            mob.natureSlowed = false;
                                        }
                                    }, 2000);
                                }
                            }
                        });
                    });

                    // Remove expired obstacles
                    this.natureObstacles = this.natureObstacles.filter(obs => {
                        return Date.now() - obs.startTime < obs.duration;
                    });
                }, 100);

                console.log('?? Naturaleza en Ascenso - 8 nature obstacles created! Enemies will be slowed!');
            },

            // WIND MASTER ABILITIES
            ventoso() {
                // Ventoso: Todos los enemigos en rango corto reciben confusion por 5s
                const allMobs = this.getAllTargets();
                let affectedCount = 0;

                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 180) { // Short range
                        // Apply confusion
                        mob.confused = true;
                        mob.confusedTime = 5000; // 5 seconds
                        mob.confusedIntensity = 0.3; // Light deviation

                        affectedCount++;
                    }
                });

                console.log(`?? Ventoso - ${affectedCount} enemies confused for 5s!`);
            },

            ciclon() {
                // Ciclón: Todos los enemigos en rango mediano son empujados drásticamente y reciben confusion por 10s
                const allMobs = this.getAllTargets();
                let affectedCount = 0;

                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 280) { // Medium range
                        // Apply physics-based push (gradual, not teleport)
                        const pushAngle = Math.atan2(dy, dx);
                        const pushForce = 150; // Total push distance
                        const pushDuration = 400; // Duration in ms
                        const pushSteps = 20; // Number of steps for smooth animation
                        const pushPerStep = pushForce / pushSteps;

                        // Apply gradual push over time
                        for (let i = 0; i < pushSteps; i++) {
                            setTimeout(() => {
                                if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                                    mob.x += Math.cos(pushAngle) * pushPerStep;
                                    mob.y += Math.sin(pushAngle) * pushPerStep;
                                }
                            }, (pushDuration / pushSteps) * i);
                        }

                        // Apply long confusion
                        mob.confused = true;
                        mob.confusedTime = 10000; // 10 seconds
                        mob.confusedIntensity = 0.5; // Moderate deviation

                        affectedCount++;
                    }
                });

                console.log(`?? Ciclón - ${affectedCount} enemies pushed and confused for 10s!`);
            },

            // ELEMENTALIST ABILITIES
            elementalStorm() {
                // Lightning Chain - hits closest enemy and chains to nearby enemies
                const allMobs = this.getAllTargets();
                if (allMobs.length === 0) {
                    console.log('? No enemies to chain lightning!');
                    return;
                }

                // Find closest enemy
                let closest = null;
                let minDist = Infinity;
                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist < minDist) {
                        minDist = dist;
                        closest = mob;
                    }
                });

                if (!closest || minDist > 400) {
                    console.log('? No enemies in range for lightning chain!');
                    return;
                }

                // Chain lightning effect
                const chainedMobs = [closest];
                let currentMob = closest;
                const maxChains = 4; // Can chain to 4 additional enemies

                for (let i = 0; i < maxChains; i++) {
                    let nextMob = null;
                    let nextDist = Infinity;

                    allMobs.forEach(mob => {
                        if (chainedMobs.includes(mob)) return;
                        const dx = mob.x - currentMob.x;
                        const dy = mob.y - currentMob.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);
                        if (dist < 250 && dist < nextDist) {
                            nextDist = dist;
                            nextMob = mob;
                        }
                    });

                    if (nextMob) {
                        chainedMobs.push(nextMob);
                        currentMob = nextMob;
                    } else {
                        break;
                    }
                }

                // Damage all chained enemies (damage decreases with each chain)
                chainedMobs.forEach((mob, index) => {
                    const damage = 35 - (index * 5); // 35, 30, 25, 20, 15
                    setTimeout(() => {
                        this.damageMob(mob.id, damage);
                        // Stun for 1 second
                        mob.confused = true;
                        mob.confusedTime = 1000;
                    }, index * 150);
                });

                console.log(`? Lightning Chain hit ${chainedMobs.length} enemies!`);
            },

            iceBarrier() {
                // Ice Prison - traps enemies in ice, dealing damage over time and slowing them
                const allMobs = this.getAllTargets();
                let frozenCount = 0;

                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 220) {
                        // Freeze and slow
                        mob.confused = true;
                        mob.confusedTime = 4000; // 4 seconds frozen
                        mob.speed *= 0.3; // Massive slow (70% reduction)

                        // Deal damage over time (5 ticks of 8 damage)
                        for (let i = 0; i < 5; i++) {
                            setTimeout(() => {
                                if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                                    this.damageMob(mob.id, 8);
                                }
                            }, i * 800);
                        }

                        frozenCount++;
                    }
                });

                // Player gets temporary shield
                Player.invulnerable = true;
                Player.invulnerableTime = 2000; // 2 seconds of invulnerability

                console.log(`?? Ice Prison trapped ${frozenCount} enemies! Shield active!`);
            },

            elementalCataclysm() {
                // Elemental Fury - Summons all 4 elements in a devastating combo
                const allMobs = this.getAllTargets();

                // PHASE 1: Lightning Storm (0-1s) - Stuns all enemies
                allMobs.forEach(mob => {
                    mob.confused = true;
                    mob.confusedTime = 2000;
                    this.damageMob(mob.id, 25);
                });
                console.log('? Phase 1: Lightning Storm - All enemies stunned!');

                // PHASE 2: Fire Wave (1.5s) - Burns enemies
                setTimeout(() => {
                    allMobs.forEach(mob => {
                        if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                            mob.burning = true;
                            mob.burnStacks = 4;
                            this.damageMob(mob.id, 30);
                        }
                    });
                    console.log('?? Phase 2: Fire Wave - All enemies burning!');
                }, 1500);

                // PHASE 3: Ice Blast (3s) - Slows and damages
                setTimeout(() => {
                    allMobs.forEach(mob => {
                        if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                            mob.speed *= 0.5;
                            this.damageMob(mob.id, 35);
                        }
                    });
                    console.log('?? Phase 3: Ice Blast - All enemies slowed!');
                }, 3000);

                // PHASE 4: Earth Quake (4.5s) - Final massive damage
                setTimeout(() => {
                    allMobs.forEach(mob => {
                        if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                            this.damageMob(mob.id, 50);
                            mob.damageReduction = Math.max(0, mob.damageReduction - 15); // Reduce their defense
                        }
                    });
                    console.log('?? Phase 4: Earth Quake - Devastating final blow!');
                }, 4500);

                // Player buff during ultimate
                Player.applyDamageBoost(30, 6000); // 30% damage boost for 6 seconds
                Player.invulnerable = true;
                Player.invulnerableTime = 3000; // Invulnerable during first 3 seconds

                console.log('??? ELEMENTAL FURY UNLEASHED! 4-phase elemental devastation!');
            },

            // RONIN SAMURAI ABILITIES
            swiftCut() {
                // Dash forward and damage enemies in path
                const dashDistance = 200;
                const angle = Math.atan2(
                    this.mobs[0]?.y - Player.y || 0,
                    this.mobs[0]?.x - Player.x || 1
                );

                const endX = Player.x + Math.cos(angle) * dashDistance;
                const endY = Player.y + Math.sin(angle) * dashDistance;

                // Check enemies along the path
                const allMobs = [...this.mobs, ...this.bosses];
                let hitCount = 0;

                allMobs.forEach(mob => {
                    // Simple line collision check
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < dashDistance) {
                        this.damageMob(mob.id, 35);
                        hitCount++;
                    }
                });

                // Move player
                Player.x = Math.max(50, Math.min(endX, 1050));
                Player.y = Math.max(50, Math.min(endY, 650));

                console.log(`?? Swift Cut! Dashed and hit ${hitCount} enemies!`);
            },

            counterAttack() {
                // Set counter stance for 2 seconds
                Player.counterActive = true;
                Player.counterTime = 2000;
                console.log('??? Counter stance activated! Next attack will be reflected!');
            },

            ninjaPower() {
                // Poder Ninja: Se hace invisible por 10s y deja una bola de humo mediana
                Player.invisible = true;
                Player.invisibleTime = 10000; // 10 seconds invisibility
                Player.invulnerable = true; // Also invulnerable while invisible
                Player.invulnerableTime = 10000;

                // Speed boost while invisible (+30%)
                Player.speed = Player.baseSpeed * 1.3;

                // Create smoke ball at player position
                const smokeBall = {
                    x: Player.x,
                    y: Player.y,
                    radius: 60, // Medium size
                    duration: 10000,
                    startTime: Date.now()
                };

                if (!this.smokeBalls) this.smokeBalls = [];
                this.smokeBalls.push(smokeBall);

                // Check for enemies touching smoke ball
                const checkInterval = setInterval(() => {
                    if (Date.now() - smokeBall.startTime > smokeBall.duration) {
                        clearInterval(checkInterval);
                        this.smokeBalls = this.smokeBalls.filter(s => s !== smokeBall);
                        return;
                    }

                    const allMobs = [...this.mobs, ...this.bosses];
                    allMobs.forEach(mob => {
                        const dx = mob.x - smokeBall.x;
                        const dy = mob.y - smokeBall.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);

                        if (dist < smokeBall.radius + mob.size) {
                            mob.confused = true;
                            mob.confusedTime = 9000; // 9 seconds confusion
                            mob.confusedIntensity = 0.4;
                        }
                    });
                }, 100);

                console.log('?? Poder Ninja - Invisible for 10s! Smoke ball deployed!');
            },

            surpriseCut() {
                // Golpe Rápido: Ataque rápido al enemigo más cercano
                const allMobs = this.getAllTargets();
                if (allMobs.length === 0) {
                    console.log('? No enemies for Golpe Rápido!');
                    return;
                }

                // Find closest enemy
                let closest = null;
                let minDist = Infinity;
                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist < minDist) {
                        minDist = dist;
                        closest = mob;
                    }
                });

                if (!closest || minDist > 300) {
                    console.log('? No enemies in range!');
                    return;
                }

                // Quick double slash
                setTimeout(() => {
                    this.damageMob(closest.id, 25);
                }, 100);

                setTimeout(() => {
                    this.damageMob(closest.id, 25);
                }, 250);

                console.log('? Golpe Rápido executed!');
            },

            thousandLeavesDance() {
                // Rapid strikes in area, ignoring defenses
                const allMobs = this.getAllTargets();
                let hitCount = 0;

                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 250) {
                        // Multiple rapid hits ignoring damage reduction
                        const originalReduction = mob.damageReduction;
                        mob.damageReduction = 0;

                        for (let i = 0; i < 5; i++) {
                            setTimeout(() => {
                                this.damageMob(mob.id, 15);
                            }, i * 100);
                        }

                        setTimeout(() => {
                            mob.damageReduction = originalReduction;
                        }, 500);

                        hitCount++;
                    }
                });

                console.log(`?? Thousand Leaves Dance! ${hitCount} enemies caught in the storm!`);
            },

            // WILD BERSERKER ABILITIES
            wildRage() {
                // Ira Imparable - Damage boost that increases when low HP + heal over time
                const healthPercent = Player.hp / Player.maxHp;
                const rageMultiplier = 2.5 - (healthPercent * 1.5); // More damage when lower health (1.0x to 2.5x)
                const damageBoost = Math.floor(35 * rageMultiplier); // 35-87% damage boost

                Player.applyDamageBoost(damageBoost, 6000);
                Player.speed *= 1.5; // 50% speed boost
                Player.berserkerRageActive = true;

                // Heal over time during rage (more healing when low HP)
                const healPerTick = Math.floor(5 * rageMultiplier); // 5-12 HP per tick
                const healInterval = setInterval(() => {
                    if (Player.berserkerRageActive && Player.hp < Player.maxHp) {
                        Player.hp = Math.min(Player.maxHp, Player.hp + healPerTick);
                    }
                }, 500);

                setTimeout(() => {
                    Player.speed /= 1.5;
                    Player.berserkerRageActive = false;
                    clearInterval(healInterval);
                }, 6000);

                console.log(`?? Ira Imparable - ${damageBoost}% damage boost! Healing ${healPerTick} HP/sec!`);
            },

            devastatingLeap() {
                // Hacha Giratoria - Spinning attack that hits multiple times with knockback
                const allMobs = this.getAllTargets();
                let totalHits = 0;

                // 4 spinning hits with increasing radius
                for (let spin = 0; spin < 4; spin++) {
                    setTimeout(() => {
                        const radius = 100 + (spin * 35); // 100, 135, 170, 205
                        const damage = 20 + (spin * 8); // 20, 28, 36, 44

                        allMobs.forEach(mob => {
                            if (!this.mobs.includes(mob) && !this.bosses.includes(mob)) return;

                            const dx = mob.x - Player.x;
                            const dy = mob.y - Player.y;
                            const dist = Math.sqrt(dx * dx + dy * dy);

                            if (dist < radius + mob.size) {
                                this.damageMob(mob.id, damage);
                                totalHits++;

                                // Knockback effect
                                const knockAngle = Math.atan2(dy, dx);
                                mob.x += Math.cos(knockAngle) * 40;
                                mob.y += Math.sin(knockAngle) * 40;

                                // Stun briefly
                                mob.confused = true;
                                mob.confusedTime = 800;
                            }
                        });

                        if (spin === 3) {
                            console.log(`??? Hacha Giratoria - ${totalHits} hits landed!`);
                        }
                    }, spin * 250);
                }
            },

            bloodlust() {
                // Frenesí de Batalla - Massive damage boost + heal on kill + damage reduction
                Player.applyDamageBoost(70, 12000); // 70% damage boost for 12 seconds
                Player.bloodthirstActive = true;
                Player.killStreak = 0;
                Player.damageReduction = (Player.damageReduction || 0) + 20; // 20% damage reduction

                // Store original damageMob function
                const originalDamageMob = this.damageMob.bind(this);
                const originalCheckAbilityHit = this.checkAbilityHit.bind(this);

                // Override damageMob to track kills
                const trackKills = (mobId, damage) => {
                    const mob = [...this.mobs, ...this.bosses].find(m => m.id === mobId);
                    if (mob && mob.hp - damage <= 0 && Player.bloodthirstActive) {
                        Player.killStreak++;

                        // Heal based on kill streak (stacking)
                        const healAmount = 20 + (Player.killStreak * 8);
                        Player.hp = Math.min(Player.maxHp, Player.hp + healAmount);

                        // Increase damage boost with each kill
                        const bonusDamage = Player.killStreak * 12;
                        Player.applyDamageBoost(70 + bonusDamage, 12000);

                        // Extend duration slightly with each kill
                        Player.bloodthirstTime = Math.min(Player.bloodthirstTime + 1000, 18000);

                        console.log(`?? Kill Streak: ${Player.killStreak} | Healed ${healAmount} HP | Damage: ${70 + bonusDamage}%`);
                    }
                    return originalDamageMob(mobId, damage);
                };

                this.damageMob = trackKills;

                setTimeout(() => {
                    Player.bloodthirstActive = false;
                    Player.killStreak = 0;
                    Player.damageReduction = Math.max(0, (Player.damageReduction || 0) - 20);
                    this.damageMob = originalDamageMob; // Restore original function
                    console.log('?? Frenesí de Batalla terminado!');
                }, 12000);

                console.log('?? Frenesí de Batalla - Grow stronger with each kill! +20% damage reduction!');
            },

            berserkerSurprise() {
                // Corte Sorpresa - Double cut to closest enemy
                console.log('⚡ Berserker Surprise Cut activated!');
                const allMobs = this.getAllTargets();

                // Find closest enemy
                let closestEnemy = null;
                let closestDistance = Infinity;
                allMobs.forEach(mob => {
                    const distance = Math.sqrt((mob.x - Player.x) ** 2 + (mob.y - Player.y) ** 2);
                    if (distance < closestDistance) {
                        closestDistance = distance;
                        closestEnemy = mob;
                    }
                });

                if (closestEnemy && closestDistance <= 200) {
                    // Create double cut effect
                    EffectRenderer.playEffect('effect_surprise', closestEnemy.x, closestEnemy.y);

                    // Deal damage twice with delay
                    this.damageMob(closestEnemy.id, 25);
                    setTimeout(() => {
                        if (closestEnemy.hp > 0) {
                            this.damageMob(closestEnemy.id, 25);
                        }
                    }, 200);
                }
            },

            doubleAxes() {
                // Doble Hacha - Area attack with dual axes
                console.log('🪓 Double Axes activated!');
                const allMobs = this.getAllTargets();

                // Create axe spin effect
                EffectRenderer.playEffect('effect_axes', Player.x, Player.y);

                // Damage all enemies in area
                allMobs.forEach(mob => {
                    const distance = Math.sqrt((mob.x - Player.x) ** 2 + (mob.y - Player.y) ** 2);
                    if (distance <= 200) {
                        this.damageMob(mob.id, 40);
                    }
                });
            },

            // SHADOW NINJA ABILITIES (REDESIGNED)
            shadowStrike() {
                // Golpe de Sombra - Dash rápido con estela de sombras
                const allMobs = this.getAllTargets();
                if (allMobs.length === 0) {
                    console.log('??? No enemies for Shadow Strike!');
                    return;
                }

                // Find closest enemy
                let closest = null;
                let minDist = Infinity;
                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist < minDist) {
                        minDist = dist;
                        closest = mob;
                    }
                });

                if (!closest || minDist > 400) {
                    console.log('??? No enemies in range!');
                    return;
                }

                // Store starting position for shadow trail
                const startX = Player.x;
                const startY = Player.y;

                // Dash to enemy
                const angle = Math.atan2(closest.y - Player.y, closest.x - Player.x);
                Player.x = closest.x - Math.cos(angle) * 60;
                Player.y = closest.y - Math.sin(angle) * 60;

                // Grant brief invincibility during and after dash (1.5 seconds)
                Player.invulnerable = true;
                Player.invulnerableTime = 1500;

                // Critical strike (daño escalado con nivel)
                const critDamage = Math.floor(45 + Player.getCurrentDamage() * 1.0);
                this.damageMob(closest.id, critDamage);

                // Create shadow trail that damages enemies
                const trailLength = Math.sqrt((Player.x - startX) ** 2 + (Player.y - startY) ** 2);
                const trailSegments = Math.floor(trailLength / 30);

                for (let i = 0; i < trailSegments; i++) {
                    const t = i / trailSegments;
                    const trailX = startX + (Player.x - startX) * t;
                    const trailY = startY + (Player.y - startY) * t;

                    // Check for enemies near this trail segment
                    setTimeout(() => {
                        allMobs.forEach(mob => {
                            const dx = mob.x - trailX;
                            const dy = mob.y - trailY;
                            const dist = Math.sqrt(dx * dx + dy * dy);

                            if (dist < 40) {
                                const trailDamage = Math.floor(15 + Player.getCurrentDamage() * 0.3);
                                this.damageMob(mob.id, trailDamage);
                            }
                        });
                    }, i * 50);
                }

                console.log('??? Shadow Strike - Dashed to enemy with shadow trail!');
            },

            shurikenRain() {
                // Marca de Muerte - Marks enemies, making them take extra damage
                const allMobs = this.getAllTargets();
                if (allMobs.length === 0) {
                    console.log('?? No enemies to mark!');
                    return;
                }

                // Find 3 closest enemies
                const sortedMobs = allMobs
                    .map(mob => ({
                        mob,
                        dist: Math.sqrt((mob.x - Player.x) ** 2 + (mob.y - Player.y) ** 2)
                    }))
                    .sort((a, b) => a.dist - b.dist)
                    .slice(0, 3);

                let markedCount = 0;
                sortedMobs.forEach(({ mob }) => {
                    // Throw shuriken
                    const angle = Math.atan2(mob.y - Player.y, mob.x - Player.x);
                    this.projectiles.push({
                        x: Player.x,
                        y: Player.y,
                        vx: Math.cos(angle) * 450,
                        vy: Math.sin(angle) * 450,
                        size: 10,
                        damage: 28,
                        color: '#9d4edd',
                        life: 2500,
                        isPlayerProjectile: true
                    });

                    // Apply death mark (enemy takes 30% more damage for 8 seconds)
                    mob.deathMarked = true;
                    mob.deathMarkTime = 8000;
                    mob.deathMarkMultiplier = 1.3; // 30% more damage

                    markedCount++;
                });

                console.log(`?? Marca de Muerte - ${markedCount} enemies marked! They take 30% more damage!`);
            },

            shadowVeil() {
                // Paso Fantasma - Teleport behind closest enemy + brief invisibility + critical strike
                const allMobs = this.getAllTargets();
                if (allMobs.length === 0) {
                    console.log('?? No enemies to teleport to!');
                    return;
                }

                // Find closest enemy
                const closest = allMobs.reduce((prev, curr) => {
                    const prevDist = Math.sqrt((prev.x - Player.x) ** 2 + (prev.y - Player.y) ** 2);
                    const currDist = Math.sqrt((curr.x - Player.x) ** 2 + (curr.y - Player.y) ** 2);
                    return prevDist < currDist ? prev : curr;
                });

                // Teleport behind the enemy
                const angle = Math.atan2(Player.y - closest.y, Player.x - closest.x);
                Player.x = closest.x + Math.cos(angle) * 90;
                Player.y = closest.y + Math.sin(angle) * 90;

                // Critical strike damage (ignores armor, escalado con nivel)
                const criticalDamage = Math.floor(65 + Player.getCurrentDamage() * 1.3);
                const originalReduction = closest.damageReduction || 0;
                closest.damageReduction = 0;
                this.damageMob(closest.id, criticalDamage);
                setTimeout(() => {
                    if (this.mobs.includes(closest) || this.bosses.includes(closest)) {
                        closest.damageReduction = originalReduction;
                    }
                }, 100);

                // Brief invisibility (can't be hit)
                Player.invulnerable = true;
                Player.invulnerableTime = 2000;

                // Speed boost after teleport
                Player.speed *= 1.4;
                setTimeout(() => {
                    Player.speed /= 1.4;
                }, 3000);

                console.log('?? Paso Fantasma - Teleported behind enemy! Critical strike + invisibility!');
            },

            shadowClone() {
                // Clon de Sombra - Creates 2 shadow clones that attack enemies
                const allMobs = this.getAllTargets();
                if (allMobs.length === 0) {
                    console.log('?? No enemies for Shadow Clones!');
                    return;
                }

                // Create 2 clones at player position
                const clones = [];
                for (let i = 0; i < 2; i++) {
                    const angle = (Math.PI * 2 * i) / 2;
                    clones.push({
                        x: Player.x + Math.cos(angle) * 50,
                        y: Player.y + Math.sin(angle) * 50,
                        lifetime: 6000,
                        createdAt: Date.now(),
                        attackCooldown: 0
                    });
                }

                // Store clones for rendering and attacking
                if (!this.shadowClones) this.shadowClones = [];
                this.shadowClones.push(...clones);

                // Clone attack interval
                const cloneInterval = setInterval(() => {
                    if (this.shadowClones.length === 0) {
                        clearInterval(cloneInterval);
                        return;
                    }

                    // Remove expired clones
                    this.shadowClones = this.shadowClones.filter(clone => {
                        return Date.now() - clone.createdAt < clone.lifetime;
                    });

                    // Each clone attacks nearest enemy
                    this.shadowClones.forEach(clone => {
                        if (clone.attackCooldown > 0) {
                            clone.attackCooldown -= 500;
                            return;
                        }

                        // Find closest enemy to clone
                        let closest = null;
                        let minDist = Infinity;
                        allMobs.forEach(mob => {
                            const dx = mob.x - clone.x;
                            const dy = mob.y - clone.y;
                            const dist = Math.sqrt(dx * dx + dy * dy);
                            if (dist < minDist && dist < 300) {
                                minDist = dist;
                                closest = mob;
                            }
                        });

                        if (closest) {
                            // Clone shoots projectile (50% del daño del jugador)
                            const cloneDamage = Math.floor((20 + Player.getCurrentDamage() * 0.4) * 0.5);
                            const angle = Math.atan2(closest.y - clone.y, closest.x - clone.x);
                            this.projectiles.push({
                                x: clone.x,
                                y: clone.y,
                                vx: Math.cos(angle) * 400,
                                vy: Math.sin(angle) * 400,
                                size: 8,
                                damage: cloneDamage,
                                color: '#2f2f2f',
                                life: 2000,
                                isPlayerProjectile: true
                            });
                            clone.attackCooldown = 1000; // 1 second cooldown
                        }
                    });
                }, 500);

                console.log('?? Shadow Clones - 2 clones created for 6 seconds!');
            },

            silentExecution() {
                // Asesino de Sombras - Execute low HP enemies instantly + massive damage to others
                const allMobs = this.getAllTargets();
                let executedCount = 0;
                let damagedCount = 0;

                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 280) {
                        const healthPercent = mob.hp / mob.maxHp;

                        // Execute enemies below 30% HP
                        if (healthPercent < 0.3) {
                            this.damageMob(mob.id, 9999); // Instant kill
                            executedCount++;
                        } else {
                            // Massive damage to others (ignores armor, escalado con nivel)
                            const executionDamage = Math.floor(85 + Player.getCurrentDamage() * 1.5);
                            const originalReduction = mob.damageReduction || 0;
                            mob.damageReduction = 0;
                            this.damageMob(mob.id, executionDamage);
                            setTimeout(() => {
                                if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                                    mob.damageReduction = originalReduction;
                                }
                            }, 100);
                            damagedCount++;
                        }

                        // Apply bleeding effect
                        mob.bleeding = true;
                        mob.bleedStacks = 5;
                        mob.bleedDamage = 6;
                    }
                });

                // Player becomes invisible and gets damage boost
                Player.invulnerable = true;
                Player.invulnerableTime = 4000;
                Player.applyDamageBoost(50, 8000);

                console.log(`?? Asesino de Sombras - Executed ${executedCount} enemies! Damaged ${damagedCount} others!`);
            },

            // ABYSSAL SHADOWLORD ABILITIES (MASTER CLASS)
            abyssalBladeStorm() {
                // Tormenta de Cuchillas Sombrías - Dash múltiple con 5 slashes giratorios + estelas DoT
                const allMobs = [...this.mobs, ...this.bosses];
                if (allMobs.length === 0) {
                    console.log('??? No enemies for Blade Storm!');
                    return;
                }

                // Find 5 closest enemies for multi-dash
                const targets = allMobs
                    .map(mob => ({
                        mob,
                        dist: Math.sqrt((mob.x - Player.x) ** 2 + (mob.y - Player.y) ** 2)
                    }))
                    .sort((a, b) => a.dist - b.dist)
                    .slice(0, 5);

                let dashCount = 0;
                const dashDelay = 150; // 150ms between dashes

                // Invulnerability during entire combo
                Player.invulnerable = true;
                Player.invulnerableTime = 2000;

                targets.forEach(({ mob }, index) => {
                    setTimeout(() => {
                        const startX = Player.x;
                        const startY = Player.y;

                        // Dash to enemy
                        const angle = Math.atan2(mob.y - Player.y, mob.x - Player.x);
                        Player.x = mob.x - Math.cos(angle) * 50;
                        Player.y = mob.y - Math.sin(angle) * 50;

                        // Spinning slash damage (higher than base ninja)
                        this.damageMob(mob.id, 55);

                        // Create shadow trail with DoT and slow
                        const trailLength = Math.sqrt((Player.x - startX) ** 2 + (Player.y - startY) ** 2);
                        const trailSegments = Math.floor(trailLength / 25);

                        for (let i = 0; i < trailSegments; i++) {
                            const t = i / trailSegments;
                            const trailX = startX + (Player.x - startX) * t;
                            const trailY = startY + (Player.y - startY) * t;

                            setTimeout(() => {
                                allMobs.forEach(trailMob => {
                                    const dx = trailMob.x - trailX;
                                    const dy = trailMob.y - trailY;
                                    const dist = Math.sqrt(dx * dx + dy * dy);

                                    if (dist < 45) {
                                        // DoT damage
                                        this.damageMob(trailMob.id, 8);
                                        // Apply slow (50%)
                                        if (!trailMob.originalSpeed) trailMob.originalSpeed = trailMob.speed;
                                        trailMob.speed = trailMob.originalSpeed * 0.5;
                                        trailMob.slowed = true;
                                        setTimeout(() => {
                                            if (this.mobs.includes(trailMob) || this.bosses.includes(trailMob)) {
                                                trailMob.speed = trailMob.originalSpeed;
                                                trailMob.slowed = false;
                                            }
                                        }, 3000);
                                    }
                                });
                            }, i * 40);
                        }

                        dashCount++;
                    }, index * dashDelay);
                });

                console.log(`??? Tormenta de Cuchillas Sombrías - ${targets.length} dashes executed!`);
            },

            abyssalDeathChain() {
                // Cadena de Muerte - Marca 6 enemigos en cadena con +40% daño, daño salta entre targets
                const allMobs = [...this.mobs, ...this.bosses];
                if (allMobs.length === 0) {
                    console.log('?? No enemies for Death Chain!');
                    return;
                }

                // Find 6 closest enemies
                const targets = allMobs
                    .map(mob => ({
                        mob,
                        dist: Math.sqrt((mob.x - Player.x) ** 2 + (mob.y - Player.y) ** 2)
                    }))
                    .sort((a, b) => a.dist - b.dist)
                    .slice(0, 6);

                let chainedCount = 0;
                targets.forEach(({ mob }, index) => {
                    setTimeout(() => {
                        // Apply death mark (40% more damage for 10 seconds)
                        mob.deathMarked = true;
                        mob.deathMarkTime = 10000;
                        mob.deathMarkMultiplier = 1.4; // 40% more damage

                        // Initial chain damage
                        this.damageMob(mob.id, 35);

                        // Chain damage to nearby enemies
                        allMobs.forEach(nearbyMob => {
                            if (nearbyMob.id !== mob.id) {
                                const dx = nearbyMob.x - mob.x;
                                const dy = nearbyMob.y - mob.y;
                                const dist = Math.sqrt(dx * dx + dy * dy);

                                if (dist < 120) {
                                    // Chain jumps to nearby enemies
                                    this.damageMob(nearbyMob.id, 25);
                                }
                            }
                        });

                        chainedCount++;
                    }, index * 100);
                });

                console.log(`?? Cadena de Muerte - ${targets.length} enemies marked! Damage chains between targets!`);
            },

            abyssalVoidLeap() {
                // Salto al Vacío Fantasma - TP detrás del boss/elite + crítico x2 + AoE oscuridad que ciega
                const allMobs = [...this.mobs, ...this.bosses];
                if (allMobs.length === 0) {
                    console.log('?? No enemies for Void Leap!');
                    return;
                }

                // Prioritize bosses, then closest enemy
                let target = this.bosses.length > 0 ? this.bosses[0] : null;
                if (!target) {
                    target = allMobs.reduce((prev, curr) => {
                        const prevDist = Math.sqrt((prev.x - Player.x) ** 2 + (prev.y - Player.y) ** 2);
                        const currDist = Math.sqrt((curr.x - Player.x) ** 2 + (curr.y - Player.y) ** 2);
                        return prevDist < currDist ? prev : curr;
                    });
                }

                // Teleport behind target
                const angle = Math.atan2(Player.y - target.y, Player.x - target.x);
                Player.x = target.x + Math.cos(angle) * 100;
                Player.y = target.y + Math.sin(angle) * 100;

                // Critical strike x2 (ignores armor)
                const originalReduction = target.damageReduction || 0;
                target.damageReduction = 0;
                this.damageMob(target.id, 90); // Double critical
                setTimeout(() => {
                    if (this.mobs.includes(target) || this.bosses.includes(target)) {
                        target.damageReduction = originalReduction;
                    }
                }, 100);

                // AoE darkness that blinds enemies (reduces their vision/accuracy)
                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 180) {
                        // Blind effect - confuse enemies
                        mob.confused = true;
                        mob.confusedTime = 3000; // 3 seconds
                        // Reduce their effective range
                        if (!mob.originalRange) mob.originalRange = mob.range || 100;
                        mob.range = mob.originalRange * 0.3; // 70% vision reduction

                        setTimeout(() => {
                            if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                                mob.confused = false;
                                mob.range = mob.originalRange;
                            }
                        }, 3000);

                        // AoE damage
                        this.damageMob(mob.id, 30);
                    }
                });

                // Brief invulnerability after leap
                Player.invulnerable = true;
                Player.invulnerableTime = 1500;

                console.log('?? Salto al Vacío Fantasma - Teleported behind target! AoE darkness blinds enemies!');
            },

            abyssalShadowLegion() {
                // Legión de Sombras - Invoca 5 clones que atacan (75% daño, 8s) y explotan al morir
                const allMobs = [...this.mobs, ...this.bosses];
                if (allMobs.length === 0) {
                    console.log('?? No enemies for Shadow Legion!');
                    return;
                }

                // Create 5 clones around player
                const clones = [];
                for (let i = 0; i < 5; i++) {
                    const angle = (Math.PI * 2 * i) / 5;
                    const clone = {
                        id: `shadow_clone_${Date.now()}_${i}`,
                        x: Player.x + Math.cos(angle) * 80,
                        y: Player.y + Math.sin(angle) * 80,
                        hp: 50,
                        maxHp: 50,
                        damage: 0.75, // 75% of player damage
                        lifetime: 8000,
                        createdAt: Date.now(),
                        attackCooldown: 0,
                        attackRate: 1000 // Attack every 1 second
                    };
                    clones.push(clone);
                }

                // Store clones for tracking
                if (!this.shadowClones) this.shadowClones = [];
                this.shadowClones.push(...clones);

                // Clone attack logic
                const cloneInterval = setInterval(() => {
                    clones.forEach(clone => {
                        if (Date.now() - clone.createdAt > clone.lifetime) {
                            // Clone expires - explode
                            allMobs.forEach(mob => {
                                const dx = mob.x - clone.x;
                                const dy = mob.y - clone.y;
                                const dist = Math.sqrt(dx * dx + dy * dy);
                                if (dist < 100) {
                                    this.damageMob(mob.id, 60); // Explosion damage
                                }
                            });
                            // Remove clone
                            const index = this.shadowClones.indexOf(clone);
                            if (index > -1) this.shadowClones.splice(index, 1);
                            return;
                        }

                        // Clone attacks nearest enemy
                        clone.attackCooldown -= 100;
                        if (clone.attackCooldown <= 0) {
                            const nearest = allMobs.reduce((prev, curr) => {
                                const prevDist = Math.sqrt((prev.x - clone.x) ** 2 + (prev.y - clone.y) ** 2);
                                const currDist = Math.sqrt((curr.x - clone.x) ** 2 + (curr.y - clone.y) ** 2);
                                return prevDist < currDist ? prev : curr;
                            });

                            if (nearest) {
                                const dist = Math.sqrt((nearest.x - clone.x) ** 2 + (nearest.y - clone.y) ** 2);
                                if (dist < 150) {
                                    this.damageMob(nearest.id, Math.floor(30 * clone.damage)); // 75% of base damage
                                    clone.attackCooldown = clone.attackRate;
                                }
                            }
                        }
                    });

                    // Clean up interval when all clones are gone
                    if (clones.every(c => Date.now() - c.createdAt > c.lifetime)) {
                        clearInterval(cloneInterval);
                    }
                }, 100);

                console.log('?? Legión de Sombras - 5 shadow clones summoned! They will explode on death!');
            },

            abyssalShadowEmperor() {
                // Emperador Sombra - Invoca mini-boss sombra (200 HP) que ataca y copia ataques
                const allMobs = [...this.mobs, ...this.bosses];

                // Create Shadow Emperor mini-boss
                const emperor = {
                    id: `shadow_emperor_miniboss_${Date.now()}`,
                    x: Player.x + 100,
                    y: Player.y,
                    hp: 200,
                    maxHp: 200,
                    damage: 40,
                    speed: 80,
                    size: 40,
                    lifetime: 15000, // 15 seconds
                    createdAt: Date.now(),
                    attackCooldown: 0,
                    attackRate: 1500, // Attack every 1.5 seconds
                    isBoss: false,
                    isMiniBoss: true
                };

                // Store emperor
                if (!this.shadowEmperors) this.shadowEmperors = [];
                this.shadowEmperors.push(emperor);

                // Emperor AI
                const emperorInterval = setInterval(() => {
                    if (Date.now() - emperor.createdAt > emperor.lifetime || emperor.hp <= 0) {
                        // Emperor expires or dies
                        const index = this.shadowEmperors.indexOf(emperor);
                        if (index > -1) this.shadowEmperors.splice(index, 1);
                        clearInterval(emperorInterval);
                        console.log('?? Shadow Emperor disappeared!');
                        return;
                    }

                    // Emperor attacks nearest enemy
                    emperor.attackCooldown -= 100;
                    if (emperor.attackCooldown <= 0 && allMobs.length > 0) {
                        const nearest = allMobs.reduce((prev, curr) => {
                            const prevDist = Math.sqrt((prev.x - emperor.x) ** 2 + (prev.y - emperor.y) ** 2);
                            const currDist = Math.sqrt((curr.x - emperor.x) ** 2 + (curr.y - emperor.y) ** 2);
                            return prevDist < currDist ? prev : curr;
                        });

                        if (nearest) {
                            const dist = Math.sqrt((nearest.x - emperor.x) ** 2 + (nearest.y - emperor.y) ** 2);
                            if (dist < 200) {
                                this.damageMob(nearest.id, emperor.damage);
                                emperor.attackCooldown = emperor.attackRate;

                                // Move towards enemy
                                const angle = Math.atan2(nearest.y - emperor.y, nearest.x - emperor.x);
                                emperor.x += Math.cos(angle) * emperor.speed * 0.1;
                                emperor.y += Math.sin(angle) * emperor.speed * 0.1;
                            }
                        }
                    }
                }, 100);

                console.log('?? Emperador Sombra - Shadow Emperor mini-boss summoned (200 HP, 15s duration)!');
            },

            abyssalEternalNight() {
                // Noche Eterna - Oscurece pantalla, ejecuta <25% HP en cadena, DoT masivo, invisibilidad
                const allMobs = [...this.mobs, ...this.bosses];
                let executedCount = 0;
                let damagedCount = 0;
                let chainExecutions = 0;

                // Phase 1: Execute enemies below 25% HP in chain (up to 10 jumps)
                const lowHpEnemies = allMobs.filter(mob => (mob.hp / mob.maxHp) < 0.25);

                lowHpEnemies.slice(0, 10).forEach((mob, index) => {
                    setTimeout(() => {
                        this.damageMob(mob.id, 9999); // Instant kill
                        executedCount++;
                        chainExecutions++;

                        // Chain to nearby enemies
                        allMobs.forEach(nearbyMob => {
                            if (nearbyMob.id !== mob.id) {
                                const dx = nearbyMob.x - mob.x;
                                const dy = nearbyMob.y - mob.y;
                                const dist = Math.sqrt(dx * dx + dy * dy);

                                if (dist < 150) {
                                    this.damageMob(nearbyMob.id, 50); // Chain damage
                                }
                            }
                        });
                    }, index * 200);
                });

                // Phase 2: Massive DoT to all remaining enemies
                allMobs.forEach(mob => {
                    if ((mob.hp / mob.maxHp) >= 0.25) {
                        // Apply massive bleeding DoT
                        mob.bleeding = true;
                        mob.bleedStacks = 10;
                        mob.bleedDamage = 12;

                        // Initial damage
                        this.damageMob(mob.id, 70);
                        damagedCount++;

                        // Apply confusion
                        mob.confused = true;
                        mob.confusedTime = 6000;
                    }
                });

                // Phase 3: Player buffs
                Player.invulnerable = true;
                Player.invulnerableTime = 6000; // 6 seconds invulnerability
                Player.invisible = true;
                Player.invisibleTime = 6000;
                Player.applyDamageBoost(50, 10000); // 50% damage boost for 10 seconds

                // Permanent speed boost during duration
                const originalSpeed = Player.speed;
                Player.speed *= 1.5; // 50% speed boost
                setTimeout(() => {
                    Player.speed = originalSpeed;
                }, 6000);

                console.log(`?? NOCHE ETERNA - Executed ${executedCount} enemies in chain! Massive DoT applied to ${damagedCount} others! You are invisible and empowered!`);
            },

            // WIND MASTER ABILITIES
            radioactiveWind() {
                // Viento Radioactivo - Lanza viento en 4 direcciones que aplica radioactividad
                // BUFFED v5: Ahora otorga buff de daño al jugador según enemigos afectados
                const directions = [
                    { angle: 0, name: 'Este' },           // Right
                    { angle: Math.PI / 2, name: 'Sur' },  // Down
                    { angle: Math.PI, name: 'Oeste' },    // Left
                    { angle: -Math.PI / 2, name: 'Norte' } // Up
                ];

                let affectedCount = 0;
                const allMobs = [...this.mobs, ...this.bosses];
                const totalEnemies = allMobs.length;

                directions.forEach((dir, index) => {
                    setTimeout(() => {
                        // Create wind projectile
                        this.projectiles.push({
                            x: Player.x,
                            y: Player.y,
                            vx: Math.cos(dir.angle) * 300,
                            vy: Math.sin(dir.angle) * 300,
                            size: 20,
                            damage: 30, // BUFFED v19.11.2025: 25 ? 30
                            color: '#39ff14',
                            life: 3000,
                            isPlayerProjectile: true,
                            isRadioactive: true
                        });

                        // Check enemies in the path
                        allMobs.forEach(mob => {
                            const dx = mob.x - Player.x;
                            const dy = mob.y - Player.y;
                            const mobAngle = Math.atan2(dy, dx);
                            const angleDiff = Math.abs(mobAngle - dir.angle);
                            const dist = Math.sqrt(dx * dx + dy * dy);

                            // If enemy is roughly in this direction (within 45 degrees) and close enough
                            if ((angleDiff < Math.PI / 4 || angleDiff > 7 * Math.PI / 4) && dist < 400) {
                                // Apply radioactivity
                                mob.radioactive = true;
                                mob.radioactiveTime = 7000; // 7 seconds
                                mob.radioactiveDamage = 4; // Damage per tick
                                mob.radioactiveTickInterval = 500; // Damage every 0.5s
                                affectedCount++;
                            }
                        });

                        // Apply damage buff based on affected enemies (after all directions processed)
                        if (index === directions.length - 1) {
                            setTimeout(() => {
                                const affectedPercentage = totalEnemies > 0 ? affectedCount / totalEnemies : 0;
                                let damageBonus = 0;

                                if (affectedPercentage >= 1.0) {
                                    // Hit ALL enemies - Maximum buff
                                    damageBonus = 0.20; // +20% damage
                                } else if (affectedPercentage >= 0.75) {
                                    // Hit 75%+ enemies
                                    damageBonus = 0.15; // +15% damage
                                } else if (affectedPercentage >= 0.50) {
                                    // Hit 50%+ enemies
                                    damageBonus = 0.10; // +10% damage
                                } else if (affectedPercentage >= 0.25) {
                                    // Hit 25%+ enemies
                                    damageBonus = 0.05; // +5% damage
                                }

                                if (damageBonus > 0) {
                                    Player.applyDamageBoost(damageBonus * 100, 6000);
                                    console.log(`??? Viento Radioactivo - ${affectedCount}/${totalEnemies} enemies affected! +${damageBonus * 100}% damage for 6s!`);
                                } else {
                                    console.log(`??? Viento Radioactivo - ${affectedCount} enemies affected!`);
                                }
                            }, 100);
                        }
                    }, index * 150);
                });
            },

            // TORNADO OVERLORD ABILITIES (MASTER CLASS)
            windSingularity() {
                // Singularidad Eólica - Crea agujero negro de viento estático
                const singularity = {
                    x: Player.x,
                    y: Player.y,
                    radius: 120,
                    pullRadius: 200,
                    duration: 8000,
                    startTime: Date.now()
                };

                if (!this.windSingularities) this.windSingularities = [];
                this.windSingularities.push(singularity);

                // Pull and stun enemies
                const pullInterval = setInterval(() => {
                    if (Date.now() - singularity.startTime > singularity.duration) {
                        clearInterval(pullInterval);
                        this.windSingularities = this.windSingularities.filter(s => s !== singularity);
                        return;
                    }

                    const allMobs = [...this.mobs, ...this.bosses];
                    allMobs.forEach(mob => {
                        const dx = singularity.x - mob.x;
                        const dy = singularity.y - mob.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);

                        if (dist < singularity.pullRadius) {
                            // Pull toward center
                            const pullForce = Math.max(0.1, 1 - (dist / singularity.pullRadius));
                            mob.x += (dx / dist) * pullForce * 8;
                            mob.y += (dy / dist) * pullForce * 8;

                            // Stun if very close
                            if (dist < singularity.radius) {
                                mob.stunned = true;
                                mob.stunnedTime = 3000;
                                mob.originalSpeed = mob.speed;
                                mob.speed = 0;

                                setTimeout(() => {
                                    if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                                        mob.stunned = false;
                                        mob.speed = mob.originalSpeed || mob.speed;
                                    }
                                }, 3000);
                            }
                        }
                    });
                }, 50);

                console.log('?? Wind Singularity created! Pulling enemies for 8s!');
            },

            atmosphericPressure() {
                // Presión Atmosférica - Aplasta enemigos cercanos
                const allMobs = this.getAllTargets();
                let affectedCount = 0;

                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 180) {
                        // Root effect (immobilize)
                        mob.rooted = true;
                        mob.rootedTime = 2000;
                        mob.originalSpeed = mob.speed;
                        mob.speed = 0;

                        // Armor break effect
                        mob.armorBroken = true;
                        mob.armorBrokenTime = 4000;
                        mob.originalDamageReduction = mob.damageReduction || 0;
                        mob.damageReduction = 0;
                        mob.damageMultiplier = 1.2; // +20% damage received

                        // Immediate damage
                        this.damageMob(mob.id, 35);

                        affectedCount++;

                        // Restore speed after root
                        setTimeout(() => {
                            if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                                mob.rooted = false;
                                mob.speed = mob.originalSpeed || mob.speed;
                            }
                        }, 2000);

                        // Remove armor break
                        setTimeout(() => {
                            if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                                mob.armorBroken = false;
                                mob.damageReduction = mob.originalDamageReduction || 0;
                                mob.damageMultiplier = 1;
                            }
                        }, 4000);
                    }
                });

                console.log(`?? Atmospheric Pressure - ${affectedCount} enemies crushed! Root 2s + Armor Break 4s!`);
            },

            enemyTornado() {
                // Tornado de Enemigo - Semi-Ultimate
                const allMobs = [...this.mobs, ...this.bosses];
                if (allMobs.length === 0) {
                    console.log('?? No enemies for Enemy Tornado!');
                    return;
                }

                // Find closest enemy
                let victim = null;
                let minDist = Infinity;
                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist < minDist) {
                        minDist = dist;
                        victim = mob;
                    }
                });

                if (!victim || minDist > 300) {
                    console.log('?? No enemies in range!');
                    return;
                }

                // Player becomes invulnerable
                Player.invulnerable = true;
                Player.invulnerableTime = 4000;

                // Grab victim and spin
                victim.grabbed = true;
                victim.grabStartTime = Date.now();

                const spinDuration = 3000;
                const spinInterval = setInterval(() => {
                    if (Date.now() - victim.grabStartTime > spinDuration) {
                        clearInterval(spinInterval);

                        // Launch victim
                        const launchAngle = Math.random() * Math.PI * 2;
                        victim.x += Math.cos(launchAngle) * 200;
                        victim.y += Math.sin(launchAngle) * 200;
                        this.damageMob(victim.id, 80);
                        victim.grabbed = false;

                        // Generate 4 static storms on remaining enemies
                        const remainingEnemies = allMobs.filter(m => m !== victim && (this.mobs.includes(m) || this.bosses.includes(m)));
                        const stormTargets = remainingEnemies.slice(0, 4);

                        stormTargets.forEach((target, index) => {
                            setTimeout(() => {
                                const storm = {
                                    x: target.x,
                                    y: target.y,
                                    radius: 80,
                                    duration: 6000,
                                    startTime: Date.now()
                                };

                                if (!this.staticStorms) this.staticStorms = [];
                                this.staticStorms.push(storm);

                                // Storm damage over time
                                const stormInterval = setInterval(() => {
                                    if (Date.now() - storm.startTime > storm.duration) {
                                        clearInterval(stormInterval);
                                        this.staticStorms = this.staticStorms.filter(s => s !== storm);
                                        return;
                                    }

                                    const currentMobs = [...this.mobs, ...this.bosses];
                                    currentMobs.forEach(mob => {
                                        const dx = mob.x - storm.x;
                                        const dy = mob.y - storm.y;
                                        const dist = Math.sqrt(dx * dx + dy * dy);

                                        if (dist < storm.radius) {
                                            this.damageMob(mob.id, 15);
                                            // Apply Strong Wind effect
                                            mob.strongWind = true;
                                            mob.strongWindTime = 7000;
                                            if (!mob.originalSpeed) mob.originalSpeed = mob.speed;
                                            mob.speed = mob.originalSpeed * 0.7; // -30% speed

                                            // Remove strong wind after duration
                                            setTimeout(() => {
                                                if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                                                    mob.strongWind = false;
                                                    mob.speed = mob.originalSpeed || mob.speed;
                                                }
                                            }, 7000);
                                        }
                                    });
                                }, 500);
                            }, index * 200);
                        });

                        return;
                    }

                    // Spin victim around player
                    const elapsed = Date.now() - victim.grabStartTime;
                    const angle = (elapsed / 100) % (Math.PI * 2);
                    const radius = 60;

                    victim.x = Player.x + Math.cos(angle) * radius;
                    victim.y = Player.y + Math.sin(angle) * radius;

                    // Tornado damage to nearby enemies
                    allMobs.forEach(mob => {
                        if (mob === victim) return;

                        const dx = mob.x - Player.x;
                        const dy = mob.y - Player.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);

                        if (dist < 150) {
                            // Massive knockback
                            const knockAngle = Math.atan2(dy, dx);
                            mob.x += Math.cos(knockAngle) * 15;
                            mob.y += Math.sin(knockAngle) * 15;

                            // Damage every 200ms
                            if (elapsed % 200 < 50) {
                                this.damageMob(mob.id, 25);
                            }
                        }
                    });
                }, 50);

                console.log('?? Enemy Tornado! Spinning victim and creating massive tornado!');
            },

            tornadoBarrage() {
                // Ráfaga de Tornados - Lanza 5 tornados en patrón circular
                const tornadoCount = 5;
                const angleStep = (Math.PI * 2) / tornadoCount;

                for (let i = 0; i < tornadoCount; i++) {
                    const angle = angleStep * i;

                    this.projectiles.push({
                        x: Player.x,
                        y: Player.y,
                        vx: Math.cos(angle) * 350,
                        vy: Math.sin(angle) * 350,
                        size: 25,
                        damage: 45,
                        color: '#39ff14',
                        life: 4000,
                        isPlayerProjectile: true,
                        piercing: true, // Atraviesa enemigos
                        confuses: true // Aplica confusión
                    });
                }

                // Apply confusion to hit enemies
                setTimeout(() => {
                    const allMobs = [...this.mobs, ...this.bosses];
                    allMobs.forEach(mob => {
                        const dx = mob.x - Player.x;
                        const dy = mob.y - Player.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);

                        if (dist < 200) {
                            mob.confused = true;
                            mob.confusedTime = 4000;
                        }
                    });
                }, 100);

                console.log('??? Tornado Barrage - 5 tornados launched!');
            },

            stormShield() {
                // Escudo de Tormenta - Invulnerabilidad + reducción de daño
                Player.invulnerable = true;
                Player.invulnerableTime = 4000; // 4 seconds invulnerability

                // Additional damage reduction for 6 more seconds
                setTimeout(() => {
                    Player.stormShieldActive = true;
                    Player.damageReduction = (Player.damageReduction || 0) + 30; // 30% damage reduction

                    setTimeout(() => {
                        Player.stormShieldActive = false;
                        Player.damageReduction = Math.max(0, (Player.damageReduction || 0) - 30);
                    }, 6000);
                }, 4000);

                console.log('??? Storm Shield - Invulnerable for 4s + 30% damage reduction for 6s more!');
            },

            apocalypticStorm() {
                // Tormenta Apocalíptica - Ultimate devastador
                const allMobs = [...this.mobs, ...this.bosses];

                // Phase 1: Player invulnerable
                Player.invulnerable = true;
                Player.invulnerableTime = 5000;

                // Phase 2: Attract all enemies
                const attractDuration = 2000;
                const attractStartTime = Date.now();
                const attractInterval = setInterval(() => {
                    if (Date.now() - attractStartTime > attractDuration) {
                        clearInterval(attractInterval);
                    } else {
                        const currentMobs = [...this.mobs, ...this.bosses];
                        currentMobs.forEach(mob => {
                            const dx = Player.x - mob.x;
                            const dy = Player.y - mob.y;
                            const dist = Math.sqrt(dx * dx + dy * dy);

                            if (dist > 0) {
                                mob.x += (dx / dist) * 10;
                                mob.y += (dy / dist) * 10;
                            }
                        });
                    }
                }, 50);

                // Phase 3: Massive damage + confusion + radioactivity
                setTimeout(() => {
                    const currentMobs = [...this.mobs, ...this.bosses];
                    currentMobs.forEach(mob => {
                        const dx = mob.x - Player.x;
                        const dy = mob.y - Player.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);

                        if (dist < 300) {
                            // Massive damage
                            this.damageMob(mob.id, 100);

                            // Apply confusion
                            mob.confused = true;
                            mob.confusedTime = 6000;

                            // Apply radioactivity
                            mob.radioactive = true;
                            mob.radioactiveTime = 10000;
                            mob.radioactiveDamage = 8;
                            mob.radioactiveTickInterval = 500;
                        }
                    });
                }, 2000);

                // Phase 4: Launch 20 tornados
                setTimeout(() => {
                    for (let i = 0; i < 20; i++) {
                        setTimeout(() => {
                            const angle = Math.random() * Math.PI * 2;

                            this.projectiles.push({
                                x: Player.x,
                                y: Player.y,
                                vx: Math.cos(angle) * 400,
                                vy: Math.sin(angle) * 400,
                                size: 30,
                                damage: 60,
                                color: '#ff00ff',
                                life: 5000,
                                isPlayerProjectile: true,
                                piercing: true
                            });
                        }, i * 100);
                    }
                }, 2500);

                // Phase 5: Damage boost
                Player.applyDamageBoost(50, 10000); // +50% damage for 10s

                console.log('??? APOCALYPTIC STORM - Ultimate devastation unleashed!');
            },

            // CYBERNETIC WARLORD ABILITIES (MASTER CLASS)
            plasmaCannon() {
                // Cañón de Plasma - Rayo láser continuo que atraviesa enemigos
                const angle = Math.atan2(
                    this.mobs[0]?.y - Player.y || 0,
                    this.mobs[0]?.x - Player.x || 1
                );

                // Create thick laser beam
                const beamLength = 600;
                const beamWidth = 40;

                // Create laser projectile (daño escalado con nivel)
                const laserDamage = Math.floor(55 + Player.getCurrentDamage() * 1.2);
                this.projectiles.push({
                    x: Player.x,
                    y: Player.y,
                    vx: Math.cos(angle) * 500,
                    vy: Math.sin(angle) * 500,
                    size: beamWidth,
                    damage: laserDamage,
                    color: '#00ffff',
                    life: 2000,
                    isPlayerProjectile: true,
                    piercing: true,
                    isLaser: true
                });

                // Damage all enemies in line
                const allMobs = [...this.mobs, ...this.bosses];
                let hitCount = 0;

                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    const mobAngle = Math.atan2(dy, dx);
                    const angleDiff = Math.abs(mobAngle - angle);

                    // Check if enemy is in laser path
                    if ((angleDiff < 0.2 || angleDiff > Math.PI * 2 - 0.2) && dist < beamLength) {
                        this.damageMob(mob.id, laserDamage);
                        hitCount++;
                    }
                });

                // Increase heat
                Player.heat = Math.min(Player.maxHeat, Player.heat + 15);
                this.checkHeatSystem();

                console.log(`?? Plasma Cannon - Hit ${hitCount} enemies! Heat: ${Player.heat}%`);
            },

            singularityGrenade() {
                // Granada de Singularidad - Atrae enemigos y luego detona
                const grenadeX = Player.x + (Math.random() - 0.5) * 200;
                const grenadeY = Player.y + (Math.random() - 0.5) * 200;

                const grenade = {
                    x: grenadeX,
                    y: grenadeY,
                    radius: 120,
                    pullRadius: 180,
                    duration: 2000,
                    startTime: Date.now(),
                    detonated: false
                };

                if (!this.singularityGrenades) this.singularityGrenades = [];
                this.singularityGrenades.push(grenade);

                // Pull enemies
                const pullInterval = setInterval(() => {
                    if (Date.now() - grenade.startTime > grenade.duration) {
                        clearInterval(pullInterval);

                        // Detonate
                        if (!grenade.detonated) {
                            grenade.detonated = true;
                            const allMobs = [...this.mobs, ...this.bosses];
                            let hitCount = 0;

                            // Daño de detonación escalado
                            const detonationDamage = Math.floor(80 + Player.getCurrentDamage() * 1.5);

                            allMobs.forEach(mob => {
                                const dx = mob.x - grenade.x;
                                const dy = mob.y - grenade.y;
                                const dist = Math.sqrt(dx * dx + dy * dy);

                                if (dist < grenade.radius) {
                                    this.damageMob(mob.id, detonationDamage);
                                    hitCount++;
                                }
                            });

                            // Increase heat on detonation
                            Player.heat = Math.min(Player.maxHeat, Player.heat + 10);
                            this.checkHeatSystem();

                            console.log(`?? Singularity Grenade detonated! ${hitCount} enemies hit! Heat: ${Player.heat}%`);

                            // Remove grenade after explosion
                            setTimeout(() => {
                                this.singularityGrenades = this.singularityGrenades.filter(g => g !== grenade);
                            }, 500);
                        }
                        return;
                    }

                    // Pull enemies toward grenade
                    const allMobs = [...this.mobs, ...this.bosses];
                    allMobs.forEach(mob => {
                        const dx = grenade.x - mob.x;
                        const dy = grenade.y - mob.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);

                        if (dist < grenade.pullRadius && dist > 0) {
                            const pullForce = Math.max(0.1, 1 - (dist / grenade.pullRadius));
                            mob.x += (dx / dist) * pullForce * 6;
                            mob.y += (dy / dist) * pullForce * 6;
                        }
                    });
                }, 50);

                console.log('?? Singularity Grenade deployed! Pulling enemies...');
            },

            droneSwarm() {
                // Enjambre de Drones - 4 drones que orbitan y disparan
                const droneCount = 4;
                const drones = [];

                for (let i = 0; i < droneCount; i++) {
                    const angle = (Math.PI * 2 / droneCount) * i;
                    drones.push({
                        id: Date.now() + i,
                        angle: angle,
                        distance: 80,
                        startTime: Date.now(),
                        duration: 8000,
                        lastShot: 0,
                        shootCooldown: 800
                    });
                }

                if (!this.combatDrones) this.combatDrones = [];
                this.combatDrones.push(...drones);

                // Increase heat when deploying drones
                Player.heat = Math.min(Player.maxHeat, Player.heat + 8);
                this.checkHeatSystem();

                // Drone shooting interval
                const droneInterval = setInterval(() => {
                    const currentTime = Date.now();
                    const activeDrones = this.combatDrones.filter(d => currentTime - d.startTime < d.duration);

                    if (activeDrones.length === 0) {
                        clearInterval(droneInterval);
                        return;
                    }

                    activeDrones.forEach(drone => {
                        // Update drone position (orbit around player)
                        drone.angle += 0.05;
                        const droneX = Player.x + Math.cos(drone.angle) * drone.distance;
                        const droneY = Player.y + Math.sin(drone.angle) * drone.distance;

                        // Shoot at nearest enemy
                        if (currentTime - drone.lastShot > drone.shootCooldown) {
                            const allMobs = [...this.mobs, ...this.bosses];
                            if (allMobs.length > 0) {
                                // Find closest enemy
                                let closest = null;
                                let minDist = Infinity;

                                allMobs.forEach(mob => {
                                    const dx = mob.x - droneX;
                                    const dy = mob.y - droneY;
                                    const dist = Math.sqrt(dx * dx + dy * dy);

                                    if (dist < minDist && dist < 250) {
                                        minDist = dist;
                                        closest = mob;
                                    }
                                });

                                if (closest) {
                                    const angle = Math.atan2(closest.y - droneY, closest.x - droneX);
                                    const droneDamage = Math.floor(20 + Player.getCurrentDamage() * 0.4);

                                    this.projectiles.push({
                                        x: droneX,
                                        y: droneY,
                                        vx: Math.cos(angle) * 400,
                                        vy: Math.sin(angle) * 400,
                                        size: 8,
                                        damage: droneDamage,
                                        color: '#00ffff',
                                        life: 1500,
                                        isPlayerProjectile: true
                                    });

                                    drone.lastShot = currentTime;
                                }
                            }
                        }
                    });
                }, 50);

                // Remove drones after duration
                setTimeout(() => {
                    this.combatDrones = this.combatDrones.filter(d => !drones.includes(d));
                }, 8000);

                console.log('?? Drone Swarm deployed! 4 drones active for 8s!');
            },

            photonBarrier() {
                // Barrera de Fotones - Muro de energía estático
                const barrierX = Player.x + 80; // 80 pixels in front of player
                const barrierY = Player.y;

                const barrier = {
                    x: barrierX,
                    y: barrierY,
                    width: 20,
                    height: 150,
                    duration: 5000,
                    startTime: Date.now()
                };

                if (!this.photonBarriers) this.photonBarriers = [];
                this.photonBarriers.push(barrier);

                // Check collision with enemies
                const barrierInterval = setInterval(() => {
                    if (Date.now() - barrier.startTime > barrier.duration) {
                        clearInterval(barrierInterval);
                        this.photonBarriers = this.photonBarriers.filter(b => b !== barrier);
                        return;
                    }

                    const allMobs = [...this.mobs, ...this.bosses];
                    allMobs.forEach(mob => {
                        // Check if enemy is touching barrier
                        const dx = Math.abs(mob.x - barrier.x);
                        const dy = Math.abs(mob.y - barrier.y);

                        if (dx < barrier.width / 2 + mob.size && dy < barrier.height / 2 + mob.size) {
                            // Push enemy back
                            if (mob.x < barrier.x) {
                                mob.x -= 10;
                            } else {
                                mob.x += 10;
                            }

                            // Burn damage (escalado con nivel)
                            const burnDamage = Math.floor(15 + Player.getCurrentDamage() * 0.3);
                            this.damageMob(mob.id, burnDamage);
                        }
                    });
                }, 100);

                console.log('??? Photon Barrier deployed! Blocking enemies for 5s!');
            },

            mechSuit() {
                // Protocolo: MECH-SUIT - Armadura pesada con misiles teledirigidos
                // Impact damage on landing
                const allMobs = [...this.mobs, ...this.bosses];
                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 150) {
                        const impactDamage = Math.floor(50 + Player.getCurrentDamage() * 1.0);
                        this.damageMob(mob.id, impactDamage);

                        // Knockback
                        const angle = Math.atan2(dy, dx);
                        mob.x += Math.cos(angle) * 80;
                        mob.y += Math.sin(angle) * 80;
                    }
                });

                // Activate MECH-SUIT mode
                Player.mechSuitActive = true;
                Player.mechSuitTime = 10000;
                Player.mechSuitStartTime = Date.now();

                // Increase heat significantly when activating MECH-SUIT
                Player.heat = Math.min(Player.maxHeat, Player.heat + 20);
                this.checkHeatSystem();

                // Modify player stats
                Player.originalSpeed = Player.speed;
                Player.speed = Player.speed * 0.8; // -20% speed
                Player.damageReduction = (Player.damageReduction || 0) + 80; // +80% defense

                // Guided missiles system
                Player.guidedMissilesActive = true;

                // Restore after duration
                setTimeout(() => {
                    Player.mechSuitActive = false;
                    Player.speed = Player.originalSpeed || Player.baseSpeed;
                    Player.damageReduction = Math.max(0, (Player.damageReduction || 0) - 80);
                    Player.guidedMissilesActive = false;
                    console.log('?? MECH-SUIT deactivated!');
                }, 10000);

                console.log('?? MECH-SUIT activated! -20% speed, +80% defense, guided missiles for 10s!');
            },

            orbitalRagnarok() {
                // Satélite Orbital "Ragnarok" - Rayo láser devastador
                const targetX = Player.x + (Math.random() - 0.5) * 300;
                const targetY = Player.y + (Math.random() - 0.5) * 300;

                const orbital = {
                    x: targetX,
                    y: targetY,
                    radius: 150,
                    warningTime: 3000,
                    startTime: Date.now(),
                    fired: false
                };

                if (!this.orbitalStrikes) this.orbitalStrikes = [];
                this.orbitalStrikes.push(orbital);

                console.log('??? Orbital Ragnarok targeting... 3 seconds until impact!');

                // Fire after warning
                setTimeout(() => {
                    if (!orbital.fired) {
                        orbital.fired = true;

                        // Vaporize everything in area
                        const allMobs = [...this.mobs, ...this.bosses];
                        let hitCount = 0;

                        allMobs.forEach(mob => {
                            const dx = mob.x - orbital.x;
                            const dy = mob.y - orbital.y;
                            const dist = Math.sqrt(dx * dx + dy * dy);

                            if (dist < orbital.radius) {
                                this.damageMob(mob.id, 9999); // Pure damage
                                hitCount++;
                            }
                        });

                        // Create burned ground
                        const burnedGround = {
                            x: orbital.x,
                            y: orbital.y,
                            radius: orbital.radius,
                            duration: 5000,
                            startTime: Date.now()
                        };

                        if (!this.burnedGrounds) this.burnedGrounds = [];
                        this.burnedGrounds.push(burnedGround);

                        // Damage over time on burned ground
                        const burnInterval = setInterval(() => {
                            if (Date.now() - burnedGround.startTime > burnedGround.duration) {
                                clearInterval(burnInterval);
                                this.burnedGrounds = this.burnedGrounds.filter(b => b !== burnedGround);
                                return;
                            }

                            const currentMobs = [...this.mobs, ...this.bosses];
                            currentMobs.forEach(mob => {
                                const dx = mob.x - burnedGround.x;
                                const dy = mob.y - burnedGround.y;
                                const dist = Math.sqrt(dx * dx + dy * dy);

                                if (dist < burnedGround.radius) {
                                    this.damageMob(mob.id, 10);
                                }
                            });
                        }, 500);

                        // Increase heat massively on ultimate use
                        Player.heat = Math.min(Player.maxHeat, Player.heat + 25);
                        this.checkHeatSystem();

                        console.log(`??? RAGNAROK FIRED! ${hitCount} enemies vaporized! Heat: ${Player.heat}%`);

                        // Remove orbital marker
                        setTimeout(() => {
                            this.orbitalStrikes = this.orbitalStrikes.filter(o => o !== orbital);
                        }, 1000);
                    }
                }, 3000);
            },

            // ===== ROMAN LEGIONARY ABILITIES =====

            gladiusFulminante() {
                // Gladius Fulminante - Serie de estocadas rápidas con aumento de velocidad de ataque
                const allMobs = [...this.mobs, ...this.bosses];
                if (allMobs.length === 0) {
                    console.log('?? No hay enemigos para Gladius Fulminante!');
                    return;
                }

                // Encontrar enemigos cercanos (radio 200)
                const nearbyEnemies = allMobs.filter(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    return dist < 200;
                });

                if (nearbyEnemies.length === 0) {
                    console.log('?? No hay enemigos cercanos!');
                    return;
                }

                // Ejecutar 5 estocadas rápidas
                const thrustCount = 5;
                let thrustIndex = 0;
                let enemiesHit = new Set();

                const thrustInterval = setInterval(() => {
                    if (thrustIndex >= thrustCount) {
                        clearInterval(thrustInterval);
                        return;
                    }

                    // Seleccionar enemigo aleatorio cercano
                    const currentNearby = allMobs.filter(mob => {
                        const dx = mob.x - Player.x;
                        const dy = mob.y - Player.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);
                        return dist < 200;
                    });

                    if (currentNearby.length > 0) {
                        const target = currentNearby[Math.floor(Math.random() * currentNearby.length)];

                        // Crear efecto visual de estocada (línea roja carmesí)
                        const angle = Math.atan2(target.y - Player.y, target.x - Player.x);
                        const thrustEffect = {
                            startX: Player.x,
                            startY: Player.y,
                            endX: target.x,
                            endY: target.y,
                            color: '#dc143c',
                            width: 4,
                            lifetime: 150,
                            createdAt: Date.now()
                        };

                        if (!this.gladiusThrusts) this.gladiusThrusts = [];
                        this.gladiusThrusts.push(thrustEffect);

                        // Daño por estocada
                        this.damageMob(target.id, 22);
                        enemiesHit.add(target.id);

                        // Crear partículas de sangre dorada (gloria romana)
                        for (let i = 0; i < 8; i++) {
                            const particleAngle = Math.random() * Math.PI * 2;
                            const particleSpeed = 100 + Math.random() * 150;
                            this.projectiles.push({
                                x: target.x,
                                y: target.y,
                                vx: Math.cos(particleAngle) * particleSpeed,
                                vy: Math.sin(particleAngle) * particleSpeed,
                                size: 4 + Math.random() * 4,
                                damage: 0,
                                color: Math.random() > 0.5 ? '#dc143c' : '#ffd700',
                                life: 400,
                                isPlayerProjectile: false,
                                isParticle: true
                            });
                        }
                    }

                    thrustIndex++;
                }, 120); // 120ms entre estocadas = muy rápido

                // Buff acumulativo de velocidad de ataque (5% por golpe)
                if (!Player.gladiusStacks) Player.gladiusStacks = 0;
                Player.gladiusStacks = Math.min(Player.gladiusStacks + 1, 10); // Máximo 10 stacks = 50%

                const attackSpeedBonus = Player.gladiusStacks * 0.05;

                // Aplicar buff visual al jugador
                Player.attackSpeedBonus = attackSpeedBonus;

                // El buff dura 8 segundos
                setTimeout(() => {
                    if (Player.gladiusStacks > 0) {
                        Player.gladiusStacks--;
                        Player.attackSpeedBonus = Player.gladiusStacks * 0.05;
                    }
                }, 8000);

                console.log(`?? Gladius Fulminante! ${thrustCount} estocadas! Velocidad de ataque: +${(attackSpeedBonus * 100).toFixed(0)}%`);
            },

            formacionTestudo() {
                // Formación Testudo - Escudo defensivo legendario romano
                console.log('??? FORMACIÓN TESTUDO! Defensa romana activada!');

                // Activar escudo testudo
                Player.testudoActive = true;
                Player.testudoStartTime = Date.now();
                Player.testudoDuration = 5000; // 5 segundos

                // Reducir daño recibido en 70%
                const originalDamageReduction = Player.damageReduction || 0;
                Player.damageReduction = 0.70;

                // Activar reflejo de daño (30% del daño bloqueado)
                Player.testudoReflect = 0.30;

                // Crear efecto visual de escudos romanos alrededor del jugador
                const shieldCount = 8;
                const testudoShields = [];

                for (let i = 0; i < shieldCount; i++) {
                    const angle = (Math.PI * 2 / shieldCount) * i;
                    testudoShields.push({
                        angle: angle,
                        distance: 60,
                        rotation: 0
                    });
                }

                Player.testudoShields = testudoShields;

                // Crear aura dorada pulsante
                Player.testudoAura = {
                    radius: 80,
                    pulseSpeed: 0.003,
                    color: '#ffd700'
                };

                // Después de 5 segundos, desactivar
                setTimeout(() => {
                    Player.testudoActive = false;
                    Player.damageReduction = originalDamageReduction;
                    Player.testudoReflect = 0;
                    Player.testudoShields = null;
                    Player.testudoAura = null;
                    console.log('??? Formación Testudo terminada');
                }, 5000);

                // Efecto de ondas de choque al activar
                for (let i = 0; i < 3; i++) {
                    setTimeout(() => {
                        const shockwave = {
                            x: Player.x,
                            y: Player.y,
                            radius: 0,
                            maxRadius: 150,
                            speed: 300,
                            color: '#dc143c',
                            lifetime: 800,
                            createdAt: Date.now()
                        };

                        if (!this.testudoShockwaves) this.testudoShockwaves = [];
                        this.testudoShockwaves.push(shockwave);
                    }, i * 200);
                }
            },

            lanzamientoPilum() {
                // Lanzamiento de Pilum - Tres jabalinas que atraviesan enemigos
                console.log('??? LANZAMIENTO DE PILUM! Jabalinas romanas!');

                const allMobs = [...this.mobs, ...this.bosses];
                if (allMobs.length === 0) {
                    console.log('??? No hay enemigos para lanzar pilum!');
                    return;
                }

                // Encontrar el enemigo más cercano para apuntar
                let closest = null;
                let minDist = Infinity;
                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist < minDist) {
                        minDist = dist;
                        closest = mob;
                    }
                });

                if (!closest) return;

                // Lanzar 3 pilums en formación (centro, izquierda, derecha)
                const baseAngle = Math.atan2(closest.y - Player.y, closest.x - Player.x);
                const spreadAngles = [0, -0.25, 0.25]; // Centro, izquierda, derecha

                spreadAngles.forEach((angleOffset, index) => {
                    setTimeout(() => {
                        const angle = baseAngle + angleOffset;

                        // Crear pilum con efecto especial (daño escalado con nivel)
                        const pilumDamage = Math.floor(35 + Player.getCurrentDamage() * 0.8);
                        const pilum = {
                            x: Player.x,
                            y: Player.y,
                            vx: Math.cos(angle) * 500,
                            vy: Math.sin(angle) * 500,
                            angle: angle,
                            size: 25,
                            damage: pilumDamage,
                            color: '#8b4513', // Marrón para la madera
                            life: 3000,
                            isPlayerProjectile: true,
                            isPilum: true,
                            piercing: true, // Atraviesa enemigos
                            hitEnemies: new Set(), // Rastrear enemigos golpeados
                            armorReduction: 0.40, // 40% reducción de armadura
                            bleedDamage: 8, // Daño de sangrado por segundo
                            bleedDuration: 5000, // 5 segundos de sangrado
                            trail: [] // Estela del pilum
                        };

                        this.projectiles.push(pilum);

                        // Efecto de lanzamiento (partículas)
                        for (let i = 0; i < 5; i++) {
                            const particleAngle = angle + (Math.random() - 0.5) * 0.5;
                            this.projectiles.push({
                                x: Player.x,
                                y: Player.y,
                                vx: Math.cos(particleAngle) * (200 + Math.random() * 100),
                                vy: Math.sin(particleAngle) * (200 + Math.random() * 100),
                                size: 3,
                                damage: 0,
                                color: '#ffd700',
                                life: 300,
                                isPlayerProjectile: false,
                                isParticle: true
                            });
                        }
                    }, index * 100); // 100ms entre cada pilum
                });
            },

            gritoCenturion() {
                // Grito del Centurión - Aturde enemigos y aumenta daño
                console.log('?? GRITO DEL CENTURIÓN! ¿Por Roma!');

                const allMobs = [...this.mobs, ...this.bosses];
                if (allMobs.length === 0) {
                    console.log('?? No hay enemigos para el grito!');
                    return;
                }

                // Crear onda de sonido visual expansiva
                for (let i = 0; i < 5; i++) {
                    setTimeout(() => {
                        const soundWave = {
                            x: Player.x,
                            y: Player.y,
                            radius: 0,
                            maxRadius: 300,
                            speed: 400,
                            color: '#dc143c',
                            lifetime: 1000,
                            createdAt: Date.now(),
                            isSoundWave: true
                        };

                        if (!this.centurionWaves) this.centurionWaves = [];
                        this.centurionWaves.push(soundWave);
                    }, i * 150);
                }

                // Aturdir enemigos cercanos (radio 250)
                let stunnedCount = 0;
                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 250) {
                        // Aturdir por 2 segundos
                        mob.stunned = true;
                        mob.stunnedTime = 2000;
                        mob.stunnedStartTime = Date.now();

                        // Guardar velocidad original
                        if (!mob.originalSpeed) {
                            mob.originalSpeed = mob.speed;
                        }
                        mob.speed = 0;

                        // Restaurar velocidad después del aturdimiento
                        setTimeout(() => {
                            if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                                mob.stunned = false;
                                mob.speed = mob.originalSpeed;
                            }
                        }, 2000);

                        // Efecto visual de aturdimiento
                        for (let i = 0; i < 3; i++) {
                            setTimeout(() => {
                                const starX = mob.x + (Math.random() - 0.5) * 40;
                                const starY = mob.y - mob.size - 20 + (Math.random() - 0.5) * 20;

                                this.projectiles.push({
                                    x: starX,
                                    y: starY,
                                    vx: 0,
                                    vy: -30,
                                    size: 12,
                                    damage: 0,
                                    color: '#ffff00',
                                    life: 800,
                                    isPlayerProjectile: false,
                                    isParticle: true,
                                    isStunStar: true
                                });
                            }, i * 200);
                        }

                        stunnedCount++;
                    }
                });

                // Buff de daño para el jugador (+50% durante 8 segundos)
                Player.centurionBoost = true;
                Player.centurionBoostMultiplier = 1.5;
                Player.centurionBoostTime = 8000;
                Player.centurionBoostStartTime = Date.now();

                setTimeout(() => {
                    Player.centurionBoost = false;
                    Player.centurionBoostMultiplier = 1.0;
                    console.log('?? Grito del Centurión terminado');
                }, 8000);

                // Crear aura carmesí alrededor del jugador
                Player.centurionAura = {
                    radius: 80,
                    color: '#dc143c',
                    duration: 8000,
                    startTime: Date.now()
                };

                console.log(`?? ${stunnedCount} enemigos aturdidos! +50% daño por 8s!`);
            },

            aguilaImperial() {
                // Águila Imperial - Semi-Ultimate Épica
                console.log('?? íGUILA IMPERIAL! ¡El espíritu de Roma desciende!');

                const allMobs = [...this.mobs, ...this.bosses];

                // Invulnerabilidad por 3 segundos
                Player.invulnerable = true;
                Player.invulnerableTime = 3000;

                // Crear Águila dorada gigante
                const eagle = {
                    x: Player.x,
                    y: -100, // Empieza arriba de la pantalla
                    targetY: Player.y,
                    size: 80,
                    descending: true,
                    startTime: Date.now(),
                    duration: 3000
                };

                if (!this.imperialEagles) this.imperialEagles = [];
                this.imperialEagles.push(eagle);

                // Animación de descenso del Águila
                const descentInterval = setInterval(() => {
                    if (eagle.descending && eagle.y < eagle.targetY) {
                        eagle.y += 15; // Velocidad de descenso
                    } else if (eagle.descending) {
                        eagle.descending = false;

                        // Al llegar, emitir ondas de choque doradas
                        for (let wave = 0; wave < 6; wave++) {
                            setTimeout(() => {
                                const shockwave = {
                                    x: Player.x,
                                    y: Player.y,
                                    radius: 0,
                                    maxRadius: 250,
                                    color: '#ffd700',
                                    lifetime: 800,
                                    createdAt: Date.now(),
                                    isEagleWave: true
                                };

                                if (!this.eagleShockwaves) this.eagleShockwaves = [];
                                this.eagleShockwaves.push(shockwave);

                                // Daño y empuje a enemigos
                                allMobs.forEach(mob => {
                                    const dx = mob.x - Player.x;
                                    const dy = mob.y - Player.y;
                                    const dist = Math.sqrt(dx * dx + dy * dy);

                                    if (dist < 250 && dist > 0) {
                                        // Daño escalado con nivel
                                        const eagleDamage = Math.floor(40 + Player.getCurrentDamage() * 0.8);
                                        this.damageMob(mob.id, eagleDamage);

                                        // Empuje
                                        const pushForce = 80;
                                        mob.x += (dx / dist) * pushForce;
                                        mob.y += (dy / dist) * pushForce;
                                    }
                                });
                            }, wave * 500);
                        }

                        clearInterval(descentInterval);
                    }
                }, 50);

                // Garantizar crítico en el siguiente ataque
                Player.guaranteedCrit = true;
                Player.guaranteedCritTime = 5000; // 5 segundos para usar el crítico

                setTimeout(() => {
                    Player.guaranteedCrit = false;
                    console.log('?? Águila Imperial terminada');
                }, 5000);

                // Partículas doradas cayendo del cielo
                for (let i = 0; i < 30; i++) {
                    setTimeout(() => {
                        const particleX = Player.x + (Math.random() - 0.5) * 200;
                        const particleY = -50;

                        this.projectiles.push({
                            x: particleX,
                            y: particleY,
                            vx: (Math.random() - 0.5) * 50,
                            vy: 200 + Math.random() * 100,
                            size: 6 + Math.random() * 6,
                            damage: 0,
                            color: '#ffd700',
                            life: 2000,
                            isPlayerProjectile: false,
                            isParticle: true,
                            isGoldenFeather: true
                        });
                    }, i * 50);
                }

                console.log('?? Invulnerable por 3s! Próximo ataque: CRÍTICO GARANTIZADO!');
            },

            legioAeterna() {
                // Legio Aeterna - Ultimate definitiva del Legionario Romano
                console.log('?? LEGIO AETERNA! íLA LEGIÓN ETERNA DE ROMA!');

                const allMobs = [...this.mobs, ...this.bosses];

                // Oscurecer el campo de batalla
                Player.legioAeternaActive = true;
                Player.legioAeternaStartTime = Date.now();
                Player.legioAeternaDuration = 4500;

                // Invulnerabilidad total durante la ultimate
                Player.invulnerable = true;
                Player.invulnerableTime = 4500;

                // Crear 20 legionarios fantasmales en formación de V (MÁXIMA OPTIMIZACIÓN)
                const legionaries = [];
                const rows = 5; // Solo 5 filas
                const legsPerRow = 4; // Solo 4 por fila
                const spacing = 70;
                const vAngle = Math.PI / 6; // íngulo de la V

                for (let row = 0; row < rows; row++) {
                    for (let col = 0; col < legsPerRow; col++) {
                        const side = col < legsPerRow / 2 ? -1 : 1;
                        const colOffset = Math.abs(col - legsPerRow / 2);

                        const x = Player.x + side * (colOffset * spacing * Math.cos(vAngle));
                        const y = Player.y + 200 + (row * spacing) + (colOffset * spacing * Math.sin(vAngle));

                        legionaries.push({
                            x: x,
                            y: y,
                            speed: 12 + Math.random() * 6
                        });
                    }
                }

                Player.legioAeternaLegionaries = legionaries;

                // Aura dorada radiante y capa carmesí ondeando
                Player.legioAeternaAura = {
                    radius: 120,
                    color: '#ffd700',
                    capeWave: 0
                };

                // Daño masivo a todos los enemigos cada 0.5 segundos
                let damageCount = 0;
                const damageInterval = setInterval(() => {
                    if (damageCount >= 9) { // 9 ticks = 4.5 segundos
                        clearInterval(damageInterval);
                        return;
                    }

                    // Daño masivo escalado con nivel
                    const legionDamage = Math.floor(80 + Player.getCurrentDamage() * 2.0);

                    allMobs.forEach(mob => {
                        // Daño masivo
                        this.damageMob(mob.id, legionDamage);

                        // Aplicar Terror Romano
                        if (!mob.terrorRomano) {
                            mob.terrorRomano = true;
                            mob.originalSpeed = mob.speed;
                            mob.originalDamage = mob.damage;
                            mob.speed *= 0.2; // -80% velocidad
                            mob.damage *= 0.2; // -80% daño

                            // Restaurar después de la ultimate
                            setTimeout(() => {
                                if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                                    mob.speed = mob.originalSpeed;
                                    mob.damage = mob.originalDamage;
                                    mob.terrorRomano = false;
                                }
                            }, 4500);
                        }
                    });

                    damageCount++;
                }, 500);

                // Efectos visuales Épicos
                // Partículas doradas y carmesí
                for (let i = 0; i < 100; i++) {
                    setTimeout(() => {
                        const angle = Math.random() * Math.PI * 2;
                        const distance = Math.random() * 300;
                        const particleX = Player.x + Math.cos(angle) * distance;
                        const particleY = Player.y + Math.sin(angle) * distance;

                        this.projectiles.push({
                            x: particleX,
                            y: particleY,
                            vx: (Math.random() - 0.5) * 100,
                            vy: -100 - Math.random() * 100,
                            size: 8 + Math.random() * 8,
                            damage: 0,
                            color: Math.random() > 0.5 ? '#ffd700' : '#dc143c',
                            life: 2000,
                            isPlayerProjectile: false,
                            isParticle: true
                        });
                    }, i * 30);
                }

                // Terminar después de 4.5 segundos
                setTimeout(() => {
                    Player.legioAeternaActive = false;
                    Player.legioAeternaLegionaries = null;
                    Player.legioAeternaAura = null;
                    console.log('?? Legio Aeterna terminada - ¡Gloria a Roma!');
                }, 4500);

                console.log('?? LEGIO AETERNA ACTIVADA! 20 legionarios de Élite cargan! Terror Romano aplicado!');
            },

            // ===== LEVEL SYSTEM HELPERS =====

            assignMobLevel(mob) {
                // Assign level based on player level with some variation
                const minLevel = Math.max(1, Player.level - 2);
                const maxLevel = Player.level + 3;
                mob.level = minLevel + Math.floor(Math.random() * (maxLevel - minLevel + 1));

                // Scale HP and damage based on level
                const levelMultiplier = 1 + (mob.level - 1) * 0.08; // +8% per level
                mob.maxHp = Math.floor(mob.maxHp * levelMultiplier);
                mob.hp = mob.maxHp;
                mob.damage = Math.floor(mob.damage * levelMultiplier);

                return mob;
            },

            // ===== SPARTAN HOPLITE ABILITIES =====

            doruPenetrante() {
                // Doru Penetrante - Lanza espartana que atraviesa enemigos
                console.log('??? DORU PENETRANTE! Lanza espartana!');

                const allMobs = [...this.mobs, ...this.bosses];
                if (allMobs.length === 0) {
                    console.log('??? No hay enemigos para lanzar el doru!');
                    return;
                }

                // Encontrar dirección hacia el enemigo más cercano
                let closest = null;
                let minDist = Infinity;
                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist < minDist) {
                        minDist = dist;
                        closest = mob;
                    }
                });

                if (!closest) return;

                const angle = Math.atan2(closest.y - Player.y, closest.x - Player.x);

                // Crear doru (lanza espartana) con daño escalado
                const doruDamage = Math.floor(40 + Player.getCurrentDamage() * 0.9);
                const doru = {
                    x: Player.x,
                    y: Player.y,
                    vx: Math.cos(angle) * 550,
                    vy: Math.sin(angle) * 550,
                    angle: angle,
                    size: 30,
                    damage: doruDamage,
                    color: '#CD7F32', // Bronce
                    life: 3500,
                    isPlayerProjectile: true,
                    isDoru: true,
                    piercing: true,
                    hitEnemies: new Set(),
                    bleedDamage: 10,
                    bleedDuration: 6000,
                    trail: []
                };

                this.projectiles.push(doru);

                // Partículas de bronce al lanzar
                for (let i = 0; i < 8; i++) {
                    const particleAngle = angle + (Math.random() - 0.5) * 0.6;
                    this.projectiles.push({
                        x: Player.x,
                        y: Player.y,
                        vx: Math.cos(particleAngle) * (250 + Math.random() * 150),
                        vy: Math.sin(particleAngle) * (250 + Math.random() * 150),
                        size: 4,
                        damage: 0,
                        color: '#CD7F32',
                        life: 400,
                        isPlayerProjectile: false,
                        isParticle: true
                    });
                }

                console.log('??? Doru lanzado! Atravesarí a todos los enemigos!');
            },

            falangeEspartana() {
                // Falange Espartana - Formación defensiva con escudo hoplon
                console.log('??? FALANGE ESPARTANA! ¿Por Esparta!');

                const allMobs = [...this.mobs, ...this.bosses];

                // Activar falange
                Player.phalanxActive = true;
                Player.phalanxStartTime = Date.now();
                Player.phalanxDuration = 6000; // 6 segundos

                // Reducir daño recibido en 75%
                const originalDamageReduction = Player.damageReduction || 0;
                Player.damageReduction = 0.75;

                // Empujar enemigos cercanos
                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 150 && dist > 0) {
                        const pushForce = 120;
                        mob.x += (dx / dist) * pushForce;
                        mob.y += (dy / dist) * pushForce;
                        this.damageMob(mob.id, 25);
                    }
                });

                // Crear escudos hoplon alrededor del jugador
                const shieldCount = 6;
                const phalanxShields = [];

                for (let i = 0; i < shieldCount; i++) {
                    const angle = (Math.PI * 2 / shieldCount) * i;
                    phalanxShields.push({
                        angle: angle,
                        distance: 65,
                        rotation: 0
                    });
                }

                Player.phalanxShields = phalanxShields;

                // Aura roja espartana
                Player.phalanxAura = {
                    radius: 85,
                    pulseSpeed: 0.004,
                    color: '#8B0000'
                };

                // Después de 6 segundos, desactivar
                setTimeout(() => {
                    Player.phalanxActive = false;
                    Player.damageReduction = originalDamageReduction;
                    Player.phalanxShields = null;
                    Player.phalanxAura = null;
                    console.log('??? Falange Espartana terminada');
                }, 6000);

                // Ondas de choque al activar
                for (let i = 0; i < 3; i++) {
                    setTimeout(() => {
                        const shockwave = {
                            x: Player.x,
                            y: Player.y,
                            radius: 0,
                            maxRadius: 160,
                            speed: 320,
                            color: '#8B0000',
                            lifetime: 900,
                            createdAt: Date.now()
                        };

                        if (!this.phalanxShockwaves) this.phalanxShockwaves = [];
                        this.phalanxShockwaves.push(shockwave);
                    }, i * 250);
                }

                console.log('??? Falange Espartana activada! -75% daño recibido!');
            },

            cargaEspartana() {
                // Carga Espartana - Dash agresivo con escudo
                console.log('? CARGA ESPARTANA! íAdelante!');

                const allMobs = [...this.mobs, ...this.bosses];

                // Dirección de la carga (hacia el mouse o enemigo más cercano)
                let chargeAngle = 0;

                if (allMobs.length > 0) {
                    const closest = allMobs.reduce((prev, curr) => {
                        const prevDist = Math.sqrt((prev.x - Player.x) ** 2 + (prev.y - Player.y) ** 2);
                        const currDist = Math.sqrt((curr.x - Player.x) ** 2 + (curr.y - Player.y) ** 2);
                        return prevDist < currDist ? prev : curr;
                    });
                    chargeAngle = Math.atan2(closest.y - Player.y, closest.x - Player.x);
                } else {
                    chargeAngle = 0; // Carga hacia la derecha por defecto
                }

                // Guardar posición inicial
                const startX = Player.x;
                const startY = Player.y;

                // Distancia de carga
                const chargeDistance = 250;
                const targetX = Player.x + Math.cos(chargeAngle) * chargeDistance;
                const targetY = Player.y + Math.sin(chargeAngle) * chargeDistance;

                // Crear estela de carga
                const chargeTrail = [];
                const steps = 15;

                for (let i = 0; i <= steps; i++) {
                    const t = i / steps;
                    const trailX = startX + (targetX - startX) * t;
                    const trailY = startY + (targetY - startY) * t;

                    setTimeout(() => {
                        // Mover jugador
                        if (i === steps) {
                            Player.x = targetX;
                            Player.y = targetY;

                            // Asegurar que está dentro del canvas
                            const canvas = document.getElementById('game-canvas');
                            Player.x = Math.max(35, Math.min(canvas.width - 35, Player.x));
                            Player.y = Math.max(35, Math.min(canvas.height - 35, Player.y));
                        }

                        // Dañar y empujar enemigos en el camino
                        allMobs.forEach(mob => {
                            const dx = mob.x - trailX;
                            const dy = mob.y - trailY;
                            const dist = Math.sqrt(dx * dx + dy * dy);

                            if (dist < 60) {
                                const chargeDamage = Math.floor(35 + Player.getCurrentDamage() * 0.7);
                                this.damageMob(mob.id, chargeDamage);

                                // Empujar y aturdir
                                const pushForce = 100;
                                mob.x += Math.cos(chargeAngle) * pushForce;
                                mob.y += Math.sin(chargeAngle) * pushForce;

                                // Aturdir por 1.5 segundos
                                if (!mob.stunned) {
                                    mob.stunned = true;
                                    mob.originalSpeed = mob.speed;
                                    mob.speed = 0;

                                    setTimeout(() => {
                                        if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                                            mob.stunned = false;
                                            mob.speed = mob.originalSpeed;
                                        }
                                    }, 1500);
                                }
                            }
                        });

                        // Partículas de polvo
                        for (let j = 0; j < 3; j++) {
                            this.projectiles.push({
                                x: trailX,
                                y: trailY,
                                vx: (Math.random() - 0.5) * 100,
                                vy: (Math.random() - 0.5) * 100,
                                size: 5 + Math.random() * 5,
                                damage: 0,
                                color: '#8B0000',
                                life: 500,
                                isPlayerProjectile: false,
                                isParticle: true
                            });
                        }
                    }, i * 30); // 30ms por paso = carga rápida
                }

                // Buff de velocidad después de la carga
                Player.chargeSpeedBoost = true;
                Player.speed *= 1.5;

                setTimeout(() => {
                    Player.chargeSpeedBoost = false;
                    Player.speed = Player.baseSpeed;
                }, 3000);

                // Invulnerabilidad breve durante la carga
                Player.invulnerable = true;
                Player.invulnerableTime = 450; // Duración de la carga

                console.log('? Carga Espartana! +50% velocidad por 3s!');
            },

            gritoAroo() {
                // Grito de Guerra: ¡AROO! - El legendario grito espartano
                console.log('?? ¡AROO! ¡AROO! ¡AROO!');

                const allMobs = [...this.mobs, ...this.bosses];

                // Crear ondas de sonido masivas
                for (let i = 0; i < 6; i++) {
                    setTimeout(() => {
                        const soundWave = {
                            x: Player.x,
                            y: Player.y,
                            radius: 0,
                            maxRadius: 350,
                            speed: 450,
                            color: '#8B0000',
                            lifetime: 1200,
                            createdAt: Date.now(),
                            isArooWave: true
                        };

                        if (!this.arooWaves) this.arooWaves = [];
                        this.arooWaves.push(soundWave);
                    }, i * 180);
                }

                // Intimidar enemigos cercanos
                let intimidatedCount = 0;
                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 300) {
                        // Intimidación: reducir velocidad y daño temporalmente
                        mob.intimidated = true;
                        mob.originalSpeed = mob.speed;
                        mob.originalDamage = mob.damage;
                        mob.speed *= 0.7; // -30% velocidad
                        mob.damage *= 0.7; // -30% daño

                        setTimeout(() => {
                            if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                                mob.speed = mob.originalSpeed;
                                mob.damage = mob.originalDamage;
                                mob.intimidated = false;
                            }
                        }, 10000);

                        intimidatedCount++;
                    }
                });

                // Buff masivo para el jugador
                Player.arooBoost = true;
                Player.arooDamageMultiplier = 1.6; // +60% daño
                Player.arooResistance = 0.4; // +40% resistencia
                Player.arooBoostTime = 10000;
                Player.arooBoostStartTime = Date.now();

                // Reducir daño recibido
                const originalDamageReduction = Player.damageReduction || 0;
                Player.damageReduction = Math.min(0.9, originalDamageReduction + Player.arooResistance);

                setTimeout(() => {
                    Player.arooBoost = false;
                    Player.arooDamageMultiplier = 1.0;
                    Player.damageReduction = originalDamageReduction;
                    console.log('?? Grito AROO terminado');
                }, 10000);

                // Aura roja intensa alrededor del jugador
                Player.arooAura = {
                    radius: 100,
                    color: '#8B0000',
                    duration: 10000,
                    startTime: Date.now()
                };

                console.log(`?? ¡AROO! ${intimidatedCount} enemigos intimidados! +60% daño, +40% resistencia!`);
            },

            bendicionAres() {
                // Bendición de Ares - El dios de la guerra bendice al guerrero
                console.log('?? BENDICIÓN DE ARES! ¡El dios de la guerra me bendice!');

                // Invulnerabilidad a control de masas
                Player.ccImmune = true;
                Player.aresBlessing = true;
                Player.aresBlessingStartTime = Date.now();
                Player.aresBlessingDuration = 8000;

                // Doble daño
                Player.aresDamageMultiplier = 2.0;

                // Curación por daño (20% lifesteal)
                Player.aresLifesteal = 0.20;

                // Invulnerabilidad total por 1 segundo al activar
                Player.invulnerable = true;
                Player.invulnerableTime = 1000;

                // Crear símbolo de Ares (espadas cruzadas) sobre el jugador
                Player.aresSymbol = {
                    active: true,
                    rotation: 0
                };

                // Partículas de fuego rojo alrededor
                for (let i = 0; i < 40; i++) {
                    setTimeout(() => {
                        const angle = Math.random() * Math.PI * 2;
                        const distance = Math.random() * 150;
                        const particleX = Player.x + Math.cos(angle) * distance;
                        const particleY = Player.y + Math.sin(angle) * distance;

                        this.projectiles.push({
                            x: particleX,
                            y: particleY,
                            vx: (Math.random() - 0.5) * 120,
                            vy: -150 - Math.random() * 100,
                            size: 8 + Math.random() * 8,
                            damage: 0,
                            color: Math.random() > 0.5 ? '#8B0000' : '#CD7F32',
                            life: 1500,
                            isPlayerProjectile: false,
                            isParticle: true
                        });
                    }, i * 40);
                }

                // Terminar después de 8 segundos
                setTimeout(() => {
                    Player.ccImmune = false;
                    Player.aresBlessing = false;
                    Player.aresDamageMultiplier = 1.0;
                    Player.aresLifesteal = 0;
                    Player.aresSymbol = null;
                    console.log('?? Bendición de Ares terminada');
                }, 8000);

                console.log('?? Bendición de Ares! x2 daño, 20% lifesteal, inmune a CC!');
            },

            lasTermopilas() {
                // Las Termópilas - Ultimate: Los 300 espartanos (18 hoplitas optimizados)
                console.log('?? LAS TERMÓPILAS! íEsta noche cenamos en el Hades!');

                const allMobs = [...this.mobs, ...this.bosses];

                // Oscurecer el campo de batalla
                Player.thermopylaeActive = true;
                Player.thermopylaeStartTime = Date.now();
                Player.thermopylaeDuration = 5000;

                // Invulnerabilidad total
                Player.invulnerable = true;
                Player.invulnerableTime = 5000;

                // Crear 18 hoplitas espartanos en formación de falange
                const hoplites = [];
                const rows = 6; // 6 filas
                const hoplitesPerRow = 3; // 3 por fila = 18 total
                const spacing = 60;

                for (let row = 0; row < rows; row++) {
                    for (let col = 0; col < hoplitesPerRow; col++) {
                        const x = Player.x - (hoplitesPerRow * spacing / 2) + (col * spacing) + spacing / 2;
                        const y = Player.y + 150 + (row * spacing);

                        hoplites.push({
                            x: x,
                            y: y,
                            speed: 8 + Math.random() * 4
                        });
                    }
                }

                Player.thermopylaeHoplites = hoplites;

                // Aura dorada y roja
                Player.thermopylaeAura = {
                    radius: 110,
                    color: '#8B0000',
                    capeWave: 0
                };

                // Daño masivo cada 0.5 segundos
                let damageCount = 0;
                const damageInterval = setInterval(() => {
                    if (damageCount >= 10) {
                        clearInterval(damageInterval);
                        return;
                    }

                    // Daño escalado con nivel
                    const thermopylaeDamage = Math.floor(75 + Player.getCurrentDamage() * 1.8);

                    allMobs.forEach(mob => {
                        this.damageMob(mob.id, thermopylaeDamage);

                        // Aplicar Miedo Espartano
                        if (!mob.spartanFear) {
                            mob.spartanFear = true;
                            mob.originalSpeed = mob.speed;
                            mob.originalDamage = mob.damage;
                            mob.speed *= 0.3; // -70% velocidad
                            mob.damage *= 0.3; // -70% daño

                            setTimeout(() => {
                                if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                                    mob.speed = mob.originalSpeed;
                                    mob.damage = mob.originalDamage;
                                    mob.spartanFear = false;
                                }
                            }, 5000);
                        }
                    });

                    damageCount++;
                }, 500);

                // Partículas Épicas
                for (let i = 0; i < 60; i++) {
                    setTimeout(() => {
                        const angle = Math.random() * Math.PI * 2;
                        const distance = Math.random() * 250;
                        const particleX = Player.x + Math.cos(angle) * distance;
                        const particleY = Player.y + Math.sin(angle) * distance;

                        this.projectiles.push({
                            x: particleX,
                            y: particleY,
                            vx: (Math.random() - 0.5) * 100,
                            vy: -120 - Math.random() * 80,
                            size: 6 + Math.random() * 6,
                            damage: 0,
                            color: Math.random() > 0.5 ? '#8B0000' : '#CD7F32',
                            life: 1800,
                            isPlayerProjectile: false,
                            isParticle: true
                        });
                    }, i * 50);
                }

                // Terminar después de 5 segundos
                setTimeout(() => {
                    Player.thermopylaeActive = false;
                    Player.thermopylaeHoplites = null;
                    Player.thermopylaeAura = null;
                    console.log('?? Las Termópilas terminadas - ¡Gloria a Esparta!');
                }, 5000);

                console.log('?? LAS TERMÓPILAS! 18 hoplitas de Élite! Miedo Espartano aplicado!');
            },

            checkHeatSystem() {
                // Check heat levels and apply effects
                if (Player.heat >= 100 && !Player.overheated) {
                    // OVERHEAT - Explosion + Silence
                    Player.overheated = true;
                    Player.silenced = true;
                    Player.silencedTime = 2000;

                    // Area explosion
                    const allMobs = [...this.mobs, ...this.bosses];
                    let hitCount = 0;

                    allMobs.forEach(mob => {
                        const dx = mob.x - Player.x;
                        const dy = mob.y - Player.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);

                        if (dist < 200) {
                            this.damageMob(mob.id, 70);
                            hitCount++;

                            // Knockback
                            const angle = Math.atan2(dy, dx);
                            mob.x += Math.cos(angle) * 60;
                            mob.y += Math.sin(angle) * 60;
                        }
                    });

                    // Reset heat
                    Player.heat = 0;

                    // Remove silence after duration
                    setTimeout(() => {
                        Player.silenced = false;
                        Player.overheated = false;
                    }, 2000);

                    console.log(`?? OVERHEAT! Explosion hit ${hitCount} enemies! Silenced for 2s!`);
                }
            },

            // CYBER GUNSLINGER BASE ABILITIES
            orbitalStrike() {
                // Track ability usage for mastery missions
                LoadoutManager.trackAbilityUsage('gun_ultimate');

                // Orbital Strike - Ataque orbital que marca una zona y luego dispara
                const targetX = Player.x + (Math.random() - 0.5) * 250;
                const targetY = Player.y + (Math.random() - 0.5) * 250;

                const orbital = {
                    x: targetX,
                    y: targetY,
                    radius: 120,
                    warningTime: 2000,
                    startTime: Date.now(),
                    fired: false
                };

                if (!this.orbitalStrikes) this.orbitalStrikes = [];
                this.orbitalStrikes.push(orbital);

                console.log('?? Orbital Strike targeting... 2 seconds until impact!');

                // Fire after warning
                setTimeout(() => {
                    if (!orbital.fired) {
                        orbital.fired = true;

                        // Damage all enemies in area
                        const allMobs = [...this.mobs, ...this.bosses];
                        let hitCount = 0;

                        allMobs.forEach(mob => {
                            const dx = mob.x - orbital.x;
                            const dy = mob.y - orbital.y;
                            const dist = Math.sqrt(dx * dx + dy * dy);

                            if (dist < orbital.radius) {
                                this.damageMob(mob.id, 150); // High damage
                                hitCount++;

                                // Knockback
                                const angle = Math.atan2(dy, dx);
                                mob.x += Math.cos(angle) * 50;
                                mob.y += Math.sin(angle) * 50;
                            }
                        });

                        console.log(`?? Orbital Strike FIRED! ${hitCount} enemies hit!`);

                        // Remove orbital marker
                        setTimeout(() => {
                            this.orbitalStrikes = this.orbitalStrikes.filter(o => o !== orbital);
                        }, 1000);
                    }
                }, 2000);
            },

            toxicAirBubbles() {
                // Burbujas de Aire Tóxico - 5 burbujas que explotan al contacto
                const bubbleCount = 5;

                for (let i = 0; i < bubbleCount; i++) {
                    setTimeout(() => {
                        // Random position near or far from player
                        const distance = 100 + Math.random() * 250; // 100-350 pixels away
                        const angle = Math.random() * Math.PI * 2;

                        const bubbleX = Player.x + Math.cos(angle) * distance;
                        const bubbleY = Player.y + Math.sin(angle) * distance;

                        // Create bubble object
                        const bubble = {
                            x: bubbleX,
                            y: bubbleY,
                            size: 35,
                            color: '#00ff88',
                            lifetime: 8000, // 8 seconds before auto-explode
                            createdAt: Date.now(),
                            exploded: false
                        };

                        // Add to bubbles array (we'll create this if it doesn't exist)
                        if (!this.toxicBubbles) this.toxicBubbles = [];
                        this.toxicBubbles.push(bubble);

                        // Check for collision with enemies periodically
                        const checkInterval = setInterval(() => {
                            if (bubble.exploded || Date.now() - bubble.createdAt > bubble.lifetime) {
                                clearInterval(checkInterval);
                                // Remove bubble
                                if (this.toxicBubbles) {
                                    this.toxicBubbles = this.toxicBubbles.filter(b => b !== bubble);
                                }
                                return;
                            }

                            const allMobs = [...this.mobs, ...this.bosses];
                            allMobs.forEach(mob => {
                                const dx = mob.x - bubble.x;
                                const dy = mob.y - bubble.y;
                                const dist = Math.sqrt(dx * dx + dy * dy);

                                if (dist < bubble.size + mob.size && !bubble.exploded) {
                                    // Explode bubble!
                                    bubble.exploded = true;

                                    // Apply poison to enemy
                                    mob.poisoned = true;
                                    mob.poisonTime = 2000; // 2 seconds
                                    mob.poisonDamage = 10; // BUFFED v19.11.2025: 8 ? 10
                                    mob.poisonTickInterval = 400; // Damage every 0.4s

                                    // Reduce defense and speed
                                    if (!mob.originalDefense) mob.originalDefense = mob.damageReduction || 0;
                                    if (!mob.originalSpeed) mob.originalSpeed = mob.speed;

                                    mob.damageReduction = Math.max(0, (mob.damageReduction || 0) - 15); // -15% defense
                                    mob.speed *= 0.4; // 60% speed reduction

                                    // Restore after poison ends
                                    setTimeout(() => {
                                        if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                                            mob.poisoned = false;
                                            if (mob.originalDefense !== undefined) {
                                                mob.damageReduction = mob.originalDefense;
                                            }
                                            if (mob.originalSpeed !== undefined) {
                                                mob.speed = mob.originalSpeed;
                                            }
                                        }
                                    }, mob.poisonTime);

                                    console.log(`?? Burbuja explotí! ${mob.name} envenenado!`);
                                    clearInterval(checkInterval);
                                }
                            });
                        }, 50);
                    }, i * 200); // Stagger bubble creation
                }

                console.log('?? Burbujas de Aire Tóxico - 5 burbujas desplegadas!');
            },

            strongWindAttraction() {
                // Atracción del Viento Fuerte - Ultimate ability
                const allMobs = [...this.mobs, ...this.bosses];
                const pullRadius = 350; // Medium radius
                let affectedMobs = [];

                // Find all enemies in radius
                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < pullRadius) {
                        affectedMobs.push(mob);
                        // Store original position for pull effect
                        mob.pullStartX = mob.x;
                        mob.pullStartY = mob.y;
                        mob.beingPulled = true;
                    }
                });

                if (affectedMobs.length === 0) {
                    console.log('?? No hay enemigos cerca para atraer!');
                    return;
                }

                // Player gets invulnerability for 6 seconds
                Player.invulnerable = true;
                Player.invulnerableTime = 6000;

                // Pull enemies towards player for 3 seconds
                const pullDuration = 3000;
                const pullStartTime = Date.now();

                const pullInterval = setInterval(() => {
                    const elapsed = Date.now() - pullStartTime;

                    if (elapsed >= pullDuration) {
                        clearInterval(pullInterval);

                        // After 3 seconds, throw enemies in random directions
                        affectedMobs.forEach(mob => {
                            if (!this.mobs.includes(mob) && !this.bosses.includes(mob)) return;

                            mob.beingPulled = false;

                            // Random direction and high speed
                            const throwAngle = Math.random() * Math.PI * 2;
                            const throwSpeed = 400 + Math.random() * 200; // 400-600 speed

                            // Apply velocity
                            mob.throwVelocityX = Math.cos(throwAngle) * throwSpeed;
                            mob.throwVelocityY = Math.sin(throwAngle) * throwSpeed;
                            mob.beingThrown = true;

                            // Damage from impact
                            this.damageMob(mob.id, 40);

                            // 65% chance to confuse
                            if (Math.random() < 0.65) {
                                mob.confused = true;
                                mob.confusedTime = 4000; // 4 seconds confusion
                            }

                            // Stop throw after 1 second
                            setTimeout(() => {
                                if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                                    mob.beingThrown = false;
                                    mob.throwVelocityX = 0;
                                    mob.throwVelocityY = 0;
                                }
                            }, 1000);
                        });

                        console.log(`?? Enemigos lanzados en direcciones aleatorias! ${affectedMobs.filter(m => m.confused).length} confundidos!`);
                    } else {
                        // Pull enemies towards player
                        affectedMobs.forEach(mob => {
                            if (!this.mobs.includes(mob) && !this.bosses.includes(mob)) return;

                            const dx = Player.x - mob.x;
                            const dy = Player.y - mob.y;
                            const dist = Math.sqrt(dx * dx + dy * dy);

                            if (dist > 50) { // Don't pull if too close
                                const pullSpeed = 8;
                                mob.x += (dx / dist) * pullSpeed;
                                mob.y += (dy / dist) * pullSpeed;
                            }
                        });
                    }
                }, 16); // ~60 FPS

                console.log(`?? Atracción del Viento Fuerte - ${affectedMobs.length} enemigos siendo atraídos!`);
            },

            // TORNADO OVERLORD ABILITIES (MASTER CLASS)
            windSingularity() {
                // Singularidad Eólica - Crea agujero negro de viento estático
                const singularity = {
                    x: Player.x,
                    y: Player.y,
                    radius: 150, // Large radius
                    pullStrength: 12,
                    duration: 5000,
                    startTime: Date.now()
                };

                if (!this.windSingularities) this.windSingularities = [];
                this.windSingularities.push(singularity);

                // Pull and stun enemies
                const pullInterval = setInterval(() => {
                    if (Date.now() - singularity.startTime > singularity.duration) {
                        clearInterval(pullInterval);
                        this.windSingularities = this.windSingularities.filter(s => s !== singularity);
                        return;
                    }

                    const allMobs = [...this.mobs, ...this.bosses];
                    allMobs.forEach(mob => {
                        const dx = singularity.x - mob.x;
                        const dy = singularity.y - mob.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);

                        if (dist < singularity.radius) {
                            // Pull toward center
                            if (dist > 20) {
                                mob.x += (dx / dist) * singularity.pullStrength;
                                mob.y += (dy / dist) * singularity.pullStrength;
                            }

                            // Stun enemies near center
                            if (dist < 50 && !mob.stunned) {
                                mob.stunned = true;
                                mob.originalSpeed = mob.speed;
                                mob.speed = 0;

                                setTimeout(() => {
                                    if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                                        mob.stunned = false;
                                        mob.speed = mob.originalSpeed;
                                    }
                                }, 3000);
                            }
                        }
                    });
                }, 50);

                console.log('? Wind Singularity created! Pulling and stunning enemies!');
            },

            atmosphericPressure() {
                // Presión Atmosférica - Aplasta enemigos, inmoviliza y rompe armadura
                const allMobs = [...this.mobs, ...this.bosses];
                let affectedCount = 0;

                allMobs.forEach(mob => {
                    const dx = mob.x - Player.x;
                    const dy = mob.y - Player.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < 250) { // Area around player
                        // Immediate damage
                        this.damageMob(mob.id, 40);

                        // Root (immobilize) for 2s
                        mob.rooted = true;
                        mob.originalSpeed = mob.speed;
                        mob.speed = 0;

                        setTimeout(() => {
                            if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                                mob.rooted = false;
                                mob.speed = mob.originalSpeed;
                            }
                        }, 2000);

                        // Break armor for 4s
                        mob.armorBroken = true;
                        mob.originalDamageReduction = mob.damageReduction || 0;
                        mob.damageReduction = 0;
                        mob.damageAmplification = 1.2; // +20% damage taken

                        setTimeout(() => {
                            if (this.mobs.includes(mob) || this.bosses.includes(mob)) {
                                mob.armorBroken = false;
                                mob.damageReduction = mob.originalDamageReduction;
                                mob.damageAmplification = 1.0;
                            }
                        }, 4000);

                        affectedCount++;
                    }
                });

                console.log(`?? Atmospheric Pressure - ${affectedCount} enemies crushed! Rooted 2s + Armor broken 4s!`);
            },

            tornadoBarrage() {
                // Ráfaga de Tornados - Lanza 5 tornados en diferentes direcciones
                const allMobs = [...this.mobs, ...this.bosses];
                if (allMobs.length === 0) {
                    console.log('??? No enemies for Tornado Barrage!');
                    return;
                }

                // Launch 5 tornados in spread pattern
                for (let i = 0; i < 5; i++) {
                    const angle = (Math.PI * 2 / 5) * i;

                    this.projectiles.push({
                        x: Player.x,
                        y: Player.y,
                        vx: Math.cos(angle) * 350,
                        vy: Math.sin(angle) * 350,
                        size: 20,
                        damage: 45,
                        color: '#39ff14',
                        life: 4000,
                        isPiercing: true,
                        piercedEnemies: [],
                        isPlayerProjectile: true,
                        onHit: (mob) => {
                            // Apply confusion
                            mob.confused = true;
                            mob.confusedTime = 4000;
                            mob.confusedIntensity = 0.5;
                            return 45;
                        }
                    });
                }

                console.log('??? Tornado Barrage - 5 tornados launched!');
            },

            stormShield() {
                // Escudo de Tormenta - Shield that reflects projectiles and gives damage reduction
                Player.invulnerable = true;
                Player.invulnerableTime = 4000; // 4 seconds

                // Damage reduction buff
                if (!Player.damageReduction) Player.damageReduction = 0;
                Player.damageReduction = 30; // 30% damage reduction

                setTimeout(() => {
                    Player.damageReduction = 0;
                }, 6000); // 6 seconds total

                // Create visual shield effect
                const shieldEffect = {
                    x: Player.x,
                    y: Player.y,
                    radius: 80,
                    duration: 4000,
                    startTime: Date.now()
                };

                if (!this.stormShields) this.stormShields = [];
                this.stormShields.push(shieldEffect);

                console.log('??? Storm Shield activated! 4s invulnerability + 30% damage reduction for 6s!');
            },

            apocalypticStorm() {
                // Tormenta Apocalíptica - Ultimate: Massive storm that devastates everything
                const allMobs = [...this.mobs, ...this.bosses];

                console.log('??? APOCALYPTIC STORM UNLEASHED!');

                // Phase 1: Pull all enemies (2s)
                const pullDuration = 2000;
                const pullStartTime = Date.now();

                const pullInterval = setInterval(() => {
                    if (Date.now() - pullStartTime >= pullDuration) {
                        clearInterval(pullInterval);
                        return;
                    }

                    allMobs.forEach(mob => {
                        if (!this.mobs.includes(mob) && !this.bosses.includes(mob)) return;

                        const dx = Player.x - mob.x;
                        const dy = Player.y - mob.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);

                        if (dist > 50) {
                            mob.x += (dx / dist) * 10;
                            mob.y += (dy / dist) * 10;
                        }
                    });
                }, 16);

                // Phase 2: Massive damage + confusion (2.5s)
                setTimeout(() => {
                    allMobs.forEach(mob => {
                        const dx = mob.x - Player.x;
                        const dy = mob.y - Player.y;
                        const dist = Math.sqrt(dx * dx + dy * dy);

                        if (dist < 400) {
                            // Massive damage
                            this.damageMob(mob.id, 120);

                            // Apply confusion
                            mob.confused = true;
                            mob.confusedTime = 10000; // 10 seconds
                            mob.confusedIntensity = 0.7;

                            // Apply radioactive
                            mob.radioactive = true;
                            mob.radioactiveTime = 8000;
                        }
                    });

                    console.log('??? Phase 2: Massive damage + confusion + radioactive!');
                }, 2500);

                // Phase 3: Launch 20 tornados in all directions (3s)
                setTimeout(() => {
                    for (let i = 0; i < 20; i++) {
                        const angle = (Math.PI * 2 / 20) * i;

                        this.projectiles.push({
                            x: Player.x,
                            y: Player.y,
                            vx: Math.cos(angle) * 400,
                            vy: Math.sin(angle) * 400,
                            size: 18,
                            damage: 60,
                            color: '#00ffaa',
                            life: 5000,
                            isPiercing: true,
                            piercedEnemies: [],
                            isPlayerProjectile: true
                        });
                    }

                    console.log('??? Phase 3: 20 tornados launched!');
                }, 3000);

                // Player invulnerability during entire ultimate
                Player.invulnerable = true;
                Player.invulnerableTime = 5000;

                // Massive damage boost
                Player.applyDamageBoost(50, 10000); // +50% damage for 10s
            },

            dropClassTicket(mob, isBoss) {
                // Check if mob drops specific class ticket
                if (!mob.dropsTicketFor) return;

                let dropChance = 0;

                // Bosses have higher drop rates
                if (isBoss) {
                    dropChance = 0.65; // 65% for bosses (increased from 35%)
                } else {
                    dropChance = 0.35; // 35% for regular mobs (increased from 15%)
                }

                // Apply custom raid penalty (reduced from 10% to 5%)
                if (this.isCustomRaid) {
                    dropChance -= 0.05; // Only 5% penalty now
                    dropChance = Math.max(0, dropChance); // Don't go below 0
                }

                if (Math.random() < dropChance) {
                    const classId = mob.dropsTicketFor;

                    // Initialize if doesn't exist
                    if (!EquipmentManager.classTickets[classId]) {
                        EquipmentManager.classTickets[classId] = 0;
                    }

                    EquipmentManager.classTickets[classId]++;

                    // Update total counter
                    const totalTickets = Object.values(EquipmentManager.classTickets).reduce((a, b) => a + b, 0);
                    document.getElementById('ticket-counter').textContent = totalTickets;

                    EquipmentManager.saveProgress();
                    this.showTicketDrop(mob.x, mob.y, classId);
                    console.log(`?? ${classId} Ticket dropped! Total:`, EquipmentManager.classTickets[classId]);
                }
            },

            showTicketDrop(x, y, classId) {
                const className = classId.replace('class_', '').charAt(0).toUpperCase() + classId.replace('class_', '').slice(1);

                // Add to canvas notifications for fullscreen
                this.canvasNotifications = this.canvasNotifications || [];
                this.canvasNotifications.push({
                    text: `?? +1 ${className} Ticket`,
                    x: x,
                    y: y,
                    startTime: Date.now(),
                    duration: 2000,
                    color: '#ffd700'
                });

                // Also show DOM popup for non-fullscreen
                const popup = document.createElement('div');
                popup.style.cssText = `
                    position: fixed;
                    left: ${x}px;
                    top: ${y}px;
                    color: #ffd700;
                    font-size: 24px;
                    font-weight: bold;
                    z-index: 9999;
                    pointer-events: none;
                    animation: floatUp 2s ease-out forwards;
                    text-shadow: 0 0 10px #ffd700, 0 0 20px #ffd700;
                `;
                popup.textContent = `?? +1 ${className} Ticket`;
                document.body.appendChild(popup);

                setTimeout(() => popup.remove(), 2000);

                // Check if any class can be unlocked now
                this.checkUnlockableClasses();
            },

            checkUnlockableClasses() {
                const classes = rolesData.classes.filter(c => c.ticketsRequired);
                const unlockable = [];

                classes.forEach(cls => {
                    if (!EquipmentManager.isClassUnlocked(cls.id)) {
                        const currentTickets = EquipmentManager.classTickets[cls.id] || 0;
                        if (currentTickets >= cls.ticketsRequired) {
                            unlockable.push(cls);
                        }
                    }
                });

                if (unlockable.length > 0) {
                    // Show notification
                    this.canvasNotifications = this.canvasNotifications || [];
                    unlockable.forEach(cls => {
                        this.canvasNotifications.push({
                            text: `? ${cls.name} Ready to Unlock!`,
                            x: 550, // Center of canvas
                            y: 100,
                            startTime: Date.now(),
                            duration: 4000,
                            color: '#00ff00',
                            isUnlockNotification: true
                        });
                    });
                }
            }
        };

        // ===== PRACTICE MODE / PLAYGROUND =====
        const PracticeModeManager = {
            active: false,
            savedGameState: null,
            settings: {
                infiniteResources: true,
                enhancedEffects: false,
                dummyImmortal: true,
                dummyHealth: 10000,
                dummyDefense: 0
            },
            controlPanel: {
                collapsed: false,
                x: 20,
                y: 20,
                width: 280,
                headerHeight: 50,
                contentHeight: 400
            },

            // Save current game state before entering practice mode
            saveGameState() {
                this.savedGameState = {
                    playerHp: Player.hp,
                    playerMaxHp: Player.maxHp,
                    playerLevel: Player.level,
                    playerExp: Player.exp,
                    playerX: Player.x,
                    playerY: Player.y,
                    equippedRole: EquipmentManager.equippedRole ? {
                        id: EquipmentManager.equippedRole.id,
                        type: EquipmentManager.equippedRole.type
                    } : null,
                    raidActive: MobRaidSystem.active
                };
                console.log('?? Game state saved for practice mode');
            },

            // Restore game state when exiting practice mode
            restoreGameState() {
                if (!this.savedGameState) return;

                Player.hp = this.savedGameState.playerHp;
                Player.maxHp = this.savedGameState.playerMaxHp;
                Player.level = this.savedGameState.playerLevel;
                Player.exp = this.savedGameState.playerExp;
                Player.x = this.savedGameState.playerX;
                Player.y = this.savedGameState.playerY;

                // Restore equipped role if it was different
                if (this.savedGameState.equippedRole) {
                    const allRoles = [...rolesData.characters, ...rolesData.classes, ...rolesData.masterClasses];
                    const role = allRoles.find(r => r.id === this.savedGameState.equippedRole.id);
                    if (role && EquipmentManager.equippedRole?.id !== role.id) {
                        EquipmentManager.equipRole(role);
                    }
                }

                console.log('?? Game state restored');
                this.savedGameState = null;
            },

            // Enter practice mode
            enterPracticeMode() {
                if (MobRaidSystem.active) {
                    console.log('?? Stopping active raid before entering practice mode');
                    MobRaidSystem.stopRaid(false);
                }

                // Ensure raid is not paused
                MobRaidSystem.paused = false;

                // Enter fullscreen
                const canvas = document.getElementById('game-canvas');
                if (canvas.requestFullscreen) {
                    canvas.requestFullscreen().catch(err => {
                        console.log('Fullscreen request failed:', err);
                    });
                } else if (canvas.webkitRequestFullscreen) {
                    canvas.webkitRequestFullscreen();
                } else if (canvas.msRequestFullscreen) {
                    canvas.msRequestFullscreen();
                }

                // Save current state
                this.saveGameState();

                // Activate practice mode
                this.active = true;

                console.log('?? Practice Mode: Movement should be enabled. MobRaidSystem.paused:', MobRaidSystem.paused);

                // Reset player to full health
                Player.hp = Player.maxHp;

                // Reset all cooldowns
                if (EquipmentManager.equippedRole) {
                    const role = EquipmentManager.equippedRole;
                    if (role.abilities) {
                        role.abilities.forEach(ability => ability.currentCooldown = 0);
                    }
                    if (role.semiUltimate) role.semiUltimate.currentCooldown = 0;
                    if (role.ultimateAbility) role.ultimateAbility.currentCooldown = 0;
                }

                // Initialize subsystems
                TrainingDummySystem.init();
                ComboTracker.init();

                // Show practice UI
                this.showPracticeUI();

                // Spawn initial dummy after a short delay to ensure Player is ready
                setTimeout(() => {
                    console.log('?? Attempting to spawn initial dummy. Player:', Player);
                    console.log('?? Player position:', Player.x, Player.y);

                    if (Player && Player.x !== undefined && Player.y !== undefined) {
                        const dummyX = Player.x + 200;
                        const dummyY = Player.y;
                        console.log('?? Spawning dummy at:', dummyX, dummyY);

                        TrainingDummySystem.spawnDummy(
                            dummyX,
                            dummyY,
                            {
                                hp: this.settings.dummyHealth,
                                defense: this.settings.dummyDefense,
                                immortal: this.settings.dummyImmortal
                            }
                        );
                        console.log('? Initial dummy spawned successfully');
                        console.log('?? Current dummies:', TrainingDummySystem.dummies);
                    } else {
                        console.error('? Player not ready for dummy spawn. Player:', Player);
                    }
                }, 200);

                console.log('?? Practice Mode activated!');
            },

            // Exit practice mode
            exitPracticeMode() {
                this.active = false;

                // Hide UI
                this.hidePracticeUI();

                // Clear subsystems
                TrainingDummySystem.clear();
                ComboTracker.reset();

                // Restore game state
                this.restoreGameState();

                console.log('?? Practice Mode deactivated');
            },

            // Toggle infinite resources
            toggleInfiniteResources() {
                this.settings.infiniteResources = !this.settings.infiniteResources;
                console.log(`?? Infinite Resources: ${this.settings.infiniteResources ? 'ON' : 'OFF'}`);
                this.savePracticeSettings();
            },

            // Toggle enhanced effects
            toggleEnhancedEffects() {
                this.settings.enhancedEffects = !this.settings.enhancedEffects;
                console.log(`? Enhanced Effects: ${this.settings.enhancedEffects ? 'ON' : 'OFF'}`);
                this.savePracticeSettings();
            },

            // Reset practice session
            resetPracticeSession() {
                // Reset player stats
                Player.hp = Player.maxHp;

                // Reset all cooldowns
                if (EquipmentManager.equippedRole) {
                    const role = EquipmentManager.equippedRole;
                    if (role.abilities) {
                        role.abilities.forEach(ability => ability.currentCooldown = 0);
                    }
                    if (role.semiUltimate) role.semiUltimate.currentCooldown = 0;
                    if (role.ultimateAbility) role.ultimateAbility.currentCooldown = 0;
                }

                // Reset dummies
                TrainingDummySystem.resetAllDummies();

                // Reset combo tracker
                ComboTracker.reset();

                // Show visual confirmation
                this.showResetConfirmation();

                console.log('?? Practice session reset');
            },

            showResetConfirmation() {
                const flash = document.createElement('div');
                flash.style.cssText = `
                    position: fixed;
                    inset: 0;
                    background: rgba(0, 255, 0, 0.3);
                    z-index: 9999;
                    pointer-events: none;
                    animation: fadeOut 0.3s ease-out forwards;
                `;
                document.body.appendChild(flash);
                setTimeout(() => flash.remove(), 300);
            },

            // Save practice settings to localStorage
            savePracticeSettings() {
                try {
                    localStorage.setItem('wildDestinyPracticeSettings', JSON.stringify(this.settings));
                } catch (e) {
                    console.error('Failed to save practice settings:', e);
                }
            },

            // Load practice settings from localStorage
            loadPracticeSettings() {
                try {
                    const saved = localStorage.getItem('wildDestinyPracticeSettings');
                    if (saved) {
                        this.settings = { ...this.settings, ...JSON.parse(saved) };
                        console.log('?? Practice settings loaded');
                    }
                } catch (e) {
                    console.error('Failed to load practice settings:', e);
                }
            },

            update(deltaTime) {
                if (!this.active) return;

                // Update subsystems
                TrainingDummySystem.update(deltaTime);
                ComboTracker.update(deltaTime);

                // Apply infinite resources
                if (this.settings.infiniteResources) {
                    // Keep player at full health (god mode)
                    if (Player.hp < Player.maxHp) {
                        Player.hp = Player.maxHp;
                    }

                    // Reset cooldowns
                    if (EquipmentManager.equippedRole) {
                        const role = EquipmentManager.equippedRole;
                        if (role.abilities) {
                            role.abilities.forEach(ability => {
                                if (ability.currentCooldown > 0) {
                                    ability.currentCooldown = 0;
                                }
                            });
                        }
                        if (role.semiUltimate && role.semiUltimate.currentCooldown > 0) {
                            role.semiUltimate.currentCooldown = 0;
                        }
                        if (role.ultimateAbility && role.ultimateAbility.currentCooldown > 0) {
                            role.ultimateAbility.currentCooldown = 0;
                        }
                    }
                }
            },

            render(ctx) {
                if (!this.active) return;

                // Render practice arena background
                this.renderArena(ctx);

                // Render subsystems
                TrainingDummySystem.render(ctx);
                ComboTracker.render(ctx);

                // Render practice mode indicator
                this.renderModeIndicator(ctx);

                // Render control panel
                this.renderControlPanel(ctx);

                // Render ability cooldowns (same as in raids)
                MobRaidSystem.renderAbilityCooldowns(ctx);
            },

            renderArena(ctx) {
                const canvas = ctx.canvas;

                // Draw grid lines
                ctx.save();
                ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)';
                ctx.lineWidth = 1;

                // Vertical lines
                for (let x = 0; x < canvas.width; x += 100) {
                    ctx.beginPath();
                    ctx.moveTo(x, 0);
                    ctx.lineTo(x, canvas.height);
                    ctx.stroke();
                }

                // Horizontal lines
                for (let y = 0; y < canvas.height; y += 100) {
                    ctx.beginPath();
                    ctx.moveTo(0, y);
                    ctx.lineTo(canvas.width, y);
                    ctx.stroke();
                }

                // Draw distance markers from player
                const distances = [200, 400, 600, 800]; // 5m, 10m, 15m, 20m intervals
                ctx.strokeStyle = 'rgba(0, 217, 255, 0.3)';
                ctx.lineWidth = 2;

                distances.forEach((dist, index) => {
                    ctx.beginPath();
                    ctx.arc(Player.x, Player.y, dist, 0, Math.PI * 2);
                    ctx.stroke();

                    // Distance label
                    ctx.fillStyle = 'rgba(0, 217, 255, 0.6)';
                    ctx.font = '12px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillText(`${(index + 1) * 5}m`, Player.x, Player.y - dist - 5);
                });

                ctx.restore();
            },

            renderModeIndicator(ctx) {
                // Removed - now part of control panel
            },

            renderControlPanel(ctx) {
                const panel = this.controlPanel;
                const canvas = ctx.canvas;

                ctx.save();

                // Panel background
                const totalHeight = panel.collapsed ? panel.headerHeight : panel.headerHeight + panel.contentHeight;
                ctx.fillStyle = 'rgba(138, 43, 226, 0.95)';
                ctx.strokeStyle = '#8a2be2';
                ctx.lineWidth = 3;
                ctx.shadowBlur = 20;
                ctx.shadowColor = 'rgba(138, 43, 226, 0.5)';
                ctx.beginPath();
                ctx.roundRect(panel.x, panel.y, panel.width, totalHeight, 15);
                ctx.fill();
                ctx.stroke();

                // Header
                ctx.fillStyle = 'rgba(0, 0, 0, 0.3)';
                ctx.beginPath();
                ctx.roundRect(panel.x, panel.y, panel.width, panel.headerHeight, [15, 15, 0, 0]);
                ctx.fill();

                // Title
                ctx.fillStyle = '#fff';
                ctx.font = 'bold 16px Orbitron';
                ctx.textAlign = 'left';
                ctx.fillText('?? CONTROLES', panel.x + 15, panel.y + 25);

                // Subtitle
                ctx.font = '10px Arial';
                ctx.fillStyle = 'rgba(255, 255, 255, 0.7)';
                ctx.fillText('Presiona P para colapsar', panel.x + 15, panel.y + 40);

                // Collapse indicator
                ctx.font = '20px Arial';
                ctx.fillStyle = '#00d9ff';
                ctx.textAlign = 'right';
                ctx.fillText(panel.collapsed ? '?' : '?', panel.x + panel.width - 15, panel.y + 30);

                // Content (if not collapsed)
                if (!panel.collapsed) {
                    let yPos = panel.y + panel.headerHeight + 20;

                    // Settings section
                    ctx.fillStyle = 'rgba(0, 0, 0, 0.3)';
                    ctx.beginPath();
                    ctx.roundRect(panel.x + 15, yPos, panel.width - 30, 80, 10);
                    ctx.fill();

                    ctx.fillStyle = '#00d9ff';
                    ctx.font = 'bold 11px Arial';
                    ctx.textAlign = 'left';
                    ctx.fillText('?? CONFIGURACIÓN', panel.x + 25, yPos + 18);

                    // Infinite Resources toggle
                    yPos += 35;
                    ctx.fillStyle = '#fff';
                    ctx.font = '12px Arial';
                    ctx.fillText('Recursos Infinitos', panel.x + 25, yPos);
                    this.renderToggle(ctx, panel.x + panel.width - 70, yPos - 12, this.settings.infiniteResources);

                    // Enhanced Effects toggle
                    yPos += 25;
                    ctx.fillText('Efectos Mejorados', panel.x + 25, yPos);
                    this.renderToggle(ctx, panel.x + panel.width - 70, yPos - 12, this.settings.enhancedEffects);

                    // Dummy section
                    yPos += 40;
                    ctx.fillStyle = 'rgba(0, 0, 0, 0.3)';
                    ctx.beginPath();
                    ctx.roundRect(panel.x + 15, yPos, panel.width - 30, 140, 10);
                    ctx.fill();

                    ctx.fillStyle = '#00d9ff';
                    ctx.font = 'bold 11px Arial';
                    ctx.fillText('?? TRAINING DUMMY', panel.x + 25, yPos + 18);

                    // Dummy HP
                    yPos += 35;
                    ctx.fillStyle = '#fff';
                    ctx.font = '11px Arial';
                    ctx.fillText('HP:', panel.x + 25, yPos);
                    ctx.fillStyle = '#ffbe0b';
                    ctx.font = 'bold 12px Arial';
                    ctx.textAlign = 'right';
                    ctx.fillText(this.settings.dummyHealth.toLocaleString(), panel.x + panel.width - 25, yPos);

                    // Dummy Defense
                    yPos += 20;
                    ctx.fillStyle = '#fff';
                    ctx.font = '11px Arial';
                    ctx.textAlign = 'left';
                    ctx.fillText('Defensa:', panel.x + 25, yPos);
                    ctx.fillStyle = '#ffbe0b';
                    ctx.font = 'bold 12px Arial';
                    ctx.textAlign = 'right';
                    ctx.fillText(this.settings.dummyDefense.toString(), panel.x + panel.width - 25, yPos);

                    // Immortal toggle
                    yPos += 25;
                    ctx.fillStyle = '#fff';
                    ctx.font = '12px Arial';
                    ctx.textAlign = 'left';
                    ctx.fillText('Inmortal', panel.x + 25, yPos);
                    this.renderToggle(ctx, panel.x + panel.width - 70, yPos - 12, this.settings.dummyImmortal);

                    // Add Dummy button
                    yPos += 30;
                    this.renderButton(ctx, panel.x + 15, yPos, panel.width - 30, 35, '? Agregar Dummy', '#00d9ff');

                    // Action buttons
                    yPos += 45;
                    this.renderButton(ctx, panel.x + 15, yPos, panel.width - 30, 30, '?? Reset', '#ffbe0b');

                    yPos += 38;
                    this.renderButton(ctx, panel.x + 15, yPos, panel.width - 30, 30, '? Salir', '#ff006e');
                }

                ctx.restore();
            },

            renderToggle(ctx, x, y, isOn) {
                // Toggle background
                ctx.fillStyle = isOn ? '#00d9ff' : '#666';
                ctx.beginPath();
                ctx.roundRect(x, y, 45, 22, 11);
                ctx.fill();

                // Toggle circle
                ctx.fillStyle = '#fff';
                ctx.beginPath();
                ctx.arc(x + (isOn ? 33 : 12), y + 11, 8, 0, Math.PI * 2);
                ctx.fill();
            },

            renderButton(ctx, x, y, width, height, text, color) {
                // Button background
                ctx.fillStyle = color;
                ctx.shadowBlur = 10;
                ctx.shadowColor = color;
                ctx.beginPath();
                ctx.roundRect(x, y, width, height, 8);
                ctx.fill();

                // Button text
                ctx.shadowBlur = 0;
                ctx.fillStyle = '#fff';
                ctx.font = 'bold 12px Arial';
                ctx.textAlign = 'center';
                ctx.fillText(text, x + width / 2, y + height / 2 + 4);
            },

            handleCanvasClick(x, y) {
                const panel = this.controlPanel;

                // Check if click is within panel bounds
                if (x < panel.x || x > panel.x + panel.width) return;
                if (y < panel.y) return;

                const totalHeight = panel.collapsed ? panel.headerHeight : panel.headerHeight + panel.contentHeight;
                if (y > panel.y + totalHeight) return;

                // Header click - toggle collapse
                if (y < panel.y + panel.headerHeight) {
                    panel.collapsed = !panel.collapsed;
                    return;
                }

                if (panel.collapsed) return;

                // Calculate relative Y position
                let relY = y - (panel.y + panel.headerHeight + 20);

                // Infinite Resources toggle (around y: 35)
                if (relY >= 15 && relY <= 50 && x > panel.x + panel.width - 70) {
                    this.settings.infiniteResources = !this.settings.infiniteResources;
                    this.savePracticeSettings();
                    return;
                }

                // Enhanced Effects toggle (around y: 60)
                if (relY >= 40 && relY <= 75 && x > panel.x + panel.width - 70) {
                    this.settings.enhancedEffects = !this.settings.enhancedEffects;
                    this.savePracticeSettings();
                    return;
                }

                // Immortal toggle (around y: 195)
                if (relY >= 180 && relY <= 215 && x > panel.x + panel.width - 70) {
                    this.settings.dummyImmortal = !this.settings.dummyImmortal;
                    this.savePracticeSettings();
                    return;
                }

                // Add Dummy button (around y: 225)
                if (relY >= 220 && relY <= 260) {
                    TrainingDummySystem.spawnDummy(
                        Player.x + (Math.random() - 0.5) * 400,
                        Player.y + (Math.random() - 0.5) * 400,
                        {
                            hp: this.settings.dummyHealth,
                            defense: this.settings.dummyDefense,
                            immortal: this.settings.dummyImmortal
                        }
                    );
                    return;
                }

                // Reset button (around y: 270)
                if (relY >= 265 && relY <= 300) {
                    this.resetPracticeSession();
                    return;
                }

                // Exit button (around y: 310)
                if (relY >= 303 && relY <= 338) {
                    this.exitPracticeMode();
                    return;
                }
            },

            showPracticeUI() {
                // UI is now rendered directly on canvas - no HTML elements needed
                console.log('?? Practice UI initialized (canvas-based)');
                return;

                /* OLD HTML-BASED UI - DISABLED
                const ui = document.createElement('div');
                ui.id = 'practice-mode-ui';
                ui.style.cssText = `
                    position: fixed;
                    top: 20px;
                    left: 20px;
                    background: linear-gradient(135deg, rgba(138, 43, 226, 0.95), rgba(75, 0, 130, 0.95));
                    backdrop-filter: blur(15px);
                    border: 3px solid #8a2be2;
                    border-radius: 15px;
                    z-index: 99999;
                    box-shadow: 0 10px 40px rgba(138, 43, 226, 0.5);
                    min-width: 280px;
                    max-width: 320px;
                    pointer-events: auto;
                `;
                
                ui.innerHTML = `
                    <div id="practice-header" style="padding: 15px 20px; cursor: pointer; display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid rgba(255, 255, 255, 0.1);">
                        <div>
                            <h3 style="color: #fff; font-size: 18px; font-weight: 900; margin: 0; font-family: 'Orbitron', sans-serif;">?? CONTROLES</h3>
                            <p style="color: rgba(255, 255, 255, 0.7); font-size: 10px; margin: 2px 0 0 0;">Click para expandir/colapsar</p>
                        </div>
                        <div id="practice-toggle-icon" style="color: #00d9ff; font-size: 24px; transition: transform 0.3s;">?</div>
                    </div>
                    
                    <div id="practice-content" style="max-height: 70vh; overflow-y: auto; padding: 20px;">
                    
                    <div style="background: rgba(0, 0, 0, 0.3); border-radius: 10px; padding: 12px; margin-bottom: 12px;">
                        <div style="color: #00d9ff; font-size: 12px; font-weight: 700; margin-bottom: 10px; text-transform: uppercase; letter-spacing: 1px;">?? Configuraciín</div>
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <span style="color: #fff; font-size: 13px; font-weight: 600;">Recursos Infinitos</span>
                            <label style="position: relative; display: inline-block; width: 50px; height: 24px;">
                                <input type="checkbox" id="practice-infinite-resources" checked style="opacity: 0; width: 0; height: 0;">
                                <span style="position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #00d9ff; transition: .4s; border-radius: 24px;"></span>
                            </label>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center;">
                            <span style="color: #fff; font-size: 13px; font-weight: 600;">Efectos Mejorados</span>
                            <label style="position: relative; display: inline-block; width: 50px; height: 24px;">
                                <input type="checkbox" id="practice-enhanced-effects" style="opacity: 0; width: 0; height: 0;">
                                <span style="position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; border-radius: 24px;"></span>
                            </label>
                        </div>
                    </div>
                    
                    <div style="background: rgba(0, 0, 0, 0.3); border-radius: 10px; padding: 12px; margin-bottom: 12px;">
                        <div style="color: #00d9ff; font-size: 12px; font-weight: 700; margin-bottom: 10px; text-transform: uppercase; letter-spacing: 1px;">?? Training Dummy</div>
                        <div style="margin-bottom: 8px;">
                            <label style="color: #fff; font-size: 12px; display: block; margin-bottom: 4px;">HP:</label>
                            <input type="number" id="practice-dummy-hp" value="10000" min="1000" max="1000000" step="1000" style="width: 100%; padding: 8px; background: rgba(0, 0, 0, 0.5); border: 2px solid rgba(0, 217, 255, 0.3); border-radius: 6px; color: #fff; font-size: 13px;">
                        </div>
                        <div style="margin-bottom: 8px;">
                            <label style="color: #fff; font-size: 12px; display: block; margin-bottom: 4px;">Defensa:</label>
                            <input type="number" id="practice-dummy-defense" value="0" min="0" max="1000" step="10" style="width: 100%; padding: 8px; background: rgba(0, 0, 0, 0.5); border: 2px solid rgba(0, 217, 255, 0.3); border-radius: 6px; color: #fff; font-size: 13px;">
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
                            <span style="color: #fff; font-size: 13px; font-weight: 600;">Inmortal</span>
                            <label style="position: relative; display: inline-block; width: 50px; height: 24px;">
                                <input type="checkbox" id="practice-dummy-immortal" checked style="opacity: 0; width: 0; height: 0;">
                                <span style="position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #00d9ff; transition: .4s; border-radius: 24px;"></span>
                            </label>
                        </div>
                        <button id="practice-spawn-dummy" style="width: 100%; padding: 12px; background: linear-gradient(135deg, #00d9ff, #0099cc); border: none; border-radius: 8px; color: #fff; font-weight: 700; cursor: pointer; font-size: 13px; transition: all 0.3s;">
                            ? Agregar Dummy
                        </button>
                    </div>
                    
                    <div style="margin-bottom: 12px;">
                        <button id="practice-reset" style="width: 100%; padding: 12px; background: linear-gradient(135deg, #ffbe0b, #ff8c00); border: none; border-radius: 8px; color: #fff; font-weight: 700; cursor: pointer; margin-bottom: 8px; font-size: 13px; transition: all 0.3s;">
                            ?? Reset
                        </button>
                        <button id="practice-exit" style="width: 100%; padding: 12px; background: linear-gradient(135deg, #ff006e, #cc0055); border: none; border-radius: 8px; color: #fff; font-weight: 700; cursor: pointer; font-size: 13px; transition: all 0.3s;">
                            ? Salir
                        </button>
                    </div>
                </div>
                `;
                
                document.body.appendChild(ui);
                
                // Toggle collapse functionality
                let isCollapsed = false;
                const header = document.getElementById('practice-header');
                const content = document.getElementById('practice-content');
                const toggleIcon = document.getElementById('practice-toggle-icon');
                
                header.addEventListener('click', () => {
                    isCollapsed = !isCollapsed;
                    if (isCollapsed) {
                        content.style.display = 'none';
                        toggleIcon.style.transform = 'rotate(-90deg)';
                        toggleIcon.textContent = '?';
                    } else {
                        content.style.display = 'block';
                        toggleIcon.style.transform = 'rotate(0deg)';
                        toggleIcon.textContent = '?';
                    }
                });
                
                // Event listeners
                document.getElementById('practice-infinite-resources').addEventListener('change', (e) => {
                    this.toggleInfiniteResources();
                    e.target.nextElementSibling.style.backgroundColor = this.settings.infiniteResources ? '#00d9ff' : '#ccc';
                });
                
                document.getElementById('practice-enhanced-effects').addEventListener('change', (e) => {
                    this.toggleEnhancedEffects();
                    e.target.nextElementSibling.style.backgroundColor = this.settings.enhancedEffects ? '#00d9ff' : '#ccc';
                });
                
                document.getElementById('practice-dummy-hp').addEventListener('change', (e) => {
                    this.settings.dummyHealth = parseInt(e.target.value);
                    this.savePracticeSettings();
                });
                
                document.getElementById('practice-dummy-defense').addEventListener('change', (e) => {
                    this.settings.dummyDefense = parseInt(e.target.value);
                    this.savePracticeSettings();
                });
                
                document.getElementById('practice-dummy-immortal').addEventListener('change', (e) => {
                    this.settings.dummyImmortal = e.target.checked;
                    e.target.nextElementSibling.style.backgroundColor = e.target.checked ? '#00d9ff' : '#ccc';
                    this.savePracticeSettings();
                });
                
                document.getElementById('practice-spawn-dummy').addEventListener('click', () => {
                    TrainingDummySystem.spawnDummy(
                        Player.x + (Math.random() - 0.5) * 400,
                        Player.y + (Math.random() - 0.5) * 400,
                        {
                            hp: this.settings.dummyHealth,
                            defense: this.settings.dummyDefense,
                            immortal: this.settings.dummyImmortal
                        }
                    );
                });
                
                document.getElementById('practice-reset').addEventListener('click', () => this.resetPracticeSession());
                document.getElementById('practice-exit').addEventListener('click', () => this.exitPracticeMode());
                
                // Hover effects
                const buttons = ui.querySelectorAll('button');
                buttons.forEach(btn => {
                    btn.addEventListener('mouseenter', () => {
                        btn.style.transform = 'translateY(-2px)';
                        btn.style.boxShadow = '0 5px 15px rgba(0, 0, 0, 0.3)';
                    });
                    btn.addEventListener('mouseleave', () => {
                        btn.style.transform = '';
                        btn.style.boxShadow = '';
                    });
                });
                END OF OLD HTML-BASED UI */
            },

            hidePracticeUI() {
                const ui = document.getElementById('practice-mode-ui');
                if (ui) ui.remove();
            },

            // Helper method to apply damage to dummies in practice mode
            applyDamageToDummies(x, y, range, damage) {
                if (!this.active) return 0;

                let hitCount = 0;
                TrainingDummySystem.dummies.forEach(dummy => {
                    const dx = dummy.x - x;
                    const dy = dummy.y - y;
                    const distance = Math.sqrt(dx * dx + dy * dy);

                    if (distance <= range + dummy.size) {
                        TrainingDummySystem.damageDummy(dummy.id, damage);
                        hitCount++;
                    }
                });

                return hitCount;
            }
        };

        // ===== TRAINING DUMMY SYSTEM =====
        const TrainingDummySystem = {
            dummies: [],
            maxDummies: 5,
            nextId: 1,

            init() {
                this.dummies = [];
                this.nextId = 1;
            },

            spawnDummy(x, y, config) {
                if (this.dummies.length >= this.maxDummies) {
                    console.log('?? Máximo de 5 dummies alcanzado');
                    // Show warning message
                    const warning = document.createElement('div');
                    warning.style.cssText = `
                        position: fixed;
                        top: 50%;
                        left: 50%;
                        transform: translate(-50%, -50%);
                        background: rgba(255, 0, 0, 0.9);
                        color: white;
                        padding: 20px 40px;
                        border-radius: 10px;
                        font-size: 18px;
                        font-weight: 700;
                        z-index: 9999;
                        animation: fadeOut 2s ease-out forwards;
                    `;
                    warning.textContent = '?? Máximo de 5 dummies alcanzado';
                    document.body.appendChild(warning);
                    setTimeout(() => warning.remove(), 2000);
                    return null;
                }

                const dummy = {
                    id: this.nextId++,
                    x: x,
                    y: y,
                    hp: config.hp || 10000,
                    maxHp: config.hp || 10000,
                    defense: config.defense || 0,
                    immortal: config.immortal !== undefined ? config.immortal : true,
                    damageReceived: 0,
                    lastHitTime: 0,
                    regenerating: false,
                    regenTimer: 0,
                    size: 40,
                    color: '#ff9900'
                };

                this.dummies.push(dummy);
                console.log(`?? Dummy #${dummy.id} spawned`);
                return dummy;
            },

            removeDummy(dummyId) {
                const index = this.dummies.findIndex(d => d.id === dummyId);
                if (index !== -1) {
                    this.dummies.splice(index, 1);
                    console.log(`??? Dummy #${dummyId} removed`);
                }
            },

            damageDummy(dummyId, damage) {
                const dummy = this.dummies.find(d => d.id === dummyId);
                if (!dummy) return;

                // Apply defense
                const actualDamage = Math.max(1, damage - dummy.defense);
                dummy.hp = Math.max(0, dummy.hp - actualDamage);
                dummy.damageReceived += actualDamage;
                dummy.lastHitTime = Date.now();

                // Register damage with combo tracker
                if (ComboTracker.active) {
                    ComboTracker.registerDamage(actualDamage);
                }

                // Check for death and regeneration
                if (dummy.hp <= 0 && dummy.immortal) {
                    dummy.regenerating = true;
                    dummy.regenTimer = 1000; // 1 second
                }

                console.log(`?? Dummy #${dummyId} took ${actualDamage} damage (HP: ${dummy.hp}/${dummy.maxHp})`);
            },

            updateDummyConfig(dummyId, config) {
                const dummy = this.dummies.find(d => d.id === dummyId);
                if (!dummy) return;

                if (config.hp !== undefined) {
                    dummy.maxHp = config.hp;
                    dummy.hp = Math.min(dummy.hp, dummy.maxHp);
                }
                if (config.defense !== undefined) dummy.defense = config.defense;
                if (config.immortal !== undefined) dummy.immortal = config.immortal;
            },

            resetAllDummies() {
                this.dummies.forEach(dummy => {
                    dummy.hp = dummy.maxHp;
                    dummy.damageReceived = 0;
                    dummy.regenerating = false;
                    dummy.regenTimer = 0;
                });
                console.log('?? All dummies reset');
            },

            clear() {
                this.dummies = [];
                this.nextId = 1;
            },

            update(deltaTime) {
                this.dummies.forEach(dummy => {
                    if (dummy.regenerating) {
                        dummy.regenTimer -= deltaTime;
                        if (dummy.regenTimer <= 0) {
                            dummy.hp = dummy.maxHp;
                            dummy.regenerating = false;
                            console.log(`?? Dummy #${dummy.id} regenerated`);
                        }
                    }
                });
            },

            render(ctx) {
                this.dummies.forEach(dummy => {
                    ctx.save();

                    // Regenerating effect
                    if (dummy.regenerating) {
                        const pulse = 1 + Math.sin(Date.now() * 0.01) * 0.3;
                        ctx.globalAlpha = 0.5 + pulse * 0.3;
                    }

                    // Dummy body
                    ctx.fillStyle = dummy.color;
                    ctx.shadowColor = dummy.color;
                    ctx.shadowBlur = 15;
                    ctx.beginPath();
                    ctx.arc(dummy.x, dummy.y, dummy.size, 0, Math.PI * 2);
                    ctx.fill();

                    // Border
                    ctx.strokeStyle = '#fff';
                    ctx.lineWidth = 3;
                    ctx.stroke();

                    // Icon
                    ctx.globalAlpha = 1;
                    ctx.fillStyle = '#fff';
                    ctx.font = '30px Arial';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText('??', dummy.x, dummy.y);

                    // HP bar
                    const barWidth = 100;
                    const barHeight = 10;
                    const hpPercent = dummy.hp / dummy.maxHp;

                    ctx.fillStyle = 'rgba(0, 0, 0, 0.7)';
                    ctx.fillRect(dummy.x - barWidth / 2, dummy.y - dummy.size - 20, barWidth, barHeight);

                    ctx.fillStyle = hpPercent > 0.5 ? '#00ff00' : hpPercent > 0.25 ? '#ffff00' : '#ff0000';
                    ctx.fillRect(dummy.x - barWidth / 2, dummy.y - dummy.size - 20, barWidth * hpPercent, barHeight);

                    // Stats text
                    ctx.fillStyle = '#fff';
                    ctx.font = 'bold 12px Arial';
                    ctx.shadowBlur = 3;
                    ctx.shadowColor = '#000';
                    ctx.fillText(`HP: ${Math.ceil(dummy.hp)}/${dummy.maxHp}`, dummy.x, dummy.y - dummy.size - 30);

                    ctx.font = '10px Arial';
                    ctx.fillText(`DEF: ${dummy.defense}`, dummy.x - 30, dummy.y - dummy.size - 42);
                    if (dummy.immortal) {
                        ctx.fillStyle = '#ffbe0b';
                        ctx.fillText('?? Inmortal', dummy.x + 30, dummy.y - dummy.size - 42);
                    }

                    // Regenerating indicator
                    if (dummy.regenerating) {
                        ctx.fillStyle = '#00ff00';
                        ctx.font = 'bold 14px Arial';
                        ctx.fillText('?? Regenerando...', dummy.x, dummy.y + dummy.size + 20);
                    }

                    ctx.restore();
                });
            }
        };

        // ===== COMBO TRACKER =====
        const ComboTracker = {
            active: false,
            currentCombo: 0,
            comboTimer: 0,
            comboTimeout: 3000,
            totalDamage: 0,
            comboStartTime: 0,
            abilitiesUsed: [],
            topCombos: [],

            init() {
                this.active = true;
                this.reset();
            },

            registerAbilityUse(abilityId, abilityName) {
                if (!this.active) return;

                // Start combo if first ability
                if (this.currentCombo === 0) {
                    this.comboStartTime = Date.now();
                }

                this.currentCombo++;
                this.comboTimer = this.comboTimeout;
                this.abilitiesUsed.push({
                    id: abilityId,
                    name: abilityName,
                    timestamp: Date.now()
                });

                console.log(`?? Combo: ${this.currentCombo} | ${abilityName}`);
            },

            registerDamage(damage) {
                if (!this.active || this.currentCombo === 0) return;
                this.totalDamage += damage;
            },

            getDPS() {
                if (this.currentCombo === 0) return 0;
                const duration = (Date.now() - this.comboStartTime) / 1000;
                return duration > 0 ? Math.round(this.totalDamage / duration) : 0;
            },

            endCombo() {
                if (this.currentCombo === 0) return;

                const comboData = {
                    comboCount: this.currentCombo,
                    totalDamage: this.totalDamage,
                    dps: this.getDPS(),
                    duration: (Date.now() - this.comboStartTime) / 1000,
                    abilitiesUsed: [...this.abilitiesUsed]
                };

                // Add to top combos if it qualifies
                this.topCombos.push(comboData);
                this.topCombos.sort((a, b) => b.comboCount - a.comboCount);
                if (this.topCombos.length > 5) {
                    this.topCombos = this.topCombos.slice(0, 5);
                }

                // Show summary
                this.showComboSummary(comboData);

                // Reset for next combo
                this.currentCombo = 0;
                this.totalDamage = 0;
                this.abilitiesUsed = [];
                this.comboTimer = 0;

                console.log(`? Combo ended: ${comboData.comboCount} hits, ${comboData.totalDamage} damage, ${comboData.dps} DPS`);
            },

            showComboSummary(comboData) {
                const summary = document.createElement('div');
                summary.style.cssText = `
                    position: fixed;
                    top: 50%;
                    left: 50%;
                    transform: translate(-50%, -50%);
                    background: linear-gradient(135deg, rgba(0, 217, 255, 0.95), rgba(255, 0, 110, 0.95));
                    border: 3px solid #00d9ff;
                    border-radius: 15px;
                    padding: 30px;
                    z-index: 9999;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.8);
                    min-width: 400px;
                    animation: scaleIn 0.3s ease-out;
                `;

                const abilityCount = {};
                comboData.abilitiesUsed.forEach(a => {
                    abilityCount[a.name] = (abilityCount[a.name] || 0) + 1;
                });

                const abilityList = Object.entries(abilityCount)
                    .map(([name, count]) => `<div style="color: rgba(255, 255, 255, 0.9); font-size: 13px;">í ${name} (x${count})</div>`)
                    .join('');

                summary.innerHTML = `
                    <div style="text-align: center; margin-bottom: 20px;">
                        <h2 style="color: #fff; font-size: 28px; font-weight: 900; margin-bottom: 5px; font-family: 'Orbitron', sans-serif;">?? COMBO FINALIZADO</h2>
                    </div>
                    <div style="background: rgba(0, 0, 0, 0.3); border-radius: 10px; padding: 20px; margin-bottom: 15px;">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px; margin-bottom: 15px;">
                            <div style="text-align: center;">
                                <div style="color: #ffbe0b; font-size: 36px; font-weight: 900; font-family: 'Orbitron', sans-serif;">${comboData.comboCount}</div>
                                <div style="color: rgba(255, 255, 255, 0.8); font-size: 12px;">COMBO</div>
                            </div>
                            <div style="text-align: center;">
                                <div style="color: #ff006e; font-size: 36px; font-weight: 900; font-family: 'Orbitron', sans-serif;">${comboData.totalDamage}</div>
                                <div style="color: rgba(255, 255, 255, 0.8); font-size: 12px;">DAíO TOTAL</div>
                            </div>
                        </div>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                            <div style="text-align: center;">
                                <div style="color: #00d9ff; font-size: 28px; font-weight: 900; font-family: 'Orbitron', sans-serif;">${comboData.dps}</div>
                                <div style="color: rgba(255, 255, 255, 0.8); font-size: 12px;">DPS</div>
                            </div>
                            <div style="text-align: center;">
                                <div style="color: #00ff88; font-size: 28px; font-weight: 900; font-family: 'Orbitron', sans-serif;">${comboData.duration.toFixed(1)}s</div>
                                <div style="color: rgba(255, 255, 255, 0.8); font-size: 12px;">DURACIíN</div>
                            </div>
                        </div>
                    </div>
                    <div style="background: rgba(0, 0, 0, 0.3); border-radius: 10px; padding: 15px; margin-bottom: 15px; max-height: 150px; overflow-y: auto;">
                        <div style="color: #00d9ff; font-size: 12px; font-weight: 700; margin-bottom: 10px;">HABILIDADES USADAS:</div>
                        ${abilityList}
                    </div>
                    <button onclick="this.parentElement.remove()" style="width: 100%; padding: 12px; background: linear-gradient(135deg, #00d9ff, #0099cc); border: none; border-radius: 8px; color: #fff; font-weight: 700; cursor: pointer; font-size: 14px;">
                        Continuar
                    </button>
                `;

                document.body.appendChild(summary);

                // Auto-remove after 10 seconds
                setTimeout(() => {
                    if (summary.parentElement) summary.remove();
                }, 10000);
            },

            reset() {
                this.currentCombo = 0;
                this.comboTimer = 0;
                this.totalDamage = 0;
                this.abilitiesUsed = [];
                this.comboStartTime = 0;
            },

            update(deltaTime) {
                if (!this.active) return;

                if (this.currentCombo > 0) {
                    this.comboTimer -= deltaTime;
                    if (this.comboTimer <= 0) {
                        this.endCombo();
                    }
                }
            },

            render(ctx) {
                if (!this.active || this.currentCombo === 0) return;

                const canvas = ctx.canvas;
                ctx.save();

                // Combo display (top-right corner)
                const x = canvas.width - 200;
                const y = 100;

                // Background
                ctx.fillStyle = 'rgba(0, 0, 0, 0.8)';
                ctx.strokeStyle = '#00d9ff';
                ctx.lineWidth = 3;
                ctx.beginPath();
                ctx.roundRect(x, y, 180, 120, 10);
                ctx.fill();
                ctx.stroke();

                // Combo count
                ctx.fillStyle = '#ffbe0b';
                ctx.font = 'bold 48px Orbitron';
                ctx.textAlign = 'center';
                ctx.shadowBlur = 15;
                ctx.shadowColor = '#ffbe0b';
                ctx.fillText(this.currentCombo, x + 90, y + 50);

                ctx.font = 'bold 14px Arial';
                ctx.fillStyle = '#fff';
                ctx.shadowBlur = 5;
                ctx.fillText('COMBO', x + 90, y + 70);

                // Damage
                ctx.font = 'bold 16px Arial';
                ctx.fillStyle = '#ff006e';
                ctx.shadowColor = '#ff006e';
                ctx.fillText(`?? ${this.totalDamage}`, x + 90, y + 90);

                // DPS
                ctx.font = 'bold 14px Arial';
                ctx.fillStyle = '#00d9ff';
                ctx.shadowColor = '#00d9ff';
                ctx.fillText(`? ${this.getDPS()} DPS`, x + 90, y + 110);

                ctx.restore();
            }
        };

        // ===== MOBILE CONTROLS SYSTEM =====
        const MobileControlsSystem = {
            enabled: false,
            joystick: {
                active: false,
                baseX: 0,
                baseY: 0,
                stickX: 0,
                stickY: 0,
                radius: 60,
                stickRadius: 25,
                touchId: null,
                maxDistance: 50
            },
            abilityButtons: [],
            touchStartX: 0,
            touchStartY: 0,

            init() {
                // Detectar si es dispositivo móvil
                this.enabled = /Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);

                if (!this.enabled) return;

                console.log('📱 Mobile Controls initialized');

                // Configurar orientación horizontal
                this.setupOrientation();

                // Configurar eventos táctiles
                this.setupTouchEvents();

                // Crear botones de habilidades para móvil
                this.createAbilityButtons();
            },

            setupOrientation() {
                // Diseño móvil completo y optimizado
                const style = document.createElement('style');
                style.textContent = `
                    /* ===== DISEÑO MÓVIL COMPLETO ===== */
                    @media screen and (max-width: 768px) {
                        
                        /* Prevenir scroll horizontal */
                        body {
                            overflow-x: hidden !important;
                            max-width: 100vw !important;
                        }
                        
                        * {
                            max-width: 100vw !important;
                        }
                        
                        /* Layout móvil - Mostrar todo de forma accesible */
                        .game-layout {
                            grid-template-areas:
                                "header"
                                "main"
                                "abilities";
                            grid-template-columns: 1fr;
                            grid-template-rows: 60px 1fr 90px;
                            gap: 0;
                            overflow-x: hidden !important;
                        }
                        
                        /* Header móvil - Compacto pero visible */
                        .game-header {
                            padding: 0 15px !important;
                            height: 60px !important;
                            border-bottom: 2px solid rgba(0, 217, 255, 0.3) !important;
                        }
                        
                        .logo {
                            gap: 10px !important;
                        }
                        
                        .logo-icon {
                            width: 40px !important;
                            height: 40px !important;
                            font-size: 24px !important;
                        }
                        
                        .logo-text h1 {
                            font-size: 16px !important;
                            letter-spacing: 1px !important;
                        }
                        
                        .logo-text p {
                            font-size: 8px !important;
                            letter-spacing: 2px !important;
                        }
                        
                        .header-actions {
                            gap: 8px !important;
                        }
                        
                        .header-btn {
                            padding: 6px 12px !important;
                            font-size: 10px !important;
                            display: none; /* Ocultar botones, usar menú hamburguesa */
                        }
                        
                        .menu-toggle {
                            width: 40px !important;
                            height: 40px !important;
                            display: flex !important;
                        }
                        
                        /* Sidebar y Stats Panel - Ocultos en móvil, accesibles por menú */
                        .sidebar, .stats-panel {
                            display: none !important;
                        }
                        
                        /* Menú lateral móvil - Más ancho y accesible */
                        .side-menu {
                            width: 85vw !important;
                            max-width: 350px !important;
                            right: -85vw !important;
                        }
                        
                        .side-menu.open {
                            right: 0 !important;
                        }
                        
                        .side-menu-header {
                            padding: 20px 15px !important;
                        }
                        
                        .side-menu-header h2 {
                            font-size: 20px !important;
                        }
                        
                        .menu-item {
                            padding: 12px 15px !important;
                        }
                        
                        .menu-item:hover {
                            padding-left: 20px !important;
                        }
                        
                        .menu-item-icon {
                            width: 35px !important;
                            height: 35px !important;
                            font-size: 20px !important;
                        }
                        
                        .menu-item-title {
                            font-size: 14px !important;
                        }
                        
                        .menu-item-desc {
                            font-size: 10px !important;
                        }
                        
                        /* Canvas principal - Optimizado para móvil */
                        .main-canvas {
                            padding: 10px !important;
                        }
                        
                        #game-canvas {
                            border-width: 2px !important;
                            border-radius: 10px !important;
                        }
                        
                        .canvas-overlay {
                            top: 10px !important;
                            right: 10px !important;
                            left: 10px !important;
                            padding: 12px 15px !important;
                            gap: 15px !important;
                            flex-direction: row !important;
                            justify-content: space-around !important;
                            border-width: 2px !important;
                            border-radius: 12px !important;
                            backdrop-filter: blur(10px) !important;
                            background: linear-gradient(135deg, rgba(10, 14, 39, 0.98), rgba(5, 8, 20, 0.98)) !important;
                        }
                        
                        .overlay-item {
                            flex-direction: column !important;
                            gap: 4px !important;
                            text-align: center !important;
                            flex: 1 !important;
                        }
                        
                        .overlay-item::after {
                            display: none !important;
                        }
                        
                        .overlay-label {
                            font-size: 28px !important;
                            margin-bottom: 2px !important;
                        }
                        
                        .overlay-value {
                            font-size: 16px !important;
                            font-weight: 900 !important;
                            letter-spacing: 0.5px !important;
                        }
                        
                        /* Barra de habilidades móvil - Rediseñada */
                        .ability-bar {
                            padding: 6px 3px !important;
                            min-height: 80px !important;
                            max-height: 80px !important;
                            gap: 3px !important;
                            overflow-x: auto !important;
                            overflow-y: hidden !important;
                            background: linear-gradient(0deg, rgba(10, 14, 39, 0.98), rgba(5, 8, 20, 0.95)) !important;
                            -webkit-overflow-scrolling: touch !important;
                            scrollbar-width: thin !important;
                        }
                        
                        .ability-bar::-webkit-scrollbar {
                            height: 4px !important;
                        }
                        
                        .ability-bar::-webkit-scrollbar-track {
                            background: rgba(0, 0, 0, 0.3) !important;
                        }
                        
                        .ability-bar::-webkit-scrollbar-thumb {
                            background: linear-gradient(90deg, var(--primary), var(--secondary)) !important;
                            border-radius: 2px !important;
                        }
                        
                        .ability-slot {
                            width: 60px !important;
                            min-width: 60px !important;
                            max-width: 60px !important;
                            height: 70px !important;
                            padding: 3px !important;
                            border-width: 2px !important;
                            flex-shrink: 0 !important;
                        }
                        
                        .ability-slot:active {
                            transform: scale(0.95) !important;
                            transition: transform 0.1s !important;
                        }
                        
                        .ability-icon {
                            width: 50px !important;
                            height: 38px !important;
                            font-size: 22px !important;
                            margin-bottom: 2px !important;
                        }
                        
                        .ability-name {
                            font-size: 7px !important;
                            line-height: 1 !important;
                            margin-bottom: 2px !important;
                            max-width: 54px !important;
                        }
                        
                        .ability-key {
                            font-size: 10px !important;
                            padding: 2px 6px !important;
                            font-weight: 800 !important;
                        }
                        
                        .ability-cooldown {
                            font-size: 18px !important;
                        }
                        
                        /* Modales móviles - Pantalla completa */
                        .modal-content {
                            width: 95vw !important;
                            max-width: 95vw !important;
                            max-height: 90vh !important;
                            overflow-y: auto !important;
                        }
                        
                        .modal-header h2 {
                            font-size: 20px !important;
                        }
                        
                        .close-button {
                            width: 35px !important;
                            height: 35px !important;
                            font-size: 20px !important;
                        }
                        
                        /* ===== LOADOUT Y MAESTRÍAS MÓVIL - REDISEÑO COMPLETO GIGANTE ===== */
                        
                        /* Modal principal - Pantalla completa */
                        #loadout-modal .modal-content,
                        #masteries-modal .modal-content {
                            flex-direction: column !important;
                            padding: 0 !important;
                            max-height: 100vh !important;
                            height: 100vh !important;
                            width: 100vw !important;
                            max-width: 100vw !important;
                            border-radius: 0 !important;
                        }
                        
                        /* Sidebar convertida en header horizontal - GIGANTE */
                        #loadout-modal .modal-content > div:first-child,
                        #masteries-modal .modal-content > div:first-child {
                            width: 100% !important;
                            height: auto !important;
                            min-height: 140px !important;
                            max-height: 140px !important;
                            border-right: none !important;
                            border-bottom: 4px solid rgba(0, 217, 255, 0.5) !important;
                            flex-direction: row !important;
                            overflow-x: auto !important;
                            overflow-y: hidden !important;
                            -webkit-overflow-scrolling: touch !important;
                            background: linear-gradient(180deg, rgba(10, 14, 39, 0.98), rgba(5, 8, 20, 0.95)) !important;
                            display: flex !important;
                            align-items: stretch !important;
                        }
                        
                        /* Logo/Header del loadout - OCULTO EN MÓVIL */
                        #loadout-modal .modal-content > div:first-child > div:first-child,
                        #masteries-modal .modal-content > div:first-child > div:first-child {
                            display: none !important;
                        }
                        
                        /* Container de tabs - Horizontal COMPLETO */
                        #loadout-modal .modal-content > div:first-child > div:nth-child(2),
                        #masteries-modal .modal-content > div:first-child > div:nth-child(2) {
                            flex-direction: row !important;
                            padding: 20px 15px !important;
                            overflow-x: auto !important;
                            overflow-y: hidden !important;
                            flex: 1 !important;
                            display: flex !important;
                            gap: 15px !important;
                            align-items: center !important;
                            width: 100% !important;
                            height: 100% !important;
                        }
                        
                        /* Scrollbar horizontal de tabs */
                        #loadout-modal .modal-content > div:first-child > div:nth-child(2)::-webkit-scrollbar,
                        #masteries-modal .modal-content > div:first-child > div:nth-child(2)::-webkit-scrollbar {
                            height: 8px !important;
                        }
                        
                        #loadout-modal .modal-content > div:first-child > div:nth-child(2)::-webkit-scrollbar-track,
                        #masteries-modal .modal-content > div:first-child > div:nth-child(2)::-webkit-scrollbar-track {
                            background: rgba(0, 0, 0, 0.3) !important;
                            border-radius: 4px !important;
                        }
                        
                        #loadout-modal .modal-content > div:first-child > div:nth-child(2)::-webkit-scrollbar-thumb,
                        #masteries-modal .modal-content > div:first-child > div:nth-child(2)::-webkit-scrollbar-thumb {
                            background: linear-gradient(90deg, var(--primary), var(--secondary)) !important;
                            border-radius: 4px !important;
                        }
                        
                        /* TABS - GIGANTES Y ESPACIOSOS */
                        #loadout-modal .loadout-nav-item,
                        #loadout-modal .modal-content > div:first-child > div:nth-child(2) > div,
                        #masteries-modal .loadout-nav-item,
                        #masteries-modal .modal-content > div:first-child > div:nth-child(2) > div {
                            padding: 15px 25px !important;
                            min-width: 180px !important;
                            max-width: 180px !important;
                            height: 100px !important;
                            min-height: 100px !important;
                            max-height: 100px !important;
                            border-left: none !important;
                            border-bottom: 6px solid transparent !important;
                            border-radius: 15px !important;
                            flex-shrink: 0 !important;
                            display: flex !important;
                            flex-direction: row !important;
                            align-items: center !important;
                            justify-content: flex-start !important;
                            gap: 15px !important;
                            background: rgba(0, 217, 255, 0.08) !important;
                            transition: all 0.3s !important;
                            border: 3px solid rgba(0, 217, 255, 0.2) !important;
                        }
                        
                        #loadout-modal .loadout-nav-item.active,
                        #loadout-modal .modal-content > div:first-child > div:nth-child(2) > div.active,
                        #masteries-modal .loadout-nav-item.active,
                        #masteries-modal .modal-content > div:first-child > div:nth-child(2) > div.active {
                            border-bottom-color: var(--primary) !important;
                            background: rgba(0, 217, 255, 0.25) !important;
                            transform: scale(1.05) !important;
                            border-color: var(--primary) !important;
                            box-shadow: 0 0 30px rgba(0, 217, 255, 0.5) !important;
                        }
                        
                        /* Icono del tab - GRANDE */
                        #loadout-modal .loadout-nav-item > div:first-child,
                        #loadout-modal .modal-content > div:first-child > div:nth-child(2) > div > div:first-child,
                        #masteries-modal .loadout-nav-item > div:first-child,
                        #masteries-modal .modal-content > div:first-child > div:nth-child(2) > div > div:first-child {
                            width: 55px !important;
                            height: 55px !important;
                            min-width: 55px !important;
                            min-height: 55px !important;
                            font-size: 36px !important;
                            margin-bottom: 0 !important;
                            display: flex !important;
                            align-items: center !important;
                            justify-content: center !important;
                            flex-shrink: 0 !important;
                        }
                        
                        /* Texto del tab */
                        #loadout-modal .loadout-nav-item > div:last-child,
                        #loadout-modal .modal-content > div:first-child > div:nth-child(2) > div > div:last-child,
                        #masteries-modal .loadout-nav-item > div:last-child,
                        #masteries-modal .modal-content > div:first-child > div:nth-child(2) > div > div:last-child {
                            display: flex !important;
                            flex-direction: column !important;
                            align-items: flex-start !important;
                            justify-content: center !important;
                            gap: 4px !important;
                            flex: 1 !important;
                        }
                        
                        /* Título del tab - GRANDE */
                        #loadout-modal .loadout-nav-item > div:last-child > div:first-child,
                        #loadout-modal .modal-content > div:first-child > div:nth-child(2) > div > div:last-child > div:first-child,
                        #masteries-modal .loadout-nav-item > div:last-child > div:first-child,
                        #masteries-modal .modal-content > div:first-child > div:nth-child(2) > div > div:last-child > div:first-child {
                            font-size: 17px !important;
                            font-weight: 900 !important;
                            margin-bottom: 0 !important;
                            text-align: left !important;
                            line-height: 1.2 !important;
                        }
                        
                        /* Subtítulo del tab */
                        #loadout-modal .loadout-nav-item > div:last-child > div:last-child,
                        #loadout-modal .modal-content > div:first-child > div:nth-child(2) > div > div:last-child > div:last-child,
                        #masteries-modal .loadout-nav-item > div:last-child > div:last-child,
                        #masteries-modal .modal-content > div:first-child > div:nth-child(2) > div > div:last-child > div:last-child {
                            font-size: 12px !important;
                            text-align: left !important;
                            line-height: 1.2 !important;
                            opacity: 0.8 !important;
                        }
                        
                        /* Close button container - Posición absoluta fuera del flujo */
                        #loadout-modal .modal-content > div:first-child > div:last-child,
                        #masteries-modal .modal-content > div:first-child > div:last-child {
                            position: fixed !important;
                            top: 20px !important;
                            right: 20px !important;
                            width: auto !important;
                            height: auto !important;
                            padding: 0 !important;
                            border: none !important;
                            background: transparent !important;
                            z-index: 10000 !important;
                            display: block !important;
                        }
                        
                        /* Botón cerrar - GIGANTE Y FLOTANTE */
                        #loadout-modal #close-loadout,
                        #loadout-modal button[id*="close"],
                        #masteries-modal #close-loadout,
                        #masteries-modal button[id*="close"] {
                            position: relative !important;
                            width: 60px !important;
                            height: 60px !important;
                            min-height: 60px !important;
                            font-size: 32px !important;
                            background: linear-gradient(135deg, rgba(255, 0, 110, 0.95), rgba(255, 0, 0, 0.95)) !important;
                            border: 4px solid var(--secondary) !important;
                            border-radius: 50% !important;
                            box-shadow: 0 0 35px rgba(255, 0, 110, 0.7), 0 5px 20px rgba(0, 0, 0, 0.6) !important;
                            display: flex !important;
                            align-items: center !important;
                            justify-content: center !important;
                            cursor: pointer !important;
                            transition: all 0.3s !important;
                            padding: 0 !important;
                            letter-spacing: 0 !important;
                            margin: 0 !important;
                        }
                        
                        #loadout-modal #close-loadout:active,
                        #loadout-modal button[id*="close"]:active,
                        #masteries-modal #close-loadout:active,
                        #masteries-modal button[id*="close"]:active {
                            transform: scale(0.85) !important;
                            box-shadow: 0 0 45px rgba(255, 0, 110, 0.9), 0 2px 12px rgba(0, 0, 0, 0.7) !important;
                        }
                        
                        /* Content area - GIGANTE espacioso */
                        #loadout-modal .modal-content > div:last-child,
                        #masteries-modal .modal-content > div:last-child {
                            flex: 1 !important;
                            overflow-y: auto !important;
                            -webkit-overflow-scrolling: touch !important;
                        }
                        
                        /* Content header - GIGANTE */
                        #loadout-modal .modal-content > div:last-child > div:first-child,
                        #masteries-modal .modal-content > div:last-child > div:first-child {
                            padding: 30px !important;
                            background: linear-gradient(135deg, rgba(0, 217, 255, 0.1), rgba(255, 0, 110, 0.1)) !important;
                        }
                        
                        #loadout-modal .modal-content > div:last-child > div:first-child h3,
                        #masteries-modal .modal-content > div:last-child > div:first-child h3 {
                            font-size: 28px !important;
                            margin-bottom: 12px !important;
                            font-weight: 900 !important;
                        }
                        
                        #loadout-modal .modal-content > div:last-child > div:first-child p,
                        #masteries-modal .modal-content > div:last-child > div:first-child p {
                            font-size: 16px !important;
                            line-height: 1.5 !important;
                        }
                        
                        /* Content body - GIGANTE ESPACIOSO */
                        #loadout-modal .modal-body,
                        #loadout-modal #loadout-content,
                        #loadout-modal .modal-content > div:last-child > div:last-child,
                        #masteries-modal .modal-body,
                        #masteries-modal #loadout-content,
                        #masteries-modal .modal-content > div:last-child > div:last-child {
                            padding: 40px 30px !important;
                        }
                        
                        /* Grid - 1 COLUMNA GIGANTE ESPACIOSA */
                        #loadout-modal .role-grid,
                        #loadout-modal #loadout-content .role-grid,
                        #loadout-modal .modal-body .role-grid,
                        #loadout-modal div[id*="loadout"] .role-grid,
                        #masteries-modal .role-grid,
                        #masteries-modal #loadout-content .role-grid,
                        #masteries-modal .modal-body .role-grid,
                        #masteries-modal div[id*="loadout"] .role-grid {
                            display: flex !important;
                            flex-direction: column !important;
                            gap: 40px !important;
                            width: 100% !important;
                            max-width: 100% !important;
                        }
                        
                        /* CARDS - GIGANTES - TODOS LOS SELECTORES POSIBLES */
                        #loadout-modal .role-card,
                        #loadout-modal .equip-card,
                        #loadout-modal #loadout-content .role-card,
                        #loadout-modal .modal-body .role-card,
                        #loadout-modal .role-grid > div,
                        #loadout-modal #loadout-content > div,
                        #loadout-modal [class*="role-card"],
                        #loadout-modal [class*="equip-card"],
                        #masteries-modal .role-card,
                        #masteries-modal .equip-card,
                        #masteries-modal #loadout-content .role-card,
                        #masteries-modal .modal-body .role-card,
                        #masteries-modal .role-grid > div,
                        #masteries-modal #loadout-content > div,
                        #masteries-modal [class*="role-card"],
                        #masteries-modal [class*="equip-card"] {
                            padding: 45px 35px !important;
                            margin: 0 !important;
                            min-height: 220px !important;
                            width: 100% !important;
                            max-width: 100% !important;
                            display: flex !important;
                            flex-direction: column !important;
                            align-items: center !important;
                            justify-content: center !important;
                            text-align: center !important;
                            border-width: 4px !important;
                            border-radius: 20px !important;
                            box-sizing: border-box !important;
                        }
                        
                        /* ICONOS - GIGANTESCOS */
                        #loadout-modal .role-card-icon,
                        #loadout-modal #loadout-content .role-card-icon,
                        #loadout-modal .modal-body .role-card-icon,
                        #loadout-modal .role-card > div:first-child,
                        #loadout-modal [class*="role-card"] > div:first-child,
                        #masteries-modal .role-card-icon,
                        #masteries-modal #loadout-content .role-card-icon,
                        #masteries-modal .modal-body .role-card-icon,
                        #masteries-modal .role-card > div:first-child,
                        #masteries-modal [class*="role-card"] > div:first-child {
                            font-size: 110px !important;
                            margin-bottom: 25px !important;
                            line-height: 1 !important;
                            width: auto !important;
                            height: auto !important;
                        }
                        
                        /* NOMBRES - GIGANTES */
                        #loadout-modal .role-card-name,
                        #loadout-modal #loadout-content .role-card-name,
                        #loadout-modal .modal-body .role-card-name,
                        #loadout-modal [class*="role-card-name"],
                        #masteries-modal .role-card-name,
                        #masteries-modal #loadout-content .role-card-name,
                        #masteries-modal .modal-body .role-card-name,
                        #masteries-modal [class*="role-card-name"] {
                            font-size: 26px !important;
                            margin-bottom: 15px !important;
                            font-weight: 900 !important;
                            line-height: 1.3 !important;
                            letter-spacing: 0.5px !important;
                        }
                        
                        /* TIPOS - GIGANTES */
                        #loadout-modal .role-card-type,
                        #loadout-modal #loadout-content .role-card-type,
                        #loadout-modal .modal-body .role-card-type,
                        #loadout-modal [class*="role-card-type"],
                        #masteries-modal .role-card-type,
                        #masteries-modal #loadout-content .role-card-type,
                        #masteries-modal .modal-body .role-card-type,
                        #masteries-modal [class*="role-card-type"] {
                            font-size: 18px !important;
                            margin-top: 10px !important;
                            font-weight: 700 !important;
                            text-transform: uppercase !important;
                            letter-spacing: 1.5px !important;
                        }
                        
                        /* Tier badges - GIGANTES */
                        #loadout-modal .role-card > div[style*="Tier"],
                        #loadout-modal .role-card > div[style*="tier"],
                        #loadout-modal .role-card > div[style*="TIER"],
                        #loadout-modal .role-card div[style*="Tier"],
                        #loadout-modal [class*="role-card"] div[style*="Tier"],
                        #masteries-modal .role-card > div[style*="Tier"],
                        #masteries-modal .role-card > div[style*="tier"],
                        #masteries-modal .role-card > div[style*="TIER"],
                        #masteries-modal .role-card div[style*="Tier"],
                        #masteries-modal [class*="role-card"] div[style*="Tier"] {
                            font-size: 24px !important;
                            padding: 15px 30px !important;
                            margin-top: 18px !important;
                            font-weight: 900 !important;
                            border-radius: 30px !important;
                        }
                        
                        /* Tickets - GIGANTES */
                        #loadout-modal .role-card > div[style*="Tickets"],
                        #loadout-modal .role-card > div[style*="tickets"],
                        #loadout-modal .role-card > div[style*="Ticket"],
                        #loadout-modal .role-card div[style*="Ticket"],
                        #loadout-modal [class*="role-card"] div[style*="Ticket"],
                        #masteries-modal .role-card > div[style*="Tickets"],
                        #masteries-modal .role-card > div[style*="tickets"],
                        #masteries-modal .role-card > div[style*="Ticket"],
                        #masteries-modal .role-card div[style*="Ticket"],
                        #masteries-modal [class*="role-card"] div[style*="Ticket"] {
                            font-size: 22px !important;
                            margin-top: 15px !important;
                            padding: 12px 20px !important;
                            font-weight: 800 !important;
                            border-radius: 12px !important;
                        }
                        
                        /* Botones - GIGANTES */
                        #loadout-modal button,
                        #loadout-modal #loadout-content button,
                        #loadout-modal .modal-body button,
                        #masteries-modal button,
                        #masteries-modal #loadout-content button,
                        #masteries-modal .modal-body button {
                            padding: 22px 35px !important;
                            font-size: 18px !important;
                            min-height: 65px !important;
                            font-weight: 900 !important;
                            border-radius: 15px !important;
                            letter-spacing: 1.5px !important;
                        }
                        
                        /* Equipamiento actual - GIGANTE espacioso */
                        #loadout-modal .equip-card-content,
                        #masteries-modal .equip-card-content {
                            padding: 30px !important;
                        }
                        
                        #loadout-modal .equip-info h3,
                        #masteries-modal .equip-info h3 {
                            font-size: 24px !important;
                            margin-bottom: 12px !important;
                            font-weight: 900 !important;
                        }
                        
                        #loadout-modal .equip-type,
                        #masteries-modal .equip-type {
                            font-size: 16px !important;
                            font-weight: 700 !important;
                        }
                        
                        #loadout-modal .equip-status,
                        #masteries-modal .equip-status {
                            font-size: 15px !important;
                            padding: 10px 20px !important;
                            font-weight: 800 !important;
                        }
                        
                        /* Imágenes de cards - GIGANTES */
                        #loadout-modal .equip-card-image,
                        #loadout-modal .role-card-image,
                        #masteries-modal .equip-card-image,
                        #masteries-modal .role-card-image {
                            height: 220px !important;
                        }
                        
                        /* ===== ESPACIADO Y SEPARACIÓN DE ELEMENTOS EN CARDS ===== */
                        
                        /* Todos los divs dentro de cards - Espaciado vertical */
                        #loadout-modal .role-card > div,
                        #loadout-modal .equip-card > div,
                        #masteries-modal .role-card > div,
                        #masteries-modal .equip-card > div {
                            margin-bottom: 12px !important;
                        }
                        
                        /* Último elemento sin margen inferior */
                        #loadout-modal .role-card > div:last-child,
                        #loadout-modal .equip-card > div:last-child,
                        #masteries-modal .role-card > div:last-child,
                        #masteries-modal .equip-card > div:last-child {
                            margin-bottom: 0 !important;
                        }
                        
                        /* Divs con posición absoluta (badges) - Espaciado mejorado */
                        #loadout-modal .role-card > div[style*="position: absolute"],
                        #loadout-modal .equip-card > div[style*="position: absolute"],
                        #masteries-modal .role-card > div[style*="position: absolute"],
                        #masteries-modal .equip-card > div[style*="position: absolute"] {
                            margin: 0 !important;
                            padding: 12px 20px !important;
                            font-size: 16px !important;
                            font-weight: 900 !important;
                            border-radius: 12px !important;
                            white-space: nowrap !important;
                        }
                        
                        /* Badge "EQUIPADO" - Más grande y visible */
                        #loadout-modal .role-card > div[style*="EQUIPADO"],
                        #loadout-modal .equip-card > div[style*="EQUIPADO"],
                        #masteries-modal .role-card > div[style*="EQUIPADO"],
                        #masteries-modal .equip-card > div[style*="EQUIPADO"] {
                            font-size: 18px !important;
                            padding: 14px 24px !important;
                        }
                        
                        /* Contenedor de información de equipamiento */
                        #loadout-modal .equip-card-header,
                        #masteries-modal .equip-card-header {
                            margin-bottom: 15px !important;
                        }
                        
                        /* Separación entre elementos de texto */
                        #loadout-modal .role-card h3,
                        #loadout-modal .role-card h4,
                        #loadout-modal .role-card p,
                        #loadout-modal .equip-card h3,
                        #loadout-modal .equip-card h4,
                        #loadout-modal .equip-card p,
                        #masteries-modal .role-card h3,
                        #masteries-modal .role-card h4,
                        #masteries-modal .role-card p,
                        #masteries-modal .equip-card h3,
                        #masteries-modal .equip-card h4,
                        #masteries-modal .equip-card p {
                            display: block !important;
                            margin: 10px 0 !important;
                            line-height: 1.4 !important;
                        }
                        
                        /* Forzar saltos de línea en elementos específicos */
                        #loadout-modal .role-card > *,
                        #loadout-modal .equip-card > *,
                        #masteries-modal .role-card > *,
                        #masteries-modal .equip-card > * {
                            display: block !important;
                            width: 100% !important;
                        }
                        
                        /* Excepciones para elementos que deben ser inline */
                        #loadout-modal .role-card > div[style*="position: absolute"],
                        #loadout-modal .equip-card > div[style*="position: absolute"],
                        #masteries-modal .role-card > div[style*="position: absolute"],
                        #masteries-modal .equip-card > div[style*="position: absolute"] {
                            display: block !important;
                            width: auto !important;
                        }
                        
                        /* Scrollbar del header - Más visible */
                        #loadout-modal .modal-content > div:first-child::-webkit-scrollbar,
                        #masteries-modal .modal-content > div:first-child::-webkit-scrollbar {
                            height: 8px !important;
                        }
                        
                        #loadout-modal .modal-content > div:first-child::-webkit-scrollbar-thumb,
                        #masteries-modal .modal-content > div:first-child::-webkit-scrollbar-thumb {
                            background: linear-gradient(90deg, var(--primary), var(--secondary)) !important;
                            border-radius: 4px !important;
                        }
                        
                        /* ===== MAESTRÍAS - ESTILOS ESPECÍFICOS GIGANTES ===== */
                        
                        /* Progreso de misiones - GIGANTE */
                        #masteries-modal .mission-progress,
                        #masteries-modal [class*="mission"],
                        #masteries-modal [class*="progress"] {
                            font-size: 18px !important;
                            padding: 20px !important;
                            margin: 15px 0 !important;
                        }
                        
                        /* Requisitos de maestría - GIGANTES */
                        #masteries-modal .requirement,
                        #masteries-modal [class*="requirement"] {
                            font-size: 16px !important;
                            padding: 15px 20px !important;
                            margin: 10px 0 !important;
                            border-width: 3px !important;
                            border-radius: 12px !important;
                        }
                        
                        /* Barras de progreso - GIGANTES */
                        #masteries-modal .progress-bar,
                        #masteries-modal [class*="progress-bar"] {
                            height: 20px !important;
                            border-radius: 10px !important;
                            margin: 12px 0 !important;
                        }
                        
                        /* Texto de progreso - GIGANTE */
                        #masteries-modal .progress-text,
                        #masteries-modal [class*="progress-text"] {
                            font-size: 16px !important;
                            font-weight: 700 !important;
                            margin: 8px 0 !important;
                        }
                        
                        /* Descripción de maestría - GIGANTE */
                        #masteries-modal .mastery-description,
                        #masteries-modal [class*="description"] {
                            font-size: 16px !important;
                            line-height: 1.6 !important;
                            padding: 20px !important;
                            margin: 15px 0 !important;
                        }
                        
                        /* Recompensas - GIGANTES */
                        #masteries-modal .reward,
                        #masteries-modal [class*="reward"] {
                            font-size: 18px !important;
                            padding: 18px 25px !important;
                            margin: 12px 0 !important;
                            border-width: 3px !important;
                            border-radius: 15px !important;
                        }
                        
                        /* Tabs móviles */
                        .tabs {
                            gap: 8px !important;
                            flex-wrap: wrap !important;
                            padding: 10px !important;
                        }
                        
                        .tab-button {
                            padding: 10px 16px !important;
                            font-size: 13px !important;
                            min-height: 44px !important;
                        }
                        
                        /* Grid de roles móvil GENERAL (fuera de loadout) */
                        .modal:not(#loadout-modal) .role-grid {
                            grid-template-columns: repeat(2, 1fr) !important;
                            gap: 15px !important;
                        }
                        
                        .modal:not(#loadout-modal) .role-card {
                            padding: 18px !important;
                            min-height: 160px !important;
                        }
                        
                        .modal:not(#loadout-modal) .role-card-icon {
                            font-size: 55px !important;
                            margin-bottom: 12px !important;
                        }
                        
                        .modal:not(#loadout-modal) .role-card-name {
                            font-size: 16px !important;
                            margin-bottom: 6px !important;
                        }
                        
                        .modal:not(#loadout-modal) .role-card-type {
                            font-size: 12px !important;
                        }
                        
                        .role-card-name {
                            font-size: 13px !important;
                        }
                        
                        .role-card-type {
                            font-size: 9px !important;
                        }
                        
                        /* Panel de información móvil */
                        #role-info-panel {
                            width: 100vw !important;
                            right: -100vw !important;
                            padding: 20px 15px !important;
                        }
                        
                        #role-info-panel.open {
                            right: 0 !important;
                        }
                        
                        /* ===== BARRA DE ESTADÍSTICAS INFERIOR - MÓVIL ===== */
                        
                        /* Contenedor principal de stats */
                        .ability-bar[style*="justify-content"] {
                            flex-direction: column !important;
                            padding: 15px 10px !important;
                            gap: 15px !important;
                            min-height: auto !important;
                            max-height: none !important;
                        }
                        
                        /* Contenedor de estadísticas */
                        .ability-bar > div:first-child {
                            width: 100% !important;
                            flex-direction: row !important;
                            justify-content: space-around !important;
                            gap: 8px !important;
                            flex-wrap: wrap !important;
                        }
                        
                        /* Cada stat individual */
                        .ability-bar > div:first-child > div[style*="text-align"] {
                            flex: 1 !important;
                            min-width: 90px !important;
                            padding: 10px 5px !important;
                            background: rgba(0, 217, 255, 0.05) !important;
                            border-radius: 10px !important;
                            border: 2px solid rgba(0, 217, 255, 0.2) !important;
                        }
                        
                        /* Labels de stats */
                        .ability-bar > div:first-child > div[style*="text-align"] > div:first-child {
                            font-size: 9px !important;
                            margin-bottom: 4px !important;
                            letter-spacing: 0.5px !important;
                        }
                        
                        /* Valores de stats */
                        .ability-bar > div:first-child > div[style*="text-align"] > div:last-child {
                            font-size: 20px !important;
                            font-weight: 900 !important;
                        }
                        
                        /* Separadores verticales - Ocultar */
                        .ability-bar > div:first-child > div[style*="width: 2px"] {
                            display: none !important;
                        }
                        
                        /* Quick Info - Ocultar en móvil */
                        .ability-bar > div:last-child {
                            display: none !important;
                        }
                    }
                    
                    /* ===== MODO JUEGO EN MÓVIL (Raids/Práctica) ===== */
                    @media screen and (max-width: 768px) {
                        .mobile-game-mode .game-header {
                            display: none !important;
                        }
                        
                        .mobile-game-mode .game-layout {
                            grid-template-areas: "main";
                            grid-template-columns: 1fr;
                            grid-template-rows: 1fr;
                        }
                        
                        .mobile-game-mode .ability-bar {
                            display: none !important;
                        }
                        
                        .mobile-game-mode .main-canvas {
                            padding: 0 !important;
                        }
                        
                        .mobile-game-mode #game-canvas {
                            border-radius: 0 !important;
                            width: 100vw !important;
                            height: 100vh !important;
                        }
                    }
                    
                    /* ===== ROTACIÓN EN PORTRAIT ===== */
                    @media screen and (max-width: 768px) and (orientation: portrait) {
                        .mobile-game-mode .main-canvas {
                            position: fixed !important;
                            top: 50% !important;
                            left: 50% !important;
                            transform: translate(-50%, -50%) rotate(90deg) !important;
                            width: 100vh !important;
                            height: 100vw !important;
                            z-index: 9999 !important;
                        }
                        
                        .mobile-game-mode #game-canvas {
                            width: 100vh !important;
                            height: 100vw !important;
                        }
                    }
                    
                    /* ===== LANDSCAPE MÓVIL ===== */
                    @media screen and (max-width: 768px) and (orientation: landscape) {
                        .game-header {
                            height: 50px !important;
                        }
                        
                        .logo-icon {
                            width: 35px !important;
                            height: 35px !important;
                        }
                        
                        .logo-text h1 {
                            font-size: 14px !important;
                        }
                        
                        .logo-text p {
                            display: none !important;
                        }
                        
                        .ability-bar {
                            min-height: 70px !important;
                            max-height: 70px !important;
                        }
                        
                        .ability-slot {
                            height: 60px !important;
                        }
                    }
                `;
                document.head.appendChild(style);

                // Agregar clase al body cuando esté en modo juego
                this.addGameModeClass();
            },

            addGameModeClass() {
                // Observar cambios en el estado del juego
                const checkGameMode = () => {
                    const body = document.body;
                    const wasInGameMode = body.classList.contains('mobile-game-mode');
                    const isInGameMode = MobRaidSystem.active || PracticeModeManager.active;

                    if (isInGameMode && !wasInGameMode) {
                        // Entrando al modo juego
                        body.classList.add('mobile-game-mode');
                        this.enterFullscreenMode();
                        this.requestOrientationLock();
                    } else if (!isInGameMode && wasInGameMode) {
                        // Saliendo del modo juego
                        body.classList.remove('mobile-game-mode');
                        this.exitFullscreenMode();
                        this.releaseOrientationLock();
                    }
                };

                // Verificar cada 500ms
                setInterval(checkGameMode, 500);
            },

            enterFullscreenMode() {
                if (!this.enabled) return;

                const canvas = document.getElementById('game-canvas');
                if (!canvas) return;

                // Intentar entrar en pantalla completa
                const requestFullscreen = canvas.requestFullscreen ||
                    canvas.webkitRequestFullscreen ||
                    canvas.mozRequestFullScreen ||
                    canvas.msRequestFullscreen;

                if (requestFullscreen) {
                    requestFullscreen.call(canvas).catch(err => {
                        console.log('No se pudo entrar en pantalla completa:', err);
                    });
                }
            },

            exitFullscreenMode() {
                if (!this.enabled) return;

                // Salir de pantalla completa
                const exitFullscreen = document.exitFullscreen ||
                    document.webkitExitFullscreen ||
                    document.mozCancelFullScreen ||
                    document.msExitFullscreen;

                if (exitFullscreen && (document.fullscreenElement || document.webkitFullscreenElement)) {
                    exitFullscreen.call(document).catch(err => {
                        console.log('No se pudo salir de pantalla completa:', err);
                    });
                }
            },

            requestOrientationLock() {
                if (!this.enabled) return;

                // Intentar bloquear orientación a landscape
                if (screen.orientation && screen.orientation.lock) {
                    screen.orientation.lock('landscape').catch(err => {
                        console.log('No se pudo bloquear la orientación:', err);
                    });
                }
            },

            releaseOrientationLock() {
                if (!this.enabled) return;

                // Liberar bloqueo de orientación
                if (screen.orientation && screen.orientation.unlock) {
                    screen.orientation.unlock();
                }
            },

            setupTouchEvents() {
                const canvas = document.getElementById('game-canvas');

                // Touch start
                canvas.addEventListener('touchstart', (e) => {
                    e.preventDefault();

                    for (let i = 0; i < e.changedTouches.length; i++) {
                        const touch = e.changedTouches[i];
                        const rect = canvas.getBoundingClientRect();
                        const x = touch.clientX - rect.left;
                        const y = touch.clientY - rect.top;

                        // Convertir coordenadas de canvas a coordenadas del juego
                        const gameX = (x / rect.width) * canvas.width;
                        const gameY = (y / rect.height) * canvas.height;

                        // Si el toque está en la mitad izquierda, activar joystick
                        if (gameX < canvas.width / 2) {
                            this.joystick.active = true;
                            this.joystick.baseX = gameX;
                            this.joystick.baseY = gameY;
                            this.joystick.stickX = gameX;
                            this.joystick.stickY = gameY;
                            this.joystick.touchId = touch.identifier;
                        }
                        // Si está en la mitad derecha, verificar botones de habilidades
                        else {
                            this.checkAbilityButtonTouch(gameX, gameY);

                            // También verificar si está en modo práctica y hacer clic en el panel
                            if (PracticeModeManager.active) {
                                PracticeModeManager.handleCanvasClick(gameX, gameY);
                            }
                        }
                    }
                }, { passive: false });

                // Touch move
                canvas.addEventListener('touchmove', (e) => {
                    e.preventDefault();

                    if (!this.joystick.active) return;

                    for (let i = 0; i < e.changedTouches.length; i++) {
                        const touch = e.changedTouches[i];

                        if (touch.identifier === this.joystick.touchId) {
                            const rect = canvas.getBoundingClientRect();
                            const x = touch.clientX - rect.left;
                            const y = touch.clientY - rect.top;

                            const gameX = (x / rect.width) * canvas.width;
                            const gameY = (y / rect.height) * canvas.height;

                            // Calcular distancia desde la base
                            const dx = gameX - this.joystick.baseX;
                            const dy = gameY - this.joystick.baseY;
                            const distance = Math.sqrt(dx * dx + dy * dy);

                            // Limitar la distancia máxima
                            if (distance > this.joystick.maxDistance) {
                                const angle = Math.atan2(dy, dx);
                                this.joystick.stickX = this.joystick.baseX + Math.cos(angle) * this.joystick.maxDistance;
                                this.joystick.stickY = this.joystick.baseY + Math.sin(angle) * this.joystick.maxDistance;
                            } else {
                                this.joystick.stickX = gameX;
                                this.joystick.stickY = gameY;
                            }

                            // Actualizar movimiento del jugador
                            this.updatePlayerMovement();
                        }
                    }
                }, { passive: false });

                // Touch end
                canvas.addEventListener('touchend', (e) => {
                    e.preventDefault();

                    for (let i = 0; i < e.changedTouches.length; i++) {
                        const touch = e.changedTouches[i];

                        if (touch.identifier === this.joystick.touchId) {
                            this.joystick.active = false;
                            this.joystick.touchId = null;

                            // Detener movimiento del jugador
                            this.movementDirection = null;
                        }
                    }
                }, { passive: false });

                // Touch cancel
                canvas.addEventListener('touchcancel', (e) => {
                    e.preventDefault();
                    this.joystick.active = false;
                    this.joystick.touchId = null;

                    // Detener movimiento del jugador
                    this.movementDirection = null;
                }, { passive: false });
            },

            updatePlayerMovement() {
                if (!this.joystick.active) return;

                // Calcular dirección normalizada
                const dx = this.joystick.stickX - this.joystick.baseX;
                const dy = this.joystick.stickY - this.joystick.baseY;
                const distance = Math.sqrt(dx * dx + dy * dy);

                if (distance > 5) { // Dead zone
                    const normalizedX = dx / this.joystick.maxDistance;
                    const normalizedY = dy / this.joystick.maxDistance;

                    // Guardar dirección para usar en update
                    this.movementDirection = {
                        x: normalizedX,
                        y: normalizedY
                    };
                } else {
                    this.movementDirection = null;
                }
            },

            createAbilityButtons() {
                // Crear botones flotantes en el canvas
                // Se actualizan dinámicamente basados en las habilidades equipadas
                this.updateAbilityButtons();
            },

            updateAbilityButtons() {
                // Actualizar posiciones y estados de los botones de habilidades
                const abilities = EquipmentManager.getAllAbilities();
                this.abilityButtons = [];

                if (!abilities || abilities.length === 0) return;

                const canvas = document.getElementById('game-canvas');
                const buttonSize = 65; // Tamaño optimizado para móvil
                const spacing = 8; // Espacio entre botones
                const marginRight = 15; // Margen desde el borde derecho
                const marginBottom = 20; // Margen desde el borde inferior

                // Posicionar botones en el lado derecho, más abajo para mejor acceso con el pulgar
                const startX = canvas.width - (buttonSize + marginRight);
                const totalHeight = (abilities.length * (buttonSize + spacing)) - spacing;
                const startY = canvas.height - totalHeight - marginBottom;

                abilities.forEach((ability, index) => {
                    this.abilityButtons.push({
                        x: startX,
                        y: startY + (index * (buttonSize + spacing)),
                        width: buttonSize,
                        height: buttonSize,
                        ability: ability,
                        icon: ability.icon || '⚔️',
                        key: ability.keyBinding ? ability.keyBinding.toUpperCase() : (index + 1).toString()
                    });
                });
            },

            checkAbilityButtonTouch(x, y) {
                // Verificar si el toque está sobre algún botón flotante
                for (let i = 0; i < this.abilityButtons.length; i++) {
                    const btn = this.abilityButtons[i];

                    if (x >= btn.x && x <= btn.x + btn.width &&
                        y >= btn.y && y <= btn.y + btn.height) {

                        // Verificar si la habilidad no está en cooldown
                        if (btn.ability.currentCooldown === 0) {
                            AbilityManager.activateAbility(btn.ability.id);

                            // Efecto visual de toque
                            this.showTouchFeedback(btn.x + btn.width / 2, btn.y + btn.height / 2);
                            return true;
                        }
                    }
                }
                return false;
            },

            showTouchFeedback(x, y) {
                // Crear efecto visual temporal de toque
                const feedback = {
                    x: x,
                    y: y,
                    radius: 10,
                    maxRadius: 40,
                    alpha: 1,
                    startTime: Date.now()
                };

                if (!this.touchFeedbacks) this.touchFeedbacks = [];
                this.touchFeedbacks.push(feedback);
            },

            render(ctx) {
                if (!this.enabled) return;

                const inGame = MobRaidSystem.active || PracticeModeManager.active;

                if (inGame) {
                    // Activar clase CSS para rotar canvas en portrait
                    const mainCanvas = document.querySelector('.main-canvas');
                    const gameCanvas = document.getElementById('game-canvas');
                    if (mainCanvas && gameCanvas) {
                        mainCanvas.classList.add('mobile-game-active');
                        gameCanvas.classList.add('mobile-game-active');
                    }

                    // Renderizar joystick si está activo
                    if (this.joystick.active) {
                        this.renderJoystick(ctx);
                    }

                    // Renderizar botones flotantes de habilidades
                    this.renderAbilityButtons(ctx);

                    // Renderizar efectos de toque
                    this.renderTouchFeedbacks(ctx);
                } else {
                    // Desactivar clase CSS cuando no está en juego
                    const mainCanvas = document.querySelector('.main-canvas');
                    const gameCanvas = document.getElementById('game-canvas');
                    if (mainCanvas && gameCanvas) {
                        mainCanvas.classList.remove('mobile-game-active');
                        gameCanvas.classList.remove('mobile-game-active');
                    }

                    // Renderizar indicador de controles móviles
                    this.renderMobileIndicator(ctx);
                }
            },

            renderJoystick(ctx) {
                ctx.save();

                // Base del joystick
                ctx.fillStyle = 'rgba(0, 217, 255, 0.3)';
                ctx.strokeStyle = 'rgba(0, 217, 255, 0.6)';
                ctx.lineWidth = 3;
                ctx.beginPath();
                ctx.arc(this.joystick.baseX, this.joystick.baseY, this.joystick.radius, 0, Math.PI * 2);
                ctx.fill();
                ctx.stroke();

                // Círculo interior de la base
                ctx.strokeStyle = 'rgba(0, 217, 255, 0.4)';
                ctx.lineWidth = 2;
                ctx.beginPath();
                ctx.arc(this.joystick.baseX, this.joystick.baseY, this.joystick.radius * 0.6, 0, Math.PI * 2);
                ctx.stroke();

                // Stick del joystick
                ctx.fillStyle = 'rgba(0, 217, 255, 0.8)';
                ctx.strokeStyle = 'rgba(255, 255, 255, 0.9)';
                ctx.lineWidth = 3;
                ctx.shadowBlur = 15;
                ctx.shadowColor = 'rgba(0, 217, 255, 0.8)';
                ctx.beginPath();
                ctx.arc(this.joystick.stickX, this.joystick.stickY, this.joystick.stickRadius, 0, Math.PI * 2);
                ctx.fill();
                ctx.stroke();

                // Línea de dirección
                ctx.strokeStyle = 'rgba(255, 255, 255, 0.5)';
                ctx.lineWidth = 2;
                ctx.shadowBlur = 0;
                ctx.beginPath();
                ctx.moveTo(this.joystick.baseX, this.joystick.baseY);
                ctx.lineTo(this.joystick.stickX, this.joystick.stickY);
                ctx.stroke();

                ctx.restore();
            },

            renderAbilityButtons(ctx) {
                if (!this.abilityButtons || this.abilityButtons.length === 0) {
                    this.updateAbilityButtons();
                    return;
                }

                ctx.save();

                this.abilityButtons.forEach((btn, index) => {
                    const isOnCooldown = btn.ability.currentCooldown > 0;
                    const isUltimate = btn.ability.id.includes('ultimate');

                    // Fondo del botón con más opacidad para mejor visibilidad
                    ctx.fillStyle = isOnCooldown ? 'rgba(50, 50, 50, 0.85)' :
                        isUltimate ? 'rgba(255, 190, 11, 0.85)' :
                            'rgba(0, 217, 255, 0.85)';
                    ctx.strokeStyle = isOnCooldown ? 'rgba(100, 100, 100, 0.9)' :
                        isUltimate ? 'rgba(255, 190, 11, 1)' :
                            'rgba(0, 217, 255, 1)';
                    ctx.lineWidth = 3;
                    ctx.shadowBlur = isOnCooldown ? 0 : 15;
                    ctx.shadowColor = isUltimate ? 'rgba(255, 190, 11, 1)' : 'rgba(0, 217, 255, 1)';

                    // Dibujar botón redondeado
                    ctx.beginPath();
                    ctx.roundRect(btn.x, btn.y, btn.width, btn.height, 12);
                    ctx.fill();
                    ctx.stroke();

                    // Icono de la habilidad - Más grande
                    ctx.shadowBlur = 0;
                    ctx.font = 'bold 34px Arial';
                    ctx.fillStyle = isOnCooldown ? 'rgba(150, 150, 150, 0.8)' : '#ffffff';
                    ctx.textAlign = 'center';
                    ctx.textBaseline = 'middle';
                    ctx.fillText(btn.icon, btn.x + btn.width / 2, btn.y + btn.height / 2 - 3);

                    // Tecla de atajo - Más visible
                    ctx.font = 'bold 13px Arial';
                    ctx.fillStyle = isUltimate ? '#ffbe0b' : '#00d9ff';
                    ctx.shadowBlur = 3;
                    ctx.shadowColor = 'rgba(0, 0, 0, 0.8)';
                    ctx.fillText(btn.key, btn.x + btn.width / 2, btn.y + btn.height - 10);
                    ctx.shadowBlur = 0;

                    // Cooldown overlay
                    if (isOnCooldown) {
                        const cooldownPercent = btn.ability.currentCooldown / btn.ability.cooldown;
                        const cooldownHeight = btn.height * cooldownPercent;

                        ctx.fillStyle = 'rgba(0, 0, 0, 0.7)';
                        ctx.beginPath();
                        ctx.roundRect(btn.x, btn.y + btn.height - cooldownHeight, btn.width, cooldownHeight, [0, 0, 12, 12]);
                        ctx.fill();

                        // Tiempo restante
                        const secondsLeft = Math.ceil(btn.ability.currentCooldown / 1000);
                        ctx.font = 'bold 20px Arial';
                        ctx.fillStyle = '#ff006e';
                        ctx.fillText(secondsLeft, btn.x + btn.width / 2, btn.y + btn.height / 2);
                    }
                });

                ctx.restore();
            },

            renderTouchFeedbacks(ctx) {
                if (!this.touchFeedbacks || this.touchFeedbacks.length === 0) return;

                ctx.save();

                const now = Date.now();
                this.touchFeedbacks = this.touchFeedbacks.filter(feedback => {
                    const elapsed = now - feedback.startTime;
                    const duration = 300; // ms

                    if (elapsed > duration) return false;

                    const progress = elapsed / duration;
                    feedback.radius = 10 + (feedback.maxRadius - 10) * progress;
                    feedback.alpha = 1 - progress;

                    ctx.strokeStyle = `rgba(0, 217, 255, ${feedback.alpha})`;
                    ctx.lineWidth = 3;
                    ctx.beginPath();
                    ctx.arc(feedback.x, feedback.y, feedback.radius, 0, Math.PI * 2);
                    ctx.stroke();

                    return true;
                });

                ctx.restore();
            },

            renderMobileIndicator(ctx) {
                if (!MobRaidSystem.active && !PracticeModeManager.active) {
                    // Mostrar indicador de controles móviles en el menú
                    ctx.save();
                    ctx.fillStyle = 'rgba(0, 217, 255, 0.8)';
                    ctx.font = 'bold 16px Arial';
                    ctx.textAlign = 'center';
                    ctx.fillText('📱 Controles Móviles Activos', ctx.canvas.width / 2, 50);
                    ctx.font = '12px Arial';
                    ctx.fillStyle = 'rgba(255, 255, 255, 0.7)';
                    ctx.fillText('Inicia una Raid o Modo Práctica para usar los controles', ctx.canvas.width / 2, 75);
                    ctx.restore();
                }
            },

            update(deltaTime) {
                if (!this.enabled) return;

                // Actualizar movimiento si el joystick está activo
                if (this.joystick.active) {
                    this.updatePlayerMovement();
                }

                // Aplicar movimiento al jugador
                if (this.movementDirection && (MobRaidSystem.active || PracticeModeManager.active)) {
                    // Calcular velocidad basada en el Player.speed
                    const speed = Player.speed || 200; // Velocidad por defecto
                    const moveX = this.movementDirection.x * speed * (deltaTime / 1000);
                    const moveY = this.movementDirection.y * speed * (deltaTime / 1000);

                    // Mover al jugador
                    Player.move(moveX, moveY);
                }

                // Actualizar botones de habilidades si está en juego
                if (MobRaidSystem.active || PracticeModeManager.active) {
                    this.updateAbilityButtons();
                }
            }
        };

        // ===== MOBILE RAID SYSTEM INTEGRATION =====
        // Modificar el sistema de Raids para soportar controles móviles
        const originalRaidRender = MobRaidSystem.render;
        MobRaidSystem.render = function (ctx) {
            originalRaidRender.call(this, ctx);

            // Renderizar controles móviles si están habilitados
            if (MobileControlsSystem.enabled) {
                MobileControlsSystem.render(ctx);
            }
        };

        // ===== MOBILE PRACTICE MODE INTEGRATION =====
        // Modificar el modo práctica para soportar controles móviles
        const originalPracticeRender = PracticeModeManager.render;
        PracticeModeManager.render = function (ctx) {
            originalPracticeRender.call(this, ctx);

            // Renderizar controles móviles si están habilitados
            if (MobileControlsSystem.enabled) {
                MobileControlsSystem.render(ctx);
            }
        };

        // Inicializar controles móviles al cargar el juego
        const originalInitGame = typeof initGame !== 'undefined' ? initGame : function () { };

        function initGameWithMobile() {
            // Inicializar controles móviles primero
            MobileControlsSystem.init();

            // Luego inicializar el juego normal
            if (typeof originalInitGame === 'function') {
                originalInitGame();
            }
        }

        initGameWithMobile();
//     </script>


