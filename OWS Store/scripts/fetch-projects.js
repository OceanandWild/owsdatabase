/**
 * Obtiene proyectos desde ows_projects (API) y genera prompts para iconos.
 * Ejecutar: node scripts/fetch-projects.js
 * Requiere que la API https://owsdatabase.onrender.com esté activa.
 */

const API_URL = 'https://owsdatabase.onrender.com';

async function fetchProjects() {
  try {
    const res = await fetch(`${API_URL}/ows-store/projects`);
    const projects = await res.json();
    return projects;
  } catch (err) {
    console.error('Error al obtener proyectos:', err.message);
    return [];
  }
}

function buildIconPrompt(project) {
  const name = project.name || 'Proyecto';
  const desc = project.description || 'Aplicación de Ocean and Wild Studios';
  const slug = project.slug || 'app';
  return {
    slug,
    name,
    filename: `${slug}-icon.ico`,
    prompt: `App icon for "${name}". ${desc}. Style: modern, professional, rounded square icon suitable for Windows desktop. Ocean and Wild Studios brand colors: cyan (#00f3ff) and purple (#bc13fe) on dark background. Clean, minimalist, recognizable at small sizes. No text, only symbolic representation.`,
  };
}

async function main() {
  console.log('Fetching projects from ows_projects...\n');
  const projects = await fetchProjects();

  if (projects.length === 0) {
    console.log('No projects found or API unavailable. Using fallback for OWS Store.\n');
    const fallback = {
      slug: 'ows-store',
      name: 'OWS Store',
      description: 'Central Studio Hub - descubrimiento de juegos, herramientas y experiencias del ecosistema Ocean and Wild Studios',
    };
    const p = buildIconPrompt(fallback);
    console.log(`--- PROMPT PARA: ${p.name} ---`);
    console.log(`Archivo sugerido: icon.ico (para la app Electron)\n`);
    console.log(p.prompt);
    return;
  }

  console.log(`Found ${projects.length} project(s):\n`);

  for (const p of projects) {
    const promptData = buildIconPrompt(p);
    console.log(`\n========== ${promptData.name} ==========`);
    console.log(`Archivo sugerido: ${promptData.filename}\n`);
    console.log(promptData.prompt);
  }
}

main();
