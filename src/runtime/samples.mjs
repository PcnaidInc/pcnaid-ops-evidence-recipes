import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readJSON} from '../shared/io.mjs';

export const ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
export const EXAMPLE_TIME='2026-10-05T12:00:00.000Z';
export const RECIPE_IDS=['cloudflare-zone-ssl','azure-storage-transport','custom-service-controls'];

export async function sample(kind,recipeId='cloudflare-zone-ssl'){
  if(kind==='evidence'&&RECIPE_IDS.includes(recipeId)){
    return {
      recipe:await readJSON(path.join(ROOT,'recipes',recipeId+'.json')),
      input:await readJSON(path.join(ROOT,'examples/evidence',recipeId+'.json')),
      options:{asOf:EXAMPLE_TIME,origin:'fixture'}
    };
  }
  throw new Error('Unknown sample or recipe');
}
