import path from 'node:path';
import {sample,ROOT,RECIPE_IDS} from '../src/runtime/samples.mjs';
import {runAnalysis} from '../src/runtime/service.mjs';
import {saveReport} from '../src/cli.mjs';

for(const recipe of RECIPE_IDS){
  const report=await runAnalysis('evidence',await sample('evidence',recipe));
  await saveReport(report,path.join(ROOT,'reports','evidence-'+recipe),{force:true});
  console.log(recipe,report.summary.result);
}
console.log('Sample evidence packets regenerated in reports/.');
