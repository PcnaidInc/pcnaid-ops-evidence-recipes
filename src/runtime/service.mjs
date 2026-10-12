import {evaluateEvidence} from '../evidence/runner.mjs';
import {assert,object} from '../shared/data.mjs';

export function runAnalysis(kind,payload){
  object(payload,'analysis request');
  if(kind==='evidence'){
    const options=payload.options??{};
    assert(options.origin!=='live_api','Browser/imported responses cannot claim live API provenance');
    return evaluateEvidence(payload.recipe,payload.input,{asOf:options.asOf,origin:options.origin??'supplied_file'});
  }
  throw new Error('Unsupported analysis');
}
