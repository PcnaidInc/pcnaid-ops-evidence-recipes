import {spawnSync} from 'node:child_process';

const res = spawnSync(process.execPath, ['--test', 'tests/evidence.test.mjs', 'tests/cli.test.mjs', 'tests/core.test.mjs'], {stdio: 'inherit'});
process.exit(res.status ?? 1);
