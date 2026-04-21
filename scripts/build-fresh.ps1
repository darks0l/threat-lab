Remove-Item -Recurse -Force "$PSScriptRoot/../dist" -ErrorAction SilentlyContinue
node "$PSScriptRoot/../node_modules/typescript/lib/tsc.js" --project "$PSScriptRoot/.." --noEmit
