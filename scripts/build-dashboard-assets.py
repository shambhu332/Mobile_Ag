"""Rebuild local pinned dashboard assets: run npm ci --prefix assets first."""
from pathlib import Path
import hashlib,json,subprocess
import tempfile,shutil
root=Path(__file__).resolve().parents[1]
modules=root/'assets/node_modules'; static=root/'mobileag/web/static'
config=(static/'theme.js').read_text().replace('tailwind.config =','module.exports =').replace("darkMode: 'class',","content: [process.cwd()+'/mobileag/web/templates/*.html',process.cwd()+'/mobileag/web/static/*.js'], darkMode:'class',")
with tempfile.TemporaryDirectory() as directory:
    configfile=Path(directory)/'config.cjs';configfile.write_text(config)
    source=Path(directory)/'input.css';source.write_text(f'@import "{modules}/tailwindcss/index.css";@config "{configfile}";@source "{root}/mobileag/web/templates";@source "{root}/mobileag/web/static/*.js";')
    subprocess.run([str(modules/'.bin/tailwindcss'),'-c',str(configfile),'-i',str(source),'-o',str(static/'dashboard.css'),'--minify'],cwd=root,check=True)
manifest=[]
for name,file in [('vis-network','standalone/umd/vis-network.min.js'),('chart.js','dist/chart.umd.js'),('lucide','dist/umd/lucide.js')]:
    pkg=json.loads((modules/name/'package.json').read_text());target=static/'vendor'/(name.replace('.','-')+'.js')
    shutil.copyfile(modules/name/file,target)
    for license in (modules/name).glob('LICENSE*'):shutil.copyfile(license,target.parent/(name+'-'+license.name))
    manifest.append({'package':name,'version':pkg['version'],'file':target.name,'sha256':hashlib.sha256(target.read_bytes()).hexdigest()})
(static/'vendor/manifest.json').write_text(json.dumps(manifest,indent=2))

for name in ['tailwindcss','uuid']:
    for license in (modules/name).glob('LICENSE*'):
        shutil.copyfile(license,static/'vendor'/(name+'-'+license.name))
