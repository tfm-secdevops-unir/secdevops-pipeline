"""Crea una rama caso/<ID> por caso del catálogo sobre la línea base de la aplicación de prueba.

Uso: python3 sembrar_casos.py REPO_APLICACION RAMA_BASE DIRECTORIO_TRABAJO [ID ...]

Cada rama tiene un único cambio identificable (C03 tiene dos commits: añadir y borrar el token).
Los secretos son ficticios, generados con una semilla fija e inválidos (RNF2).
Los commits se crean sin hooks: el aviso local de pre-commit bloquearía los casos de secretos.
"""
import json
import os
import random
import re
import subprocess
import sys

REPO, BASE, TRABAJO = sys.argv[1:4]
SOLO = set(sys.argv[4:])
rnd = random.Random(20261107)
ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
TOKEN = 'ghp_' + ''.join(rnd.choice(ALNUM) for _ in range(36))
TOKEN_C03 = 'ghp_' + ''.join(rnd.choice(ALNUM) for _ in range(36))
AWS_ID = 'AKIA' + ''.join(rnd.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567') for _ in range(16))
AWS_SECRETO = ''.join(rnd.choice(ALNUM + '+/') for _ in range(40))
BACKEND = 'backend/Dockerfile'
FROM_NODE = re.compile(r'^FROM node:22-alpine@sha256:[0-9a-f]+', re.M)
arbol = ''


def sh(*args, cwd=None):
    return subprocess.run(args, cwd=cwd or REPO, check=True, text=True, capture_output=True).stdout


def leer(ruta):
    with open(os.path.join(arbol, ruta)) as f:
        return f.read()


def escribir(ruta, texto):
    with open(os.path.join(arbol, ruta), 'w') as f:
        f.write(texto)


def reemplazar(ruta, viejo, nuevo):
    texto = leer(ruta)
    assert viejo in texto, (ruta, viejo)
    escribir(ruta, texto.replace(viejo, nuevo, 1))


def ruta_nueva(codigo):
    reemplazar('backend/src/app.js', 'module.exports', codigo + '\nmodule.exports')


def dependencia(nombre, version, overrides=None):
    pkg = json.loads(leer('backend/package.json'))
    pkg['dependencies'][nombre] = version
    if overrides:
        pkg['overrides'] = overrides
    escribir('backend/package.json', json.dumps(pkg, indent=2) + '\n')
    # Lockfile v2: lo leen tanto npm 10 como el npm 6 de node:14 (caso C08).
    sh('npm', 'install', '--package-lock-only', '--lockfile-version', '2', '--ignore-scripts', '--no-audit',
       '--no-fund', cwd=os.path.join(arbol, 'backend'))


def excepcion(caduca, solicitante='f4biaan', aprobador='jbroncano'):
    """Excepción sobre C06: cubre todos los hallazgos de lodash 4.17.20 (dos bloquean y dos avisan)."""
    dependencia('lodash', '4.17.20')
    entradas = ''
    for cve in ('CVE-2021-23337', 'CVE-2026-4800', 'CVE-2020-28500', 'CVE-2025-13465'):
        entradas += f'  - hallazgo: {cve}:lodash@4.17.20\n    motivo: Caso de lógica de la puerta sobre C06\n'
        entradas += f'    solicitante: {solicitante}\n' if solicitante else ''
        entradas += f'    aprobador: {aprobador}\n' if aprobador else ''
        entradas += f'    caduca: {caduca}\n'
    escribir('.github/excepciones.yml', leer('.github/excepciones.yml').rstrip('\n') + '\n' + entradas)


def cambiar_from(nuevo):
    escribir(BACKEND, FROM_NODE.sub('FROM ' + nuevo, leer(BACKEND), count=1))


def quitar_ultimo_user(ruta):
    texto = leer(ruta)
    i = texto.rindex('USER 101\n')
    escribir(ruta, texto[:i] + texto[i + len('USER 101\n'):])


def l01():
    ruta_nueva("""app.get('/api/expenses/total', async (req, res) => {
  const [resultado] = await Expense.aggregate([{ $group: { _id: null, total: { $sum: '$amount' } } }]);
  res.json({ total: resultado ? resultado.total : 0 });
});
""")
    escribir('backend/test/expenses.test.js', leer('backend/test/expenses.test.js') + """
test('GET /api/expenses/total suma los importes', async () => {
  await request(app).post('/api/expenses').send({ description: 'pan', amount: 2 });
  const res = await request(app).get('/api/expenses/total');
  expect(res.status).toBe(200);
  expect(res.body.total).toBe(2);
});
""")


def l05():
    base = FROM_NODE.search(leer(BACKEND)).group(0)[5:]
    escribir(BACKEND, f'''FROM {base} AS dependencias
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

FROM {base}
RUN rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg
WORKDIR /app
COPY --from=dependencias /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:3000/api/health || exit 1
CMD ["node", "src/server.js"]
''')


CASOS = {
    'C01': ('Token ficticio con formato ghp_ en backend/src/app.js',
            lambda: reemplazar('backend/src/app.js', 'const app = express();', f"const GITHUB_TOKEN = '{TOKEN}';\n\nconst app = express();")),
    'C02': ('Clave ficticia con formato AKIA y su secreto en un .env incluido en el commit',
            lambda: escribir('.env', f'AWS_ACCESS_KEY_ID={AWS_ID}\nAWS_SECRET_ACCESS_KEY={AWS_SECRETO}\n')),
    'C04': ('eval(req.body.expr) en una ruta de Express',
            lambda: ruta_nueva("app.post('/api/calcular', (req, res) => {\n  res.json({ resultado: eval(req.body.expr) });\n});\n")),
    'C05': ('Expense.find con $where concatenado con req.query, y Expense.find(req.query)',
            lambda: ruta_nueva("app.get('/api/buscar', async (req, res) => {\n"
                               "  const porTexto = await Expense.find({ $where: \"this.description == '\" + req.query.texto + \"'\" });\n"
                               "  const porFiltro = await Expense.find(req.query);\n"
                               "  res.json({ porTexto, porFiltro });\n});\n")),
    'C06': ('lodash 4.17.20 como dependencia directa de producción', lambda: dependencia('lodash', '4.17.20')),
    'C07': ('mkdirp 0.5.5 con minimist fijado en 1.2.5 (transitiva)', lambda: dependencia('mkdirp', '0.5.5', {'minimist': '1.2.5'})),
    'C08': ('FROM node:14-alpine, con USER node', lambda: cambiar_from('node:14-alpine')),
    'C09': ('FROM node:22-alpine sin USER', lambda: reemplazar(BACKEND, 'USER node\n', '')),
    'A01': ('FROM node:latest, con USER node', lambda: cambiar_from('node:latest')),
    'A02': ('got 11.8.3 como dependencia de producción', lambda: dependencia('got', '11.8.3')),
    'A03': ('res.redirect(req.query.u)', lambda: ruta_nueva("app.get('/api/ir', (req, res) => {\n  res.redirect(req.query.u);\n});\n")),
    'A04': ('Dockerfile sin HEALTHCHECK', lambda: escribir(BACKEND, re.sub(r'^HEALTHCHECK .*\n', '', leer(BACKEND), flags=re.M))),
    'L01': ('Nueva ruta de consulta en el backend, con su prueba', l01),
    'L02': ('Cambio de texto en el frontend', lambda: reemplazar('frontend/src/App.jsx', '<h1>Gastos</h1>', '<h1>Mis gastos</h1>')),
    'L03': ('Documentación con TU_TOKEN_AQUI y la clave de ejemplo de AWS',
            lambda: escribir('docs-configuracion.md', '# Configuración\n\nDefine el token de GitHub en `GITHUB_TOKEN=TU_TOKEN_AQUI`.\n\n'
                             'Ejemplo de credenciales de AWS de la documentación oficial:\n\n```\n'
                             'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n```\n')),
    'L04': ('lodash 4.18.1 (versión corregida de C06)', lambda: dependencia('lodash', '4.18.1')),
    'L05': ('Dockerfile multietapa, USER node y base con digest', l05),
    'L06': ('process.env.API_TOKEN en lugar de un valor',
            lambda: reemplazar('backend/src/app.js', 'const app = express();', 'const API_TOKEN = process.env.API_TOKEN;\n\nconst app = express();')),
    'L07': ('FROM nginxinc/nginx-unprivileged:alpine sin USER en la etapa final', lambda: quitar_ultimo_user('frontend/Dockerfile')),
    # Casos de lógica de la puerta, con fecha de referencia 2026-11-07.
    'E01': ('Excepción aprobada y vigente sobre C06 (caduca a 15 días)', lambda: excepcion('2026-11-22')),
    'E02': ('Excepción sin aprobación sobre C06 (aprobada por el propio solicitante)',
            lambda: excepcion('2026-11-22', solicitante='jbroncano', aprobador='jbroncano')),
    'E03': ('Excepción vencida sobre C06', lambda: excepcion('2026-11-06')),
    'E04': ('Excepción con vigencia excesiva sobre C06 (más de 30 días)', lambda: excepcion('2026-12-31')),
}


def commit(mensaje):
    sh('git', 'add', '-A', '-f', '.', cwd=arbol)
    sh('git', '-c', 'core.hooksPath=/dev/null', 'commit', '-q', '-m', mensaje, cwd=arbol)


for caso in ['C01', 'C02', 'C03'] + [c for c in CASOS if c[0] != 'C' or c > 'C03']:
    if SOLO and caso not in SOLO:
        continue
    rama = f'caso/{caso}'
    arbol = os.path.join(os.path.abspath(TRABAJO), caso)
    subprocess.run(['git', 'worktree', 'remove', '--force', arbol], cwd=REPO, capture_output=True)
    sh('git', 'worktree', 'add', '-q', '-B', rama, arbol, BASE)
    if caso == 'C03':
        reemplazar('backend/src/app.js', 'const app = express();', f"const GITHUB_TOKEN = '{TOKEN_C03}';\n\nconst app = express();")
        commit('test(C03): token ficticio añadido')
        reemplazar('backend/src/app.js', f"const GITHUB_TOKEN = '{TOKEN_C03}';\n\n", '')
        commit('test(C03): token ficticio eliminado en el commit siguiente')
    else:
        descripcion, aplicar = CASOS[caso]
        aplicar()
        commit(f'test({caso}): {descripcion}')
    sh('git', 'worktree', 'remove', '--force', arbol)
    print(rama, sh('git', 'log', '--oneline', '-1', rama).strip())
