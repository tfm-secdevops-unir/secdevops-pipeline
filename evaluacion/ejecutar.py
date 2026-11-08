"""Lanza los casos del catálogo, espera cada ejecución, descarga sus evidencias y escribe resultados.csv.

Requiere gh autenticado con permiso para lanzar workflows en el repositorio de la aplicación.

  python3 ejecutar.py --repo tfm-secdevops-unir/expense-tracker --casos C01,L01 --repeticiones 3 \
      --modo completo --fecha 2026-11-07 --semilla 20261107 --salida resultados.csv

Cada caso se ejecuta sobre su rama caso/<ID>; P02 y P03 se ejecutan sobre --ref-base con la entrada simular.
El orden se aleatoriza con la semilla, que queda registrada en el CSV.
"""
import argparse
import csv
import datetime
import glob
import hashlib
import json
import os
import random
import re
import subprocess
import time

HERRAMIENTAS = ['gitleaks', 'trufflehog', 'semgrep', 'trivy-fs', 'dependency-check',
                'trivy-image', 'grype', 'trivy-config', 'docker-inspect', 'zap']


def gh(*args, check=True):
    return subprocess.run(['gh', *args], check=check, capture_output=True, text=True).stdout


def fecha(texto):
    return datetime.datetime.fromisoformat(texto.replace('Z', '+00:00'))


def lanzar(repo, ref, entradas):
    antes = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=5)
    args = ['workflow', 'run', 'ci.yml', '-R', repo, '--ref', ref]
    for clave, valor in entradas.items():
        args += ['-f', f'{clave}={valor}']
    gh(*args)
    for _ in range(60):  # la ejecución tarda unos segundos en aparecer
        time.sleep(5)
        runs = json.loads(gh('run', 'list', '-R', repo, '-w', 'ci.yml', '-b', ref, '-e', 'workflow_dispatch',
                             '-L', '5', '--json', 'databaseId,createdAt'))
        nuevas = [r for r in runs if fecha(r['createdAt']) >= antes]
        if nuevas:
            return min(nuevas, key=lambda r: r['createdAt'])['databaseId']
    raise RuntimeError(f'no apareció la ejecución de {ref}')


def evidencias(repo, run, destino):
    os.makedirs(destino, exist_ok=True)
    gh('run', 'download', str(run), '-R', repo, '-n', 'evidencias', '-D', destino, check=False)
    h = hashlib.sha256()
    for ruta in sorted(glob.glob(os.path.join(destino, '**', '*'), recursive=True)):
        if os.path.isfile(ruta):
            h.update(os.path.relpath(ruta, destino).encode())
            with open(ruta, 'rb') as f:
                h.update(f.read())
    return h.hexdigest()


def leer_json(patron):
    rutas = glob.glob(patron, recursive=True)
    if not rutas:
        return None
    with open(rutas[0]) as f:
        return json.load(f)


def fila(caso, repeticion, args, run, destino, sha):
    vista = json.loads(gh('run', 'view', str(run), '-R', args.repo, '--json', 'conclusion,startedAt,updatedAt,jobs'))
    inicio = fecha(vista['startedAt'])
    final = leer_json(os.path.join(destino, 'decision-final', 'decision.json'))
    previa = leer_json(os.path.join(destino, 'decision-previa', 'decision-previa.json'))
    decision = (final or previa or {}).get('decision', 'sin-decision')
    # Tiempo hasta el bloqueo: fin de la puerta que bloquea, desde el inicio de la ejecución.
    t_bloqueo = ''
    for job in vista['jobs']:
        nombre = job['name'].split(' / ')[-1]
        if nombre in ('puerta-previa', 'puerta') and job['conclusion'] == 'failure' and job.get('completedAt'):
            t_bloqueo = round((fecha(job['completedAt']) - inicio).total_seconds(), 1)
            break
    r = {
        'caso': caso['id'], 'tipo': caso['tipo'], 'capa': caso['capa'], 'esperado': caso['esperado'],
        'repeticion': repeticion, 'pipeline': args.pipeline, 'modo': args.modo, 'semilla': args.semilla,
        'run_id': run, 'conclusion': vista['conclusion'], 'decision': decision,
        'correcta': decision == caso['esperado'],
        'duracion_total_s': round((fecha(vista['updatedAt']) - inicio).total_seconds(), 1),
        't_bloqueo_s': t_bloqueo, 'sha256_evidencias': sha,
    }
    clave = re.compile(caso['clave'], re.I) if caso['clave'] else None
    for h in HERRAMIENTAS:
        resumenes = [json.load(open(p)) for p in glob.glob(os.path.join(destino, '**', f'resumen-{h}.json'), recursive=True)]
        if not resumenes:
            continue
        hallazgos = [x for res in resumenes for x in res['hallazgos']]
        r[f'{h}_estado'] = ','.join(sorted({res['estado'] for res in resumenes}))
        r[f'{h}_hallazgos'] = len(hallazgos)
        r[f'{h}_duracion_s'] = round(sum(res['duracion_s'] or 0 for res in resumenes), 2)
        if clave:
            r[f'{h}_detecta'] = any(clave.search(x['id']) or clave.search(x['regla']) for x in hallazgos)
    return r



def main():
    p = argparse.ArgumentParser()
    p.add_argument('--repo', required=True)
    p.add_argument('--catalogo', default=os.path.join(os.path.dirname(__file__), 'catalogo.csv'))
    p.add_argument('--casos', default='')
    p.add_argument('--repeticiones', type=int, default=1)
    p.add_argument('--pipeline', default='seguro', choices=['seguro', 'base'])
    p.add_argument('--modo', default='completo', choices=['operativo', 'completo'])
    p.add_argument('--fecha', default='')
    p.add_argument('--ref-base', default='develop')
    p.add_argument('--semilla', type=int, default=20261107)
    p.add_argument('--evidencias', default='evidencias')
    p.add_argument('--salida', default='resultados.csv')
    args = p.parse_args()

    with open(args.catalogo) as f:
        catalogo = {c['id']: c for c in csv.DictReader(f)}
    ids = args.casos.split(',') if args.casos else list(catalogo)
    plan = [(i, n) for i in ids for n in range(1, args.repeticiones + 1)]
    random.Random(args.semilla).shuffle(plan)

    filas = []
    for i, n in plan:
        caso = catalogo[i]
        ref = args.ref_base if caso['simular'] else f'caso/{i}'
        entradas = {'pipeline': args.pipeline, 'modo': args.modo, 'fecha-referencia': args.fecha,
                    'simular': caso['simular'] or 'ninguno'}
        run = lanzar(args.repo, ref, entradas)
        print(f'{i} rep {n}: ejecución {run}', flush=True)
        gh('run', 'watch', str(run), '-R', args.repo, '--interval', '15', check=False)
        destino = os.path.join(args.evidencias, f'{i}-{n}-{run}')
        r = fila(caso, n, args, run, destino, evidencias(args.repo, run, destino))
        print(f"  decisión {r['decision']} (esperado {caso['esperado']}), {r['duracion_total_s']} s", flush=True)
        filas.append(r)

    columnas = list(dict.fromkeys(k for r in filas for k in r))
    with open(args.salida, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=columnas)
        w.writeheader()
        w.writerows(filas)
    print(f'{len(filas)} filas en {args.salida}')


if __name__ == '__main__':
    main()
