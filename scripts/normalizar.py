"""Convierte el informe de una herramienta al esquema común resumen.json.

Uso:
  normalizar.py HERRAMIENTA --informe RUTA --codigo N --inicio EPOCH --salida RUTA
                [--objetivo DIR] [--version V] [--rol principal|alternativa]
                [--fin-de-vida RUTA] [--fecha AAAA-MM-DD]

El resumen siempre se escribe. Si la herramienta terminó con un código que no
corresponde a un análisis completo, o su informe no se puede leer, el estado
es "error" y la puerta lo trata como indeterminado (R8).
"""
import argparse
import datetime
import json
import sys
import time

ESQUEMA = 1

# Códigos de salida que indican que el análisis terminó, con o sin hallazgos.
CODIGOS_OK = {
    'gitleaks': {0, 2},        # se ejecuta con --exit-code 2
    'trufflehog': {0, 183},    # 183 con --fail y hallazgos
    'semgrep': {0},
    'trivy-fs': {0},
    'trivy-image': {0},
    'trivy-config': {0},
    'grype': {0},
    'dependency-check': {0},
    'docker-inspect': {0},
    'zap': {0, 1, 2},          # 1 y 2: alertas FAIL o WARN
}

CAPAS = {
    'gitleaks': 'secretos', 'trufflehog': 'secretos',
    'semgrep': 'sast',
    'trivy-fs': 'dependencias', 'dependency-check': 'dependencias',
    'trivy-image': 'imagen', 'grype': 'imagen', 'docker-inspect': 'imagen',
    'trivy-config': 'configuracion',
    'zap': 'dast',
}

ROL_POR_DEFECTO = {
    'trufflehog': 'alternativa', 'dependency-check': 'alternativa', 'grype': 'alternativa',
    'zap': 'complementaria',
}

SEVERIDADES = {
    'CRITICAL': 'critica', 'HIGH': 'alta', 'MEDIUM': 'media', 'MODERATE': 'media',
    'LOW': 'baja', 'NEGLIGIBLE': 'baja', 'INFO': 'baja', 'UNKNOWN': 'desconocida',
    # Semgrep: ERROR equivale a alta, WARNING a media e INFO a baja.
    'ERROR': 'alta', 'WARNING': 'media',
}


def severidad(valor):
    return SEVERIDADES.get(str(valor or '').upper(), 'desconocida')


def hallazgo(id_, categoria, sev, regla, ubicacion='', mensaje='', paquete=None,
             version_instalada=None, corregida_en=None):
    return {
        'id': id_, 'categoria': categoria, 'severidad': sev, 'regla': regla,
        'ubicacion': ubicacion, 'mensaje': mensaje[:300], 'paquete': paquete,
        'version_instalada': version_instalada, 'corregida_en': corregida_en,
    }


def gitleaks(datos, _):
    for f in datos or []:
        commit = (f.get('Commit') or '')[:7]
        ubicacion = f"{f['File']}:{f['StartLine']}"
        yield hallazgo(f"{f['RuleID']}:{ubicacion}:{commit}", 'secreto', 'alta', f['RuleID'],
                       ubicacion, f.get('Description', ''))


def trufflehog(lineas, _):
    for f in lineas:
        git = f.get('SourceMetadata', {}).get('Data', {}).get('Git', {})
        ubicacion = f"{git.get('file', '')}:{git.get('line', '')}"
        commit = (git.get('commit') or '')[:7]
        yield hallazgo(f"{f['DetectorName']}:{ubicacion}:{commit}", 'secreto', 'alta',
                       f['DetectorName'], ubicacion, f.get('DetectorDescription', ''))


def semgrep(datos, _):
    for r in datos.get('results', []):
        ubicacion = f"{r['path']}:{r['start']['line']}"
        yield hallazgo(f"{r['check_id']}:{ubicacion}", 'sast', severidad(r['extra'].get('severity')),
                       r['check_id'], ubicacion, r['extra'].get('message', ''))


def trivy_vulnerabilidades(datos, args):
    for res in datos.get('Results') or []:
        for v in res.get('Vulnerabilities') or []:
            paquete = f"{v['PkgName']}@{v['InstalledVersion']}"
            yield hallazgo(f"{v['VulnerabilityID']}:{paquete}", 'vulnerabilidad', severidad(v.get('Severity')),
                           v['VulnerabilityID'], res.get('Target', ''), v.get('Title', ''),
                           v['PkgName'], v['InstalledVersion'], v.get('FixedVersion') or None)
    so = (datos.get('Metadata') or {}).get('OS') or {}
    if so.get('EOSL'):
        nombre = f"{so.get('Family')} {so.get('Name')}"
        yield hallazgo(f"eosl:{args.objetivo}:{nombre}", 'soporte', 'alta', 'EOSL', args.objetivo,
                       f'Sistema operativo sin soporte: {nombre}')


def trivy_config(datos, args):
    for res in datos.get('Results') or []:
        for m in res.get('Misconfigurations') or []:
            if m.get('Status', 'FAIL') != 'FAIL':
                continue
            ubicacion = f"{args.objetivo}/{res.get('Target', '')}"
            yield hallazgo(f"{m['ID']}:{ubicacion}", 'configuracion', severidad(m.get('Severity')),
                           m['ID'], ubicacion, m.get('Title', ''))


def grype(datos, _):
    for m in datos.get('matches', []):
        v, a = m['vulnerability'], m['artifact']
        paquete = f"{a['name']}@{a['version']}"
        fix = v.get('fix') or {}
        corregida = ', '.join(fix.get('versions') or []) if fix.get('state') == 'fixed' else None
        yield hallazgo(f"{v['id']}:{paquete}", 'vulnerabilidad', severidad(v.get('severity')),
                       v['id'], a.get('type', ''), v.get('description', '') or '',
                       a['name'], a['version'], corregida)


def dependency_check(datos, _):
    # Dependency-Check no informa de la versión corregida: corregida_en queda
    # como "desconocida" y la puerta la trata como corrección disponible.
    for dep in datos.get('dependencies', []):
        paquetes = dep.get('packages') or [{}]
        purl = paquetes[0].get('id', dep.get('fileName', ''))
        nombre, _, version = purl.split('/')[-1].partition('@')
        for v in dep.get('vulnerabilities') or []:
            yield hallazgo(f"{v['name']}:{nombre}@{version}", 'vulnerabilidad', severidad(v.get('severity')),
                           v['name'], dep.get('filePath', ''), v.get('description', '') or '',
                           nombre, version, 'desconocida')


# Variable que las imágenes oficiales definen con la versión del entorno, y
# cuántas cifras forman la rama de soporte (Node: 22; PHP y Python: 8.3, 3.12).
ENTORNOS = {'NODE_VERSION': ('node', 1), 'PHP_VERSION': ('php', 2), 'PYTHON_VERSION': ('python', 2)}


def docker_inspect(datos, args):
    config = datos[0]['Config']
    usuario = config.get('User') or ''
    if usuario.split(':')[0] in ('', 'root', '0'):
        yield hallazgo(f'usuario-root:{args.objetivo}', 'usuario', 'alta', 'R5', args.objetivo,
                       f'Usuario efectivo root (User="{usuario}")')
    with open(args.fin_de_vida) as f:
        fin_de_vida = json.load(f)
    hoy = datetime.date.fromisoformat(args.fecha)
    for variable in config.get('Env') or []:
        nombre, _, version = variable.partition('=')
        if nombre not in ENTORNOS:
            continue
        entorno, cifras = ENTORNOS[nombre]
        rama = '.'.join(version.split('.')[:cifras])
        fecha = fin_de_vida.get(entorno, {}).get(rama)
        if fecha and datetime.date.fromisoformat(fecha) <= hoy:
            yield hallazgo(f'fin-de-vida:{args.objetivo}:{entorno}-{rama}', 'soporte', 'alta', 'R6',
                           args.objetivo, f'{entorno} {version} sin soporte desde {fecha}')


def zap(datos, _):
    for sitio in datos.get('site', []):
        for a in sitio.get('alerts', []):
            riesgo = a.get('riskdesc', '').split(' ')[0]
            sev = {'High': 'alta', 'Medium': 'media', 'Low': 'baja', 'Informational': 'baja'}.get(riesgo, 'desconocida')
            yield hallazgo(f"zap-{a['pluginid']}:{sitio.get('@name', '')}", 'dast', sev,
                           a['pluginid'], sitio.get('@name', ''), a.get('alert', ''))


LECTORES = {
    'gitleaks': gitleaks, 'trufflehog': trufflehog, 'semgrep': semgrep,
    'trivy-fs': trivy_vulnerabilidades, 'trivy-image': trivy_vulnerabilidades,
    'trivy-config': trivy_config, 'grype': grype, 'dependency-check': dependency_check,
    'docker-inspect': docker_inspect, 'zap': zap,
}


def leer_informe(herramienta, ruta):
    with open(ruta) as f:
        texto = f.read()
    if herramienta == 'trufflehog':  # una línea JSON por hallazgo
        return [json.loads(l) for l in texto.splitlines() if l.strip().startswith('{')]
    return json.loads(texto) if texto.strip() else None


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('herramienta', choices=sorted(LECTORES))
    p.add_argument('--informe', required=True)
    p.add_argument('--codigo', type=int, required=True)
    p.add_argument('--inicio', type=float, help='marca de tiempo (date +%%s.%%N) al lanzar la herramienta')
    p.add_argument('--salida', required=True)
    p.add_argument('--objetivo', default='.')
    p.add_argument('--version', default='')
    p.add_argument('--rol')
    p.add_argument('--fin-de-vida', dest='fin_de_vida')
    p.add_argument('--fecha', default=datetime.date.today().isoformat())
    args = p.parse_args(argv)

    resumen = {
        'esquema': ESQUEMA, 'herramienta': args.herramienta, 'version': args.version,
        'capa': CAPAS[args.herramienta], 'rol': args.rol or ROL_POR_DEFECTO.get(args.herramienta, 'principal'),
        'objetivo': args.objetivo, 'estado': 'ok', 'codigo_salida': args.codigo,
        'duracion_s': round(time.time() - args.inicio, 2) if args.inicio else None, 'error': None, 'hallazgos': [],
    }
    try:
        if args.codigo not in CODIGOS_OK[args.herramienta]:
            raise RuntimeError(f'código de salida {args.codigo}')
        datos = leer_informe(args.herramienta, args.informe)
        vistos = set()
        for h in LECTORES[args.herramienta](datos, args):
            if h['id'] not in vistos:  # duplicados exactos dentro de la misma herramienta
                vistos.add(h['id'])
                resumen['hallazgos'].append(h)
    except Exception as e:  # cualquier fallo de lectura deja el análisis sin resultado fiable
        resumen.update(estado='error', error=f'{type(e).__name__}: {e}', hallazgos=[])

    with open(args.salida, 'w') as f:
        json.dump(resumen, f, indent=2, ensure_ascii=False)
    print(f"{args.herramienta} ({args.objetivo}): {resumen['estado']}, {len(resumen['hallazgos'])} hallazgos")


if __name__ == '__main__':
    sys.exit(main())
