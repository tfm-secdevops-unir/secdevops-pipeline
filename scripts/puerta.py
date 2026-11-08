"""Puerta de decisión: aplica la política R1 a R10 a los resúmenes de las etapas.

Uso:
  puerta.py --resumenes DIR --esperados gitleaks semgrep trivy-fs ... --salida decision.json
            [--excepciones excepciones.json] [--lideres jbroncano,...] [--fecha AAAA-MM-DD]
            [--fase previa|final] [--modo operativo|completo]

Estados: pasar, avisar, bloquear e indeterminado. El código de salida es 0 con
pasar o avisar y 1 con bloquear o indeterminado, para que el check quede en rojo.
La política está descrita en POLITICA-SEGURIDAD.md.
"""
import argparse
import datetime
import glob
import json
import os
import sys

ORDEN = ['pasar', 'avisar', 'bloquear', 'indeterminado']
CAMPOS_HALLAZGO = {'id', 'categoria', 'severidad', 'regla'}
CAMPOS_RESUMEN = {'esquema', 'herramienta', 'capa', 'rol', 'objetivo', 'estado', 'hallazgos'}
CADUCIDAD_MAXIMA = 30
GRAVES = ('critica', 'alta')


def regla(h, capa):
    """Devuelve (regla, decisión) para un hallazgo, según la Tabla 16 de la memoria."""
    cat, sev = h['categoria'], h['severidad']
    if cat == 'secreto':
        return 'R1', 'bloquear'
    if cat == 'sast':
        return 'R2', 'bloquear' if sev == 'alta' else 'avisar'
    if cat == 'vulnerabilidad':
        r = 'R3' if capa == 'dependencias' else 'R4'
        return r, 'bloquear' if sev in GRAVES and h.get('corregida_en') else 'avisar'
    if cat == 'usuario':
        return 'R5', 'bloquear'
    if cat == 'soporte':
        return 'R6', 'bloquear'
    if cat == 'configuracion':
        if h['regla'] in ('DS-0002', 'AVD-DS-0002'):  # el usuario lo decide R5 con docker inspect
            return 'R5', 'informar'
        return 'R7', 'bloquear' if sev in GRAVES else 'avisar'
    if cat == 'dast':
        return 'R10', 'informar'
    return 'R8', 'indeterminado'  # categoría desconocida: no se puede decidir


def validar_excepcion(e, lideres, fecha):
    """Devuelve el motivo por el que la excepción no es válida, o None si lo es (R9)."""
    faltan = [c for c in ('hallazgo', 'motivo', 'solicitante', 'aprobador', 'caduca') if not e.get(c)]
    if faltan:
        return f"faltan campos: {', '.join(faltan)}"
    if e['aprobador'] not in lideres:
        return f"{e['aprobador']} no es líder de seguridad"
    if e['aprobador'] == e['solicitante']:
        return 'aprobada por el propio solicitante'
    try:
        caduca = datetime.date.fromisoformat(str(e['caduca']))
    except ValueError:
        return f"caducidad con formato inválido: {e['caduca']}"
    dias = (caduca - fecha).days
    if dias < 0:
        return f'vencida el {caduca}'
    if dias > CADUCIDAD_MAXIMA:
        return f'vigencia de {dias} días, más de {CADUCIDAD_MAXIMA}'
    return None


def resumen_valido(r):
    return (isinstance(r, dict) and CAMPOS_RESUMEN <= r.keys() and r['esquema'] == 1
            and r['estado'] in ('ok', 'error') and isinstance(r['hallazgos'], list)
            and all(isinstance(h, dict) and CAMPOS_HALLAZGO <= h.keys() for h in r['hallazgos']))


def clave(r):
    return r['herramienta'] if r['objetivo'] in ('.', '') else f"{r['herramienta']}:{r['objetivo']}"


def decidir(resumenes, esperados, excepciones, lideres, fecha):
    motivos, aplicadas, invalidas, por_herramienta = [], [], [], {}

    validas = {}
    for e in excepciones:
        error = validar_excepcion(e, lideres, fecha)
        if error:
            invalidas.append({'hallazgo': e.get('hallazgo'), 'motivo': error})
        else:
            validas[e['hallazgo']] = e

    presentes = {}
    for ruta, r in resumenes:
        if not resumen_valido(r):
            motivos.append({'regla': 'R8', 'decision': 'indeterminado', 'herramienta': os.path.basename(ruta),
                            'hallazgo': None, 'detalle': 'resumen inválido'})
            continue
        presentes[clave(r)] = r

    for k in esperados:
        if k not in presentes:
            motivos.append({'regla': 'R8', 'decision': 'indeterminado', 'herramienta': k,
                            'hallazgo': None, 'detalle': 'resumen ausente'})

    for k, r in sorted(presentes.items()):
        propia = 'pasar'
        if r['estado'] == 'error':
            propia = 'indeterminado'
            if r['rol'] == 'principal':
                motivos.append({'regla': 'R8', 'decision': 'indeterminado', 'herramienta': k,
                                'hallazgo': None, 'detalle': r.get('error') or 'la herramienta falló'})
        for h in r['hallazgos']:
            num, decision = regla(h, r['capa'])
            if h['id'] in validas and decision in ('bloquear', 'avisar'):
                if r['rol'] == 'principal':
                    aplicadas.append({'hallazgo': h['id'], 'regla': num, 'decision_omitida': decision,
                                      'aprobador': validas[h['id']]['aprobador'],
                                      'caduca': str(validas[h['id']]['caduca'])})
                continue
            propia = max(propia, decision, key=lambda d: ORDEN.index(d) if d in ORDEN else 0)
            if r['rol'] == 'principal' and decision != 'pasar':
                motivos.append({'regla': num, 'decision': decision, 'herramienta': k, 'hallazgo': h['id'],
                                'detalle': f"{h['severidad']} {h.get('mensaje', '')}"[:200]})
        por_herramienta[k] = propia

    decisiones = {m['decision'] for m in motivos}
    final = next((d for d in reversed(ORDEN) if d in decisiones), 'pasar')
    return {'decision': final, 'motivos': motivos, 'excepciones_aplicadas': aplicadas,
            'excepciones_invalidas': invalidas, 'decision_por_herramienta': por_herramienta}


def markdown(d):
    lineas = [f"### Puerta {d['fase']} ({d['modo']}): **{d['decision'].upper()}**", '',
              f"Fecha de referencia: {d['fecha_referencia']}", '']
    if d['motivos']:
        lineas += ['| Regla | Decisión | Herramienta | Hallazgo |', '|---|---|---|---|']
        lineas += [f"| {m['regla']} | {m['decision']} | {m['herramienta']} | `{m['hallazgo'] or m['detalle']}` |"
                   for m in d['motivos']]
    for e in d['excepciones_aplicadas']:
        lineas.append(f"- Excepción aplicada (R9): `{e['hallazgo']}`, aprobada por {e['aprobador']}, caduca {e['caduca']}")
    for e in d['excepciones_invalidas']:
        lineas.append(f"- Excepción inválida, se aplica la regla: `{e['hallazgo']}` ({e['motivo']})")
    if d['decision_por_herramienta']:
        lineas += ['', '| Herramienta | Decisión con sus hallazgos |', '|---|---|']
        lineas += [f'| {k} | {v} |' for k, v in d['decision_por_herramienta'].items()]
    return '\n'.join(lineas) + '\n'


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument('--resumenes', required=True)
    p.add_argument('--esperados', nargs='*', default=[])
    p.add_argument('--excepciones')
    p.add_argument('--lideres', default='')
    p.add_argument('--fecha', default='')
    p.add_argument('--fase', default='final')
    p.add_argument('--modo', default='operativo')
    p.add_argument('--salida', required=True)
    args = p.parse_args(argv)

    fecha = datetime.date.fromisoformat(args.fecha) if args.fecha else datetime.date.today()
    lideres = {x.strip() for x in args.lideres.split(',') if x.strip()}

    resumenes = []
    for ruta in sorted(glob.glob(os.path.join(args.resumenes, '**', 'resumen-*.json'), recursive=True)):
        try:
            with open(ruta) as f:
                resumenes.append((ruta, json.load(f)))
        except (OSError, ValueError):
            resumenes.append((ruta, None))

    excepciones, error_excepciones = [], None
    if args.excepciones and os.path.exists(args.excepciones):
        try:
            with open(args.excepciones) as f:
                excepciones = (json.load(f) or {}).get('excepciones') or []
        except (OSError, ValueError, AttributeError) as e:
            error_excepciones = str(e)

    d = decidir(resumenes, args.esperados, excepciones, lideres, fecha)
    if error_excepciones:  # un archivo de excepciones ilegible no puede ignorarse en silencio
        d['motivos'].append({'regla': 'R8', 'decision': 'indeterminado', 'herramienta': 'excepciones',
                             'hallazgo': None, 'detalle': error_excepciones})
        d['decision'] = 'indeterminado'
    d.update(fase=args.fase, modo=args.modo, fecha_referencia=fecha.isoformat())

    with open(args.salida, 'w') as f:
        json.dump(d, f, indent=2, ensure_ascii=False)
    texto = markdown(d)
    print(texto)
    if os.environ.get('GITHUB_STEP_SUMMARY'):
        with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
            f.write(texto)
    return 0 if d['decision'] in ('pasar', 'avisar') else 1


if __name__ == '__main__':
    sys.exit(main())
