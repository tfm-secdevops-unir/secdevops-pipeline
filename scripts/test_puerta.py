"""Casos de lógica de la puerta (Tabla 18) y reglas R1 a R10. Ejecutar: python3 scripts/test_puerta.py"""
import datetime
import json
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
from puerta import decidir  # noqa: E402

FECHA = datetime.date(2026, 11, 7)
LIDERES = {'lider'}
C06 = 'CVE-2021-23337:lodash@4.17.20'


def resumen(herramienta, capa, hallazgos=(), estado='ok', rol='principal', objetivo='.'):
    return {'esquema': 1, 'herramienta': herramienta, 'capa': capa, 'rol': rol, 'objetivo': objetivo,
            'estado': estado, 'hallazgos': list(hallazgos)}


def vuln(id_=C06, sev='alta', corregida='4.17.21'):
    return {'id': id_, 'categoria': 'vulnerabilidad', 'severidad': sev, 'regla': id_.split(':')[0],
            'corregida_en': corregida}


def limpios():
    return [('gitleaks', resumen('gitleaks', 'secretos')), ('semgrep', resumen('semgrep', 'sast')),
            ('trivy-fs', resumen('trivy-fs', 'dependencias'))]


ESPERADOS = ['gitleaks', 'semgrep', 'trivy-fs']


def con_c06(excepciones=()):
    rs = limpios()
    rs[2] = ('trivy-fs', resumen('trivy-fs', 'dependencias', [vuln()]))
    return decidir(rs, ESPERADOS, list(excepciones), LIDERES, FECHA)


def excepcion(**cambios):
    e = {'hallazgo': C06, 'motivo': 'prueba', 'solicitante': 'dev', 'aprobador': 'lider',
         'caduca': (FECHA + datetime.timedelta(days=15)).isoformat()}
    e.update(cambios)
    return e


def test_reglas():
    assert decidir(limpios(), ESPERADOS, [], LIDERES, FECHA)['decision'] == 'pasar'
    assert con_c06()['decision'] == 'bloquear'
    secreto = {'id': 's', 'categoria': 'secreto', 'severidad': 'alta', 'regla': 'github-pat'}
    rs = limpios()
    rs[0] = ('gitleaks', resumen('gitleaks', 'secretos', [secreto]))
    d = decidir(rs, ESPERADOS, [], LIDERES, FECHA)
    assert d['decision'] == 'bloquear' and d['motivos'][0]['regla'] == 'R1'
    aviso = {'id': 'w', 'categoria': 'sast', 'severidad': 'media', 'regla': 'open-redirect'}
    rs = limpios()
    rs[1] = ('semgrep', resumen('semgrep', 'sast', [aviso]))
    assert decidir(rs, ESPERADOS, [], LIDERES, FECHA)['decision'] == 'avisar'  # A03
    ds2 = {'id': 'd', 'categoria': 'configuracion', 'severidad': 'alta', 'regla': 'DS-0002'}
    rs = limpios() + [('c', resumen('trivy-config', 'configuracion', [ds2], objetivo='web'))]
    assert decidir(rs, ESPERADOS, [], LIDERES, FECHA)['decision'] == 'pasar'  # L07: DS-0002 no decide
    zap = {'id': 'z', 'categoria': 'dast', 'severidad': 'alta', 'regla': '10038'}
    rs = limpios() + [('z', resumen('zap', 'dast', [zap], rol='complementaria'))]
    assert decidir(rs, ESPERADOS, [], LIDERES, FECHA)['decision'] == 'pasar'  # R10


def test_alternativa_no_decide():
    rs = limpios() + [('g', resumen('trufflehog', 'secretos', estado='error', rol='alternativa'))]
    d = decidir(rs, ESPERADOS, [], LIDERES, FECHA)
    assert d['decision'] == 'pasar' and d['decision_por_herramienta']['trufflehog'] == 'indeterminado'


def test_e01_excepcion_valida():
    d = con_c06([excepcion()])
    assert d['decision'] == 'pasar' and d['excepciones_aplicadas'][0]['hallazgo'] == C06


def test_e02_sin_aprobacion():
    for e in (excepcion(aprobador=''), excepcion(solicitante='lider')):
        d = con_c06([e])
        assert d['decision'] == 'bloquear' and d['excepciones_invalidas'], e


def test_e03_vencida():
    d = con_c06([excepcion(caduca='2026-11-06')])
    assert d['decision'] == 'bloquear' and 'vencida' in d['excepciones_invalidas'][0]['motivo']


def test_e04_vigencia_excesiva():
    d = con_c06([excepcion(caduca='2026-12-08')])
    assert d['decision'] == 'bloquear' and 'más de 30' in d['excepciones_invalidas'][0]['motivo']


def test_p01_alta_sin_correccion():
    rs = limpios()
    rs[2] = ('trivy-fs', resumen('trivy-fs', 'dependencias', [vuln(corregida=None)]))
    assert decidir(rs, ESPERADOS, [], LIDERES, FECHA)['decision'] == 'avisar'


def test_p02_fallo_de_herramienta():
    rs = limpios()
    rs[0] = ('gitleaks', resumen('gitleaks', 'secretos', estado='error'))
    assert decidir(rs, ESPERADOS, [], LIDERES, FECHA)['decision'] == 'indeterminado'


def test_p03_informe_ausente_o_invalido():
    assert decidir(limpios()[1:], ESPERADOS, [], LIDERES, FECHA)['decision'] == 'indeterminado'
    rs = limpios()
    rs[0] = ('resumen-gitleaks.json', {'basura': True})
    assert decidir(rs, ESPERADOS, [], LIDERES, FECHA)['decision'] == 'indeterminado'


def test_cli_codigo_de_salida():
    puerta = os.path.join(os.path.dirname(__file__), 'puerta.py')
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, 'resumen-gitleaks.json'), 'w') as f:
            json.dump(resumen('gitleaks', 'secretos'), f)
        ok = subprocess.run([sys.executable, puerta, '--resumenes', d, '--esperados', 'gitleaks',
                             '--salida', os.path.join(d, 'decision.json')], capture_output=True)
        roja = subprocess.run([sys.executable, puerta, '--resumenes', d, '--esperados', 'gitleaks', 'semgrep',
                               '--salida', os.path.join(d, 'decision.json')], capture_output=True)
    assert ok.returncode == 0 and roja.returncode == 1


if __name__ == '__main__':
    pruebas = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    for prueba in pruebas:
        prueba()
        print('ok', prueba.__name__)
    print(f'{len(pruebas)} pruebas superadas')
