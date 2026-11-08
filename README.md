# secdevops-pipeline

Pipeline reutilizable de GitHub Actions para el TFM SecDevOps. Los proyectos no copian la lógica: la llaman desde un workflow mínimo, fijado por SHA.

| Workflow | Estado |
|---|---|
| `.github/workflows/base.yml` | Pipeline base, sin controles de seguridad |
| `.github/workflows/seguro.yml` | Pipeline seguro: los mismos pasos más secretos, SAST, dependencias, imagen, puerta, evidencias y DAST |

## Uso

```yaml
# .github/workflows/ci.yml del proyecto
name: ci

on:
  push:
    branches: [develop, main, 'release/**']
  pull_request:
    branches: [develop, main]

permissions:
  contents: read

jobs:
  base:
    uses: tfm-secdevops-unir/secdevops-pipeline/.github/workflows/base.yml@<sha>
    with:
      proyectos-node: '["backend","frontend"]'
      imagenes: '["backend","frontend"]'
      mongo: true
```

| Entrada | Qué recibe |
|---|---|
| `proyectos-node` | Carpetas Node: `npm ci`, `npm test` y `npm run build` si existe. |
| `proyectos-java` | Carpetas con `pom.xml` (`mvn verify`) o `gradlew` (`gradlew build`). |
| `proyectos-php` | Carpetas con Composer y PHPUnit: `composer install` y `vendor/bin/phpunit`. |
| `imagenes` | Contextos de `docker build`. |
| `mongo` | Arranca `mongo:7` y define `MONGO_URL` en los proyectos Node. |
| `node-version`, `java-version`, `php-version` | Versiones. Por defecto 22, 21 y 8.3. |

Todas son opcionales, pero hace falta al menos un proyecto o una imagen. `prueba.yml` ejecuta el pipeline contra los proyectos de `pruebas/` en cada push.

## Pipeline seguro

`seguro.yml` es un pipeline independiente de `base.yml`: repite sus pasos (política de ramas, pruebas y construcción) y añade los controles. La política que aplica la puerta está en [POLITICA-SEGURIDAD.md](POLITICA-SEGURIDAD.md).

```yaml
jobs:
  seguro:
    uses: tfm-secdevops-unir/secdevops-pipeline/.github/workflows/seguro.yml@<sha>
    permissions:
      contents: read
      id-token: write         # la plantilla localiza su propio commit para cargar la puerta
      security-events: write  # SARIF en la pestaña Security
    secrets: inherit           # opcional: DOCKERHUB_USUARIO, DOCKERHUB_TOKEN y NVD_API_KEY
    with:
      proyectos-node: '["backend","frontend"]'
      imagenes: '["backend","frontend"]'
      mongo: true
      lideres-seguridad: usuario-lider
      compose: docker-compose.yml
```

| Etapa | Principal (decide) | Alternativa (modo completo) |
|---|---|---|
| Secretos (historial completo) | Gitleaks 8.30.1 | TruffleHog 3.99.8, sin verificación |
| SAST | Semgrep 1.183.0 | Ninguna |
| Dependencias de producción | Trivy fs 0.76.2 | OWASP Dependency-Check 13.0.0 |
| Imagen y configuración | Trivy image y config, `docker inspect` | Grype 0.121.1; Docker Scout si hay credenciales |
| SBOM | CycloneDX por imagen, generado con Trivy | |
| DAST | OWASP ZAP 2.17.0 baseline, solo informa | |

Las herramientas se ejecutan como imágenes de Docker fijadas por versión y digest, sin acciones de terceros.

| Entrada | Qué recibe |
|---|---|
| Las de `base.yml` | Proyectos, imágenes, `mongo` y versiones, con el mismo significado. |
| `modo` | `operativo` (por defecto) o `completo`. |
| `semgrep-config` | Paquetes de Semgrep. Por defecto `p/javascript p/nodejs p/expressjs p/owasp-top-ten`. |
| `excepciones` | Archivo de excepciones. Por defecto `.github/excepciones.yml`. |
| `lideres-seguridad` | Usuarios que pueden aprobar excepciones, separados por comas. |
| `fecha-referencia` | Fecha con la que se valida la caducidad de las excepciones. Vacía, la del día. |
| `compose`, `staging-url`, `staging-salud` | Staging efímero y DAST después de la decisión. Sin `compose` no hay DAST. |
| `simular` | Solo para evaluar la puerta: `fallo-herramienta` o `informe-invalido`. |

El check obligatorio es `seguro / resultado`. `prueba.yml` ejecuta `seguro.yml` contra los proyectos de `pruebas/` y `scripts/test_puerta.py` comprueba la lógica de la puerta.

## Proteger el pipeline en cada proyecto

1. Añade `.github/CODEOWNERS` con `/.github/` a nombre de al menos dos responsables del pipeline.
2. En las reglas de `develop` y `main`, exige PR, revisión del code owner y el check `seguro / resultado` (o `base / resultado` si el proyecto solo usa el pipeline base), sin bypass.

Un cambio en este repo no llega a un proyecto hasta que ese proyecto actualiza el SHA.
