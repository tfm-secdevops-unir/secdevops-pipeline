# Política de seguridad del pipeline

Versión 1, del 7 de noviembre de 2026. La aplica `scripts/puerta.py` en `seguro.yml`. Cualquier cambio en esta política entra por pull request y lo aprueba el líder de seguridad.

## Roles

| Rol | Responsabilidad |
|---|---|
| Arquitecto de plataforma | Mantiene `base.yml`, la etapa de imagen, el staging y la carpeta `.github/` de cada proyecto. |
| Líder de seguridad | Mantiene esta política y la puerta, y aprueba las excepciones. |
| Ingeniero de calidad | Mantiene el catálogo de casos, el análisis de dependencias y la medición. |

## Separación entre detección y decisión

Las herramientas solo generan informes. Cada etapa convierte su informe al esquema común (`resumen-*.json`, ver más abajo) y la puerta decide con esos resúmenes. Ninguna herramienta corta el pipeline por su cuenta.

La puerta produce uno de cuatro estados:

| Estado | Check obligatorio | Significado |
|---|---|---|
| `pasar` | Verde | Sin hallazgos que exijan una acción. |
| `avisar` | Verde | Hay hallazgos que no exigen detener la integración; quedan en el resumen de la ejecución. |
| `bloquear` | Rojo | Una regla de bloqueo se cumple. Las reglas de rama impiden integrar en `develop` o `main`. |
| `indeterminado` | Rojo | Falta un análisis o su informe no es válido. No cuenta como detección. |

Si hay motivos de varios estados, gana el más grave en este orden: indeterminado, bloquear, avisar, pasar.

## Reglas

| Regla | Condición | Decisión |
|---|---|---|
| R1 | Cualquier secreto detectado en el árbol o en el historial | Bloquear |
| R2 | Hallazgo SAST con severidad ERROR (WARNING o INFO: avisar) | Bloquear |
| R3 | Vulnerabilidad crítica o alta con corrección disponible en una dependencia de producción (medias, bajas o sin corrección: avisar) | Bloquear |
| R4 | Vulnerabilidad crítica o alta con corrección disponible en la imagen construida (medias, bajas o sin corrección: avisar) | Bloquear |
| R5 | Usuario efectivo root según `docker inspect`: `User` vacío, `root` o `0`. DS-0002 se registra, pero no decide por sí solo | Bloquear |
| R6 | Imagen base sin soporte: Trivy informa EOSL del sistema operativo, o el entorno de ejecución figura como fin de vida en `politica/fin-de-vida.json` | Bloquear |
| R7 | Fallo de configuración de severidad alta distinto de usuario (medio o bajo: avisar) | Bloquear |
| R8 | Fallo de herramienta, informe ausente o informe inválido | Indeterminado |
| R9 | Excepción válida sobre un hallazgo | Omite el hallazgo y deja constancia |
| R10 | Hallazgo de OWASP ZAP | Solo informe |

Severidades: Semgrep ERROR equivale a alta, WARNING a media e INFO a baja.

Solo deciden las herramientas principales: Gitleaks, Semgrep, Trivy (fs, image y config) y `docker inspect`. TruffleHog, OWASP Dependency-Check y Grype se ejecutan en el modo completo y su decisión se calcula aparte, en `decision_por_herramienta`, sin alterar la decisión operativa. Docker Scout y OWASP ZAP solo informan.

Dependency-Check no informa de la versión corregida. Para calcular su decisión aparte, una vulnerabilidad crítica o alta se trata como corregible.

## Excepciones (R9)

Las excepciones se declaran en `.github/excepciones.yml` del proyecto. Esa carpeta está protegida por `CODEOWNERS`, de modo que añadir una excepción exige la revisión de su propietario.

```yaml
excepciones:
  - hallazgo: CVE-2021-23337:lodash@4.17.20   # identificador del hallazgo, tal como aparece en la decisión
    motivo: Sin versión compatible hasta la migración de la API de informes
    solicitante: usuario-que-la-pide
    aprobador: usuario-lider-de-seguridad
    caduca: 2026-12-01
```

Una excepción es válida solo si cumple todo lo siguiente:

1. Tiene `hallazgo`, `motivo`, `solicitante`, `aprobador` y `caduca`.
2. El aprobador figura en la entrada `lideres-seguridad` del proyecto.
3. El aprobador no es el solicitante.
4. La caducidad no ha vencido en la fecha de referencia y no está a más de 30 días de ella.

Una excepción inválida o vencida se ignora, se informa en el resumen de la ejecución y se aplica la regla. Un archivo de excepciones que no se puede leer da `indeterminado`.

La fecha de referencia es la del día de la ejecución. Para repetir una evaluación con la misma fecha se usa la entrada `fecha-referencia`.

Límite conocido: los campos `solicitante` y `aprobador` son texto. La aprobación efectiva es la revisión del pull request que modifica el archivo, exigida por `CODEOWNERS`.

## Modos de ejecución

| Modo | Uso | Comportamiento |
|---|---|---|
| `operativo` | Push y pull request | Deciden las herramientas principales. Si la puerta previa (secretos, código y dependencias) bloquea, no se ejecutan las pruebas ni la etapa de imagen. Mide el tiempo hasta el bloqueo. |
| `completo` | Evaluación, por ejecución manual | Se ejecutan también las alternativas y todas las etapas terminan aunque haya hallazgos. La puerta final decide con todos los informes. Mide detección y coste por etapa. |

## Evidencias

Cada herramienta guarda su informe y su resumen como artefacto, también cuando la puerta bloquea o una etapa falla. El job `evidencias` los reúne en el artefacto `evidencias`, que se conserva 90 días, y envía los SARIF a la pestaña Security. Los informes de secretos se guardan con el secreto enmascarado: Gitleaks con `--redact` y TruffleHog sin los campos `Raw` y `RawV2`.

## Esquema común de resumen

Cada etapa escribe un `resumen-<herramienta>.json`:

| Campo | Contenido |
|---|---|
| `esquema` | Versión del esquema (1). |
| `herramienta`, `version` | Herramienta y versión que generó el informe. |
| `capa` | `secretos`, `sast`, `dependencias`, `imagen`, `configuracion` o `dast`. |
| `rol` | `principal`, `alternativa` o `complementaria`. |
| `objetivo` | `.` para el repositorio o el contexto de la imagen analizada. |
| `estado` | `ok` si el análisis terminó, `error` si no. |
| `codigo_salida`, `duracion_s`, `error` | Código de salida, duración del paso y motivo del error. |
| `hallazgos` | Lista con `id`, `categoria`, `severidad`, `regla`, `ubicacion`, `mensaje`, `paquete`, `version_instalada` y `corregida_en`. |

El `id` identifica el hallazgo para las excepciones y la deduplicación: `CVE:paquete@versión` en vulnerabilidades, `regla:archivo:línea:commit` en secretos, `regla:archivo:línea` en SAST y `regla:archivo` en configuración.

## Fin de vida (R6)

`politica/fin-de-vida.json` recoge las fechas de fin de soporte de Node.js, PHP y Python según endoflife.date. La rama del entorno se toma de la variable que definen las imágenes oficiales (`NODE_VERSION`, `PHP_VERSION`, `PYTHON_VERSION`). Java no está en la lista: las imágenes de Temurin indican la versión en otro formato y su soporte depende del distribuidor. Las imágenes Java solo se evalúan por el EOSL del sistema operativo.
