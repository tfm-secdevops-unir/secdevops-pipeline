# secdevops-pipeline

Pipeline reutilizable de GitHub Actions para el TFM SecDevOps. Los proyectos no copian la lógica: la llaman desde un workflow mínimo, fijado por SHA.

| Workflow | Estado |
|---|---|
| `.github/workflows/base.yml` | Pipeline base, sin controles de seguridad |
| `.github/workflows/seguro.yml` | Pendiente: mismo pipeline con controles de seguridad |

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

## Proteger el pipeline en cada proyecto

1. Añade `.github/CODEOWNERS` con `/.github/` a nombre de al menos dos responsables del pipeline.
2. En las reglas de `develop` y `main`, exige PR, revisión del code owner y el check `base / resultado`, sin bypass.

Un cambio en este repo no llega a un proyecto hasta que ese proyecto actualiza el SHA.
