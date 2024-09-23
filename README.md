# Generación de Claves LUOV

Este repositorio contiene una implementación del esquema de firma LUOV (Oil-and-Vinegar No Balanceado basado en Redes) para la generación de claves. El algoritmo está diseñado para ser seguro contra ataques cuánticos.

## Tabla de Contenidos

- [Descripción](#descripción)
- [Requisitos](#requisitos)

## Descripción

LUOV es un algoritmo de firma digital post-cuántico que utiliza redes para la seguridad. Esta implementación se centra en la generación de claves públicas y privadas, siguiendo los parámetros para LUOV-7-83-283.

### Características Principales

- Generación de claves públicas y privadas.
- Generación de bytes aleatorios seguros utilizando SHAKE256.
- Manejo eficiente de operaciones en campos finitos.

## Requisitos

Para ejecutar esta implementación, necesitarás:

- Python 3.6 o superior
- Los siguientes paquetes:
  - `numpy`
  - `pycryptodome`

Puedes instalar los paquetes requeridos usando pip:

```bash 
pip install numpy pycryptodome
