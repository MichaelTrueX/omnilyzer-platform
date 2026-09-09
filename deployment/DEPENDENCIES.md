# Deployment control-plane dependencies

Task 014 C1 has a dedicated dependency boundary for Ubuntu 24.04, Linux x86_64, CPython 3.12, and glibc. Python is bounded to `>=3.12,<3.13`. The direct dependencies are exactly `PyJWT[crypto]==2.13.0` and `cryptography==50.0.1`; the complete binary-wheel closure also pins `cffi==2.1.1` and `pycparser==3.0`. Gunicorn is not part of C1.

## Reviewed artifacts

| Package | Relationship | Accepted wheel | SHA-256 | License | Upstream provenance |
|---|---|---|---|---|---|
| PyJWT 2.13.0 | direct | `pyjwt-2.13.0-py3-none-any.whl` | `66adcc2aff09b3f1bbd95fc1e1577df8ac8723c978552fd43304c8a290ac5728` | MIT | [PyJWT source](https://github.com/jpadilla/pyjwt), [PyPI project](https://pypi.org/project/PyJWT/2.13.0/) |
| cryptography 50.0.1 | direct | `cryptography-50.0.1-cp311-abi3-manylinux_2_34_x86_64.whl` | `51afcfceb15597cf2635068e4ac9a56b2abde622edde17f37d85fd7b5306497a` | Apache-2.0 OR BSD-3-Clause | [cryptography source](https://github.com/pyca/cryptography), [PyPI project](https://pypi.org/project/cryptography/50.0.1/) |
| cffi 2.1.1 | transitive | `cffi-2.1.1-cp312-cp312-manylinux2014_x86_64.manylinux_2_17_x86_64.whl` | `c1453022f490d2459a11819d83ad1d586e9ff65a12ac3e705ffebd46d3685dcf` | MIT-0 | [cffi source](https://github.com/python-cffi/cffi), [PyPI project](https://pypi.org/project/cffi/2.1.1/) |
| pycparser 3.0 | transitive | `pycparser-3.0-py3-none-any.whl` | `b727414169a36b7d524c1c3e31839a521725078d7b2ff038656844266160a992` | BSD-3-Clause | [pycparser source](https://github.com/eliben/pycparser), [PyPI project](https://pypi.org/project/pycparser/3.0/) |

The filenames, dependency metadata, license expressions, project links, and bytes were inspected from the downloaded wheels. The lock contains no source-distribution filename or hash. These records establish the reviewed dependency inputs; they do not establish a production wheelhouse.

## Future offline installation contract

A future reviewed wheelhouse must contain only the four exact wheel files above. Installation must use the bounded Python series and all of these controls together:

```bash
python3 -m pip install \
  --require-hashes \
  --only-binary=:all: \
  --no-index \
  --find-links <reviewed-wheelhouse> \
  --requirement deployment/requirements-linux-x86_64-py312.lock
```

Task 014 C1 proved this command shape in a securely created temporary virtual environment after downloading the reviewed wheels to a temporary wheelhouse. Neither that temporary proof nor this repository creates, installs, or claims a production wheelhouse. Source builds remain forbidden.
