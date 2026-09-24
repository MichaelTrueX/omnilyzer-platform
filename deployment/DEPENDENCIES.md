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

## Separate provisioning installer

The command above records C1's historical dependency proof; it does not grant
future provisioning authority to a system or PATH-selected pip. C31P separately
reviews `pip-26.2.1-py3-none-any.whl` as a provisioning tool with exact size
1,816,632 and SHA-256
`71138adf1f4ca900cdb7d289c21b7494329f2332b6d85f0e1c42108c0384ed3e`.
PyPI identifies that artifact as a Trusted Publishing upload from `pypa/pip`,
commit `634a6ec1a5d9dcc2433571cdb2f4c58a4bb29caf`, tag
`refs/tags/26.2.1`, workflow `.github/workflows/release.yml`, and Sigstore log
index `2341605236`.

The installer is staged and qualified separately from the exact four-wheel
runtime closure. Future C31 execution uses the absolute C24 venv interpreter
with `-I` and a fixed direct-wheel `runpy` bootstrap that asserts the imported
pip version and wheel origin. It does not use system pip, ensurepip, PATH lookup,
or a network bootstrap. C31P installs nothing, and pip is not added to the
runtime lock or accepted runtime wheelhouse.

## C31A offline runtime installation and retained output evidence

C31A fixes the future runtime installation to pip 26.2.1's reviewed
direct-from-wheel bootstrap, isolated mode, a closed environment, umask 0022,
and `install --no-input --disable-pip-version-check --no-cache-dir --no-index
--only-binary=:all: --no-deps --require-hashes --no-compile`. Its find-links
snapshot and requirements lock must be identity-bound provisioning inputs; a
qualified untrusted pathname may not simply be reopened later.

The compact retained installed-tree model is
`provenance/python-runtime-py312-linux-x86_64-installed.json` (57,824 bytes,
SHA-256
`3966c1f4075e2813131f249eb02a473acf0e4d11be61b05f858678b668d2766b`).
It was derived from the four exact wheel bytes above after their filename,
size and SHA-256 checks, using the separately reviewed pip wheel. It records
wheel payload files, compiled extensions, distribution metadata, venv
structure, exact symlink targets and deterministic pip-generated files.
Installed `RECORD` data is hashed output evidence rather than a trust root.
The cffi 2.1.1 installed `RECORD` has 34 rows and is 2,665 bytes with SHA-256
`e17a08d7a6b2a942aca45d2e533ca3c805d02d069a6674fdda39ba5e90193200`.
Pip 26.2.1 uses Python `csv.writer`'s CRLF line ending; the earlier LF-normalized
provenance entry was 2,631 bytes with SHA-256
`7f43cc4e11358f6468993deccf1bcd24bc451b7464deb7ea7b14e4fba361abdb`.
Pip itself is absent from the accepted runtime distributions, and bytecode is
suppressed with `--no-compile` and rejected by the exact-tree qualifier.
