# idanalysister

A declaratively-configurable IDAPython framework for extracting call-site argument
values and resolving argument values at arbitrary points inside a function body.

See `document/architecture.md` for the design and `document/user_manual.md` for
usage instructions and examples.

## Development setup

```sh
python3.13 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/unit                       # no IDA required
pytest tests/integration -m requires_ida  # requires a local IDA Pro / idalib install
```

The package itself must be imported from inside IDAPython (or via `idalib`) to use
`adapters.ida_port_impl`; `tests/unit` exercises the analysis core through a fake
adapter and needs no IDA installation.
