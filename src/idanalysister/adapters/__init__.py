"""IDA interaction boundary.

Every `ida_*` module import in the entire framework lives under this
package. `core/`, `locators/`, `conventions/`, and `postproc/` depend only on
the `IdaPort` interface (`adapters.ida_port`), never on a concrete
implementation — that indirection is what lets the analysis core run against
`adapters.fake_port.FakeIdaPort` in plain `pytest`, with no IDA installation.
"""
