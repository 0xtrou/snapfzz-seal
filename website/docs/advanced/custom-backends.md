# Custom Backends

## Compile Backend

Implement `CompileBackend` trait:

```rust
trait CompileBackend {
    fn detect(&self, path: &Path) -> bool;
    fn compile(&self, path: &Path, out: &Path) -> Result<()>;
}
```

## Sandbox Backend

Implement `SandboxBackend` trait:

```rust
trait SandboxBackend {
    fn provision(&self, config: &SandboxConfig) -> Result<String>;
    fn exec(&self, id: &str, config: &ExecConfig) -> Result<ExecutionResult>;
    fn destroy(&self, id: &str) -> Result<()>;
}
```
