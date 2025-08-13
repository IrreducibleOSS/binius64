# Binius Examples

This crate provides example circuits for the Binius zero-knowledge proof system. These examples serve multiple purposes:

- **Testing**: Verify that the Binius framework works correctly with real-world circuits
- **Profiling**: Benchmark and optimize the performance of proof generation and verification
- **Learning**: Demonstrate best practices and patterns for building circuits with Binius

## Available Examples

- **sha256**: SHA-256 hash function implementation demonstrating efficient binary field arithmetic
- **zklogin**: Zero-knowledge authentication circuit for JWT verification

Each example is a standalone binary that can be run with customizable parameters to test different configurations and input sizes.

## Creating New Circuit Examples

This guide shows how to create new circuit examples using the standardized `ExampleCircuit` trait and the simplified CLI API.

## Quick Start Template

Here's a minimal template for a new circuit example:

```rust
use anyhow::{ensure, Result};
use binius_examples::{Cli, ExampleCircuit};
use binius_frontend::compiler::{circuit::WitnessFiller, CircuitBuilder, Wire};
use clap::Args;

// The main example struct that holds circuit components
struct MyCircuitExample {
    params: Params,
    // Store any gadgets or wire references needed for witness population
    // e.g., gadget: MyGadget,
}

// Circuit parameters that affect structure (compile-time configuration)
#[derive(Args, Debug)]
struct Params {
    /// Maximum size for the circuit
    #[arg(long, default_value_t = 1024)]
    max_size: usize,

    /// Whether to use optimized mode
    #[arg(long, default_value_t = false)]
    optimized: bool,
}

// Instance data for witness population (runtime values)
#[derive(Args, Debug)]
struct Instance {
    /// Input value (if not provided, random data is generated)
    #[arg(long)]
    input: Option<String>,

    /// Size of the input
    #[arg(long)]
    size: Option<usize>,
}

impl ExampleCircuit for MyCircuitExample {
    type Params = Params;
    type Instance = Instance;

    fn build(params: Params, builder: &mut CircuitBuilder) -> Result<Self> {
        // Build your circuit here
        // 1. Add witnesses
        // 2. Add constants
        // 3. Create gadgets
        // 4. Add constraints
        
        // Example:
        // let input_wire = builder.add_witness();
        // let output_wire = builder.add_inout();
        // let gadget = MyGadget::new(builder, params.max_size, input_wire, output_wire);
        
        Ok(Self {
            params,
            // gadget,
        })
    }

    fn populate_witness(&self, instance: Instance, w: &mut WitnessFiller) -> Result<()> {
        // Process instance data and populate witness values
        
        // Example with random or user-provided input:
        let input_data = if let Some(input) = instance.input {
            // Process user-provided input
            input.as_bytes().to_vec()
        } else {
            // Generate random data
            let size = instance.size.unwrap_or(self.params.max_size);
            let mut rng = rand::rngs::StdRng::seed_from_u64(0);
            let mut data = vec![0u8; size];
            rand::RngCore::fill_bytes(&mut rng, &mut data);
            data
        };
        
        // Validate instance data against circuit parameters
        ensure!(
            input_data.len() <= self.params.max_size,
            "Input size ({}) exceeds maximum ({})",
            input_data.len(),
            self.params.max_size
        );
        
        // Populate witness values
        // self.gadget.populate_input(w, &input_data);
        // self.gadget.populate_output(w, &output);
        
        Ok(())
    }
}

fn main() -> Result<()> {
    let _tracing_guard = tracing_profile::init_tracing()?;
    
    // Create and run the CLI - this is all you need!
    Cli::<MyCircuitExample>::new("my_circuit")
        .about("Description of what your circuit does")
        .run()
}
```

## The Simple API

The new API requires only three things from developers:

1. **Implement `ExampleCircuit`** - Define your circuit logic
2. **Define `Params` and `Instance` structs** - Use `#[derive(Args)]` for automatic CLI parsing
3. **Call `Cli::new().run()`** - The library handles everything else

No more manual CLI struct definitions or boilerplate code!

## Design Guidelines

### 1. Separation of Concerns

- **Params**: Circuit structure configuration (compile-time)
  - Maximum sizes, bounds, modes
  - Affects how the circuit is built
  - Examples: `max_len`, `exact_len`, `use_optimization`

- **Instance**: Witness data (runtime)
  - Actual input values for a specific proof
  - Should be validated against params
  - Examples: `message`, `input_value`, `seed`

### 2. Circuit Building

In the `build` method:
1. Create witnesses using `builder.add_witness()`
2. Create constants using `builder.add_constant_64()`
3. Create input/output wires using `builder.add_inout()`
4. Instantiate gadgets with the builder
5. Store references needed for witness population

### 3. Witness Population

In the `populate_witness` method:
1. Process instance data (parse, validate, generate if needed)
2. Validate against circuit parameters
3. Populate all witness values using the stored references
4. Use deterministic randomness (`StdRng::seed_from_u64(0)`) for reproducibility

### 4. Error Handling

- Use `ensure!` for validation with clear error messages
- Return `Result<()>` from all trait methods
- Validate instance data against params before populating witnesses

## CLI Builder Options

The `Cli` builder provides additional customization options:

```rust
Cli::<MyExample>::new("my_circuit")
    .about("Short description")           // Shown in help
    .long_about("Detailed description")   // Shown with --help
    .version("1.0.0")                     // Version info
    .author("Your Name")                  // Author info
    .run()
```

## Common Patterns

### Random Data Generation

```rust
let data = if let Some(user_input) = instance.input {
    user_input.as_bytes().to_vec()
} else {
    let mut rng = StdRng::seed_from_u64(0);
    let mut data = vec![0u8; size];
    rng.fill_bytes(&mut data);
    data
};
```

### Variable vs Fixed Size

```rust
let len_wire = if params.exact_len {
    builder.add_constant_64(params.max_len as u64)
} else {
    builder.add_witness()
};
```

### Hash Computation

```rust
use sha2::{Digest, Sha256};
let hash: [u8; 32] = Sha256::digest(&data).into();
```

## Argument Attributes

Use clap's derive attributes to customize CLI arguments:

```rust
#[derive(Args, Debug)]
struct Params {
    /// Help text for the argument
    #[arg(long, short = 'n', default_value_t = 100)]
    number: usize,
    
    /// Optional argument
    #[arg(long)]
    optional_value: Option<String>,
    
    /// Boolean flag
    #[arg(long, short)]
    verbose: bool,
    
    /// Value with custom parser
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..100))]
    percentage: u32,
}
```

For mutually exclusive options:

```rust
#[derive(Args, Debug)]
#[group(multiple = false)]
struct Instance {
    #[arg(long)]
    from_file: Option<String>,
    
    #[arg(long)]
    from_stdin: bool,
}
```

## Testing Your Example

Build and run your example:

```bash
# Build
cargo build --release --example my_circuit

# Run with default parameters
cargo run --release --example my_circuit

# Run with custom parameters
cargo run --release --example my_circuit -- --max-size 2048 --input "test data"

# Show help
cargo run --release --example my_circuit -- --help

# Run with increased verbosity
RUST_LOG=info cargo run --release --example my_circuit
```

## Adding to Cargo.toml

Add your example to `crates/examples/Cargo.toml`:

```toml
[[example]]
name = "my_circuit"
path = "examples/my_circuit.rs"
```

## Real Examples

Look at these examples for reference:
- `sha256.rs` - Shows parameter/instance separation, random data generation
- `zklogin.rs` - Shows complex witness population with external data generation

## Tips

1. **Keep it simple**: The main function should just create the CLI and run it
2. **Use descriptive help text**: Document what each parameter does
3. **Validate early**: Check instance compatibility with params in `populate_witness`
4. **Use deterministic randomness**: Always seed with a fixed value for reproducibility
5. **Store what you need**: Keep references to gadgets/wires in your struct for witness population