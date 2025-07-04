# Coding Conventions for Circuits

Circuits are supposed to be written in Rust and then compiled offline. Therefore, the performance
aspect of the circuit compilation is not important and we should optimize for readability rather
than utmost performance. One concrete suggestion here is to not use const generics and statically
sized arrays. Instead, prefer passing upper-bound as variables, and use Vec<Wire> instead of
fixed sized arrays.

# The shape of a Circuit

A typical circuit looks like this.

```rust
struct Gadget {
	pub a: Vec<Wire>,
	pub b: Vec<Wire>,
	subgadget: [Subgadget; 2],
	internal_wires: Vec<Wire>,
}

impl Gadget {
	pub fn new(circuit: &CircuitBuilder, a: Vec<Wire>, b: Vec<Wire>, max_len: usize) -> Self {
		// Build wiring using the CircuitBuilder...

		// Create subgadget.
		let subgadget = [
			Subgadget::new(&circuit.subcircuit("subgadget[0]"), &a, &b, max_len),
			Subgadget::new(&circuit.subcircuit("subgadget[1]"), &a, &b, max_len)
		];
		Self {
			a,
			b,
			subgadget,
			internal_wires: Vec::new(),
		}
	}
	pub fn populate_a(&self, w: &mut WitnessFiller, a: &[u8]) { .. }
	pub fn populate_b(&self, w: &mut WitnessFiller, b: &[u32]) { .. }
}
```

Let's look at it from different angles.

`Gadget::new` receives a `CircuitBuilder`. Note that circuit builders are namespaced. It's
up to the caller of the constructor to provide a namespace via the
`subcircuit(name) -> CircuitBuilder` method.

Note that the gadget does not declare any input wires. This is because it's up to the user to
decide how to feed the gadget. They may decide between public (`circuit.add_inout()`) or private
parameters (`circuit.add_witness()`). They may even specialize some parameters to constants and
expect the optimizer to fold constants. Yet another reason, is that the user may simply feed wires
to the gadget that are results of some other computation.

This leads us to `populate_a` and `populate_b`. These methods are used to populate the gadget's
input wires with data, hopefully in a user friendly way. The reason we use two separate methods
instead of a single `populate` method that takes all the parameters is because the input wires may be
aliased. That is, if a gadget A output wires are passed as inputs into gadget B, then if gadget
B populated its input wires then the values are going to be overwritten.
