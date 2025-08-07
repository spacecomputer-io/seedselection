# seedselection

**WARNING: This project is experimental and work-in-progress, use at your own risk!**

![Build & Test (Core)](https://github.com/spacecomputer-io/seedselection/actions/workflows/build_test.yml/badge.svg?branch=main)

## Overview

This crate provides a simple and effective ways to implement deterministic selection in distributed systems. 

The focus is on random seeds to provide fair selection and good distribution. The selection process is deterministic, meaning that the same input will always produce the same output. This is useful for ensuring that all peers in a distributed system agree on the selected items, without introducing network calls or the need for a central authority.

A max-heap is used to efficiently select the top `n` items based on a distance function (xor distance) applied to the each of items against the hash of seed+seq+name.

### Security Considerations

- The selection depends on the entropy of the seed, so it is crucial to use a secure and unpredictable seed to ensure fairness and security. We encourage users to use SpaceComputer's [orbitport](https://docs.spacecomputer.io/orbitport) as a source of randomness.
- The hash function is pluggable, it should be cryptographically secure to prevent manipulation of the selection process.

## Usage

To use this crate, add it to your `Cargo.toml`:

```toml
[dependencies]
seedselection = { git = "https://github.com/spacecomputer-io/seedselection.git", tag = "v0.1.0" }
```

Then, you can use it in your code:

```rust
use seedselection::xor_dist;
use sha2::Sha256;
        
let name = "test";
let seed = b"test-seed";
let seq = 1;
let n = 3;
let ids = vec![
    // ... list of peer IDs
];

let selected = xor_dist::xor_distance_selection(name, seed, seq, n, &ids, Sha256::new).unwrap();
println!("Selected peers: {:?}", selected);
```

**NOTE:** There is an equivalent Go implementation: [spacecomputer-io/seedselection-go](https://github.com/spacecomputer-io/seedselection-go).

## License

This project is licensed under the terms of the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

We welcome contributions to this project! If you have suggestions for improvements or new features, please open an issue or submit a pull request.
