Binary Signature Scanner
========================

Scanner for binary signatures.

Intended use case is scanning for signatures in executables.

Documentation
-------------

For now documentation can be found on [crates.fyi](https://crates.fyi/crates/scanner/).

Usage
-----

This library can be found on [crates.io](https://crates.io/crates/scanner). In your Cargo.toml put

```
[dependencies]
scanner = "0.1"
```

Examples
--------

Signatures are a sequence of `pat::Unit`s, they can be created statically or parsed at runtime:

```rust
extern create scanner;
use scanner::pat::{parse, Unit};

const MY_PATTERN: &'static [Unit] = &[Unit::Byte(0xE9), Unit::Store, Unit::Skip(4), Unit::Byte(0xC3)];

let pat = parse("E9*???? C3").unwrap();
assert_eq!(pat, MY_PATTERN);
```

The signature scanner supports two major use cases:

* Find a single unique match of a pattern.

  ```rust
  extern crate scanner;
  use scanner::{Scanner, Match, pat};

  const BYTES: &'static [u8] = b"\x22\x01\xD5\x44\x22\x01\x69\x55";
  const PATTERN: &'static [pat::Unit] = &[pat::Unit::Byte(0x22), pat::Unit::RelByte, pat::Unit::Store, pat::Unit::Byte(0x55)];

  let scan = Scanner::new(BYTES, 0..BYTES.len() as u32, 0);
  if let Some(mach) = scan.find(PATTERN) {
  	// Found a unqiue match
  	assert_eq!(mach, Match { haystack: BYTES, at: 5, store: [7, 0, 0, 0, 0] });
  }
  else {
  	// No unique match was found
  }
  ```

* Find all matches for a pattern.

  ```rust
  extern crate scanner;
  use scanner::{Scanner, Match, pat};

  const BYTES: &'static [u8] = b"\xDD\x7F\xDD\x15\xDD\xC1\xDD";
  const PATTERN: &'static [pat::Unit] = &[pat::Unit::Byte(0xDD), pat::Unit::Skip(1), pat::Unit::Byte(0xDD)];

  let scan = Scanner::new(BYTES, 0..BYTES.len() as u32, 0);
  let matches: Vec<Match> = scan.iter(PATTERN).collect();

  assert_eq!(matches, vec![
  	Match { haystack: BYTES, at: 0, store: [0, 0, 0, 0, 0] },
  	Match { haystack: BYTES, at: 2, store: [0, 0, 0, 0, 0] },
  	Match { haystack: BYTES, at: 4, store: [0, 0, 0, 0, 0] },
  ]);
  ```

Typically you want to use this crate to scan for signatures in the code section (eg `.text`), for this there's an optional dependency on the `pelite` crate and a `From` conversion from `&PeView` to construct a `Scanner`.

Design
------

Signatures can be a messy business, this crate attempts to assist with some of the common pitfalls while providing some nice features.

* The signatures can be parsed from text, this allows signatures to live conveniently in an external configuration file.

  This is optional however, you can construct your signature from components as shown in the examples.

* Unless scanning for a particular function, you're not interested in the location the match happened rather in extracting some argument from an instruction parameter which looks like this in C:

  ```C
  unsigned char* match = ...;
  float* interesting = *(float**)(match + 0x7);
  ```

  There are two aspects that can be really tricky to get right; first you need the correct offset from the match, second you need to cast and dereference the correct number of times. Believe me I never get this right on first try. It gets more hairy if the argument is RIP relative to the current ptr.

  To solve the 'correct offset' problem, signatures can use `*`, this saves the ptr in the `store` array of the `Match`. For now this is limited to 5 stores per signature.

  To solve the 'correct dereferences' problem, signatures can tell the scanner to follow relative addresses with `r1` (signed byte) or `r4` (signed dword) and absolute addresses with `j` then save that location with a `*`. To continue matching before the indirection you put a `+` in front of the jump then use `-` to go back where the scan left off. Max recursion depth is 4.

  Note that `j` works correctly in 32 and 64bit (depending if you select to parse the signature as 32 or 64bit). PIC support is pending.

* In most cases you want a single unique match, debugging a crash because your signature accidentally matched the wrong thing because it wasn't unique is *not* a fun experience. To solve this the `Scanner::find` will check to make sure the match is unique, this trades some speed for 'correctness' but saves a ton of headaches.

* Speed matters, for this the crate limits the scan range and implements optimized quicksearch. This is faster than a naive find pattern!

License
-------

MIT - see license.txt
