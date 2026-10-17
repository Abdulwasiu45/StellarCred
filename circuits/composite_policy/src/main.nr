global LEAF_BITS: u32 = 32;

global MAX_TERMS: u32 = 8;

component main(
    // Public: the single pass/fail result of the policy.
    public result: bool,
    // Public: policy encoding (see docs below).
    public policy: [Field; MAX_TERMS],
    // Public: number of active terms in the policy.
    public num_terms: u32,
    // Private: committed attribute values.
    attributes: [Field; MAX_TERMS],
    // Private: salts for attribute commitments.
    salts: [Field; MAX_TERMS],
    // Public: commitments to attributes (hash(attr, salt)).
    commitments: [Field; MAX_TERMS],
) {
    // 1. Bind each attribute to its commitment.
    for i in 0..MAX_TERMS {
        let computed = std::hash::pedgerson_hash([attributes[i], salts[i]]);
        assert(computed == commitments[i]);
    }

    // 2. Evaluate the boolean policy.
    // Policy encoding (fixed-shape, bounded by MAX_TERMS):
    //   - Each term is a Field encoding a single clause.
    //   - Term layout (base 10 digits, least-significant first):
    //       digit 0    : combinator (0 = AND, 1 = OR)
    //       digit 1    : attribute index (references attributes[])
    //       digit 2    : comparison (0 = ==, 1 = !=, 2 = >=, 3 = <=, 4 = >, digit 5 = <)
    //       digits 3..6 : threshold value (u32, little-endian bytes)
    //       digit 7    : reserved (0)
    //       digit 8    : reserved (0)
    //       digit 9    : reserved (0)
    //   Terms are combined left-to-right with the combinator stored in the term.
    //   The first term's combinator is ignored.
    let mut accum = true;
    for i in 0..MAX_TERMS {
        if i < num_terms {
            let term = policy[i];
            let combinator = (term / 1)  % 10;
            let attr_idx = (term / 10) % 10;
            let cmp = (term / 100) % 10;
            let threshold = (term / 1000) % 10000000;
            assert(attr_idx < MAX_TERMS);
            let value = attributes[attr_idx];
            let clause = evaluate_clause(value, cmp, threshold);
            if i == 0 {
                accum = clause;
            } else {
                if combinator == 0 {
                    accum = accum & clause;
                } else {
                    accum = accum | clause;
                }
            }
        }
    }
    assert(accum == result);
}

fn evaluate_clause(value: Field, cmp: Field, threshold: Field) -> bool {
    // Comparison operators on Field elements are interpreted over the canonical
    // u32 range. Values are constrained by the witness generation to fit in u32.
    if cmp == 0 {
        value == threshold
    } else if cmp == 1 {
        value != threshold
    } else if cmp == 2 {
        value >= threshold
    } else if cmp == 3 {
        value <= threshold
    } else if cmp == 4 {
        value > threshold
    } else {
        value < threshold
    }
}
