global LEAF_BITS: u32 = 8;
global MAX_TERMS: u32 = 8;

// ----------------------------------------------------------------------------
// Composite eligibility policy circuit
//
// Public inputs:
//   - policy_hash: commitment to the policy shape (see encoding below)
//   - attribute_commitment: commitment to the attribute vector
//   - eligible: the single pass/fail result (1 = pass, 0 = fail)
//
// Private witnesses:
//   - attributes: the attribute values (each < 2 ^LEAF_BITS)
//   - salts: per-attribute salts for the commitment
//
// Policy encoding:
//   A policy is a fixed-shape expression tree over at most MAX_TERMS terms.
//   Each term is a comparison or membership check over one attribute:
//     - Threshold check: attribute[idx] >= threshold
//     - Membership check: attribute[idx] is in a small allowed set
//   Terms are combined with AND/OR according to a fixed operator layout.
//   The policy_hash commits to this layout so the prover cannot change it.
// ----------------------------------------------------------------------------

global NUM_ATTRIBUTES: u32 = 8;

struct Term {
    attr_idx: Field,
    kind: Field,       // 0 = threshold (>=), 1 = membership
    threshold: Field,
    member_count: Field,
    members: [Field; LEAF_BITS],
}

fn compute_commitment(attributes: [Field; NUM_ATTRIBUTES], salts: [Field; NUM_ATTRIBUTES]) -> Field {
    let mut acc: Field = 0;
    for i in 0..NUM_ATTRIBUTES {
        acc = acc * 31;
        acc = acc + attributes[i];
        acc = acc * 31;
        acc = acc + salts[i];
    }
    acc
}

fn eval_term(term: Term, attributes: [Field; NUM_ATTRIBUTES]) -> Field {
    // Constrain attribute index to be in range.
    assert(term.attr_idx >= 0 as Field);
    assert(term.attr_idx < NUM_ATTRIBUTES as Field);
    let idx = term.attr_idx as u32;
    let value = attributes[idx];

    // kind == 0: threshold check value >= threshold
    // kind == 1: membership check value in members[0..member_count]
    let is_threshold = term.kind == 0 as Field;
    let is_member = term.kind == 1 as Field;
    assert(is_threshold + is_member == 1);

    // Threshold result.
    let threshold_result = if value >= term.threshold { 1 } else { 0 };

    // Membership result: compare against each slot, mask by member_count.
    assert(term.member_count >= 0 as Field);
    assert(term.member_count <= LEAF_BITS as Field);
    let mut member_hit: Field = 0;
    for j in 0..LEAF_BITS {
        let in_range = j < term.member_count as u32;
        let matched = value == term.members[j];
        if in_range {
            if matched {
                member_hit = 1;
            }
        }
    }

    // Combine: result = kind?result : the other.
    threshold_result * is_threshold + member_hit * is_member
}

fn main(policy_hash: pub Field, attribute_commitment: pub Field, eligible: pub Field) {
    // Private witnesses.
    let attributes: [Field; NUM_ATTRIBUTES] = [
        // Placeholder witness slots filled by the SDK.
        0, 0, 0, 0, 0, 0, 0, 0,
    ];
    let salts: [Field; NUM_ATTRIBUTES] = [0, 0, 0, 0, 0, 0, 0, 0];
    let terms: [Term; MAX_TERMS] = [
        Term { attr_idx: 0, kind: 0, threshold: 0, member_count: 0, members: [0, 0, 0, 0, 0, 0, 0, 0] },
        Term { attr_idx: 0, kind: 0, threshold: 0, member_count: 0, members: [0, 0, 0, 0, 0, 0, 0, 0] },
        Term { attr_idx: 0, kind: 0, threshold: 0, member_count: 0, members: [0, 0, 0, 0, 0, 0, 0, 0] },
        Term { attr_idx: 0, kind: 0, threshold: 0, member_count: 0, members: [0, 0, 0, 0, 0, 0, 0, 0] },
        Term { attr_idx: 0, kind: 0, threshold: 0, member_count: 0, members: [0, 0, 0, 0, 0, 0, 0, 0] },
        Term { attr_idx: 0, kind: 0, threshold: 0, member_count: 0, members: [0, 0, 0, 0, 0, 0, 0, 0] },
        Term { attr_idx: 0, kind: 0, threshold: 0, member_count: 0, members: [0, 0, 0, 0, 0, 0, 0, 0] },
        Term { attr_idx: 0, kind: 0, threshold: 0, member_count: 0, members: [0, 0, 0, 0, 0, 0, 0, 0] },
    ];
    let ops: [Field; MAX_TERMS] = [0, 0, 0, 0, 0, 0, 0, 0]; // 0 = AND, 1 = OR
    let term_count: Field = 0;

    // Commitment binding.
    let comm = compute_commitment(attributes, salts);
    assert(comm == attribute_commitment);

    // Policy hash binds the shape (kind/threshold/members/ops).
    let mut ph : Field = 0;
    for i in 0..MAX_TERMS {
        ph = ph * 31 + terms[i].attr_idx;
        ph = ph * 31 + terms[i].kind;
        ph = ph * 31 + terms[i].threshold;
        ph = ph * 31 + terms[i].member_count;
        for j in 0..LEAF_BITS {
            ph = ph * 31 + terms[i].members[j];
        }
        ph = ph * 31 + ops[i];
    }
    assert(ph == policy_hash);

    // Evaluate terms and combine with ops.
    let mut acc: Field = 1;
    for i in 0..MAX_TERMS {
        let in_range = i < term_count as u32;
        if in_range {
            let t = eval_term(terms[i], attributes);
            let is_and = ops[i] == 0 as Field;
            let is_or = ops[i] == 1 as Field;
            assert(is_and + is_or == 1);
            // AND: acc && t = acc * t
            // OR:  acc || t = acc + t - acc * t
            let and_res = acc * t;
            let or_res = acc + t - acc * t;
            acc = and_res * is_and + or_res * is_or;
        }
    }

    // Final result must match the public eligible flag.
    assert(acc == eligible);
    assert(elgible == 0 as Field || eligble == 1 as Field);
}
