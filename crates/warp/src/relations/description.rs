use ark_ff::Field;
use ark_relations::gr1cs::{
    predicate::polynomial_constraint::R1CS_PREDICATE_LABEL, ConstraintSynthesizer, ConstraintSystem,
};
use serde::Serialize;

use super::r1cs::R1CSConstraints;

#[derive(Serialize)]
pub struct SerializableConstraintMatrices {
    pub num_instance_variables: usize,
    pub num_witness_variables: usize,
    pub num_constraints: usize,
    pub a: Vec<Vec<(Vec<u8>, usize)>>,
    pub b: Vec<Vec<(Vec<u8>, usize)>>,
    pub c: Vec<Vec<(Vec<u8>, usize)>>,
}

impl SerializableConstraintMatrices {
    pub fn serialize_nested_field<F: Field>(
        original: Vec<Vec<(F, usize)>>,
    ) -> Vec<Vec<(Vec<u8>, usize)>> {
        original
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .map(|(coeff, col_idx)| {
                        let mut buf = Vec::new();
                        coeff.serialize_uncompressed(&mut buf).unwrap();
                        (buf, col_idx)
                    })
                    .collect()
            })
            .collect()
    }

    pub fn generate_description<F: Field>(
        constraint_synthesizer: impl ConstraintSynthesizer<F>,
    ) -> Vec<u8> {
        // ark-relations 0.6 (gr1cs): the standalone `ConstraintMatrices` type
        // is gone. Metadata accessors live on the `ConstraintSystemRef`, and
        // `to_matrices()` returns a per-predicate `BTreeMap` of matrices. For
        // R1CS, the "R1CS" entry holds A, B, C in that order.
        let constraint_system = ConstraintSystem::<F>::new_ref();
        constraint_synthesizer
            .generate_constraints(constraint_system.clone())
            .unwrap();
        constraint_system.finalize();

        let num_instance_variables = constraint_system.num_instance_variables();
        let num_witness_variables = constraint_system.num_witness_variables();
        let num_constraints = constraint_system.num_constraints();

        let mut per_predicate = constraint_system.to_matrices().unwrap();
        let mut abc = per_predicate
            .remove(R1CS_PREDICATE_LABEL)
            .expect("R1CS predicate present")
            .into_iter();
        let a = abc.next().unwrap_or_default();
        let b = abc.next().unwrap_or_default();
        let c = abc.next().unwrap_or_default();

        let serializable = SerializableConstraintMatrices {
            num_instance_variables,
            num_witness_variables,
            num_constraints,
            a: Self::serialize_nested_field(a),
            b: Self::serialize_nested_field(b),
            c: Self::serialize_nested_field(c),
        };
        serializable.to_bytes()
    }

    pub fn from_sparse_r1cs<F: Field>(
        num_instance_variables: usize,
        num_witness_variables: usize,
        constraints: &R1CSConstraints<F>,
    ) -> Self {
        let (a, bc): (Vec<_>, Vec<_>) = constraints
            .iter()
            .map(|(a, b, c)| {
                (
                    a.iter()
                        .map(|(coefficient, column)| (*coefficient, *column))
                        .collect(),
                    (
                        b.iter()
                            .map(|(coefficient, column)| (*coefficient, *column))
                            .collect(),
                        c.iter()
                            .map(|(coefficient, column)| (*coefficient, *column))
                            .collect(),
                    ),
                )
            })
            .unzip();
        let (b, c) = bc.into_iter().unzip();

        Self {
            num_instance_variables,
            num_witness_variables,
            num_constraints: constraints.len(),
            a: Self::serialize_nested_field(a),
            b: Self::serialize_nested_field(b),
            c: Self::serialize_nested_field(c),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self)
            .expect("serializing canonical R1CS constraint data to a byte vector cannot fail")
    }
}
