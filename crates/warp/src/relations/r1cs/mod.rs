pub mod hashchain;

use ark_ff::Field;
use ark_relations::gr1cs::{
    predicate::polynomial_constraint::R1CS_PREDICATE_LABEL, ConstraintSystemRef,
};

use crate::errors::WARPError;
use crate::utils::poly::Hypercube;

use super::{BundledPESAT, SerializableConstraintMatrices};

pub type R1CSConstraints<F> = Vec<(Vec<(F, usize)>, Vec<(F, usize)>, Vec<(F, usize)>)>;

#[derive(Clone)]
pub struct R1CS<F: Field> {
    pub p: R1CSConstraints<F>,
    pub m: usize,
    pub n: usize,
    pub k: usize,
    pub log_m: usize,
    pub log_n: usize,
}

impl<F: Field> TryFrom<ConstraintSystemRef<F>> for R1CS<F> {
    type Error = WARPError;

    fn try_from(cs: ConstraintSystemRef<F>) -> Result<Self, Self::Error> {
        // ark-relations 0.6 (gr1cs): metadata accessors moved onto the
        // ConstraintSystemRef itself, and `to_matrices()` returns a
        // per-predicate map. For R1CS we read the "R1CS" entry, which holds
        // exactly three matrices (A, B, C).
        let num_constraints = cs.num_constraints();
        let num_instance = cs.num_instance_variables();
        let num_witness = cs.num_witness_variables();

        let m = num_constraints.next_power_of_two();
        let n = num_instance + num_witness;
        let k = num_witness;

        // `n = instance + witness` can legitimately be zero for a degenerate
        // constraint system; `ilog2` would panic, so surface a typed error
        // instead. (`m` is `next_power_of_two`, hence always >= 1.)
        let log_m = usize::try_from(
            m.checked_ilog2()
                .ok_or(WARPError::DegenerateR1CSDimensions(m))?,
        )
        .expect("log2 of a usize always fits in usize");
        let log_n = usize::try_from(
            n.checked_ilog2()
                .ok_or(WARPError::DegenerateR1CSDimensions(n))?,
        )
        .expect("log2 of a usize always fits in usize");

        let mut per_predicate = cs.to_matrices().map_err(|_| WARPError::R1CSNonExistingLC)?;
        let mut abc = per_predicate
            .remove(R1CS_PREDICATE_LABEL)
            .ok_or(WARPError::R1CSNonExistingLC)?
            .into_iter();
        let mut a = abc.next().unwrap_or_default().into_iter();
        let mut b = abc.next().unwrap_or_default().into_iter();
        let mut c = abc.next().unwrap_or_default().into_iter();
        let mut p = vec![];
        for _ in 0..m {
            let a_i = a.next().unwrap_or(Vec::with_capacity(0));
            let b_i = b.next().unwrap_or(Vec::with_capacity(0));
            let c_i = c.next().unwrap_or(Vec::with_capacity(0));
            p.push((a_i, b_i, c_i));
        }

        Ok(R1CS {
            p,
            m,
            n,
            k,
            log_m,
            log_n,
        })
    }
}

impl<F: Field> R1CS<F> {
    fn eval_lc(lc: &[(F, usize)], z: &[F]) -> Result<F, WARPError> {
        let mut acc = F::zero();
        for (coeff, var) in lc.iter() {
            acc += *coeff
                * z.get(*var)
                    .ok_or(WARPError::R1CSWitnessSize(z.len(), *var))?;
        }
        Ok(acc)
    }

    pub fn eval_p_i(&self, z: &[F], i: usize) -> Result<F, WARPError> {
        let (a_i, b_i, c_i) = self.p.get(i).ok_or(WARPError::R1CSNonExistingLC)?;
        let eval_a_i = Self::eval_lc(a_i, z)?;
        let eval_b_i = Self::eval_lc(b_i, z)?;
        let eval_c_i = Self::eval_lc(c_i, z)?;
        Ok(eval_a_i * eval_b_i - eval_c_i)
    }
}

impl<F: Field> BundledPESAT<F> for R1CS<F> {
    type Config = (usize, usize, usize);
    type Constraints = R1CSConstraints<F>;

    fn evaluate_bundled(&self, zero_evader_evals: &[F], z: &[F]) -> Result<F, WARPError> {
        Hypercube::new(self.log_m).try_fold(F::ZERO, |acc, index| {
            let eq_tau_i = *zero_evader_evals
                .get(index)
                .ok_or(WARPError::ZeroEvaderSize(zero_evader_evals.len(), index))?;
            let p_i = self.eval_p_i(z, index)?;
            Ok(acc + eq_tau_i * p_i)
        })
    }

    fn config(&self) -> Self::Config {
        (self.m, self.n, self.k)
    }

    fn description(&self) -> Vec<u8> {
        SerializableConstraintMatrices::from_sparse_r1cs(
            self.n.saturating_sub(self.k),
            self.k,
            &self.p,
        )
        .to_bytes()
    }

    fn constraints(&self) -> &Self::Constraints {
        &self.p
    }
}
