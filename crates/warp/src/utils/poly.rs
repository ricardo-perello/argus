use ark_ff::Field;

/// Evaluate the multilinear equality polynomial eq(tau, point) where `point` is
/// a vertex of the boolean hypercube encoded as a usize (bit decomposition).
///
/// eq(tau, x) = prod_i (tau_i * x_i + (1 - tau_i)(1 - x_i))
pub fn eq_poly<F: Field>(tau: &[F], point: usize) -> F {
    let n = tau.len();
    let mut result = F::one();
    for i in 0..n {
        let bit = (point >> i) & 1;
        if bit == 1 {
            result *= tau[i];
        } else {
            result *= F::one() - tau[i];
        }
    }
    result
}

/// Evaluate the multilinear equality polynomial eq(x, y) for two vectors of
/// field elements (not necessarily binary).
///
/// eq(x, y) = prod_i (x_i * y_i + (1 - x_i)(1 - y_i))
pub fn eq_poly_non_binary<F: Field>(x: &[F], y: &[F]) -> F {
    assert_eq!(x.len(), y.len());
    x.iter().zip(y).fold(F::one(), |acc, (x_i, y_i)| {
        acc * (*x_i * *y_i + (F::one() - x_i) * (F::one() - y_i))
    })
}

/// Evaluate eq(point, i) for all i in {0,1}^n (ascending order).
pub fn compute_hypercube_eq_evals<F: Field>(num_variables: usize, point: &[F]) -> Vec<F> {
    let size = 1 << num_variables;
    (0..size).map(|i| eq_poly(point, i)).collect()
}

/// Simple iterator over the boolean hypercube {0,1}^n in ascending index order.
pub struct Hypercube {
    n: usize,
    current: usize,
    size: usize,
}

impl Hypercube {
    pub fn new(n: usize) -> Self {
        Self {
            n,
            current: 0,
            size: 1 << n,
        }
    }

    pub fn num_variables(&self) -> usize {
        self.n
    }
}

impl Iterator for Hypercube {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current < self.size {
            let idx = self.current;
            self.current += 1;
            Some(idx)
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.size - self.current;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Hypercube {}

/// Reduce evaluation tables by folding pairs with a challenge value.
/// Used in sumcheck: for each pair (table[2i], table[2i+1]),
/// compute table[i] = table[2i] + c * (table[2i+1] - table[2i]).
///
/// This operates on a collection of tables (Vec of Vecs), halving each.
pub fn tablewise_reduce<F: Field>(tables: &mut Vec<Vec<F>>, challenge: F) {
    let half = tables.len() / 2;
    let mut reduced = Vec::with_capacity(half);
    for i in 0..half {
        let left = &tables[2 * i];
        let right = &tables[2 * i + 1];
        let folded: Vec<F> = left
            .iter()
            .zip(right.iter())
            .map(|(&l, &r)| l + challenge * (r - l))
            .collect();
        reduced.push(folded);
    }
    *tables = reduced;
}

/// Reduce a single evaluation vector by folding pairs with a challenge.
/// pairwise: v[i] = v[2i] + c * (v[2i+1] - v[2i])
pub fn pairwise_reduce<F: Field>(evals: &mut Vec<F>, challenge: F) {
    let half = evals.len() / 2;
    let mut reduced = Vec::with_capacity(half);
    for i in 0..half {
        reduced.push(evals[2 * i] + challenge * (evals[2 * i + 1] - evals[2 * i]));
    }
    *evals = reduced;
}
