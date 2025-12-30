1. Do we use Simple or Double PIR as the baseline?
2. How do we parallelize queries across clients? Since we are memory-bandwidth constrained, all other client queries must wait for the first client query to complete.
3. How do we handle SSD-based design?
4. How do we handle the updates?
5. How do we reduce communication?
   * YPIR and InsPIRe
6. How do we implement keyword look-up?
   * Chamalet
   * https://eprint.iacr.org/2025/210