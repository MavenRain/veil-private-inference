pragma circom 2.2.3;
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

// A proof of knowledge of the blinding for an attested receipt commitment.
// Signatures and attestation policy are verified by the host before this proof.
template ReceiptBinding() {
    signal input tuple[10];
    signal input commitment;
    signal input blind;
    component bounds[10];
    component h = Poseidon(12);
    h.inputs[0] <== 1447381324;
    for (var i = 0; i < 10; i++) {
        bounds[i] = Num2Bits(128);
        bounds[i].in <== tuple[i];
        h.inputs[i + 1] <== tuple[i];
    }
    h.inputs[11] <== blind;
    h.out === commitment;
}
component main {public [tuple, commitment]} = ReceiptBinding();
