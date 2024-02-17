extern crate prost_build;

fn main() {
    prost_build::Config::new()
        .out_dir("src/codegen")
        .compile_protos(
            &[
                "proto/aes_cmac.proto",
                "proto/aes_cmac_prf.proto",
                "proto/aes_ctr.proto",
                "proto/aes_ctr_hmac_aead.proto",
                "proto/aes_ctr_hmac_streaming.proto",
                "proto/aes_eax.proto",
                "proto/aes_gcm.proto",
                "proto/aes_gcm_hkdf_streaming.proto",
                "proto/aes_gcm_siv.proto",
                "proto/aes_siv.proto",
                "proto/chacha20_poly1305.proto",
                "proto/common.proto",
                "proto/config.proto",
                "proto/ecdsa.proto",
                "proto/ecies_aead_hkdf.proto",
                "proto/ed25519.proto",
                "proto/empty.proto",
                "proto/hkdf_prf.proto",
                "proto/hmac.proto",
                "proto/hmac_prf.proto",
                "proto/hpke.proto",
                "proto/jwt_ecdsa.proto",
                "proto/jwt_hmac.proto",
                "proto/jwt_rsa_ssa_pkcs1.proto",
                "proto/jwt_rsa_ssa_pss.proto",
                "proto/kms_aead.proto",
                "proto/kms_envelope.proto",
                "proto/prf_based_deriver.proto",
                "proto/rsa_ssa_pkcs1.proto",
                "proto/rsa_ssa_pss.proto",
                "proto/test_proto.proto",
                "proto/tink.proto",
                "proto/xchacha20_poly1305.proto",
            ],
            &["."],
        )
        .unwrap();
}
