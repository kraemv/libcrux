use crate::keys::*;
use crate::Error;
use libcrux_agent::aead::*;
use libcrux_agent::aead_messages::*;
use libcrux_agent::hkdf_messages::*;
use libcrux_agent::hmac::Sha2_256HMAC;
use libcrux_agent::hmac_messages::*;
use libcrux_agent::kex_messages::*;
use libcrux_agent::messages::{IPCRequest, IPCResponse, MessageKind};
use libcrux_agent::rng_messages::EntropyRequest;
use libcrux_agent::signatures::{EcDsaP256SHA256, Ed25519};
use libcrux_agent::signing_messages::*;
use zerocopy::*;

pub(crate) fn handle_request(request: & IPCRequest) -> Result<IPCResponse, Error> {
    match request.get_header().get_type() {
        MessageKind::ChaCha20Poly1305Decrypt => {
            let request =
                AeadDecryptRequest::<ChaCha20Poly1305, CHACHA_NONCE_LEN, CHACHA_TAG_LEN>::try_from(
                    request.get_payload(),
                )?;
            handle_chacha20poly1305_decrypt_request(&request)
        }
        MessageKind::ChaCha20Poly1305Encrypt => {
            let request =
                AeadEncryptRequest::<ChaCha20Poly1305, CHACHA_NONCE_LEN, CHACHA_TAG_LEN>::try_from(
                    request.get_payload(),
                )?;
            handle_chacha20poly1305_encrypt_request(&request)
        }
        MessageKind::EcDsaP256Sign => {
            let request = SignRequest::<EcDsaP256SHA256>::try_from(request.get_payload())?;
            handle_ecdsa_p256_sign_request(&request)
        }
        MessageKind::Ed25519Sign => {
            let request = SignRequest::<Ed25519>::try_from(request.get_payload())?;
            handle_ed25519_sign_request(&request)
        }

        MessageKind::Entropy => {
            let request = EntropyRequest::from(request.get_payload());
            handle_entropy_request(&request)
        }

        MessageKind::Error => Err(Error::IO),

        MessageKind::MlKem768Decaps => {
            let request = MlKem768DecapsRequest::try_ref_from_bytes(request.get_payload())?;
            handle_mlkem768_decaps(request)
        }

        MessageKind::MlKem768Encaps => {
            let request = MlKem768EncapsRequest::try_ref_from_bytes(request.get_payload())?;
            handle_mlkem768_encaps(request)
        }

        MessageKind::MlKem768KeyGen => handle_mlkem768_key_gen(),

        MessageKind::X25519Derive => {
            let request = X25519DeriveRequest::try_ref_from_bytes(request.get_payload())?;
            handle_x25519_derive(request)
        }

        MessageKind::X25519KeyGen => handle_x25519_key_gen(),

        MessageKind::Export => {
            let request = ExportNonceRequest::try_ref_from_bytes(request.get_payload())?;
            let response = ExportNonceResponse::new(export_nonce(request.get_id())?);
            Ok(IPCResponse::from(response))
        }

        MessageKind::HkdfExtractPublic => {
            let request = HkdfExtractPublicRequest::try_from(request.get_payload())?;
            handle_hkdf_extract_public_salt(&request)
        }

        MessageKind::HkdfExtractSecret => {
            let request = HkdfExtractSecretRequest::try_from(request.get_payload())?;
            handle_hkdf_extract_secret_salt(&request)
        }

        MessageKind::HkdfExpand => {
            let request = HkdfExpandRequest::try_from(request.get_payload())?;
            handle_hkdf_expand(&request)
        }

        MessageKind::HmacSha2_256Authenticate => {
            let request = HmacRequest::<Sha2_256HMAC>::try_from(request.get_payload())?;
            handle_hmac_sha2_256_authenticate(&request)
        }
    }
}

pub(crate) fn handle_chacha20poly1305_decrypt_request(
    request: &AeadDecryptRequest<'_, ChaCha20Poly1305, CHACHA_NONCE_LEN, CHACHA_TAG_LEN>,
) -> Result<IPCResponse, Error> {
    let id = request.get_id();
    let nonce = request.get_nonce();
    let ciphertext = request.get_ciphertext();
    let tag = request.get_tag();
    let aad = request.get_aad();
    let mut plaintext = vec![0u8; ciphertext.len()];
    chacha20poly1305_decrypt_for_id(id, &mut plaintext, nonce, tag, ciphertext, aad)
        .map(|plaintext| IPCResponse::from(AeadDecryptResponse::from(plaintext)))
}

pub(crate) fn handle_chacha20poly1305_encrypt_request(
    request: &AeadEncryptRequest<'_, ChaCha20Poly1305, CHACHA_NONCE_LEN, CHACHA_TAG_LEN>,
) -> Result<IPCResponse, Error> {
    let id = request.get_id();
    let nonce = request.get_nonce();
    let plaintext = request.get_plaintext();
    let aad = request.get_aad();
    let mut ciphertext = vec![0u8; plaintext.len()];
    chacha20poly1305_encrypt_for_id(id, &mut ciphertext, nonce, plaintext, aad).map(
        |(ciphertext, tag)| IPCResponse::from(AeadEncryptResponse::from_parts(ciphertext, tag)),
    )
}

pub(crate) fn handle_ecdsa_p256_sign_request(
    request: &SignRequest<EcDsaP256SHA256>,
) -> Result<IPCResponse, Error> {
    ecdsa_p256_sign_for_id(request.get_id(), request.get_payload())
        .map(|sig| IPCResponse::from(SignResponse::<EcDsaP256SHA256>::from(sig)))
}

pub(crate) fn handle_ed25519_sign_request(
    request: &SignRequest<Ed25519>,
) -> Result<IPCResponse, Error> {
    ed25519_sign_for_id(request.get_id(), request.get_payload())
        .map(|sig| IPCResponse::from(SignResponse::<Ed25519>::from(sig)))
}

pub(crate) fn handle_entropy_request(request: &EntropyRequest) -> Result<IPCResponse, Error> {
    add_entropy(request.as_ref()).map(|()| IPCResponse::entropy())
}

pub(crate) fn handle_x25519_key_gen() -> Result<IPCResponse, Error> {
    x25519_generate_key_id().map(|(id, pk)| IPCResponse::from(X25519KeyGenResponse::new(id, pk)))
}

pub(crate) fn handle_mlkem768_key_gen() -> Result<IPCResponse, Error> {
    mlkem_768_generate_key_id()
        .map(|(id, pk)| IPCResponse::from(MlKem768KeyGenResponse::new(id, pk)))
}

pub(crate) fn handle_x25519_derive(request: &X25519DeriveRequest) -> Result<IPCResponse, Error> {
    x25519_derive_for_key_id(request.get_id(), request.get_key())
        .map(|shk| IPCResponse::from(X25519DeriveResponse::new(shk)))
}

pub(crate) fn handle_mlkem768_decaps(
    request: &MlKem768DecapsRequest,
) -> Result<IPCResponse, Error> {
    mlkem_768_decaps_for_id(request.get_id(), request.get_ciphertext())
        .map(|shk| IPCResponse::from(MlKem768DecapsResponse::new(shk)))
}

pub(crate) fn handle_mlkem768_encaps(
    request: &MlKem768EncapsRequest,
) -> Result<IPCResponse, Error> {
    let pk = request.get_key();
    mlkem_768_encaps_for_id(pk)
        .map(|(id, ct)| IPCResponse::from(MlKem768EncapsResponse::new(id, ct)))
}

pub(crate) fn handle_hkdf_extract_public_salt(
    request: &HkdfExtractPublicRequest,
) -> Result<IPCResponse, Error> {
    hkdf_extract_public_salt(request.get_id(), request.get_salt())
        .map(|id| IPCResponse::from(HkdfResponse::<HkdfExtractPublicSalt>::new(id)))
}

pub(crate) fn handle_hkdf_extract_secret_salt(
    request: &HkdfExtractSecretRequest,
) -> Result<IPCResponse, Error> {
    hkdf_extract_secret_salt(request.get_id(), request.get_salt())
        .map(|id| IPCResponse::from(HkdfResponse::<HkdfExtractSecretSalt>::new(id)))
}

pub(crate) fn handle_hkdf_expand(request: &HkdfExpandRequest<'_>) -> Result<IPCResponse, Error> {
    hkdf_expand(
        request.get_id(),
        request.get_info(),
        request.get_output_len(),
    )
    .map(|id| IPCResponse::from(HkdfResponse::<HkdfExpand>::new(id)))
}

pub(crate) fn handle_hmac_sha2_256_authenticate(
    request: &HmacRequest<Sha2_256HMAC>,
) -> Result<IPCResponse, Error> {
    hmac_sha2_256_authenticate(request.get_id(), request.get_payload())
        .map(|tag| IPCResponse::from(HmacResponse::from(tag)))
}
