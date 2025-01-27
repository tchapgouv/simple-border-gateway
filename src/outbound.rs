use std::{fs, future::Future};

use http::Method;
// use hudsucker::{
//     certificate_authority::OpensslAuthority, openssl::{hash::MessageDigest, pkey::PKey, x509::X509}, rustls::crypto::aws_lc_rs, Body, HttpContext, HttpHandler, Proxy, RequestOrResponse
// };
use hudsucker::{
    certificate_authority::RcgenAuthority, rustls::crypto::aws_lc_rs, Body, HttpContext,
    HttpHandler, Proxy, RequestOrResponse,
};
use rcgen::{CertificateParams, KeyPair};

// use crate::membership;

#[derive(Clone)]
struct LogHandler;

impl HttpHandler for LogHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: http::Request<Body>,
    ) -> RequestOrResponse {
        if req.method() != Method::CONNECT {
            println!("req {:?}", req.uri().to_string());
            // membership::filter_outgoing_req(req).await
            req.into()
        } else {
            req.into()
        }
    }

    async fn handle_response(
        &mut self,
        _ctx: &HttpContext,
        res: http::Response<Body>,
    ) -> http::Response<Body> {
        // println!("res {:?}", res);
        res
    }
}

pub(crate) async fn create_proxy<F>(
    listening_addr: &str,
    ca_priv_key_path: &str,
    ca_cert_path: &str,
    shutdown_signal: F,
) where
    F: Future<Output = ()> + Send + 'static,
{
    let ca_private_key =
    fs::read_to_string(ca_priv_key_path).expect("Failed to read CA private key file");
    let ca_cert = fs::read_to_string(ca_cert_path).expect("Failed to read CA certificate file");

    let key_pair =
        KeyPair::from_pem(ca_private_key.as_str()).expect("Failed to parse CA private key");
    let ca_cert = CertificateParams::from_ca_cert_pem(ca_cert.as_str())
        .expect("Failed to parse CA certificate")
        .self_signed(&key_pair)
        .expect("Failed to sign CA certificate");

    let ca = RcgenAuthority::new(key_pair, ca_cert, 1_000, aws_lc_rs::default_provider());

    // let ca_private_key =
    // fs::read(ca_priv_key_path).expect("Failed to read CA private key file");
    // let ca_cert = fs::read(ca_cert_path).expect("Failed to read CA certificate file");

    // let private_key =
    //     PKey::private_key_from_pem(ca_private_key.as_slice()).expect("Failed to parse private key");
    // let ca_cert = X509::from_pem(ca_cert.as_slice()).expect("Failed to parse CA certificate");

    // let ca = OpensslAuthority::new(
    //     private_key,
    //     ca_cert,
    //     MessageDigest::sha256(),
    //     1_000,
    //     aws_lc_rs::default_provider(),
    // );

    let proxy = Proxy::builder()
        .with_addr(listening_addr.parse().unwrap())
        .with_ca(ca)
        .with_rustls_client(aws_lc_rs::default_provider())
        // .with_native_tls_client()
        .with_http_handler(LogHandler)
        .with_graceful_shutdown(shutdown_signal)
        .build()
        .expect("Failed to build proxy");

    let res = proxy.start().await;
    if res.is_err() {
        println!("error outbound proxy start {:?}", res.err());
    }
}
