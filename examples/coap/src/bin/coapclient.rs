use coap::CoAPClient;
use coap_lite::ResponseType;
use edhoc_rs::*;
use std::time::Duration;

const ID_CRED_I: &str = "a104412b";
const ID_CRED_R: &str = "a1044132";
const CRED_I: &str = "a2027734322d35302d33312d46462d45462d33372d33322d333908a101a5010202412b2001215820ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb62258206e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8";
const I: &str = "fb13adeb6518cee5f88417660841142e830a81fe334380a953406a1305e8706b";
const _G_I_X_COORD: &str = "ac75e9ece3e50bfc8ed60399889522405c47bf16df96660a41298cb4307f7eb6"; // not used
const _G_I_Y_COORD: &str = "6e5de611388a4b8a8211334ac7d37ecb52a387d257e6db3c2a93df21ff3affc8"; // not used
const CRED_R: &str = "a2026b6578616d706c652e65647508a101a501020241322001215820bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f02258204519e257236b2a0ce2023f0931f1f386ca7afda64fcde0108c224c51eabf6072";
const G_R: &str = "bbc34960526ea4d32e940cad2a234148ddc21791a12afbcbac93622046dd44f0";

fn main() {
    let url = "coap://127.0.0.1:5683/.well-known/edhoc";
    let timeout = Duration::new(5, 0);
    println!("Client request: {}", url);

    let state: EdhocState = Default::default();
    let mut initiator =
        EdhocInitiator::new(state, &I, &G_R, &ID_CRED_I, &CRED_I, &ID_CRED_R, &CRED_R);

    // Send Message 1 over CoAP and convert the response to byte
    let mut msg_1_buf = Vec::from([0xf5u8]); // EDHOC message_1 when transported over CoAP is prepended with CBOR true
    let message_1 = initiator.prepare_message_1().unwrap();
    msg_1_buf.extend_from_slice(&message_1.content[..message_1.len]);
    println!("message_1 len = {}", msg_1_buf.len());

    let response = CoAPClient::post_with_timeout(url, msg_1_buf, timeout).unwrap();
    if response.get_status() != &ResponseType::Changed {
        panic!("Message 1 response error: {:?}", response.get_status());
    }
    println!("response_vec = {:02x?}", response.message.payload);
    println!("message_2 len = {}", response.message.payload.len());

    let c_r = initiator.process_message_2(
        &response.message.payload[..]
            .try_into()
            .expect("wrong length"),
    );

    if c_r.is_ok() {
        let mut msg_3 = Vec::from([c_r.unwrap()]);
        let (message_3, _prk_out) = initiator.prepare_message_3().unwrap();
        msg_3.extend_from_slice(&message_3.content[..message_3.len]);
        println!("message_3 len = {}", msg_3.len());

        let _response = CoAPClient::post_with_timeout(url, msg_3, timeout).unwrap();
        // we don't care about the response to message_3 for now

        let _oscore_secret = initiator.edhoc_exporter(0u8, &[], 16).unwrap(); // label is 0
        let _oscore_salt = initiator.edhoc_exporter(1u8, &[], 8).unwrap(); // label is 1

        println!("EDHOC exchange successfully completed");
        println!("OSCORE secret: {:02x?}", _oscore_secret);
        println!("OSCORE salt: {:02x?}", _oscore_salt);
    } else {
        panic!("Message 2 processing error: {:#?}", c_r);
    }
}
