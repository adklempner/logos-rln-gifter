//! The peer signer: there is no key here. The part is empty; the identity
//! is the libp2p node's peer id, which only the host knows
//! (`libp2p_module.peerInfo`), so `identity` takes it from `args.peer_id`.

use rln_auth_vector::{args_object, Binding, Identity, Signer};
use serde_json::Value;

use crate::scheme::peer::{parse_peer_id, PeerId, NAME};

pub struct PeerSigner;

impl Signer for PeerSigner {
    fn scheme(&self) -> &'static str {
        NAME
    }
    fn sign(
        &self,
        _b: &Binding,
        _digest: &[u8; 32],
        _args: Option<&Value>,
    ) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }
    fn identity(&self, args: Option<&Value>) -> Result<Box<dyn Identity>, String> {
        let raw = args_object(args)?
            .and_then(|o| o.get("peer_id").and_then(Value::as_str).map(str::to_owned))
            .ok_or("peer identity: args.peer_id is required (the node's own, from libp2p_module.peerInfo)")?;
        Ok(Box::new(PeerId(parse_peer_id(&raw)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheme::peer::tests::ED25519_B58;

    #[test]
    fn signs_nothing_and_names_the_peer_it_is_told() {
        let b = Binding {
            id_commitment: [1; 32],
            rate_max: 1,
            audience: String::new(),
        };
        assert!(PeerSigner.sign(&b, &[0; 32], None).unwrap().is_empty());
        let args = serde_json::json!({ "peer_id": ED25519_B58 });
        assert_eq!(
            PeerSigner.identity(Some(&args)).unwrap().canonical(),
            parse_peer_id(ED25519_B58).unwrap()
        );
        let Err(e) = PeerSigner.identity(None) else {
            panic!()
        };
        assert!(e.contains("peer_id"), "{e}");
    }
}
