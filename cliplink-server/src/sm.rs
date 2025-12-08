use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use cliplink_common::{Config, Packet};

pub struct PubKeySyn;
pub struct EncKey;
pub struct Connected;

pub enum Input<'a> {
    PubKeySyn(&'a str),
}

pub enum Output {
    RsaAck,
    RsaDeny(&'static str),
}

impl<'a> From<&Packet<'a>> for Input<'a> {
    fn from(packet: &Packet<'a>) -> Self {
        match packet.ty {
            "sshsyn" => Self::PubKeySyn(packet.pl),
            _ => unimplemented!("unexpected type"),
        }
    }
}

impl<'a> From<&Output> for Packet<'a> {
    fn from(pl: &Output) -> Self {
        match pl {
            Output::RsaAck => Packet::new("sshsynack", ""),
            Output::RsaDeny(pl) => Packet::new("sshsyndeny", pl),
            _ => unimplemented!("unexpected type"),
        }
    }
}

#[derive(Debug)]
pub enum StreamStateError {
    PubKeyNotFound,
}

pub struct StreamState;

// sshsyn > sshsynack | sshsyndeny
//
// client                  | server
// pubkeysyn (pub ssh key) > pubkeyack
// enckeyack               < enckey (encrypted)
// copy   (payload)        > copyack
// paste                   < pasteack (payload)

impl StreamState {
    pub fn gen_aes256_key(&self, input: Input) -> Result<Output, Output> {
        if !matches!(input, Input::PubKeySyn(pub_key)) {
            return Err(Output::RsaDeny("pub key not found"));
        }

        Ok(Output::RsaAck)
    }
}

#[cfg(test)]
mod test {}
