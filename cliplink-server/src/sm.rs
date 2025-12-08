use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use cliplink_common::{Config, OwnedPacket, Packet, ToBytes};

pub struct SshSyn;
pub struct EncKey;
pub struct Connected;

pub enum Input<'a> {
    SshSyn(&'a str),
}

pub enum Output {
    SshSynAck(String),
    SshSynDeny(&'static str),
}

impl<'a> From<&Packet<'a>> for Input<'a> {
    fn from(packet: &Packet<'a>) -> Self {
        match packet.ty {
            "sshsyn" => Self::SshSyn(packet.pl),
            _ => unimplemented!("unexpected type"),
        }
    }
}

impl From<Output> for OwnedPacket {
    fn from(pl: Output) -> Self {
        match pl {
            Output::SshSynAck(pl) => OwnedPacket::new("sshsynack".into(), pl),
            Output::SshSynDeny(pl) => OwnedPacket::new("sshsyndeny".into(), pl.into()),
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
pub fn validate_ssh_key(input: Input) -> Result<(), Output> {
    if !matches!(input, Input::SshSyn(pub_key)) {
        return Err(Output::SshSynDeny("pub key not found"));
    }

    Ok(())
}

pub fn gen_aes256_key(input: Input) -> Result<Output, Output> {
    if !matches!(input, Input::SshSyn(pub_key)) {
        return Err(Output::SshSynDeny("pub key not found"));
    }

    Ok(Output::SshSynAck(String::default()))
}

#[cfg(test)]
mod test {}
