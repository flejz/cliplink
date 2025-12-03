use std::{marker::PhantomData, net::TcpStream};

use cliplink_common::Packet;

pub enum StreamPayload<'a> {
    SshSyn(&'a str),
    SshAck,
    SshDeny(&'static str),
}

impl<'a> From<&Packet<'a>> for StreamPayload<'a> {
    fn from(packet: &Packet<'a>) -> Self {
        match packet.ty {
            "sshsyn" => Self::SshSyn(packet.pl),
            _ => unimplemented!("unexpected type"),
        }
    }
}

impl<'a> From<&StreamPayload<'a>> for Packet<'a> {
    fn from(pl: &StreamPayload<'a>) -> Self {
        match pl {
            StreamPayload::SshAck => Packet::new("sshsynack", ""),
            StreamPayload::SshDeny(pl) => Packet::new("sshsyndeny", pl),
            _ => unimplemented!("unexpected payload"),
        }
    }
}

pub struct SshSyn;
pub struct EncKey;
pub struct Connected;

pub struct StreamState<T = SshSyn> {
    stream: TcpStream,
    _phantom: PhantomData<T>,
}

pub trait StreamStateTransition<T> {
    fn transition(self, pl: StreamPayload) -> Result<T, ()>;
    fn is_ready(&self) -> bool {
        false
    }
}

impl<T> StreamState<T> {
    fn to<S>(self) -> StreamState<S> {
        StreamState {
            stream: self.stream,
            _phantom: PhantomData::<S>,
        }
    }
}

impl StreamState {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            _phantom: PhantomData,
        }
    }
}

// sshsyn > sshsynack | sshsyndeny
//
// client               | server
// sshsyn (pub ssh key) > sshack
// enckeyack            < enckey (encrypted)
// copy   (payload)     > copyack
// paste                < pasteack (payload)

impl StreamStateTransition<StreamState<EncKey>> for StreamState<SshSyn> {
    fn transition(self, pl: StreamPayload) -> Result<StreamState<EncKey>, ()> {
        Ok(self.to::<EncKey>())
    }
}

impl StreamStateTransition<StreamState<Connected>> for StreamState<EncKey> {
    fn transition(self, pl: StreamPayload) -> Result<StreamState<Connected>, ()> {
        Ok(self.to::<Connected>())
    }
}

impl StreamStateTransition<StreamState<Connected>> for StreamState<Connected> {
    fn transition(self, pl: StreamPayload) -> Result<StreamState<Connected>, ()> {
        Ok(self.to::<Connected>())
    }

    fn is_ready(&self) -> bool {
        true
    }
}

impl StreamState<Connected> {
    pub fn write(self) -> Result<(), ()> {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::net::TcpStream;

    use cliplink_common::Packet;

    use crate::sm::{StreamState, StreamStateTransition};

    const PUB_RSA_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQClVX9wH/ZtB36MWKYqPqN9ZTebtL4aEihEieCqcW0L5hEb1oksUaMfIEoBpqenb3lNP0vIEOiurpS9o65c+8xIz5WY+lCBXkgb8n9irkKqWy/bRe+N/gdtb2WYWFzgQaAIeB9N8VAaJeeG8BjD5CE0Y0VkgxVQqhqtOwNVY29vQF6NXDEvrtM1LWo2xhjzYjpFppeWs0yTg+oWosYxcTomAYjlbWqUBo6DJ6oCfo5+j+2vf96tfQaEXho0QbiLa0eP4r8Xwg1pnJ8GPYG8C3gmm8GW1OSDWKTKBPYKdxJot0dvUmc6cp/ogNz4z03tHXYputR6aQFcVCofyphru1c7";

    #[test]
    fn vai() {
        let packet = Packet::new("sshsyn", PUB_RSA_KEY);
        let state = StreamState::new();
        let state = state.transition(&packet);
    }
}
