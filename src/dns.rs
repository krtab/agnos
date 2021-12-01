use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use futures_util::stream::StreamExt;
use tokio::net::{ToSocketAddrs, UdpSocket};
use trust_dns_proto::{
    op::MessageType,
    rr::{rdata::TXT, DNSClass, Name, RData, Record, RecordType},
    udp::UdpStream,
    xfer::SerialMessage,
    BufStreamHandle,
};

#[derive(Clone, Debug)]
pub(crate) struct DnsWorkerHandle {
    tokens: Arc<Mutex<HashMap<Name, Vec<String>>>>,
}

impl DnsWorkerHandle {
    pub(crate) fn add_token(&self, name: Name, val: String) {
        tracing::debug!("Adding token {} to name: {}.", &val, &name);
        let mut lock = self.tokens.lock().unwrap();
        lock.entry(name).or_default().push(val);
        for (k, v) in lock.iter() {
            tracing::debug!("{}: {:?}", k, v);
        }
    }

    pub(crate) fn get_tokens(&self, name: &Name) -> Option<Vec<String>> {
        self.tokens.lock().unwrap().get(name).cloned()
    }

    // pub(crate) fn delete_token(&self, name: &Name) -> Option<String> {
    //     self.tokens.lock().unwrap().remove(name)
    // }

    fn new() -> Self {
        Self {
            tokens: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

pub(crate) struct DnsWorker {
    handle: DnsWorkerHandle,
    udp_stream: UdpStream<UdpSocket>,
    buf_stream_handle: BufStreamHandle,
}

impl DnsWorker {
    pub(crate) async fn new<A: ToSocketAddrs>(listening_addr: A) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(listening_addr).await?;
        let (udp_stream, buf_stream_handle) = UdpStream::with_bound(socket);
        Ok(DnsWorker {
            handle: DnsWorkerHandle::new(),
            udp_stream,
            buf_stream_handle,
        })
    }

    pub(crate) async fn run(mut self) {
        let mut stream = Box::pin(self.udp_stream.filter_map(|serialized_message| async {
            tracing::debug!("Received a DNS message.");
            let serialized_message = serialized_message.unwrap();
            let message = serialized_message.to_message().unwrap();
            let queries = message.queries();
            if queries.len() != 1 {
                return None;
            }
            let q = &queries[0];
            match (q.query_class(), q.query_type()) {
                (DNSClass::IN, RecordType::TXT) => (),
                _ => return None,
            }
            let name = q.name();
            tracing::debug!("Queried name: {}", &name);
            let mut labels = name.iter();
            let first_label = labels.next().map(|s| s.to_ascii_lowercase());
            match first_label.as_deref() {
                Some(b"_acme-challenge") => {}
                _ => {
                    tracing::debug!("First label {:?} ignoring.", &first_label);
                    return None;
                }
            }
            let parent_name = Name::from_labels(labels).unwrap();
            let tokens = self.handle.get_tokens(&parent_name);
            tracing::debug!("For {} tokens are {:?}.", &parent_name, &tokens);
            match tokens {
                None => None,
                Some(v) if v.is_empty() => None,
                Some(v) => {
                    tracing::debug!("Replying with tokens:");
                    let mut m = message.clone();
                    m.set_authoritative(true)
                        .set_message_type(MessageType::Response)
                        .set_recursion_available(false);
                    for tk in v {
                        tracing::debug!(" - {}",&tk);
                        m.add_answer(Record::from_rdata(
                            name.clone(),
                            1,
                            RData::TXT(TXT::new(vec![tk])),
                        ));
                    }
                    let buf = m.to_vec().unwrap();
                    Some(SerialMessage::new(buf, serialized_message.addr()))
                }
            }
        }));
        while let Some(serial_reply) = stream.next().await {
            self.buf_stream_handle.send(serial_reply).unwrap()
        }
    }

    /// Get a reference to the dns worker's handle.
    pub(crate) fn handle(&self) -> &DnsWorkerHandle {
        &self.handle
    }
}
