use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::net::{TcpListener, ToSocketAddrs, UdpSocket};
use trust_dns_proto::{
    error::ProtoError,
    op::{Header, MessageType, ResponseCode},
    rr::{rdata::TXT, DNSClass, Name, RData, Record, RecordType},
};
use trust_dns_server::{
    authority::MessageResponseBuilder,
    client::op::LowerQuery,
    server::{Request, RequestHandler},
    ServerFuture,
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

struct DnsRequestHandler {
    handle: DnsWorkerHandle,
}

impl RequestHandler for DnsRequestHandler {
    type ResponseFuture = std::future::Ready<()>;

    fn handle_request<R: trust_dns_server::server::ResponseHandler>(
        &self,
        request: Request,
        mut response_handle: R,
    ) -> Self::ResponseFuture {
        let req_message = request.message;
        let queries = req_message.queries();
        fn process_query(queries: &[LowerQuery], handle: &DnsWorkerHandle) -> Option<Vec<Record>> {
            if queries.len() != 1 {
                return None;
            }
            let q = &queries[0];
            match (q.query_class(), q.query_type()) {
                (DNSClass::IN, RecordType::TXT) => (),
                _ => return None,
            }
            let name = q.original().name();
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
            let tokens = handle.get_tokens(&parent_name);
            tracing::debug!("For {} tokens are {:?}.", &parent_name, &tokens);
            match tokens {
                None => None,
                Some(v) if v.is_empty() => None,
                Some(v) => {
                    let mut res = Vec::new();
                    for tk in v {
                        res.push(Record::from_rdata(
                            name.clone(),
                            1,
                            RData::TXT(TXT::new(vec![tk])),
                        ));
                    }
                    Some(res)
                }
            }
        }
        let answer_records = process_query(queries, &self.handle);
        if let Some(answer_records) = answer_records {
            tracing::debug!("Replying with tokens:");
            let mut header = Header::new();
            header
                .set_id(req_message.id())
                .set_message_type(MessageType::Response)
                .set_op_code(req_message.op_code())
                .set_authoritative(true)
                .set_truncated(false)
                .set_recursion_available(false)
                .set_recursion_desired(req_message.recursion_desired())
                .set_authentic_data(false)
                .set_checking_disabled(req_message.checking_disabled())
                .set_response_code(ResponseCode::NoError)
                .set_query_count(1)
                .set_answer_count(answer_records.len().try_into().unwrap())
                .set_name_server_count(0)
                .set_additional_count(0);

            let response = MessageResponseBuilder::new(Some(req_message.raw_queries())).build(
                header,
                Box::new(answer_records.iter()) as Box<dyn Iterator<Item = &Record> + Send>,
                Box::new(None.iter()) as Box<dyn Iterator<Item = &Record> + Send>,
                Box::new(None.iter()) as Box<dyn Iterator<Item = &Record> + Send>,
                Box::new(None.iter()) as Box<dyn Iterator<Item = &Record> + Send>,
            );
            response_handle.send_response(response).unwrap();
        }
        std::future::ready(())
    }
}

pub(crate) struct DnsWorker {
    serv_future: ServerFuture<DnsRequestHandler>,
    handle: DnsWorkerHandle,
}

impl DnsWorker {
    pub(crate) async fn new<A: ToSocketAddrs>(listening_addr: A) -> std::io::Result<Self> {
        let handle = DnsWorkerHandle::new();
        let mut serv_future = ServerFuture::new(DnsRequestHandler {
            handle: handle.clone(),
        });
        let udp_socket = UdpSocket::bind(&listening_addr).await?;
        serv_future.register_socket(udp_socket);
        let tcp_listener = TcpListener::bind(&listening_addr).await?;
        serv_future.register_listener(tcp_listener, Duration::from_secs(60));
        Ok(DnsWorker {
            serv_future,
            handle,
        })
    }

    pub(crate) async fn run(self) -> std::result::Result<(), ProtoError> {
        self.serv_future.block_until_done().await
    }

    /// Get a reference to the dns worker's handle.
    pub(crate) fn handle(&self) -> &DnsWorkerHandle {
        &self.handle
    }
}
