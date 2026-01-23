use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::str;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// Constantes e lookup tables
const SAMP_MAGIC: &[u8; 4] = b"SAMP";
const MAX_PACKET_SIZE: usize = 2048;
const MAX_ACCEPTABLE_HOSTNAME_SIZE: usize = 255;
const MAX_ACCEPTABLE_GAMEMODE_SIZE: usize = 255;
const MAX_ACCEPTABLE_LANGUAGE_SIZE: usize = 255;
const TARGET_PPS: u32 = 2000;

static CP1251_TABLE: [char; 128] = [
    '\u{0402}', '\u{0403}', '\u{201A}', '\u{0453}', '\u{201E}', '\u{2026}', '\u{2020}', '\u{2021}',
    '\u{20AC}', '\u{2030}', '\u{0409}', '\u{2039}', '\u{040A}', '\u{040C}', '\u{040B}', '\u{040F}',
    '\u{0452}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}', '\u{2022}', '\u{2013}', '\u{2014}',
    '\u{0098}', '\u{2122}', '\u{0459}', '\u{203A}', '\u{045A}', '\u{045C}', '\u{045B}', '\u{045F}',
    '\u{00A0}', '\u{040E}', '\u{045E}', '\u{0408}', '\u{00A4}', '\u{0490}', '\u{00A6}', '\u{00A7}',
    '\u{0401}', '\u{00A9}', '\u{0404}', '\u{00AB}', '\u{00AC}', '\u{00AD}', '\u{00AE}', '\u{0407}',
    '\u{00B0}', '\u{00B1}', '\u{0406}', '\u{0456}', '\u{0491}', '\u{00B5}', '\u{00B6}', '\u{00B7}',
    '\u{0451}', '\u{2116}', '\u{0454}', '\u{00BB}', '\u{0458}', '\u{0405}', '\u{0455}', '\u{0457}',
    '\u{0410}', '\u{0411}', '\u{0412}', '\u{0413}', '\u{0414}', '\u{0415}', '\u{0416}', '\u{0417}',
    '\u{0418}', '\u{0419}', '\u{041A}', '\u{041B}', '\u{041C}', '\u{041D}', '\u{041E}', '\u{041F}',
    '\u{0420}', '\u{0421}', '\u{0422}', '\u{0423}', '\u{0424}', '\u{0425}', '\u{0426}', '\u{0427}',
    '\u{0428}', '\u{0429}', '\u{042A}', '\u{042B}', '\u{042C}', '\u{042D}', '\u{042E}', '\u{042F}',
    '\u{0430}', '\u{0431}', '\u{0432}', '\u{0433}', '\u{0434}', '\u{0435}', '\u{0436}', '\u{0437}',
    '\u{0438}', '\u{0439}', '\u{043A}', '\u{043B}', '\u{043C}', '\u{043D}', '\u{043E}', '\u{043F}',
    '\u{0440}', '\u{0441}', '\u{0442}', '\u{0443}', '\u{0444}', '\u{0445}', '\u{0446}', '\u{0447}',
    '\u{0448}', '\u{0449}', '\u{044A}', '\u{044B}', '\u{044C}', '\u{044D}', '\u{044E}', '\u{044F}',
];

#[derive(Debug)]
pub enum SampError {
    Io(io::Error),
    Protocol(&'static str),
    OutOfBounds,
    MismatchOrigin,
    MismatchOpcode,
    ResolutionFailed,
    Timeout,
    PingSignatureMismatch,
    IPv6Unavailable,
}

impl std::error::Error for SampError {}

impl fmt::Display for SampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O: {}", e),
            Self::Protocol(s) => write!(f, "Protocol: {}", s),
            Self::OutOfBounds => write!(f, "Buffer overrun"),
            Self::MismatchOrigin => write!(f, "Origin mismatch (spoofing detected)"),
            Self::MismatchOpcode => write!(f, "Opcode mismatch"),
            Self::ResolutionFailed => write!(f, "DNS resolution failed"),
            Self::Timeout => write!(f, "Request timed out"),
            Self::PingSignatureMismatch => write!(f, "Ping cookie mismatch"),
            Self::IPv6Unavailable => write!(f, "IPv6 interface unavailable on client"),
        }
    }
}

impl From<io::Error> for SampError {
    fn from(e: io::Error) -> Self {
        SampError::Io(e)
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Info = b'i',
    Rules = b'r',
    Clients = b'c',
    Detailed = b'd',
    Ping = b'p',
    OpenMp = b'o',
}

// Estruturas de dados
#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub password: bool,
    pub players: u16,
    pub max_players: u16,
    pub hostname: String,
    pub gamemode: String,
    pub mapname: String,
    pub is_openmp: bool,
}

#[derive(Debug, Clone)]
pub struct ServerRule {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct ServerClient {
    pub name: String,
    pub score: i32,
}

#[derive(Debug, Clone)]
pub struct OpenMpInfo {
    pub discord: String,
    pub banner_light: String,
    pub banner_dark: String,
    pub logo: String,
}

#[derive(Debug)]
pub struct BatchResult {
    pub target: String,
    pub info: Result<ServerInfo, SampError>,
}

struct CookieRng {
    state: u64,
}

impl CookieRng {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;
        Self { state: nanos }
    }

    fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (self.state >> 33) as u32
    }
}

fn decode_str(bytes: &[u8]) -> Cow<'_, str> {
    if let Ok(s) = str::from_utf8(bytes) {
        return Cow::Borrowed(s);
    }
    let s: String = bytes
        .iter()
        .map(|&b| {
            if b < 128 {
                b as char
            } else {
                CP1251_TABLE[(b - 0x80) as usize]
            }
        })
        .collect();
    Cow::Owned(s)
}

struct ByteReader<'a> {
    inner: &'a [u8],
    cursor: usize,
}

impl<'a> ByteReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            inner: data,
            cursor: 0,
        }
    }

    fn remaining(&self) -> usize {
        self.inner.len().saturating_sub(self.cursor)
    }

    fn read_u8(&mut self) -> Result<u8, SampError> {
        if self.remaining() < 1 {
            return Err(SampError::OutOfBounds);
        }
        let b = self.inner[self.cursor];
        self.cursor += 1;
        Ok(b)
    }

    fn read_le_u16(&mut self) -> Result<u16, SampError> {
        if self.remaining() < 2 {
            return Err(SampError::OutOfBounds);
        }
        let b = &self.inner[self.cursor..self.cursor + 2];
        self.cursor += 2;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn read_le_u32(&mut self) -> Result<u32, SampError> {
        if self.remaining() < 4 {
            return Err(SampError::OutOfBounds);
        }
        let b = &self.inner[self.cursor..self.cursor + 4];
        self.cursor += 4;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_le_i32(&mut self) -> Result<i32, SampError> {
        if self.remaining() < 4 {
            return Err(SampError::OutOfBounds);
        }
        let b = &self.inner[self.cursor..self.cursor + 4];
        self.cursor += 4;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_slice(&mut self, len: usize) -> Result<&'a [u8], SampError> {
        if self.remaining() < len {
            return Err(SampError::OutOfBounds);
        }
        let s = &self.inner[self.cursor..self.cursor + len];
        self.cursor += len;
        Ok(s)
    }

    fn read_str_u32(&mut self, limit: usize) -> Result<Cow<'a, str>, SampError> {
        let len = self.read_le_u32()? as usize;
        if len > limit {
            return Err(SampError::Protocol(
                "String length exceeds strict safety limit",
            ));
        }
        let bytes = self.read_slice(len)?;
        Ok(decode_str(bytes))
    }

    fn read_str_u8(&mut self) -> Result<Cow<'a, str>, SampError> {
        let len = self.read_u8()? as usize;
        let bytes = self.read_slice(len)?;
        Ok(decode_str(bytes))
    }
}

fn build_packet(out_buf: &mut Vec<u8>, target: SocketAddr, opcode: Opcode, payload: Option<&[u8]>) {
    out_buf.clear();
    out_buf.extend_from_slice(SAMP_MAGIC);

    match target {
        SocketAddr::V4(v4) => {
            out_buf.extend_from_slice(&v4.ip().octets());
            out_buf.extend_from_slice(&v4.port().to_le_bytes());
        }
        SocketAddr::V6(v6) => {
            out_buf.extend_from_slice(&[0, 0, 0, 0]);
            out_buf.extend_from_slice(&v6.port().to_le_bytes());
        }
    }

    out_buf.push(opcode as u8);

    if let Some(data) = payload {
        out_buf.extend_from_slice(data);
    }
}

fn validate_header(buf: &[u8], target: SocketAddr, opcode: Opcode) -> Result<(), SampError> {
    if buf.len() < 11 {
        return Err(SampError::OutOfBounds);
    }
    if &buf[0..4] != SAMP_MAGIC {
        return Err(SampError::Protocol("Invalid Magic"));
    }

    match target {
        SocketAddr::V4(addr) => {
            if buf[4..8] != addr.ip().octets() {
                return Err(SampError::MismatchOrigin);
            }
            if buf[8..10] != addr.port().to_le_bytes() {
                return Err(SampError::MismatchOrigin);
            }
        }
        SocketAddr::V6(addr) => {
            if buf[8..10] != addr.port().to_le_bytes() {
                return Err(SampError::MismatchOrigin);
            }
        }
    }

    if buf[10] != opcode as u8 {
        return Err(SampError::MismatchOpcode);
    }
    Ok(())
}

struct TokenBucket {
    tokens: f64,
    fill_rate: f64,
    last_update: Instant,
}

impl TokenBucket {
    fn new(rate: u32) -> Self {
        Self {
            tokens: rate as f64,
            fill_rate: rate as f64,
            last_update: Instant::now(),
        }
    }

    fn take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.fill_rate).min(self.fill_rate);
        self.last_update = now;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

pub struct SampClient {
    socket_v4: UdpSocket,
    socket_v6: Option<UdpSocket>,
    send_buf: Arc<Mutex<Vec<u8>>>,
}

impl SampClient {
    pub fn new(timeout: Duration) -> Result<Self, SampError> {
        let socket_v4 = UdpSocket::bind("0.0.0.0:0")?;
        socket_v4.set_read_timeout(Some(timeout))?;
        socket_v4.set_write_timeout(Some(timeout))?;

        let socket_v6 = match UdpSocket::bind("[::]:0") {
            Ok(s) => {
                let _ = s.set_read_timeout(Some(timeout));
                let _ = s.set_write_timeout(Some(timeout));
                Some(s)
            }
            Err(_) => None,
        };

        Ok(Self {
            socket_v4,
            socket_v6,
            send_buf: Arc::new(Mutex::new(Vec::with_capacity(MAX_PACKET_SIZE))),
        })
    }

    fn resolve(&self, target: impl ToSocketAddrs) -> Result<SocketAddr, SampError> {
        let mut addrs = target.to_socket_addrs()?;
        let first = addrs.next().ok_or(SampError::ResolutionFailed)?;

        if first.is_ipv4() {
            return Ok(first);
        }

        if let Some(v4) = addrs.find(|x| x.is_ipv4()) {
            return Ok(v4);
        }

        Ok(first)
    }

    fn get_socket_for(&self, addr: SocketAddr) -> Result<&UdpSocket, SampError> {
        match addr {
            SocketAddr::V4(_) => Ok(&self.socket_v4),
            SocketAddr::V6(_) => self.socket_v6.as_ref().ok_or(SampError::IPv6Unavailable),
        }
    }

    fn query<F, T>(
        &self,
        addr: SocketAddr,
        opcode: Opcode,
        payload: Option<&[u8]>,
        parser: F,
    ) -> Result<T, SampError>
    where
        F: Fn(&[u8]) -> Result<T, SampError>,
    {
        let socket = self.get_socket_for(addr)?;

        {
            let mut buf = self.send_buf.lock().unwrap();
            build_packet(&mut buf, addr, opcode, payload);
            socket.send_to(&buf, addr)?;
        }

        let mut buf = [0u8; MAX_PACKET_SIZE];
        let start = Instant::now();
        let timeout = socket.read_timeout()?.unwrap_or(Duration::from_secs(1));

        loop {
            if start.elapsed() > timeout {
                return Err(SampError::Timeout);
            }
            match socket.recv_from(&mut buf) {
                Ok((len, src)) => {
                    if src == addr && validate_header(&buf[..len], src, opcode).is_ok() {
                        return parser(&buf[11..len]);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::TimedOut => return Err(SampError::Timeout),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(SampError::Io(e)),
            }
        }
    }

    // (SAMP + IP + Port + Opcode) = 11 bytes
    pub fn get_info(&self, target: impl ToSocketAddrs) -> Result<ServerInfo, SampError> {
        let addr = self.resolve(target)?;
        self.query(addr, Opcode::Info, None, |data| {
            let mut r = ByteReader::new(data);
            Ok(ServerInfo {
                password: r.read_u8()? != 0,
                players: r.read_le_u16()?,
                max_players: r.read_le_u16()?,
                hostname: r.read_str_u32(MAX_ACCEPTABLE_HOSTNAME_SIZE)?.into_owned(),
                gamemode: r.read_str_u32(MAX_ACCEPTABLE_GAMEMODE_SIZE)?.into_owned(),
                mapname: r.read_str_u32(MAX_ACCEPTABLE_LANGUAGE_SIZE)?.into_owned(),
                is_openmp: false,
            })
        })
    }

    pub fn get_rules(&self, target: impl ToSocketAddrs) -> Result<Vec<ServerRule>, SampError> {
        let addr = self.resolve(target)?;
        self.query(addr, Opcode::Rules, None, |data| {
            let mut r = ByteReader::new(data);
            let count = r.read_le_u16()?;
            let mut rules = Vec::with_capacity(count as usize);
            for _ in 0..count {
                rules.push(ServerRule {
                    name: r.read_str_u8()?.into_owned(),
                    value: r.read_str_u8()?.into_owned(),
                });
            }
            Ok(rules)
        })
    }

    pub fn get_clients(&self, target: impl ToSocketAddrs) -> Result<Vec<ServerClient>, SampError> {
        let addr = self.resolve(target)?;
        self.query(addr, Opcode::Clients, None, |data| {
            let mut r = ByteReader::new(data);
            let count = r.read_le_u16()?;
            let mut clients = Vec::with_capacity(count as usize);
            for _ in 0..count {
                let name = r.read_str_u8()?.into_owned();
                let score = r.read_le_i32()?;
                clients.push(ServerClient { name, score });
            }
            Ok(clients)
        })
    }

    pub fn get_ping(&self, target: impl ToSocketAddrs) -> Result<Duration, SampError> {
        let addr = self.resolve(target)?;
        let mut rng = CookieRng::new();
        let cookie = rng.next_u32().to_le_bytes();

        let start = Instant::now();
        self.query(addr, Opcode::Ping, Some(&cookie), |data| {
            if data.len() < 4 {
                return Err(SampError::OutOfBounds);
            }
            if data[0..4] != cookie {
                return Err(SampError::PingSignatureMismatch);
            }
            Ok(())
        })?;

        Ok(start.elapsed())
    }

    pub fn get_openmp_info(&self, target: impl ToSocketAddrs) -> Result<OpenMpInfo, SampError> {
        let addr = self.resolve(target)?;
        self.query(addr, Opcode::OpenMp, None, |data| {
            let mut r = ByteReader::new(data);
            Ok(OpenMpInfo {
                discord: r.read_str_u32(50)?.into_owned(),
                banner_light: r.read_str_u32(160)?.into_owned(),
                banner_dark: r.read_str_u32(160)?.into_owned(),
                logo: r.read_str_u32(160)?.into_owned(),
            })
        })
    }

    pub fn is_openmp(&self, rules: &[ServerRule]) -> bool {
        for r in rules {
            if r.name == "version" && r.value.contains("omp") {
                return true;
            }
            if r.name == "allow_DL" {
                return true;
            }
        }
        false
    }
}

struct PendingReq {
    target: String,
    sent_at: Instant,
    retries: u8,
}

pub fn query_batch(targets: Vec<String>, timeout: Duration, retries: usize) -> Vec<BatchResult> {
    let (tx, rx) = mpsc::channel();
    let total = targets.len();

    thread::spawn(move || {
        let chunks: Vec<_> = targets.chunks((targets.len() / 8).max(1)).collect();
        thread::scope(|s| {
            for chunk in chunks {
                let txc = tx.clone();
                s.spawn(move || {
                    for t in chunk {
                        let res = t.to_socket_addrs().map(|mut i| {
                            let first = i.next();
                            match first {
                                Some(addr) => {
                                    let resolved = if addr.is_ipv4() {
                                        addr
                                    } else {
                                        i.find(|x| x.is_ipv4()).unwrap_or(addr)
                                    };
                                    Some(resolved)
                                }
                                None => None,
                            }
                        });

                        let final_res = match res {
                            Ok(Some(addr)) => Ok(addr),
                            Ok(None) => Err(io::Error::other("No address found")),
                            Err(e) => Err(e),
                        };

                        let _ = txc.send((t.clone(), final_res));
                    }
                });
            }
        });
    });

    let sock_v4 = UdpSocket::bind("0.0.0.0:0").ok();
    let sock_v6 = UdpSocket::bind("[::]:0").ok();

    if sock_v4.is_none() && sock_v6.is_none() {
        return Vec::new();
    }

    if let Some(ref s) = sock_v4 {
        let _ = s.set_nonblocking(true);
    }
    if let Some(ref s) = sock_v6 {
        let _ = s.set_nonblocking(true);
    }

    let mut results = Vec::with_capacity(total);
    let mut pending: HashMap<SocketAddr, PendingReq> = HashMap::new();
    let mut queue = VecDeque::new();
    let mut limiter = TokenBucket::new(TARGET_PPS);
    let deadline = Instant::now() + timeout + Duration::from_secs(2);

    let mut resolved_count = 0;
    let mut send_buf = Vec::with_capacity(1024);
    let mut recv_buf = [0u8; MAX_PACKET_SIZE];

    while Instant::now() < deadline {
        let mut busy = false;

        while let Ok((host, res)) = rx.try_recv() {
            resolved_count += 1;
            match res {
                Ok(addr) => queue.push_back((host, addr)),
                Err(e) => results.push(BatchResult {
                    target: host,
                    info: Err(SampError::Io(e)),
                }),
            }
        }

        while !queue.is_empty() {
            if !limiter.take() {
                break;
            }
            if let Some((host, addr)) = queue.pop_front() {
                let socket = match addr {
                    SocketAddr::V4(_) => sock_v4.as_ref(),
                    SocketAddr::V6(_) => sock_v6.as_ref(),
                };

                if let Some(s) = socket {
                    build_packet(&mut send_buf, addr, Opcode::Info, None);
                    match s.send_to(&send_buf, addr) {
                        Ok(_) => {
                            pending.insert(
                                addr,
                                PendingReq {
                                    target: host,
                                    sent_at: Instant::now(),
                                    retries: retries as u8,
                                },
                            );
                            busy = true;
                        }
                        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                            queue.push_front((host, addr));
                            break;
                        }
                        Err(_) => {
                            results.push(BatchResult {
                                target: host,
                                info: Err(SampError::Io(io::Error::other("Send failed"))),
                            });
                        }
                    }
                } else {
                    results.push(BatchResult {
                        target: host,
                        info: Err(SampError::IPv6Unavailable),
                    });
                }
            }
        }

        let sockets_to_poll = [&sock_v4, &sock_v6];
        for socket in sockets_to_poll.into_iter().flatten() {
            loop {
                match socket.recv_from(&mut recv_buf) {
                    Ok((len, src)) => {
                        if let Some(req) = pending.remove(&src) {
                            busy = true;
                            let res = (|| {
                                validate_header(&recv_buf[..len], src, Opcode::Info)?;
                                let mut r = ByteReader::new(&recv_buf[11..len]);
                                Ok(ServerInfo {
                                    password: r.read_u8()? != 0,
                                    players: r.read_le_u16()?,
                                    max_players: r.read_le_u16()?,
                                    hostname: r
                                        .read_str_u32(MAX_ACCEPTABLE_HOSTNAME_SIZE)?
                                        .into_owned(),
                                    gamemode: r
                                        .read_str_u32(MAX_ACCEPTABLE_GAMEMODE_SIZE)?
                                        .into_owned(),
                                    mapname: r
                                        .read_str_u32(MAX_ACCEPTABLE_LANGUAGE_SIZE)?
                                        .into_owned(),
                                    is_openmp: false,
                                })
                            })();
                            results.push(BatchResult {
                                target: req.target,
                                info: res,
                            });
                        }
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }

        if !pending.is_empty() {
            let now = Instant::now();
            let mut retry = Vec::new();
            let mut fail = Vec::new();

            for (addr, req) in pending.iter() {
                if now.duration_since(req.sent_at) > timeout {
                    if req.retries > 0 {
                        retry.push(*addr);
                    } else {
                        fail.push(*addr);
                    }
                }
            }

            for addr in fail {
                if let Some(req) = pending.remove(&addr) {
                    results.push(BatchResult {
                        target: req.target,
                        info: Err(SampError::Timeout),
                    });
                }
            }

            for addr in retry {
                if let Some(mut req) = pending.remove(&addr) {
                    req.retries -= 1;
                    req.sent_at = Instant::now();
                    queue.push_front((req.target.clone(), addr));
                }
            }
        }

        if resolved_count == total && pending.is_empty() && queue.is_empty() {
            break;
        }
        if !busy {
            thread::sleep(Duration::from_millis(1));
        }
    }

    results
}
