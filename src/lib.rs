use std::borrow::Cow;
use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::str;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// Constantes e lookup tables
const SAMP_MAGIC: &[u8; 4] = b"SAMP";
const MAX_PACKET_SIZE: usize = 2048;
const MAX_STRING_LEN: usize = 64;
const MIN_INTERVAL_PER_IP: Duration = Duration::from_millis(500);

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

#[derive(Debug)]
pub enum SampError {
    Io(io::Error),
    BufferUnderflow,
    InvalidMagic,
    SpoofedOrigin,
    OpcodeMismatch,
    EncodingError,
    Timeout,
    ResolutionFailed,
}

impl std::error::Error for SampError {}

impl fmt::Display for SampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O Error: {}", e),
            Self::BufferUnderflow => write!(f, "Packet buffer underflow"),
            Self::InvalidMagic => write!(f, "Invalid protocol magic"),
            Self::SpoofedOrigin => write!(f, "Origin mismatch"),
            Self::OpcodeMismatch => write!(f, "Opcode mismatch"),
            Self::EncodingError => write!(f, "Encoding or length error"),
            Self::Timeout => write!(f, "Request timed out"),
            Self::ResolutionFailed => write!(f, "DNS resolution failed"),
        }
    }
}

impl From<io::Error> for SampError {
    fn from(e: io::Error) -> Self {
        SampError::Io(e)
    }
}

#[derive(Debug, Clone)]
pub struct ServerInfo<'a> {
    pub password: bool,
    pub players: u16,
    pub max_players: u16,
    pub hostname: Cow<'a, str>,
    pub gamemode: Cow<'a, str>,
    pub mapname: Cow<'a, str>,
}

impl<'a> ServerInfo<'a> {
    pub fn into_owned(self) -> ServerInfo<'static> {
        ServerInfo {
            password: self.password,
            players: self.players,
            max_players: self.max_players,
            hostname: Cow::Owned(self.hostname.into_owned()),
            gamemode: Cow::Owned(self.gamemode.into_owned()),
            mapname: Cow::Owned(self.mapname.into_owned()),
        }
    }
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

pub struct BatchResult {
    pub target: SocketAddr,
    pub original_input: String,
    pub result: Result<ServerInfo<'static>, SampError>,
    pub rtt: Duration,
}

struct ByteReader<'a> {
    inner: &'a [u8],
    cursor: usize,
}

impl<'a> ByteReader<'a> {
    #[inline(always)]
    fn new(data: &'a [u8]) -> Self {
        Self {
            inner: data,
            cursor: 0,
        }
    }

    #[inline(always)]
    fn check_bounds(&self, len: usize) -> Result<(), SampError> {
        if self.cursor + len > self.inner.len() {
            Err(SampError::BufferUnderflow)
        } else {
            Ok(())
        }
    }

    fn read_u8(&mut self) -> Result<u8, SampError> {
        self.check_bounds(1)?;
        let b = self.inner[self.cursor];
        self.cursor += 1;
        Ok(b)
    }

    fn read_le_u16(&mut self) -> Result<u16, SampError> {
        self.check_bounds(2)?;
        let bytes = self.inner[self.cursor..self.cursor + 2].try_into().unwrap();
        self.cursor += 2;
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_le_u32(&mut self) -> Result<u32, SampError> {
        self.check_bounds(4)?;
        let bytes = self.inner[self.cursor..self.cursor + 4].try_into().unwrap();
        self.cursor += 4;
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_le_i32(&mut self) -> Result<i32, SampError> {
        self.read_le_u32().map(|x| x as i32)
    }

    fn read_str_len(&mut self, len: usize) -> Result<Cow<'a, str>, SampError> {
        self.check_bounds(len)?;
        let slice = &self.inner[self.cursor..self.cursor + len];
        self.cursor += len;

        if slice.iter().all(|&b| b < 128) {
            return Ok(Cow::Borrowed(
                std::str::from_utf8(slice).map_err(|_| SampError::EncodingError)?,
            ));
        }

        let s: String = slice
            .iter()
            .map(|&b| {
                if b < 128 {
                    b as char
                } else {
                    CP1251_TABLE[(b - 0x80) as usize]
                }
            })
            .collect();

        Ok(Cow::Owned(s))
    }

    fn read_str_u32(&mut self) -> Result<Cow<'a, str>, SampError> {
        let len = self.read_le_u32()? as usize;
        if len > MAX_STRING_LEN {
            return Err(SampError::EncodingError);
        }
        self.read_str_len(len)
    }

    fn read_str_u8(&mut self) -> Result<Cow<'a, str>, SampError> {
        let len = self.read_u8()? as usize;
        self.read_str_len(len)
    }
}

struct GcraLimiter {
    emission_interval: u64,
    tat: Instant,
}

impl GcraLimiter {
    fn new(pps: u64) -> Self {
        Self {
            emission_interval: 1_000_000_000 / pps.max(1),
            tat: Instant::now(),
        }
    }

    fn check(&mut self) -> bool {
        let now = Instant::now();
        if now < self.tat {
            return false;
        }
        self.tat = now + Duration::from_nanos(self.emission_interval);
        true
    }
}

struct FastRng {
    state: u64,
}

impl FastRng {
    fn new() -> Self {
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;

        let addr_entropy = &start as *const _ as u64;

        Self {
            state: start ^ addr_entropy,
        }
    }

    fn next_u32(&mut self) -> u32 {
        self.state = self
            .state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.state >> 32) as u32
    }
}

fn normalize_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4() {
            Some(v4) => SocketAddr::V4(SocketAddrV4::new(v4, v6.port())),
            None => addr,
        },
        v4 => v4,
    }
}

fn build_packet(buf: &mut [u8], addr: SocketAddr, opcode: Opcode, payload: Option<&[u8]>) -> usize {
    buf[0..4].copy_from_slice(SAMP_MAGIC);
    let effective_addr = normalize_addr(addr);

    match effective_addr {
        SocketAddr::V4(ip) => {
            buf[4..8].copy_from_slice(&ip.ip().octets());
            buf[8..10].copy_from_slice(&ip.port().to_le_bytes());
        }
        SocketAddr::V6(_) => {
            buf[4..8].fill(0);
            buf[8..10].copy_from_slice(&addr.port().to_le_bytes());
        }
    }

    buf[10] = opcode as u8;

    let mut cursor = 11;
    if let Some(data) = payload {
        buf[cursor..cursor + data.len()].copy_from_slice(data);
        cursor += data.len();
    }
    cursor
}

fn validate_header(
    buf: &[u8],
    len: usize,
    origin: SocketAddr,
    opcode: Opcode,
) -> Result<(), SampError> {
    if len < 11 {
        return Err(SampError::BufferUnderflow);
    }
    if &buf[0..4] != SAMP_MAGIC {
        return Err(SampError::InvalidMagic);
    }
    if buf[10] != opcode as u8 {
        return Err(SampError::OpcodeMismatch);
    }

    let effective_addr = normalize_addr(origin);

    match effective_addr {
        SocketAddr::V4(ip) => {
            if buf[4..8] != ip.ip().octets() {
                return Err(SampError::SpoofedOrigin);
            }
            if buf[8..10] != ip.port().to_le_bytes() {
                return Err(SampError::SpoofedOrigin);
            }
        }
        SocketAddr::V6(ip) => {
            if buf[8..10] != ip.port().to_le_bytes() {
                return Err(SampError::SpoofedOrigin);
            }
        }
    }

    Ok(())
}

pub struct SampClient {
    socket: UdpSocket,
}

impl SampClient {
    pub fn new(timeout: Duration) -> Result<Self, SampError> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;

        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;
        Ok(Self { socket })
    }

    fn resolve(&self, target: impl ToSocketAddrs) -> Result<SocketAddr, SampError> {
        target
            .to_socket_addrs()?
            .next()
            .ok_or(SampError::ResolutionFailed)
    }

    fn send_recv<F, T>(
        &self,
        addr: SocketAddr,
        opcode: Opcode,
        payload: Option<&[u8]>,
        parser: F,
    ) -> Result<T, SampError>
    where
        F: Fn(&[u8]) -> Result<T, SampError>,
    {
        let mut buf = [0u8; MAX_PACKET_SIZE];
        let len = build_packet(&mut buf, addr, opcode, payload);

        self.socket.send_to(&buf[..len], addr)?;

        let (recv_len, src) = self.socket.recv_from(&mut buf)?;
        let normalized_src = normalize_addr(src);
        let normalized_target = normalize_addr(addr);

        if normalized_src != normalized_target {
            return Err(SampError::SpoofedOrigin);
        }

        validate_header(&buf, recv_len, src, opcode)?;
        parser(&buf[11..recv_len])
    }

    // (SAMP + IP + Port + Opcode) = 11 bytes
    pub fn get_info(&self, target: impl ToSocketAddrs) -> Result<ServerInfo<'static>, SampError> {
        let addr = self.resolve(target)?;
        self.send_recv(addr, Opcode::Info, None, |data| {
            let mut r = ByteReader::new(data);
            Ok(ServerInfo {
                password: r.read_u8()? != 0,
                players: r.read_le_u16()?,
                max_players: r.read_le_u16()?,
                hostname: r.read_str_u32()?.into_owned().into(),
                gamemode: r.read_str_u32()?.into_owned().into(),
                mapname: r.read_str_u32()?.into_owned().into(),
            }
            .into_owned())
        })
    }

    pub fn get_rules(&self, target: impl ToSocketAddrs) -> Result<Vec<ServerRule>, SampError> {
        let addr = self.resolve(target)?;
        self.send_recv(addr, Opcode::Rules, None, |data| {
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
        self.send_recv(addr, Opcode::Clients, None, |data| {
            let mut r = ByteReader::new(data);
            let count = r.read_le_u16()?;
            let mut clients = Vec::with_capacity(count as usize);
            for _ in 0..count {
                clients.push(ServerClient {
                    name: r.read_str_u8()?.into_owned(),
                    score: r.read_le_i32()?,
                });
            }
            Ok(clients)
        })
    }

    pub fn get_ping(&self, target: impl ToSocketAddrs) -> Result<Duration, SampError> {
        let addr = self.resolve(target)?;
        let mut rng = FastRng::new();
        let cookie = rng.next_u32().to_le_bytes();
        let start = Instant::now();

        self.send_recv(addr, Opcode::Ping, Some(&cookie), |data| {
            if data.len() < 4 || data[0..4] != cookie {
                Err(SampError::OpcodeMismatch)
            } else {
                Ok(())
            }
        })?;

        Ok(start.elapsed())
    }
}

struct PendingRequest {
    original_input: String,
    sent_at: Instant,
    retries_left: u8,
}

pub fn query_batch(
    targets: Vec<String>,
    timeout: Duration,
    retries: usize,
    global_pps: u64,
) -> Result<Vec<BatchResult>, SampError> {
    let socket = UdpSocket::bind("[::]:0")?;

    socket.set_read_timeout(Some(Duration::from_millis(200)))?;

    let socket_rx = socket.try_clone()?;

    let (tx_resolve, rx_resolve) = mpsc::sync_channel(1024);
    let (tx_recv, rx_recv) = mpsc::channel();
    let total_targets = targets.len();

    let should_exit = &AtomicBool::new(false);

    let mut results = Vec::with_capacity(total_targets);

    thread::scope(|s| {
        s.spawn(move || {
            for target in targets {
                if should_exit.load(Ordering::Relaxed) {
                    break;
                }

                let addr_res = target.to_socket_addrs().map(|mut i| {
                    let addrs: Vec<_> = i.by_ref().collect();
                    addrs
                        .iter()
                        .find(|a| a.is_ipv4())
                        .copied()
                        .or_else(|| addrs.first().copied())
                });

                if tx_resolve.send((target, addr_res)).is_err() {
                    break;
                }
            }
        });

        let tx_recv_clone = tx_recv.clone();
        s.spawn(move || {
            let mut buf = [0u8; MAX_PACKET_SIZE];
            while !should_exit.load(Ordering::Relaxed) {
                match socket_rx.recv_from(&mut buf) {
                    Ok((len, src)) => {
                        if len > 11 && &buf[0..4] == SAMP_MAGIC && buf[10] == Opcode::Info as u8 {
                            let res = (|| {
                                validate_header(&buf, len, src, Opcode::Info)?;
                                let mut r = ByteReader::new(&buf[11..len]);
                                Ok(ServerInfo {
                                    password: r.read_u8()? != 0,
                                    players: r.read_le_u16()?,
                                    max_players: r.read_le_u16()?,
                                    hostname: r.read_str_u32()?.into_owned().into(),
                                    gamemode: r.read_str_u32()?.into_owned().into(),
                                    mapname: r.read_str_u32()?.into_owned().into(),
                                }
                                .into_owned())
                            })();

                            if tx_recv_clone.send((src, res)).is_err() {
                                break;
                            }
                        }
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::TimedOut =>
                    {
                        continue;
                    }
                    Err(_) => break,
                }
            }
        });

        let mut pending = HashMap::with_capacity(total_targets);
        let mut send_queue = VecDeque::new();
        let mut global_limiter = GcraLimiter::new(global_pps);
        let mut ip_last_sent: HashMap<IpAddr, Instant> = HashMap::new();

        let mut resolved_count = 0;
        let mut send_buf = [0u8; 128];
        let deadline = Instant::now() + timeout + Duration::from_secs(2);

        loop {
            let now = Instant::now();

            while let Ok((host, res)) = rx_resolve.try_recv() {
                resolved_count += 1;
                match res {
                    Ok(Some(addr)) => send_queue.push_back((host, addr, retries)),
                    _ => results.push(BatchResult {
                        target: SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0),
                        original_input: host,
                        result: Err(SampError::ResolutionFailed),
                        rtt: Duration::ZERO,
                    }),
                }
            }

            while !send_queue.is_empty() {
                if !global_limiter.check() {
                    break;
                }

                if let Some((host, addr, retries_left)) = send_queue.pop_front() {
                    let is_rate_limited = ip_last_sent
                        .get(&addr.ip())
                        .map(|last| now.duration_since(*last) < MIN_INTERVAL_PER_IP)
                        .unwrap_or(false);

                    if is_rate_limited {
                        send_queue.push_front((host, addr, retries_left));
                        break;
                    }

                    ip_last_sent.insert(addr.ip(), now);
                    let len = build_packet(&mut send_buf, addr, Opcode::Info, None);

                    if socket.send_to(&send_buf[..len], addr).is_ok() {
                        let normalized_addr = normalize_addr(addr);

                        pending.insert(
                            normalized_addr,
                            PendingRequest {
                                original_input: host,
                                sent_at: now,
                                retries_left: retries_left as u8,
                            },
                        );
                    }
                }
            }

            while let Ok((src, res)) = rx_recv.try_recv() {
                let normalized_src = normalize_addr(src);

                if let Some(req) = pending.remove(&normalized_src) {
                    results.push(BatchResult {
                        target: normalized_src,
                        original_input: req.original_input,
                        result: res,
                        rtt: now.duration_since(req.sent_at),
                    });
                }
            }

            let mut timeouts = Vec::new();
            for (addr, req) in pending.iter() {
                if now.duration_since(req.sent_at) > timeout {
                    timeouts.push(*addr);
                }
            }

            for addr in timeouts {
                if let Some(req) = pending.remove(&addr) {
                    if req.retries_left > 0 {
                        send_queue.push_back((
                            req.original_input,
                            addr,
                            (req.retries_left - 1) as usize,
                        ));
                    } else {
                        results.push(BatchResult {
                            target: addr,
                            original_input: req.original_input,
                            result: Err(SampError::Timeout),
                            rtt: timeout,
                        });
                    }
                }
            }

            if (resolved_count == total_targets && pending.is_empty() && send_queue.is_empty())
                || now > deadline
            {
                should_exit.store(true, Ordering::Relaxed);
                break;
            }

            thread::sleep(Duration::from_millis(1));
        }

        drop(rx_recv);
    });

    Ok(results)
}
