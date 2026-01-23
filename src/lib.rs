use std::fmt;
use std::io::{self, Cursor, Read, Write};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum SampError {
    Io(io::Error),
    ProtocolViolation(&'static str),
    AddressResolution(String),
    PacketTooLarge,
    PacketTooShort,
    InvalidMagic,
    OriginMismatch,
    Timeout,
}

impl fmt::Display for SampError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SampError::Io(e) => write!(f, "IO/Network error: {}", e),
            SampError::ProtocolViolation(s) => write!(f, "Protocol violation: {}", s),
            SampError::AddressResolution(s) => write!(f, "Couldn't resolve address: {}", s),
            SampError::PacketTooLarge => write!(f, "Packet exceeded limits"),
            SampError::PacketTooShort => write!(f, "Packet is too short and/or is truncated"),
            SampError::InvalidMagic => write!(f, "Invalid magic bytes"),
            SampError::OriginMismatch => {
                write!(
                    f,
                    "Response IP does not match the expected address (possible IP spoofing)"
                )
            }
            SampError::Timeout => write!(f, "Request timed out"),
        }
    }
}

impl std::error::Error for SampError {}

impl From<io::Error> for SampError {
    fn from(err: io::Error) -> Self {
        SampError::Io(err)
    }
}

// Constantes
const SAMP_MAGIC: &[u8; 4] = b"SAMP";
const MAX_PACKET_SIZE: usize = 2048;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    Information = b'i',
    Rules = b'r',
    Clients = b'c',
}

// Interfaces para leitura/escrita binária
trait PacketReader {
    fn read_u8(&mut self) -> Result<u8, SampError>;
    fn read_u16_le(&mut self) -> Result<u16, SampError>;
    fn read_u32_le(&mut self) -> Result<u32, SampError>;
    fn read_samp_string(&mut self) -> Result<String, SampError>;
}

trait PacketWriter {
    fn write_u8(&mut self, v: u8) -> Result<(), SampError>;
    fn write_u16_le(&mut self, v: u16) -> Result<(), SampError>;
    fn write_bytes(&mut self, v: &[u8]) -> Result<(), SampError>;
}

impl<T: AsRef<[u8]>> PacketReader for Cursor<T> {
    fn read_u8(&mut self) -> Result<u8, SampError> {
        let mut buf = [0u8; 1];
        self.read_exact(&mut buf)
            .map_err(|_| SampError::PacketTooShort)?;
        Ok(buf[0])
    }

    fn read_u16_le(&mut self) -> Result<u16, SampError> {
        let mut buf = [0u8; 2];
        self.read_exact(&mut buf)
            .map_err(|_| SampError::PacketTooShort)?;
        Ok(u16::from_le_bytes(buf))
    }

    fn read_u32_le(&mut self) -> Result<u32, SampError> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)
            .map_err(|_| SampError::PacketTooShort)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_samp_string(&mut self) -> Result<String, SampError> {
        let len = self.read_u32_le()? as usize;

        if len > 512 {
            return Err(SampError::ProtocolViolation("Strange string length"));
        }

        let current_pos = self.position() as usize;
        let total_len = self.get_ref().as_ref().len();

        if current_pos + len > total_len {
            return Err(SampError::PacketTooShort);
        }
        let mut buf = vec![0u8; len];
        self.read_exact(&mut buf)?;

        // lossy deve parsear encoding legacy sem panic
        Ok(String::from_utf8_lossy(&buf).to_string())
    }
}

// Escritor
impl<T> PacketWriter for Cursor<T>
where
    Cursor<T>: Write,
{
    fn write_u8(&mut self, v: u8) -> Result<(), SampError> {
        self.write_all(&[v])?;
        Ok(())
    }

    fn write_u16_le(&mut self, v: u16) -> Result<(), SampError> {
        self.write_all(&v.to_le_bytes())?;
        Ok(())
    }

    fn write_bytes(&mut self, v: &[u8]) -> Result<(), SampError> {
        self.write_all(v)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub has_password: bool,
    pub players: u16,
    pub max_players: u16,
    pub hostname: String,
    pub gamemode: String,
    pub mapname: String,
}

pub struct SampClient {
    socket: UdpSocket,
    timeout: Duration,
    retries: usize,
}

impl SampClient {
    pub fn builder() -> SampClientBuilder {
        SampClientBuilder::default()
    }

    pub fn get_information<A: ToSocketAddrs>(&self, target: A) -> Result<ServerInfo, SampError> {
        let addr = self.resolve_address(target)?;
        let mut buf = [0u8; MAX_PACKET_SIZE];
        let size = self.communicate(addr, Opcode::Information, &mut buf)?;

        self.parse_info_packet(&buf[..size])
    }

    fn communicate(
        &self,
        addr: SocketAddr,
        opcode: Opcode,
        out_buf: &mut [u8],
    ) -> Result<usize, SampError> {
        let mut attempt = 0;

        loop {
            self.send_request(addr, opcode)?;
            let deadline = Instant::now() + self.timeout;

            loop {
                let time_left = deadline.saturating_duration_since(Instant::now());
                if time_left.is_zero() {
                    break;
                }

                self.socket.set_read_timeout(Some(time_left))?;

                match self.socket.recv_from(out_buf) {
                    Ok((amt, src)) => {
                        if src != addr {
                            continue;
                        }

                        if self.validate_header(&out_buf[..amt], opcode).is_ok() {
                            return Ok(amt);
                        }
                        continue;
                    }
                    Err(e) => match e.kind() {
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                            break;
                        }
                        _ => return Err(SampError::Io(e)),
                    },
                }
            }

            attempt += 1;
            if attempt > self.retries {
                return Err(SampError::Timeout);
            }
        }
    }

    fn validate_header(&self, data: &[u8], expected_opcode: Opcode) -> Result<(), SampError> {
        if data.len() < 11 {
            return Err(SampError::PacketTooShort);
        }
        if &data[0..4] != SAMP_MAGIC {
            return Err(SampError::InvalidMagic);
        }
        if data[10] != expected_opcode as u8 {
            return Err(SampError::ProtocolViolation("Unexpected opcode"));
        }
        Ok(())
    }

    fn resolve_address<A: ToSocketAddrs>(&self, target: A) -> Result<SocketAddr, SampError> {
        target
            .to_socket_addrs()
            .map_err(SampError::Io)?
            .find(|addr| addr.is_ipv4())
            .ok_or_else(|| SampError::AddressResolution("Couldn't find an IPV4 address".into()))
    }

    fn send_request(&self, addr: SocketAddr, opcode: Opcode) -> Result<(), SampError> {
        let mut buffer = [0u8; 15];
        let mut cursor = Cursor::new(&mut buffer[..]);

        cursor.write_bytes(SAMP_MAGIC)?;

        match addr.ip() {
            IpAddr::V4(ip) => cursor.write_bytes(&ip.octets())?,
            _ => {
                return Err(SampError::AddressResolution(
                    "IPV6 is not supported by the protocol".into(),
                ));
            }
        };

        cursor.write_u16_le(addr.port())?;
        cursor.write_u8(opcode as u8)?;

        let len = cursor.position() as usize;
        self.socket.send_to(&cursor.get_ref()[..len], addr)?;
        Ok(())
    }

    fn parse_info_packet(&self, data: &[u8]) -> Result<ServerInfo, SampError> {
        let mut cursor = Cursor::new(data);
        // (SAMP + IP + Port + Opcode) = 11 bytes
        cursor.set_position(11);

        let has_password = cursor.read_u8()? != 0;
        let players = cursor.read_u16_le()?;
        let max_players = cursor.read_u16_le()?;
        let hostname = cursor.read_samp_string()?;
        let gamemode = cursor.read_samp_string()?;
        let mapname = cursor.read_samp_string()?;

        Ok(ServerInfo {
            has_password,
            players,
            max_players,
            hostname,
            gamemode,
            mapname,
        })
    }
}

pub struct SampClientBuilder {
    timeout: Duration,
    retries: usize,
    bind_port: u16,
}

impl Default for SampClientBuilder {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(2),
            retries: 2,
            bind_port: 0,
        }
    }
}

impl SampClientBuilder {
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn retries(mut self, retries: usize) -> Self {
        self.retries = retries;
        self
    }

    pub fn bind_port(mut self, port: u16) -> Self {
        self.bind_port = port;
        self
    }

    pub fn build(self) -> Result<SampClient, SampError> {
        let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], self.bind_port)))?;
        socket.set_write_timeout(Some(self.timeout))?;

        Ok(SampClient {
            socket,
            timeout: self.timeout,
            retries: self.retries,
        })
    }
}

pub fn query_batch(
    targets: Vec<String>,
    thread_count: usize,
) -> Vec<(String, Result<ServerInfo, SampError>)> {
    let jobs = Arc::new(Mutex::new(targets.into_iter()));
    let (tx, rx) = mpsc::channel();
    let mut handles = vec![];

    for _ in 0..thread_count {
        let jobs_ref = Arc::clone(&jobs);
        let tx_ref = tx.clone();

        handles.push(thread::spawn(move || {
            let client = SampClient::builder()
                .timeout(Duration::from_secs(2))
                .retries(1)
                .build();

            let client = match client {
                Ok(c) => c,
                Err(_) => return,
            };

            loop {
                let target_ip = {
                    let mut iter = jobs_ref.lock().unwrap();
                    match iter.next() {
                        Some(ip) => ip,
                        None => break,
                    }
                };

                let result = client.get_information(&target_ip);
                let _ = tx_ref.send((target_ip, result));
            }
        }));
    }

    drop(tx);

    let mut results = Vec::new();
    for res in rx {
        results.push(res);
    }

    for h in handles {
        let _ = h.join();
    }

    results
}
