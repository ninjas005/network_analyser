//! DNS monitoring over captured packets: queries matched with their answers,
//! response times, failures, and per-name / server / client totals.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::capture::Packet;
use crate::gateway::Level;

const MAX_TXNS: usize = 100_000;
/// Seconds after which a query counts as unanswered.
pub const TIMEOUT: f64 = 5.0;
const SLOW: f64 = 0.2;

#[derive(Clone, Debug)]
pub struct Txn {
    pub proto: String,
    pub tcp: bool,
    pub client: IpAddr,
    pub server: IpAddr,
    pub id: u16,
    pub name: String,
    pub qtype: u16,
    pub asked: Option<f64>,
    pub answered: Option<f64>,
    pub rcode: u16,
    pub answers: Vec<String>,
    pub min_ttl: Option<u32>,
    pub retries: u32,
    pub truncated: bool,
    /// A second, different answer arrived for the same query.
    pub conflict: bool,
    /// Repeated and still unanswered when the capture ended.
    pub failed: bool,
    /// Multicast: no single answer is expected.
    pub multicast: bool,
    /// Packet numbers of query and response.
    pub nos: (Option<usize>, Option<usize>),
}

impl Txn {
    pub fn time(&self) -> Option<f64> {
        Some((self.answered? - self.asked?).max(0.0))
    }
    pub fn unanswered(&self, now: f64) -> bool {
        !self.multicast
            && self.answered.is_none()
            && (self.failed || self.asked.is_some_and(|t| now - t > TIMEOUT))
    }
    pub fn status(&self, now: f64) -> (Level, String) {
        match self.answered {
            Some(_) if self.conflict => (Level::Bad, "conflicting answers".into()),
            Some(_) => match self.rcode {
                0 if self.answers.is_empty() && !self.multicast => (Level::Info, "no data".into()),
                0 => (Level::Good, "NOERROR".into()),
                3 => (Level::Warn, "NXDOMAIN".into()),
                r => (Level::Bad, crate::dns::rcode_name(r).into()),
            },
            None if self.unanswered(now) => (Level::Bad, "no answer".into()),
            None if self.multicast => (Level::Info, "multicast".into()),
            None => (Level::Info, "waiting".into()),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Agg {
    pub queries: u64,
    pub answers: u64,
    pub nxdomain: u64,
    pub errors: u64,
    pub time_sum: f64,
    pub time_max: f64,
    pub timed: u64,
    pub names: HashSet<String>,
}

impl Agg {
    pub fn avg(&self) -> Option<f64> {
        (self.timed > 0).then(|| self.time_sum / self.timed as f64)
    }
    fn answer(&mut self, t: Option<f64>, rcode: u16) {
        self.answers += 1;
        match rcode {
            0 => {}
            3 => self.nxdomain += 1,
            _ => self.errors += 1,
        }
        if let Some(t) = t {
            self.time_sum += t;
            self.time_max = self.time_max.max(t);
            self.timed += 1;
        }
    }
}

type Key = (IpAddr, u16, IpAddr, u16, String, u16);

#[derive(Default)]
pub struct Monitor {
    pub txns: Vec<Txn>,
    pub ignored: u64,
    pub names: HashMap<String, Agg>,
    pub servers: HashMap<IpAddr, Agg>,
    pub clients: HashMap<IpAddr, Agg>,
    pub types: HashMap<u16, u64>,
    pub queries: u64,
    pub responses: u64,
    pub retries: u64,
    pub slow: u64,
    pub conflicts: u64,
    pub unsolicited: u64,
    pub tunnel: HashSet<String>,
    pub now: f64,
    open: HashMap<Key, usize>,
}

impl Monitor {
    pub fn add(&mut self, p: &Packet) {
        self.now = self.now.max(p.ts);
        let Some(m) = &p.d.dns else { return };
        let (Some(src), Some(dst)) = (p.d.src_ip, p.d.dst_ip) else {
            return;
        };
        let (sp, dp) = (p.d.src_port.unwrap_or(0), p.d.dst_port.unwrap_or(0));
        let multicast = p.d.proto != "DNS";
        let tcp = p.d.transport == Some("TCP");
        if multicast && m.response {
            // Announcements: log the first record.
            self.responses += 1;
            let Some(r) = m.answers().next() else { return };
            let (name, qtype) = (r.name.clone(), r.rtype);
            let answers = m.answers().take(8).map(|r| r.data.clone()).collect();
            self.push(Txn {
                proto: p.d.proto.clone(),
                tcp,
                client: src,
                server: dst,
                id: m.id,
                name,
                qtype,
                asked: None,
                answered: Some(p.ts),
                rcode: m.rcode,
                answers,
                min_ttl: m.answers().map(|r| r.ttl).min(),
                retries: 0,
                truncated: m.truncated,
                conflict: false,
                failed: false,
                multicast,
                nos: (None, Some(p.no)),
            });
            return;
        }
        for (name, qtype) in &m.questions {
            let lname = name.to_lowercase();
            if m.response {
                let key = (dst, dp, src, m.id, lname.clone(), *qtype);
                self.response(p, m, key, name, tcp);
            } else {
                let key = (src, sp, dst, m.id, lname.clone(), *qtype);
                self.query(p, m, key, name, tcp, multicast);
            }
        }
    }

    fn push(&mut self, t: Txn) -> Option<usize> {
        if self.txns.len() >= MAX_TXNS {
            self.ignored += 1;
            return None;
        }
        self.txns.push(t);
        Some(self.txns.len() - 1)
    }

    fn query(
        &mut self,
        p: &Packet,
        m: &crate::appproto::DnsMsg,
        key: Key,
        name: &str,
        tcp: bool,
        multicast: bool,
    ) {
        self.queries += 1;
        *self.types.entry(key.5).or_default() += 1;
        if let Some(&i) = self.open.get(&key)
            && self.txns[i].answered.is_none()
            && !multicast
        {
            self.txns[i].retries += 1;
            self.retries += 1;
            return;
        }
        if !multicast {
            self.names.entry(key.4.clone()).or_default().queries += 1;
            let c = self.clients.entry(key.0).or_default();
            c.queries += 1;
            if c.names.len() < 10_000 {
                c.names.insert(key.4.clone());
            }
            let s = self.servers.entry(key.2).or_default();
            s.queries += 1;
            if s.names.len() < 10_000 {
                s.names.insert(key.4.clone());
            }
            if crate::anomaly::looks_like_tunnel(&key.4) && self.tunnel.len() < 1000 {
                self.tunnel.insert(key.4.clone());
            }
        }
        let i = self.push(Txn {
            proto: p.d.proto.clone(),
            tcp,
            client: key.0,
            server: key.2,
            id: m.id,
            name: name.to_string(),
            qtype: key.5,
            asked: Some(p.ts),
            answered: None,
            rcode: 0,
            answers: Vec::new(),
            min_ttl: None,
            retries: 0,
            truncated: false,
            conflict: false,
            failed: false,
            multicast,
            nos: (Some(p.no), None),
        });
        if let Some(i) = i {
            self.open.insert(key, i);
        }
    }

    fn response(
        &mut self,
        p: &Packet,
        m: &crate::appproto::DnsMsg,
        key: Key,
        name: &str,
        tcp: bool,
    ) {
        self.responses += 1;
        let mut answers: Vec<String> = m
            .answers()
            .map(|r| format!("{} {}", crate::dns::type_name(r.rtype), r.data))
            .collect();
        answers.truncate(32);
        let ttl = m.answers().map(|r| r.ttl).min();
        match self.open.get(&key).copied() {
            Some(i) if self.txns[i].answered.is_some() => {
                let t = &mut self.txns[i];
                let set = |v: &[String]| v.iter().cloned().collect::<HashSet<_>>();
                // Duplicates are normal; a different answer is not.
                if !t.conflict && (t.rcode != m.rcode || set(&t.answers) != set(&answers)) {
                    t.conflict = true;
                    self.conflicts += 1;
                }
            }
            Some(i) => {
                let t = &mut self.txns[i];
                t.answered = Some(p.ts);
                t.rcode = m.rcode;
                t.answers = answers;
                t.min_ttl = ttl;
                t.truncated = m.truncated;
                t.nos.1 = Some(p.no);
                let time = t.time();
                if time.is_some_and(|x| x > SLOW) {
                    self.slow += 1;
                }
                self.totals(&key, time, m.rcode);
            }
            None => {
                // The query was not captured.
                self.unsolicited += 1;
                self.totals(&key, None, m.rcode);
                let i = self.push(Txn {
                    proto: p.d.proto.clone(),
                    tcp,
                    client: key.0,
                    server: key.2,
                    id: m.id,
                    name: name.to_string(),
                    qtype: key.5,
                    asked: None,
                    answered: Some(p.ts),
                    rcode: m.rcode,
                    answers,
                    min_ttl: ttl,
                    retries: 0,
                    truncated: m.truncated,
                    conflict: false,
                    failed: false,
                    multicast: false,
                    nos: (None, Some(p.no)),
                });
                if let Some(i) = i {
                    self.open.insert(key, i);
                }
            }
        }
    }

    fn totals(&mut self, key: &Key, time: Option<f64>, rcode: u16) {
        self.names
            .entry(key.4.clone())
            .or_default()
            .answer(time, rcode);
        self.servers.entry(key.2).or_default().answer(time, rcode);
        self.clients.entry(key.0).or_default().answer(time, rcode);
    }

    /// End of the capture: a query that was repeated without an answer failed;
    /// one asked just before the end may still have been answered.
    pub fn finish(&mut self) {
        for t in &mut self.txns {
            t.failed = t.answered.is_none() && t.retries > 0;
        }
    }

    pub fn unanswered(&self) -> usize {
        self.txns.iter().filter(|t| t.unanswered(self.now)).count()
    }

    /// Average response time over all servers.
    pub fn avg(&self) -> Option<f64> {
        let (s, n) = self
            .servers
            .values()
            .fold((0.0, 0), |(s, n), a| (s + a.time_sum, n + a.timed));
        (n > 0).then(|| s / n as f64)
    }

    pub fn findings(&self) -> Vec<(Level, String)> {
        let mut out = Vec::new();
        let un = self.unanswered();
        if un > 0 {
            out.push((Level::Bad, format!("Queries without an answer: {un}")));
        }
        if self.conflicts > 0 {
            out.push((
                Level::Bad,
                format!(
                    "Queries that received two different answers: {} (possible spoofing or an intercepting resolver)",
                    self.conflicts
                ),
            ));
        }
        let err: u64 = self.servers.values().map(|a| a.errors).sum();
        if err > 0 {
            out.push((
                Level::Warn,
                format!("Failed answers (SERVFAIL, REFUSED…): {err}"),
            ));
        }
        let nx: u64 = self.servers.values().map(|a| a.nxdomain).sum();
        let ans: u64 = self.servers.values().map(|a| a.answers).sum();
        if nx > 10 && nx * 4 > ans {
            out.push((
                Level::Warn,
                format!(
                    "{nx} of {ans} answers are NXDOMAIN: wrong search domain, misconfiguration or generated names"
                ),
            ));
        }
        if self.slow > 0 {
            out.push((
                Level::Info,
                format!(
                    "Slow answers: {} took longer than {:.0} ms",
                    self.slow,
                    SLOW * 1000.0
                ),
            ));
        }
        if self.retries > 0 {
            out.push((Level::Info, format!("Repeated queries: {}", self.retries)));
        }
        if !self.tunnel.is_empty() {
            out.push((
                Level::Warn,
                format!(
                    "Names that look like data carried in DNS (long random labels): {}",
                    self.tunnel.len()
                ),
            ));
        }
        if self.unsolicited > 0 {
            out.push((
                Level::Info,
                format!("Answers whose query was not captured: {}", self.unsolicited),
            ));
        }
        if out.is_empty() && self.queries > 0 {
            out.push((Level::Good, "No problems seen".into()));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(id: u16, resp: bool, rcode: u8, answer: Option<[u8; 4]>) -> Vec<u8> {
        let mut m = id.to_be_bytes().to_vec();
        m.extend([if resp { 0x81 } else { 1 }, rcode, 0, 1]);
        m.extend([0, answer.is_some() as u8, 0, 0, 0, 0]);
        m.extend(b"\x04Host\x07example\0\0\x01\0\x01");
        if let Some(a) = answer {
            m.extend([0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
            m.extend(a);
        }
        m
    }

    fn pkt(no: usize, ts: f64, resp: bool, body: &[u8]) -> Packet {
        let mut u: Vec<u8> = if resp {
            vec![0, 53, 0xd4, 0x31]
        } else {
            vec![0xd4, 0x31, 0, 53]
        };
        u.extend(((8 + body.len()) as u16).to_be_bytes());
        u.extend([0, 0]);
        u.extend(body);
        let (a, b) = ([10, 0, 0, 5], [10, 0, 0, 1]);
        let mut f = vec![0x45, 0];
        f.extend(((20 + u.len()) as u16).to_be_bytes());
        f.extend([0, 1, 0, 0, 64, 17, 0, 0]);
        f.extend(if resp { b } else { a });
        f.extend(if resp { a } else { b });
        f.extend(u);
        Packet {
            no,
            ts,
            linktype: 101,
            d: crate::dissect::dissect(101, &f),
            data: f,
            ..Default::default()
        }
    }

    #[test]
    fn matches_retries_conflicts_and_timeouts() {
        let mut m = Monitor::default();
        m.add(&pkt(1, 1.0, false, &msg(7, false, 0, None)));
        m.add(&pkt(2, 2.0, false, &msg(7, false, 0, None)));
        m.add(&pkt(3, 2.05, true, &msg(7, true, 0, Some([1, 2, 3, 4]))));
        assert_eq!(m.txns.len(), 1);
        let t = &m.txns[0];
        assert_eq!((t.retries, t.nos), (1, (Some(1), Some(3))));
        assert!((t.time().unwrap() - 1.05).abs() < 1e-9);
        assert_eq!(t.answers, ["A 1.2.3.4"]);
        // Identical duplicate: fine. Different: conflict.
        m.add(&pkt(4, 2.06, true, &msg(7, true, 0, Some([1, 2, 3, 4]))));
        assert_eq!(m.conflicts, 0);
        m.add(&pkt(5, 2.07, true, &msg(7, true, 0, Some([6, 6, 6, 6]))));
        assert_eq!(m.conflicts, 1);
        // Names are matched without regard to case.
        assert_eq!(m.names["host.example"].queries, 1);
        m.add(&pkt(6, 3.0, false, &msg(8, false, 0, None)));
        assert_eq!(m.unanswered(), 0);
        m.add(&pkt(7, 9.0, false, &msg(9, false, 0, None)));
        m.add(&pkt(8, 9.1, true, &msg(9, true, 3, None)));
        assert_eq!(m.unanswered(), 1);
        assert_eq!(
            m.servers[&"10.0.0.1".parse::<IpAddr>().unwrap()].nxdomain,
            1
        );
        assert_eq!(m.txns[2].status(m.now).1, "NXDOMAIN");
    }
}
