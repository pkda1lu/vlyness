//! Keyring сервера: набор клиентов, каждый со своим PSK, с выпуском и отзывом.
//!
//! Заменяет модель «один общий PSK на всех»: теперь каждый клиент — отдельная запись
//! (id, метка, PSK, дата, флаг отзыва). Сервер принимает соединение, если токен проходит
//! по **любому** активному PSK (перебор в `authorize_any`), поэтому отзыв одного клиента
//! не трогает остальных. Панель управляет keyring на живую: [`Keyring::active`] — тот
//! самый [`PskList`], который читает серверный цикл, поэтому выпуск/отзыв применяются
//! без рестарта.
//!
//! Персист — JSON-файл (обычно `/var/lib/vlyness/keyring.json`, писчий каталог сервиса).
//! Если файла ещё нет — заводится один клиент `default` с PSK из `server.toml`, чтобы
//! ранее розданные профили продолжали работать.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use serde::{Deserialize, Serialize};

use vlyness_carrier::PskList;

use crate::{b64_encode, decode_psk};

/// Запись клиента в keyring.
#[derive(Clone, Serialize, Deserialize)]
pub struct ClientEntry {
    pub id: String,
    pub label: String,
    pub psk_b64: String,
    pub created: u64,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Default, Serialize, Deserialize)]
struct KeyringFile {
    clients: Vec<ClientEntry>,
}

/// Keyring: метаданные клиентов + разделяемый живой список активных PSK.
pub struct Keyring {
    clients: Vec<ClientEntry>,
    path: Option<PathBuf>,
    active: PskList,
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Keyring {
    /// Загрузить keyring из файла или завести новый с клиентом `default` = `server.toml`-PSK.
    /// `path = None` — режим без персиста (изменения живут только в памяти).
    pub fn load_or_seed(path: Option<PathBuf>, default_psk_b64: &str) -> Arc<Mutex<Keyring>> {
        let clients = match path.as_ref().filter(|p| p.exists()) {
            Some(p) => match std::fs::read_to_string(p) {
                Ok(s) => serde_json::from_str::<KeyringFile>(&s).map(|f| f.clients).unwrap_or_default(),
                Err(_) => Vec::new(),
            },
            None => Vec::new(),
        };
        let seeded = clients.is_empty();
        let clients = if seeded {
            vec![ClientEntry {
                id: "default".to_string(),
                label: "config (общий PSK)".to_string(),
                psk_b64: default_psk_b64.to_string(),
                created: now(),
                revoked: false,
            }]
        } else {
            clients
        };

        let kr = Keyring { clients, path, active: Arc::new(Mutex::new(Vec::new())) };
        kr.resync();
        if seeded {
            kr.persist();
        }
        Arc::new(Mutex::new(kr))
    }

    /// Разделяемый список активных PSK — передаётся в `ServerParams`/`QuicServerParams`.
    pub fn psk_list(&self) -> PskList {
        self.active.clone()
    }

    /// Снимок клиентов (для панели).
    pub fn list(&self) -> Vec<ClientEntry> {
        self.clients.clone()
    }

    /// Выпустить нового клиента со свежим PSK. Возвращает запись (в ней PSK для профиля).
    pub fn issue(&mut self, label: &str) -> ClientEntry {
        let mut psk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut psk);
        let label = if label.trim().is_empty() { "client".to_string() } else { label.trim().to_string() };
        let entry = ClientEntry {
            id: rand_hex(6),
            label,
            psk_b64: b64_encode(&psk),
            created: now(),
            revoked: false,
        };
        self.clients.push(entry.clone());
        self.resync();
        self.persist();
        entry
    }

    /// Отозвать клиента по id. `false` — не найден.
    pub fn revoke(&mut self, id: &str) -> bool {
        let Some(c) = self.clients.iter_mut().find(|c| c.id == id) else {
            return false;
        };
        if c.revoked {
            return true;
        }
        c.revoked = true;
        self.resync();
        self.persist();
        true
    }

    /// Пересобрать живой список активных PSK из неотозванных записей.
    fn resync(&self) {
        let psks: Vec<[u8; 32]> = self
            .clients
            .iter()
            .filter(|c| !c.revoked)
            .filter_map(|c| decode_psk(&c.psk_b64).ok())
            .collect();
        *self.active.lock().expect("PskList mutex") = psks;
    }

    fn persist(&self) {
        let Some(path) = &self.path else {
            return;
        };
        let file = KeyringFile { clients: self.clients.clone() };
        match serde_json::to_string_pretty(&file) {
            Ok(json) => {
                if let Some(dir) = path.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                if let Err(e) = std::fs::write(path, json) {
                    eprintln!("[keyring] не удалось записать {}: {e}", path.display());
                }
            }
            Err(e) => eprintln!("[keyring] сериализация не удалась: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_psk() -> String {
        b64_encode(&[0x11u8; 32])
    }

    #[test]
    fn seeds_default_client() {
        let kr = Keyring::load_or_seed(None, &seed_psk());
        let kr = kr.lock().unwrap();
        assert_eq!(kr.list().len(), 1);
        assert_eq!(kr.list()[0].id, "default");
        assert_eq!(kr.psk_list().lock().unwrap().len(), 1, "default активен");
    }

    #[test]
    fn issue_adds_active_psk() {
        let kr = Keyring::load_or_seed(None, &seed_psk());
        let mut kr = kr.lock().unwrap();
        let e = kr.issue("телефон");
        assert_ne!(e.psk_b64, seed_psk(), "у нового клиента свой PSK");
        assert_eq!(kr.list().len(), 2);
        assert_eq!(kr.psk_list().lock().unwrap().len(), 2, "оба активны");
    }

    #[test]
    fn revoke_removes_from_active() {
        let kr = Keyring::load_or_seed(None, &seed_psk());
        let mut kr = kr.lock().unwrap();
        let e = kr.issue("ноут");
        assert_eq!(kr.psk_list().lock().unwrap().len(), 2);
        assert!(kr.revoke(&e.id));
        assert_eq!(kr.psk_list().lock().unwrap().len(), 1, "отозванный PSK убран из активных");
        assert!(kr.list().iter().find(|c| c.id == e.id).unwrap().revoked);
        assert!(!kr.revoke("нет-такого"));
    }

    #[test]
    fn persist_roundtrip() {
        let dir = std::env::temp_dir().join(format!("vlyness-kr-{}", rand_hex(4)));
        let path = dir.join("keyring.json");
        let kr = Keyring::load_or_seed(Some(path.clone()), &seed_psk());
        let id = { kr.lock().unwrap().issue("x").id };
        // Перечитать с диска.
        let kr2 = Keyring::load_or_seed(Some(path.clone()), &seed_psk());
        let kr2 = kr2.lock().unwrap();
        assert_eq!(kr2.list().len(), 2, "клиенты восстановлены с диска");
        assert!(kr2.list().iter().any(|c| c.id == id));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
