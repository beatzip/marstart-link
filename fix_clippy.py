#!/usr/bin/env python3
import re

# Fix 1: wireguard.rs - удалить unused метод current_session
with open('src-tauri/src/wireguard.rs', 'r', encoding='utf-8') as f:
    content = f.read()

content = re.sub(
    r'\s*pub fn current_session\(&self\) -> u64 \{\s*self\.session_id\.load\(Ordering::SeqCst\)\s*\}',
    '',
    content
)

# Fix 2: wireguard.rs - заменить impl Default на derive
content = re.sub(
    r'(#\[derive\(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize\)\])\s*pub enum TunnelPhase \{(\s*)Idle,',
    r'\1, Default]\npub enum TunnelPhase {\2#[default]\2Idle,',
    content
)
content = re.sub(
    r'\s*impl Default for TunnelPhase \{\s*fn default\(\) -> Self \{\s*Self::Idle\s*\}\s*\}',
    '',
    content
)

# Fix 3: session_guard.clone()
content = content.replace(
    'session_guard,\n            session_id,',
    'session_guard.clone(),\n            session_id,'
)

with open('src-tauri/src/wireguard.rs', 'w', encoding='utf-8') as f:
    f.write(content)
print("✅ wireguard.rs fixed")

# Fix 4: wireguard_config.rs - удалить unused type
with open('src-tauri/src/wireguard_config.rs', 'r', encoding='utf-8') as f:
    content = f.read()

content = re.sub(
    r'pub type WireguardAllowedIpFlag = u32;\s*pub const _WIREGUARD_ALLOWED_IP_REMOVE: WireguardAllowedIpFlag = 1 << 0;',
    '',
    content
)

# Fix 5: wireguard_config.rs - убрать unsafe вокруг match addr
content = re.sub(
    r'(pub fn socket_addr_to_sockaddr_inet\(addr: &SocketAddr\) -> SOCKADDR_INET \{\s*let mut sockaddr: SOCKADDR_INET = unsafe \{ std::mem::zeroed\(\) \};\s*)unsafe \{(\s*)match addr \{',
    r'\1\2match addr {',
    content
)
# Удалить закрывающую } от unsafe (перед sockaddr в конце функции)
content = re.sub(
    r'(\s*\}\s*)\}\s*sockaddr\s*\}',
    r'\1sockaddr\n}',
    content
)

with open('src-tauri/src/wireguard_config.rs', 'w', encoding='utf-8') as f:
    f.write(content)
print("✅ wireguard_config.rs fixed")

# Fix 6: wireguard_serializer.rs - убрать unsafe вокруг addr.v4 и addr.v6
with open('src-tauri/src/wireguard_serializer.rs', 'r', encoding='utf-8') as f:
    content = f.read()

# Убрать unsafe { addr.v4 = ...; }
content = re.sub(
    r'(\s*// ✅ from_ne_bytes \(NOT from_be_bytes\)\s*)unsafe \{(\s*addr\.v4 = IN_ADDR \{[^}]+\};\s*)\}',
    r'\1\2',
    content
)

# Убрать unsafe { addr.v6 = ...; }
content = re.sub(
    r'(\s*let mut addr: WireguardIpAddress = unsafe \{ std::mem::zeroed\(\) \};\s*)unsafe \{(\s*addr\.v6 = IN6_ADDR \{[^}]+\};\s*)\}',
    r'\1\2',
    content
)

# Fix 7: write_struct - Vec<u8> -> [u8]
content = content.replace(
    'fn write_struct<T: Copy>(val: &T, buf: &mut Vec<u8>, off: &mut usize)',
    'fn write_struct<T: Copy>(val: &T, buf: &mut [u8], off: &mut usize)'
)

with open('src-tauri/src/wireguard_serializer.rs', 'w', encoding='utf-8') as f:
    f.write(content)
print("✅ wireguard_serializer.rs fixed")

print("\n🎉 All fixes applied!")
