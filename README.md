# mion

**MASQUE-based L3 IP Overlay Network**

mion は、HTTP/3 上の MASQUE CONNECT-IP を用いた L3 オーバーレイネットワークの PoC 実装です。  
WireGuard が通れないような HTTPS のみ許可されたファイアウォール環境でも、UDP 443 さえ通れば動作します。

```
client ──CONNECT-IP over HTTP/3 (UDP:443)──> proxy <──── client
```

## 特徴

- **MASQUE CONNECT-IP** — HTTP/3 (QUIC) 上で L3 パケットをトンネリング
- **mTLS 相互認証** — Ed25519 自己署名証明書による公開鍵ベース認証、CA 不要
- **WireGuard ライクな操作** — 設定ファイル形式・CLI・鍵管理が WireGuard に準拠
- **単一 UDP ソケット** — すべての通信を 1 つのソケットで処理し NAT mapping を維持
- **Keepalive / Roaming / Failover** — 接続維持・endpoint 追従・自動切替
- **hub 中継対応** — proxy を中心とした複数 client 間のルーティングをサポート

## プラットフォーム対応

| Platform | Status | 備考 |
|----------|--------|------|
| Linux    | ✅ support | TUN + netlink |
| macOS    | ✅ support | utun + ifconfig |
| Windows  | 🚧 Not yet implemented | WinTUN 実装待ち |

## アーキテクチャ

```
┌──────────────────────────────────────────────────┐
│                     miond                        │
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │ Identity │  │   Auth   │  │   Keepalive   │  │
│  │ Ed25519  │  │  mTLS    │  │   Roaming     │  │
│  │ PeerID   │  │          │  │   Failover    │  │
│  └──────────┘  └──────────┘  └───────────────┘  │
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │  Client  │  │  Proxy   │  │  AllowedIPs   │  │
│  │  (Dial)  │  │ (Listen) │  │  Routing      │  │
│  └──────────┘  └──────────┘  └───────────────┘  │
│                                                  │
│  ┌──────────────────┐  ┌─────────────────────┐  │
│  │   TUN Device     │  │  Single UDP Socket  │  │
│  └──────────────────┘  └─────────────────────┘  │
└──────────────────────────────────────────────────┘
```

## ディレクトリ構成

```
cmd/
├── mion/           CLI ツール (show, set, genkey, pubkey)
├── mion-quick/     起動・停止ヘルパー (up, down)
└── miond/          デーモン本体
config/             WireGuard 形式の設定ファイルパーサ
internal/
├── auth/           mTLS 設定 (Client/Proxy 用)
├── client/         CONNECT-IP クライアント (DialPeer, 転送)
├── daemon/         シグナルハンドリング (Linux/macOS/Windows)
├── failover/       endpoint フェイルオーバー
├── identity/       Ed25519 鍵管理・PeerID 導出・自己署名証明書
├── ipc/            UAPI プロトコル (UNIX ドメインソケット)
├── keepalive/      Persistent keepalive
├── mion/           コアオーケストレーション
├── peer/           Peer 状態管理・KnownPeers レジストリ
├── platform/       プラットフォーム固有パス (Linux/macOS/Windows)
├── proxy/          HTTP/3 + CONNECT-IP サーバ
├── roaming/        endpoint ローミング検知
├── routing/        AllowedIPs ルーティングテーブル
└── tunnel/         TUN デバイス (Linux/macOS 実装 + stub)
```

## 必要要件

- **Go 1.26.1+**
- **root 権限** (TUN デバイス作成に必要)
- Linux: `CAP_NET_ADMIN`
- macOS: root または適切な entitlement

## ビルド

```bash
go build -o bin/miond       ./cmd/miond
go build -o bin/mion        ./cmd/mion
go build -o bin/mion-quick  ./cmd/mion-quick
```

クロスコンパイル例:

```bash
# Linux 向けバイナリを macOS でビルド
GOOS=linux GOARCH=amd64 go build -o bin/miond-linux ./cmd/miond
```

## 鍵の生成

```bash
# 各ノードで実行
mion genkey | tee privatekey | mion pubkey > publickey

cat privatekey   # Ed25519 秘密鍵 (base64 seed)
cat publickey    # Ed25519 公開鍵 (base64)
```

proxy・各 client それぞれで鍵ペアを生成し、**相手の公開鍵を控えて**おきます。

## 設定ファイル

WireGuard と同じ INI 形式です。デフォルトのパスは `/etc/mion/<interface>.conf` ですが任意のパスを指定できます。

### proxy (`/etc/mion/mi0n.conf`)

```ini
[Interface]
PrivateKey = <proxy の秘密鍵>
Address = 100.100.0.3/24
ListenPort = 4443
Role = proxy

[Peer]
PublicKey = <client01 の公開鍵>
AllowedIPs = 100.100.0.1/32
PersistentKeepalive = 25

[Peer]
PublicKey = <client02 の公開鍵>
AllowedIPs = 100.100.0.2/32
PersistentKeepalive = 25
```

### client01 (`/etc/mion/mi0n.conf`)

```ini
[Interface]
PrivateKey = <client01 の秘密鍵>
Address = 100.100.0.1/24
Role = client

[Peer]
PublicKey = <proxy の公開鍵>
Endpoint = <proxy の IP>:4443
AllowedIPs = 100.100.0.3/32, 100.100.0.2/32
PersistentKeepalive = 25
```

### 設定項目一覧

| セクション | キー | 説明 |
|---|---|---|
| `[Interface]` | `PrivateKey` | 自ノードの Ed25519 秘密鍵 (base64) |
| | `Address` | TUN に割り当てる IP/prefix |
| | `ListenPort` | UDP リッスンポート (client は省略可) |
| | `Role` | `client` または `proxy` |
| `[Peer]` | `PublicKey` | 相手の Ed25519 公開鍵 (base64) |
| | `AllowedIPs` | 相手に許可する IP prefix (カンマ区切り可) |
| | `Endpoint` | 相手の `IP:port` (client→proxy で必須) |
| | `PersistentKeepalive` | Keepalive 間隔 (秒、0 = 無効) |

## 起動

```bash
# 方法 A: miond を直接起動
sudo miond -config /etc/mion/mi0n.conf -interface mi0n

# 方法 B: mion-quick (フルパス指定も可)
sudo mion-quick up mi0n
sudo mion-quick up /path/to/mi0n.conf
```

## 状態確認

```bash
mion show mi0n
```

出力例:

```
interface: mi0n
  listening port: 51820

peer:
  public key: XdtOcXazRY7wd3SemdDFaIOJwJn7ntP74pOl4yXOD1s=
  peer id: KhWP2nvDdIVE3fvHgOqLFsaVi8xsLoSBpE1E214rVkA=
  endpoint: 203.0.113.1:4443
  allowed ips: 100.100.0.3/32, 100.100.0.2/32
  persistent keepalive: every 25 seconds
  active: 1
```

## 停止

```bash
sudo mion-quick down mi0n
# または miond プロセスに SIGTERM / SIGINT
```

## hub 中継構成での注意事項

proxy を中心とした hub 構成（client ↔ proxy ↔ client）では、OS の ICMP Redirect が干渉する場合があります。  
proxy ノードで以下を設定してください:

```bash
# 一時的に適用
sysctl -w net.ipv4.conf.all.send_redirects=0

# 永続化
echo "net.ipv4.conf.all.send_redirects=0" > /etc/sysctl.d/99-mion.conf
sysctl --system
```

> **Note**: これは mion 固有の問題ではなく、WireGuard を含む TUN ベースの hub 中継構成で共通して発生する Linux カーネルの挙動です。

また、各ノードで peer 宛ての明示ルートを追加してください:

```bash
# proxy で (各 client の /32 ルートを投入)
ip route add 100.100.0.1/32 dev mi0n
ip route add 100.100.0.2/32 dev mi0n

# client01 で
ip route add 100.100.0.2/32 dev mi0n

# client02 で
ip route add 100.100.0.1/32 dev mi0n
```

## 認証モデル

mion は **SSH の `authorized_keys` / `known_hosts` と同じモデル**を採用しています。

- CA は不要（自己署名証明書）
- 信頼の根拠は「設定ファイルに公開鍵が登録されていること」
- mTLS により **双方向**で認証
- `KnownPeers` に未登録の相手からの接続は拒否

```
client                           proxy
  │  自己署名証明書 (Ed25519) →    │
  │  ← 自己署名証明書 (Ed25519)   │
  │                               │
  │  VerifyPeerCertificate:       │
  │  pubkey → SHA-256 → peer_id  │
  │  peer_id ∈ KnownPeers ?      │
  │  → Yes: 許可 / No: 拒否       │
```

## 接続維持機能

| 機能 | 説明 |
|---|---|
| **Keepalive** | QUIC レベルの `KeepAlivePeriod`（25秒）で NAT state を維持 |
| **Roaming** | 動的 endpoint のピアからのアドレス変化を検知し自動更新 |
| **自動再接続** | 接続断を検知すると指数バックオフ（2s〜30s）で自動リトライ |

## テスト

```bash
go test ./...
```

## 開発フェーズ

- [x] **Phase 1**: 最小接続成立 — Proxy/Client, HTTP/3+MASQUE+CONNECT-IP, mTLS, KnownPeers, AllowedIPs, TUN, UAPI
- [x] **Phase 2**: 接続維持 — Keepalive, Roaming, 自動再接続
- [x] **Phase 3**: 接続安定化 — Linux 実機での TUN/ping 検証、Proxy 再起動時の自動復帰確認
- [x] **Phase 4**: macOS 対応 — utun デバイスによる macOS でのフル動作確認

## 今後の課題

- `mion-quick up` での OS ルート自動投入（AllowedIPs → `ip route add`）
- proxy ロール時の `send_redirects=0` 自動適用
- Windows 対応（WinTUN + Named pipe）
- スループット計測

## 依存ライブラリ

| ライブラリ | 用途 |
|---|---|
| `quic-go/quic-go` | QUIC トランスポート |
| `quic-go/connect-ip-go` | MASQUE CONNECT-IP プロトコル |
| `songgao/water` | TUN デバイス作成 (Linux/macOS) |
| `vishvananda/netlink` | Linux ネットワーク設定 |
| `yosida95/uritemplate` | URI テンプレート (CONNECT-IP) |

## ライセンス

TBD
