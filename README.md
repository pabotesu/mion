# MION

**MASQUE-based L3 IP Overlay Network**

MION は、HTTP/3 上の MASQUE CONNECT-IP を用いて Client から Proxy への L3 オーバーレイ接続を成立・維持する通信コアです。

```
<Client> ────CONNECT-IP over HTTP/3────> <Proxy>
```

## 特徴

- **MASQUE CONNECT-IP** — HTTP/3 (QUIC) 上で L3 パケットをトンネリング
- **mTLS 相互認証** — Ed25519 自己署名証明書による公開鍵ベース認証
- **WireGuard ライクな操作** — 設定ファイル形式・CLI・鍵管理がすべて WireGuard に準拠
- **単一 UDP ソケット** — すべての通信を 1 つのソケットで処理し NAT mapping を維持
- **Keepalive / Roaming / Failover** — 接続維持・endpoint 追従・自動切替

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
├── daemon/         シグナルハンドリング
├── failover/       endpoint フェイルオーバー
├── identity/       Ed25519 鍵管理・PeerID 導出・自己署名証明書
├── ipc/            UAPI プロトコル (UNIX ソケット)
├── keepalive/      Persistent keepalive
├── mion/           コアオーケストレーション
├── peer/           Peer 状態管理・KnownPeers レジストリ
├── platform/       プラットフォーム固有パス
├── proxy/          HTTP/3 + CONNECT-IP サーバ
├── roaming/        endpoint ローミング検知
├── routing/        AllowedIPs ルーティングテーブル
└── tunnel/         TUN デバイス (Linux 実装 + stub)
```

## 必要要件

- **Go 1.26.1+**
- **Linux** (TUN デバイスの作成に必要。macOS では stub で動作)
- **root 権限** (TUN 作成に `CAP_NET_ADMIN` が必要)

## ビルド

```bash
go build -o bin/miond       ./cmd/miond
go build -o bin/mion        ./cmd/mion
go build -o bin/mion-quick  ./cmd/mion-quick
```

## 鍵の生成

```bash
# 秘密鍵を生成し、同時に公開鍵も導出
mion genkey | tee privatekey | mion pubkey > publickey

# 確認
cat privatekey   # → base64 エンコードされた Ed25519 秘密鍵 (seed)
cat publickey    # → base64 エンコードされた Ed25519 公開鍵
```

Proxy 側・Client 側それぞれで鍵ペアを生成し、**相手の公開鍵を控えて**おきます。

## 設定ファイル

WireGuard と同じ INI 形式です。

### Proxy 側 (`/etc/mion/mion0.conf`)

```ini
[Interface]
PrivateKey = <Proxy の秘密鍵 (base64)>
Address = 10.0.0.1/24
ListenPort = 51820
Role = proxy

[Peer]
PublicKey = <Client の公開鍵 (base64)>
AllowedIPs = 10.0.0.2/32
PersistentKeepalive = 25
```

### Client 側 (`/etc/mion/mion0.conf`)

```ini
[Interface]
PrivateKey = <Client の秘密鍵 (base64)>
Address = 10.0.0.2/24
Role = client

[Peer]
PublicKey = <Proxy の公開鍵 (base64)>
AllowedIPs = 10.0.0.1/32
Endpoint = <Proxy の IP アドレス>:51820
PersistentKeepalive = 25
```

### 設定項目一覧

| セクション | キー | 説明 |
|---|---|---|
| `[Interface]` | `PrivateKey` | 自ノードの Ed25519 秘密鍵 (base64) |
| | `Address` | TUN に割り当てる IP/prefix |
| | `ListenPort` | UDP リッスンポート (Client は省略可) |
| | `Role` | `client` または `proxy` |
| `[Peer]` | `PublicKey` | 相手の Ed25519 公開鍵 (base64) |
| | `AllowedIPs` | 相手に許可する IP prefix (カンマ区切り可) |
| | `Endpoint` | 相手の `IP:port` (Client→Proxy で必須) |
| | `PersistentKeepalive` | Keepalive 間隔 (秒、0 = 無効) |

## 起動

```bash
# 方法 A: 直接起動
sudo miond -config /etc/mion/mion0.conf -interface mion0

# 方法 B: mion-quick
sudo mion-quick up mion0
```

## 状態確認

```bash
mion show mion0
```

出力例:

```
interface: mion0
  listening port: 51820

peer: <base64 公開鍵>
  endpoint: 203.0.113.1:51820
  allowed ips: 10.0.0.2/32
  persistent keepalive: every 25 seconds
```

## ランタイム設定変更

```bash
# Peer の追加・変更 (UAPI プロトコル経由)
mion set mion0 public_key=<base64> endpoint=198.51.100.1:51820 allowed_ip=10.0.0.3/32
```

## 停止

```bash
sudo mion-quick down mion0
# または miond プロセスに SIGTERM / SIGINT
```

## 認証モデル

MION は **SSH の `authorized_keys` / `known_hosts` と同じモデル**を採用しています。

- CA は不在 (自己署名証明書)
- 信頼の根拠は「設定ファイルに公開鍵が登録されていること」
- mTLS により **双方向**で認証
- `KnownPeers` に未登録の相手からの接続は拒否

```
Client                           Proxy
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
| **Keepalive** | QUIC レベルの `KeepAlivePeriod` (25秒) で NAT state を維持 |
| **Roaming** | 動的endpoint のピアからのアドレス変化を検知し自動更新 |
| **自動再接続** | 接続断を検知すると指数バックオフ (2s〔30s) で自動リトライ |

## テスト

```bash
go test ./...
```

現在 47 テスト (config: 5, auth: 7, identity: 4, routing: 10, peer: 8, ipc: 5, roaming: 4, failover: 3, selfcert: 1) がすべて PASS しています。

## 開発フェーズ

- [x] **Phase 1**: 最小接続成立 — Proxy/Client, HTTP/3+MASQUE+CONNECT-IP, mTLS, KnownPeers, AllowedIPs, TUN, UAPI
- [x] **Phase 2**: 接続維持 — Keepalive, Roaming, 自動再接続
- [x] **Phase 3**: 接続安定化 — Linux 実機での TUN/ping 検証、Proxy 再起動時の自動復帰確認

## 依存ライブラリ

| ライブラリ | 用途 |
|---|---|
| `quic-go/quic-go` | QUIC トランスポート |
| `quic-go/connect-ip-go` | MASQUE CONNECT-IP プロトコル |
| `songgao/water` | Linux TUN デバイス作成 |
| `vishvananda/netlink` | Linux ネットワーク設定 |
| `yosida95/uritemplate` | URI テンプレート (CONNECT-IP) |

## ライセンス

TBD
