# 802.11-analysis-script
IEEE 802.11 の pcap/pcapng ファイルを解析し、各端末の Airtime 占有率・実効スループット・データレートとDurationの相関を分析するスクリプトです。
## 前提条件
- **Python 3.10 以上**
- **Wireshark / tshark** がインストールされていること（パケット解析に使用）
  - macOS: `brew install wireshark`
  - Ubuntu: `sudo apt install tshark`
---
## 環境構築
### Anaconda 仮想環境を使用する場合
```bash
# 仮想環境の作成
conda create -n wlan-analysis python=3.12 -y
# 仮想環境の有効化
conda activate wlan-analysis
# 必要なライブラリのインストール
conda install pandas matplotlib -y
```
### Anaconda を使用しない場合（pip）
```bash
# （任意）venv で仮想環境を作成
python3 -m venv .venv
source .venv/bin/activate    # macOS / Linux
# .venv\Scripts\activate     # Windows
# 必要なライブラリのインストール
pip install pandas matplotlib
```
> **Note:** `argparse`, `json`, `os`, `subprocess`, `sys`, `tempfile`, `datetime` は Python 標準ライブラリのためインストール不要です。
---
## clients.json の設定
スクリプトは `clients.json` を読み込み、MACアドレスをホスト名に変換して表示します。
自身の環境に合わせて編集してください。
```json
{
    "aa:bb:cc:dd:ee:ff": "端末名1",
    "11:22:33:44:55:66": "AP(BSSID)"
}
```
- キー: MACアドレス（小文字、コロン区切り）
- 値: 任意のホスト名
- 未登録のMACアドレスはそのまま表示されます
---
## 使い方
### 基本
```bash
python script.py <pcapファイル>
```
### オプション付き
```bash
python script.py capture.pcapng --output-dir results --mtu-min 1400 --mtu-max 1500
```
### コマンドラインオプション
| オプション | デフォルト | 説明 |
|---|---|---|
| `pcap_file`（必須） | — | 解析対象の `.pcap` または `.pcapng` ファイルパス |
| `--output-dir` | `.`（カレントディレクトリ） | 出力ファイルの保存先ディレクトリ |
| `--mtu-min` | `1400` | 散布図フィルタの最小フレーム長 (Bytes) |
| `--mtu-max` | `1500` | 散布図フィルタの最大フレーム長 (Bytes) |
> `--mtu-min` / `--mtu-max` は散布図用データ（`scatter_data.csv` および `scatter_rate_vs_duration.png`）のみに影響します。フレーム長をMTU付近に絞ることで、ペイロードサイズが揃った条件下でのデータレートと Duration の関係を観察できます。
---
## 出力ファイル
スクリプトは以下の4つのファイルを出力します。
### 1. `raw_packets.csv` — 全パケット生データ
tshark で抽出した全パケットの詳細データです。
| カラム名 | 説明 |
|---|---|
| `timestamp` | パケットの受信時刻 (UTC) |
| `frame_length` | フレーム長 (Bytes) |
| `frame_type` | フレームタイプ（`0`:管理, `1`:制御, `2`:データ） |
| `frame_subtype` | フレームサブタイプ（tshark の `fc.type_subtype` 値） |
| `frame_subtype_int` | フレームサブタイプの整数値（10進） |
| `frame_type_label` | フレームタイプの日本語ラベル（管理/制御/データ/不明） |
| `duration_us` | フレームの送信所要時間 (µs) |
| `data_rate_mbps` | PHY データレート (Mbps) |
| `src_mac` | 送信元MACアドレス（TA優先、SA fallback） |
| `dst_mac` | 宛先MACアドレス（RA優先、DA fallback） |
| `src_host` | 送信元ホスト名（`clients.json` で解決） |
| `dst_host` | 宛先ホスト名（`clients.json` で解決） |
| `airtime_owner_mac` | Airtime帰属先MACアドレス |
| `airtime_owner_host` | Airtime帰属先ホスト名 |
> **Airtime帰属の特殊処理:** ACK/CTS フレームは Transmitter Address (TA) を持たないため、Receiver Address (RA) が示す端末に Airtime を帰属させています。
---
### 2. `airtime_summary.csv` — 端末別 Airtime 集計
端末ごとの Airtime 占有率やスループットの集計結果です。
| カラム名 | 説明 |
|---|---|
| `airtime_owner_mac` | 端末のMACアドレス |
| `host_name` | ホスト名（`clients.json` で解決） |
| `total_duration_us` | 端末に帰属する全フレームの Duration 合計 (µs) |
| `airtime_occupancy_pct` | **絶対 Airtime 占有率 (%)** — 分母はキャプチャ実時間 |
| `airtime_relative_pct` | **相対 Airtime 占有率 (%)** — 分母は全端末の Duration 合計 |
| `total_bytes` | 端末の総送受信バイト数 |
| `packet_count` | 端末に帰属するパケット総数 |
| `throughput_bps` | 実効スループット (bps) |
| `throughput_mbps` | 実効スループット (Mbps) |
| `avg_data_rate_mbps` | 平均 PHY データレート (Mbps) |
| `ctrl_ACK` | ACK フレーム数 |
| `ctrl_CTS` | CTS フレーム数 |
| `ctrl_BA` | Block Ack フレーム数 |
| `ctrl_BAR` | Block Ack Request フレーム数 |
| `ctrl_RTS` | RTS フレーム数 |
| `ctrl_PS-Poll` | PS-Poll フレーム数 |
| `ctrl_CF-End` | CF-End フレーム数 |
| `ctrl_CF-End+ACK` | CF-End + CF-Ack フレーム数 |
> **Note:** `ctrl_*` カラムは該当する制御フレームが存在する端末にのみ値が入ります（存在しない場合は空欄）。
#### 占有率の2つの定義
| 指標 | 分母 | 用途 |
|---|---|---|
| `airtime_occupancy_pct`（絶対占有率） | キャプチャ実時間 | DIFS/SIFS/バックオフ/アイドル時間を含む、物理チャネル全体に対する占有率。各端末がチャネルをどれだけ使っているかの正確な指標 |
| `airtime_relative_pct`（相対占有率） | 全端末の Duration 合計 | 観測された送信時間内での端末間の比率。アイドル時間を除外した参考値 |
---
### 3. `scatter_data.csv` — 散布図用データ
MTU 付近（`--mtu-min` 〜 `--mtu-max`）のフレームのみを抽出したデータです。
| カラム名 | 説明 |
|---|---|
| `data_rate_mbps` | PHY データレート (Mbps) |
| `duration_us` | Duration (µs) |
| `src_mac` | 送信元MACアドレス |
| `src_host` | 送信元ホスト名 |
---
### 4. `scatter_rate_vs_duration.png` — 散布図
データレート (Mbps) を横軸、Duration (µs) を縦軸とした散布図です。端末ごとに色分けされます。
フレーム長を MTU 付近に揃えることで、同一ペイロードサイズにおけるデータレートと送信時間の関係を可視化します。データレートが高いほど Duration が短くなる反比例の関係が確認できます。

## コンソール出力の見方
スクリプト実行時、コンソールに以下のサマリーが表示されます。
```
================================================================================
  端末別 Airtime 占有率サマリー（絶対値: 分母=キャプチャ実時間）
================================================================================
  Oneplus 13R           Airtime:   12.34%  (相対:  45.67%)  Duration:    1234567 µs  Tput:   5.6789 Mbps  (ACK:500, BA:120, BAR:80)
  Galaxy S8             Airtime:    8.90%  (相対:  32.10%)  Duration:     890123 µs  Tput:   3.4567 Mbps  (ACK:300, RTS:50, CTS:50)
--------------------------------------------------------------------------------
  チャネル利用合計       Airtime:   25.00%  アイドル/オーバーヘッド:   75.00%
  （内訳）              観測Duration合計:    2345678 µs  キャプチャ時間:   10000000 µs
================================================================================
```
| 表示項目 | 説明 |
|---|---|
| `Airtime` | 絶対 Airtime 占有率 (%) |
| `相対` | 相対 Airtime 占有率 (%) |
| `Duration` | 端末に帰属する Duration の合計 (µs) |
| `Tput` | 実効スループット (Mbps) |
| `(ACK:N, BA:N, ...)` | 制御フレームのサブタイプ別カウント（0の項目は省略） |
| `チャネル利用合計` | 全端末の絶対占有率の合計 |
| `アイドル/オーバーヘッド` | チャネルが使用されていない時間の割合（DIFS, SIFS, バックオフ, アイドル等を含む） |
---
## pcap ファイルの自動修復
入力ファイルが破損している場合、スクリプトは `capinfos` で整合性をチェックし、必要に応じて `editcap` で破損パケットを除去した修復ファイルを自動生成します。修復用の一時ファイルは処理完了後に自動削除されます。
# 802.11-analysis-script