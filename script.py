#!/usr/bin/env python3
"""
IEEE 802.11 pcap パケット解析スクリプト
========================================
pcap/pcapng ファイルを読み込み、各端末の Airtime 占有率・
データレートとの相関を分析します。

使い方:
    python script.py <pcapファイル> [--output-dir DIR] [--mtu-min N] [--mtu-max N]
"""

import argparse
import os
import subprocess
import sys
import tempfile
from datetime import datetime

import json

import pandas as pd
import matplotlib
matplotlib.use("Agg")  
import matplotlib.pyplot as plt

# ============================================================
# MACアドレス → ホスト名 マッピング (clients.json から読み込み)
# ============================================================
_CLIENTS_JSON = os.path.join(os.path.dirname(os.path.abspath(__file__)), "clients.json")
with open(_CLIENTS_JSON, encoding="utf-8") as _f:
    MAC_TO_HOST: dict[str, str] = json.load(_f)

# フレームタイプ定数
FRAME_TYPE_MAP = {
    "0": "管理",
    "1": "制御",
    "2": "データ",
}

# Airtime帰属の特殊処理が必要な制御フレームの fc_type_subtype 値
# tshark -T fields は fc_type_subtype を10進整数で出力する
# ACK/CTS は TA を持たず RA のみ。RA が示す端末に Airtime を帰属させる。
CONTROL_SUBTYPES_RA_ONLY = {
    28,  # CTS (Clear To Send)  — 0x001c
    29,  # ACK                  — 0x001d
}

# 制御フレームのサブタイプ名マッピング (fc_type_subtype 10進値 → 表示名)
CONTROL_SUBTYPE_NAMES = {
    24: "BAR",          # Block Ack Request — 0x0018
    25: "BA",           # Block Ack         — 0x0019
    26: "PS-Poll",      # PS-Poll           — 0x001a
    27: "RTS",          # Request To Send   — 0x001b
    28: "CTS",          # Clear To Send     — 0x001c
    29: "ACK",          # Acknowledgement   — 0x001d
    30: "CF-End",       # CF-End            — 0x001e
    31: "CF-End+ACK",   # CF-End + CF-Ack   — 0x001f
}

# tshark で抽出するフィールド定義: (tsharkフィールド名, DataFrame列名)
TSHARK_FIELDS = [
    ("frame.time_epoch",      "timestamp_epoch"),
    ("frame.len",             "frame_length"),
    ("wlan.fc.type",          "frame_type"),
    ("wlan.fc.type_subtype",  "frame_subtype"),
    ("wlan.ta",               "ta"),
    ("wlan.sa",               "sa"),
    ("wlan.ra",               "ra"),
    ("wlan.da",               "da"),
    ("wlan_radio.duration",   "duration_us"),
    ("wlan_radio.data_rate",  "data_rate_mbps"),
]


def resolve_host(mac) -> str:
    """MACアドレスをホスト名に解決する。未登録ならMACアドレスをそのまま返す。"""
    if mac is None or (isinstance(mac, float) and pd.isna(mac)) or mac != mac:
        return "Unknown"
    return MAC_TO_HOST.get(str(mac).lower(), str(mac))


def parse_args() -> argparse.Namespace:
    """コマンドライン引数をパースする。"""
    parser = argparse.ArgumentParser(
        description="IEEE 802.11 pcap パケット解析ツール — Airtime占有率・データレート相関分析"
    )
    parser.add_argument(
        "pcap_file",
        help="解析対象の .pcap または .pcapng ファイルパス",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="出力先ディレクトリ（デフォルト: カレントディレクトリ）",
    )
    parser.add_argument(
        "--mtu-min",
        type=int,
        default=1400,
        help="正規化フィルタ: 最小フレーム長 (Bytes)（デフォルト: 1400）",
    )
    parser.add_argument(
        "--mtu-max",
        type=int,
        default=1500,
        help="正規化フィルタ: 最大フレーム長 (Bytes)（デフォルト: 1500）",
    )
    return parser.parse_args()


def repair_pcap(pcap_file: str) -> str | None:
    """
    editcap を使って破損した pcap ファイルを修復する。
    修復成功時は一時ファイルのパスを返す。修復不要・失敗時は None を返す。

    Parameters
    ----------
    pcap_file : str
        元の pcap/pcapng ファイルパス

    Returns
    -------
    str | None
        修復済みファイルのパス、または None
    """
    # capinfos でファイル全体の整合性をチェック
    try:
        result = subprocess.run(
            ["capinfos", pcap_file],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0 and "cut short" not in result.stderr.lower():
            return None  # 正常なファイル — 修復不要
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # capinfos が無い場合は tshark でフォールバック
        try:
            result = subprocess.run(
                ["tshark", "-r", pcap_file],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0:
                return None
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return None

    # editcap で破損パケットを除去した一時ファイルを作成
    print("[WARN] pcap ファイルが破損している可能性があります。editcap で修復を試みます...")
    suffix = ".pcapng" if pcap_file.endswith(".pcapng") else ".pcap"
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=suffix)
    os.close(tmp_fd)

    try:
        result = subprocess.run(
            ["editcap", pcap_file, tmp_path],
            capture_output=True, text=True, timeout=120,
        )
        if os.path.isfile(tmp_path) and os.path.getsize(tmp_path) > 0:
            print(f"[INFO] 修復済みファイルを作成しました: {tmp_path}")
            return tmp_path
        else:
            print("[ERROR] editcap による修復に失敗しました。", file=sys.stderr)
            return None
    except FileNotFoundError:
        print("[ERROR] editcap が見つかりません。Wireshark / tshark をインストールしてください。", file=sys.stderr)
        return None
    except subprocess.TimeoutExpired:
        print("[ERROR] editcap がタイムアウトしました。", file=sys.stderr)
        return None


def extract_packets(pcap_file: str) -> pd.DataFrame:
    """
    tshark -T fields を使ってパケット情報を高速に抽出する。

    PyShark の XML/JSON パースオーバーヘッドを回避し、tshark から
    必要なフィールドだけを TSV 形式で一括出力 → pandas に直接読み込む。
    数百万パケット規模の pcap でも高速に処理できる。

    Parameters
    ----------
    pcap_file : str
        pcap/pcapng ファイルのパス

    Returns
    -------
    pd.DataFrame
        抽出されたパケット情報の DataFrame
    """
    # 破損チェック & 修復
    repaired_path = repair_pcap(pcap_file)
    target_file = repaired_path if repaired_path else pcap_file

    print(f"[INFO] ファイルを読み込み中 (tshark -T fields): {target_file}")

    # tshark コマンド構成
    cmd = [
        "tshark", "-r", target_file,
        "-T", "fields",
        "-E", "separator=,",
        "-E", "header=y",
        "-E", "quote=d",       # フィールドをダブルクォートで囲む
        "-E", "occurrence=f",  # 複数値フィールドは最初の値のみ
    ]
    for tshark_name, _ in TSHARK_FIELDS:
        cmd.extend(["-e", tshark_name])

    # tshark 出力を一時ファイルに直接書き出し（大規模データのメモリ節約）
    tmp_fd, tmp_csv = tempfile.mkstemp(suffix=".csv")
    os.close(tmp_fd)

    try:
        with open(tmp_csv, "w") as f:
            proc = subprocess.run(
                cmd, stdout=f, stderr=subprocess.PIPE, text=True,
            )

        if proc.returncode != 0:
            # 破損ファイルでも途中まで出力されている場合は続行
            if not os.path.isfile(tmp_csv) or os.path.getsize(tmp_csv) == 0:
                print(f"[ERROR] tshark 失敗: {proc.stderr.strip()}", file=sys.stderr)
                return pd.DataFrame()
            print(f"[WARN] tshark 非ゼロ終了 (rc={proc.returncode}): {proc.stderr.strip()}")
            print("[WARN] 出力済みデータで処理を続行します。")

        # pandas で CSV 読み込み
        col_rename = {tshark_name: col_name for tshark_name, col_name in TSHARK_FIELDS}
        df = pd.read_csv(
            tmp_csv,
            dtype=str,
            na_values=[""],
            keep_default_na=False,
        )
        df.rename(columns=col_rename, inplace=True)

    finally:
        if os.path.isfile(tmp_csv):
            os.remove(tmp_csv)

    # 修復用の一時ファイルを削除
    if repaired_path and os.path.isfile(repaired_path):
        os.remove(repaired_path)
        print(f"[INFO] 一時ファイルを削除しました: {repaired_path}")

    if df.empty:
        print("[INFO] 完了: 0 パケット抽出")
        return df

    # ==========================================
    # 型変換
    # ==========================================
    df["timestamp"] = pd.to_datetime(
        pd.to_numeric(df["timestamp_epoch"], errors="coerce"),
        unit="s", utc=True,
    )
    df["frame_length"] = pd.to_numeric(df["frame_length"], errors="coerce").astype("Int64")
    df["duration_us"] = pd.to_numeric(df["duration_us"], errors="coerce")
    df["data_rate_mbps"] = pd.to_numeric(df["data_rate_mbps"], errors="coerce")

    # frame_subtype を整数に変換 (tshark は 16進 "0x001d" 等で出力)
    def _parse_int_auto(val):
        """10進・16進 両対応の整数変換"""
        if pd.isna(val) or str(val).strip() == "":
            return pd.NA
        try:
            return int(str(val).strip(), 0)  # 0: 基数自動判定 (0x → 16進)
        except (ValueError, TypeError):
            return pd.NA
    df["frame_subtype_int"] = df["frame_subtype"].apply(_parse_int_auto).astype("Int64")

    # ==========================================
    # MAC アドレス統合 (TA優先→SA fallback, RA優先→DA fallback)
    # ==========================================
    df["src_mac"] = df["ta"].fillna(df["sa"])
    df["dst_mac"] = df["ra"].fillna(df["da"])

    # ==========================================
    # フレームタイプラベル
    # ==========================================
    df["frame_type_label"] = df["frame_type"].map(FRAME_TYPE_MAP).fillna("不明")

    # ==========================================
    # ホスト名解決
    # ==========================================
    df["src_host"] = df["src_mac"].apply(resolve_host)
    df["dst_host"] = df["dst_mac"].apply(resolve_host)

    # ==========================================
    # Airtime 帰属先の決定
    # ACK/CTS は TA を持たないため、RA (dst_mac) の端末に帰属させる
    # ==========================================
    is_ack_cts = (
        df["frame_subtype_int"].isin(CONTROL_SUBTYPES_RA_ONLY)
        & df["dst_mac"].notna()
    )
    df["airtime_owner_mac"] = df["src_mac"].copy()
    df.loc[is_ack_cts, "airtime_owner_mac"] = df.loc[is_ack_cts, "dst_mac"]
    df["airtime_owner_host"] = df["airtime_owner_mac"].apply(resolve_host)

    # 不要な中間カラムを削除
    df.drop(columns=["timestamp_epoch", "ta", "sa", "ra", "da"],
            inplace=True)

    print(f"[INFO] 完了: {len(df)} パケット抽出")
    return df


def compute_airtime_summary(df: pd.DataFrame, capture_duration_sec: float) -> tuple[pd.DataFrame, dict]:
    """
    端末ごとの Airtime 集計・占有率・実効スループットを算出する。

    占有率は2種類算出する:
    - airtime_occupancy_pct: 絶対占有率（分母 = キャプチャ実時間）
      → DIFS/SIFS/バックオフ/アイドル時間を含む物理的に正確な占有率
    - airtime_relative_pct:  相対占有率（分母 = 全端末のDuration合計）
      → 観測されたパケット送信時間内での比率（参考値）

    Parameters
    ----------
    df : pd.DataFrame
        全パケットの DataFrame
    capture_duration_sec : float
        キャプチャの総時間（秒）

    Returns
    -------
    tuple[pd.DataFrame, dict]
        (端末ごとの集計結果, チャネル利用統計)
    """
    # duration_us と airtime_owner_mac が有効なパケットのみ対象
    # ACK/CTS は src_mac=None だが airtime_owner_mac に RA が入っているため除外されない
    valid = df.dropna(subset=["airtime_owner_mac", "duration_us"])

    total_observed_duration_us = valid["duration_us"].sum()
    capture_duration_us = capture_duration_sec * 1e6  # wall-clock 時間を µs に変換

    summary_rows = []
    for mac, group in valid.groupby("airtime_owner_mac"):
        dur_sum = group["duration_us"].sum()
        byte_sum = group["frame_length"].sum()
        pkt_count = len(group)

        # 制御フレームのサブタイプ別カウント
        ctrl_frames = group[group["frame_type"] == "1"]
        ctrl_counts = {}
        for subtype_val, subtype_name in CONTROL_SUBTYPE_NAMES.items():
            count = int((ctrl_frames["frame_subtype_int"] == subtype_val).sum())
            if count > 0:
                ctrl_counts[f"ctrl_{subtype_name}"] = count

        # 絶対占有率（分母 = キャプチャ実時間）
        abs_occupancy_pct = (dur_sum / capture_duration_us * 100) if capture_duration_us > 0 else 0.0

        # 相対占有率（分母 = 全端末のDuration合計、参考値）
        rel_occupancy_pct = (dur_sum / total_observed_duration_us * 100) if total_observed_duration_us > 0 else 0.0

        # 実効スループット (bps)
        throughput_bps = (byte_sum * 8 / capture_duration_sec) if capture_duration_sec > 0 else 0.0

        # 平均データレート
        avg_rate = group["data_rate_mbps"].dropna().mean()

        row = {
            "airtime_owner_mac": mac,
            "host_name": resolve_host(mac),
            "total_duration_us": dur_sum,
            "airtime_occupancy_pct": round(abs_occupancy_pct, 4),
            "airtime_relative_pct": round(rel_occupancy_pct, 4),
            "total_bytes": byte_sum,
            "packet_count": pkt_count,
            "throughput_bps": round(throughput_bps, 2),
            "throughput_mbps": round(throughput_bps / 1e6, 4),
            "avg_data_rate_mbps": round(avg_rate, 2) if pd.notna(avg_rate) else None,
        }
        row.update(ctrl_counts)
        summary_rows.append(row)

    summary_df = pd.DataFrame(summary_rows)
    if not summary_df.empty:
        summary_df = summary_df.sort_values("airtime_occupancy_pct", ascending=False).reset_index(drop=True)

    # チャネル利用統計
    total_abs_occupancy = summary_df["airtime_occupancy_pct"].sum() if not summary_df.empty else 0.0
    channel_stats = {
        "capture_duration_us": capture_duration_us,
        "total_observed_duration_us": total_observed_duration_us,
        "total_occupancy_pct": round(total_abs_occupancy, 4),
        "overhead_idle_pct": round(100.0 - total_abs_occupancy, 4),
    }

    return summary_df, channel_stats


def create_scatter_data(df: pd.DataFrame, mtu_min: int, mtu_max: int) -> pd.DataFrame:
    """
    散布図用データを作成する（MTU付近パケットのみ抽出）。

    Parameters
    ----------
    df : pd.DataFrame
        全パケットの DataFrame
    mtu_min : int
        最小フレーム長
    mtu_max : int
        最大フレーム長

    Returns
    -------
    pd.DataFrame
        散布図用の (data_rate_mbps, duration_us, src_mac, src_host) データ
    """
    filtered = df.dropna(subset=["data_rate_mbps", "duration_us"])
    filtered = filtered[
        (filtered["frame_length"] >= mtu_min) & (filtered["frame_length"] <= mtu_max)
    ]
    return filtered[["data_rate_mbps", "duration_us", "src_mac", "src_host"]].reset_index(drop=True)


def plot_scatter(scatter_df: pd.DataFrame, output_path: str) -> None:
    """
    データレート vs Duration の散布図を描画・保存する。
    端末ごとに色分けし、凡例にホスト名を表示する。

    Parameters
    ----------
    scatter_df : pd.DataFrame
        散布図用データ
    output_path : str
        PNG 保存先パス
    """
    if scatter_df.empty:
        print("[WARN] 散布図用データが空のため、グラフを生成しません。")
        return

    plt.rcParams["font.family"] = "sans-serif"
    # macOS の日本語フォント対応
    plt.rcParams["font.sans-serif"] = ["Hiragino Sans", "Hiragino Maru Gothic Pro", "Arial Unicode MS", "sans-serif"]
    plt.rcParams["axes.unicode_minus"] = False

    fig, ax = plt.subplots(figsize=(12, 7))

    # 端末ごとに色分け
    hosts = scatter_df["src_host"].unique()
    colors = plt.cm.tab10.colors
    for i, host in enumerate(hosts):
        subset = scatter_df[scatter_df["src_host"] == host]
        color = colors[i % len(colors)]
        ax.scatter(
            subset["data_rate_mbps"],
            subset["duration_us"],
            label=host,
            alpha=0.5,
            s=15,
            color=color,
            edgecolors="none",
        )

    ax.set_xlabel("データレート (Mbps)", fontsize=13)
    ax.set_ylabel("Duration (µs)", fontsize=13)
    ax.set_title("データレート vs Airtime Duration（MTUフィルタ適用）", fontsize=15, fontweight="bold")
    ax.legend(title="端末", fontsize=9, title_fontsize=10, loc="upper right")
    ax.grid(True, alpha=0.3)

    fig.tight_layout()
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    print(f"[INFO] 散布図を保存しました: {output_path}")


def main():
    args = parse_args()

    # --- 入力ファイル検証 ---
    if not os.path.isfile(args.pcap_file):
        print(f"[ERROR] ファイルが見つかりません: {args.pcap_file}", file=sys.stderr)
        sys.exit(1)

    # --- 出力ディレクトリ作成 ---
    os.makedirs(args.output_dir, exist_ok=True)

    # --- パケット抽出 (tshark -T fields → pandas 直接読み込み) ---
    df = extract_packets(args.pcap_file)

    if df.empty:
        print("[ERROR] 抽出できたパケットが0件です。終了します。", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] DataFrame 作成完了: {len(df)} 行")

    # --- キャプチャ時間算出 ---
    timestamps = df["timestamp"].dropna()
    if len(timestamps) >= 2:
        capture_duration_sec = (timestamps.max() - timestamps.min()).total_seconds()
    else:
        capture_duration_sec = 0.0
    print(f"[INFO] キャプチャ時間: {capture_duration_sec:.2f} 秒")

    # --- CSV 1: 生データ ---
    raw_csv_path = os.path.join(args.output_dir, "raw_packets.csv")
    df.to_csv(raw_csv_path, index=False, encoding="utf-8-sig")
    print(f"[INFO] 生データCSV出力: {raw_csv_path} ({len(df)} 行)")

    # --- Airtime 集計 ---
    summary_df, channel_stats = compute_airtime_summary(df, capture_duration_sec)
    if not summary_df.empty:
        # --- CSV 2: Airtime集計 ---
        summary_csv_path = os.path.join(args.output_dir, "airtime_summary.csv")
        summary_df.to_csv(summary_csv_path, index=False, encoding="utf-8-sig")
        print(f"[INFO] Airtime集計CSV出力: {summary_csv_path} ({len(summary_df)} 端末)")

        # --- コンソール表示 ---
        print("\n" + "=" * 80)
        print("  端末別 Airtime 占有率サマリー（絶対値: 分母=キャプチャ実時間）")
        print("=" * 80)
        for _, row in summary_df.head(20).iterrows():
            ctrl_parts = []
            for subtype_name in CONTROL_SUBTYPE_NAMES.values():
                col = f"ctrl_{subtype_name}"
                if col in row and pd.notna(row[col]) and int(row[col]) > 0:
                    ctrl_parts.append(f"{subtype_name}:{int(row[col])}")
            ctrl_info = f"  ({', '.join(ctrl_parts)})" if ctrl_parts else ""
            print(
                f"  {row['host_name']:<20s}  "
                f"Airtime: {row['airtime_occupancy_pct']:>7.2f}%  "
                f"(相対: {row['airtime_relative_pct']:>6.2f}%)  "
                f"Duration: {row['total_duration_us']:>10.0f} µs  "
                f"Tput: {row['throughput_mbps']:>8.4f} Mbps"
                f"{ctrl_info}"
            )
        print("-" * 80)
        print(
            f"  {'チャネル利用合計':<20s}  "
            f"Airtime: {channel_stats['total_occupancy_pct']:>7.2f}%  "
            f"アイドル/オーバーヘッド: {channel_stats['overhead_idle_pct']:>7.2f}%"
        )
        print(
            f"  {'（内訳）':<20s}  "
            f"観測Duration合計: {channel_stats['total_observed_duration_us']:>10.0f} µs  "
            f"キャプチャ時間: {channel_stats['capture_duration_us']:>10.0f} µs"
        )
        print("=" * 80 + "\n")
    else:
        print("[WARN] Airtime集計データがありません。")

    # --- 散布図用データ ---
    scatter_df = create_scatter_data(df, args.mtu_min, args.mtu_max)
    scatter_csv_path = os.path.join(args.output_dir, "scatter_data.csv")
    scatter_df.to_csv(scatter_csv_path, index=False, encoding="utf-8-sig")
    print(f"[INFO] 散布図用CSV出力: {scatter_csv_path} ({len(scatter_df)} 行)")

    # --- 散布図 PNG ---
    scatter_png_path = os.path.join(args.output_dir, "scatter_rate_vs_duration.png")
    plot_scatter(scatter_df, scatter_png_path)
    
    print("[INFO] すべての処理が完了しました。")


if __name__ == "__main__":
    main()
