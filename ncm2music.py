# -*- coding: utf-8 -*-
"""
NCM -> 原格式无损转换工具
NCM 是网易云音乐的加密壳: 去掉加密层后, 内核就是原始音频文件,
因此不做任何转码/重采样, 音质 100% 与原文件一致。同时写回标题/歌手/专辑/封面标签。

算法对照参考: taurusxin/ncmdump (github), 与其 C++ 实现逐字节一致。
v2 增强 (借鉴 NCM-Format-Converter-v1.3.0 逆向结论):
  - 格式嗅探扩展: mp3 / flac / wav(RIFF) / m4a(ftyp) / ogg(OggS) / aac(ADTS)
  - 流式解密 (1MB 分段), 大文件不吃内存; progress/cancel 回调钩子
  - 标签与封面按容器写入: MP4(covr) / Ogg(metadata_block_picture) / WAV(ID3)
  - 无法内嵌封面时 (ADTS AAC 或嵌封面失败) 写旁车文件 "<名>.cover.jpg/.png"
  - 原子写入: 先写 ".converting" 临时文件, 完成后 os.replace

用法:
    python ncm2music.py <ncm目录或单个ncm文件> [-o 输出目录]
"""

import argparse
import base64
import json
import os
import struct
import sys
import threading
from Crypto.Cipher import AES
from mutagen.flac import FLAC, Picture
from mutagen.id3 import ID3, APIC, TALB, TIT2, TPE1, TPE2
from mutagen.mp4 import MP4, MP4Cover
from mutagen.oggopus import OggOpus
from mutagen.oggvorbis import OggVorbis

CHUNK = 1 << 20  # 流式解密段大小

# ---- 网易加密常量 (经真实文件验证) ----
MAGIC = b"CTENFDAM"
KEY_AES = b"hzHRAmso5kInbaxW"  # 解密歌曲 key (AES-ECB)
META_AES = (
    b"#14ljk_!\\]&0U<'("  # 解密元数据 (AES-ECB), 需先去 "163 key(Don't modify):" 头
)


class Cancelled(Exception):
    """解密过程中收到取消事件"""


def pkcs7_trim(data: bytes) -> bytes:
    """taglib 风格: 最后一字节为填充长度"""
    if not data:
        return data
    pad = data[-1]
    return data[: len(data) - pad] if 0 < pad <= 16 else data


def aes_ecb_decrypt(key: bytes, data: bytes) -> bytes:
    return pkcs7_trim(AES.new(key, AES.MODE_ECB).decrypt(data))


def build_keybox(key: bytes):
    box = list(range(256))
    last = 0
    pos = 0
    klen = len(key)
    for i in range(256):
        swap = box[i]
        c = (swap + last + key[pos]) & 0xFF
        pos += 1
        if pos >= klen:
            pos = 0
        box[i] = box[c]
        box[c] = swap
        last = c
    return box


def snip_unicode_escape(s: str) -> str:
    """元数据 JSON 可能含双重转义的 \\uXXXX, 尽量还原"""
    if "\\u" in s or "\\n" in s or '\\"' in s:
        try:
            return json.loads('"{0}"'.format(s))
        except Exception:
            pass
    return s


def parse_ncm_header(handle):
    """从文件对象当前位置(10字节 magic+gap 之后)解析头部。
    返回 (key, meta_dict, image_bytes, audio_offset)。"""
    pos = 10

    # ---- 歌曲密钥: XOR 0x64 -> AES -> 直接 ASCII 取内容作 keybox 密钥 ----
    handle.seek(pos)
    key_len = struct.unpack("<I", handle.read(4))[0]
    pos += 4
    kd = bytearray(handle.read(key_len))
    pos += key_len
    for i in range(key_len):
        kd[i] ^= 0x64
    key_dec = aes_ecb_decrypt(KEY_AES, bytes(kd))  # b'neteasecloudmusic<keytext>'
    key = key_dec[17:]

    # ---- 元数据: XOR 0x63 -> 跳过22字节头 -> base64 -> AES -> 跳过'music:' -> JSON ----
    meta_dict = {}
    handle.seek(pos)
    meta_len = struct.unpack("<I", handle.read(4))[0]
    pos += 4
    if meta_len:
        md = bytearray(handle.read(meta_len))
        pos += meta_len
        for i in range(meta_len):
            md[i] ^= 0x63
        try:
            payload = base64.b64decode(bytes(md[22:]))
            dec = aes_ecb_decrypt(META_AES, payload)  # b'music:{...}'
            meta_dict = json.loads(dec[6:].decode("utf-8", "ignore"))
        except Exception:
            meta_dict = {}

    # ---- CRC32(4) + gap(1) + 封面帧: frame_len(4) + image_len(4) + image ----
    pos += 5
    handle.seek(pos)
    frame_len = struct.unpack("<I", handle.read(4))[0]
    pos += 4
    image_len = struct.unpack("<I", handle.read(4))[0]
    pos += 4
    image = handle.read(image_len) if image_len else b""
    pos += image_len
    pos += max(0, frame_len - image_len)  # 帧内剩余(老格式一般为0)

    return key, meta_dict, image, pos


def sniff_format(head: bytes, meta: dict) -> str:
    """按解密后的文件头嗅探真实容器格式 (借鉴 ncm_core, 分支顺序避开歧义)。
    返回 (fmt, skip_bytes): skip_bytes 为流内已嵌入 ID3 标签应跳过的字节数。"""
    if head[:4] == b"fLaC":
        return "flac", 0
    if head[:4] == b"RIFF":
        return "wav", 0
    if head[:4] == b"OggS":
        return "ogg", 0
    if head[4:8] == b"ftyp":  # mp4/m4a: size(4) + 'ftyp'
        return "m4a", 0
    if head[:3] == b"ID3":
        # 网易嵌入的原 ID3 标签: 同步安全整数(head[6..9], 每字节7位), 不含10字节头
        sz = 0
        for i, shift in enumerate((21, 14, 7, 0)):
            sz |= head[6 + i] << shift
        if 0 < sz < (1 << 31):
            return "mp3", 10 + sz  # 跳过原标签, 统一由 apply_tags 重写
        return "mp3", 0
    if head[0] == 0xFF and (head[1] & 0xE0) == 0xE0:
        # ADTS AAC: sync 12bit=0xFFF 且 layer 恒为 00; MP3 的 layer 位为 01
        return ("aac" if (head[1] & 0x06) == 0x00 else "mp3"), 0
    return str(meta.get("format", "mp3")).lower(), 0


def decrypt_chunks(handle, start, box, total, progress=None, cancel=None):
    """从 start 开始流式解密音频, 逐段 yield"""
    idx = 0
    handle.seek(start)
    while True:
        if cancel is not None and cancel.is_set():
            raise Cancelled()
        raw = handle.read(CHUNK)
        if not raw:
            break
        arr = bytearray(raw)
        n = len(arr)
        for k in range(n):
            j = (idx + k + 1) & 0xFF
            arr[k] ^= box[(box[j] + box[(box[j] + j) & 0xFF]) & 0xFF]
        idx += n
        if progress is not None:
            progress(idx, total)
        yield bytes(arr)


def _text(meta: dict):
    """从元数据取 (title, album, artist)"""

    def snip(v):
        return snip_unicode_escape(v) if isinstance(v, str) else v

    title = snip(str(meta.get("musicName", ""))) if meta else ""
    album = snip(str(meta.get("album", ""))) if meta else ""
    artist = ""
    if meta:
        ar = meta.get("artist", [])
        if isinstance(ar, list) and ar:
            artist = "&".join(snip(str(a[0])) for a in ar if isinstance(a, list) and a)
    return title, album, artist


def _picture(meta_image: bytes):
    """if 有封面: 返回 (mime, image), else (b'', b'')"""
    if not meta_image:
        return "", b""
    mime = "image/png" if meta_image[:4] == b"\x89PNG" else "image/jpeg"
    return mime, meta_image


def _sidecar_paths(audio_path: str, image: bytes) -> str:
    """写旁车封面文件, 返回其路径 (含扩展名)"""
    ext = ".png" if image[:4] == b"\x89PNG" else ".jpg"
    sc = audio_path[:-4] + ".cover" + ext
    with open(sc, "wb") as f:
        f.write(image)
    return sc


def apply_tags(path: str, fmt: str, meta: dict, image: bytes):
    """把标题/歌手/专辑/封面写回音频文件。
    返回 sidecar_path(仅当封面没能内嵌且 image 非空时), 失败抛异常由调用方处理。"""

    title, album, artist = _text(meta)
    mime, cover = _picture(image)

    def set_common(add_fn):
        """容器无关的文本标签设值"""
        add_fn("title", title)
        add_fn("album", album)
        add_fn("artist", artist)

    sidecar = None
    if fmt == "flac":
        tags = FLAC(path)
        set_common(lambda k, v: tags.__setitem__(k, [v]) if v else None)
        if artist:
            tags["albumartist"] = [artist]
        if cover:
            pic = Picture()
            pic.data = cover
            pic.type = 3
            pic.mime = mime
            tags.add_picture(pic)
        tags.save()
    elif fmt in ("m4a", "mp4"):
        mp4 = MP4(path)
        m = {
            "title": "\xa9nam",
            "album": "\xa9alb",
            "artist": "\xa9ART",
        }
        for key, tag in m.items():
            v = {"title": title, "album": album, "artist": artist}[key]
            if v:
                mp4[tag] = [v]
        if artist:
            mp4["aART"] = [artist]
        if cover:
            ifmt = MP4Cover.FORMAT_PNG if mime == "image/png" else MP4Cover.FORMAT_JPEG
            mp4["covr"] = [MP4Cover(cover, imageformat=ifmt)]
        mp4.save()
    elif fmt == "ogg":
        try:
            ogg = OggVorbis(path)
        except Exception:
            ogg = OggOpus(path)  # OggS 也可能是 opus
        set_common(lambda k, v: ogg.__setitem__(k, [v]) if v else None)
        if cover:
            pic = Picture()
            pic.data = cover
            pic.type = 3
            pic.mime = mime
            pic.depth, pic.width, pic.height = 24, 0, 0
            ogg["metadata_block_picture"] = [
                base64.b64encode(pic.write()).decode("ascii")
            ]
        ogg.save()
    elif fmt == "wav":
        from mutagen.wave import WAVE

        wav = WAVE(path)
        if wav.tags is None:
            wav.add_tags()
        set_common(
            lambda k, v: wav.tags.add(
                {"title": TIT2, "album": TALB, "artist": TPE1}[k](encoding=3, text=v)
            )
            if v
            else None
        )
        if artist:
            wav.tags.add(TPE2(encoding=3, text=artist))
        if cover:
            wav.tags.add(APIC(encoding=3, mime=mime, type=3, desc="Cover", data=cover))
        wav.save()
    elif fmt == "mp3":
        try:
            tags = ID3(path)
        except Exception:
            tags = ID3()
        if title:
            tags.add(TIT2(encoding=3, text=title))
        if album:
            tags.add(TALB(encoding=3, text=album))
        if artist:
            tags.add(TPE1(encoding=3, text=artist))
            tags.add(TPE2(encoding=3, text=artist))
        if cover:
            tags.add(APIC(encoding=3, mime=mime, type=3, desc="Cover", data=cover))
        tags.save(path, v2_version=3)
    else:
        # aac 等无可靠 ID3 容器: 封面走旁车
        if cover:
            sidecar = _sidecar_paths(path, cover)
    return sidecar


def convert_one(ncm_path: str, out_dir: str, progress=None, cancel=None):
    """转换单个 ncm。返回 (out_path, fmt, size, skipped, sidecar)"""
    with open(ncm_path, "rb") as f:
        if f.read(8) != MAGIC:
            raise ValueError("不是有效的 NCM 文件(魔数不符)")
        total = os.fstat(f.fileno()).st_size
        key, meta, image, audio_offset = parse_ncm_header(f)
        box = build_keybox(key)

        # 先解密起始块用于嗅探格式 => 决定输出文件名
        chunks = decrypt_chunks(f, audio_offset, box, total, progress, cancel)
        head = next(chunks, b"")
        fmt, skip = sniff_format(bytes(head), meta)

        base = os.path.splitext(os.path.basename(ncm_path))[0]
        out_path = os.path.join(out_dir, base + "." + fmt)
        if os.path.exists(out_path):
            # 仍需吃掉剩余 chunk 才算进度, 但直接跳过写入
            return out_path, fmt, total - audio_offset, True, None

        tmp = out_path + ".converting"
        import itertools

        with open(tmp, "wb") as out:
            for ch in itertools.chain([head], chunks):
                if skip:  # 嗅探头内嵌原 ID3: 跳过原标签字节(可跨块)
                    if skip >= len(ch):
                        skip -= len(ch)
                        continue
                    ch = ch[skip:]
                    skip = 0
                out.write(ch)
        os.replace(tmp, out_path)  # 原子落地, 中断不留半截文件

    sidecar = None
    try:
        sidecar = apply_tags(out_path, fmt, meta, image)
    except Exception as e:
        print(f"    (音频已转换, 但写标签失败: {e})")
    return out_path, fmt, total - audio_offset, False, sidecar


def make_progress_fn(name: str):
    """大文件(>30MB)打印百分比进度, 小文件安静"""

    def cb(done, total):
        if total < 30 * 1024 * 1024:
            return None
        end = done >= total
        sys.stdout.write(
            "\r    解密 %-50s %3d%%%s"
            % (name[:50], done * 100 // total, "\n" if end else "")
        )
        sys.stdout.flush()

    return cb


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("src", help="NCM 文件或目录")
    ap.add_argument(
        "-o",
        "--outdir",
        default=None,
        help="输出目录(默认: 源目录下的 converted 文件夹)",
    )
    args = ap.parse_args()

    src = args.src
    files, out_dir = collect_targets(src, args.outdir)
    if files is None:
        sys.exit(1)
    run_batch(files, out_dir)


def collect_targets(src, outdir=None):
    """解析输入路径 -> (ncm文件列表, 输出目录); 无效返回 (None, None)。"""
    src = src.strip().strip('"')
    if os.path.isfile(src):
        files = [src]
        out_dir = outdir or os.path.dirname(src)
    elif os.path.isdir(src):
        files = sorted(
            os.path.join(src, x) for x in os.listdir(src) if x.lower().endswith(".ncm")
        )
        out_dir = outdir or os.path.join(src, "converted")
    else:
        print("路径不存在:", src)
        return None, None
    return files, out_dir


def run_batch(files, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    print(f"待转换: {len(files)} 个 | 输出目录: {out_dir}\n")

    cancel = threading.Event()
    ok, fail, skipped = 0, 0, 0
    for idx, p in enumerate(files, 1):
        name = os.path.basename(p)
        try:
            out_path, fmt, size, skipped_, sidecar = convert_one(
                p, out_dir, progress=make_progress_fn(name), cancel=cancel
            )
            if skipped_:
                skipped += 1
                print(f"[{idx}/{len(files)}] 跳过(已存在) {os.path.basename(out_path)}")
            else:
                ok += 1
                extra = f" + 封面旁车 {os.path.basename(sidecar)}" if sidecar else ""
                print(
                    f"[{idx}/{len(files)}] OK  {name} -> {os.path.basename(out_path)} "
                    f"({size / 1024 / 1024:.1f} MB){extra}"
                )
        except Cancelled:
            print(f"[{idx}/{len(files)}] 已取消 {name}")
            break
        except KeyboardInterrupt:
            cancel.set()
            print("收到 Ctrl+C, 取消后续任务…")
            break
        except Exception as e:
            fail += 1
            print(f"[{idx}/{len(files)}] 失败 {name}: {e}")

    print(f"\n完成: 成功 {ok}, 跳过 {skipped}, 失败 {fail}")


DEFAULT_DIR = os.path.join(
    os.path.expanduser("~"), "Music", "Cloud", "VipSongsDownload"
)

HELP_TEXT = """\
本工具把网易云音乐的 .ncm 加密文件无损还原为普通音频:
  - 源文件是 320k MP3  -> 输出 MP3
  - 源文件是 FLAC 无损 -> 输出 FLAC (不降音质)
  - 源文件是 M4A/其他  -> 按真实容器输出
  - 歌名 / 歌手 / 专辑 / 封面 自动写入, 任何播放器可用
  - 已转换过的自动跳过, 下载了新歌再跑一次即可

命令行方式(高级, 可选):
  python ncm2music.py <ncm文件或目录> [-o 输出目录]

修改默认下载目录: 编辑本脚本中的 DEFAULT_DIR 一行。
"""


def find_ncm_dirs(max_hits=8):
    """自动搜索本机包含 .ncm 文件的下载目录 (常见位置优先, 各盘符浅层扫描)。"""
    _prune = {
        "windows",
        "$recycle.bin",
        "system volume information",
        "program files",
        "program files (x86)",
        "programdata",
        "appdata",
        ".git",
        "node_modules",
        "__pycache__",
        "site-packages",
        ".cache",
        ".vscode",
    }
    hits = []
    seen = set()

    def add(path):
        p = os.path.normpath(path)
        if p in seen or not os.path.isdir(p):
            return
        seen.add(p)
        try:
            if any(x.lower().endswith(".ncm") for x in os.listdir(p)) and p not in hits:
                hits.append(p)
        except OSError:
            pass

    # 1. 已知/常见位置
    add(DEFAULT_DIR)
    home = os.path.expanduser("~")
    for sub in ("Music", "Documents", "Downloads", "Desktop"):
        add(os.path.join(home, sub))

    # 2. 各盘符浅层 (最多4层目录) 扫描
    for d in "CDEFGHI":
        root = d + ":\\"
        if not os.path.isdir(root):
            continue
        base_depth = root.count("\\")
        for cur, dirs, files in os.walk(root):
            if any(x.lower().endswith(".ncm") for x in files):
                add(cur)
                if len(hits) >= max_hits:
                    return hits
            if cur.count("\\") - base_depth >= 4:
                dirs[:] = []
            dirs[:] = [x for x in dirs if x.lower() not in _prune]
    return hits


def interactive():
    print("=" * 50)
    print("   NCM 网易云音乐解密转换器 (交互版)")
    print("=" * 50)
    print("把 .ncm 无损还原为 mp3/flac 等普通格式, 自动带封面标签")
    print("默认下载目录:", DEFAULT_DIR)
    while True:
        print("\n" + "-" * 46)
        print("  1. 转换整个文件夹   (使用默认下载目录)")
        print("  2. 转换其他文件夹   (自行输入路径)")
        print("  3. 转换单个文件     (自行输入 ncm 文件路径)")
        print("  4. 帮助说明")
        print("  0. 退出")
        choice = input("请输入编号后回车: ").strip()
        if choice == "0":
            print("再见!")
            return
        if choice == "1":
            src, outdir = DEFAULT_DIR, None
            if not os.path.isdir(DEFAULT_DIR):
                print("默认下载目录在这台电脑上不存在, 正在自动搜索网易云下载目录…")
                hits = find_ncm_dirs()
                if hits:
                    print("\n找到以下含 .ncm 文件的目录:")
                    for i, h in enumerate(hits, 1):
                        cnt = sum(
                            1 for x in os.listdir(h) if x.lower().endswith(".ncm")
                        )
                        print(f"  {i}. {h}  ({cnt} 个 ncm)")
                    pick = input("选择目录编号 (直接回车=选 1): ").strip().strip('"')
                    src = (
                        hits[int(pick) - 1]
                        if pick.isdigit() and 0 < int(pick) <= len(hits)
                        else hits[0]
                    )
                else:
                    src = (
                        input(
                            "未能自动找到, 请粘贴网易云下载文件夹路径 (直接回车返回菜单): "
                        )
                        .strip()
                        .strip('"')
                    )
                if not src:
                    continue
                outdir = (
                    input("输出目录(直接回车=自动存放): ").strip().strip('"') or None
                )
        elif choice == "4":
            print(HELP_TEXT)
            continue
        elif choice in ("2", "3"):
            src = input("请粘贴路径 (直接回车返回菜单): ").strip().strip('"')
            if not src:
                continue
            outdir = input("输出目录(直接回车=自动存放): ").strip().strip('"') or None
        else:
            print("无效输入, 请输入菜单里的编号")
            continue
        files, out_dir = collect_targets(src, outdir)
        if files is None:
            continue
        if not files:
            print("该文件夹下没有找到 .ncm 文件:", src)
            continue
        run_batch(files, out_dir)


if __name__ == "__main__":
    if len(sys.argv) == 1:
        interactive()
    else:
        main()
