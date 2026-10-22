# ncm2music

网易云音乐加密音频 `.ncm` → 通用音频格式（MP3 / FLAC / M4A 等）的无损解密转换器。

带中文交互菜单，Windows 下双击即可使用；也可以作为命令行工具批量转换。

> **仅供个人对已购买音乐做本地备份 / 在任意播放器离线播放使用。请勿用于未授权的传播。**

## 特性

- **无损解密**：只是解密容器，不重新编码 —— 源文件是 320k MP3 就输出 MP3，是 FLAC 无损就输出 FLAC，不降音质
- **自动嗅探真实容器格式**：MP3 / FLAC / WAV / M4A / OGG / AAC 交叉识别，不会张冠李戴
- **标签自动写入**：歌名 / 歌手 / 专辑 / 封面图（FLAC picture、MP3 APIC、MP4 covr、OGG block 全支持）
- **无法内嵌封面时自动落旁车文件**：`歌名.cover.jpg`
- **流式解密**：1MB 分块处理，大文件不占内存，转换过程实时显示百分比
- **幂等**：已转换过的自动跳过，随时重跑、中断可续
- **原子落地**：先写临时文件再替换，中断不会留下损坏的半成品
- **自动搜索下载目录**：找不到默认目录时自动扫描常见位置和各盘符

## 使用

### 环境

需要 Python 3.8+ 与两个依赖：

```bash
pip install pycryptodome mutagen
```

### 交互菜单（推荐）

```bash
python ncm2music.py
```

不带任何参数启动，进入中文交互界面：

```
==================================================
   NCM 网易云音乐解密转换器 (交互版)
==================================================
把 .ncm 无损还原为 mp3/flac 等普通格式, 自动带封面标签
默认下载目录: D:\AlanNieu\Music\Cloud\VipSongsDownload

----------------------------------------------
  1. 转换整个文件夹   (使用默认下载目录)
  2. 转换其他文件夹   (自行输入路径)
  3. 转换单个文件     (自行输入 ncm 文件路径)
  4. 帮助说明
  0. 退出
```

日常使用就是：下载新歌 → 双击 → 按 1 → 回车 → 完成。

默认下载目录自动取 `%USERPROFILE%\Music\Cloud\VipSongsDownload`（网易云默认安装路径），也可在脚本顶部 `DEFAULT_DIR` 处修改；找不到时会自动扫描常见位置和各盘符。

### 双击运行（Windows）

仓库里的 `run_windows.bat` 会自动定位脚本并以 UTF-8 启动，放在同目录双击即可。

### 命令行

```bash
python ncm2music.py <ncm文件或目录> [-o 输出目录]
```

- `-o` 省略时，单文件输出到原目录，文件夹输出到 `<目录>\converted`
- 幂等：输出已存在则跳过

## 打包成单文件 exe（可选，发给朋友）

```bash
pip install pyinstaller
python -m PyInstaller --clean --noconfirm NCM2Music.spec
# 产物: dist\NCM2Music.exe (~13MB, 免 Python 环境直接双击)
```

## 实现说明

NCM 是网易云音乐的自有加密容器：头部存放经 AES-ECB 加密的 RC4 密钥与元数据，音频体用 keybox XOR 流加密。解密流程：

1. 校验 magic `CTENFDAM`
2. AES-ECB 解密核心密钥段（`hzHRAmso5kInbaxW`），取第 17 字节起的 ASCII keybox 密钥
3. 元数据段按 `0x63` XOR → 跳 22 字节 → base64 → AES-ECB 解出 JSON
4. 跳过 CRC(4)+gap(1)+封面帧，得到音频段偏移
5. 音频逐字节 `b ^= box[(box[j]+box[(box[j]+j)&0xff])&0xff]`（`j=(i+1)&0xff`）
6. 按解密后真实文件头确定容器格式并重写标签

## 许可证

[MIT](./LICENSE) —— 转换功能不附带任何云端接口，亦不提供任何绕开下载限制的能力。
