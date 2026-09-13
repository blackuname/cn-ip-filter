#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
中国 IP 域名分类器
Python 3.6+

功能：
1. 从输入文件读取域名
2. DNS 解析域名
3. 使用 GeoLite2-Country.mmdb 判断 IP 国家/地区
4. CN / HK / MO / TW 归类为中国
5. 根域名 / 子域名分类
6. 实时写入结果
7. DNS 缓存
8. 支持断点继续
9. Ctrl+C 安全退出

运行：
    python3 cn.py -f success.txt -t 1000

指定数据库：
    python3 cn.py -f success.txt -t 1000 -m GeoLite2-Country.mmdb
"""

from __future__ import print_function

import os
import sys
import re
import time
import signal
import socket
import argparse
import asyncio
import threading
import subprocess
from urllib.parse import urlsplit

try:
    import aiodns
except ImportError:
    print("[错误] 未安装 aiodns")
    print("安装：pip3 install aiodns")
    sys.exit(1)

try:
    import geoip2.database
except ImportError:
    print("[错误] 未安装 geoip2")
    print("安装：pip3 install geoip2")
    sys.exit(1)

try:
    import tldextract
except ImportError:
    print("[错误] 未安装 tldextract")
    print("安装：pip3 install tldextract")
    sys.exit(1)


# ============================================================
# 配置
# ============================================================

DEFAULT_MMDB = "GeoLite2-Country.mmdb"

MMDB_URL = (
    "https://cdn.jsdelivr.net/gh/"
    "Loyalsoldier/geoip@release/GeoLite2-Country.mmdb"
)

DNS_SERVERS = [
    "223.5.5.5",
    "119.29.29.29",
    "8.8.8.8",
    "1.1.1.1",
]

# 中国地区
CHINA_COUNTRIES = set([
    "CN",
    "HK",
    "MO",
    "TW",
])

# DNS 超时
DNS_TIMEOUT = 1.5

# DNS 重试次数
DNS_RETRIES = 2

# DNS 缓存最大数量
DNS_CACHE_MAX = 500000

# 输出刷新间隔
FLUSH_INTERVAL = 1.0

# fsync 间隔
FSYNC_INTERVAL = 60.0

# 队列大小
QUEUE_MULTIPLIER = 4


# ============================================================
# 全局停止事件
# ============================================================

STOP_EVENT = None


# ============================================================
# 工具函数
# ============================================================

def print_flush(text):
    print(text)
    try:
        sys.stdout.flush()
    except Exception:
        pass


def normalize_domain(value):
    """
    清洗输入：
    http://example.com/a
    https://example.com:8080/a
    example.com
    www.example.com

    最终返回：
    example.com
    www.example.com
    """

    if value is None:
        return None

    value = value.strip()

    if not value:
        return None

    # 去掉 BOM
    value = value.lstrip("\ufeff")

    # 去掉空格
    value = value.strip()

    # 如果不是 scheme，urlsplit 可能解析错误
    test_value = value

    if "://" not in test_value:
        test_value = "//" + test_value

    try:
        parsed = urlsplit(test_value)
        host = parsed.hostname
    except Exception:
        return None

    if not host:
        return None

    host = host.strip().lower()

    # 去掉最后的 .
    host = host.rstrip(".")

    if not host:
        return None

    # IPv6 不作为域名处理
    if ":" in host:
        return None

    # IDN 转 Punycode
    try:
        host = host.encode("idna").decode("ascii").lower()
    except Exception:
        return None

    # 基础合法性
    if len(host) > 253:
        return None

    if not re.match(r"^[a-z0-9.-]+$", host):
        return None

    if host.startswith(".") or host.endswith("."):
        return None

    if ".." in host:
        return None

    parts = host.split(".")

    if len(parts) < 2:
        return None

    for part in parts:
        if not part:
            return None

        if len(part) > 63:
            return None

        if part.startswith("-") or part.endswith("-"):
            return None

        if not re.match(r"^[a-z0-9-]+$", part):
            return None

    return host


def is_ip(value):
    """
    判断是否 IPv4
    """

    try:
        socket.inet_aton(value)

        # 防止 inet_aton 接受 1.2.3
        if value.count(".") != 3:
            return False

        for x in value.split("."):
            if not x.isdigit():
                return False

            if int(x) > 255:
                return False

        return True

    except Exception:
        return False


def classify_domain(domain):
    """
    分类：

    www.example.com
        -> 根域名

    example.com
        -> 根域名

    a.example.com
        -> 子域名

    a.b.example.com
        -> 子域名

    注意：
    www 前缀一律按子域名处理。
    """

    try:
        result = TLD_EXTRACTOR(domain)

        registered = result.registered_domain

        if not registered:
            return None, None

        subdomain = result.subdomain

        # www 一律按子域名处理
        if subdomain == "www":
            return domain, "sub"

        # 没有子域
        if not subdomain:
            return registered, "tld"

        return domain, "sub"

    except Exception:
        return None, None


TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


# ============================================================
# 主处理器
# ============================================================

class DomainProcessor(object):

    def __init__(self, input_file, threads, mmdb_file):

        self.input_file = input_file
        self.threads = threads
        self.mmdb_file = mmdb_file

        self.loop = None

        # 停止事件
        self.stop_event = asyncio.Event()

        # DNS 缓存
        self.dns_cache = {}

        # DNS 缓存锁
        self.cache_lock = None

        # 写文件锁
        self.write_lock = None

        # 统计
        self.total = 0
        self.processed_count = 0
        self.china_count = 0
        self.other_count = 0
        self.failed_count = 0
        self.skipped_count = 0

        self.start_time = time.time()

        # 上一次统计
        self.last_stat_time = self.start_time
        self.last_stat_count = 0

        # GeoIP
        self.geoip_reader = None

        # 输出文件
        self.files = {}

        # 文件 flush
        self.last_flush_time = time.time()
        self.last_fsync_time = time.time()

        # 已处理
        self.processed = set()

        # DNS resolver
        self.resolvers = []

        # 只初始化一次，避免每个域名重复创建 TLDExtract
        self.extractor = tldextract.TLDExtract(suffix_list_urls=())

    # --------------------------------------------------------
    # 下载 GeoIP
    # --------------------------------------------------------

    def download_mmdb(self):

        if os.path.exists(self.mmdb_file):
            try:
                if os.path.getsize(self.mmdb_file) > 1024 * 1024:
                    print_flush(
                        "[+] GeoIP 数据库已存在：{}".format(
                            self.mmdb_file
                        )
                    )
                    return True
            except Exception:
                pass

        print_flush("[+] 正在下载 GeoLite2-Country.mmdb ...")

        tmp_file = self.mmdb_file + ".tmp"

        try:

            # 优先 curl
            cmd = [
                "curl",
                "-L",
                "--connect-timeout",
                "10",
                "--max-time",
                "120",
                "-o",
                tmp_file,
                MMDB_URL,
            ]

            result = subprocess.call(cmd)

            if result != 0:
                raise RuntimeError(
                    "curl 下载失败"
                )

            if not os.path.exists(tmp_file):
                raise RuntimeError(
                    "下载文件不存在"
                )

            if os.path.getsize(tmp_file) < 1024 * 1024:
                raise RuntimeError(
                    "下载的 mmdb 文件异常"
                )

            os.replace(
                tmp_file,
                self.mmdb_file
            )

            print_flush(
                "[+] GeoIP 数据库下载完成：{}".format(
                    self.mmdb_file
                )
            )

            return True

        except Exception as e:

            try:
                if os.path.exists(tmp_file):
                    os.remove(tmp_file)
            except Exception:
                pass

            print_flush(
                "[!] GeoIP 下载失败：{}".format(e)
            )

            print_flush(
                "[!] 请手动下载："
            )

            print_flush(MMDB_URL)

            return False

    # --------------------------------------------------------
    # 初始化
    # --------------------------------------------------------

    def initialize(self):

        if not os.path.exists(self.input_file):
            print_flush(
                "[!] 输入文件不存在：{}".format(
                    self.input_file
                )
            )
            return False

        if not self.download_mmdb():
            return False

        try:
            self.geoip_reader = geoip2.database.Reader(
                self.mmdb_file
            )
        except Exception as e:
            print_flush(
                "[!] GeoIP 数据库打开失败：{}".format(e)
            )
            return False

        # DNS resolver：使用一个 resolver 管理多个 DNS，避免每个域名同时向 4 个 DNS 发包，
        # 在高并发下更容易触发本机 UDP/socket 或 DNS 服务端限流。
        try:
            resolver = aiodns.DNSResolver(
                nameservers=DNS_SERVERS,
                timeout=DNS_TIMEOUT,
                tries=1
            )
            self.resolvers = [resolver]
            print_flush(
                "[+] DNS：{} | timeout={}s | retries={}".format(
                    ", ".join(DNS_SERVERS), DNS_TIMEOUT, DNS_RETRIES
                )
            )
        except Exception as e:
            print_flush("[!] DNS 初始化失败: {}".format(e))

        if not self.resolvers:
            print_flush(
                "[!] 没有可用 DNS resolver"
            )
            return False

        # 输出文件
        self.open_files()

        # 加载已处理域名
        self.load_processed()

        return True

    # --------------------------------------------------------
    # 打开输出
    # --------------------------------------------------------

    def open_files(self):

        output_files = [
            "china_tld.txt",
            "china_sub.txt",
            "other_tld.txt",
            "other_sub.txt",
            "failed_domains.txt",
            "processed_domains.txt",
        ]

        for filename in output_files:

            self.files[filename] = open(
                filename,
                "a",
                buffering=1
            )

    # --------------------------------------------------------
    # 读取已处理
    # --------------------------------------------------------

    def load_processed(self):

        filename = "processed_domains.txt"

        if not os.path.exists(filename):
            return

        print_flush(
            "[+] 正在读取断点记录..."
        )

        count = 0

        try:

            with open(
                filename,
                "r"
            ) as f:

                for line in f:

                    domain = line.strip()

                    if domain:
                        self.processed.add(
                            domain
                        )

                        count += 1

            print_flush(
                "[+] 已加载 {} 个已处理域名".format(
                    count
                )
            )

        except Exception as e:

            print_flush(
                "[!] 读取断点文件失败：{}".format(
                    e
                )
            )

    # --------------------------------------------------------
    # DNS 查询
    # --------------------------------------------------------

    async def resolve_domain(self, domain):
        """
        稳定高速 DNS 查询。
        不再同时向多个 DNS 发起重复请求，避免高并发时出现：
        aiodns.error.DNSError: (11, 'Could not contact DNS servers')
        """
        if is_ip(domain):
            return domain

        cached = self.dns_cache.get(domain)
        if cached:
            return cached

        resolver = self.resolvers[0]

        for attempt in range(DNS_RETRIES):
            try:
                result = await resolver.query(domain, "A")
                if result:
                    ip = result[0].host
                    if ip:
                        if len(self.dns_cache) < DNS_CACHE_MAX:
                            self.dns_cache[domain] = ip
                        return ip
            except Exception:
                if attempt + 1 < DNS_RETRIES:
                    await asyncio.sleep(0.005)

        return None

    # --------------------------------------------------------
    # GeoIP
    # --------------------------------------------------------

    def is_china_ip(self, ip):

        try:

            result = self.geoip_reader.country(
                ip
            )

            country_code = result.country.iso_code

            if country_code in CHINA_COUNTRIES:
                return True, country_code

            return False, country_code

        except Exception:

            return False, None

    # --------------------------------------------------------
    # 写结果
    # --------------------------------------------------------

    async def write_result(
        self,
        domain,
        result_type,
        country_code=None
    ):
        # 单事件循环下，短小的文件 write 无需 asyncio.Lock。
        # 去掉锁可减少几十万次 coroutine 切换。
        if result_type == "china_tld":
            self.files["china_tld.txt"].write(domain + "\n")
            self.china_count += 1

        elif result_type == "china_sub":
            self.files["china_sub.txt"].write(domain + "\n")
            self.china_count += 1

        elif result_type == "other_tld":
            self.files["other_tld.txt"].write(domain + "\n")
            self.other_count += 1

        elif result_type == "other_sub":
            self.files["other_sub.txt"].write(domain + "\n")
            self.other_count += 1

        elif result_type == "failed":
            self.files["failed_domains.txt"].write(domain + "\n")
            self.failed_count += 1

        self.files["processed_domains.txt"].write(domain + "\n")
        self.processed_count += 1

    # --------------------------------------------------------
    # flush
    # --------------------------------------------------------

    def flush_files(self, force_fsync=False):

        now = time.time()

        # 每秒 flush
        if (
            now - self.last_flush_time
            >= FLUSH_INTERVAL
        ):

            for f in self.files.values():

                try:
                    f.flush()
                except Exception:
                    pass

            self.last_flush_time = now

        # 每 10 秒 fsync
        if (
            force_fsync
            or now - self.last_fsync_time
            >= FSYNC_INTERVAL
        ):

            for f in self.files.values():

                try:
                    f.flush()
                    os.fsync(f.fileno())
                except Exception:
                    pass

            self.last_fsync_time = now

    # --------------------------------------------------------
    # 处理单个域名
    # --------------------------------------------------------

    async def process_domain(self, domain):

        if self.stop_event.is_set():
            return

        # 已处理
        if domain in self.processed:
            self.skipped_count += 1
            return

        # 加入当前 processed
        self.processed.add(domain)

        # DNS
        ip = await self.resolve_domain(
            domain
        )

        if not ip:

            await self.write_result(
                domain,
                "failed"
            )

            return

        # GeoIP
        is_china, country_code = (
            self.is_china_ip(ip)
        )

        # 域名类型
        registered, domain_type = (
            classify_domain(domain)
        )

        if not registered:

            await self.write_result(
                domain,
                "failed",
                country_code
            )

            return

        if is_china:

            if domain_type == "tld":

                await self.write_result(
                    domain,
                    "china_tld",
                    country_code
                )

            else:

                await self.write_result(
                    domain,
                    "china_sub",
                    country_code
                )

        else:

            if domain_type == "tld":

                await self.write_result(
                    domain,
                    "other_tld",
                    country_code
                )

            else:

                await self.write_result(
                    domain,
                    "other_sub",
                    country_code
                )

    # --------------------------------------------------------
    # worker
    # --------------------------------------------------------

    async def worker(self, queue):

        while True:

            domain = await queue.get()

            try:

                if domain is None:
                    return

                try:

                    await self.process_domain(
                        domain
                    )

                except Exception:

                    try:
                        await self.write_result(
                            domain,
                            "failed"
                        )
                    except Exception:
                        pass

            finally:

                queue.task_done()

    # --------------------------------------------------------
    # producer
    # --------------------------------------------------------

    async def producer(self, queue):

        print_flush(
            "[+] 开始读取：{}".format(
                self.input_file
            )
        )

        try:

            with open(
                self.input_file,
                "r"
            ) as f:

                for line in f:

                    if self.stop_event.is_set():
                        break

                    domain = normalize_domain(
                        line
                    )

                    if not domain:
                        continue

                    self.total += 1

                    # 已处理直接跳过
                    if domain in self.processed:

                        self.skipped_count += 1

                        continue

                    await queue.put(
                        domain
                    )

        except KeyboardInterrupt:

            self.stop_event.set()

        except Exception as e:

            print_flush(
                "[!] 读取输入文件失败：{}".format(
                    e
                )
            )

    # --------------------------------------------------------
    # 统计
    # --------------------------------------------------------

    def show_stats(self):

        now = time.time()

        elapsed = now - self.start_time

        if elapsed <= 0:
            elapsed = 0.001

        speed = (
            self.processed_count
            / elapsed
        )

        print(
            "\r"
            "总数:{:<10} "
            "处理:{:<10} "
            "中国:{:<10} "
            "其他:{:<10} "
            "失败:{:<10} "
            "跳过:{:<10} "
            "DNS缓存:{:<8} "
            "速度:{:.1f}/s".format(
                self.total,
                self.processed_count,
                self.china_count,
                self.other_count,
                self.failed_count,
                self.skipped_count,
                len(self.dns_cache),
                speed
            ),
            end=""
        )

        try:
            sys.stdout.flush()
        except Exception:
            pass

    # --------------------------------------------------------
    # 统计任务
    # --------------------------------------------------------

    async def stats_loop(self):

        while not self.stop_event.is_set():

            await asyncio.sleep(
                1
            )

            self.show_stats()

            self.flush_files()

    # --------------------------------------------------------
    # 主运行
    # --------------------------------------------------------

    async def run(self):

        self.loop = asyncio.get_event_loop()

        self.cache_lock = asyncio.Lock()

        self.write_lock = asyncio.Lock()

        queue_size = max(
            self.threads * QUEUE_MULTIPLIER,
            1000
        )

        queue = asyncio.Queue(
            maxsize=queue_size
        )

        # workers
        workers = []

        for i in range(
            self.threads
        ):

            task = asyncio.ensure_future(
                self.worker(queue)
            )

            workers.append(task)

        # producer
        producer_task = asyncio.ensure_future(
            self.producer(queue)
        )

        # stats
        stats_task = asyncio.ensure_future(
            self.stats_loop()
        )

        try:

            await producer_task

            # 等待队列处理完成
            await queue.join()

        except KeyboardInterrupt:

            self.stop_event.set()

        finally:

            self.stop_event.set()

            # 停止 worker
            for i in range(
                self.threads
            ):

                await queue.put(None)

            # 等待 worker
            await asyncio.gather(
                *workers,
                return_exceptions=True
            )

            stats_task.cancel()

            try:
                await stats_task
            except Exception:
                pass

            self.flush_files(
                force_fsync=True
            )

    # --------------------------------------------------------
    # 关闭
    # --------------------------------------------------------

    def close(self):

        print()

        print_flush(
            "[+] 正在关闭文件..."
        )

        self.flush_files(
            force_fsync=True
        )

        for f in self.files.values():

            try:
                f.close()
            except Exception:
                pass

        if self.geoip_reader:

            try:
                self.geoip_reader.close()
            except Exception:
                pass

        print_flush(
            "[+] 文件已关闭"
        )


# ============================================================
# 信号处理
# ============================================================

def install_signal(processor):

    def handler(signum, frame):

        print()
        print_flush(
            "[!] 收到停止信号，正在安全退出..."
        )

        try:
            processor.stop_event.set()
        except Exception:
            pass

    try:

        signal.signal(
            signal.SIGINT,
            handler
        )

        signal.signal(
            signal.SIGTERM,
            handler
        )

    except Exception:
        pass


# ============================================================
# 参数
# ============================================================

def parse_args():

    parser = argparse.ArgumentParser(
        description="中国 IP 域名分类工具"
    )

    parser.add_argument(
        "-f",
        "--file",
        required=True,
        help="输入域名文件"
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=2000,
        help="并发数量，默认 500"
    )

    parser.add_argument(
        "-m",
        "--mmdb",
        default=DEFAULT_MMDB,
        help="GeoLite2-Country.mmdb 路径"
    )

    return parser.parse_args()


# ============================================================
# 主函数
# ============================================================

def main():

    args = parse_args()

    if args.threads < 1:
        args.threads = 1

    if args.threads > 10000:

        print_flush(
            "[!] 并发过高，自动限制到 5000"
        )

        args.threads = 10000

    print()
    print("=" * 70)
    print("        中国 IP 域名分类工具")
    print("=" * 70)

    print(
        "输入文件 : {}".format(
            args.file
        )
    )

    print(
        "并发数量 : {}".format(
            args.threads
        )
    )

    print(
        "GeoIP    : {}".format(
            args.mmdb
        )
    )

    print(
        "DNS      : {}".format(
            ", ".join(DNS_SERVERS)
        )
    )

    print(
        "中国地区 : CN / HK / MO / TW"
    )

    print("=" * 70)
    print()

    processor = DomainProcessor(
        args.file,
        args.threads,
        args.mmdb
    )

    install_signal(
        processor
    )

    if not processor.initialize():

        processor.close()

        sys.exit(1)

    try:

        loop = asyncio.get_event_loop()

        loop.run_until_complete(
            processor.run()
        )

    except KeyboardInterrupt:

        print()
        print_flush(
            "[!] 用户中断"
        )

    except Exception as e:

        print()
        print_flush(
            "[!] 程序异常：{}".format(
                e
            )
        )

    finally:

        processor.close()

    elapsed = (
        time.time()
        - processor.start_time
    )

    if elapsed <= 0:
        elapsed = 0.001

    print()
    print("=" * 70)
    print("处理完成")
    print("=" * 70)

    print(
        "输入有效域名 : {}".format(
            processor.total
        )
    )

    print(
        "实际处理     : {}".format(
            processor.processed_count
        )
    )

    print(
        "中国域名     : {}".format(
            processor.china_count
        )
    )

    print(
        "其他国家     : {}".format(
            processor.other_count
        )
    )

    print(
        "解析失败     : {}".format(
            processor.failed_count
        )
    )

    print(
        "跳过/已处理  : {}".format(
            processor.skipped_count
        )
    )

    print(
        "平均速度     : {:.2f} 域名/秒".format(
            processor.processed_count
            / elapsed
        )
    )

    print()
    print("输出文件：")
    print("  china_tld.txt")
    print("  china_sub.txt")
    print("  other_tld.txt")
    print("  other_sub.txt")
    print("  failed_domains.txt")
    print("  processed_domains.txt")
    print("=" * 70)


if __name__ == "__main__":
    main()
