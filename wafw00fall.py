import subprocess
import time
import threading
from concurrent.futures import ThreadPoolExecutor

lock = threading.Lock()

def check_waf(target):
    try:
        result = subprocess.run(
            ["wafw00f", target],
            capture_output=True,
            text=True,
            timeout=20
        )
        output = result.stdout.lower()

        # 无 WAF
        if "no waf detected" in output or "is behind no known" in output:
            return "no_waf"

        # 已识别具体 WAF
        if any(x in output for x in [
            "web application firewall",
            "is behind",
            "detected"
        ]):
            if "no waf" not in output:
                return "has_waf"

        # suspicious / unknown / generic
        if any(x in output for x in ["unknown", "suspicious", "generic"]):
            return "unidentified"

        return "unidentified"

    except Exception:
        return "error"


def process_target(target):
    print(f"[+] 扫描: {target}")
    status = check_waf(target)

    if status == "no_waf":
        print(f"    [-] 未发现 WAF → 写入 ok1.txt")

        # 实时写入（线程安全）
        with lock:
            with open("ok1.txt", "a") as ok:
                ok.write(target + "\n")

    elif status == "has_waf":
        print(f"    [!] 发现 WAF → 跳过")
    else:
        print(f"    [*] 未识别 / suspicious → 跳过")

    time.sleep(0.2)


def main():
    with open("targets.txt", "r") as f:
        targets = [line.strip() for line in f if line.strip()]

    threads = 10  # ← 修改并发数

    print(f"\n[*] 任务开始，共 {len(targets)} 个目标（并发：{threads}）\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(process_target, targets)

    print("\n任务完成！所有无WAF目标已实时写入 ok1.txt\n")


if __name__ == "__main__":
    main()
