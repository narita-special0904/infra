import os
import schedule
import time
import re
from datetime import datetime, timedelta, timezone
from collections import Counter
import matplotlib.pyplot as plt
import japanize_matplotlib

from langchain_openai import AzureChatOpenAI
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser

# 異常検知する直近N時間定義
N = 2

# AOAIモデル
model = AzureChatOpenAI(
    azure_endpoint = os.environ["AZURE_OPENAI_ENDPOINT"],
    azure_deployment = os.environ["AZURE_OPENAI_MODEL_4O_MINI"],
    api_version = "2024-11-01-preview",
    api_key = os.environ["AZURE_OPENAI_API_KEY"],
    temperature = 0.0,
    max_tokens = 3000,
)

# 出力パーサー
output_parser = StrOutputParser()

# Apacheアクセスログ読込み
def read_logs(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()

    return logs
    
# 直近N時間のログを日本時間(JST)で抽出
def fileter_logs_by_time(logs, time_format="%d/%b/%Y:%H:%M:%S", recent_hours=N):
    # 現在時刻(JST)
    jst = timezone(timedelta(hours=9))
    now = datetime.now(jst)
    n_hours_ago = now - timedelta(hours=recent_hours)

    # ログ格納用リスト
    filterd_logs = []
    for line in logs:
        match = re.search(r'\[([\w:/]+)\s[+\-]\d{4}\]', line)  # 日付部分を抽出

        if match:
            log_time_str = match.group(1)
            log_time     = datetime.strptime(log_time_str, time_format)
            log_time_jst = log_time.replace(tzinfo=jst)

            if n_hours_ago <= log_time_jst <= now:
                filterd_logs.append(line)

    return filterd_logs


# LangChainによる異常検知
def detect_anomalies_with_langchain(logs):
    # Apache combinedフォーマットでHTTPステータスコードでログ抽出する場合は、下記をコメントイン
    # target_logs = "\n".join([line for line in logs if re.search(r'"\w+ [^"]+ HTTP/[\d.]+" (4|5)\d{2} ', line)])

    target_logs = logs

    # プロンプト
    prompt = PromptTemplate.from_template(f"""### 指示 ###
    以下のApacheログにはセキュリティ観点から異常が含まれているか確認して、
    下記の四点を該当行単位かつ日付の昇順に回答してください。
    １．アクセス元IPアドレス
    ２．日付（YYYY/MM/DD HH:MM:SS)
    ３．問題点（概要と問題点箇所のログ抽出）
    ４．解決策

    ### Apacheログ ###
    {target_logs}
    """)


    # Chain
    chain = prompt | model | output_parser

    return chain.invoke({"target_logs": target_logs})

# チェックタスク
def check_logs():
    # 対象ログファイル
    log_file = "/var/log/httpd/access.log"
    # ログ読込み
    logs = read_logs(log_file)
    # 直近N時間のログをフィルタリング
    recent_logs = fileter_logs_by_time(logs)

    if not recent_logs:
        print(f"直近でログはありませんでした") # ログがない確率は極めて低いですが念の為
        # 処理を終了させる
        return

    # LangChainによる異常検知
    annomalies = detect_anomalies_with_langchain(recent_logs)
    print("異常が検知されました！")
    print(annomalies)

# スケジュール設定
def schedule_log_checks(unit, interval=N):
    # interval_hours毎にログをチェックするスケジュール
    if unit == "H":
        schedule.every(interval).hours.do(check_logs)    # 時間単位
    elif unit == "M":
        schedule.every(interval).minutes.do(check_logs)  # 分単位
    elif unit == "S":
        schedule.every(interval).seconds.do(check_logs)  # 秒単位(テスト用)

    # スケジュール実行ループ
    print(f"{N}時間毎の実行にスケジューリングされています。停止はCtrl+Cです。\n\n")
    while True:
        schedule.run_pending()
        time.sleep(1)

# メイン関数
if __name__ == "__main__":
    # チェック間隔
    interval = 10
    # チェック間隔時間単位（時H／分M／秒S)
    unit = "S"

    schedule_log_checks(unit, interval)
    