from gevent import monkey; monkey.patch_all(thread=False)
import time
from collections import defaultdict
import hashlib, pickle
from aoab.core.add import ADD  

def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()

def add_reliablebroadcast(sid, pid, N, f, PK2s, SK2, leader, input_val, receive, send, logger=None):
    """
    ADD-based Reliable Broadcast (实现 ADD 论文 Algorithm 3)
    1. Leader 对 Hash(M) 运行 Bracha RBC。
    2. 同时运行 ADD(M) 分发数据。
    3. 只有当 RBC 达成一致 且 ADD 恢复出 M 且 Hash 匹配时，输出 M。
    """
    
    # 辅助发送函数
    def broadcast(o): send(-1, o)

    # --- 1. 初始化 ---
    start_time = time.time()
    
    # Bracha RBC 的状态 (仅针对 Hash)
    echo_received = defaultdict(set)   # {hash: {senders}}
    ready_received = defaultdict(set)  # {hash: {senders}}
    ready_sent = False
    rbc_output_hash = None             # 最终一致认可的哈希
    
    # ADD 实例初始化
    # 如果我是 leader，我负责输入数据；否则输入 None
    add_input = input_val if pid == leader else None
    add_instance = ADD(sid + "-ADD", pid, N, f, add_input, send, logger)
    
    # 如果是 Leader，立即开始广播
    if pid == leader:
        # 1. 启动 ADD 分发数据
        add_instance.run()
        # 2. 启动 RBC 广播哈希
        m_hash = hash(input_val)
        broadcast(('PROPOSE', m_hash))

    # --- 2. 主循环 ---
    while True:
        # A. 检查是否可以输出
        # 条件：RBC 输出了哈希 + ADD 输出了数据 + 两者匹配
        if rbc_output_hash is not None:
            # 确保 ADD 正在运行（帮助恢复数据）
            add_instance.run()
            
            data = add_instance.return_output()
            if data is not None:
                if hash(data) == rbc_output_hash:
                    return data, rbc_output_hash
                else:
                    if logger: logger.warn(f"ADD-RBC {sid}: Hash mismatch!")

        # B. 接收消息
        try:
            # 非阻塞尝试接收，或者带微小超时
            sender, msg = receive(timeout=0.001)
        except:
            # 如果没消息，继续循环检查 ADD 解码状态
            # (因为 ADD 可能已经收集够了分片正在解码)
            add_instance.try_decode()
            continue

        tag = msg[0]
        
        # --- 处理 ADD 消息 (DISPERSE/RECONSTRUCT) ---
        if tag in ['DISPERSE', 'RECONSTRUCT']:
            add_instance.handle_message(sender, msg)
            continue

        # --- 处理 Bracha RBC 消息 (PROPOSE/ECHO/READY) ---
        if tag == 'PROPOSE':
            # 只有 Leader 能发 PROPOSE
            if sender == leader and msg[1] is not None:
                h = msg[1]
                # 收到 Proposal，发送 ECHO
                broadcast(('ECHO', h))

        elif tag == 'ECHO':
            h = msg[1]
            if sender not in echo_received[h]:
                echo_received[h].add(sender)
                # 收到 N-f (2t+1) 个 ECHO -> 发送 READY
                if len(echo_received[h]) >= N - f and not ready_sent:
                    ready_sent = True
                    broadcast(('READY', h))

        elif tag == 'READY':
            h = msg[1]
            if sender not in ready_received[h]:
                ready_received[h].add(sender)
                # 收到 f+1 个 READY -> 发送 READY (放大)
                if len(ready_received[h]) >= f + 1 and not ready_sent:
                    ready_sent = True
                    broadcast(('READY', h))
                
                # 收到 N-f 个 READY -> RBC 完成，锁定哈希
                if len(ready_received[h]) >= N - f and rbc_output_hash is None:
                    rbc_output_hash = h
                    if logger: logger.debug(f"ADD-RBC {sid}: Hash decided {h[:4].hex()}")
