from gevent import monkey; monkey.patch_all(thread=False)
import time
from collections import defaultdict
import hashlib, pickle
from aoab.core.add import ADD

# 引入阈值签名库 (复用项目现有代码)
# 假设 PK2s 是 TBLSPublicKey 的列表，SK2 是 TBLSPrivateKey
# 参考 crypto/threshsig/boldyreva.py

def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()

def add_provablereliablebroadcast(sid, pid, N, f, PK2s, SK2, leader, input_val, receive, send, logger=None):
    """
    ADD-based Provable Reliable Broadcast (ADD-PRBC)
    
    Difference from RBC:
    - Generates a Threshold Signature (Sigma) on the Hash(M) as the Proof.
    - Output: (M, Sigma)
    """
    
    def broadcast(o): send(-1, o)
    
    # 状态容器
    echo_received = defaultdict(set)
    ready_received = defaultdict(set)
    ready_shares = defaultdict(lambda: {}) # 收集 READY 的签名份额 {h: {node_id: sig_share}}
    ready_sent = False
    
    # 最终结果
    prbc_output_hash = None
    prbc_output_proof = None # 这是一个完整的阈值签名
    
    # 1. 初始化 ADD 实例
    add_input = input_val if pid == leader else None
    add_instance = ADD(sid + "-ADD", pid, N, f, add_input, send, logger)
    
    # 2. Leader 开始
    if pid == leader:
        add_instance.run()
        m_hash = hash(input_val)
        broadcast(('PROPOSE', m_hash))

    while True:
        # --- 检查完成条件 ---
        # 必须同时满足：
        # 1. RBC 达成了共识 (有了完整的阈值签名 Proof)
        # 2. ADD 恢复出了数据
        # 3. 数据哈希匹配
        if prbc_output_proof is not None:
            # 确保 ADD 还在尝试恢复数据
            add_instance.run()
            data = add_instance.return_output()
            
            if data is not None:
                if hash(data) == prbc_output_hash:
                    # [关键修改] 返回数据和阈值签名证明
                    return data, prbc_output_proof
        
        # --- 接收消息 ---
        try:
            sender, msg = receive(timeout=0.001)
        except:
            add_instance.try_decode()
            continue
        
        tag = msg[0]

        # 处理 ADD 消息
        if tag in ['DISPERSE', 'RECONSTRUCT']:
            add_instance.handle_message(sender, msg)
            continue

        # 处理 PRBC 消息
        if tag == 'PROPOSE':
            # msg = ('PROPOSE', h)
            if sender == leader and msg[1] is not None:
                h = msg[1]
                broadcast(('ECHO', h))

        elif tag == 'ECHO':
            # msg = ('ECHO', h)
            h = msg[1]
            if sender not in echo_received[h]:
                echo_received[h].add(sender)
                # 收到 2f+1 ECHO -> 发送 READY 并附带签名份额
                if len(echo_received[h]) >= N - f and not ready_sent:
                    ready_sent = True
                    # [关键修改] 计算签名份额
                    # SK2.sign(h) 返回签名份额
                    sig_share = SK2.sign(h)
                    broadcast(('READY', h, sig_share))

        elif tag == 'READY':
            # msg = ('READY', h, sig_share)
            h = msg[1]
            sig_share = msg[2]
            
            # 验证签名份额是否有效
            try:
                # PK2s[sender] 是发送者的公钥分片
                # verify_share(sig_share, message_hash)
                if not PK2s.verify_share(sig_share, sender, h):
                    if logger: logger.warn(f"Invalid Ready share from {sender}")
                    continue
            except:
                continue

            if sender not in ready_received[h]:
                ready_received[h].add(sender)
                ready_shares[h][sender] = sig_share
                
                # 收到 f+1 READY -> 即使没收到 ECHO 也发送 READY (Amplification)
                if len(ready_received[h]) >= f + 1 and not ready_sent:
                    ready_sent = True
                    my_share = SK2.sign(h)
                    broadcast(('READY', h, my_share))
                
                # 收到 2f+1 READY -> 合成阈值签名 (Proof)
                if len(ready_shares[h]) >= N - f and prbc_output_proof is None:
                    try:
                        # [关键修改] 合成签名
                        # combine_shares(shares_dict) -> signature
                        # 注意：需要从 ready_shares 中取前 2f+1 个
                        shares_to_combine = dict(list(ready_shares[h].items())[:N-f])
                        sigma = PK2s.combine_shares(shares_to_combine)
                        
                        # 验证合成后的签名
                        if PK2s.verify_signature(sigma, h):
                            prbc_output_hash = h
                            prbc_output_proof = sigma
                            if logger: logger.info(f"PRBC {sid} Proof Constructed!")
                    except Exception as e:
                        if logger: logger.error(f"Combine shares failed: {e}")
