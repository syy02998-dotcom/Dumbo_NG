from gevent import monkey; monkey.patch_all(thread=False)
import logging
import time
import gevent
import gevent.queue
import pickle
import hashlib
import statistics  # 用于计算中位数
from aoab.core.add_rbc import add_reliablebroadcast
from dumbomvba.core.dumbomvba import dumbomvba

def aoab(sid, i, N, f, PK2s, SK2, input_func, output_func, receive_func, send_func):
    """
    AOAB Protocol with Strict Timestamp Ordering
    Paper: "AOAB: Optimal and Fair Ordering of Financial Transactions"
    """
    logger = logging.getLogger("aoab-node-%d" % i)
    K = 1000
    
    # 本地逻辑时钟 (Sequence Number)
    # 论文 Definition 2: seq_i(t) = (e, s)
    local_sequence_number = 0
    
    # 消息通道
    rbc_inputs = [gevent.queue.Queue() for _ in range(N)]
    mvba_input = gevent.queue.Queue()
    ts_req_queue = gevent.queue.Queue() # 处理 TS_REQUEST
    ts_rep_queues = [gevent.queue.Queue() for _ in range(N)] # 处理 TS_REPLY (我是Leader时用到)

    def dispatcher():
        while True:
            try:
                sender, msg = receive_func()
                tag = msg[0]
                
                if tag == 'RBC':
                    rbc_inputs[msg[1]].put((sender, msg[2]))
                elif tag == 'MVBA':
                    mvba_input.put((sender, msg[1]))
                
                # --- 新增：排序阶段的消息 ---
                elif tag == 'TS_REQUEST':
                    # 收到 Leader 请求，要回复我的本地 seq
                    ts_req_queue.put((sender, msg[1]))
                elif tag == 'TS_REPLY':
                    # 我是 Leader，收到别人回复的 seq
                    # msg = ('TS_REPLY', leader_id, batch_hash, seq, sig)
                    # 只有当我是那个 leader_id 时才处理（其实这里可以简化）
                    if msg[1] == i: 
                        ts_rep_queues[i].put((sender, msg))
            except Exception as e:
                gevent.sleep(0.01)
    
    gevent.spawn(dispatcher)

    # --- 协程：响应时间戳请求 (Server Side of Ordering Phase) ---
    def timestamp_server():
        nonlocal local_sequence_number
        while True:
            try:
                sender, batch_hash = ts_req_queue.get()
                # 论文逻辑：收到请求，分配 seq，自增
                assigned_seq = local_sequence_number
                local_sequence_number += 1
                
                # 这里应该对 (epoch, assigned_seq, batch_hash) 进行签名
                # 为了简化代码，这里用 "SIG" 字符串代替实际签名调用
                # 实际应为: sig = ecdsa_sign(SK2, f"{batch_hash}-{assigned_seq}".encode())
                sig = b"dummy_sig" 
                
                # 回复给 Leader
                send_func(sender, ('TS_REPLY', sender, batch_hash, assigned_seq, sig))
            except:
                gevent.sleep(0.01)
    gevent.spawn(timestamp_server)

    # --- Epoch Loop ---
    for r in range(K):
        logger.info(f"--- Starting Epoch {r} ---")
        epoch_start = time.time()

        # 1. Input Phase
        try: tx_batch = input_func() 
        except: tx_batch = b"Empty"
        
        batch_hash = hashlib.sha256(tx_batch).digest()

        # 2. Ordering Phase (论文 Algorithm 1: Assigning Sequence Numbers)
        # 只有当前 Leader 需要执行此逻辑
        
        rbc_threads = []
        rbc_results = [None] * N
        
        def run_leader_protocol(leader_id):
            # A. 排序阶段 (Ordering Phase)
            # 只有 Leader 执行主动逻辑，其他节点在 timestamp_server 中被动响应
            final_payload = None
            
            if leader_id == i:
                # 1. 广播请求
                # 论文: broadcasts request for sequence numbers
                for j in range(N):
                    send_func(j, ('TS_REQUEST', batch_hash))
                
                # 2. 收集 2f+1 个回复
                collected_seqs = []
                collected_proofs = []
                
                while len(collected_seqs) < 2 * f + 1:
                    try:
                        # ('TS_REPLY', leader_id, b_hash, seq, sig)
                        sender, msg = ts_rep_queues[i].get(timeout=0.1)
                        if msg[2] == batch_hash: # 校验 hash 匹配
                            collected_seqs.append(msg[3])
                            collected_proofs.append((sender, msg[3], msg[4]))
                    except gevent.queue.Empty:
                        # 重发请求以防丢包 (Retransmission)
                        for j in range(N): send_func(j, ('TS_REQUEST', batch_hash))
                
                # 3. 计算中位数 (Median)
                # 论文: builds threshold signature for the median value tau
                median_seq = statistics.median(collected_seqs)
                logger.info(f"Leader {i}: Computed Median Seq {median_seq} from {collected_seqs}")
                
                # 构造最终包含排序信息的包
                # Format: (Transactions, Median_Timestamp, Proofs)
                final_payload = pickle.dumps({
                    'tx': tx_batch,
                    'ts': median_seq,
                    'proofs': collected_proofs
                })
            else:
                final_payload = None # 其他人等待接收

            # B. 广播阶段 (Agreement Phase - ADD-RBC)
            def rbc_send(target, payload):
                wrapped_msg = ('RBC', leader_id, payload)
                if target == -1:
                    for j in range(N): send_func(j, wrapped_msg)
                else:
                    send_func(target, wrapped_msg)
            
            def rbc_recv(timeout=None):
                try: return rbc_inputs[leader_id].get(timeout=timeout)
                except: raise Exception("Timeout")

            try:
                # 运行 RBC，传输带时间戳的包
                data_bytes, _ = add_reliablebroadcast(
                    f"{sid}-E{r}-L{leader_id}", 
                    i, N, f, PK2s, SK2,
                    leader_id, final_payload, rbc_recv, rbc_send, logger
                )
                
                # C. 验证阶段 (Validation)
                # 收到数据后，必须验证其中位数时间戳是否合法
                # 论文: Verify validity of proposal
                data = pickle.loads(data_bytes)
                tx = data['tx']
                ts = data['ts']
                proofs = data['proofs']
                
                # 简单验证: 证明数量足够，且中位数计算正确
                # (严格实现还需要验证签名)
                valid_seqs = [p[1] for p in proofs]
                if len(valid_seqs) >= 2*f+1 and abs(statistics.median(valid_seqs) - ts) < 0.001:
                    rbc_results[leader_id] = data
                else:
                    logger.warn(f"Invalid timestamp from Leader {leader_id}")
                    
            except Exception as e:
                # logger.error(f"RBC {leader_id} error: {e}")
                pass

        # 启动 N 个并发流程
        threads = [gevent.spawn(run_leader_protocol, nid) for nid in range(N)]

        # 3. MVBA Consensus
        # 等待 N-f 个完成
        while sum(1 for res in rbc_results if res is not None) < N - f:
            gevent.sleep(0.01)
            
        completed_indices = [idx for idx, res in enumerate(rbc_results) if res is not None]
        
        # 运行 MVBA
        def mvba_send(target, payload):
            if target == -1:
                for j in range(N): send_func(j, ('MVBA', payload))
            else:
                send_func(target, ('MVBA', payload))
        def mvba_recv(): return mvba_input.get()

        try:
            decided_proposal = dumbomvba(
                f"{sid}-MVBA-{r}", i, N, f, PK2s, SK2,
                completed_indices, mvba_recv, mvba_send, logger
            )
            if decided_proposal is None: decided_proposal = []
        except: decided_proposal = []

        # 4. Delivery & Sorting (论文 Definition 7: Fair Ordering)
        final_batches = []
        for idx in decided_proposal:
            while rbc_results[idx] is None: gevent.sleep(0.01)
            final_batches.append(rbc_results[idx])
            
        # --- 按中位数时间戳排序 ---
        # 论文: transactions with lower assigned ordering indicators will always appear before...
        # Primary Key: Median Timestamp (ts)
        # Secondary Key: Transaction Hash (deterministic tie-breaking)
        final_batches.sort(key=lambda b: (b['ts'], hashlib.sha256(b['tx']).digest()))
        
        # 提取纯交易数据输出
        output_txs = [b['tx'] for b in final_batches]
        
        if output_func: output_func(output_txs)
        logger.info(f"Epoch {r} Delivered {len(output_txs)} batches. Sorted timestamps: {[b['ts'] for b in final_batches]}")
