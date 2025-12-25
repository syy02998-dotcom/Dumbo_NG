from gevent import monkey; monkey.patch_all(thread=False)
import logging
import time
import gevent
import gevent.queue
import pickle
import hashlib
import statistics
from aoab.core.add_prbc import add_provablereliablebroadcast
from dumbomvba.core.dumbomvba import dumbomvba

def aoab(sid, i, N, f, PK2s, SK2, input_func, output_func, receive_func, send_func):
    """
    AOAB 协议主逻辑 (Asynchronous Ordered Atomic Broadcast)
    
    论文: "AOAB: Optimal and Fair Ordering of Financial Transactions" (DSN '24)
    
    核心流程:
    1. 排序阶段 (Ordering Phase): Leader 收集 2f+1 个节点的逻辑时钟，计算中位数时间戳。
    2. 广播阶段 (Broadcast Phase): 使用 ADD-PRBC 广播 (交易批次, 中位数时间戳, 证明)。
    3. 协议阶段 (Agreement Phase): 使用 MVBA 对已完成的广播实例达成共识。
    4. 交付阶段 (Delivery Phase): 根据协商出的中位数时间戳对交易进行公平排序并输出。
    """
    logger = logging.getLogger("aoab-node-%d" % i)
    K = 1000  # 运行轮数 (Epochs)
    
    # --- 本地逻辑时钟 (Sequence Number) ---
    # 对应论文 Definition 2 中的 seq_i(t) = (e, s)
    # 这是一个单调递增的计数器，用于生成公平的排序指示器
    local_sequence_number = 0
    
    # --- 消息通道 ---
    # 用于将底层 socket 接收到的混合消息分发给对应的协程
    rbc_inputs = [gevent.queue.Queue() for _ in range(N)]
    mvba_input = gevent.queue.Queue()
    ts_req_queue = gevent.queue.Queue()  # 处理来自其他 Leader 的 TS_REQUEST
    ts_rep_queues = [gevent.queue.Queue() for _ in range(N)] # 处理发给我的 TS_REPLY (当我作为 Leader 时)

    # --- 消息分发器 (Dispatcher) ---
    def dispatcher():
        while True:
            try:
                gevent.sleep(0)
                sender, msg = receive_func()
                tag = msg[0]
                
                # 路由 ADD-PRBC 消息: ('RBC', leader_id, payload)
                if tag == 'RBC':
                    leader_id = msg[1]
                    payload = msg[2]
                    rbc_inputs[leader_id].put((sender, payload))
                
                # 路由 MVBA 消息
                elif tag == 'MVBA':
                    mvba_input.put((sender, msg[1]))
                
                # 路由 排序阶段 (Ordering Phase) 的请求消息
                elif tag == 'TS_REQUEST':
                    # msg = ('TS_REQUEST', batch_hash)
                    ts_req_queue.put((sender, msg[1]))
                
                # 路由 排序阶段 (Ordering Phase) 的响应消息
                elif tag == 'TS_REPLY':
                    # msg = ('TS_REPLY', target_leader, batch_hash, seq, sig)
                    target_leader = msg[1]
                    # 只有当我是目标 Leader 时才处理这些回复
                    if target_leader == i:
                        ts_rep_queues[i].put((sender, msg))
            except Exception as e:
                # logger.error(f"Dispatch error: {e}")
                gevent.sleep(0.01)
    
    # 启动分发器协程
    gevent.spawn(dispatcher)

    # --- 时间戳服务协程 (Timestamp Server) ---
    # 对应论文 Algorithm 1: 响应来自任何 Leader 的 SEQ-REQ
    def timestamp_server():
        nonlocal local_sequence_number
        while True:
            try:
                gevent.sleep(0)
                sender, batch_hash = ts_req_queue.get()
                
                # AOAB 逻辑: 收到请求后，分配当前序列号，并自增
                assigned_seq = local_sequence_number
                local_sequence_number += 1
                
                # 在生产环境中，此处应该使用 ECDSA 私钥对 (epoch, batch_hash, assigned_seq) 进行签名
                # 这样 Leader 就无法伪造这一步。为了演示，此处简化为模拟签名。
                # sig = SK_ecdsa.sign(f"{batch_hash}-{assigned_seq}")
                sig = b"placeholder_sig" 
                
                # 发送回复: ('TS_REPLY', target_leader, batch_hash, seq, sig)
                send_func(sender, ('TS_REPLY', sender, batch_hash, assigned_seq, sig))
            except:
                gevent.sleep(0.01)
    
    # 启动时间戳服务
    gevent.spawn(timestamp_server)

    # --- 主循环 (Epoch Loop) ---
    for r in range(K):
        logger.info(f"--- Starting Epoch {r} ---")
        epoch_start = time.time()

        # 1. 输入阶段 (Input Phase)
        try:
            tx_batch = input_func()
        except:
            tx_batch = b"Empty"
        
        # 计算交易批次的哈希，用于绑定时间戳请求
        batch_hash = hashlib.sha256(tx_batch).digest()

        # 2. 排序与广播阶段 (Ordering & Broadcast Phase)
        # 启动 N 个并发实例，每个节点作为 Leader 负责广播自己的交易
        rbc_results = [None] * N
        
        def run_instance(leader_id):
            # --- Leader 逻辑: 只有当前实例的 Leader 执行 ---
            final_payload = None
            
            if leader_id == i:
                # [Step A]: 排序阶段 (Ordering Phase) - 收集时间戳
                
                # 1. 广播请求 (Broadcast TS_REQUEST)
                for j in range(N):
                    send_func(j, ('TS_REQUEST', batch_hash))
                
                # 2. 收集 2f+1 个回复 (Collect TS_REPLY)
                collected_seqs = []
                collected_proofs = []
                
                while len(collected_seqs) < 2 * f + 1:
                    try:
                        # 从队列获取: ('TS_REPLY', leader_id, b_hash, seq, sig)
                        sender, msg = ts_rep_queues[i].get(timeout=0.1)
                        # 校验哈希匹配，防止跨批次攻击
                        if msg[2] == batch_hash: 
                            collected_seqs.append(msg[3])
                            collected_proofs.append((sender, msg[3], msg[4]))
                    except gevent.queue.Empty:
                        # 超时重传请求 (Retransmission)
                        for j in range(N): send_func(j, ('TS_REQUEST', batch_hash))
                
                # 3. 计算中位数时间戳 (Compute Median Timestamp / Tau)
                median_seq = statistics.median(collected_seqs)
                logger.info(f"Leader {i} assigned Median TS: {median_seq}")
                
                # 构造最终广播包: (交易批次, 中位数时间戳, 证明集)
                final_payload = pickle.dumps({
                    'tx': tx_batch,
                    'ts': median_seq,
                    'proofs': collected_proofs
                })
            else:
                # 如果不是 Leader，输入为 None (等待 ADD 恢复)
                final_payload = None

            # --- 参与 ADD-PRBC 广播 ---
            
            # 辅助函数: 包装消息头
            def rbc_send(target, payload):
                wrapped = ('RBC', leader_id, payload)
                if target == -1:
                    for j in range(N): send_func(j, wrapped)
                else:
                    send_func(target, wrapped)
            
            def rbc_recv(timeout=None):
                try: return rbc_inputs[leader_id].get(timeout=timeout)
                except: raise Exception("Timeout")

            try:
                # 运行 ADD-PRBC
                # 返回值: (数据, 阈值签名证明)
                # 这里的阈值签名证明了 "数据可用性" (Data Availability)
                data_bytes, prbc_proof = add_provablereliablebroadcast(
                    f"{sid}-E{r}-L{leader_id}", 
                    i, N, f, PK2s, SK2,
                    leader_id, final_payload, rbc_recv, rbc_send, logger
                )
                
                # --- 验证阶段 (Validation Phase) ---
                # 除了验证 PRBC 证明，AOAB 还要求验证时间戳排序的合法性
                data_struct = pickle.loads(data_bytes)
                ts = data_struct['ts']
                proofs = data_struct['proofs'] # [(node, seq, sig), ...]
                
                # 1. 验证是否有足够的证明 (2f+1)
                if len(proofs) < 2 * f + 1:
                    logger.warn(f"RBC {leader_id} rejected: insufficient timestamp proofs")
                    return

                # 2. 验证中位数计算是否正确
                # (在严格实现中，这里还需使用 ECDSA 公钥验证 proofs 中每个签名的合法性)
                seqs = [p[1] for p in proofs]
                calculated_median = statistics.median(seqs)
                
                # 允许极小的浮点误差(如果是float)，或者是整数完全相等
                if abs(calculated_median - ts) < 0.001:
                    # 所有检查通过，接受该交易批次
                    rbc_results[leader_id] = data_struct
                else:
                    logger.warn(f"RBC {leader_id} rejected: median mismatch {ts} vs {calculated_median}")

            except Exception as e:
                # logger.error(f"Instance {leader_id} exception: {e}")
                pass

        # 启动 N 个并发广播任务
        tasks = [gevent.spawn(run_instance, nid) for nid in range(N)]

        # 3. 等待阶段 (Wait for Completion)
        # 等待至少 N-f 个广播实例完成
        while sum(1 for res in rbc_results if res is not None) < N - f:
            gevent.sleep(0.01)
        
        # 4. 共识阶段 (Agreement Phase - MVBA)
        # 提议已完成的 RBC 索引列表
        completed_indices = [idx for idx, res in enumerate(rbc_results) if res is not None]
        
        def mvba_send(target, payload):
            if target == -1:
                for j in range(N): send_func(j, ('MVBA', payload))
            else:
                send_func(target, ('MVBA', payload))
        def mvba_recv(): return mvba_input.get()

        try:
            # 运行 Dumbo-MVBA (或 ACS)
            # 输出: 决定的索引列表 (全网一致)
            decided_indices = dumbomvba(
                f"{sid}-MVBA-{r}", i, N, f, PK2s, SK2,
                completed_indices, mvba_recv, mvba_send, logger
            )
            if decided_indices is None: decided_indices = []
        except Exception as e:
            logger.error(f"MVBA failed: {e}")
            decided_indices = []

        logger.info(f"Epoch {r}: Consensus on indices {decided_indices}")

        # 5. 交付与排序阶段 (Delivery & Fair Ordering)
        final_batches = []
        for idx in decided_indices:
            # 如果共识决定了包含索引 idx，但我本地还没跑完该广播，必须等待完成
            # (PRBC 的可靠性保证了只要有一个诚实节点完成，我也一定能完成)
            while rbc_results[idx] is None:
                gevent.sleep(0.01)
            final_batches.append(rbc_results[idx])
        
        # --- 公平排序逻辑 (Fair Ordering) ---
        # 依据 AOAB 论文 Definition 7
        # 主排序键: 协商出的中位数时间戳 (ts)
        # 次排序键: 交易内容的哈希 (用于打破时间戳相同的平局，保证确定性)
        final_batches.sort(key=lambda b: (b['ts'], hashlib.sha256(b['tx']).digest()))
        
        # 提取纯交易数据
        ordered_txs = [b['tx'] for b in final_batches]
        timestamps = [b['ts'] for b in final_batches]
        
        # 输出给上层应用
        if output_func:
            output_func(ordered_txs)
            
        logger.info(f"Epoch {r} Finished. Delivered {len(ordered_txs)} batches. Ordered TS: {timestamps}")
