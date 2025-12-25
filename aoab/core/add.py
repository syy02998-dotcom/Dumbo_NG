from gevent import monkey; monkey.patch_all(thread=False)
from collections import defaultdict
from honeybadgerbft.core.reliablebroadcast import encode, decode
import hashlib, pickle

def hash(x):
    return hashlib.sha256(pickle.dumps(x)).digest()

class ADD:
    def __init__(self, sid, pid, N, f, input_val, send, logger=None):
        self.sid = sid
        self.pid = pid
        self.N = N
        self.f = f
        self.input_val = input_val  # 如果是发送者，这里有值；否则为 None
        self.send = send
        self.logger = logger
        
        # ADD 论文参数 (N=3t+1, K=t+1)
        # 这里 K 是纠删码恢复所需的最小分片数
        self.K = f + 1  
        
        # 状态存储
        self.my_segment = None          # 对应论文中的 m_i* (本节点持有的分片)
        self.reconstruct_segments = {}  # 收集到的分片 {sender_id: segment}
        self.output = None              # 最终解码出的 M
        
        # 阶段标志
        self.dispersed = False
        self.reconstructing = False

    def run(self):
        """发送者调用此方法开始分发"""
        if self.input_val is not None and not self.dispersed:
            # 1. 编码 (Erasure Coding)
            # honeybadgerbft 的 encode 返回 N 个分片
            try:
                segments = encode(self.K, self.N, self.input_val)
            except Exception as e:
                if self.logger: self.logger.error(f"ADD Encode failed: {e}")
                return

            # 2. 分发 (Disperse)
            # 发送 (DISPERSE, m_j) 给节点 j
            for j in range(self.N):
                self.send(j, ('DISPERSE', self.sid, segments[j]))
            
            # 自己保存一份
            self.my_segment = segments[self.pid]
            self.dispersed = True
            
            # 既然有了自己的分片，立即进入重构阶段协助他人
            self.start_reconstruction()

    def handle_message(self, sender, msg):
        """处理收到的网络消息"""
        tag, sid, data = msg
        if sid != self.sid: return

        if tag == 'DISPERSE':
            # 收到分片 m_i
            if self.my_segment is None:
                self.my_segment = data
                # 收到分片后，立即广播 RECONSTRUCT 消息（对应论文中的“echo”行为）
                self.start_reconstruction()

        elif tag == 'RECONSTRUCT':
            # 收到其他人的分片用于恢复
            segment = data
            if sender not in self.reconstruct_segments:
                self.reconstruct_segments[sender] = segment
                self.try_decode()

    def start_reconstruction(self):
        """广播自己的分片以供全网恢复"""
        if self.reconstructing: return
        self.reconstructing = True
        # 广播 (RECONSTRUCT, m_i)
        self.send(-1, ('RECONSTRUCT', self.sid, self.my_segment))
        # 尝试解码（可能我们自己就有足够的分片）
        self.try_decode()

    def try_decode(self):
        """尝试使用收集到的分片进行 RS 解码"""
        if self.output is not None: return

        # 只要收集到 K 个分片，就可以尝试解码
        if len(self.reconstruct_segments) >= self.K:
            # zfec decode 需要一个长度为 N 的列表，缺失的位置为 None
            stripes = [self.reconstruct_segments.get(i) for i in range(self.N)]
            try:
                decoded_val = decode(self.K, self.N, stripes)
                self.output = decoded_val
            except Exception as e:
                # 某些情况下（如有恶意分片）解码可能会失败，继续等待更多分片
                pass

    def return_output(self):
        return self.output
