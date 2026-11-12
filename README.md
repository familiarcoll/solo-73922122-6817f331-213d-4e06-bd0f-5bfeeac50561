# 员工门户 · 密码找回演示

一个可实际启动的密码找回（忘记密码）演示系统：员工通过邮箱收到一次性随机链接，
在 10 分钟内设置新密码，重置成功后旧密码与该账号的全部旧会话同时失效。

技术栈：**FastAPI + SQLite（WAL 模式）+ argon2-cffi**，
附带一个与业务库隔离的**本地演示邮箱**，浏览器即可完成完整找回流程。

## 一、快速启动

### 方式 A：Docker Compose（推荐，两个 Web 进程）

```bash
docker compose up --build
```

启动后浏览器打开：

- 进程 1：<http://localhost:8001/>
- 进程 2：<http://localhost:8002/>

两个进程共享同一个 SQLite 数据卷（`portal-data`），用于演示跨进程并发。
停止并清空数据：`docker compose down -v`。

### 方式 B：本地直接运行（无需 Docker）

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
./run_local.sh
```

打开 <http://127.0.0.1:8001/>。数据落在 `./data/`，重启进程不丢失。

### 预置账号

| 用户名 | 邮箱 | 初始密码 |
|---|---|---|
| `alice` | `alice@example.test` | `Wonderland-1` |
| `bob` | `bob@example.test` | `Secret-2` |

## 二、浏览器演示流程

1. 用 `alice / Wonderland-1` 登录，进入 **我的身份** 查看当前会话与密码版本。
2. 打开 **找回密码**，输入 `alice`（用户名或邮箱均可），提交申请。
3. 打开 **演示邮箱** → `alice@example.test` → 最新邮件，点击邮件中的链接。
4. 在打开的页面设置新密码并提交，看到“密码重置成功”。
5. 回到 **我的身份**：原会话已被撤销，被要求重新登录；旧密码无法登录，新密码可以登录。
6. 再次打开同一封邮件里的链接：提示“已被使用过”，不能重复重置。

## 三、关键安全语义与实现位置

| 需求 | 实现 |
|---|---|
| 随机链接 10 分钟有效 | `app/config.py` 的 `RESET_TTL_SECONDS=600`；`app/service.py` 写入 `expires_at`，每次核验都比较当前时间 |
| 业务库仅存令牌摘要 | `secrets.token_urlsafe(32)` 生成 256bit 令牌；库里只存 SHA-256 摘要（`app/security.py`），原始令牌只出现在邮件里 |
| 签发新链接即作废旧链接 | `request_password_reset` 在同一写事务里把该账号所有未消费链接置为 `superseded` |
| 哈希计算不持写锁 | Argon2 哈希/校验全部在写事务**之外**执行（`prepare_password_reset`/`login`），慢哈希期间仍可申请链接、登录、查身份 |
| 重置三件事一起生效 | `commit_password_reset` 用单个 `BEGIN IMMEDIATE` 事务原子完成：条件消费链接 → 替换密码并 `password_version+1` → 删除该账号全部会话 |
| 同链接并发只成功一次 | 消费用条件 `UPDATE ... WHERE consumed_at IS NULL AND superseded_at IS NULL AND expires_at > now`，检查 `rowcount`，跨进程只有一个赢家 |
| 新链接后旧链接在途重置失败 | 在途重置的最终提交会重新核验链接状态；旧链接已被 `superseded`，条件 UPDATE 命中 0 行，整体回滚 |
| 旧密码核验跨越重置不发会话 | 登录在慢哈希之后、写事务内复查 `password_version`，若期间被重置则放弃会话（`login`） |
| 重置失败不改状态 | 失败路径不产生写操作或事务回滚；令牌只读核验函数绝不改状态 |
| 重启保留数据 | SQLite 文件存于数据卷 / `data/` 目录；无内存态 |
| 哈希延迟可调 | 应用内 **哈希延迟** 页面（`/settings`），设置持久化到业务库，用于把 argon2 计算拉开观察交错操作 |

### 为什么用 WAL + IMMEDIATE

- `PRAGMA journal_mode=WAL`：读不阻塞写、写不阻塞读，多进程可同时读；
- 每个写事务 `BEGIN IMMEDIATE` 立即取得保留锁，配合 `busy_timeout` 排队等待；
- 所有“一次性消费”都靠**条件 UPDATE + rowcount** 在单事务内判定，
  因此两个独立 OS 进程并发时，同一条链接的消费也只能有一个成功。

## 四、并发与交错操作演示

把 **哈希延迟** 调到 5000ms 后：

- 提交一次重置，在等待的 5 秒内，另开窗口申请新链接 / 登录 / 打开“我的身份”，
  这些请求都能立即响应——证明哈希计算不持有数据库写锁。
- 在两个端口（8001、8002）各开一个标签页，用邮件里的同一链接同时提交，
  只有一个页面显示成功，另一个提示链接已被使用/作废。
- 先让一次重置进入哈希等待，再申请一条新链接，则前者提交时会因旧链接被作废而失败，
  密码保持不变。

## 五、测试

```bash
pip install -r requirements.txt
pytest
```

包含 14 个测试（`tests/`），覆盖：完整找回流程、同链接跨线程并发单次成功、
新链接作废旧链接及在途重置失败、登录跨越重置不发会话、慢哈希不阻塞其他操作、
失败不改变状态、过期链接拒绝、库中仅存摘要、账号枚举防护、会话撤销，
以及走完整 HTTP 表单的端到端流程。

另可用两个真实 uvicorn 进程做跨进程验证（见下）。

## 六、目录结构

```
app/
  config.py       # 配置（环境变量可调）
  db.py           # SQLite 连接、WAL、建表、写事务助手
  security.py     # Argon2 哈希/校验、随机令牌、SHA-256 摘要、会话标识
  service.py      # 业务服务层（事务边界、令牌生命周期、会话、演示邮箱）
  main.py         # FastAPI 路由与页面
  templates/      # Jinja2 页面
tests/            # pytest 测试
Dockerfile
docker-compose.yml
run_local.sh      # 无 Docker 本地双进程启动
```
