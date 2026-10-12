"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc CHECKPOINTS.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Gợi ý kiến trúc (không bắt buộc theo đúng, nhưng đủ để làm trong 13') ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document. Cụ thể:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại (KHÔNG dùng
           customer_id mà nó trả về).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được một chỉ thị viết không dấu / lookalike: filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc). Sinh viên NÊN thử filter chuỗi trước, rồi tự phá nó bằng
một bản viết lại không dấu của lure, trước khi chuyển sang cách này.

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None,
           principal_id: str = "support_l1") -> str
        `llm` cung cấp:
            llm.find_injection(text: str) -> InjectedInstruction | None
            llm.summarize(docs: list[dict]) -> str
        `log_dir` là thư mục chứa ledger.jsonl (mặc định: reports/).
        Mỗi tool call truyền principal_id, requested_tool, agent_scopes,
        parent_scopes và expires_at vào PolicyContext; ledger ghi
        on_behalf_of = principal_id, agent_id, run_id, expires_at.
        Principal chỉ được tra trong data/principals.json. Run B không
        được đọc customer cho support_l1; dpo vẫn đọc được khách hợp lệ.
        Trả về câu trả lời cuối cùng hiển thị cho người dùng — hành vi
        quan sát được từ ngoài (CLI) không đổi so với trước khi contain,
        chỉ có sink log và ledger là khác.
"""
from __future__ import annotations

from pathlib import Path
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from uuid import uuid4

from agent import ledger, pii, policy, tools

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def handle(message: str, llm, log_dir: Path | None = None,
           principal_id: str = "support_l1") -> str:
    path = (Path(log_dir) if log_dir is not None else REPORTS_DIR) / "ledger.jsonl"
    agent_id = f"lab24-agent/{uuid4().hex}"
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    run_a, run_b = f"run-a/{uuid4().hex}", f"run-b/{uuid4().hex}"
    parent_scopes = ("search_docs", "read_customer")

    def authorize(tool, args, classification, run_id, scopes, purpose, *, depth=0, egress=False):
        context = policy.PolicyContext(
            data_classification=classification, request_purpose=purpose,
            agent_owner=f"{agent_id}/{run_id}", delegation_depth=depth,
            egress_enabled=egress, principal_id=principal_id,
            requested_tool=tool, agent_scopes=scopes,
            parent_scopes=parent_scopes if depth else (), expires_at=expires_at,
        )
        allow, reason = policy.check(context)
        # Write the decision before executing a tool; logging failure stops execution.
        ledger.append({
            "ts": datetime.now(timezone.utc).isoformat(), "agent_id": agent_id,
            "run_id": run_id, "on_behalf_of": principal_id, "expires_at": expires_at,
            "tool": tool, "args_hash": hashlib.sha256(
                json.dumps(args, sort_keys=True, ensure_ascii=False).encode("utf-8")
            ).hexdigest(), "classification": classification,
            "decision": "allow" if allow else "deny", "reason": reason,
        }, path)
        return allow

    # Run A: untrusted documents only; no private store and no egress capability.
    if not authorize("search_docs", {"query": message}, "internal", run_a,
                     ("search_docs",), "summarize-tickets"):
        return "Không được phép tìm kiếm ticket cho principal này."
    docs = tools.search_docs(message)
    safe_docs = [{"id": d["id"], "text": pii.redact(d["text"])} for d in docs]
    injection = llm.find_injection("\n\n".join(d["text"] for d in safe_docs))
    if injection is not None:
        # The attempted private-data POST is evaluated by PEP, never executed in A.
        allowed = authorize("http_post", {"url": injection.target_url, "intent": "restricted-records"},
                            "restricted", run_a, ("search_docs",), "support-reply", egress=True)
        if allowed:
            raise RuntimeError("Policy unexpectedly authorized egress from Run A")
    ticket_ids = tuple(sorted({int(match.group(1)) for d in safe_docs
                              if (match := re.fullmatch(r"ticket-([0-9]+)(?:b)?\.md", d["id"]))}))
    # Only typed IDs cross the boundary: no text, injected customer ID or URL.
    _run_b(ticket_ids, run_b, authorize)
    return llm.summarize(safe_docs)


def _run_b(ticket_ids: tuple[int, ...], run_id: str, authorize) -> None:
    if not isinstance(ticket_ids, tuple) or any(type(item) is not int or item < 0 for item in ticket_ids):
        raise ValueError("Run B accepts only nonnegative integer ticket IDs")
    if not ticket_ids:
        return
    scopes = ("read_customer",)
    # Gate the trusted lookup before even opening the private JSON store.
    if not authorize("read_customer", {"ticket_ids": ticket_ids, "phase": "trusted-resolution"},
                     "restricted", run_id, scopes, "support-reply", depth=1):
        return
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    related = set(ticket_ids)
    customer_ids = sorted({record["customer_id"] for record in customers
                           if related.intersection(record.get("related_tickets", []))})
    for customer_id in customer_ids:
        if authorize("read_customer", {"customer_id": customer_id}, "restricted", run_id,
                     scopes, "support-reply", depth=1):
            tools.read_customer(customer_id)
