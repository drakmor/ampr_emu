#!/usr/bin/env python3

import argparse
import datetime
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


LINE_RE = re.compile(r"^\[(\d+)(?:\s+([0-9T:\-.]+Z|unavailable))?\s+th=([^\]]+)\]\s*(.*)$")
KV_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=([^ \t]+)")

VERBOSE_PREFIXES = {
    "apr.reactor.submit",
    "apr.reactor.start",
    "apr.reactor.blocked",
    "apr.reactor.wait",
    "apr.reactor.queueRead",
    "apr.reactor.aio.submit",
    "apr.reactor.aio.complete",
    "apr.reactor.completion",
    "apr.reactor.deferCompletion",
    "apr.reactor.done",
    "apr.reactor.done.noop",
    "apr.reactor.runtime.release",
    "cb.append.op",
    "cb.append.after",
    "cb.append.size",
    "cb.pack.words",
    "exp.apr.cb.append",
    "exp.amm.submit1",
    "amm.leaf.submit.id",
    "apr.fdcache.acquire",
}

FAIL_WORDS = (
    ".fail",
    ".error",
    ".reject",
    " failed",
    " fail ",
    " reject ",
    "partial",
    "dropPending",
    "backpressure",
    "status=mismatch",
)

APR_PRIORITY_LANES = 7


@dataclass
class JobStats:
    first_line: int
    first_seq: int
    priority: Optional[int] = None
    commands: Optional[int] = None
    submit_backlog: Optional[int] = None
    queued_reads: int = 0
    aio_submits: int = 0
    aio_completes: int = 0
    completion_writes: int = 0
    deferred_completions: int = 0
    equeue_attempts: int = 0
    equeue_delivered: int = 0
    equeue_pending: int = 0
    equeue_blocked: int = 0
    done_line: Optional[int] = None
    done_seq: Optional[int] = None
    rc: Optional[int] = None
    error_offset: Optional[int] = None
    fail_reasons: Counter = field(default_factory=Counter)
    last_line: int = 0
    last_seq: int = 0
    wait_enter_line: Optional[int] = None
    wait_enter_seq: Optional[int] = None
    wait_leave_line: Optional[int] = None
    wait_leave_seq: Optional[int] = None
    wait_boost_line: Optional[int] = None
    wait_boost_seq: Optional[int] = None
    wait_boosts: int = 0
    max_waiters: int = 0
    last_stall_line: Optional[int] = None
    last_stall_seq: Optional[int] = None
    last_stall_op: Optional[str] = None
    last_stall_op_index: Optional[int] = None
    last_stall_pending_reads: Optional[int] = None
    last_stall_active_reads: Optional[int] = None
    first_queue_line: Optional[int] = None
    first_queue_seq: Optional[int] = None
    first_aio_submit_line: Optional[int] = None
    first_aio_submit_seq: Optional[int] = None
    map_failures: int = 0


@dataclass
class AioStallSample:
    line: int
    seq: int
    aio_id: int
    job: int
    read_seq: int
    file_id: int
    length: int
    offset: int
    age_ms: int
    state: int
    poll_rc: int
    sample_kind: str


@dataclass
class AioDetailSample:
    line: int
    seq: int
    kind: str
    reason: str
    aio_id: int
    job: int
    read_seq: int
    file_id: int
    path: str
    length: int
    offset: int
    age_ms: int
    state: int
    poll_rc: int
    return_value: int
    bypass: int
    close_after: int


@dataclass
class AioErrorEvent:
    line: int
    seq: int
    event: str
    rc: Optional[int]
    reason: str
    job: int
    read_seq: int
    aio_id: int
    file_id: int
    path: str
    length: int
    offset: int


@dataclass
class AioEfaultDetail:
    line: int
    seq: int
    aio_id: int
    job: int
    read_seq: int
    file_id: int
    path: str
    length: int
    offset: int
    logical_length: int
    logical_offset: int
    age_ms: int
    in_amm_va: int
    overlaps_amm_va: int
    map_active: int
    map_ranges: int
    map_overlaps: int
    map_covered: int
    map_full: int
    first_gap: int
    first_overlap: str
    last_overlap: str


@dataclass
class PendingReadDetail:
    line: int
    seq: int
    reason: str
    priority: int
    job: int
    read_seq: int
    file_id: int
    path: str
    length: int
    offset: int
    queue_reads: int
    pending_reads: int
    active_reads: int
    per_file_active: int = 0
    per_file_limit: int = 0
    cached_active: int = 0
    cached_limit: int = 0
    wait_boosted: int = 0
    idle_boost: int = 0


@dataclass
class AprOrderEvent:
    line: int
    seq: int
    event: str
    reason: str
    job: int
    read_seq: int
    priority: int
    blocker: int
    blocker_source: str
    blocker_op: str
    pending_reads: int
    read_chains: int
    active_reads: int
    active_jobs: int
    incoming: int
    body: str


@dataclass
class BacklogFileDetail:
    line: int
    seq: int
    reason: str
    rank: int
    file_id: int
    path: str
    pending: int
    active: int
    pending_bytes: int
    active_bytes: int
    max_pending_len: int
    max_active_len: int
    pending_cached: int
    pending_small: int
    pending_normal: int
    pending_bulk: int
    active_cached: int
    active_small: int
    active_normal: int
    active_bulk: int
    wait_boosted: int
    pressure: int


@dataclass
class DoneDetail:
    line: int
    seq: int
    done: int
    pending: int
    pending_waits: int
    first: int
    last: int
    newest: int
    newest_rc: int
    newest_waitable: int
    newest_has_equeue: int
    newest_equeue_published: int
    newest_completion_ready: int
    samples: int


@dataclass
class DoneSample:
    line: int
    seq: int
    rank: int
    submit_id: int
    waitable: int
    waiting: int
    newest: int


@dataclass
class WaitPendingSample:
    line: int
    seq: int
    kind: str
    job: int
    pending: int
    incoming: int
    done: int
    waiters: int
    wait_job_pending: int
    wait_job_incoming: int
    wait_job_done: int
    pending_reads: int
    active_reads: int
    pressure: int
    wait_pressure: int
    oldest_aio_age_ms: int
    oldest_aio_job: int
    oldest_aio_match: int
    oldest_aio_seq: int
    oldest_aio_id: int
    oldest_aio_file_id: int
    oldest_aio_len: int
    oldest_aio_off: int


@dataclass
class ReactorStateSample:
    line: int
    seq: int
    reason: str
    active_jobs: int
    pending_reads: int
    read_chains: int
    active_reads: int
    pending: int
    incoming: int
    done: int
    waiters: int
    pressure: int
    wait_pressure: int
    first_job: int
    op_index: int
    commands: int
    op: str
    job_cursor_read: int
    job_speculative_read: int
    job_pending: int
    job_active: int
    job_ready_completions: int
    job_completion_ops: int
    job_completed: int
    job_failed: int
    job_ready_to_publish: int
    job_publishing: int
    job_completion_ready: int
    job_has_equeue: int
    job_equeue_published: int
    job_waitable: int
    first_aio_id: int
    first_aio_age_ms: int
    first_aio_job: int
    first_aio_seq: int
    first_aio_file_id: int
    first_aio_len: int
    first_aio_off: int


@dataclass
class WindowLatencyAggregate:
    windows: int = 0
    count: int = 0
    total_us: int = 0
    max_us: int = 0
    max_window_p95_us: int = 0
    max_window_p99_us: int = 0


@dataclass
class ReactorBatchAggregate:
    windows: int = 0
    window_ms: int = 0
    calls: int = 0
    items: int = 0
    accepted_items: int = 0
    failed_calls: int = 0
    singleton_calls: int = 0
    max_items: int = 0
    capacity: int = 0
    rounds: int = 0
    round_items: int = 0
    full_rounds: int = 0
    priority_calls: Counter = field(default_factory=Counter)
    priority_items: Counter = field(default_factory=Counter)
    apr_priority_items: Counter = field(default_factory=Counter)


@dataclass
class ReactorIoAggregate:
    windows: int = 0
    window_ms: int = 0
    accepted_count: int = 0
    accepted_bytes: int = 0
    le64k: int = 0
    le256k: int = 0
    partial_quantum: int = 0
    full_quantum: int = 0
    over_quantum: int = 0
    quantum_bytes: int = 0
    priority_count: Counter = field(default_factory=Counter)
    priority_bytes: Counter = field(default_factory=Counter)


@dataclass
class FdStatus:
    line: int
    seq: int
    tag: str
    probe_path: str
    probe_limit: int
    probe_opened: int
    probe_rc: int
    probe_errno: int
    free_exact: int
    aio_limit: int
    direct_full_limit: int
    fd_cache_cap: int
    fd_cache_reserve: int


@dataclass
class HeapStatus:
    line: int
    seq: int
    tag: str
    rc: int
    max_system: int
    current_system: int
    max_inuse: int
    current_inuse: int
    committed_free: int
    expandable_free: int
    total_free: int


@dataclass
class AmmSubmitDiag:
    line: int
    seq: int
    thread: str
    mode: str
    buffer: Optional[int]
    current_offset: Optional[int]
    priority: Optional[int]
    result: str
    id_out: str
    body: str


@dataclass
class AprSubmitDiag:
    line: int
    seq: int
    thread: str
    phase: str
    cb: Optional[int]
    priority: Optional[int]
    result: str
    id_value: str
    body: str
    backpressure_count: int = 0
    last_backpressure_line: Optional[int] = None
    last_backpressure_seq: Optional[int] = None
    last_backpressure_job: Optional[int] = None
    last_backpressure_pending: Optional[int] = None
    last_backpressure_incoming: Optional[int] = None
    last_backpressure_active_jobs: Optional[int] = None
    last_backpressure_pending_reads: Optional[int] = None
    last_backpressure_active_reads: Optional[int] = None
    last_backpressure_waiters: Optional[int] = None
    last_backpressure_body: str = ""


@dataclass
class AmmBufferStats:
    buffer: int
    first_line: int
    first_seq: int
    last_line: int
    last_seq: int
    append_count: int = 0
    type_counts: Counter = field(default_factory=Counter)
    max_cmd_off: int = 0
    max_cb_next: int = 0
    last_cmd_off: Optional[int] = None
    last_cb_next: Optional[int] = None
    last_cb_num: Optional[int] = None
    last_type: str = ""
    last_target_va: Optional[int] = None
    last_target_size: Optional[int] = None


@dataclass
class MapEvent:
    line: int
    seq: int
    kind: str
    action: str
    va: Optional[int] = None
    size: Optional[int] = None
    dmem_offset: Optional[int] = None
    type_value: Optional[int] = None
    prot: Optional[int] = None
    direct: Optional[int] = None
    rc: Optional[int] = None
    reason: Optional[str] = None
    job: Optional[int] = None
    body: str = ""


@dataclass
class LogStats:
    path: str
    session_start_line: int = 1
    sessions_seen: int = 1
    all_sessions: bool = False
    parsed_lines: int = 0
    malformed_lines: int = 0
    seq_min: Optional[int] = None
    seq_max: Optional[int] = None
    missing_seq: int = 0
    duplicate_seq: int = 0
    seq_reversals: int = 0
    last_seq: Optional[int] = None
    seq_seen: set = field(default_factory=set)
    timestamped_lines: int = 0
    event_time_start: Optional[str] = None
    event_time_end: Optional[str] = None
    event_time_start_epoch: Optional[float] = None
    event_time_end_epoch: Optional[float] = None
    event_time_reversals: int = 0
    event_time_parse_errors: int = 0
    threads: Counter = field(default_factory=Counter)
    prefixes: Counter = field(default_factory=Counter)
    amm_writer: Counter = field(default_factory=Counter)
    amm_writer_failures: Counter = field(default_factory=Counter)
    suspicious: List[Tuple[int, int, str]] = field(default_factory=list)
    jobs: Dict[int, JobStats] = field(default_factory=dict)
    active_aio: Dict[int, Tuple[int, int, int, int]] = field(default_factory=dict)
    pending_aio_submit_leaves: Dict[Tuple[int, int], Tuple[int, int, int]] = field(default_factory=dict)
    max_aio_active: int = 0
    max_apr_backlog: int = 0
    max_submit_backlog: int = 0
    max_priority_queue: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    wait_enters: int = 0
    wait_leaves: int = 0
    wait_boosts: int = 0
    wait_boost_reserves: int = 0
    wait_boost_direct_reserves: int = 0
    wait_admit_blocks: int = 0
    wait_admit_block_reasons: Counter = field(default_factory=Counter)
    max_wait_admit_block_count: int = 0
    max_wait_admit_block_active_jobs: int = 0
    max_wait_admit_block_pending: int = 0
    max_wait_admit_block_incoming: int = 0
    max_wait_admit_block_pending_reads: int = 0
    max_wait_admit_block_active_reads: int = 0
    max_wait_admit_block_oldest_aio_age_ms: int = 0
    last_wait_admit_block: Optional[Tuple[int, int, str]] = None
    apr_done_evictions: int = 0
    apr_done_evicted_ids: int = 0
    max_done_retained: int = 0
    max_done_pending: int = 0
    max_done_pending_waits: int = 0
    direct_open_enters: int = 0
    direct_open_leaves: int = 0
    direct_open_headroom_defers: int = 0
    acquire_defers: int = 0
    acquire_defer_reasons: Counter = field(default_factory=Counter)
    active_direct_opens: Dict[Tuple[int, int], Tuple[int, int, str, int, int]] = field(default_factory=dict)
    map_cb_ops: Counter = field(default_factory=Counter)
    map_cb_api: Counter = field(default_factory=Counter)
    map_runtime: Counter = field(default_factory=Counter)
    map_runtime_reject_reasons: Counter = field(default_factory=Counter)
    map_amm: Counter = field(default_factory=Counter)
    map_fail_reasons: Counter = field(default_factory=Counter)
    map_total_bytes_by_op: Counter = field(default_factory=Counter)
    map_errors: List[MapEvent] = field(default_factory=list)
    map_tail: List[MapEvent] = field(default_factory=list)
    cb_append_sizes: Counter = field(default_factory=Counter)
    cb_append_size_bytes: Counter = field(default_factory=Counter)
    cb_append_size_mismatches: int = 0
    cb_append_capacity_rejects: int = 0
    cb_append_max_next_offset: int = 0
    equeue_waits: int = 0
    equeue_direct_waits: int = 0
    equeue_direct_by_eq: Counter = field(default_factory=Counter)
    equeue_names: Dict[str, str] = field(default_factory=dict)
    apr_local_equeue: Counter = field(default_factory=Counter)
    apr_local_equeue_counter_lines: int = 0
    apr_local_equeue_wait_lines: int = 0
    apr_local_equeue_grace_lines: int = 0
    apr_local_equeue_wake_skip_metric_lines: int = 0
    apr_local_equeue_timeout_metric_lines: int = 0
    apr_local_equeue_live_wait_intents: int = 0
    apr_local_equeue_wait_intent_peak: int = 0
    apr_local_equeue_grace_configured_us: int = 0
    apr_local_equeue_grace_adaptive: int = 0
    apr_local_equeue_grace_min_us: int = 0
    apr_local_equeue_grace_max_us: int = 0
    autogen_events: int = 0
    reactor_blocked: int = 0
    reactor_backlog_reasons: Counter = field(default_factory=Counter)
    reactor_backlog_slow_cooldown: int = 0
    backlog_file_samples: List[BacklogFileDetail] = field(default_factory=list)
    read_order_defers: int = 0
    read_order_defer_reasons: Counter = field(default_factory=Counter)
    read_order_blocker_sources: Counter = field(default_factory=Counter)
    read_promotions: int = 0
    read_promotion_reasons: Counter = field(default_factory=Counter)
    read_promotion_blocks: int = 0
    read_promotion_block_reasons: Counter = field(default_factory=Counter)
    wait_admit_order_blocks: int = 0
    runwindow_order_expands: int = 0
    apr_order_samples: List[AprOrderEvent] = field(default_factory=list)
    reactor_stalls: int = 0
    read_completion_backpressure_events: int = 0
    read_completion_backpressure_max_span: int = 0
    last_reactor_stall: Optional[Tuple[int, int, str]] = None
    stall_ops: Counter = field(default_factory=Counter)
    stall_max_active_jobs: int = 0
    stall_max_pending_reads: int = 0
    stall_max_read_chains: int = 0
    stall_max_active_reads: int = 0
    stall_max_aio_age_ms: int = 0
    max_reactor_active_jobs: int = 0
    max_reactor_pending_reads: int = 0
    max_reactor_read_chains: int = 0
    max_reactor_active_reads: int = 0
    max_reactor_incoming: int = 0
    stall_aio_samples: Dict[int, AioStallSample] = field(default_factory=dict)
    aio_detail_counts: Counter = field(default_factory=Counter)
    aio_detail_samples: List[AioDetailSample] = field(default_factory=list)
    aio_error_counts: Counter = field(default_factory=Counter)
    aio_error_samples: List[AioErrorEvent] = field(default_factory=list)
    aio_short_reads: int = 0
    aio_efault_details: List[AioEfaultDetail] = field(default_factory=list)
    pending_detail_samples: List[PendingReadDetail] = field(default_factory=list)
    done_detail_samples: List[DoneDetail] = field(default_factory=list)
    done_id_samples: List[DoneSample] = field(default_factory=list)
    wait_pending_samples: List[WaitPendingSample] = field(default_factory=list)
    reactor_state_samples: List[ReactorStateSample] = field(default_factory=list)
    job_queue_first_read_latency: WindowLatencyAggregate = field(
        default_factory=WindowLatencyAggregate
    )
    first_read_queue_first_aio_latency: WindowLatencyAggregate = field(
        default_factory=WindowLatencyAggregate
    )
    job_queue_first_aio_latency: WindowLatencyAggregate = field(
        default_factory=WindowLatencyAggregate
    )
    pending_read_queue_submit_latency: WindowLatencyAggregate = field(
        default_factory=WindowLatencyAggregate
    )
    saw_cursor_direct_read_metrics: bool = False
    reactor_active_loop_gap_latency: WindowLatencyAggregate = field(
        default_factory=WindowLatencyAggregate
    )
    reactor_wake_overshoot_latency: WindowLatencyAggregate = field(
        default_factory=WindowLatencyAggregate
    )
    admission_priority_latency: Dict[int, Dict[str, WindowLatencyAggregate]] = field(
        default_factory=dict
    )
    aio_batch_metrics: ReactorBatchAggregate = field(default_factory=ReactorBatchAggregate)
    aio_io_metrics: ReactorIoAggregate = field(default_factory=ReactorIoAggregate)
    fd_statuses: List[FdStatus] = field(default_factory=list)
    heap_statuses: List[HeapStatus] = field(default_factory=list)
    index_runtime_build_started: Optional[Tuple[int, int, str]] = None
    index_built: Optional[Tuple[int, int, str]] = None
    index_saved: Optional[Tuple[int, int, str]] = None
    index_last_progress: Optional[Tuple[int, int, int, int, int]] = None
    index_last_dir: Optional[Tuple[int, int, str, int, int, int]] = None
    index_last_stat_enter: Optional[Tuple[int, int, str, int, int, int]] = None
    index_last_stat_leave: Optional[Tuple[int, int, str]] = None
    verbose_lines: int = 0
    tail: List[Tuple[int, int, str]] = field(default_factory=list)
    empty_body_lines: List[Tuple[int, int, str]] = field(default_factory=list)
    active_amm_submit_diag: Dict[str, Tuple[int, int, str]] = field(default_factory=dict)
    active_amm_submit_detail: Dict[str, AmmSubmitDiag] = field(default_factory=dict)
    amm_submit_diag_begins: int = 0
    amm_submit_diag_leaves: int = 0
    amm_submit_diag_unmatched_leaves: int = 0
    amm_submit_diag_nested_begins: int = 0
    amm_submit_modes: Counter = field(default_factory=Counter)
    amm_submit_rcs: Counter = field(default_factory=Counter)
    amm_submit_retry_total: int = 0
    amm_buffers: Dict[int, AmmBufferStats] = field(default_factory=dict)
    active_apr_submit_detail: Dict[str, AprSubmitDiag] = field(default_factory=dict)
    apr_submit_enters: int = 0
    apr_submit_leaves: int = 0
    apr_submit_unmatched_leaves: int = 0
    apr_submit_nested_enters: int = 0
    apr_submit_backpressure_events: int = 0
    apr_submit_backpressure_max_pending: int = 0
    apr_submit_backpressure_max_active_jobs: int = 0
    apr_submit_backpressure_max_pending_reads: int = 0
    apr_submit_backpressure_max_active_reads: int = 0
    saw_active_lanes_field: bool = False
    saw_legacy_active_jobs_field: bool = False
    reactor_priority_events: List[Tuple[int, int, int, Optional[int], int, int]] = field(default_factory=list)
    thread_last_event: Dict[str, Tuple[int, int, str]] = field(default_factory=dict)


def parse_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    value = value.rstrip(",")
    # Occupancy counters are commonly logged as current/capacity. Callers of
    # parse_int want the current value; the capacity is reported separately.
    if "/" in value:
        value = value.split("/", 1)[0]
    try:
        return int(value, 0)
    except ValueError:
        return None


def add_window_latency(
    aggregate: WindowLatencyAggregate,
    kv: Dict[str, str],
    stem: str,
) -> None:
    count = parse_int(kv.get(f"{stem}Count")) or 0
    total_us = parse_int(kv.get(f"{stem}TotalUs"))
    if total_us is None:
        total_us = count * (parse_int(kv.get(f"{stem}AvgUs")) or 0)
    aggregate.windows += 1
    aggregate.count += count
    aggregate.total_us += total_us
    aggregate.max_us = max(aggregate.max_us, parse_int(kv.get(f"{stem}MaxUs")) or 0)
    aggregate.max_window_p95_us = max(
        aggregate.max_window_p95_us,
        parse_int(kv.get(f"{stem}P95Us")) or 0,
    )
    aggregate.max_window_p99_us = max(
        aggregate.max_window_p99_us,
        parse_int(kv.get(f"{stem}P99Us")) or 0,
    )


def add_window_latency_alias(
    aggregate: WindowLatencyAggregate,
    kv: Dict[str, str],
    *stems: str,
) -> Optional[str]:
    """Parse the first latency stem present, allowing old and cursor-direct logs."""
    for stem in stems:
        if any(
            key in kv
            for key in (
                f"{stem}Count",
                f"{stem}TotalUs",
                f"{stem}AvgUs",
                f"{stem}MaxUs",
            )
        ):
            add_window_latency(aggregate, kv, stem)
            return stem
    return None


def priority_admission_latency(
    stats: LogStats,
    priority: int,
    stage: str,
) -> WindowLatencyAggregate:
    stages = stats.admission_priority_latency.setdefault(priority, {})
    aggregate = stages.get(stage)
    if aggregate is None:
        aggregate = WindowLatencyAggregate()
        stages[stage] = aggregate
    return aggregate


def parse_active_lanes(kv: Dict[str, str]) -> Optional[int]:
    return parse_int(kv.get("activeLanes") or kv.get("activeJobs"))


def parse_lane_limit(kv: Dict[str, str]) -> Optional[int]:
    return parse_int(kv.get("lanes") or kv.get("runWindow"))


def reactor_active_label(stats: "LogStats") -> str:
    if stats.saw_active_lanes_field:
        return "activeLanes"
    max_active = max(
        stats.max_reactor_active_jobs,
        stats.stall_max_active_jobs,
        stats.apr_submit_backpressure_max_active_jobs,
        stats.max_wait_admit_block_active_jobs,
    )
    if max_active <= APR_PRIORITY_LANES:
        return "activeLanes"
    return "activeJobs"


def parse_addr(value: Optional[str]) -> Optional[int]:
    parsed = parse_int(value)
    if parsed is not None:
        return parsed
    if value is None:
        return None
    value = value.rstrip(",")
    if re.fullmatch(r"[0-9A-Fa-f]+", value):
        try:
            return int(value, 16)
        except ValueError:
            return None
    return None


RC_NAMES = {
    0x80020005: "EIO",
    0x8002000E: "EFAULT",
    0x80020010: "EBUSY",
    0x80020018: "EMFILE",
    0x80020023: "EAGAIN",
}


def rc_u32(rc: Optional[int]) -> Optional[int]:
    if rc is None:
        return None
    return rc & 0xFFFFFFFF


def format_rc(rc: Optional[int]) -> str:
    value = rc_u32(rc)
    if value is None:
        return "n/a"
    name = RC_NAMES.get(value)
    return f"0x{value:x}/{name}" if name else f"0x{value:x}"


def parse_event_time_epoch(value: Optional[str]) -> Optional[float]:
    if not value or value == "unavailable":
        return None
    try:
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def update_event_time(stats: LogStats, value: Optional[str]) -> None:
    if value is None:
        return
    stats.timestamped_lines += 1
    if value == "unavailable":
        return
    if stats.event_time_start is None:
        stats.event_time_start = value
    stats.event_time_end = value

    epoch = parse_event_time_epoch(value)
    if epoch is None:
        stats.event_time_parse_errors += 1
        return
    if stats.event_time_start_epoch is None:
        stats.event_time_start_epoch = epoch
    if stats.event_time_end_epoch is not None and epoch < stats.event_time_end_epoch:
        stats.event_time_reversals += 1
    stats.event_time_end_epoch = epoch


def event_time_duration_seconds(stats: LogStats) -> Optional[float]:
    if stats.event_time_start_epoch is None or stats.event_time_end_epoch is None:
        return None
    return round(max(0.0, stats.event_time_end_epoch - stats.event_time_start_epoch), 6)


def message_prefix(body: str) -> str:
    if not body:
        return "<empty>"
    first = body.split(None, 1)[0]
    return first


def parse_kv(body: str) -> Dict[str, str]:
    return {match.group(1): match.group(2) for match in KV_RE.finditer(body)}


def update_tail(stats: LogStats, line_no: int, seq: int, body: str, limit: int) -> None:
    if limit <= 0:
        return
    stats.tail.append((line_no, seq, body))
    if len(stats.tail) > limit:
        del stats.tail[0 : len(stats.tail) - limit]


def get_job(stats: LogStats, job_id: int, line_no: int, seq: int) -> JobStats:
    job = stats.jobs.get(job_id)
    if job is None:
        job = JobStats(first_line=line_no, first_seq=seq, last_line=line_no, last_seq=seq)
        stats.jobs[job_id] = job
    else:
        job.last_line = line_no
        job.last_seq = seq
    return job


def record_aio_submit(
    stats: LogStats,
    job_id: int,
    read_seq: int,
    aio_id: Optional[int],
    line_no: int,
    seq: int,
    active: Optional[int] = None,
) -> None:
    job = get_job(stats, job_id, line_no, seq)
    job.aio_submits += 1
    if job.first_aio_submit_line is None:
        job.first_aio_submit_line = line_no
        job.first_aio_submit_seq = seq
    if aio_id is not None:
        stats.active_aio[aio_id] = (job_id, read_seq, line_no, seq)
    if active is not None:
        stats.max_aio_active = max(stats.max_aio_active, active)
    else:
        stats.max_aio_active = max(stats.max_aio_active, len(stats.active_aio))


def record_aio_error(
    stats: LogStats,
    line_no: int,
    seq: int,
    event: str,
    kv: Dict[str, str],
    job_id: Optional[int],
    sample_limit: int = 200,
) -> None:
    rc = parse_int(kv.get("rc"))
    reason = kv.get("reason", "")
    file_id = parse_int(kv.get("fileId")) or 0
    path = kv.get("path", "")
    key = (event, rc_u32(rc), reason, file_id, path)
    stats.aio_error_counts[key] += 1
    if len(stats.aio_error_samples) >= sample_limit:
        return
    stats.aio_error_samples.append(
        AioErrorEvent(
            line=line_no,
            seq=seq,
            event=event,
            rc=rc,
            reason=reason,
            job=job_id or 0,
            read_seq=parse_int(kv.get("seq")) or 0,
            aio_id=parse_int(kv.get("aioId")) or 0,
            file_id=file_id,
            path=path,
            length=parse_int(kv.get("len")) or parse_int(kv.get("logicalLen")) or 0,
            offset=parse_int(kv.get("off")) or parse_int(kv.get("logicalOff")) or 0,
        )
    )


def finalize_pending_aio_submit_leaves(stats: LogStats) -> None:
    for (job_id, read_seq), (aio_id, line_no, seq) in list(stats.pending_aio_submit_leaves.items()):
        record_aio_submit(stats, job_id, read_seq, aio_id, line_no, seq)
    stats.pending_aio_submit_leaves.clear()


def add_suspicious(stats: LogStats, line_no: int, seq: int, body: str, limit: int) -> None:
    if len(stats.suspicious) < limit:
        stats.suspicious.append((line_no, seq, body))


def add_map_event(stats: LogStats, event: MapEvent, error: bool = False, limit: int = 100) -> None:
    stats.map_tail.append(event)
    if len(stats.map_tail) > limit:
        del stats.map_tail[0 : len(stats.map_tail) - limit]
    if error and len(stats.map_errors) < limit:
        stats.map_errors.append(event)


def add_stall_aio_sample(
    stats: LogStats,
    line_no: int,
    seq: int,
    kv: Dict[str, str],
    prefix: str,
    sample_kind: str,
) -> None:
    aio_id = parse_int(kv.get(f"{prefix}AioId"))
    if not aio_id:
        return
    job_id = parse_int(kv.get(f"{prefix}AioJob")) or 0
    read_seq = parse_int(kv.get(f"{prefix}AioSeq")) or 0
    file_id = parse_int(kv.get(f"{prefix}AioFileId")) or 0
    length = parse_int(kv.get(f"{prefix}AioLen")) or 0
    offset = parse_int(kv.get(f"{prefix}AioOff")) or 0
    age_ms = parse_int(kv.get(f"{prefix}AioAgeMs")) or 0
    state = parse_int(kv.get(f"{prefix}AioState"))
    poll_rc = parse_int(kv.get(f"{prefix}AioPollRc"))
    if prefix == "oldest" and aio_id == parse_int(kv.get("firstAioId")):
        if state is None:
            state = parse_int(kv.get("firstAioState"))
        if poll_rc is None:
            poll_rc = parse_int(kv.get("firstAioPollRc"))
    state = state or 0
    poll_rc = poll_rc or 0
    stats.stall_max_aio_age_ms = max(stats.stall_max_aio_age_ms, age_ms)
    stats.stall_aio_samples[aio_id] = AioStallSample(
        line=line_no,
        seq=seq,
        aio_id=aio_id,
        job=job_id,
        read_seq=read_seq,
        file_id=file_id,
        length=length,
        offset=offset,
        age_ms=age_ms,
        state=state,
        poll_rc=poll_rc,
        sample_kind=sample_kind,
    )
    if job_id:
        get_job(stats, job_id, line_no, seq)


def add_aio_detail_sample(stats: LogStats, sample: AioDetailSample, limit: int = 500) -> None:
    stats.aio_detail_counts[sample.kind] += 1
    stats.stall_max_aio_age_ms = max(stats.stall_max_aio_age_ms, sample.age_ms)
    stats.aio_detail_samples.append(sample)
    if len(stats.aio_detail_samples) > limit:
        del stats.aio_detail_samples[0 : len(stats.aio_detail_samples) - limit]
    if sample.job:
        get_job(stats, sample.job, sample.line, sample.seq)


def add_aio_efault_detail(stats: LogStats, sample: AioEfaultDetail, limit: int = 200) -> None:
    stats.aio_detail_counts["efault"] += 1
    stats.aio_efault_details.append(sample)
    if len(stats.aio_efault_details) > limit:
        del stats.aio_efault_details[0 : len(stats.aio_efault_details) - limit]
    if sample.job:
        get_job(stats, sample.job, sample.line, sample.seq)


def add_pending_detail_sample(stats: LogStats, sample: PendingReadDetail, limit: int = 200) -> None:
    stats.pending_detail_samples.append(sample)
    if len(stats.pending_detail_samples) > limit:
        del stats.pending_detail_samples[0 : len(stats.pending_detail_samples) - limit]
    stats.max_apr_backlog = max(stats.max_apr_backlog, sample.pending_reads)
    stats.max_aio_active = max(stats.max_aio_active, sample.active_reads)
    stats.max_priority_queue[sample.priority] = max(stats.max_priority_queue[sample.priority], sample.queue_reads)
    if sample.job:
        get_job(stats, sample.job, sample.line, sample.seq)


def add_apr_order_sample(stats: LogStats, sample: AprOrderEvent, limit: int = 200) -> None:
    stats.apr_order_samples.append(sample)
    if len(stats.apr_order_samples) > limit:
        del stats.apr_order_samples[0 : len(stats.apr_order_samples) - limit]
    stats.max_reactor_pending_reads = max(stats.max_reactor_pending_reads, sample.pending_reads)
    stats.max_reactor_read_chains = max(stats.max_reactor_read_chains, sample.read_chains)
    stats.max_reactor_active_reads = max(stats.max_reactor_active_reads, sample.active_reads)
    stats.max_reactor_active_jobs = max(stats.max_reactor_active_jobs, sample.active_jobs)
    stats.max_reactor_incoming = max(stats.max_reactor_incoming, sample.incoming)
    if sample.job:
        get_job(stats, sample.job, sample.line, sample.seq)


def add_backlog_file_sample(stats: LogStats, sample: BacklogFileDetail, limit: int = 400) -> None:
    stats.backlog_file_samples.append(sample)
    if len(stats.backlog_file_samples) > limit:
        del stats.backlog_file_samples[0 : len(stats.backlog_file_samples) - limit]


def add_done_detail_sample(stats: LogStats, sample: DoneDetail, limit: int = 100) -> None:
    stats.done_detail_samples.append(sample)
    if len(stats.done_detail_samples) > limit:
        del stats.done_detail_samples[0 : len(stats.done_detail_samples) - limit]
    stats.max_done_retained = max(stats.max_done_retained, sample.done)
    stats.max_done_pending = max(stats.max_done_pending, sample.pending)
    stats.max_done_pending_waits = max(stats.max_done_pending_waits, sample.pending_waits)


def add_done_id_sample(stats: LogStats, sample: DoneSample, limit: int = 400) -> None:
    stats.done_id_samples.append(sample)
    if len(stats.done_id_samples) > limit:
        del stats.done_id_samples[0 : len(stats.done_id_samples) - limit]


def add_wait_pending_sample(stats: LogStats, sample: WaitPendingSample, limit: int = 400) -> None:
    stats.wait_pending_samples.append(sample)
    if len(stats.wait_pending_samples) > limit:
        del stats.wait_pending_samples[0 : len(stats.wait_pending_samples) - limit]
    stats.max_apr_backlog = max(stats.max_apr_backlog, sample.pending)
    stats.max_aio_active = max(stats.max_aio_active, sample.active_reads)
    stats.stall_max_aio_age_ms = max(stats.stall_max_aio_age_ms, sample.oldest_aio_age_ms)
    stats.max_reactor_pending_reads = max(stats.max_reactor_pending_reads, sample.pending_reads)
    stats.max_reactor_active_reads = max(stats.max_reactor_active_reads, sample.active_reads)
    stats.max_reactor_incoming = max(stats.max_reactor_incoming, sample.incoming)
    if sample.job:
        job = get_job(stats, sample.job, sample.line, sample.seq)
        job.max_waiters = max(job.max_waiters, sample.waiters)


def add_reactor_state_sample(stats: LogStats, sample: ReactorStateSample, limit: int = 200) -> None:
    stats.reactor_state_samples.append(sample)
    if len(stats.reactor_state_samples) > limit:
        del stats.reactor_state_samples[0 : len(stats.reactor_state_samples) - limit]
    stats.max_apr_backlog = max(stats.max_apr_backlog, sample.pending)
    stats.max_aio_active = max(stats.max_aio_active, sample.active_reads)
    stats.stall_max_aio_age_ms = max(stats.stall_max_aio_age_ms, sample.first_aio_age_ms)
    stats.max_reactor_active_jobs = max(stats.max_reactor_active_jobs, sample.active_jobs)
    stats.max_reactor_pending_reads = max(stats.max_reactor_pending_reads, sample.pending_reads)
    stats.max_reactor_active_reads = max(stats.max_reactor_active_reads, sample.active_reads)
    stats.max_reactor_incoming = max(stats.max_reactor_incoming, sample.incoming)
    if sample.first_job:
        get_job(stats, sample.first_job, sample.line, sample.seq)


def add_fd_status(stats: LogStats, status: FdStatus, limit: int = 20) -> None:
    stats.fd_statuses.append(status)
    if len(stats.fd_statuses) > limit:
        del stats.fd_statuses[0 : len(stats.fd_statuses) - limit]


def add_heap_status(stats: LogStats, status: HeapStatus, limit: int = 50) -> None:
    stats.heap_statuses.append(status)
    if len(stats.heap_statuses) > limit:
        del stats.heap_statuses[0 : len(stats.heap_statuses) - limit]


def record_amm_submit_cmd(stats: LogStats, line_no: int, seq: int, kv: Dict[str, str]) -> None:
    buffer = parse_addr(kv.get("buffer"))
    if buffer is None:
        return
    item = stats.amm_buffers.get(buffer)
    if item is None:
        item = AmmBufferStats(buffer=buffer, first_line=line_no, first_seq=seq, last_line=line_no, last_seq=seq)
        stats.amm_buffers[buffer] = item
    else:
        item.last_line = line_no
        item.last_seq = seq
    item.append_count += 1

    cmd_type = kv.get("type") or "<unknown>"
    item.type_counts[cmd_type] += 1
    cmd_off = parse_int(kv.get("cmdOff"))
    cb_next = parse_int(kv.get("cbNext"))
    cb_num = parse_int(kv.get("cbNum"))
    if cmd_off is not None:
        item.last_cmd_off = cmd_off
        item.max_cmd_off = max(item.max_cmd_off, cmd_off)
    if cb_next is not None:
        item.last_cb_next = cb_next
        item.max_cb_next = max(item.max_cb_next, cb_next)
    if cb_num is not None:
        item.last_cb_num = cb_num
    item.last_type = cmd_type
    item.last_target_va = parse_addr(kv.get("targetVa"))
    item.last_target_size = parse_int(kv.get("targetSize"))


def map_event_from_body(
    line_no: int,
    seq: int,
    kind: str,
    action: str,
    body: str,
    kv: Dict[str, str],
    job_id: Optional[int] = None,
) -> MapEvent:
    is_direct = "Direct" in action or kv.get("direct") == "1"
    size_value = parse_int(kv.get("size") or (kv.get("c") if is_direct else kv.get("b")))
    type_value = parse_int(kv.get("type") or (kv.get("u32a") if is_direct else kv.get("u32b")))
    prot_value = parse_int(kv.get("prot") or (kv.get("u32b") if is_direct else kv.get("u32a")))
    return MapEvent(
        line=line_no,
        seq=seq,
        kind=kind,
        action=action,
        va=parse_int(kv.get("va") or kv.get("a")),
        size=size_value,
        dmem_offset=parse_int(kv.get("dmemOffset") or kv.get("off") or (kv.get("b") if is_direct else None)),
        type_value=type_value,
        prot=prot_value,
        direct=parse_int(kv.get("direct")),
        rc=parse_int(kv.get("rc")),
        reason=kv.get("reason"),
        job=job_id,
        body=body,
    )


def analyze_line(stats: LogStats, line_no: int, seq: int, thread: str, body: str, suspicious_limit: int) -> None:
    stats.parsed_lines += 1
    stats.threads[thread] += 1

    prefix = message_prefix(body)
    stats.prefixes[prefix] += 1
    if not body and len(stats.empty_body_lines) < suspicious_limit:
        stats.empty_body_lines.append((line_no, seq, thread))
    if prefix in VERBOSE_PREFIXES or prefix.startswith("[cb-") or prefix.startswith("[apr-cb-"):
        stats.verbose_lines += 1

    if stats.seq_min is None or seq < stats.seq_min:
        stats.seq_min = seq
    if stats.seq_max is None or seq > stats.seq_max:
        stats.seq_max = seq
    if seq in stats.seq_seen:
        stats.duplicate_seq += 1
    else:
        stats.seq_seen.add(seq)
    if stats.last_seq is not None:
        if seq <= stats.last_seq:
            stats.seq_reversals += 1
    stats.last_seq = seq

    kv = parse_kv(body)
    read_chains = parse_int(kv.get("readChains"))
    if "activeLanes" in kv:
        stats.saw_active_lanes_field = True
    if "activeJobs" in kv:
        stats.saw_legacy_active_jobs_field = True
    job_id = parse_int(kv.get("job"))
    if prefix == "apr.reactor.thread" and " priority " in f" {body} ":
        old_prio = parse_int(kv.get("old"))
        configured_prio = parse_int(kv.get("configured"))
        target_prio = parse_int(kv.get("target"))
        new_prio = parse_int(kv.get("new"))
        if old_prio is not None and target_prio is not None and new_prio is not None:
            stats.reactor_priority_events.append(
                (line_no, seq, old_prio, configured_prio, target_prio, new_prio)
            )
    if prefix == "amm.submit.cmd":
        record_amm_submit_cmd(stats, line_no, seq, kv)
    if prefix == "amm.submit.diag" and " begin " in f" {body} ":
        stats.amm_submit_diag_begins += 1
        stats.amm_submit_modes[kv.get("mode", "unknown")] += 1
        if thread in stats.active_amm_submit_diag:
            stats.amm_submit_diag_nested_begins += 1
        stats.active_amm_submit_diag[thread] = (line_no, seq, body)
        stats.active_amm_submit_detail[thread] = AmmSubmitDiag(
            line=line_no,
            seq=seq,
            thread=thread,
            mode=kv.get("mode", "unknown"),
            buffer=parse_addr(kv.get("buffer")),
            current_offset=parse_int(kv.get("currentOffset")),
            priority=parse_int(kv.get("prio")),
            result=kv.get("res", ""),
            id_out=kv.get("idOut", ""),
            body=body,
        )
    elif prefix == "amm.submit.diag" and " leave " in f" {body} ":
        stats.amm_submit_diag_leaves += 1
        if thread not in stats.active_amm_submit_diag:
            stats.amm_submit_diag_unmatched_leaves += 1
        rc = parse_int(kv.get("rc"))
        if rc is not None:
            stats.amm_submit_rcs[format_rc(rc)] += 1
        retries = parse_int(kv.get("retries"))
        if retries is not None:
            stats.amm_submit_retry_total += retries
        stats.active_amm_submit_diag.pop(thread, None)
        stats.active_amm_submit_detail.pop(thread, None)
    if prefix == "lk.apr.submit" and " enter " in f" {body} ":
        stats.apr_submit_enters += 1
        if thread in stats.active_apr_submit_detail:
            stats.apr_submit_nested_enters += 1
        stats.active_apr_submit_detail[thread] = AprSubmitDiag(
            line=line_no,
            seq=seq,
            thread=thread,
            phase=kv.get("phase", ""),
            cb=parse_addr(kv.get("cb")),
            priority=parse_int(kv.get("prio")),
            result=kv.get("res", ""),
            id_value=kv.get("id", ""),
            body=body,
        )
    elif prefix == "lk.apr.submit" and " leave " in f" {body} ":
        stats.apr_submit_leaves += 1
        if thread not in stats.active_apr_submit_detail:
            stats.apr_submit_unmatched_leaves += 1
        stats.active_apr_submit_detail.pop(thread, None)
    elif prefix == "apr.reactor.submit.backpressure":
        stats.apr_submit_backpressure_events += 1
        pending = parse_int(kv.get("pending"))
        active_lanes = parse_active_lanes(kv)
        pending_reads = parse_int(kv.get("pendingReads"))
        read_chains = parse_int(kv.get("readChains"))
        active_reads = parse_int(kv.get("activeReads"))
        if pending is not None:
            stats.apr_submit_backpressure_max_pending = max(
                stats.apr_submit_backpressure_max_pending, pending
            )
        if active_lanes is not None:
            stats.apr_submit_backpressure_max_active_jobs = max(
                stats.apr_submit_backpressure_max_active_jobs, active_lanes
            )
        if pending_reads is not None:
            stats.apr_submit_backpressure_max_pending_reads = max(
                stats.apr_submit_backpressure_max_pending_reads, pending_reads
            )
        if active_reads is not None:
            stats.apr_submit_backpressure_max_active_reads = max(
                stats.apr_submit_backpressure_max_active_reads, active_reads
            )
        detail = stats.active_apr_submit_detail.get(thread)
        if detail is not None:
            detail.backpressure_count += 1
            detail.last_backpressure_line = line_no
            detail.last_backpressure_seq = seq
            detail.last_backpressure_job = parse_int(kv.get("job"))
            detail.last_backpressure_pending = pending
            detail.last_backpressure_incoming = parse_int(kv.get("incoming"))
            detail.last_backpressure_active_jobs = active_lanes
            detail.last_backpressure_pending_reads = pending_reads
            detail.last_backpressure_active_reads = active_reads
            detail.last_backpressure_waiters = parse_int(kv.get("waiters"))
            detail.last_backpressure_body = body
    failure_body = body.replace(" failed=0", "")
    if job_id is not None:
        job = get_job(stats, job_id, line_no, seq)
        reason = kv.get("reason")
        if reason and any(word in failure_body for word in FAIL_WORDS):
            job.fail_reasons[reason] += 1

    if any(word in failure_body for word in FAIL_WORDS):
        add_suspicious(stats, line_no, seq, body, suspicious_limit)

    op_type = kv.get("type")
    if prefix == "cb.append.size" and op_type:
        off = parse_int(kv.get("off"))
        size = parse_int(kv.get("size"))
        next_off = parse_int(kv.get("next"))
        stats.cb_append_sizes[op_type] += 1
        if size is not None:
            stats.cb_append_size_bytes[op_type] += size
        if next_off is not None:
            stats.cb_append_max_next_offset = max(stats.cb_append_max_next_offset, next_off)
        if off is not None and size is not None and next_off is not None and off + size != next_off:
            stats.cb_append_size_mismatches += 1

    if prefix == "cb.append" and kv.get("reason") == "capacity":
        stats.cb_append_capacity_rejects += 1
    if prefix == "cb.append.op" and op_type and ("Map" in op_type or "Unmap" in op_type):
        stats.map_cb_ops[op_type] += 1
        kind = "apr-cb-op" if op_type.startswith("AprMap") else "amm-cb-op"
        event = map_event_from_body(line_no, seq, kind, op_type, body, kv)
        if event.size is not None:
            stats.map_total_bytes_by_op[op_type] += event.size
        add_map_event(stats, event)

    if prefix in ("apr.cb.mapBegin", "apr.cb.mapDirectBegin", "apr.cb.mapEnd"):
        action = prefix.rsplit(".", 1)[-1]
        if " enter " in f" {body} ":
            stats.map_cb_api[f"{action}.enter"] += 1
        elif " leave " in f" {body} ":
            stats.map_cb_api[f"{action}.leave"] += 1
        elif " reject " in f" {body} ":
            stats.map_cb_api[f"{action}.reject"] += 1
            stats.map_runtime_reject_reasons[kv.get("reason", "unknown")] += 1
            add_map_event(
                stats,
                map_event_from_body(line_no, seq, "apr-cb-api", action, body, kv),
                error=True,
            )
        else:
            stats.map_cb_api[action] += 1

    if prefix == "cb.append" and kv.get("reason") and "map" in kv.get("reason", ""):
        stats.map_runtime_reject_reasons[kv.get("reason", "unknown")] += 1
        add_map_event(
            stats,
            map_event_from_body(line_no, seq, "cb-guard", "reject", body, kv),
            error=True,
        )

    if prefix == "apr.map.begin":
        if " reject " in f" {body} ":
            stats.map_runtime["begin.reject"] += 1
            stats.map_runtime_reject_reasons[kv.get("reason", "unknown")] += 1
            add_map_event(
                stats,
                map_event_from_body(line_no, seq, "apr-runtime", "begin.reject", body, kv),
                error=True,
            )
        elif " mapped " in f" {body} ":
            stats.map_runtime["begin.mapped"] += 1
            event = map_event_from_body(line_no, seq, "apr-runtime", "begin.mapped", body, kv)
            add_map_event(stats, event)
        elif " existing " in f" {body} ":
            stats.map_runtime["begin.existing"] += 1
            event = map_event_from_body(line_no, seq, "apr-runtime", "begin.existing", body, kv)
            add_map_event(stats, event, error=(event.rc not in (None, 0)))

    if prefix in ("amm.map_shared", "amm.map_flexible", "amm.unmap_region"):
        action = prefix.split(".", 1)[1]
        if " failed " in f" {body} ":
            stats.map_amm[f"{action}.failed"] += 1
            add_map_event(
                stats,
                map_event_from_body(line_no, seq, "amm-runtime", f"{action}.failed", body, kv),
                error=True,
            )
        elif " retry " in f" {body} ":
            stats.map_amm[f"{action}.retry"] += 1
        elif " mapped " in f" {body} ":
            stats.map_amm[f"{action}.mapped"] += 1
            add_map_event(stats, map_event_from_body(line_no, seq, "amm-runtime", f"{action}.mapped", body, kv))
        else:
            stats.map_amm[action] += 1
            add_map_event(stats, map_event_from_body(line_no, seq, "amm-runtime", action, body, kv))

    if prefix == "apr.reactor.submit" and job_id is not None:
        job = get_job(stats, job_id, line_no, seq)
        job.priority = parse_int(kv.get("prio"))
        job.commands = parse_int(kv.get("commands") or kv.get("ops"))
        job.submit_backlog = parse_int(kv.get("backlog"))
        if job.submit_backlog is not None:
            stats.max_submit_backlog = max(stats.max_submit_backlog, job.submit_backlog)
            stats.max_apr_backlog = max(stats.max_apr_backlog, job.submit_backlog)

    elif prefix == "apr.reactor.queueRead" and job_id is not None:
        job = get_job(stats, job_id, line_no, seq)
        job.queued_reads += 1
        if job.first_queue_line is None:
            job.first_queue_line = line_no
            job.first_queue_seq = seq
        pending = parse_int(kv.get("pending"))
        prio = parse_int(kv.get("prio"))
        if pending is not None:
            stats.max_apr_backlog = max(stats.max_apr_backlog, pending)
        if prio is not None and pending is not None:
            stats.max_priority_queue[prio] = max(stats.max_priority_queue[prio], pending)

    elif prefix == "apr.reactor.aio.order.defer":
        stats.read_order_defers += 1
        reason = kv.get("reason", "unknown")
        blocker_source = kv.get("blockerSource", "unknown")
        stats.read_order_defer_reasons[reason] += 1
        stats.read_order_blocker_sources[blocker_source] += 1
        add_apr_order_sample(
            stats,
            AprOrderEvent(
                line=line_no,
                seq=seq,
                event="aio.order.defer",
                reason=reason,
                job=parse_int(kv.get("job")) or 0,
                read_seq=parse_int(kv.get("seq")) or 0,
                priority=parse_int(kv.get("prio")) or 0,
                blocker=parse_int(kv.get("blocker")) or 0,
                blocker_source=blocker_source,
                blocker_op=kv.get("blockerOp", ""),
                pending_reads=parse_int(kv.get("pendingReads")) or 0,
                read_chains=parse_int(kv.get("readChains")) or 0,
                active_reads=parse_int(kv.get("activeReads")) or 0,
                active_jobs=parse_active_lanes(kv) or 0,
                incoming=parse_int(kv.get("incoming")) or 0,
                body=body,
            ),
        )

    elif prefix == "apr.reactor.read.promote":
        stats.read_promotions += 1
        stats.read_promotion_reasons[kv.get("reason", "unknown")] += 1

    elif prefix == "apr.reactor.read.promote.block":
        stats.read_promotion_blocks += 1
        reason = kv.get("reason", "unknown")
        stats.read_promotion_block_reasons[reason] += 1
        add_apr_order_sample(
            stats,
            AprOrderEvent(
                line=line_no,
                seq=seq,
                event="read.promote.block",
                reason=reason,
                job=parse_int(kv.get("job")) or 0,
                read_seq=parse_int(kv.get("seq")) or 0,
                priority=0,
                blocker=parse_int(kv.get("blockerSeq")) or 0,
                blocker_source="same-job-seq",
                blocker_op="pending-read",
                pending_reads=parse_int(kv.get("pendingReads")) or 0,
                read_chains=parse_int(kv.get("readChains")) or 0,
                active_reads=parse_int(kv.get("activeReads")) or 0,
                active_jobs=0,
                incoming=0,
                body=body,
            ),
        )

    elif prefix == "apr.reactor.aio.submit" and job_id is not None:
        aio_id = parse_int(kv.get("aioId"))
        read_seq = parse_int(kv.get("seq")) or 0
        stats.pending_aio_submit_leaves.pop((job_id, read_seq), None)
        record_aio_submit(stats, job_id, read_seq, aio_id, line_no, seq, parse_int(kv.get("active")))

    elif prefix == "apr.reactor.aio.submit.enter":
        active = parse_int(kv.get("active"))
        if active is not None:
            stats.max_aio_active = max(stats.max_aio_active, active)

    elif prefix == "apr.reactor.aio.submit.leave" and job_id is not None:
        submit_rc = parse_int(kv.get("rc")) or 0
        if submit_rc == 0:
            read_seq = parse_int(kv.get("seq")) or 0
            aio_id = parse_int(kv.get("aioId"))
            if aio_id is not None:
                stats.pending_aio_submit_leaves.pop((job_id, read_seq), None)
                record_aio_submit(stats, job_id, read_seq, aio_id, line_no, seq)
        else:
            record_aio_error(stats, line_no, seq, "submit.leave", kv, job_id)

    elif prefix == "apr.reactor.aio.submit.defer" and job_id is not None:
        record_aio_error(stats, line_no, seq, "submit.defer", kv, job_id)

    elif prefix == "apr.reactor.aio.materialize.submit.fail" and job_id is not None:
        record_aio_error(stats, line_no, seq, "materialize.submit.fail", kv, job_id)

    elif prefix == "apr.reactor.aio.complete.fail" and job_id is not None:
        record_aio_error(stats, line_no, seq, "complete.fail", kv, job_id)
        read_seq = parse_int(kv.get("seq")) or 0
        stats.pending_aio_submit_leaves.pop((job_id, read_seq), None)
        aio_id = parse_int(kv.get("aioId"))
        if aio_id is not None:
            stats.active_aio.pop(aio_id, None)

    elif prefix == "apr.reactor.aio.complete.retry" and job_id is not None:
        record_aio_error(stats, line_no, seq, "complete.retry", kv, job_id)

    elif prefix == "apr.reactor.aio.complete.short" and job_id is not None:
        stats.aio_short_reads += 1

    elif prefix == "apr.reactor.aio.efault.detail":
        sample = AioEfaultDetail(
            line=line_no,
            seq=seq,
            aio_id=parse_int(kv.get("aioId")) or 0,
            job=parse_int(kv.get("job")) or 0,
            read_seq=parse_int(kv.get("seq")) or 0,
            file_id=parse_int(kv.get("fileId")) or 0,
            path=kv.get("path", ""),
            length=parse_int(kv.get("len")) or 0,
            offset=parse_int(kv.get("off")) or 0,
            logical_length=parse_int(kv.get("logicalLen")) or 0,
            logical_offset=parse_int(kv.get("logicalOff")) or 0,
            age_ms=parse_int(kv.get("ageMs")) or 0,
            in_amm_va=parse_int(kv.get("inAmmVa")) or 0,
            overlaps_amm_va=parse_int(kv.get("overlapsAmmVa")) or 0,
            map_active=parse_int(kv.get("mapActive")) or 0,
            map_ranges=parse_int(kv.get("mapRanges")) or 0,
            map_overlaps=parse_int(kv.get("mapOverlaps")) or 0,
            map_covered=parse_int(kv.get("mapCovered")) or 0,
            map_full=parse_int(kv.get("mapFull")) or 0,
            first_gap=parse_int(kv.get("firstGap")) or 0,
            first_overlap=kv.get("firstOverlap", ""),
            last_overlap=kv.get("lastOverlap", ""),
        )
        add_aio_efault_detail(stats, sample)

    elif prefix == "apr.reactor.aio.complete" and job_id is not None:
        job = get_job(stats, job_id, line_no, seq)
        job.aio_completes += 1
        read_seq = parse_int(kv.get("seq")) or 0
        stats.pending_aio_submit_leaves.pop((job_id, read_seq), None)
        aio_id = parse_int(kv.get("aioId"))
        if aio_id is not None:
            stats.active_aio.pop(aio_id, None)
        active = parse_int(kv.get("active"))
        if active is not None:
            stats.max_aio_active = max(stats.max_aio_active, active)

    elif prefix == "apr.reactor.completion" and job_id is not None:
        get_job(stats, job_id, line_no, seq).completion_writes += 1

    elif prefix == "apr.reactor.deferCompletion" and job_id is not None:
        get_job(stats, job_id, line_no, seq).deferred_completions += 1

    elif prefix == "apr.reactor.equeue.pending" and job_id is not None:
        pending = parse_int(kv.get("pending"))
        job = get_job(stats, job_id, line_no, seq)
        job.equeue_pending = max(job.equeue_pending, pending or 1)

    elif prefix == "apr.reactor.equeue.defer" and job_id is not None:
        blocked = parse_int(kv.get("blocked"))
        job = get_job(stats, job_id, line_no, seq)
        job.equeue_blocked = max(job.equeue_blocked, blocked or 1)

    elif prefix == "apr.reactor.done" and job_id is not None:
        job = get_job(stats, job_id, line_no, seq)
        job.done_line = line_no
        job.done_seq = seq
        job.rc = parse_int(kv.get("rc"))
        job.error_offset = parse_int(kv.get("errorOffset"))
        reads = parse_int(kv.get("reads"))
        aio_submits = parse_int(kv.get("aioSubmits"))
        aio_completes = parse_int(kv.get("aioCompletes"))
        completion_writes = parse_int(kv.get("completionWrites"))
        equeue_attempts = parse_int(kv.get("equeueAttempts"))
        equeue_delivered = parse_int(kv.get("equeueDelivered"))
        equeue_pending = parse_int(kv.get("equeuePending"))
        equeue_blocked = parse_int(kv.get("equeueBlocked"))
        if reads is not None:
            job.queued_reads = max(job.queued_reads, reads)
        if aio_submits is not None:
            job.aio_submits = max(job.aio_submits, aio_submits)
        if aio_completes is not None:
            job.aio_completes = max(job.aio_completes, aio_completes)
        if aio_submits is not None and aio_completes is not None and aio_completes >= aio_submits:
            for aio_id, active in list(stats.active_aio.items()):
                if active[0] == job_id:
                    stats.active_aio.pop(aio_id, None)
        if completion_writes is not None:
            job.completion_writes = max(job.completion_writes, completion_writes)
        if equeue_attempts is not None:
            job.equeue_attempts = max(job.equeue_attempts, equeue_attempts)
        if equeue_delivered is not None:
            job.equeue_delivered = max(job.equeue_delivered, equeue_delivered)
        if equeue_pending is not None:
            job.equeue_pending = max(job.equeue_pending, equeue_pending)
        if equeue_blocked is not None:
            job.equeue_blocked = max(job.equeue_blocked, equeue_blocked)

    elif prefix == "apr.reactor.done.noop" and job_id is not None:
        job = get_job(stats, job_id, line_no, seq)
        job.commands = 0
        job.done_line = line_no
        job.done_seq = seq
        job.rc = parse_int(kv.get("rc")) or 0
        job.error_offset = 0

    elif prefix == "apr.reactor.runtime.release" and job_id is not None:
        job = get_job(stats, job_id, line_no, seq)
        job.done_line = line_no
        job.done_seq = seq
        if parse_int(kv.get("failed")) == 0:
            job.rc = 0
            job.error_offset = 0

    elif prefix == "lk.apr.submit" and kv.get("mode") == "empty-noop":
        no_op_id = parse_int(kv.get("idValue"))
        if no_op_id is not None:
            job = get_job(stats, no_op_id, line_no, seq)
            job.commands = 0
            job.done_line = line_no
            job.done_seq = seq
            job.rc = 0
            job.error_offset = 0

    elif prefix == "apr.reactor.fail" and job_id is not None:
        record_aio_error(stats, line_no, seq, "reactor.fail", kv, job_id)
        reason = kv.get("reason", "unknown")
        if "map" in reason:
            stats.map_fail_reasons[reason] += 1
            job = get_job(stats, job_id, line_no, seq)
            job.map_failures += 1
            add_map_event(
                stats,
                map_event_from_body(line_no, seq, "apr-job", "fail", body, kv, job_id),
                error=True,
            )

    elif prefix in ("apr.reactor.wait", "lk.apr.wait"):
        wait_job_id = job_id
        if wait_job_id is None:
            wait_job_id = parse_int(kv.get("submitId"))
        if " enter " in f" {body} ":
            stats.wait_enters += 1
            if wait_job_id is not None:
                job = get_job(stats, wait_job_id, line_no, seq)
                if job.wait_enter_line is None:
                    job.wait_enter_line = line_no
                    job.wait_enter_seq = seq
        if " leave " in f" {body} ":
            stats.wait_leaves += 1
            if wait_job_id is not None:
                job = get_job(stats, wait_job_id, line_no, seq)
                job.wait_leave_line = line_no
                job.wait_leave_seq = seq

    elif prefix in ("apr.reactor.wait.pending", "apr.reactor.wait.snapshot"):
        add_wait_pending_sample(
            stats,
            WaitPendingSample(
                line=line_no,
                seq=seq,
                kind=prefix.rsplit(".", 1)[-1],
                job=parse_int(kv.get("job")) or 0,
                pending=parse_int(kv.get("pending")) or 0,
                incoming=parse_int(kv.get("incoming")) or 0,
                done=parse_int(kv.get("done")) or 0,
                waiters=parse_int(kv.get("waiters")) or 0,
                wait_job_pending=parse_int(kv.get("waitJobPending")) or 0,
                wait_job_incoming=parse_int(kv.get("waitJobIncoming")) or 0,
                wait_job_done=parse_int(kv.get("waitJobDone")) or 0,
                pending_reads=parse_int(kv.get("pendingReads")) or 0,
                active_reads=parse_int(kv.get("activeReads")) or 0,
                pressure=parse_int(kv.get("pressure")) or 0,
                wait_pressure=parse_int(kv.get("waitPressure")) or 0,
                oldest_aio_age_ms=parse_int(kv.get("oldestAioAgeMs")) or 0,
                oldest_aio_job=parse_int(kv.get("oldestAioJob")) or 0,
                oldest_aio_match=parse_int(kv.get("oldestAioMatch")) or 0,
                oldest_aio_seq=parse_int(kv.get("oldestAioSeq")) or 0,
                oldest_aio_id=parse_int(kv.get("oldestAioId")) or 0,
                oldest_aio_file_id=parse_int(kv.get("oldestAioFileId")) or 0,
                oldest_aio_len=parse_int(kv.get("oldestAioLen")) or 0,
                oldest_aio_off=parse_int(kv.get("oldestAioOff")) or 0,
            ),
        )

    elif prefix == "apr.reactor.wait.admit.block":
        stats.wait_admit_blocks += 1
        reason = kv.get("reason", "unknown")
        stats.wait_admit_block_reasons[reason] += 1
        stats.max_wait_admit_block_count = max(
            stats.max_wait_admit_block_count, parse_int(kv.get("count")) or 0
        )
        stats.max_wait_admit_block_active_jobs = max(
            stats.max_wait_admit_block_active_jobs, parse_active_lanes(kv) or 0
        )
        stats.max_wait_admit_block_pending = max(
            stats.max_wait_admit_block_pending, parse_int(kv.get("pending")) or 0
        )
        stats.max_wait_admit_block_incoming = max(
            stats.max_wait_admit_block_incoming, parse_int(kv.get("incoming")) or 0
        )
        stats.max_wait_admit_block_pending_reads = max(
            stats.max_wait_admit_block_pending_reads, parse_int(kv.get("pendingReads")) or 0
        )
        stats.max_wait_admit_block_active_reads = max(
            stats.max_wait_admit_block_active_reads, parse_int(kv.get("activeReads")) or 0
        )
        stats.max_wait_admit_block_oldest_aio_age_ms = max(
            stats.max_wait_admit_block_oldest_aio_age_ms, parse_int(kv.get("oldestAioAgeMs")) or 0
        )
        stats.last_wait_admit_block = (line_no, seq, body)
        stats.max_apr_backlog = max(stats.max_apr_backlog, parse_int(kv.get("pending")) or 0)
        stats.max_reactor_active_jobs = max(stats.max_reactor_active_jobs, parse_active_lanes(kv) or 0)
        stats.max_reactor_pending_reads = max(stats.max_reactor_pending_reads, parse_int(kv.get("pendingReads")) or 0)
        stats.max_reactor_active_reads = max(stats.max_reactor_active_reads, parse_int(kv.get("activeReads")) or 0)
        stats.max_reactor_incoming = max(stats.max_reactor_incoming, parse_int(kv.get("incoming")) or 0)

    elif prefix == "apr.reactor.wait.admit.order.block":
        stats.wait_admit_order_blocks += 1
        stats.read_order_defer_reasons["wait-admit-prior-map"] += 1
        add_apr_order_sample(
            stats,
            AprOrderEvent(
                line=line_no,
                seq=seq,
                event="wait.admit.order.block",
                reason="prior-map",
                job=parse_int(kv.get("job")) or 0,
                read_seq=0,
                priority=parse_int(kv.get("prio")) or 0,
                blocker=parse_int(kv.get("blocker")) or 0,
                blocker_source="incoming-map-op",
                blocker_op=kv.get("blockerOp", ""),
                pending_reads=parse_int(kv.get("pendingReads")) or 0,
                read_chains=parse_int(kv.get("readChains")) or 0,
                active_reads=parse_int(kv.get("activeReads")) or 0,
                active_jobs=parse_active_lanes(kv) or 0,
                incoming=parse_int(kv.get("incoming")) or 0,
                body=body,
            ),
        )

    elif prefix == "apr.reactor.runwindow.order.expand":
        stats.runwindow_order_expands += 1
        stats.max_reactor_active_jobs = max(stats.max_reactor_active_jobs, parse_active_lanes(kv) or 0)
        stats.max_reactor_incoming = max(stats.max_reactor_incoming, parse_int(kv.get("incoming")) or 0)
        stats.max_reactor_pending_reads = max(stats.max_reactor_pending_reads, parse_int(kv.get("pendingReads")) or 0)

    elif prefix == "apr.reactor.counters.admission":
        add_window_latency(stats.job_queue_first_aio_latency, kv, "jobQueueFirstAio")
        stem = add_window_latency_alias(
            stats.pending_read_queue_submit_latency,
            kv,
            "readReadyAio",
            "pendingReadQueueSubmit",
        )
        stats.saw_cursor_direct_read_metrics |= stem == "readReadyAio"

    elif prefix == "apr.reactor.counters.admission.stage":
        add_window_latency(
            stats.job_queue_first_read_latency,
            kv,
            "jobQueueFirstRead",
        )
        stem = add_window_latency_alias(
            stats.first_read_queue_first_aio_latency,
            kv,
            "firstReadReadyFirstAio",
            "firstReadQueueFirstAio",
        )
        stats.saw_cursor_direct_read_metrics |= stem == "firstReadReadyFirstAio"

    elif prefix == "apr.reactor.counters.loop":
        add_window_latency(
            stats.reactor_active_loop_gap_latency,
            kv,
            "activeLoopGap",
        )
        add_window_latency(
            stats.reactor_wake_overshoot_latency,
            kv,
            "wakeOvershoot",
        )

    elif prefix == "apr.reactor.counters.admission.prio.job":
        priority = parse_int(kv.get("aprPrio"))
        if priority is not None and 0 <= priority < APR_PRIORITY_LANES:
            add_window_latency(
                priority_admission_latency(stats, priority, "job_queue_first_read"),
                kv,
                "jobQueueFirstRead",
            )
            stem = add_window_latency_alias(
                priority_admission_latency(stats, priority, "first_read_queue_first_aio"),
                kv,
                "firstReadReadyFirstAio",
                "firstReadQueueFirstAio",
            )
            stats.saw_cursor_direct_read_metrics |= stem == "firstReadReadyFirstAio"
            add_window_latency(
                priority_admission_latency(stats, priority, "job_queue_first_aio"),
                kv,
                "jobQueueFirstAio",
            )

    elif prefix in (
        "apr.reactor.counters.admission.prio.read",
        "apr.reactor.counters.admission.prio.pending",
    ):
        priority = parse_int(kv.get("aprPrio"))
        if priority is not None and 0 <= priority < APR_PRIORITY_LANES:
            stem = add_window_latency_alias(
                priority_admission_latency(
                    stats,
                    priority,
                    "pending_read_queue_submit",
                ),
                kv,
                "readReadyAio",
                "pendingReadQueueSubmit",
            )
            stats.saw_cursor_direct_read_metrics |= stem == "readReadyAio"

    elif prefix == "apr.reactor.counters.batch":
        batch = stats.aio_batch_metrics
        batch.windows += 1
        batch.window_ms += parse_int(kv.get("counterWindowMs")) or 0
        batch.calls += parse_int(kv.get("aioBatchCalls")) or 0
        batch.items += parse_int(kv.get("aioBatchItems")) or 0
        batch.accepted_items += parse_int(kv.get("aioBatchAcceptedItems")) or 0
        batch.failed_calls += parse_int(kv.get("aioBatchFailedCalls")) or 0
        batch.singleton_calls += parse_int(kv.get("aioBatchSingletonCalls")) or 0
        batch.max_items = max(batch.max_items, parse_int(kv.get("aioBatchMaxItems")) or 0)
        batch.capacity += parse_int(kv.get("aioBatchCapacity")) or 0
        batch.rounds += parse_int(kv.get("aioBatchRounds")) or 0
        batch.round_items += parse_int(kv.get("aioBatchRoundItems")) or 0
        batch.full_rounds += parse_int(kv.get("aioBatchFullRounds")) or 0
        for name in ("high", "mid", "low"):
            batch.priority_calls[name] += parse_int(kv.get(f"{name}Calls")) or 0
            batch.priority_items[name] += parse_int(kv.get(f"{name}Items")) or 0

    elif prefix == "apr.reactor.counters.batch.prio":
        for priority in range(APR_PRIORITY_LANES):
            stats.aio_batch_metrics.apr_priority_items[priority] += (
                parse_int(kv.get(f"apr{priority}Items")) or 0
            )

    elif prefix == "apr.reactor.counters.io":
        io = stats.aio_io_metrics
        io.windows += 1
        io.window_ms += parse_int(kv.get("counterWindowMs")) or 0
        io.accepted_count += parse_int(kv.get("acceptedCount")) or 0
        io.accepted_bytes += parse_int(kv.get("acceptedBytes")) or 0
        io.le64k += parse_int(kv.get("le64K")) or 0
        io.le256k += parse_int(kv.get("le256K")) or 0
        io.partial_quantum += parse_int(kv.get("partialQuantum")) or 0
        io.full_quantum += parse_int(kv.get("fullQuantum")) or 0
        io.over_quantum += parse_int(kv.get("overQuantum")) or 0
        io.quantum_bytes = max(io.quantum_bytes, parse_int(kv.get("quantumBytes")) or 0)
        for priority in range(APR_PRIORITY_LANES):
            io.priority_count[priority] += parse_int(kv.get(f"apr{priority}Count")) or 0
            io.priority_bytes[priority] += parse_int(kv.get(f"apr{priority}Bytes")) or 0

    elif prefix == "apr.reactor.state":
        first_job_id = parse_int(kv.get("firstJob")) or 0
        if first_job_id:
            job = get_job(stats, first_job_id, line_no, seq)
            equeue_attempts = parse_int(kv.get("jobEqueueAttempts"))
            equeue_delivered = parse_int(kv.get("jobEqueueDelivered"))
            equeue_pending = parse_int(kv.get("jobEqueuePending"))
            equeue_blocked = parse_int(kv.get("jobEqueueBlocked"))
            if equeue_attempts is not None:
                job.equeue_attempts = max(job.equeue_attempts, equeue_attempts)
            if equeue_delivered is not None:
                job.equeue_delivered = max(job.equeue_delivered, equeue_delivered)
            if equeue_pending is not None:
                job.equeue_pending = max(job.equeue_pending, equeue_pending)
            if equeue_blocked is not None:
                job.equeue_blocked = max(job.equeue_blocked, equeue_blocked)
        add_reactor_state_sample(
            stats,
            ReactorStateSample(
                line=line_no,
                seq=seq,
                reason=kv.get("reason", "unknown"),
                active_jobs=parse_active_lanes(kv) or 0,
                pending_reads=parse_int(kv.get("pendingReads")) or 0,
                read_chains=parse_int(kv.get("readChains")) or 0,
                active_reads=parse_int(kv.get("activeReads")) or 0,
                pending=parse_int(kv.get("pending")) or 0,
                incoming=parse_int(kv.get("incoming")) or 0,
                done=parse_int(kv.get("done")) or 0,
                waiters=parse_int(kv.get("waiters")) or 0,
                pressure=parse_int(kv.get("pressure")) or 0,
                wait_pressure=parse_int(kv.get("waitPressure")) or 0,
                first_job=parse_int(kv.get("firstJob")) or 0,
                op_index=parse_int(kv.get("opIndex")) or 0,
                commands=parse_int(kv.get("commands")) or 0,
                op=kv.get("op", ""),
                job_cursor_read=parse_int(kv.get("jobCursorRead")) or 0,
                job_speculative_read=parse_int(kv.get("jobSpeculativeRead")) or 0,
                job_pending=parse_int(kv.get("jobPending")) or 0,
                job_active=parse_int(kv.get("jobActive")) or 0,
                job_ready_completions=parse_int(kv.get("jobReadyCompletions")) or 0,
                job_completion_ops=parse_int(kv.get("jobCompletionOps")) or 0,
                job_completed=parse_int(kv.get("jobCompleted")) or 0,
                job_failed=parse_int(kv.get("jobFailed")) or 0,
                job_ready_to_publish=parse_int(kv.get("jobReadyToPublish")) or 0,
                job_publishing=parse_int(kv.get("jobPublishing")) or 0,
                job_completion_ready=parse_int(kv.get("jobCompletionReady")) or 0,
                job_has_equeue=parse_int(kv.get("jobHasEqueue")) or 0,
                job_equeue_published=parse_int(kv.get("jobEqueuePublished")) or 0,
                job_waitable=parse_int(kv.get("jobWaitable")) or 0,
                first_aio_id=parse_int(kv.get("firstAioId")) or 0,
                first_aio_age_ms=parse_int(kv.get("firstAioAgeMs")) or 0,
                first_aio_job=parse_int(kv.get("firstAioJob")) or 0,
                first_aio_seq=parse_int(kv.get("firstAioSeq")) or 0,
                first_aio_file_id=parse_int(kv.get("firstAioFileId")) or 0,
                first_aio_len=parse_int(kv.get("firstAioLen")) or 0,
                first_aio_off=parse_int(kv.get("firstAioOff")) or 0,
            ),
        )

    elif prefix == "apr.reactor.wait.boost" and job_id is not None:
        stats.wait_boosts += 1
        job = get_job(stats, job_id, line_no, seq)
        job.wait_boosts += 1
        if job.wait_boost_line is None:
            job.wait_boost_line = line_no
            job.wait_boost_seq = seq
        waiters = parse_int(kv.get("waiters"))
        if waiters is not None:
            job.max_waiters = max(job.max_waiters, waiters)

    elif prefix == "apr.reactor.waitBoost.reserve":
        stats.wait_boost_reserves += 1

    elif prefix == "apr.reactor.waitBoost.directReserve":
        stats.wait_boost_direct_reserves += 1

    elif prefix == "apr.reactor.done.evict":
        stats.apr_done_evictions += 1
        stats.apr_done_evicted_ids += parse_int(kv.get("count")) or 0

    elif prefix == "apr.reactor.done.growth" and job_id is not None:
        job = get_job(stats, job_id, line_no, seq)
        job.done_line = line_no
        job.done_seq = seq
        job.rc = parse_int(kv.get("rc"))

    elif prefix == "apr.reactor.done.detail":
        add_done_detail_sample(
            stats,
            DoneDetail(
                line=line_no,
                seq=seq,
                done=parse_int(kv.get("done")) or 0,
                pending=parse_int(kv.get("pending")) or 0,
                pending_waits=parse_int(kv.get("pendingWaits")) or 0,
                first=parse_int(kv.get("first")) or 0,
                last=parse_int(kv.get("last")) or 0,
                newest=parse_int(kv.get("newest")) or 0,
                newest_rc=parse_int(kv.get("newestRc")) or 0,
                newest_waitable=parse_int(kv.get("newestWaitable")) or 0,
                newest_has_equeue=parse_int(kv.get("newestHasEqueue")) or 0,
                newest_equeue_published=parse_int(kv.get("newestEqueuePublished")) or 0,
                newest_completion_ready=parse_int(kv.get("newestCompletionReady")) or 0,
                samples=parse_int(kv.get("samples")) or 0,
            ),
        )

    elif prefix == "apr.reactor.done.sample":
        add_done_id_sample(
            stats,
            DoneSample(
                line=line_no,
                seq=seq,
                rank=parse_int(kv.get("rank")) or 0,
                submit_id=parse_int(kv.get("submitId")) or 0,
                waitable=parse_int(kv.get("waitable")) or 0,
                waiting=parse_int(kv.get("waiting")) or 0,
                newest=parse_int(kv.get("newest")) or 0,
            ),
        )

    elif prefix == "apr.reactor.acquire.direct.enter":
        stats.direct_open_enters += 1
        file_id = parse_int(kv.get("fileId")) or 0
        if job_id is not None:
            stats.active_direct_opens[(job_id, file_id)] = (
                line_no,
                seq,
                kv.get("path", ""),
                parse_int(kv.get("len")) or 0,
                parse_int(kv.get("off")) or 0,
            )

    elif prefix == "apr.reactor.acquire.direct.leave":
        stats.direct_open_leaves += 1
        file_id = parse_int(kv.get("fileId")) or 0
        if job_id is not None:
            stats.active_direct_opens.pop((job_id, file_id), None)

    elif prefix == "apr.reactor.acquire.direct.no-headroom":
        stats.direct_open_headroom_defers += 1

    elif prefix == "apr.reactor.acquire.defer":
        stats.acquire_defers += 1
        reason = kv.get("reason")
        if reason:
            stats.acquire_defer_reasons[reason] += 1

    elif prefix in (
        "apr.reactor.aio.backlogActive",
        "apr.reactor.aio.slowActive",
        "apr.reactor.aio.slowComplete",
    ):
        kind = prefix.rsplit(".", 1)[-1]
        sample = AioDetailSample(
            line=line_no,
            seq=seq,
            kind=kind,
            reason=kv.get("reason", "unknown"),
            aio_id=parse_int(kv.get("aioId")) or 0,
            job=parse_int(kv.get("job")) or 0,
            read_seq=parse_int(kv.get("seq")) or 0,
            file_id=parse_int(kv.get("fileId")) or 0,
            path=kv.get("path", ""),
            length=parse_int(kv.get("len")) or 0,
            offset=parse_int(kv.get("off")) or 0,
            age_ms=parse_int(kv.get("ageMs")) or 0,
            state=parse_int(kv.get("state")) or 0,
            poll_rc=parse_int(kv.get("pollRc")) or 0,
            return_value=parse_int(kv.get("return")) or 0,
            bypass=parse_int(kv.get("bypass")) or 0,
            close_after=parse_int(kv.get("closeAfter")) or 0,
        )
        add_aio_detail_sample(stats, sample)

    elif prefix == "apr.reactor.pending.detail":
        sample = PendingReadDetail(
            line=line_no,
            seq=seq,
            reason=kv.get("reason", "unknown"),
            priority=parse_int(kv.get("prio")) or 0,
            job=parse_int(kv.get("job")) or 0,
            read_seq=parse_int(kv.get("seq")) or 0,
            file_id=parse_int(kv.get("fileId")) or 0,
            path=kv.get("path", ""),
            length=parse_int(kv.get("len")) or 0,
            offset=parse_int(kv.get("off")) or 0,
            queue_reads=parse_int(kv.get("queueReads")) or 0,
            pending_reads=parse_int(kv.get("pendingReads")) or 0,
            active_reads=parse_int(kv.get("activeReads")) or 0,
            per_file_active=parse_int(kv.get("perFileActive")) or 0,
            per_file_limit=parse_int(kv.get("perFileLimit")) or 0,
            cached_active=parse_int(kv.get("cachedActive")) or 0,
            cached_limit=parse_int(kv.get("cachedLimit")) or 0,
            wait_boosted=parse_int(kv.get("waitBoosted")) or 0,
            idle_boost=parse_int(kv.get("idleBoost")) or 0,
        )
        add_pending_detail_sample(stats, sample)

    elif prefix == "apr.reactor.backlog.file":
        sample = BacklogFileDetail(
            line=line_no,
            seq=seq,
            reason=kv.get("reason", "unknown"),
            rank=parse_int(kv.get("rank")) or 0,
            file_id=parse_int(kv.get("fileId")) or 0,
            path=kv.get("path", ""),
            pending=parse_int(kv.get("pending")) or 0,
            active=parse_int(kv.get("active")) or 0,
            pending_bytes=parse_int(kv.get("pendingBytes")) or 0,
            active_bytes=parse_int(kv.get("activeBytes")) or 0,
            max_pending_len=parse_int(kv.get("maxPendingLen")) or 0,
            max_active_len=parse_int(kv.get("maxActiveLen")) or 0,
            pending_cached=parse_int(kv.get("pendingCached")) or 0,
            pending_small=parse_int(kv.get("pendingSmall")) or 0,
            pending_normal=parse_int(kv.get("pendingNormal")) or 0,
            pending_bulk=parse_int(kv.get("pendingBulk")) or 0,
            active_cached=parse_int(kv.get("activeCached")) or 0,
            active_small=parse_int(kv.get("activeSmall")) or 0,
            active_normal=parse_int(kv.get("activeNormal")) or 0,
            active_bulk=parse_int(kv.get("activeBulk")) or 0,
            wait_boosted=parse_int(kv.get("waitBoosted")) or 0,
            pressure=parse_int(kv.get("pressure")) or 0,
        )
        add_backlog_file_sample(stats, sample)

    elif prefix == "fd.status":
        add_fd_status(
            stats,
            FdStatus(
                line=line_no,
                seq=seq,
                tag=kv.get("tag", ""),
                probe_path=kv.get("probePath", ""),
                probe_limit=parse_int(kv.get("probeLimit")) or 0,
                probe_opened=parse_int(kv.get("probeOpened")) or 0,
                probe_rc=parse_int(kv.get("probeRc")) or 0,
                probe_errno=parse_int(kv.get("probeErrno")) or 0,
                free_exact=parse_int(kv.get("freeExact")) or 0,
                aio_limit=parse_int(kv.get("aioLimit")) or 0,
                direct_full_limit=parse_int(kv.get("directFullLimit")) or 0,
                fd_cache_cap=parse_int(kv.get("fdCacheCap")) or 0,
                fd_cache_reserve=parse_int(kv.get("fdCacheReserve")) or 0,
            ),
        )

    elif prefix == "heap.status":
        add_heap_status(
            stats,
            HeapStatus(
                line=line_no,
                seq=seq,
                tag=kv.get("tag", ""),
                rc=parse_int(kv.get("rc")) or 0,
                max_system=parse_int(kv.get("maxSystem")) or 0,
                current_system=parse_int(kv.get("currentSystem")) or 0,
                max_inuse=parse_int(kv.get("maxInuse")) or 0,
                current_inuse=parse_int(kv.get("currentInuse")) or 0,
                committed_free=parse_int(kv.get("committedFree")) or 0,
                expandable_free=parse_int(kv.get("expandableFree")) or 0,
                total_free=parse_int(kv.get("totalFree")) or 0,
            ),
        )

    if prefix == "apr.equeue.counters":
        stats.apr_local_equeue_counter_lines += 1
        if "wakeNoWaiterSkips" in kv:
            stats.apr_local_equeue_wake_skip_metric_lines += 1
        for name in (
            "publishAttempts",
            "published",
            "backpressure",
            "fallbackHooks",
            "fallbackQueue",
            "fallbackRegistration",
            "fallbackWake",
            "wakeTriggers",
            "wakeElisions",
            "wakeNoWaiterSkips",
            "wakeFailures",
        ):
            stats.apr_local_equeue[name] += parse_int(kv.get(name)) or 0
    elif prefix == "apr.equeue.wait.counters":
        stats.apr_local_equeue_wait_lines += 1
        if "nativeWaitZero" in kv:
            stats.apr_local_equeue_timeout_metric_lines += 1
        for name in (
            "trackedWaits",
            "directWaits",
            "nativeWaits",
            "nativeWaitZero",
            "nativeWaitFinite",
            "nativeWaitInfinite",
            "nativeEvents",
            "hiddenFiltered",
            "staleWakes",
            "syntheticEvents",
            "syntheticDirectReturns",
        ):
            stats.apr_local_equeue[name] += parse_int(kv.get(name)) or 0
        live_wait_intents = parse_int(kv.get("liveWaitIntents"))
        wait_intent_peak = parse_int(kv.get("waitIntentPeak"))
        if live_wait_intents is not None:
            stats.apr_local_equeue_live_wait_intents = live_wait_intents
        if wait_intent_peak is not None:
            stats.apr_local_equeue_wait_intent_peak = max(
                stats.apr_local_equeue_wait_intent_peak, wait_intent_peak
            )
    elif prefix == "apr.equeue.grace.counters":
        stats.apr_local_equeue_grace_lines += 1
        for name in (
            "attempts",
            "hits",
            "misses",
            "events",
            "spinIterations",
            "elapsedUs",
            "increases",
            "decreases",
            "cooldowns",
            "cooldownEvents",
            "rearms",
        ):
            stats.apr_local_equeue[name] += parse_int(kv.get(name)) or 0
        configured_us = parse_int(kv.get("configuredUs"))
        if configured_us is not None:
            stats.apr_local_equeue_grace_configured_us = configured_us
        for name, attribute in (
            ("adaptive", "apr_local_equeue_grace_adaptive"),
            ("minUs", "apr_local_equeue_grace_min_us"),
            ("maxUs", "apr_local_equeue_grace_max_us"),
        ):
            value = parse_int(kv.get(name))
            if value is not None:
                setattr(stats, attribute, value)

    if "eq.wait" in prefix or prefix.startswith("eq.wait"):
        stats.equeue_waits += 1
    if prefix == "eq.create.overlay":
        eq = kv.get("eq")
        name = kv.get("name")
        if eq and name:
            stats.equeue_names[eq] = name
    if prefix == "eq.wait.overlay" and " direct " in f" {body} ":
        stats.equeue_direct_waits += 1
        eq = kv.get("eq")
        if eq:
            stats.equeue_direct_by_eq[eq] += 1
    if prefix == "apr.reactor.autogen_equeue":
        stats.autogen_events += 1
    if prefix == "apr.reactor.blocked":
        stats.reactor_blocked += 1
    if prefix == "apr.reactor.backlog":
        reason = kv.get("reason", "unknown")
        stats.reactor_backlog_reasons[reason] += 1
        if parse_int(kv.get("slowCooldown")):
            stats.reactor_backlog_slow_cooldown += 1
        pending_reads = parse_int(kv.get("pendingReads"))
        active_reads = parse_int(kv.get("activeReads"))
        if pending_reads is not None:
            stats.max_apr_backlog = max(stats.max_apr_backlog, pending_reads)
        if active_reads is not None:
            stats.max_aio_active = max(stats.max_aio_active, active_reads)
    if prefix == "apr.reactor.read.completion.backpressure":
        stats.read_completion_backpressure_events += 1
        latest = parse_int(kv.get("latest"))
        completed = parse_int(kv.get("completed"))
        if latest is not None and completed is not None and latest >= completed:
            stats.read_completion_backpressure_max_span = max(
                stats.read_completion_backpressure_max_span,
                latest - completed,
            )
    if prefix == "apr.reactor.stall":
        stats.reactor_stalls += 1
        stats.last_reactor_stall = (line_no, seq, body)
        active_jobs = parse_active_lanes(kv)
        pending_reads = parse_int(kv.get("pendingReads"))
        active_reads = parse_int(kv.get("activeReads"))
        if active_jobs is not None:
            stats.stall_max_active_jobs = max(stats.stall_max_active_jobs, active_jobs)
        if pending_reads is not None:
            stats.stall_max_pending_reads = max(stats.stall_max_pending_reads, pending_reads)
            stats.max_apr_backlog = max(stats.max_apr_backlog, pending_reads)
        if read_chains is not None:
            stats.stall_max_read_chains = max(stats.stall_max_read_chains, read_chains)
            stats.max_reactor_read_chains = max(stats.max_reactor_read_chains, read_chains)
        if active_reads is not None:
            stats.stall_max_active_reads = max(stats.stall_max_active_reads, active_reads)
            stats.max_aio_active = max(stats.max_aio_active, active_reads)
        op = kv.get("op")
        if op:
            stats.stall_ops[op] += 1
        first_job = parse_int(kv.get("firstJob"))
        if first_job:
            job = get_job(stats, first_job, line_no, seq)
            job.commands = parse_int(kv.get("commands") or kv.get("ops")) or job.commands
            job.last_stall_line = line_no
            job.last_stall_seq = seq
            job.last_stall_op = op
            job.last_stall_op_index = parse_int(kv.get("opIndex"))
            job.last_stall_pending_reads = parse_int(kv.get("jobPending"))
            job.last_stall_active_reads = parse_int(kv.get("jobActive"))
        add_stall_aio_sample(stats, line_no, seq, kv, "first", "first")
        add_stall_aio_sample(stats, line_no, seq, kv, "oldest", "oldest")

    if read_chains is not None:
        stats.max_reactor_read_chains = max(stats.max_reactor_read_chains, read_chains)

    if prefix == "apr.index":
        if " building runtime index" in body:
            stats.index_runtime_build_started = (line_no, seq, body)
        elif body.startswith("apr.index built "):
            stats.index_built = (line_no, seq, body)
        elif body.startswith("apr.index saved "):
            stats.index_saved = (line_no, seq, body)
        elif body.startswith("apr.index scan.progress"):
            dirs = parse_int(kv.get("dirs"))
            files = parse_int(kv.get("files"))
            pending = parse_int(kv.get("pendingDirs"))
            if dirs is not None and files is not None and pending is not None:
                stats.index_last_progress = (line_no, seq, dirs, files, pending)
        elif body.startswith("apr.index scan.dir enter"):
            dirs = parse_int(kv.get("dirs"))
            files = parse_int(kv.get("files"))
            pending = parse_int(kv.get("pendingDirs"))
            path = kv.get("path")
            if path and dirs is not None and files is not None and pending is not None:
                stats.index_last_dir = (line_no, seq, path, dirs, files, pending)
        elif body.startswith("apr.index scan.stat enter"):
            dirs = parse_int(kv.get("dirs"))
            files = parse_int(kv.get("files"))
            pending = parse_int(kv.get("pendingDirs"))
            path = kv.get("path")
            if path and dirs is not None and files is not None and pending is not None:
                stats.index_last_stat_enter = (line_no, seq, path, dirs, files, pending)
        elif body.startswith("apr.index scan.stat leave"):
            path = kv.get("path")
            if path:
                stats.index_last_stat_leave = (line_no, seq, path)

    if prefix.startswith("amm.writer."):
        writer = prefix.split(".", 2)[2]
        stats.amm_writer[writer] += 1
        rc = parse_int(kv.get("rc"))
        if rc not in (None, 0):
            stats.amm_writer_failures[f"{writer}:0x{rc:x}"] += 1

    stats.thread_last_event[thread] = (line_no, seq, body)


def find_latest_session_start(path: Path) -> Tuple[int, int]:
    latest_start = 1
    sessions = 0
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, raw in enumerate(f, 1):
            match = LINE_RE.match(raw.rstrip("\r\n"))
            if match and int(match.group(1)) == 1:
                latest_start = line_no
                sessions += 1
    return latest_start, max(sessions, 1)


def analyze_log(path: Path, tail_limit: int, suspicious_limit: int, latest_session: bool = True) -> LogStats:
    session_start, sessions_seen = find_latest_session_start(path) if latest_session else (1, 1)
    stats = LogStats(
        path=str(path),
        session_start_line=session_start,
        sessions_seen=sessions_seen,
        all_sessions=not latest_session,
    )
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, raw in enumerate(f, 1):
            if line_no < session_start:
                continue
            line = raw.rstrip("\r\n")
            match = LINE_RE.match(line)
            if not match:
                stats.malformed_lines += 1
                continue
            seq = int(match.group(1))
            event_time = match.group(2)
            thread = match.group(3)
            body = match.group(4)
            update_event_time(stats, event_time)
            update_tail(stats, line_no, seq, body, tail_limit)
            analyze_line(stats, line_no, seq, thread, body, suspicious_limit)
    if stats.seq_min is not None and stats.seq_max is not None:
        stats.missing_seq = stats.seq_max - stats.seq_min + 1 - len(stats.seq_seen)
    finalize_pending_aio_submit_leaves(stats)
    return stats


def unfinished_jobs(stats: LogStats) -> List[Tuple[int, JobStats]]:
    return sorted(
        (
            (job_id, job)
            for job_id, job in observed_jobs(stats)
            if job.done_line is None
        ),
        key=lambda item: item[1].last_seq,
    )


def job_has_runtime_signal(job: JobStats) -> bool:
    return (
        job.priority is not None
        or job.commands is not None
        or job.queued_reads != 0
        or job.aio_submits != 0
        or job.aio_completes != 0
        or job.completion_writes != 0
        or job.deferred_completions != 0
        or job.equeue_attempts != 0
        or job.equeue_delivered != 0
        or job.equeue_pending != 0
        or job.equeue_blocked != 0
        or job.done_line is not None
        or job.rc is not None
        or bool(job.fail_reasons)
        or job.wait_enter_line is not None
        or job.wait_leave_line is not None
        or job.wait_boost_line is not None
        or job.first_queue_line is not None
        or job.first_aio_submit_line is not None
        or job.map_failures != 0
    )


def observed_jobs(stats: LogStats) -> List[Tuple[int, JobStats]]:
    return [(job_id, job) for job_id, job in stats.jobs.items() if job_has_runtime_signal(job)]


def failed_jobs(stats: LogStats) -> List[Tuple[int, JobStats]]:
    return sorted(
        (
            (job_id, job)
            for job_id, job in observed_jobs(stats)
            if job.rc not in (None, 0) or job.fail_reasons
        ),
        key=lambda item: item[1].last_seq,
    )


def waited_jobs(stats: LogStats) -> List[Tuple[int, JobStats]]:
    return sorted(
        ((job_id, job) for job_id, job in stats.jobs.items() if job.wait_enter_line is not None),
        key=lambda item: item[1].wait_enter_seq or 0,
    )


def wait_to_submit_delay(job: JobStats) -> Optional[int]:
    if job.wait_enter_seq is None or job.first_aio_submit_seq is None:
        return None
    if job.first_aio_submit_seq < job.wait_enter_seq:
        return 0
    return job.first_aio_submit_seq - job.wait_enter_seq


def wait_to_queue_delay(job: JobStats) -> Optional[int]:
    if job.wait_enter_seq is None or job.first_queue_seq is None:
        return None
    if job.first_queue_seq < job.wait_enter_seq:
        return 0
    return job.first_queue_seq - job.wait_enter_seq


def queue_to_submit_delay(job: JobStats) -> Optional[int]:
    if job.first_queue_seq is None or job.first_aio_submit_seq is None:
        return None
    if job.first_aio_submit_seq < job.first_queue_seq:
        return 0
    return job.first_aio_submit_seq - job.first_queue_seq


def waited_submit_delay_jobs(stats: LogStats) -> List[Tuple[int, JobStats, int]]:
    delayed: List[Tuple[int, JobStats, int]] = []
    for job_id, job in waited_jobs(stats):
        delay = wait_to_submit_delay(job)
        if delay is not None:
            delayed.append((job_id, job, delay))
    return sorted(delayed, key=lambda item: item[2], reverse=True)


def format_job(job_id: int, job: JobStats) -> str:
    rc = "n/a" if job.rc is None else f"0x{job.rc:x}"
    done = "no" if job.done_line is None else f"line {job.done_line}, seq {job.done_seq}"
    stall = ""
    if job.last_stall_line is not None:
        stall = (
            f" stallOp={job.last_stall_op}@{job.last_stall_op_index} "
            f"stallPending={job.last_stall_pending_reads} stallActive={job.last_stall_active_reads}"
        )
    return (
        f"job=0x{job_id:x} prio={job.priority} commands={job.commands} rc={rc} "
        f"reads={job.queued_reads} aio={job.aio_submits}/{job.aio_completes} "
        f"writes={job.completion_writes} deferred={job.deferred_completions} "
        f"equeue={job.equeue_attempts}/{job.equeue_delivered}/{job.equeue_pending}/{job.equeue_blocked} "
        f"first=line {job.first_line},seq {job.first_seq} last=line {job.last_line},seq {job.last_seq}{stall} done={done}"
    )


def format_waited_job(job_id: int, job: JobStats) -> str:
    wait_to_queue = wait_to_queue_delay(job)
    queue_to_submit = queue_to_submit_delay(job)
    wait_to_submit = wait_to_submit_delay(job)
    wait_to_queue_text = "n/a" if wait_to_queue is None else str(wait_to_queue)
    queue_to_submit_text = "n/a" if queue_to_submit is None else str(queue_to_submit)
    wait_to_submit_text = "n/a" if wait_to_submit is None else str(wait_to_submit)
    return (
        f"job=0x{job_id:x} prio={job.priority} waitSeq={job.wait_enter_seq} "
        f"queueSeq={job.first_queue_seq} submitSeq={job.first_aio_submit_seq} "
        f"leaveSeq={job.wait_leave_seq} doneSeq={job.done_seq} "
        f"waitToQueue={wait_to_queue_text} queueToSubmit={queue_to_submit_text} "
        f"waitToSubmit={wait_to_submit_text} boosts={job.wait_boosts} maxWaiters={job.max_waiters}"
    )


def format_map_event(event: MapEvent) -> str:
    parts = [
        f"line {event.line}",
        f"seq {event.seq}",
        event.kind,
        event.action,
    ]
    if event.job is not None:
        parts.append(f"job=0x{event.job:x}")
    if event.va is not None:
        parts.append(f"va=0x{event.va:x}")
    if event.size is not None:
        parts.append(f"size=0x{event.size:x}")
    if event.dmem_offset is not None:
        parts.append(f"dmemOffset=0x{event.dmem_offset:x}")
    if event.type_value is not None:
        parts.append(f"type=0x{event.type_value:x}")
    if event.prot is not None:
        parts.append(f"prot=0x{event.prot:x}")
    if event.direct is not None:
        parts.append(f"direct={event.direct}")
    if event.rc is not None:
        parts.append(f"rc=0x{event.rc:x}")
    if event.reason:
        parts.append(f"reason={event.reason}")
    return " ".join(parts)


def format_order_event(event: AprOrderEvent) -> str:
    parts = [
        f"line {event.line}",
        f"seq {event.seq}",
        event.event,
        f"reason={event.reason}",
    ]
    if event.job:
        parts.append(f"job=0x{event.job:x}")
    if event.read_seq:
        parts.append(f"readSeq=0x{event.read_seq:x}")
    if event.priority:
        parts.append(f"prio={event.priority}")
    if event.blocker:
        parts.append(f"blocker=0x{event.blocker:x}")
    if event.blocker_source:
        parts.append(f"source={event.blocker_source}")
    if event.blocker_op:
        parts.append(f"op={event.blocker_op}")
    parts.append(f"reads={event.pending_reads}/{event.active_reads}")
    if event.active_jobs or event.incoming:
        parts.append(f"jobs={event.active_jobs}+{event.incoming}")
    return " ".join(parts)


def format_amm_buffer_summary(item: Optional[AmmBufferStats]) -> str:
    if item is None:
        return "buffer commands=<none>"
    types = ", ".join(f"{name}:{count}" for name, count in item.type_counts.most_common(4))
    parts = [
        f"commands={item.append_count}",
        f"range=line {item.first_line}..{item.last_line}",
        f"maxOff=0x{item.max_cmd_off:x}",
        f"maxNext=0x{item.max_cb_next:x}",
    ]
    if item.last_cb_num is not None:
        parts.append(f"lastCbNum={item.last_cb_num}")
    if item.last_type:
        parts.append(f"lastType={item.last_type}")
    if item.last_target_va is not None:
        parts.append(f"lastVa=0x{item.last_target_va:x}")
    if item.last_target_size is not None:
        parts.append(f"lastSize=0x{item.last_target_size:x}")
    if types:
        parts.append(f"types=({types})")
    return " ".join(parts)


def format_open_amm_submit(stats: LogStats, thread: str, detail: AmmSubmitDiag) -> str:
    parts = [
        f"thread {thread}",
        f"line {detail.line}",
        f"seq {detail.seq}",
        f"mode={detail.mode}",
    ]
    if detail.buffer is not None:
        parts.append(f"buffer=0x{detail.buffer:x}")
    if detail.current_offset is not None:
        parts.append(f"currentOffset=0x{detail.current_offset:x}")
    if detail.priority is not None:
        parts.append(f"prio={detail.priority}")
    if detail.id_out:
        parts.append(f"idOut={detail.id_out}")

    last = stats.thread_last_event.get(thread)
    if last and (last[0], last[1]) > (detail.line, detail.seq):
        parts.append(f"threadContinued=line {last[0]},seq {last[1]}")
    if detail.buffer is not None:
        parts.append(format_amm_buffer_summary(stats.amm_buffers.get(detail.buffer)))
    return " ".join(parts)


def format_open_apr_submit(stats: LogStats, thread: str, detail: AprSubmitDiag) -> str:
    active_label = reactor_active_label(stats)
    parts = [
        f"thread {thread}",
        f"line {detail.line}",
        f"seq {detail.seq}",
    ]
    if detail.phase:
        parts.append(f"phase={detail.phase}")
    if detail.cb is not None:
        parts.append(f"cb=0x{detail.cb:x}")
    if detail.priority is not None:
        parts.append(f"prio={detail.priority}")
    if detail.result:
        parts.append(f"res={detail.result}")
    if detail.id_value:
        parts.append(f"id={detail.id_value}")
    if detail.backpressure_count:
        parts.append(f"backpressure={detail.backpressure_count}")
        if detail.last_backpressure_line is not None and detail.last_backpressure_seq is not None:
            parts.append(
                f"lastBackpressure=line {detail.last_backpressure_line},seq {detail.last_backpressure_seq}"
            )
        if detail.last_backpressure_job is not None:
            parts.append(f"job=0x{detail.last_backpressure_job:x}")
        if detail.last_backpressure_pending is not None:
            parts.append(f"pending={detail.last_backpressure_pending}")
        if detail.last_backpressure_incoming is not None:
            parts.append(f"incoming={detail.last_backpressure_incoming}")
        if detail.last_backpressure_active_jobs is not None:
            parts.append(f"{active_label}={detail.last_backpressure_active_jobs}")
        if detail.last_backpressure_pending_reads is not None:
            parts.append(f"pendingReads={detail.last_backpressure_pending_reads}")
        if detail.last_backpressure_active_reads is not None:
            parts.append(f"activeReads={detail.last_backpressure_active_reads}")
        if detail.last_backpressure_waiters is not None:
            parts.append(f"waiters={detail.last_backpressure_waiters}")

    last = stats.thread_last_event.get(thread)
    if last and (last[0], last[1]) > (detail.line, detail.seq):
        parts.append(f"threadContinued=line {last[0]},seq {last[1]}")
    return " ".join(parts)


def build_findings(stats: LogStats) -> List[str]:
    findings: List[str] = []
    unfinished = unfinished_jobs(stats)
    failed = failed_jobs(stats)
    active_label = reactor_active_label(stats)

    if stats.missing_seq:
        findings.append(f"Sequence gap detected: {stats.missing_seq} missing log ids.")
    if stats.duplicate_seq:
        findings.append(f"Duplicate sequence ids detected: {stats.duplicate_seq}.")
    if stats.malformed_lines:
        findings.append(f"Malformed lines: {stats.malformed_lines}.")
    if stats.empty_body_lines:
        line_no, seq, thread = stats.empty_body_lines[-1]
        findings.append(f"Empty log body detected at line {line_no}, seq {seq}, thread {thread}; log may be truncated mid-write.")
    if stats.aio_batch_metrics.failed_calls:
        rejected_items = max(
            0,
            stats.aio_batch_metrics.items - stats.aio_batch_metrics.accepted_items,
        )
        findings.append(
            "AIO multiple-submit failures observed: "
            f"calls={stats.aio_batch_metrics.failed_calls}, items={rejected_items}."
        )
    if stats.aio_io_metrics.over_quantum:
        findings.append(
            "Accepted AIO requests exceeded the configured dispatch quantum: "
            f"count={stats.aio_io_metrics.over_quantum}, "
            f"quantum={stats.aio_io_metrics.quantum_bytes} bytes."
        )
    if (
        stats.aio_io_metrics.windows
        and stats.aio_batch_metrics.windows
        and stats.aio_io_metrics.accepted_count != stats.aio_batch_metrics.accepted_items
    ):
        findings.append(
            "Accepted AIO accounting mismatch: "
            f"io={stats.aio_io_metrics.accepted_count}, "
            f"batch={stats.aio_batch_metrics.accepted_items}."
        )
    if stats.active_amm_submit_diag:
        details = [
            format_open_amm_submit(stats, thread, detail)
            for thread, detail in sorted(stats.active_amm_submit_detail.items())
        ]
        if not details:
            details = [
                f"thread {thread} line {line_no}, seq {seq}"
                for thread, (line_no, seq, _body) in sorted(stats.active_amm_submit_diag.items())
            ]
        parts = "; ".join(details)
        findings.append(
            "AMM submit diagnostic has begin without leave "
            f"({stats.amm_submit_diag_begins}/{stats.amm_submit_diag_leaves} begin/leave): {parts}."
        )
        continued = [
            thread
            for thread, detail in stats.active_amm_submit_detail.items()
            if stats.thread_last_event.get(thread)
            and stats.thread_last_event[thread][0:2] > (detail.line, detail.seq)
        ]
        if continued:
            findings.append(
                "At least one open AMM submit thread continued logging after the begin line; "
                "treat that as a missing/truncated leave line unless the crash backtrace also lands inside the mapper submit."
            )
    if stats.amm_submit_diag_unmatched_leaves:
        findings.append(f"AMM submit diagnostic has {stats.amm_submit_diag_unmatched_leaves} leave line(s) without an active begin.")
    if stats.amm_submit_diag_nested_begins:
        findings.append(f"AMM submit diagnostic has {stats.amm_submit_diag_nested_begins} nested begin line(s) on the same thread.")
    if stats.active_apr_submit_detail:
        details = [
            format_open_apr_submit(stats, thread, detail)
            for thread, detail in sorted(stats.active_apr_submit_detail.items())
        ]
        findings.append(
            "APR submit has active enter at the log tail "
            f"({stats.apr_submit_enters}/{stats.apr_submit_leaves} enter/leave): "
            f"{'; '.join(details)}."
        )
        blocked = [
            detail for detail in stats.active_apr_submit_detail.values()
            if detail.backpressure_count
        ]
        if blocked:
            findings.append(
                "APR submit appears blocked by reactor backpressure at the log tail; "
                "treat this as producer-thread starvation unless a later submit leave exists."
            )
    if stats.apr_submit_unmatched_leaves:
        suffix = " This may be caused by sequence gaps." if stats.missing_seq else ""
        findings.append(
            f"APR submit diagnostic has {stats.apr_submit_unmatched_leaves} leave line(s) without an active enter."
            f"{suffix}"
        )
    if stats.apr_submit_nested_enters:
        suffix = " This may be caused by sequence gaps." if stats.missing_seq else ""
        findings.append(
            f"APR submit diagnostic has {stats.apr_submit_nested_enters} nested enter line(s) on the same thread."
            f"{suffix}"
        )
    if stats.apr_submit_backpressure_events:
        findings.append(
            f"APR submit backpressure observed {stats.apr_submit_backpressure_events} time(s); "
            f"max pending={stats.apr_submit_backpressure_max_pending}, "
            f"{active_label}={stats.apr_submit_backpressure_max_active_jobs}, "
            f"pendingReads={stats.apr_submit_backpressure_max_pending_reads}, "
            f"activeReads={stats.apr_submit_backpressure_max_active_reads}."
        )
    priority_demotions = [
        event for event in stats.reactor_priority_events
        if event[2] > 0 and event[4] > event[2]
    ]
    if priority_demotions:
        line_no, seq, old_prio, configured_prio, target_prio, new_prio = priority_demotions[-1]
        configured = f", configured={configured_prio}" if configured_prio is not None else ""
        findings.append(
            "APR reactor priority was lowered relative to its inherited FIFO priority: "
            f"line {line_no}, seq {seq}, old={old_prio}{configured}, target={target_prio}, new={new_prio}. "
            "On Prospero lower numeric FIFO priority is higher; this can starve APR/AIO completion under "
            "high-priority loader waits."
        )
    if stats.event_time_reversals:
        findings.append(f"Event timestamp reversals detected: {stats.event_time_reversals}.")
    if stats.event_time_parse_errors:
        findings.append(f"Event timestamp parse errors: {stats.event_time_parse_errors}.")
    if stats.fd_statuses:
        fd = stats.fd_statuses[-1]
        if fd.probe_opened == 0 and fd.probe_errno != 24:
            findings.append(
                f"FD startup probe could not open {fd.probe_path or '<unknown>'}: "
                f"rc=0x{fd.probe_rc:x}, errno={fd.probe_errno}."
            )
        elif fd.free_exact and fd.probe_opened < fd.direct_full_limit:
            findings.append(
                f"Startup FD headroom ({fd.probe_opened}) is below direct full-file limit ({fd.direct_full_limit})."
            )
        elif fd.free_exact and fd.probe_opened < fd.aio_limit:
            findings.append(
                f"Startup FD headroom ({fd.probe_opened}) is below global AIO limit ({fd.aio_limit})."
            )
    if stats.heap_statuses:
        bad_heap = [heap for heap in stats.heap_statuses if heap.rc != 0]
        if bad_heap:
            heap = bad_heap[-1]
            findings.append(f"Heap diagnostic failed at tag={heap.tag}: rc=0x{heap.rc:x}.")

    if stats.active_aio:
        findings.append(f"AIO has {len(stats.active_aio)} submitted reads without completion in the log tail.")
    if stats.stall_aio_samples and not stats.active_aio:
        findings.append(
            f"Stall watchdog sampled {len(stats.stall_aio_samples)} active AIO id(s) "
            f"(max sampled age {stats.stall_max_aio_age_ms} ms); explicit submit/complete lines are absent."
        )
    if stats.aio_detail_counts:
        details = ", ".join(f"{name}:{count}" for name, count in stats.aio_detail_counts.most_common(5))
        max_age = max((sample.age_ms for sample in stats.aio_detail_samples), default=0)
        findings.append(f"AIO detail diagnostics observed ({details}); max sampled age {max_age} ms.")
        slow_complete = [
            sample for sample in stats.aio_detail_samples
            if sample.kind == "slowComplete" and sample.age_ms >= 1000
        ]
        if slow_complete:
            top = max(slow_complete, key=lambda sample: (sample.age_ms, sample.line))
            status = "no APR failures were logged, but " if not unfinished and not failed else ""
            findings.append(
                f"APR/AIO latency risk: {status}{len(slow_complete)} slow completion sample(s) reached "
                f"{top.age_ms} ms; top fileId={top.file_id}, len=0x{top.length:x}, "
                f"bypass={top.bypass}, closeAfter={top.close_after}, path={top.path or '<unknown>'}."
            )
    if stats.aio_error_counts:
        total_errors = sum(stats.aio_error_counts.values())
        by_rc: Counter = Counter()
        by_event: Counter = Counter()
        for (event, rc, _reason, _file_id, _path), count in stats.aio_error_counts.items():
            by_event[event] += count
            by_rc[rc] += count
        top_rc = ", ".join(f"{format_rc(rc)}:{count}" for rc, count in by_rc.most_common(5))
        top_events = ", ".join(f"{event}:{count}" for event, count in by_event.most_common(5))
        findings.append(f"AIO error/defer events observed: {total_errors}; rc=({top_rc}); events=({top_events}).")
        eagain = by_rc.get(0x80020023, 0)
        if eagain:
            findings.append(f"AIO submit backpressure observed: {eagain} EAGAIN/defer event(s).")
    if stats.aio_short_reads:
        findings.append(
            f"AIO short reads observed: {stats.aio_short_reads}; treated as successful completed reads."
        )
    if stats.aio_efault_details:
        map_full = sum(1 for sample in stats.aio_efault_details if sample.map_full)
        map_gap = len(stats.aio_efault_details) - map_full
        amm_hits = sum(1 for sample in stats.aio_efault_details if sample.overlaps_amm_va)
        latest = stats.aio_efault_details[-1]
        findings.append(
            f"AIO EFAULT detail diagnostics observed: {len(stats.aio_efault_details)} sample(s), "
            f"AMM-overlap={amm_hits}, mapFull={map_full}, mapGap={map_gap}; latest job=0x{latest.job:x}, "
            f"fileId={latest.file_id}, len=0x{latest.length:x}, mapCovered=0x{latest.map_covered:x}, "
            f"firstGap=0x{latest.first_gap:x}, path={latest.path or '<unknown>'}."
        )
    if stats.wait_admit_blocks:
        reasons = ", ".join(
            f"{reason}:{count}" for reason, count in stats.wait_admit_block_reasons.most_common(5)
        )
        findings.append(
            f"APR wait admission was blocked {stats.wait_admit_blocks} time(s) ({reasons}); "
            f"max block count={stats.max_wait_admit_block_count}, "
            f"{active_label}={stats.max_wait_admit_block_active_jobs}, "
            f"pending={stats.max_wait_admit_block_pending}, incoming={stats.max_wait_admit_block_incoming}, "
            f"pendingReads={stats.max_wait_admit_block_pending_reads}, "
            f"activeReads={stats.max_wait_admit_block_active_reads}."
        )
    if stats.wait_admit_order_blocks:
        findings.append(
            f"APR wait admission skipped {stats.wait_admit_order_blocks} wait-boost job(s) "
            "to preserve earlier same-priority APR map ordering."
        )
    if stats.read_order_defers:
        reasons = ", ".join(
            f"{reason}:{count}" for reason, count in stats.read_order_defer_reasons.most_common(5)
        )
        sources = ", ".join(
            f"{source}:{count}" for source, count in stats.read_order_blocker_sources.most_common(5)
        )
        findings.append(
            f"APR read submit was deferred {stats.read_order_defers} time(s) for ordering; "
            f"related order reasons=({reasons}); "
            f"blockers=({sources})."
        )
    if stats.read_promotion_blocks:
        reasons = ", ".join(
            f"{reason}:{count}" for reason, count in stats.read_promotion_block_reasons.most_common(5)
        )
        findings.append(
            f"APR read promotion was blocked {stats.read_promotion_blocks} time(s) "
            f"to preserve same-job read sequence ({reasons})."
        )
    if stats.runwindow_order_expands:
        findings.append(
            f"Legacy APR run-window expansion was observed {stats.runwindow_order_expands} time(s) "
            "to admit an earlier map-side-effect job and avoid an ordering deadlock."
        )
    if stats.max_done_pending >= 32 or stats.max_done_retained >= 64:
        findings.append(
            f"APR completion backlog retained up to done={stats.max_done_retained}, "
            f"pending={stats.max_done_pending}, pendingWaits={stats.max_done_pending_waits}."
        )
    if stats.max_reactor_active_jobs >= 64 or stats.max_apr_backlog >= 128 or stats.max_reactor_incoming >= 64:
        read_backlog = (
            f"readChains={stats.max_reactor_read_chains}"
            if stats.saw_cursor_direct_read_metrics or stats.max_reactor_read_chains
            else f"pendingReads={stats.max_reactor_pending_reads}"
        )
        findings.append(
            f"APR reactor backlog peaked at {active_label}={stats.max_reactor_active_jobs}, "
            f"pending={stats.max_apr_backlog}, incoming={stats.max_reactor_incoming}, "
            f"{read_backlog}, activeReads={stats.max_reactor_active_reads}."
        )
    if stats.pending_detail_samples:
        latest = stats.pending_detail_samples[-1]
        findings.append(
            f"Backlog detail latest head read: reason={latest.reason}, prio={latest.priority}, "
            f"fileId={latest.file_id}, len=0x{latest.length:x}, path={latest.path or '<unknown>'}."
        )
    if stats.wait_pending_samples:
        latest_wait = stats.wait_pending_samples[-1]
        wait_job = ""
        if latest_wait.wait_job_pending or latest_wait.wait_job_incoming or latest_wait.wait_job_done:
            wait_job = (
                f", waitJob=pending:{latest_wait.wait_job_pending}/"
                f"incoming:{latest_wait.wait_job_incoming}/done:{latest_wait.wait_job_done}/"
                f"oldestAioMatch:{latest_wait.oldest_aio_match}"
            )
        findings.append(
            f"Latest APR wait sample ({latest_wait.kind}): job=0x{latest_wait.job:x}, pending={latest_wait.pending}, "
            f"incoming={latest_wait.incoming}, pendingReads={latest_wait.pending_reads}, "
            f"activeReads={latest_wait.active_reads}, pressure={latest_wait.pressure}, "
            f"waitPressure={latest_wait.wait_pressure}, oldestAioAge={latest_wait.oldest_aio_age_ms} ms, "
            f"oldestAioJob=0x{latest_wait.oldest_aio_job:x}{wait_job}."
        )
    if stats.reactor_state_samples:
        latest_state = stats.reactor_state_samples[-1]
        job_flags = ""
        if (
            latest_state.job_ready_completions
            or latest_state.job_completion_ops
            or latest_state.job_completed
            or latest_state.job_failed
            or latest_state.job_ready_to_publish
            or latest_state.job_publishing
            or latest_state.job_completion_ready
            or latest_state.job_has_equeue
            or latest_state.job_equeue_published
            or latest_state.job_waitable
        ):
            job_flags = (
                f", jobFlags=completed:{latest_state.job_completed}/failed:{latest_state.job_failed}/"
                f"ready:{latest_state.job_ready_to_publish}/publishing:{latest_state.job_publishing}/"
                f"completionReady:{latest_state.job_completion_ready}/equeue:"
                f"{latest_state.job_has_equeue}:{latest_state.job_equeue_published}/"
                f"waitable:{latest_state.job_waitable}, completionQueues="
                f"{latest_state.job_ready_completions}/{latest_state.job_completion_ops}"
            )
        state_reads = (
            f"readChains={latest_state.read_chains}"
            if stats.saw_cursor_direct_read_metrics or latest_state.read_chains
            else f"pendingReads={latest_state.pending_reads}"
        )
        cursor_flags = ""
        if stats.saw_cursor_direct_read_metrics or latest_state.read_chains:
            cursor_flags = (
                f", cursorRead={latest_state.job_cursor_read}, "
                f"speculativeRead={latest_state.job_speculative_read}"
            )
        findings.append(
            f"Latest APR reactor state ({latest_state.reason}): {active_label}={latest_state.active_jobs}, "
            f"{state_reads}, activeReads={latest_state.active_reads}, "
            f"pending={latest_state.pending}, incoming={latest_state.incoming}, firstJob=0x{latest_state.first_job:x}, "
            f"op={latest_state.op}{cursor_flags}, firstAioAge={latest_state.first_aio_age_ms} ms{job_flags}."
        )
    if stats.stall_max_pending_reads:
        findings.append(
            f"APR stall samples reached pendingReads={stats.stall_max_pending_reads}, "
            f"activeReads={stats.stall_max_active_reads}, {active_label}={stats.stall_max_active_jobs}."
        )
    if unfinished:
        findings.append(
            f"APR has {len(unfinished)} command buffer(s) without a completion/release record."
        )
    if failed:
        findings.append(f"APR has {len(failed)} failed or partially dropped command buffer(s).")

    total = max(stats.parsed_lines, 1)
    verbose_ratio = stats.verbose_lines / total
    if stats.verbose_lines > 1000 and verbose_ratio >= 0.10:
        findings.append(
            f"High-volume verbose logging is present: {stats.verbose_lines} lines "
            f"({verbose_ratio:.1%}). This can dominate startup time."
        )

    if stats.wait_enters > stats.wait_leaves:
        findings.append(
            f"APR wait imbalance: {stats.wait_enters} wait enter line(s), {stats.wait_leaves} wait leave line(s)."
        )
    if stats.wait_boosts:
        findings.append(
            f"APR wait boost observed: {stats.wait_boosts} boost line(s), "
            f"reserve hits={stats.wait_boost_reserves}, direct reserve hits={stats.wait_boost_direct_reserves}."
        )
    if stats.acquire_defers:
        reasons = ", ".join(
            f"{reason}:{count}" for reason, count in stats.acquire_defer_reasons.most_common(5)
        )
        findings.append(f"APR acquire deferred {stats.acquire_defers} time(s); reasons=({reasons}).")
    if stats.active_direct_opens:
        job_id, file_id = next(reversed(stats.active_direct_opens))
        line, _seq, path, length, offset = stats.active_direct_opens[(job_id, file_id)]
        findings.append(
            "APR direct full-file open has unmatched enter at tail: "
            f"job=0x{job_id:x}, fileId={file_id}, line={line}, path={path}, len=0x{length:x}, off=0x{offset:x}."
        )
    if stats.map_errors:
        findings.append(f"Map-related error/reject events were logged: {len(stats.map_errors)} retained sample(s).")
    if stats.map_fail_reasons:
        reasons = ", ".join(f"{reason}:{count}" for reason, count in stats.map_fail_reasons.most_common(5))
        findings.append(f"APR job map failures: {reasons}.")
    if stats.reactor_blocked:
        findings.append(f"APR reactor reported {stats.reactor_blocked} sampled blocked parser state line(s).")
    if stats.reactor_stalls:
        line_no, seq, body = stats.last_reactor_stall or (0, 0, "")
        findings.append(
            f"APR reactor reported {stats.reactor_stalls} stall watchdog line(s); "
            f"last at line {line_no}, seq {seq}: {body}"
        )
    equeue_pending = sum(job.equeue_pending for _, job in observed_jobs(stats))
    equeue_blocked = sum(job.equeue_blocked for _, job in observed_jobs(stats))
    if equeue_pending:
        findings.append(f"APR equeue completion had {equeue_pending} pending retry event(s); commands stayed pending until delivery.")
    if equeue_blocked:
        findings.append(f"APR equeue completion was blocked {equeue_blocked} time(s) by full overlay queues.")
    if stats.equeue_direct_waits and stats.tail:
        direct_tail = sum(
            1
            for _, _, body in stats.tail
            if body.startswith("eq.wait.overlay") and " direct " in f" {body} "
        )
        if direct_tail >= max(8, len(stats.tail) * 3 // 4):
            top_eq, top_count = stats.equeue_direct_by_eq.most_common(1)[0]
            name = stats.equeue_names.get(top_eq, "unknown")
            findings.append(
                f"Tail is dominated by direct non-APR equeue waits: eq={top_eq} name={name} "
                f"({direct_tail}/{len(stats.tail)} retained tail lines, {top_count} total direct waits)."
            )

    if stats.index_runtime_build_started and not stats.index_built:
        if stats.index_last_progress:
            line_no, seq, dirs, files, pending = stats.index_last_progress
            findings.append(
                f"Runtime index build did not finish in the log; last progress at line {line_no}, "
                f"seq {seq}: dirs={dirs}, files={files}, pendingDirs={pending}."
            )
        else:
            line_no, seq, body = stats.index_runtime_build_started
            findings.append(
                f"Runtime index build started but no completion was logged; start at line {line_no}, seq {seq}: {body}"
            )

    return findings


def print_report(stats: LogStats, top: int, tail_limit: int) -> None:
    active_label = reactor_active_label(stats)
    print(f"AMPR log analysis: {stats.path}")
    print("")
    print("Summary")
    if stats.all_sessions:
        print("  session:             all")
    else:
        print(f"  session start line:  {stats.session_start_line} ({stats.sessions_seen} session(s) in file)")
    print(f"  parsed lines:        {stats.parsed_lines}")
    print(f"  malformed lines:     {stats.malformed_lines}")
    print(f"  sequence range:      {stats.seq_min}..{stats.seq_max}")
    print(f"  missing seq ids:     {stats.missing_seq}")
    print(f"  duplicate seq ids:   {stats.duplicate_seq}")
    print(f"  sequence reversals:  {stats.seq_reversals}")
    if stats.empty_body_lines:
        line_no, seq, thread = stats.empty_body_lines[-1]
        print(f"  empty body lines:    {len(stats.empty_body_lines)} (last line {line_no}, seq {seq}, th={thread})")
    if stats.amm_submit_diag_begins or stats.amm_submit_diag_leaves:
        print(f"  AMM submit begin/leave:{stats.amm_submit_diag_begins}/{stats.amm_submit_diag_leaves}")
        if stats.amm_submit_diag_unmatched_leaves or stats.amm_submit_diag_nested_begins:
            print(
                f"  AMM submit diag odd:  unmatchedLeave={stats.amm_submit_diag_unmatched_leaves} "
                f"nestedBegin={stats.amm_submit_diag_nested_begins}"
            )
        if stats.active_amm_submit_diag:
            active = ", ".join(
                f"th={thread}@{line_no}/{seq}"
                for thread, (line_no, seq, _body) in sorted(stats.active_amm_submit_diag.items())
            )
            print(f"  AMM submit open:     {active}")
    if stats.timestamped_lines:
        duration = event_time_duration_seconds(stats)
        duration_text = f"{duration:.3f}s" if duration is not None else "n/a"
        if stats.event_time_start is not None and stats.event_time_end is not None:
            print(f"  event time range:    {stats.event_time_start}..{stats.event_time_end} ({duration_text})")
        else:
            print("  event time range:    n/a")
        print(f"  timestamped lines:   {stats.timestamped_lines}")
        print(f"  time reversals:      {stats.event_time_reversals}")
    print(f"  threads:             {len(stats.threads)}")
    print("")

    if stats.fd_statuses:
        fd = stats.fd_statuses[-1]
        print("FD")
        print(f"  startup line/seq:    {fd.line}/{fd.seq} tag={fd.tag}")
        exact = "exact" if fd.free_exact else "at least"
        print(f"  probe path:          {fd.probe_path}")
        print(f"  free fd headroom:    {exact} {fd.probe_opened} (limit {fd.probe_limit})")
        print(f"  probe rc/errno:      0x{fd.probe_rc:x}/{fd.probe_errno}")
        print(f"  aio/direct/cache:    {fd.aio_limit}/{fd.direct_full_limit}/{fd.fd_cache_cap} reserve={fd.fd_cache_reserve}")
        print("")

    if stats.heap_statuses:
        heap = stats.heap_statuses[-1]
        print("Heap")
        print(f"  latest line/seq:     {heap.line}/{heap.seq} tag={heap.tag} rc=0x{heap.rc:x}")
        print(f"  system max/current:  0x{heap.max_system:x}/0x{heap.current_system:x}")
        print(f"  inuse max/current:   0x{heap.max_inuse:x}/0x{heap.current_inuse:x}")
        print(f"  free committed/exp/total: 0x{heap.committed_free:x}/0x{heap.expandable_free:x}/0x{heap.total_free:x}")
        if len(stats.heap_statuses) > 1:
            tags = ", ".join(f"{item.tag}@{item.seq}" for item in stats.heap_statuses[-5:])
            print(f"  recent tags:         {tags}")
        print("")

    if stats.amm_submit_diag_begins or stats.amm_buffers:
        print("AMM Submit")
        if stats.amm_submit_modes:
            modes = ", ".join(f"{name}: {count}" for name, count in stats.amm_submit_modes.most_common(5))
            print(f"  modes:               {modes}")
        if stats.amm_submit_rcs:
            rcs = ", ".join(f"{name}: {count}" for name, count in stats.amm_submit_rcs.most_common(5))
            print(f"  leave rc:            {rcs}")
        print(f"  mapper retries:      {stats.amm_submit_retry_total}")
        if stats.active_amm_submit_detail:
            print("  open submits:")
            for thread, detail in sorted(stats.active_amm_submit_detail.items()):
                print(f"  - {format_open_amm_submit(stats, thread, detail)}")
        if stats.amm_buffers:
            top_buffers = sorted(
                stats.amm_buffers.values(),
                key=lambda item: (item.append_count, item.last_line),
                reverse=True,
            )[:top]
            print("  busiest buffers:")
            for item in top_buffers:
                print(f"  - buffer=0x{item.buffer:x} {format_amm_buffer_summary(item)}")
        print("")

    jobs_observed = observed_jobs(stats)
    jobs_total = len(jobs_observed)
    done_total = sum(1 for _, job in jobs_observed if job.done_line is not None)
    reads_total = sum(job.queued_reads for _, job in jobs_observed)
    aio_submit_total = sum(job.aio_submits for _, job in jobs_observed)
    aio_complete_total = sum(job.aio_completes for _, job in jobs_observed)
    equeue_attempt_total = sum(job.equeue_attempts for _, job in jobs_observed)
    equeue_delivered_total = sum(job.equeue_delivered for _, job in jobs_observed)
    equeue_pending_total = sum(job.equeue_pending for _, job in jobs_observed)
    equeue_blocked_total = sum(job.equeue_blocked for _, job in jobs_observed)
    print("APR/AIO")
    print(f"  jobs submitted/seen: {jobs_total}")
    print(f"  jobs done:           {done_total}")
    print(f"  jobs unfinished:     {jobs_total - done_total}")
    print(f"  queued reads:        {reads_total}")
    print(f"  AIO submit/complete: {aio_submit_total}/{aio_complete_total}")
    print(f"  AIO short reads:     {stats.aio_short_reads}")
    if equeue_attempt_total or equeue_delivered_total or equeue_pending_total or equeue_blocked_total:
        print(
            "  equeue completion:  "
            f"attempt/deliver/pending/block={equeue_attempt_total}/{equeue_delivered_total}/"
            f"{equeue_pending_total}/{equeue_blocked_total}"
        )
    print(f"  AIO open in tail:    {len(stats.active_aio)}")
    print(f"  max AIO active:      {stats.max_aio_active}")
    print(f"  max APR backlog:     {stats.max_apr_backlog}")
    print(f"  max reactor active:  {stats.max_reactor_active_jobs} ({active_label})")
    print(f"  max pending/incoming:{stats.max_apr_backlog}/{stats.max_reactor_incoming}")
    if stats.saw_cursor_direct_read_metrics or stats.max_reactor_read_chains:
        print(f"  max read chains/act: {stats.max_reactor_read_chains}/{stats.max_reactor_active_reads}")
    else:
        print(f"  max reads pend/act:  {stats.max_reactor_pending_reads}/{stats.max_reactor_active_reads}")
    print(f"  max submit backlog:  {stats.max_submit_backlog}")
    first_read_admission = stats.job_queue_first_read_latency
    first_submit_admission = stats.first_read_queue_first_aio_latency
    job_admission = stats.job_queue_first_aio_latency
    pending_admission = stats.pending_read_queue_submit_latency
    loop_gap = stats.reactor_active_loop_gap_latency
    wake_overshoot = stats.reactor_wake_overshoot_latency
    if (
        first_read_admission.windows
        or first_submit_admission.windows
        or job_admission.windows
        or pending_admission.windows
        or loop_gap.windows
        or wake_overshoot.windows
    ):
        first_read_avg = (
            first_read_admission.total_us / first_read_admission.count
            if first_read_admission.count
            else 0.0
        )
        first_submit_avg = (
            first_submit_admission.total_us / first_submit_admission.count
            if first_submit_admission.count
            else 0.0
        )
        job_avg = job_admission.total_us / job_admission.count if job_admission.count else 0.0
        pending_avg = (
            pending_admission.total_us / pending_admission.count
            if pending_admission.count
            else 0.0
        )
        loop_gap_avg = loop_gap.total_us / loop_gap.count if loop_gap.count else 0.0
        wake_overshoot_avg = (
            wake_overshoot.total_us / wake_overshoot.count
            if wake_overshoot.count
            else 0.0
        )
        print(
            "  job->first queued us:"
            f" count={first_read_admission.count} avg={first_read_avg:.1f} "
            f"max={first_read_admission.max_us} maxWindowP95/P99="
            f"{first_read_admission.max_window_p95_us}/"
            f"{first_read_admission.max_window_p99_us}"
        )
        print(
            ("  first ready->AIO us:" if stats.saw_cursor_direct_read_metrics else "  first queued->AIO us:")
            + f" count={first_submit_admission.count} avg={first_submit_avg:.1f} "
            f"max={first_submit_admission.max_us} maxWindowP95/P99="
            f"{first_submit_admission.max_window_p95_us}/"
            f"{first_submit_admission.max_window_p99_us}"
        )
        print(
            "  job->first AIO us:  "
            f"count={job_admission.count} avg={job_avg:.1f} max={job_admission.max_us} "
            f"maxWindowP95/P99={job_admission.max_window_p95_us}/"
            f"{job_admission.max_window_p99_us}"
        )
        print(
            ("  read ready->AIO us: " if stats.saw_cursor_direct_read_metrics else "  pending->submit us: ")
            + f"count={pending_admission.count} avg={pending_avg:.1f} "
            f"max={pending_admission.max_us} maxWindowP95/P99="
            f"{pending_admission.max_window_p95_us}/{pending_admission.max_window_p99_us}"
        )
        print(
            "  active loop gap us: "
            f"count={loop_gap.count} avg={loop_gap_avg:.1f} max={loop_gap.max_us} "
            f"maxWindowP95/P99={loop_gap.max_window_p95_us}/"
            f"{loop_gap.max_window_p99_us}"
        )
        print(
            "  wake overshoot us:  "
            f"count={wake_overshoot.count} avg={wake_overshoot_avg:.1f} "
            f"max={wake_overshoot.max_us} maxWindowP95/P99="
            f"{wake_overshoot.max_window_p95_us}/"
            f"{wake_overshoot.max_window_p99_us}"
        )
    if stats.admission_priority_latency:
        print("  admission by APR priority:")
        for priority in sorted(stats.admission_priority_latency):
            stages = stats.admission_priority_latency[priority]
            parts = []
            first_label = "ready->AIO" if stats.saw_cursor_direct_read_metrics else "queue->AIO"
            read_label = "read-ready->AIO" if stats.saw_cursor_direct_read_metrics else "pending->submit"
            for label, stage in (
                ("job->read", "job_queue_first_read"),
                (first_label, "first_read_queue_first_aio"),
                ("job->AIO", "job_queue_first_aio"),
                (read_label, "pending_read_queue_submit"),
            ):
                aggregate = stages.get(stage, WindowLatencyAggregate())
                average = aggregate.total_us / aggregate.count if aggregate.count else 0.0
                parts.append(
                    f"{label}=n{aggregate.count}/avg{average:.1f}/max{aggregate.max_us}us"
                )
            print(f"    APR {priority}: {', '.join(parts)}")
    batch = stats.aio_batch_metrics
    if batch.windows:
        average_items = batch.items / batch.calls if batch.calls else 0.0
        fill_pct = 100.0 * batch.items / batch.capacity if batch.capacity else 0.0
        singleton_pct = 100.0 * batch.singleton_calls / batch.calls if batch.calls else 0.0
        accepted_pct = 100.0 * batch.accepted_items / batch.items if batch.items else 0.0
        saved_calls = max(0, batch.items - batch.calls)
        reduction_pct = 100.0 * saved_calls / batch.items if batch.items else 0.0
        average_round_items = batch.round_items / batch.rounds if batch.rounds else 0.0
        full_round_pct = 100.0 * batch.full_rounds / batch.rounds if batch.rounds else 0.0
        print(
            "  AIO batch calls/items: "
            f"{batch.calls}/{batch.items} accepted={batch.accepted_items} "
            f"failedCalls={batch.failed_calls}"
        )
        print(
            "  AIO batch efficiency: "
            f"avg={average_items:.2f} fill={fill_pct:.1f}% "
            f"singletons={batch.singleton_calls} ({singleton_pct:.1f}%) "
            f"savedCalls={saved_calls} ({reduction_pct:.1f}%) accepted={accepted_pct:.1f}%"
        )
        print(
            "  AIO batch rounds:    "
            f"{batch.rounds} items={batch.round_items} avg={average_round_items:.2f} "
            f"full={batch.full_rounds} ({full_round_pct:.1f}%)"
        )
        priority_parts = []
        for name in ("high", "mid", "low"):
            calls = batch.priority_calls[name]
            items = batch.priority_items[name]
            average = items / calls if calls else 0.0
            priority_parts.append(f"{name}={calls}/{items}/{average:.2f}")
        print(f"  batch prio call/item/avg: {', '.join(priority_parts)}")
        apr_parts = [
            f"{priority}:{batch.apr_priority_items[priority]}"
            for priority in range(APR_PRIORITY_LANES)
        ]
        print(f"  batch APR priority items: {', '.join(apr_parts)}")
    io = stats.aio_io_metrics
    if io.windows:
        average_bytes = io.accepted_bytes / io.accepted_count if io.accepted_count else 0.0
        full_pct = 100.0 * io.full_quantum / io.accepted_count if io.accepted_count else 0.0
        throughput_mib_s = (
            io.accepted_bytes * 1000.0 / io.window_ms / (1024.0 * 1024.0)
            if io.window_ms
            else 0.0
        )
        print(
            "  AIO accepted bytes: "
            f"requests={io.accepted_count} bytes={io.accepted_bytes} "
            f"avg={average_bytes:.1f} throughput={throughput_mib_s:.1f} MiB/s"
        )
        print(
            "  AIO request sizes:  "
            f"<=64K={io.le64k}, 64K..256K={io.le256k}, "
            f"256K..quantum={io.partial_quantum}, full={io.full_quantum} "
            f"({full_pct:.1f}%), over={io.over_quantum}, quantum={io.quantum_bytes}"
        )
        io_priority_parts = []
        for priority in range(APR_PRIORITY_LANES):
            count = io.priority_count[priority]
            byte_count = io.priority_bytes[priority]
            average = byte_count / count if count else 0.0
            io_priority_parts.append(
                f"{priority}:{count}/{byte_count}/{average:.0f}"
            )
        print(f"  AIO prio count/bytes/avg: {', '.join(io_priority_parts)}")
    print(f"  APR submit enter/leave: {stats.apr_submit_enters}/{stats.apr_submit_leaves}")
    print(f"  submit backpressure: {stats.apr_submit_backpressure_events}")
    if stats.apr_submit_backpressure_events:
        print(
            f"  submit pressure max: pending={stats.apr_submit_backpressure_max_pending} "
            f"{active_label}={stats.apr_submit_backpressure_max_active_jobs} "
            f"reads={stats.apr_submit_backpressure_max_pending_reads}/{stats.apr_submit_backpressure_max_active_reads}"
        )
    if stats.active_apr_submit_detail:
        print("  open APR submits:")
        for thread, detail in sorted(stats.active_apr_submit_detail.items()):
            print(f"  - {format_open_apr_submit(stats, thread, detail)}")
    if stats.max_priority_queue:
        by_prio = ", ".join(
            f"prio {prio}: {depth}" for prio, depth in sorted(stats.max_priority_queue.items())
        )
        print(f"  max pending by prio: {by_prio}")
    print(f"  APR waits enter/leave: {stats.wait_enters}/{stats.wait_leaves}")
    print(f"  wait boosts:         {stats.wait_boosts}")
    print(f"  wait reserve hits:   {stats.wait_boost_reserves}")
    print(f"  wait direct reserve: {stats.wait_boost_direct_reserves}")
    print(f"  wait admit blocks:   {stats.wait_admit_blocks}")
    print(f"  wait order blocks:   {stats.wait_admit_order_blocks}")
    if stats.wait_admit_block_reasons:
        reasons = ", ".join(f"{name}: {count}" for name, count in stats.wait_admit_block_reasons.most_common(5))
        print(f"  wait block reasons:  {reasons}")
        print(
            f"  wait block maxima:   count={stats.max_wait_admit_block_count} "
            f"{active_label}={stats.max_wait_admit_block_active_jobs} "
            f"pending={stats.max_wait_admit_block_pending} incoming={stats.max_wait_admit_block_incoming} "
            f"reads={stats.max_wait_admit_block_pending_reads}/{stats.max_wait_admit_block_active_reads} "
            f"oldestAioAge={stats.max_wait_admit_block_oldest_aio_age_ms}ms"
        )
    if (
        stats.read_order_defers
        or stats.read_promotions
        or stats.read_promotion_blocks
        or stats.wait_admit_order_blocks
        or stats.runwindow_order_expands
    ):
        print(
            f"  read order:          defer={stats.read_order_defers} "
            f"promote={stats.read_promotions} promoteBlock={stats.read_promotion_blocks} "
            f"legacyRunWindowExpand={stats.runwindow_order_expands}"
        )
        if stats.read_order_defer_reasons:
            reasons = ", ".join(
                f"{name}: {count}" for name, count in stats.read_order_defer_reasons.most_common(5)
            )
            print(f"  order defer reasons: {reasons}")
        if stats.read_order_blocker_sources:
            sources = ", ".join(
                f"{name}: {count}" for name, count in stats.read_order_blocker_sources.most_common(5)
            )
            print(f"  order blockers:      {sources}")
        if stats.read_promotion_reasons:
            reasons = ", ".join(
                f"{name}: {count}" for name, count in stats.read_promotion_reasons.most_common(5)
            )
            print(f"  promotion reasons:   {reasons}")
        if stats.read_promotion_block_reasons:
            reasons = ", ".join(
                f"{name}: {count}" for name, count in stats.read_promotion_block_reasons.most_common(5)
            )
            print(f"  promote block reason:{reasons}")
    print(f"  done evictions:      {stats.apr_done_evictions} events / {stats.apr_done_evicted_ids} ids")
    print(
        f"  done backlog max:    done={stats.max_done_retained} "
        f"pending={stats.max_done_pending} pendingWaits={stats.max_done_pending_waits}"
    )
    if stats.done_detail_samples:
        latest_done = stats.done_detail_samples[-1]
        print(
            f"  latest done detail:  done={latest_done.done} pending={latest_done.pending} "
            f"pendingWaits={latest_done.pending_waits} first=0x{latest_done.first:x} "
            f"last=0x{latest_done.last:x} newest=0x{latest_done.newest:x} "
            f"equeue={latest_done.newest_has_equeue}/{latest_done.newest_equeue_published}"
        )
        sample_count = min(latest_done.samples, len(stats.done_id_samples), 5)
        if sample_count:
            samples = stats.done_id_samples[-sample_count:]
            ids = ", ".join(
                f"0x{sample.submit_id:x}{'*' if sample.waiting else ''}" for sample in samples
            )
            print(f"  latest done ids:     {ids}")
    print(f"  direct open enter/leave:{stats.direct_open_enters}/{stats.direct_open_leaves}")
    if stats.direct_open_headroom_defers or stats.acquire_defers:
        reasons = ", ".join(f"{name}: {count}" for name, count in stats.acquire_defer_reasons.most_common(5))
        print(f"  acquire defers:      {stats.acquire_defers} headroom={stats.direct_open_headroom_defers} reasons={reasons}")
    if stats.active_direct_opens:
        job_id, file_id = next(reversed(stats.active_direct_opens))
        line, _seq, path, length, offset = stats.active_direct_opens[(job_id, file_id)]
        print(f"  direct open tail:    job=0x{job_id:x} fileId={file_id} line={line} path={path} len=0x{length:x} off=0x{offset:x}")
    if stats.reactor_backlog_reasons:
        reasons = ", ".join(f"{name}: {count}" for name, count in stats.reactor_backlog_reasons.most_common(5))
        print(f"  backlog reasons:     {reasons}")
        print(f"  slow cooldown hits:  {stats.reactor_backlog_slow_cooldown}")
    print(f"  equeue waits:        {stats.equeue_waits}")
    print(f"  direct equeue waits: {stats.equeue_direct_waits}")
    if stats.equeue_direct_by_eq:
        top_direct = ", ".join(
            f"{eq}({stats.equeue_names.get(eq, 'unknown')}): {count}"
            for eq, count in stats.equeue_direct_by_eq.most_common(3)
        )
        print(f"  top direct equeues:  {top_direct}")
    if stats.apr_local_equeue_counter_lines or stats.apr_local_equeue_wait_lines:
        local = stats.apr_local_equeue
        no_waiter_skip = (
            str(local["wakeNoWaiterSkips"])
            if stats.apr_local_equeue_wake_skip_metric_lines
            else "n/a"
        )
        print(
            "  APR local equeue:    "
            f"publish={local['published']}/{local['publishAttempts']} "
            f"fallback={local['fallbackHooks'] + local['fallbackQueue'] + local['fallbackRegistration'] + local['fallbackWake']} "
            f"backpressure={local['backpressure']} wakeFail={local['wakeFailures']}"
        )
        print(
            "  local wake activity: "
            f"trigger={local['wakeTriggers']} armedSkip={local['wakeElisions']} "
            f"noWaiterSkip={no_waiter_skip} stale={local['staleWakes']}"
        )
        if stats.apr_local_equeue_timeout_metric_lines:
            print(
                "  local wait timeout:  "
                f"zero={local['nativeWaitZero']} finite={local['nativeWaitFinite']} "
                f"infinite={local['nativeWaitInfinite']} "
                f"intent={stats.apr_local_equeue_live_wait_intents}/"
                f"{stats.apr_local_equeue_wait_intent_peak}"
            )
        else:
            print("  local wait timeout:  metrics unavailable in this build")
        if stats.apr_local_equeue_grace_lines:
            adaptive = ""
            if stats.apr_local_equeue_grace_adaptive:
                adaptive = (
                    f"adaptive={stats.apr_local_equeue_grace_min_us}-"
                    f"{stats.apr_local_equeue_grace_max_us}us "
                )
            print(
                "  local wait grace:    "
                f"configured={stats.apr_local_equeue_grace_configured_us}us "
                f"{adaptive}"
                f"attempt/hit/miss={local['attempts']}/{local['hits']}/{local['misses']} "
                f"events={local['events']} elapsed={local['elapsedUs']}us "
                f"up/down/cooldown/rearm={local['increases']}/"
                f"{local['decreases']}/{local['cooldowns']}/{local['rearms']}"
            )
        else:
            print("  local wait grace:    metrics unavailable in this build")
    print(f"  autogen events:      {stats.autogen_events}")
    print(f"  blocked samples:     {stats.reactor_blocked}")
    print(
        "  completion window:   "
        f"backpressure={stats.read_completion_backpressure_events} "
        f"maxSpan={stats.read_completion_backpressure_max_span}"
    )
    print(f"  reactor stalls:      {stats.reactor_stalls}")
    if stats.reactor_stalls:
        print(
            f"  stall max {active_label}/pending/active: "
            f"{stats.stall_max_active_jobs}/{stats.stall_max_pending_reads}/{stats.stall_max_active_reads}"
        )
        print(f"  stall max AIO age:   {stats.stall_max_aio_age_ms} ms")
        if stats.stall_ops:
            ops = ", ".join(f"{name}: {count}" for name, count in stats.stall_ops.most_common(5))
            print(f"  stall ops:           {ops}")
        if stats.stall_aio_samples:
            print(f"  stall sampled AIO:   {len(stats.stall_aio_samples)} id(s)")
    if stats.aio_detail_counts:
        details = ", ".join(f"{name}: {count}" for name, count in stats.aio_detail_counts.most_common(5))
        print(f"  AIO detail samples:  {details}")
        slow_complete = [
            sample for sample in stats.aio_detail_samples
            if sample.kind == "slowComplete"
        ]
        if slow_complete:
            top_slow = max(slow_complete, key=lambda sample: (sample.age_ms, sample.line))
            print(
                f"  slowComplete max:    {top_slow.age_ms}ms job=0x{top_slow.job:x} "
                f"fileId={top_slow.file_id} len=0x{top_slow.length:x} "
                f"bypass={top_slow.bypass} closeAfter={top_slow.close_after}"
            )
    if stats.pending_detail_samples:
        latest = stats.pending_detail_samples[-1]
        print(
            f"  latest pending head: reason={latest.reason} prio={latest.priority} "
            f"fileId={latest.file_id} len=0x{latest.length:x} "
            f"perFile={latest.per_file_active}/{latest.per_file_limit} "
            f"cached={latest.cached_active}/{latest.cached_limit} "
            f"waitBoosted={latest.wait_boosted} idleBoost={latest.idle_boost}"
        )
    if stats.backlog_file_samples:
        latest_files = stats.backlog_file_samples[-5:]
        top_files = "; ".join(
            f"#{sample.rank} fileId={sample.file_id} p/a={sample.pending}/{sample.active} "
            f"pc/ps/pn/pb={sample.pending_cached}/{sample.pending_small}/"
            f"{sample.pending_normal}/{sample.pending_bulk}"
            for sample in latest_files
        )
        print(f"  latest backlog files:{top_files}")
    print("")

    if stats.map_cb_ops or stats.map_cb_api or stats.map_runtime or stats.map_amm:
        print("Map")
        if stats.map_cb_ops:
            ops = ", ".join(f"{name}: {count}" for name, count in stats.map_cb_ops.most_common(8))
            print(f"  cb ops:              {ops}")
        if stats.map_total_bytes_by_op:
            bytes_by_op = ", ".join(
                f"{name}: 0x{total:x}" for name, total in stats.map_total_bytes_by_op.most_common(8)
            )
            print(f"  cb op bytes:         {bytes_by_op}")
        if stats.map_cb_api:
            api = ", ".join(f"{name}: {count}" for name, count in stats.map_cb_api.most_common(8))
            print(f"  APR cb API:          {api}")
        if stats.map_runtime:
            runtime = ", ".join(f"{name}: {count}" for name, count in stats.map_runtime.most_common(8))
            print(f"  APR runtime:         {runtime}")
        if stats.map_amm:
            amm = ", ".join(f"{name}: {count}" for name, count in stats.map_amm.most_common(8))
            print(f"  AMM runtime:         {amm}")
        if stats.map_runtime_reject_reasons:
            rejects = ", ".join(
                f"{name}: {count}" for name, count in stats.map_runtime_reject_reasons.most_common(8)
            )
            print(f"  map rejects:         {rejects}")
        if stats.map_fail_reasons:
            failures = ", ".join(f"{name}: {count}" for name, count in stats.map_fail_reasons.most_common(8))
            print(f"  job map failures:    {failures}")
        print("")

    if (
        stats.cb_append_sizes
        or stats.cb_append_capacity_rejects
        or stats.cb_append_size_mismatches
    ):
        print("Command Buffer")
        if stats.cb_append_sizes:
            sizes = ", ".join(
                f"{name}: {count}/0x{stats.cb_append_size_bytes[name]:x}"
                for name, count in stats.cb_append_sizes.most_common(10)
            )
            print(f"  append count/bytes:  {sizes}")
        print(f"  max next offset:     0x{stats.cb_append_max_next_offset:x}")
        print(f"  offset mismatches:   {stats.cb_append_size_mismatches}")
        print(f"  capacity rejects:    {stats.cb_append_capacity_rejects}")
        print("")

    if stats.index_runtime_build_started or stats.index_last_progress or stats.index_built or stats.index_saved:
        print("APR Index")
        if stats.index_runtime_build_started:
            line_no, seq, _ = stats.index_runtime_build_started
            print(f"  runtime build:       started at line {line_no}, seq {seq}")
        if stats.index_last_progress:
            line_no, seq, dirs, files, pending = stats.index_last_progress
            print(
                f"  last progress:       line {line_no}, seq {seq}, "
                f"dirs={dirs}, files={files}, pendingDirs={pending}"
            )
        if stats.index_last_dir:
            line_no, seq, path, dirs, files, pending = stats.index_last_dir
            print(
                f"  last dir detail:     line {line_no}, seq {seq}, "
                f"dirs={dirs}, files={files}, pendingDirs={pending}, path={path}"
            )
        if stats.index_last_stat_enter:
            line_no, seq, path, dirs, files, pending = stats.index_last_stat_enter
            print(
                f"  last stat enter:     line {line_no}, seq {seq}, "
                f"dirs={dirs}, files={files}, pendingDirs={pending}, path={path}"
            )
        if stats.index_last_stat_leave:
            line_no, seq, path = stats.index_last_stat_leave
            print(f"  last stat leave:     line {line_no}, seq {seq}, path={path}")
        if stats.index_built:
            line_no, seq, _ = stats.index_built
            print(f"  built:               line {line_no}, seq {seq}")
        if stats.index_saved:
            line_no, seq, _ = stats.index_saved
            print(f"  saved:               line {line_no}, seq {seq}")
        print("")

    findings = build_findings(stats)
    print("Findings")
    if findings:
        for item in findings:
            print(f"  - {item}")
    else:
        print("  - No obvious APR/AIO failure pattern was detected.")
    print("")

    unfinished = unfinished_jobs(stats)
    if unfinished:
        print("Unfinished Jobs")
        for job_id, job in unfinished[-top:]:
            print(f"  - {format_job(job_id, job)}")
        print("")

    failed = failed_jobs(stats)
    if failed:
        print("Failed/Partial Jobs")
        for job_id, job in failed[-top:]:
            reasons = ", ".join(f"{k}:{v}" for k, v in job.fail_reasons.items()) or "none"
            print(f"  - {format_job(job_id, job)} reasons={reasons}")
        print("")

    if stats.apr_order_samples:
        print("APR Ordering")
        for sample in stats.apr_order_samples[-top:]:
            print(f"  - {format_order_event(sample)}")
        print("")

    if stats.map_errors:
        print("Map Errors")
        for event in stats.map_errors[:top]:
            print(f"  - {format_map_event(event)}")
        print("")

    if stats.map_tail:
        print("Recent Map Events")
        for event in stats.map_tail[-top:]:
            print(f"  - {format_map_event(event)}")
        print("")

    waited_delays = waited_submit_delay_jobs(stats)
    if waited_delays:
        print("Waited Job Submit Delays")
        for job_id, job, _ in waited_delays[:top]:
            print(f"  - {format_waited_job(job_id, job)}")
        print("")

    if stats.active_aio:
        print("Open AIO Requests")
        for aio_id, (job_id, read_seq, line_no, seq) in sorted(stats.active_aio.items())[:top]:
            print(
                f"  - aioId={aio_id} job=0x{job_id:x} readSeq=0x{read_seq:x} "
                f"submitted=line {line_no},seq {seq}"
            )
        print("")

    if stats.stall_aio_samples:
        print("Sampled AIO From Stalls")
        samples = sorted(stats.stall_aio_samples.values(), key=lambda sample: (sample.age_ms, sample.line), reverse=True)
        for sample in samples[:top]:
            print(
                f"  - aioId={sample.aio_id} kind={sample.sample_kind} job=0x{sample.job:x} "
                f"readSeq=0x{sample.read_seq:x} fileId={sample.file_id} len=0x{sample.length:x} "
                f"off=0x{sample.offset:x} ageMs={sample.age_ms} state=0x{sample.state:x} "
                f"pollRc=0x{sample.poll_rc:x} line={sample.line},seq={sample.seq}"
            )
        print("")

    if stats.aio_detail_samples:
        print("AIO Detail Samples")
        samples = sorted(stats.aio_detail_samples, key=lambda sample: (sample.age_ms, sample.line), reverse=True)
        for sample in samples[:top]:
            print(
                f"  - kind={sample.kind} reason={sample.reason} aioId={sample.aio_id} "
                f"job=0x{sample.job:x} readSeq=0x{sample.read_seq:x} fileId={sample.file_id} "
                f"len=0x{sample.length:x} off=0x{sample.offset:x} ageMs={sample.age_ms} "
                f"state=0x{sample.state:x} pollRc=0x{sample.poll_rc:x} "
                f"return=0x{sample.return_value:x} path={sample.path or '<unknown>'} "
                f"line={sample.line},seq={sample.seq}"
            )
        print("")

    if stats.aio_error_counts:
        print("AIO Errors")
        for (event, rc, reason, file_id, path), count in stats.aio_error_counts.most_common(top):
            print(
                f"  {count:8d}  event={event} rc={format_rc(rc)} "
                f"reason={reason or '<none>'} fileId={file_id} path={path or '<unknown>'}"
            )
        if stats.aio_error_samples:
            print("  samples:")
            for sample in stats.aio_error_samples[-min(top, len(stats.aio_error_samples)):]:
                print(
                    f"  - event={sample.event} rc={format_rc(sample.rc)} reason={sample.reason or '<none>'} "
                    f"job=0x{sample.job:x} readSeq=0x{sample.read_seq:x} aioId={sample.aio_id} "
                    f"fileId={sample.file_id} len=0x{sample.length:x} off=0x{sample.offset:x} "
                    f"path={sample.path or '<unknown>'} line={sample.line},seq={sample.seq}"
                )
        print("")

    if stats.aio_efault_details:
        print("AIO EFAULT Details")
        for sample in stats.aio_efault_details[-top:]:
            print(
                f"  - aioId={sample.aio_id} job=0x{sample.job:x} readSeq=0x{sample.read_seq:x} "
                f"fileId={sample.file_id} len=0x{sample.length:x} off=0x{sample.offset:x} "
                f"logicalLen=0x{sample.logical_length:x} logicalOff=0x{sample.logical_offset:x} "
                f"ageMs={sample.age_ms} inAmmVa={sample.in_amm_va} overlapsAmmVa={sample.overlaps_amm_va} "
                f"mapActive={sample.map_active} mapRanges={sample.map_ranges} mapOverlaps={sample.map_overlaps} "
                f"mapCovered=0x{sample.map_covered:x} mapFull={sample.map_full} "
                f"firstGap=0x{sample.first_gap:x} firstOverlap={sample.first_overlap or '<none>'} "
                f"lastOverlap={sample.last_overlap or '<none>'} path={sample.path or '<unknown>'} "
                f"line={sample.line},seq={sample.seq}"
            )
        print("")

    if stats.pending_detail_samples:
        print("Pending Read Detail Samples")
        for sample in stats.pending_detail_samples[-top:]:
            print(
                f"  - reason={sample.reason} prio={sample.priority} job=0x{sample.job:x} "
                f"readSeq=0x{sample.read_seq:x} fileId={sample.file_id} len=0x{sample.length:x} "
                f"off=0x{sample.offset:x} queueReads={sample.queue_reads} "
                f"pendingReads={sample.pending_reads} activeReads={sample.active_reads} "
                f"perFileActive={sample.per_file_active} perFileLimit={sample.per_file_limit} "
                f"cachedActive={sample.cached_active} cachedLimit={sample.cached_limit} "
                f"waitBoosted={sample.wait_boosted} idleBoost={sample.idle_boost} "
                f"path={sample.path or '<unknown>'} line={sample.line},seq={sample.seq}"
            )
        print("")

    if stats.amm_writer:
        print("AMM Writer Commands")
        for writer, count in stats.amm_writer.most_common(top):
            print(f"  {count:8d}  {writer}")
        if stats.amm_writer_failures:
            print("  failures:")
            for key, count in stats.amm_writer_failures.most_common(top):
                print(f"  {count:8d}  {key}")
        print("")

    print("Top Prefixes")
    for prefix, count in stats.prefixes.most_common(top):
        print(f"  {count:8d}  {prefix}")
    print("")

    if stats.suspicious:
        print("Suspicious Lines")
        for line_no, seq, body in stats.suspicious[:top]:
            print(f"  line {line_no}, seq {seq}: {body}")
        print("")

    if tail_limit > 0 and stats.tail:
        print("Tail")
        for line_no, seq, body in stats.tail[-tail_limit:]:
            print(f"  line {line_no}, seq {seq}: {body}")


def window_latency_to_json(aggregate: WindowLatencyAggregate) -> Dict[str, object]:
    return {
        "windows": aggregate.windows,
        "count": aggregate.count,
        "total_us": aggregate.total_us,
        "average_us": (
            aggregate.total_us / aggregate.count if aggregate.count else 0.0
        ),
        "max_us": aggregate.max_us,
        "max_window_p95_us": aggregate.max_window_p95_us,
        "max_window_p99_us": aggregate.max_window_p99_us,
    }


def stats_to_json(stats: LogStats, top: int) -> Dict[str, object]:
    unfinished = unfinished_jobs(stats)
    failed = failed_jobs(stats)
    waited = waited_jobs(stats)
    waited_delays = waited_submit_delay_jobs(stats)
    jobs_observed = observed_jobs(stats)
    return {
        "path": stats.path,
        "session_start_line": stats.session_start_line,
        "sessions_seen": stats.sessions_seen,
        "all_sessions": stats.all_sessions,
        "parsed_lines": stats.parsed_lines,
        "malformed_lines": stats.malformed_lines,
        "seq_min": stats.seq_min,
        "seq_max": stats.seq_max,
        "missing_seq": stats.missing_seq,
        "duplicate_seq": stats.duplicate_seq,
        "seq_reversals": stats.seq_reversals,
        "empty_body_lines": [
            {"line": line, "seq": seq, "thread": thread}
            for line, seq, thread in stats.empty_body_lines
        ],
        "reactor_admission_latency": {
            "job_queue_first_read": window_latency_to_json(
                stats.job_queue_first_read_latency
            ),
            "first_read_queue_first_aio": window_latency_to_json(
                stats.first_read_queue_first_aio_latency
            ),
            "first_read_ready_first_aio": window_latency_to_json(
                stats.first_read_queue_first_aio_latency
            ) if stats.saw_cursor_direct_read_metrics else None,
            "job_queue_first_aio": window_latency_to_json(
                stats.job_queue_first_aio_latency
            ),
            "pending_read_queue_submit": window_latency_to_json(
                stats.pending_read_queue_submit_latency
            ),
            "read_ready_aio": window_latency_to_json(
                stats.pending_read_queue_submit_latency
            ) if stats.saw_cursor_direct_read_metrics else None,
            "active_loop_gap": window_latency_to_json(
                stats.reactor_active_loop_gap_latency
            ),
            "wake_overshoot": window_latency_to_json(
                stats.reactor_wake_overshoot_latency
            ),
            "by_apr_priority": {
                str(priority): {
                    stage: window_latency_to_json(aggregate)
                    for stage, aggregate in stages.items()
                }
                for priority, stages in sorted(stats.admission_priority_latency.items())
            },
        },
        "aio_batch_metrics": {
            "windows": stats.aio_batch_metrics.windows,
            "window_ms": stats.aio_batch_metrics.window_ms,
            "calls": stats.aio_batch_metrics.calls,
            "items": stats.aio_batch_metrics.items,
            "accepted_items": stats.aio_batch_metrics.accepted_items,
            "failed_calls": stats.aio_batch_metrics.failed_calls,
            "singleton_calls": stats.aio_batch_metrics.singleton_calls,
            "max_items": stats.aio_batch_metrics.max_items,
            "capacity": stats.aio_batch_metrics.capacity,
            "rounds": stats.aio_batch_metrics.rounds,
            "round_items": stats.aio_batch_metrics.round_items,
            "full_rounds": stats.aio_batch_metrics.full_rounds,
            "average_items_per_round": (
                stats.aio_batch_metrics.round_items / stats.aio_batch_metrics.rounds
                if stats.aio_batch_metrics.rounds
                else 0.0
            ),
            "average_items_per_call": (
                stats.aio_batch_metrics.items / stats.aio_batch_metrics.calls
                if stats.aio_batch_metrics.calls
                else 0.0
            ),
            "fill_percent": (
                100.0 * stats.aio_batch_metrics.items / stats.aio_batch_metrics.capacity
                if stats.aio_batch_metrics.capacity
                else 0.0
            ),
            "singleton_percent": (
                100.0
                * stats.aio_batch_metrics.singleton_calls
                / stats.aio_batch_metrics.calls
                if stats.aio_batch_metrics.calls
                else 0.0
            ),
            "saved_calls": max(
                0,
                stats.aio_batch_metrics.items - stats.aio_batch_metrics.calls,
            ),
            "saved_call_percent": (
                100.0
                * max(0, stats.aio_batch_metrics.items - stats.aio_batch_metrics.calls)
                / stats.aio_batch_metrics.items
                if stats.aio_batch_metrics.items
                else 0.0
            ),
            "accepted_percent": (
                100.0
                * stats.aio_batch_metrics.accepted_items
                / stats.aio_batch_metrics.items
                if stats.aio_batch_metrics.items
                else 0.0
            ),
            "priority_calls": dict(stats.aio_batch_metrics.priority_calls),
            "priority_items": dict(stats.aio_batch_metrics.priority_items),
            "apr_priority_items": {
                str(priority): stats.aio_batch_metrics.apr_priority_items[priority]
                for priority in range(APR_PRIORITY_LANES)
            },
        },
        "aio_io_metrics": {
            "windows": stats.aio_io_metrics.windows,
            "window_ms": stats.aio_io_metrics.window_ms,
            "accepted_count": stats.aio_io_metrics.accepted_count,
            "accepted_bytes": stats.aio_io_metrics.accepted_bytes,
            "average_bytes": (
                stats.aio_io_metrics.accepted_bytes
                / stats.aio_io_metrics.accepted_count
                if stats.aio_io_metrics.accepted_count
                else 0.0
            ),
            "throughput_mib_per_sec": (
                stats.aio_io_metrics.accepted_bytes
                * 1000.0
                / stats.aio_io_metrics.window_ms
                / (1024.0 * 1024.0)
                if stats.aio_io_metrics.window_ms
                else 0.0
            ),
            "size_buckets": {
                "le_64k": stats.aio_io_metrics.le64k,
                "gt_64k_le_256k": stats.aio_io_metrics.le256k,
                "gt_256k_lt_quantum": stats.aio_io_metrics.partial_quantum,
                "full_quantum": stats.aio_io_metrics.full_quantum,
                "over_quantum": stats.aio_io_metrics.over_quantum,
            },
            "quantum_bytes": stats.aio_io_metrics.quantum_bytes,
            "full_quantum_percent": (
                100.0
                * stats.aio_io_metrics.full_quantum
                / stats.aio_io_metrics.accepted_count
                if stats.aio_io_metrics.accepted_count
                else 0.0
            ),
            "by_apr_priority": {
                str(priority): {
                    "count": stats.aio_io_metrics.priority_count[priority],
                    "bytes": stats.aio_io_metrics.priority_bytes[priority],
                    "average_bytes": (
                        stats.aio_io_metrics.priority_bytes[priority]
                        / stats.aio_io_metrics.priority_count[priority]
                        if stats.aio_io_metrics.priority_count[priority]
                        else 0.0
                    ),
                }
                for priority in range(APR_PRIORITY_LANES)
            },
        },
        "amm_submit_diag": {
            "begins": stats.amm_submit_diag_begins,
            "leaves": stats.amm_submit_diag_leaves,
            "unmatched_leaves": stats.amm_submit_diag_unmatched_leaves,
            "nested_begins": stats.amm_submit_diag_nested_begins,
            "modes": dict(stats.amm_submit_modes),
            "rcs": dict(stats.amm_submit_rcs),
            "retry_total": stats.amm_submit_retry_total,
            "open": [
                {
                    "thread": thread,
                    "line": detail.line,
                    "seq": detail.seq,
                    "mode": detail.mode,
                    "buffer": f"0x{detail.buffer:x}" if detail.buffer is not None else None,
                    "current_offset": f"0x{detail.current_offset:x}" if detail.current_offset is not None else None,
                    "priority": detail.priority,
                    "id_out": detail.id_out,
                    "thread_continued": (
                        stats.thread_last_event.get(thread) is not None
                        and stats.thread_last_event[thread][0:2] > (detail.line, detail.seq)
                    ),
                    "thread_last_line": stats.thread_last_event.get(thread, (None, None, ""))[0],
                    "thread_last_seq": stats.thread_last_event.get(thread, (None, None, ""))[1],
                    "buffer_summary": (
                        {
                            "append_count": stats.amm_buffers[detail.buffer].append_count,
                            "first_line": stats.amm_buffers[detail.buffer].first_line,
                            "last_line": stats.amm_buffers[detail.buffer].last_line,
                            "max_cmd_off": f"0x{stats.amm_buffers[detail.buffer].max_cmd_off:x}",
                            "max_cb_next": f"0x{stats.amm_buffers[detail.buffer].max_cb_next:x}",
                            "last_cb_num": stats.amm_buffers[detail.buffer].last_cb_num,
                            "last_type": stats.amm_buffers[detail.buffer].last_type,
                            "last_target_va": (
                                f"0x{stats.amm_buffers[detail.buffer].last_target_va:x}"
                                if stats.amm_buffers[detail.buffer].last_target_va is not None
                                else None
                            ),
                            "last_target_size": (
                                f"0x{stats.amm_buffers[detail.buffer].last_target_size:x}"
                                if stats.amm_buffers[detail.buffer].last_target_size is not None
                                else None
                            ),
                            "types": dict(stats.amm_buffers[detail.buffer].type_counts),
                        }
                        if detail.buffer is not None and detail.buffer in stats.amm_buffers
                        else None
                    ),
                    "body": detail.body,
                }
                for thread, detail in sorted(stats.active_amm_submit_detail.items())
            ],
        },
        "apr_submit_diag": {
            "enters": stats.apr_submit_enters,
            "leaves": stats.apr_submit_leaves,
            "unmatched_leaves": stats.apr_submit_unmatched_leaves,
            "nested_enters": stats.apr_submit_nested_enters,
            "backpressure_events": stats.apr_submit_backpressure_events,
            "backpressure_max": {
                "pending": stats.apr_submit_backpressure_max_pending,
                "active_lanes": stats.apr_submit_backpressure_max_active_jobs,
                "active_jobs": stats.apr_submit_backpressure_max_active_jobs,
                "pending_reads": stats.apr_submit_backpressure_max_pending_reads,
                "active_reads": stats.apr_submit_backpressure_max_active_reads,
            },
            "open": [
                {
                    "thread": thread,
                    "line": detail.line,
                    "seq": detail.seq,
                    "phase": detail.phase,
                    "cb": f"0x{detail.cb:x}" if detail.cb is not None else None,
                    "priority": detail.priority,
                    "result": detail.result,
                    "id": detail.id_value,
                    "backpressure_count": detail.backpressure_count,
                    "last_backpressure": (
                        {
                            "line": detail.last_backpressure_line,
                            "seq": detail.last_backpressure_seq,
                            "job": (
                                f"0x{detail.last_backpressure_job:x}"
                                if detail.last_backpressure_job is not None
                                else None
                            ),
                            "pending": detail.last_backpressure_pending,
                            "incoming": detail.last_backpressure_incoming,
                            "active_lanes": detail.last_backpressure_active_jobs,
                            "active_jobs": detail.last_backpressure_active_jobs,
                            "pending_reads": detail.last_backpressure_pending_reads,
                            "active_reads": detail.last_backpressure_active_reads,
                            "waiters": detail.last_backpressure_waiters,
                            "body": detail.last_backpressure_body,
                        }
                        if detail.last_backpressure_line is not None
                        else None
                    ),
                    "thread_continued": (
                        stats.thread_last_event.get(thread) is not None
                        and stats.thread_last_event[thread][0:2] > (detail.line, detail.seq)
                    ),
                    "thread_last_line": stats.thread_last_event.get(thread, (None, None, ""))[0],
                    "thread_last_seq": stats.thread_last_event.get(thread, (None, None, ""))[1],
                    "body": detail.body,
                }
                for thread, detail in sorted(stats.active_apr_submit_detail.items())
            ],
        },
        "timestamped_lines": stats.timestamped_lines,
        "event_time_start": stats.event_time_start,
        "event_time_end": stats.event_time_end,
        "event_time_duration_seconds": event_time_duration_seconds(stats),
        "event_time_reversals": stats.event_time_reversals,
        "event_time_parse_errors": stats.event_time_parse_errors,
        "threads": dict(stats.threads),
        "prefixes_top": stats.prefixes.most_common(top),
        "amm_writer": dict(stats.amm_writer),
        "amm_writer_failures": dict(stats.amm_writer_failures),
        "amm_buffers_top": [
            {
                "buffer": f"0x{item.buffer:x}",
                "append_count": item.append_count,
                "first_line": item.first_line,
                "last_line": item.last_line,
                "max_cmd_off": f"0x{item.max_cmd_off:x}",
                "max_cb_next": f"0x{item.max_cb_next:x}",
                "last_cb_num": item.last_cb_num,
                "last_type": item.last_type,
                "last_target_va": f"0x{item.last_target_va:x}" if item.last_target_va is not None else None,
                "last_target_size": f"0x{item.last_target_size:x}" if item.last_target_size is not None else None,
                "types": dict(item.type_counts),
            }
            for item in sorted(
                stats.amm_buffers.values(),
                key=lambda entry: (entry.append_count, entry.last_line),
                reverse=True,
            )[:top]
        ],
        "verbose_lines": stats.verbose_lines,
        "fd_statuses": [
            {
                "line": fd.line,
                "seq": fd.seq,
                "tag": fd.tag,
                "probe_path": fd.probe_path,
                "probe_limit": fd.probe_limit,
                "probe_opened": fd.probe_opened,
                "probe_rc": f"0x{fd.probe_rc:x}",
                "probe_errno": fd.probe_errno,
                "free_exact": fd.free_exact,
                "aio_limit": fd.aio_limit,
                "direct_full_limit": fd.direct_full_limit,
                "fd_cache_cap": fd.fd_cache_cap,
                "fd_cache_reserve": fd.fd_cache_reserve,
            }
            for fd in stats.fd_statuses[-top:]
        ],
        "heap_statuses": [
            {
                "line": heap.line,
                "seq": heap.seq,
                "tag": heap.tag,
                "rc": f"0x{heap.rc:x}",
                "max_system": f"0x{heap.max_system:x}",
                "current_system": f"0x{heap.current_system:x}",
                "max_inuse": f"0x{heap.max_inuse:x}",
                "current_inuse": f"0x{heap.current_inuse:x}",
                "committed_free": f"0x{heap.committed_free:x}",
                "expandable_free": f"0x{heap.expandable_free:x}",
                "total_free": f"0x{heap.total_free:x}",
            }
            for heap in stats.heap_statuses[-top:]
        ],
        "jobs_seen": len(jobs_observed),
        "jobs_done": sum(1 for _, job in jobs_observed if job.done_line is not None),
        "jobs_unfinished": len(unfinished),
        "jobs_failed_or_partial": len(failed),
        "equeue_completion": {
            "attempts": sum(job.equeue_attempts for _, job in jobs_observed),
            "delivered": sum(job.equeue_delivered for _, job in jobs_observed),
            "pending": sum(job.equeue_pending for _, job in jobs_observed),
            "blocked": sum(job.equeue_blocked for _, job in jobs_observed),
        },
        "aio_errors": [
            {
                "event": event,
                "rc": format_rc(rc),
                "reason": reason,
                "file_id": file_id,
                "path": path,
                "count": count,
            }
            for (event, rc, reason, file_id, path), count in stats.aio_error_counts.most_common(top)
        ],
        "aio_error_samples": [
            {
                "line": sample.line,
                "seq": sample.seq,
                "event": sample.event,
                "rc": format_rc(sample.rc),
                "reason": sample.reason,
                "job": f"0x{sample.job:x}",
                "read_seq": f"0x{sample.read_seq:x}",
                "aio_id": sample.aio_id,
                "file_id": sample.file_id,
                "path": sample.path,
                "length": f"0x{sample.length:x}",
                "offset": f"0x{sample.offset:x}",
            }
            for sample in stats.aio_error_samples[-top:]
        ],
        "queued_reads": sum(job.queued_reads for _, job in jobs_observed),
        "aio_submits": sum(job.aio_submits for _, job in jobs_observed),
        "aio_completes": sum(job.aio_completes for _, job in jobs_observed),
        "aio_open": len(stats.active_aio),
        "max_aio_active": stats.max_aio_active,
        "max_apr_backlog": stats.max_apr_backlog,
        "max_reactor_active_lanes": stats.max_reactor_active_jobs,
        "max_reactor_active_jobs": stats.max_reactor_active_jobs,
        "max_reactor_pending_reads": stats.max_reactor_pending_reads,
        "max_reactor_read_chains": stats.max_reactor_read_chains,
        "max_reactor_active_reads": stats.max_reactor_active_reads,
        "max_reactor_incoming": stats.max_reactor_incoming,
        "max_submit_backlog": stats.max_submit_backlog,
        "max_priority_queue": dict(stats.max_priority_queue),
        "wait_enters": stats.wait_enters,
        "wait_leaves": stats.wait_leaves,
        "wait_boosts": stats.wait_boosts,
        "wait_boost_reserves": stats.wait_boost_reserves,
        "wait_boost_direct_reserves": stats.wait_boost_direct_reserves,
        "wait_admit_blocks": stats.wait_admit_blocks,
        "wait_admit_block_reasons": dict(stats.wait_admit_block_reasons),
        "wait_admit_order_blocks": stats.wait_admit_order_blocks,
        "read_order": {
            "defers": stats.read_order_defers,
            "defer_reasons": dict(stats.read_order_defer_reasons),
            "blocker_sources": dict(stats.read_order_blocker_sources),
            "promotions": stats.read_promotions,
            "promotion_reasons": dict(stats.read_promotion_reasons),
            "promotion_blocks": stats.read_promotion_blocks,
            "promotion_block_reasons": dict(stats.read_promotion_block_reasons),
            "legacy_runwindow_expands": stats.runwindow_order_expands,
            "runwindow_expands": stats.runwindow_order_expands,
            "samples": [
                {
                    "line": item.line,
                    "seq": item.seq,
                    "event": item.event,
                    "reason": item.reason,
                    "job": f"0x{item.job:x}",
                    "read_seq": f"0x{item.read_seq:x}",
                    "priority": item.priority,
                    "blocker": f"0x{item.blocker:x}",
                    "blocker_source": item.blocker_source,
                    "blocker_op": item.blocker_op,
                    "pending_reads": item.pending_reads,
                    "read_chains": item.read_chains,
                    "active_reads": item.active_reads,
                    "active_lanes": item.active_jobs,
                    "active_jobs": item.active_jobs,
                    "incoming": item.incoming,
                    "body": item.body,
                }
                for item in stats.apr_order_samples[-top:]
            ],
        },
        "wait_admit_block_maxima": {
            "count": stats.max_wait_admit_block_count,
            "active_lanes": stats.max_wait_admit_block_active_jobs,
            "active_jobs": stats.max_wait_admit_block_active_jobs,
            "pending": stats.max_wait_admit_block_pending,
            "incoming": stats.max_wait_admit_block_incoming,
            "pending_reads": stats.max_wait_admit_block_pending_reads,
            "active_reads": stats.max_wait_admit_block_active_reads,
            "oldest_aio_age_ms": stats.max_wait_admit_block_oldest_aio_age_ms,
        },
        "apr_done_evictions": stats.apr_done_evictions,
        "apr_done_evicted_ids": stats.apr_done_evicted_ids,
        "done_backlog_max": {
            "done": stats.max_done_retained,
            "pending": stats.max_done_pending,
            "pending_waits": stats.max_done_pending_waits,
        },
        "done_detail": [
            {
                "line": item.line,
                "seq": item.seq,
                "done": item.done,
                "pending": item.pending,
                "pending_waits": item.pending_waits,
                "first": f"0x{item.first:x}",
                "last": f"0x{item.last:x}",
                "newest": f"0x{item.newest:x}",
                "newest_rc": f"0x{item.newest_rc:x}",
                "newest_waitable": item.newest_waitable,
                "newest_has_equeue": item.newest_has_equeue,
                "newest_equeue_published": item.newest_equeue_published,
                "newest_completion_ready": item.newest_completion_ready,
                "samples": item.samples,
            }
            for item in stats.done_detail_samples[-top:]
        ],
        "done_id_samples": [
            {
                "line": item.line,
                "seq": item.seq,
                "rank": item.rank,
                "submit_id": f"0x{item.submit_id:x}",
                "waitable": item.waitable,
                "waiting": item.waiting,
                "newest": item.newest,
            }
            for item in stats.done_id_samples[-top:]
        ],
        "wait_pending_samples": [
            {
                "line": item.line,
                "seq": item.seq,
                "kind": item.kind,
                "job": f"0x{item.job:x}",
                "pending": item.pending,
                "incoming": item.incoming,
                "done": item.done,
                "waiters": item.waiters,
                "wait_job_pending": item.wait_job_pending,
                "wait_job_incoming": item.wait_job_incoming,
                "wait_job_done": item.wait_job_done,
                "pending_reads": item.pending_reads,
                "active_reads": item.active_reads,
                "pressure": item.pressure,
                "wait_pressure": item.wait_pressure,
                "oldest_aio_age_ms": item.oldest_aio_age_ms,
                "oldest_aio_job": f"0x{item.oldest_aio_job:x}",
                "oldest_aio_match": item.oldest_aio_match,
                "oldest_aio_seq": f"0x{item.oldest_aio_seq:x}",
                "oldest_aio_id": item.oldest_aio_id,
                "oldest_aio_file_id": item.oldest_aio_file_id,
                "oldest_aio_len": f"0x{item.oldest_aio_len:x}",
                "oldest_aio_off": f"0x{item.oldest_aio_off:x}",
            }
            for item in stats.wait_pending_samples[-top:]
        ],
        "reactor_state_samples": [
            {
                "line": item.line,
                "seq": item.seq,
                "reason": item.reason,
                "active_lanes": item.active_jobs,
                "active_jobs": item.active_jobs,
                "pending_reads": item.pending_reads,
                "active_reads": item.active_reads,
                "pending": item.pending,
                "incoming": item.incoming,
                "done": item.done,
                "waiters": item.waiters,
                "pressure": item.pressure,
                "wait_pressure": item.wait_pressure,
                "first_job": f"0x{item.first_job:x}",
                "op_index": item.op_index,
                "commands": item.commands,
                "op": item.op,
                "job_pending": item.job_pending,
                "job_active": item.job_active,
                "job_ready_completions": item.job_ready_completions,
                "job_completion_ops": item.job_completion_ops,
                "job_completed": item.job_completed,
                "job_failed": item.job_failed,
                "job_ready_to_publish": item.job_ready_to_publish,
                "job_publishing": item.job_publishing,
                "job_completion_ready": item.job_completion_ready,
                "job_has_equeue": item.job_has_equeue,
                "job_equeue_published": item.job_equeue_published,
                "job_waitable": item.job_waitable,
                "first_aio_id": item.first_aio_id,
                "first_aio_age_ms": item.first_aio_age_ms,
                "first_aio_job": f"0x{item.first_aio_job:x}",
                "first_aio_seq": f"0x{item.first_aio_seq:x}",
                "first_aio_file_id": item.first_aio_file_id,
                "first_aio_len": f"0x{item.first_aio_len:x}",
                "first_aio_off": f"0x{item.first_aio_off:x}",
            }
            for item in stats.reactor_state_samples[-top:]
        ],
        "direct_open_enters": stats.direct_open_enters,
        "direct_open_leaves": stats.direct_open_leaves,
        "direct_open_headroom_defers": stats.direct_open_headroom_defers,
        "acquire_defers": stats.acquire_defers,
        "acquire_defer_reasons": dict(stats.acquire_defer_reasons),
        "active_direct_opens": [
            {
                "job": f"0x{job_id:x}",
                "file_id": file_id,
                "line": item[0],
                "seq": item[1],
                "path": item[2],
                "length": f"0x{item[3]:x}",
                "offset": f"0x{item[4]:x}",
            }
            for (job_id, file_id), item in stats.active_direct_opens.items()
        ],
        "reactor_backlog_reasons": dict(stats.reactor_backlog_reasons),
        "reactor_backlog_slow_cooldown": stats.reactor_backlog_slow_cooldown,
        "backlog_file_samples": [
            {
                "line": item.line,
                "seq": item.seq,
                "reason": item.reason,
                "rank": item.rank,
                "file_id": item.file_id,
                "path": item.path,
                "pending": item.pending,
                "active": item.active,
                "pending_bytes": f"0x{item.pending_bytes:x}",
                "active_bytes": f"0x{item.active_bytes:x}",
                "max_pending_len": f"0x{item.max_pending_len:x}",
                "max_active_len": f"0x{item.max_active_len:x}",
                "pending_cached": item.pending_cached,
                "pending_small": item.pending_small,
                "pending_normal": item.pending_normal,
                "pending_bulk": item.pending_bulk,
                "active_cached": item.active_cached,
                "active_small": item.active_small,
                "active_normal": item.active_normal,
                "active_bulk": item.active_bulk,
                "wait_boosted": item.wait_boosted,
                "pressure": item.pressure,
            }
            for item in stats.backlog_file_samples[-top:]
        ],
        "waited_jobs": len(waited),
        "map": {
            "cb_ops": dict(stats.map_cb_ops),
            "cb_op_bytes": dict(stats.map_total_bytes_by_op),
            "apr_cb_api": dict(stats.map_cb_api),
            "apr_runtime": dict(stats.map_runtime),
            "amm_runtime": dict(stats.map_amm),
            "reject_reasons": dict(stats.map_runtime_reject_reasons),
            "job_fail_reasons": dict(stats.map_fail_reasons),
            "error_count": len(stats.map_errors),
            "errors": [
                {
                    "line": event.line,
                    "seq": event.seq,
                    "kind": event.kind,
                    "action": event.action,
                    "job": f"0x{event.job:x}" if event.job is not None else None,
                    "va": f"0x{event.va:x}" if event.va is not None else None,
                    "size": f"0x{event.size:x}" if event.size is not None else None,
                    "dmem_offset": f"0x{event.dmem_offset:x}" if event.dmem_offset is not None else None,
                    "type": f"0x{event.type_value:x}" if event.type_value is not None else None,
                    "prot": f"0x{event.prot:x}" if event.prot is not None else None,
                    "direct": event.direct,
                    "rc": f"0x{event.rc:x}" if event.rc is not None else None,
                    "reason": event.reason,
                    "body": event.body,
                }
                for event in stats.map_errors[:top]
            ],
            "recent": [
                {
                    "line": event.line,
                    "seq": event.seq,
                    "kind": event.kind,
                    "action": event.action,
                    "job": f"0x{event.job:x}" if event.job is not None else None,
                    "va": f"0x{event.va:x}" if event.va is not None else None,
                    "size": f"0x{event.size:x}" if event.size is not None else None,
                    "dmem_offset": f"0x{event.dmem_offset:x}" if event.dmem_offset is not None else None,
                    "type": f"0x{event.type_value:x}" if event.type_value is not None else None,
                    "prot": f"0x{event.prot:x}" if event.prot is not None else None,
                    "direct": event.direct,
                    "rc": f"0x{event.rc:x}" if event.rc is not None else None,
                    "reason": event.reason,
                }
                for event in stats.map_tail[-top:]
            ],
        },
        "command_buffer": {
            "append_counts": dict(stats.cb_append_sizes),
            "append_bytes": dict(stats.cb_append_size_bytes),
            "max_next_offset": f"0x{stats.cb_append_max_next_offset:x}",
            "offset_mismatches": stats.cb_append_size_mismatches,
            "capacity_rejects": stats.cb_append_capacity_rejects,
        },
        "equeue_waits": stats.equeue_waits,
        "equeue_direct_waits": stats.equeue_direct_waits,
        "equeue_direct_top": [
            {"eq": eq, "name": stats.equeue_names.get(eq, "unknown"), "count": count}
            for eq, count in stats.equeue_direct_by_eq.most_common(top)
        ],
        "apr_local_equeue": {
            "counter_lines": stats.apr_local_equeue_counter_lines,
            "wait_counter_lines": stats.apr_local_equeue_wait_lines,
            "grace_counter_lines": stats.apr_local_equeue_grace_lines,
            "wake_skip_metric_lines": stats.apr_local_equeue_wake_skip_metric_lines,
            "timeout_metric_lines": stats.apr_local_equeue_timeout_metric_lines,
            "counters": dict(stats.apr_local_equeue),
            "live_wait_intents": stats.apr_local_equeue_live_wait_intents,
            "wait_intent_peak": stats.apr_local_equeue_wait_intent_peak,
            "grace_configured_us": stats.apr_local_equeue_grace_configured_us,
            "grace_adaptive": stats.apr_local_equeue_grace_adaptive,
            "grace_min_us": stats.apr_local_equeue_grace_min_us,
            "grace_max_us": stats.apr_local_equeue_grace_max_us,
        },
        "autogen_events": stats.autogen_events,
        "reactor_blocked": stats.reactor_blocked,
        "read_completion_backpressure_events": stats.read_completion_backpressure_events,
        "read_completion_backpressure_max_span": stats.read_completion_backpressure_max_span,
        "reactor_stalls": stats.reactor_stalls,
        "stall_max_active_lanes": stats.stall_max_active_jobs,
        "stall_max_active_jobs": stats.stall_max_active_jobs,
        "stall_max_pending_reads": stats.stall_max_pending_reads,
        "stall_max_read_chains": stats.stall_max_read_chains,
        "stall_max_active_reads": stats.stall_max_active_reads,
        "stall_max_aio_age_ms": stats.stall_max_aio_age_ms,
        "stall_ops": dict(stats.stall_ops),
        "stall_aio_samples": [
            {
                "aio_id": sample.aio_id,
                "kind": sample.sample_kind,
                "job": f"0x{sample.job:x}",
                "read_seq": f"0x{sample.read_seq:x}",
                "file_id": sample.file_id,
                "length": f"0x{sample.length:x}",
                "offset": f"0x{sample.offset:x}",
                "age_ms": sample.age_ms,
                "state": f"0x{sample.state:x}",
                "poll_rc": f"0x{sample.poll_rc:x}",
                "line": sample.line,
                "seq": sample.seq,
            }
            for sample in sorted(
                stats.stall_aio_samples.values(), key=lambda item: (item.age_ms, item.line), reverse=True
            )[:top]
        ],
        "aio_detail_counts": dict(stats.aio_detail_counts),
        "aio_detail_samples": [
            {
                "kind": sample.kind,
                "reason": sample.reason,
                "aio_id": sample.aio_id,
                "job": f"0x{sample.job:x}",
                "read_seq": f"0x{sample.read_seq:x}",
                "file_id": sample.file_id,
                "path": sample.path,
                "length": f"0x{sample.length:x}",
                "offset": f"0x{sample.offset:x}",
                "age_ms": sample.age_ms,
                "state": f"0x{sample.state:x}",
                "poll_rc": f"0x{sample.poll_rc:x}",
                "return": f"0x{sample.return_value:x}",
                "bypass": sample.bypass,
                "close_after": sample.close_after,
                "line": sample.line,
                "seq": sample.seq,
            }
            for sample in sorted(stats.aio_detail_samples, key=lambda item: (item.age_ms, item.line), reverse=True)[:top]
        ],
        "aio_efault_details": [
            {
                "aio_id": sample.aio_id,
                "job": f"0x{sample.job:x}",
                "read_seq": f"0x{sample.read_seq:x}",
                "file_id": sample.file_id,
                "path": sample.path,
                "length": f"0x{sample.length:x}",
                "offset": f"0x{sample.offset:x}",
                "logical_length": f"0x{sample.logical_length:x}",
                "logical_offset": f"0x{sample.logical_offset:x}",
                "age_ms": sample.age_ms,
                "in_amm_va": sample.in_amm_va,
                "overlaps_amm_va": sample.overlaps_amm_va,
                "map_active": sample.map_active,
                "map_ranges": sample.map_ranges,
                "map_overlaps": sample.map_overlaps,
                "map_covered": f"0x{sample.map_covered:x}",
                "map_full": sample.map_full,
                "first_gap": f"0x{sample.first_gap:x}",
                "first_overlap": sample.first_overlap,
                "last_overlap": sample.last_overlap,
                "line": sample.line,
                "seq": sample.seq,
            }
            for sample in stats.aio_efault_details[-top:]
        ],
        "pending_detail_samples": [
            {
                "reason": sample.reason,
                "priority": sample.priority,
                "job": f"0x{sample.job:x}",
                "read_seq": f"0x{sample.read_seq:x}",
                "file_id": sample.file_id,
                "path": sample.path,
                "length": f"0x{sample.length:x}",
                "offset": f"0x{sample.offset:x}",
                "queue_reads": sample.queue_reads,
                "pending_reads": sample.pending_reads,
                "active_reads": sample.active_reads,
                "per_file_active": sample.per_file_active,
                "per_file_limit": sample.per_file_limit,
                "cached_active": sample.cached_active,
                "cached_limit": sample.cached_limit,
                "wait_boosted": sample.wait_boosted,
                "idle_boost": sample.idle_boost,
                "line": sample.line,
                "seq": sample.seq,
            }
            for sample in stats.pending_detail_samples[-top:]
        ],
        "last_reactor_stall": (
            {
                "line": stats.last_reactor_stall[0],
                "seq": stats.last_reactor_stall[1],
                "body": stats.last_reactor_stall[2],
            }
            if stats.last_reactor_stall
            else None
        ),
        "index_runtime_build_started": (
            {
                "line": stats.index_runtime_build_started[0],
                "seq": stats.index_runtime_build_started[1],
                "body": stats.index_runtime_build_started[2],
            }
            if stats.index_runtime_build_started
            else None
        ),
        "index_built": (
            {"line": stats.index_built[0], "seq": stats.index_built[1], "body": stats.index_built[2]}
            if stats.index_built
            else None
        ),
        "index_saved": (
            {"line": stats.index_saved[0], "seq": stats.index_saved[1], "body": stats.index_saved[2]}
            if stats.index_saved
            else None
        ),
        "index_last_progress": (
            {
                "line": stats.index_last_progress[0],
                "seq": stats.index_last_progress[1],
                "dirs": stats.index_last_progress[2],
                "files": stats.index_last_progress[3],
                "pending_dirs": stats.index_last_progress[4],
            }
            if stats.index_last_progress
            else None
        ),
        "index_last_dir": (
            {
                "line": stats.index_last_dir[0],
                "seq": stats.index_last_dir[1],
                "path": stats.index_last_dir[2],
                "dirs": stats.index_last_dir[3],
                "files": stats.index_last_dir[4],
                "pending_dirs": stats.index_last_dir[5],
            }
            if stats.index_last_dir
            else None
        ),
        "index_last_stat_enter": (
            {
                "line": stats.index_last_stat_enter[0],
                "seq": stats.index_last_stat_enter[1],
                "path": stats.index_last_stat_enter[2],
                "dirs": stats.index_last_stat_enter[3],
                "files": stats.index_last_stat_enter[4],
                "pending_dirs": stats.index_last_stat_enter[5],
            }
            if stats.index_last_stat_enter
            else None
        ),
        "index_last_stat_leave": (
            {
                "line": stats.index_last_stat_leave[0],
                "seq": stats.index_last_stat_leave[1],
                "path": stats.index_last_stat_leave[2],
            }
            if stats.index_last_stat_leave
            else None
        ),
        "findings": build_findings(stats),
        "unfinished_jobs": [
            {
                "job": f"0x{job_id:x}",
                "priority": job.priority,
                "commands": job.commands,
                "last_stall_op": job.last_stall_op,
                "last_stall_op_index": job.last_stall_op_index,
                "last_stall_pending_reads": job.last_stall_pending_reads,
                "last_stall_active_reads": job.last_stall_active_reads,
                "queued_reads": job.queued_reads,
                "aio_submits": job.aio_submits,
                "aio_completes": job.aio_completes,
                "completion_writes": job.completion_writes,
                "deferred_completions": job.deferred_completions,
                "first_line": job.first_line,
                "first_seq": job.first_seq,
                "last_line": job.last_line,
                "last_seq": job.last_seq,
            }
            for job_id, job in unfinished[-top:]
        ],
        "failed_jobs": [
            {
                "job": f"0x{job_id:x}",
                "rc": job.rc,
                "error_offset": job.error_offset,
                "fail_reasons": dict(job.fail_reasons),
                "last_line": job.last_line,
                "last_seq": job.last_seq,
            }
            for job_id, job in failed[-top:]
        ],
        "waited_submit_delays": [
            {
                "job": f"0x{job_id:x}",
                "priority": job.priority,
                "wait_seq": job.wait_enter_seq,
                "queue_seq": job.first_queue_seq,
                "submit_seq": job.first_aio_submit_seq,
                "leave_seq": job.wait_leave_seq,
                "done_seq": job.done_seq,
                "wait_to_queue_seq_delta": wait_to_queue_delay(job),
                "queue_to_submit_seq_delta": queue_to_submit_delay(job),
                "wait_to_submit_seq_delta": delay,
                "boosts": job.wait_boosts,
                "max_waiters": job.max_waiters,
            }
            for job_id, job, delay in waited_delays[:top]
        ],
        "open_aio": [
            {
                "aio_id": aio_id,
                "job": f"0x{job_id:x}",
                "read_seq": f"0x{read_seq:x}",
                "submit_line": line_no,
                "submit_seq": seq,
            }
            for aio_id, (job_id, read_seq, line_no, seq) in sorted(stats.active_aio.items())[:top]
        ],
    }


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze libSceAmpr APR/AIO debug logs.")
    parser.add_argument("log", nargs="?", default="apr_emu.log", help="Path to apr_emu.log")
    parser.add_argument("--top", type=int, default=20, help="Number of rows in top/detail sections")
    parser.add_argument("--tail", type=int, default=20, help="Number of tail lines to retain")
    parser.add_argument(
        "--suspicious-limit",
        type=int,
        default=200,
        help="Maximum suspicious lines retained while scanning",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    parser.add_argument(
        "--all-sessions",
        action="store_true",
        help="Analyze the whole file instead of only the latest sequence-id session",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    path = Path(args.log)
    if not path.is_file():
        raise SystemExit(f"log file not found: {path}")

    stats = analyze_log(
        path,
        max(args.tail, 0),
        max(args.suspicious_limit, 0),
        latest_session=not args.all_sessions,
    )
    if args.json:
        print(json.dumps(stats_to_json(stats, max(args.top, 0)), indent=2, sort_keys=True))
    else:
        print_report(stats, max(args.top, 0), max(args.tail, 0))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
