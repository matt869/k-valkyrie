"""
K-Valkyrie Entity Tracker
Maintains lifecycle state of Process, File, Socket, and MemFD entities
within the provenance graph. Thread-safe via a read-write lock pattern.
"""

from __future__ import annotations

import enum
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class EntityType(str, enum.Enum):
    """Types of provenance graph entities."""
    PROCESS = "process"
    FILE = "file"
    SOCKET = "socket"
    MEMFD = "memfd"


class EntityState(str, enum.Enum):
    """Lifecycle states an entity can transition through."""
    ACTIVE = "ACTIVE"
    TERMINATED = "TERMINATED"
    QUARANTINED = "QUARANTINED"


@dataclass
class Entity:
    """
    Represents a single provenance graph entity with lifecycle metadata.

    Attributes:
        id: Unique entity identifier (e.g., ``Process:1234``).
        entity_type: One of PROCESS, FILE, SOCKET, MEMFD.
        created_at: Monotonic timestamp when the entity was first seen (ns).
        last_seen: Monotonic timestamp of the most recent activity (ns).
        state: Current lifecycle state.
        metadata: Arbitrary key-value metadata for enrichment.
    """
    id: str
    entity_type: EntityType
    created_at: int
    last_seen: int
    state: EntityState = EntityState.ACTIVE
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize entity to a plain dictionary."""
        return {
            "id": self.id,
            "entity_type": self.entity_type.value,
            "created_at": self.created_at,
            "last_seen": self.last_seen,
            "state": self.state.value,
            "metadata": dict(self.metadata),
        }


class _ReadWriteLock:
    """
    Simple read-write lock allowing concurrent readers but exclusive writers.
    Uses a condition variable for writer starvation avoidance.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._readers_cv = threading.Condition(self._lock)
        self._writers_cv = threading.Condition(self._lock)
        self._readers: int = 0
        self._writer: bool = False
        self._write_waiters: int = 0

    def acquire_read(self) -> None:
        """Acquire a shared read lock."""
        with self._lock:
            while self._writer or self._write_waiters > 0:
                self._readers_cv.wait()
            self._readers += 1

    def release_read(self) -> None:
        """Release a shared read lock."""
        with self._lock:
            self._readers -= 1
            if self._readers == 0:
                self._writers_cv.notify()

    def acquire_write(self) -> None:
        """Acquire an exclusive write lock."""
        with self._lock:
            self._write_waiters += 1
            while self._writer or self._readers > 0:
                self._writers_cv.wait()
            self._write_waiters -= 1
            self._writer = True

    def release_write(self) -> None:
        """Release an exclusive write lock."""
        with self._lock:
            self._writer = False
            self._readers_cv.notify_all()
            self._writers_cv.notify()


class _ReadLockCtx:
    """Context manager for read lock acquisition."""
    def __init__(self, rwlock: _ReadWriteLock) -> None:
        self._rwlock = rwlock

    def __enter__(self) -> _ReadLockCtx:
        self._rwlock.acquire_read()
        return self

    def __exit__(self, *args: Any) -> None:
        self._rwlock.release_read()


class _WriteLockCtx:
    """Context manager for write lock acquisition."""
    def __init__(self, rwlock: _ReadWriteLock) -> None:
        self._rwlock = rwlock

    def __enter__(self) -> _WriteLockCtx:
        self._rwlock.acquire_write()
        return self

    def __exit__(self, *args: Any) -> None:
        self._rwlock.release_write()


class EntityTracker:
    """
    Thread-safe tracker for provenance graph entity lifecycle management.

    Maintains a registry of Process, File, Socket, and MemFD entities with
    their creation time, last activity time, lifecycle state, and metadata.

    Uses a read-write lock so multiple threads can read concurrently while
    mutations are serialized.

    Usage::

        tracker = EntityTracker()
        tracker.register("Process:1234", EntityType.PROCESS, metadata={"comm": "bash"})
        tracker.update("Process:1234", metadata={"comm": "ls"})
        active = tracker.get_active()
        tracker.terminate("Process:1234")
        pruned = tracker.prune_stale(max_age_ns=60_000_000_000)
    """

    def __init__(self) -> None:
        self._entities: Dict[str, Entity] = {}
        self._type_index: Dict[EntityType, Set[str]] = {
            etype: set() for etype in EntityType
        }
        self._rwlock = _ReadWriteLock()

    def _read_lock(self) -> _ReadLockCtx:
        return _ReadLockCtx(self._rwlock)

    def _write_lock(self) -> _WriteLockCtx:
        return _WriteLockCtx(self._rwlock)

    def register(
        self,
        entity_id: str,
        entity_type: EntityType,
        *,
        timestamp_ns: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
        state: EntityState = EntityState.ACTIVE,
    ) -> Entity:
        """
        Register a new entity or re-activate an existing one.

        Args:
            entity_id: Unique identifier (e.g., ``Process:1234``).
            entity_type: Entity category.
            timestamp_ns: Event timestamp in nanoseconds. Defaults to now.
            metadata: Additional key-value metadata.
            state: Initial state (default ACTIVE).

        Returns:
            The registered or updated Entity.
        """
        now = timestamp_ns if timestamp_ns is not None else time.time_ns()
        meta = metadata or {}

        with self._write_lock():
            existing = self._entities.get(entity_id)
            if existing is not None:
                # Re-activate if previously terminated
                existing.last_seen = now
                existing.state = state
                existing.metadata.update(meta)
                return existing

            entity = Entity(
                id=entity_id,
                entity_type=entity_type,
                created_at=now,
                last_seen=now,
                state=state,
                metadata=meta,
            )
            self._entities[entity_id] = entity
            self._type_index[entity_type].add(entity_id)
            logger.debug(
                "Registered entity %s (type=%s, state=%s)",
                entity_id,
                entity_type.value,
                state.value,
            )
            return entity

    def update(
        self,
        entity_id: str,
        *,
        timestamp_ns: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
        state: Optional[EntityState] = None,
    ) -> Optional[Entity]:
        """
        Update an existing entity's last-seen time, metadata, and/or state.

        Args:
            entity_id: Entity to update.
            timestamp_ns: New last-seen timestamp. Defaults to now.
            metadata: Metadata fields to merge.
            state: New lifecycle state (optional).

        Returns:
            The updated Entity, or None if not found.
        """
        now = timestamp_ns if timestamp_ns is not None else time.time_ns()

        with self._write_lock():
            entity = self._entities.get(entity_id)
            if entity is None:
                logger.debug("Update failed: entity %s not found", entity_id)
                return None
            entity.last_seen = now
            if metadata:
                entity.metadata.update(metadata)
            if state is not None:
                entity.state = state
            return entity

    def terminate(
        self,
        entity_id: str,
        *,
        timestamp_ns: Optional[int] = None,
    ) -> Optional[Entity]:
        """
        Mark an entity as TERMINATED.

        Args:
            entity_id: Entity to terminate.
            timestamp_ns: Termination timestamp. Defaults to now.

        Returns:
            The terminated Entity, or None if not found.
        """
        return self.update(
            entity_id,
            timestamp_ns=timestamp_ns,
            state=EntityState.TERMINATED,
        )

    def quarantine(
        self,
        entity_id: str,
        *,
        timestamp_ns: Optional[int] = None,
        reason: str = "",
    ) -> Optional[Entity]:
        """
        Mark an entity as QUARANTINED.

        Args:
            entity_id: Entity to quarantine.
            timestamp_ns: Quarantine timestamp. Defaults to now.
            reason: Reason for quarantine (stored in metadata).

        Returns:
            The quarantined Entity, or None if not found.
        """
        meta = {"quarantine_reason": reason} if reason else None
        return self.update(
            entity_id,
            timestamp_ns=timestamp_ns,
            metadata=meta,
            state=EntityState.QUARANTINED,
        )

    def get(self, entity_id: str) -> Optional[Entity]:
        """
        Look up an entity by ID.

        Args:
            entity_id: Entity identifier.

        Returns:
            The Entity, or None if not found.
        """
        with self._read_lock():
            return self._entities.get(entity_id)

    def get_active(self) -> List[Entity]:
        """
        Return all entities in the ACTIVE state.

        Returns:
            List of active entities (snapshot).
        """
        with self._read_lock():
            return [
                e for e in self._entities.values()
                if e.state == EntityState.ACTIVE
            ]

    def get_by_type(self, entity_type: EntityType) -> List[Entity]:
        """
        Return all entities of a specific type.

        Args:
            entity_type: Entity type to filter by.

        Returns:
            List of matching entities (snapshot).
        """
        with self._read_lock():
            ids = self._type_index.get(entity_type, set())
            return [self._entities[eid] for eid in ids if eid in self._entities]

    def get_by_state(self, state: EntityState) -> List[Entity]:
        """
        Return all entities in a specific state.

        Args:
            state: Lifecycle state to filter by.

        Returns:
            List of matching entities (snapshot).
        """
        with self._read_lock():
            return [e for e in self._entities.values() if e.state == state]

    def get_quarantined(self) -> List[Entity]:
        """Return all quarantined entities."""
        return self.get_by_state(EntityState.QUARANTINED)

    def prune_stale(
        self,
        max_age_ns: int,
        *,
        reference_time_ns: Optional[int] = None,
        preserve_quarantined: bool = True,
    ) -> List[str]:
        """
        Remove entities that have not been seen within the age window.

        Args:
            max_age_ns: Maximum age in nanoseconds since last_seen.
            reference_time_ns: Reference time for age calculation. Defaults to now.
            preserve_quarantined: If True, do not prune quarantined entities.

        Returns:
            List of pruned entity IDs.
        """
        ref_time = reference_time_ns if reference_time_ns is not None else time.time_ns()
        cutoff = ref_time - max_age_ns
        pruned: List[str] = []

        with self._write_lock():
            to_remove: List[str] = []
            for eid, entity in self._entities.items():
                if entity.last_seen < cutoff:
                    if preserve_quarantined and entity.state == EntityState.QUARANTINED:
                        continue
                    to_remove.append(eid)

            for eid in to_remove:
                entity = self._entities.pop(eid)
                self._type_index[entity.entity_type].discard(eid)
                pruned.append(eid)

        if pruned:
            logger.info("Pruned %d stale entities", len(pruned))
        return pruned

    def count(self) -> int:
        """Return total number of tracked entities."""
        with self._read_lock():
            return len(self._entities)

    def count_by_state(self) -> Dict[str, int]:
        """Return entity counts grouped by state."""
        with self._read_lock():
            counts: Dict[str, int] = {}
            for entity in self._entities.values():
                key = entity.state.value
                counts[key] = counts.get(key, 0) + 1
            return counts

    def all_entities(self) -> List[Entity]:
        """Return a snapshot list of all entities."""
        with self._read_lock():
            return list(self._entities.values())

    def clear(self) -> None:
        """Remove all tracked entities."""
        with self._write_lock():
            self._entities.clear()
            for s in self._type_index.values():
                s.clear()
        logger.info("Entity tracker cleared")
