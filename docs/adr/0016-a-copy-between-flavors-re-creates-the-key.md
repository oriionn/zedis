# 16. A copy between flavors re-creates the key

Date: 2026-09-26 · Status: accepted

## Context

Copying a key to another server — the migration page, the key menu's
*copy to* — is `DUMP` on one side and `RESTORE` on the other: one payload,
any type, the encoding and the TTL carried whole. A `RESTORE` only takes a
payload up to the RDB version its own server writes, and the two flavors
number theirs apart. Measured on 2026-09-26: Redis 7.4 writes 12 and
Redis 8.10 15, Valkey 8.0 writes 11 and Valkey 9.1 80. So a copy between
them is refused — "DUMP payload version or checksum are wrong" — in every
direction but Valkey 8 → Redis, and a migration from a Redis 8 to a Valkey
9 failed every key with that line and nothing to be done about it.

The refusal is not a bug to route around: Redis 8 and Valkey 9 have each
changed what a payload can hold (a hash field's TTL, a new encoding), and a
server that accepted the other's payload would be guessing.

## Decision

The refusal is answered by re-creating the key from what the source holds,
by type, in commands both sides read and write: `GET` / `SET`, `HSCAN` /
`HSET`, `LRANGE` / `RPUSH`, `SSCAN` / `SADD`, `ZSCAN` / `ZADD`, `XRANGE` /
`XADD` under each entry's own id, `JSON.GET` / `JSON.SET`, paged at 500
elements and finished with `PEXPIRE` for the TTL the dump saw. It fires on
that one refusal (`is_foreign_payload`) and on nothing else: a `BUSYKEY`
is still the conflict question, an `OOM` is still the target's answer.
The outcome is its own status, `RestoreStatus::Recreated`, so the
migration log can say which keys travelled that way rather than fold them
into *written*.

What it cannot carry, it names rather than approximates: a module type
other than JSON (a Bloom filter, a time series, a vector set have no
portable read), a stream's consumer groups, a hash's per-field TTLs, a
stream with no entries. A `.zdis` file holds payloads and no source to
read from, so its import keeps the refusal and tells the person to export
as JSON instead — the readable formats were always the logical ones.

## Consequences

- A migration between a Redis and a Valkey lands in both directions; the
  cost is round trips per key instead of one, which is what a cross-flavor
  move is worth.
- `copy_key` and the migration's server-to-server path go through
  `restore_or_recreate_chunk`; a new path that restores from a *server*
  should too, and one that restores from a *file* cannot.
- The rule is measured, not read: the RDB versions above are what
  `DUMP` answered on the images named, and the live test
  `standalone_copy_lands_on_a_server_of_the_other_flavor` runs against a
  server of the other flavor by hand (`ZEDIS_IT_FOREIGN`), since the
  matrix has one flavor per lane.

## Amended 2026-10-17 — a single key says what it would lose first

A re-created key was reported after the fact: the copy had already run, and
a stream's consumer groups were gone from the target by the time the toast
said so. For one key — the key menu's *copy to* — that is the wrong order,
because the person is still there to decide.

So that copy asks first (`copy_preflight`). It dumps the key, and asks the
*target* whether it reads the payload rather than looking the answer up in
a table of RDB versions, which would be wrong on the next release of either
flavor: a `RESTORE` of the payload under a name nobody uses
(`zedis:copy-probe:<uuid>`), already expired (`1 … ABSTTL`). Redis and
Valkey both check the payload before the expiry; an expired one answers
`OK` and writes nothing, a foreign one is refused with the line
`is_foreign_payload` knows. Measured both ways between Redis 8.6.1 and
Valkey 9.0.0, and the live test asserts that no probe key is left behind.
Any other refusal (a replica, a permission, a lock on the bridge) is not
the preflight's to report: it says "restorable" and the copy meets the
same refusal and says so.

When the target refuses, the preflight reads what re-creating would leave
behind (`CopyLoss`): a type with no portable read is `Uncopyable` and the
copy is refused before anything is written; a stream's consumer groups are
counted (`XINFO GROUPS`); a hash's field TTLs are counted with `HTTL`
where the source supports them (`floors::HASH_FIELD_TTL`), up to
`FIELD_TTL_CHECK` (10,000) fields — past that the dialog says "at least".
An empty stream is no longer among the losses: it is re-created through a
throwaway group with `MKSTREAM`.

No losses, and the copy restores the dump the preflight already took.
Losses, and a confirm lists them by name; the confirmed copy dumps again,
since the key may have changed while the dialog was open. Either way the
result says *re-created by type*, with what did not travel.

The prefix copy and the migration page keep reporting per key in their
log: a question per key across a prefix is not a question anyone answers.

The live test `standalone_copy_preflight_says_what_a_copy_would_leave_behind`
runs one-flavor in the matrix (a same-server copy is restorable and loses
nothing) and both flavors by hand with `ZEDIS_IT_FOREIGN`.
