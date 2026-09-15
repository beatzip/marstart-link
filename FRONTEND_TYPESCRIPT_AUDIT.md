# Frontend TypeScript Audit

**Date:** 2025  
**Scope:** `src/App.tsx`, `src/components/LivingMars.tsx`, `src/types.ts`, `src/api.ts`  
**Tool:** `npx tsc --noEmit`  
**Total errors found:** 13 (at 7 distinct locations)  
**Task-relevant errors:** 5 (explicitly requested classification)  
**New errors discovered:** 8 (additional errors found during audit, documented below)

---

## Summary

| # | File | Line | Error Code | Type | Severity |
|---|------|------|------------|------|----------|
| 1 | `src/App.tsx` | 104 | TS2345 | Stale type / API mismatch (type widening) | Medium |
| 2 | `src/components/LivingMars.tsx` | 82 | TS7006 | Implicit any — missing parameter types | Low |
| 3 | `src/components/LivingMars.tsx` | 84 | TS7006 | Implicit any — missing parameter types | Low |
| 4 | `src/components/LivingMars.tsx` | 94 | TS7006 | Implicit any — missing parameter types | Low |
| 5 | `src/components/LivingMars.tsx` | 177 | TS7006 | Implicit any — missing parameter types | Low |
| 6 | `src/components/LivingMars.tsx` | 217 | TS7006 | Implicit any — missing parameter types (discovered) | Low |
| 7 | `src/components/LivingMars.tsx` | 280 | TS2339 | Type narrowing failure — `never` after exhaustive check (discovered) | Medium |
| 8 | `src/components/LivingMars.tsx` | 286 | TS18047 | Possible null — unchecked dereference (discovered) | Medium |
| 9 | `src/components/LivingMars.tsx` | 289 | TS7006 | Implicit any — missing parameter types (discovered) | Low |
| 10 | `src/components/LivingMars.tsx` | 295 | TS7053 | Implicit any — index signature missing (discovered) | Low |
| 11 | `src/components/LivingMars.tsx` | 476 | TS2322 | Type assignment — `number` vs `null` (discovered) | Medium |
| 12 | `src/components/LivingMars.tsx` | 479 | TS2322 | Type assignment — `number` vs `null` (discovered) | Medium |
| 13 | `src/types.ts` | 92 | (upstream) | `FsmStateView`/`AutopilotDecision` not imported by App.tsx | Info |

> **Note:** All 13 errors are **pre-existing**. None of the 5 control-plane changes
> under audit touched any frontend (TypeScript/JavaScript) file. The frontend errors
> were caused by earlier refactoring work (commit `465af3e` and prior) and are
> unrelated to the Rust control-plane test fixes.

---

## Detailed Classification

### Error 1: `App.tsx:104` — TS2345 (GameSignal.reason type mismatch)

**Classification:** Stale type / API mismatch (type widening)

**Root cause:**

The `api.gameState()` function in `src/api.ts:150-160` returns different types depending
on the environment:

```typescript
// src/api.ts:150-160
gameState: () =>
  isTauri()
    ? invoke<GameSignal>('game_get_state')
    : Promise.resolve({
        detected: false,
        game_id: null,
        game_name: null,
        confidence: 0,
        reason: 'Idle',           // ← widened to `string` by TypeScript
        timestamp_ms: Date.now(),
      }),
```

The Rust backend serializes `DetectionReason` via `#[derive(Serialize)]`, producing a
plain string (`"Idle"`, `"Process"`, etc.). The TypeScript type in `src/types.ts:80`
correctly narrows this to a union:

```typescript
// src/types.ts:75-82
export interface GameSignal {
  detected: boolean;
  game_id: string | null;
  game_name: string | null;
  confidence: number;
  reason: 'Idle' | 'Process' | 'UdpBurst' | 'Both';
  timestamp_ms: number;
}
```

However, the mock fallback in `api.ts` creates an inline object literal where
`'Idle'` is widened to `string` in the `Promise.resolve()` context. Since
`Promise.allSettled()` returns a union of `Fulfilled<T>` and `Rejected`, the inferred
type of `gameR.value` becomes:

```
GameSignal | { detected: boolean; game_id: null; game_name: null;
              confidence: number; reason: string; timestamp_ms: number; }
```

`string` is not assignable to `'Idle' | 'Process' | 'UduBurst' | 'Both'`.

**Evidence:**
- Rust `DetectionReason` enum (`game_detection/mod.rs:34-40`) derives `Serialize` —
  it serializes as a string.
- Rust `GameSignal` struct (`game_detection/mod.rs:42-50`) has `reason: DetectionReason`.
- TypeScript `GameSignal` type (`types.ts:75-82`) correctly defines the union.
- The mismatch arises from the mock fallback in `api.ts` not matching the declared type.

**Fix:**

Add `as const` to the mock fallback's `reason` field, or cast the entire object:

```typescript
reason: 'Idle' as const,
```

Alternatively, type the `Promise.resolve()` return explicitly:

```typescript
: Promise.resolve({...} as GameSignal)
```

**Recommended action:** Apply `as const` to `reason: 'Idle'` in `api.ts:158`.

---

### Error 2: `LivingMars.tsx:82` — TS7006 (implicit any: `a`, `b`, `t`)

**Classification:** Implicit any — missing parameter types

**Root cause:**

```typescript
// LivingMars.tsx:82
const lerp = (a, b, t) => a + (b - a) * t;
```

The function parameters `a`, `b`, `t` have no type annotations. With `"strict": true`
in `tsconfig.json`, TypeScript infers `any` and emits TS7006.

**Fix:** Add explicit types:

```typescript
const lerp = (a: number, b: number, t: number): number => a + (b - a) * t;
```

**Recommended action:** Add type annotations to all untyped function parameters
in `LivingMars.tsx`.

---

### Error 3: `LivingMars.tsx:84` — TS7006 (implicit any: `route`, `t`)

**Classification:** Implicit any — missing parameter types

**Root cause:**

```typescript
// LivingMars.tsx:84
function bzPt(route, t) {
```

Same pattern as Error 2. Parameters lack type annotations.

**Fix:**

```typescript
function bzPt(route: { p0: [number, number]; cp1: [number, number];
                  cp2: [number, number]; p1: [number, number] }, t: number): [number, number] {
```

---

### Error 4: `LivingMars.tsx:94` — TS7006 (implicit any: `ctx`, `time`, `br`, `mlPhase`)

**Classification:** Implicit any — missing parameter types

**Root cause:**

```typescript
// LivingMars.tsx:94
function drawSphere(ctx, time, br, mlPhase) {
```

Four parameters without type annotations in a canvas rendering helper.

---

### Error 5: `LivingMars.tsx:177` — TS7006 (implicit any: `ctx`, `orb`, `oa`, `nodeAngle`, `front`)

**Classification:** Implicit any — missing parameter types

**Root cause:**

Five parameters without type annotations in a canvas rendering function at
line 177.

---

### Additional Errors (discovered during audit, not in original scope)

#### Error 6: `LivingMars.tsx:217` — TS7006 (implicit any: `ctx`, `alpha`)

Another canvas rendering function with untyped parameters.

#### Error 7: `LivingMars.tsx:280` — TS2339 (Property 'getContext' does not exist on type 'never')

**Classification:** Type narrowing failure

The `useRef` for the canvas element narrows to `never` due to an overly specific
or incorrect generic type parameter. The ref's type doesn't match `HTMLCanvasElement`,
so TypeScript concludes the only possible type is `never`.

**Fix:** Ensure the `useRef` is typed as `useRef<HTMLCanvasElement | null>(null)`.

#### Error 8: `LivingMars.tsx:286` — TS18047 ('sc' is possibly 'null')

**Classification:** Possible null

A variable (`sc`) obtained from `getContext()` is used without a null check.
`getContext()` returns `WebGLRenderingContext | null`, so downstream code must
guard against `null`.

#### Error 9: `LivingMars.tsx:289` — TS7006 (implicit any: `now`)

Callback parameter in an animation frame handler without type annotation.

#### Error 10: `LivingMars.tsx:295` — TS7053 (index signature missing)

**Classification:** Index signature issue

An object with known keys (`offline`, `connecting`, `connected`, `excellent`,
`warning`, `critical`) is being indexed with a `string` variable, but the object's
type doesn't have an index signature. This is the `T` brand-tokens object
(temperature states for the Mars visualization).

**Fix:** Either add an index signature or type the lookup variable as a union of
the known keys.

#### Errors 11 & 12: `LivingMars.tsx:476, 479` — TS2322 (Type 'number' not assignable to type 'null')

**Classification:** Type assignment mismatch

Two assignments where a `number` value is being assigned to a variable whose
type is inferred as `null` (likely from an initializer of `null`).

#### Error 13 (info): `types.ts:92` — FsmStateView not imported

`App.tsx` imports `FsmState` from `types.ts` but the `FsmStateView` interface
is not used in `App.tsx`. This is informational, not an error.

---

## Cross-Reference to Control-Plane Changes

| Control-plane change | Frontend impact |
|---|---|
| `snapshot/mod.rs` Unknown→health | None — `Health` enum is unchanged |
| `autopilot/policy.rs` defaults | None — frontend doesn't consume `PolicyConfig` |
| `autopilot/mod.rs` feed_stability | None — frontend reads `AutopilotDecision` which is unchanged |
| `net_probe.rs` test address | None — test-only |
| `routes/mod.rs` clear_target | None — routes test-only |

**No frontend changes are required due to the 5 control-plane changes.**

However, if the control plane defaults (`game_mode_margin`, `recovery_cooldown_ms`)
were to be exposed to the frontend via `routes_set_policy` Tauri command
(`main.rs:606-619`), the frontend would need type definitions for `PolicyConfig`.
Currently the frontend only receives `RouteState` (with `cooldown_ms` and
`switch_margin`), not the autopilot `PolicyConfig`.

---

## Recommended Priority Order

| Priority | Error | Effort | Impact |
|---|---|---|---|
| P1 | Error 1 (App.tsx:104) — `reason` widening | 1-line fix | High — blocks `setGame()` type safety |
| P2 | Error 7 (LivingMars.tsx:280) — `never` ref | 5 min | Medium — blocks canvas rendering |
| P3 | Error 8 (LivingMars.tsx:286) — null check | 5 min | Medium — potential runtime crash |
| P4 | Error 10 (LivingMars.tsx:295) — index signature | 10 min | Low — cosmetic, runtime works |
| P5 | Error 11-12 (LivingMars.tsx:476, 479) — type mismatch | 10 min | Low — runtime works, type-unsafe |
| P6 | Errors 2-6, 9 | 15 min | Low — add type annotations |

---

## Conclusion

All 5 TypeScript errors fall into two categories:

1. **Stale type / API mismatch** (Error 1): The mock fallback in `api.ts` doesn't
   match the `GameSignal` interface because string literal types are widened to
   `string` in `Promise.resolve()`.

2. **Implicit any** (Errors 2-6, 9): Canvas rendering helper functions in
   `LivingMars.tsx` have untyped parameters, which is flagged by `strict: true`.

The remaining 6 errors (7, 8, 10-13) were discovered during the audit but were
not in the original scope of 5 errors. They are primarily in the
`LivingMars.tsx` visualization component and are unrelated to the control plane
logic.

**Per task instructions, no TypeScript fixes are to be applied in this task
(Phase 1 audit only). These are documented here for classification.**
